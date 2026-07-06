package interceptor

import (
	"bytes"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/Tarekinh0/qindu/internal/tokenize"
)

// TestEnforceSSEReader_RehydrateFrame verifies that SSE frames containing
// tokens are rehydrated correctly.
func TestEnforceSSEReader_RehydrateFrame(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	engine := newTestEngine()

	tokenizer := tokenize.New(engine, tokenize.WithLogger(logger))
	// Tokenize some PII to create a mapping.
	_, err := tokenizer.Tokenize("user@example.com")
	if err != nil {
		t.Fatalf("Tokenize: %v", err)
	}

	// Find the token that was assigned.
	tokenized, err := tokenizer.Tokenize("user@example.com")
	if err != nil {
		t.Fatalf("Tokenize again: %v", err)
	}
	// tokenized contains "<<EMAIL_1>>" — extract it.
	token := extractToken(tokenized)

	// Create SSE frame with the token in the data payload.
	frameData := []byte("data: Your email is " + token + "\n\n")

	reader := newEnforceSSEReader(EnforceSSEConfig{
		Upstream:    io.NopCloser(bytes.NewReader(frameData)),
		Engine:      engine,
		Logger:      logger,
		PIILogging:  false,
		Host:        "chatgpt.com",
		ContentType: "text/event-stream",
		Tokenizer:   tokenizer,
	})

	out, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll SSE: %v", err)
	}
	_ = reader.Close()

	output := string(out)
	if !strings.Contains(output, "user@example.com") {
		t.Errorf("SSE output should contain rehydrated PII 'user@example.com', got: %q", output)
	}
	if strings.Contains(output, token) && !strings.Contains(output, "user@example.com") {
		t.Errorf("SSE output should not contain raw token when rehydrated, got: %q", output)
	}
}

// extractToken extracts a <<TYPE_N>> token from a tokenized string.
func extractToken(tokenized string) string {
	start := strings.Index(tokenized, "<<")
	if start < 0 {
		return ""
	}
	end := strings.Index(tokenized[start:], ">>")
	if end < 0 {
		return ""
	}
	return tokenized[start : start+end+2]
}

// TestEnforceSSEReader_SlidingBufferTokenSplit verifies that tokens split
// across SSE chunk boundaries are reassembled by the sliding buffer.
func TestEnforceSSEReader_SlidingBufferTokenSplit(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	engine := newTestEngine()

	tokenizer := tokenize.New(engine, tokenize.WithLogger(logger))
	_, err := tokenizer.Tokenize("user@example.com")
	if err != nil {
		t.Fatalf("Tokenize: %v", err)
	}

	tokenized, _ := tokenizer.Tokenize("user@example.com")
	token := extractToken(tokenized)

	if len(token) < 6 {
		t.Fatal("token too short for split test")
	}

	// Split the token: "<<EMA" and "IL_1>>"
	splitPoint := len(token) / 2
	part1 := token[:splitPoint]
	part2 := token[splitPoint:]

	// Chunk 1: data: starts with prefix and split token.
	chunk1 := []byte("data: Your email is " + part1)
	// Chunk 2: rest of token.
	chunk2 := []byte(part2 + " confirmed\n\n")

	// Combine both chunks into a single upstream reader.
	fullContent := append(chunk1, chunk2...)

	reader := newEnforceSSEReader(EnforceSSEConfig{
		Upstream:    io.NopCloser(bytes.NewReader(fullContent)),
		Engine:      engine,
		Logger:      logger,
		PIILogging:  false,
		Host:        "chatgpt.com",
		ContentType: "text/event-stream",
		Tokenizer:   tokenizer,
	})

	out, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll SSE: %v", err)
	}
	_ = reader.Close()

	output := string(out)
	if !strings.Contains(output, "user@example.com") {
		t.Errorf("SSE sliding buffer should reassemble split token and rehydrate, got: %q", output)
	}
}

// TestEnforceSSEReader_SlidingBufferOverflow verifies that an oversized
// << prefix (exceeding 4KB) in a data: payload is flushed as-is with a WARN.
func TestEnforceSSEReader_SlidingBufferOverflow(t *testing.T) {
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	engine := newTestEngine()

	tokenizer := tokenize.New(engine, tokenize.WithLogger(logger))
	_, _ = tokenizer.Tokenize("user@example.com")

	// Create a data: line with << prefix followed by >4KB without closing >>.
	// This triggers the sliding buffer overflow path in rehydrateWithSlidingBuffer.
	longPrefix := "data: <<" + strings.Repeat("X", 5000) + "\n\n"

	reader := newEnforceSSEReader(EnforceSSEConfig{
		Upstream:    io.NopCloser(bytes.NewReader([]byte(longPrefix))),
		Engine:      engine,
		Logger:      logger,
		PIILogging:  false,
		Host:        "chatgpt.com",
		ContentType: "text/event-stream",
		Tokenizer:   tokenizer,
	})

	out, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll SSE overflow: %v", err)
	}
	_ = reader.Close()

	// Output should contain the overflowed content (flushed as-is).
	if len(out) == 0 {
		t.Error("overflowed SSE should still produce output (flushed as-is)")
	}

	logOutput := logBuf.String()
	if !strings.Contains(logOutput, "sliding_buffer_overflow") {
		t.Error("overflow should log sliding_buffer_overflow warning")
	}
	if !strings.Contains(logOutput, "pii_values_logged") {
		t.Error("overflow warning should contain pii_values_logged")
	}
}

// TestEnforceSSEReader_BufferZeroedOnClose verifies the sliding buffer
// is zeroed when the reader is closed.
func TestEnforceSSEReader_BufferZeroedOnClose(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	engine := newTestEngine()

	tokenizer := tokenize.New(engine, tokenize.WithLogger(logger))
	_, _ = tokenizer.Tokenize("user@example.com")
	tokenized, _ := tokenizer.Tokenize("user@example.com")
	token := extractToken(tokenized)

	// Send a chunk ending with partial token prefix.
	chunk := []byte("data: Your email is " + token[:len(token)-3])

	reader := newEnforceSSEReader(EnforceSSEConfig{
		Upstream:    io.NopCloser(bytes.NewReader(chunk)),
		Engine:      engine,
		Logger:      logger,
		PIILogging:  false,
		Host:        "chatgpt.com",
		ContentType: "text/event-stream",
		Tokenizer:   tokenizer,
	})

	// Read enough to trigger sliding buffer accumulation.
	_, _ = io.ReadAll(reader)
	_ = reader.Close()

	// After close, slidingBuf should be nil (zeroed).
	if reader.slidingBuf != nil {
		t.Error("slidingBuf should be nil after Close()")
	}
}

// TestEnforceSSEReader_NonSSEContent verifies that non-SSE content
// is handled gracefully.
func TestEnforceSSEReader_NonSSEContent(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	engine := newTestEngine()

	tokenizer := tokenize.New(engine, tokenize.WithLogger(logger))
	_, _ = tokenizer.Tokenize("user@example.com")

	// Plain text (not SSE).
	content := []byte("just some plain text without token")

	reader := newEnforceSSEReader(EnforceSSEConfig{
		Upstream:    io.NopCloser(bytes.NewReader(content)),
		Engine:      engine,
		Logger:      logger,
		PIILogging:  false,
		Host:        "chatgpt.com",
		ContentType: "text/event-stream",
		Tokenizer:   tokenizer,
	})

	out, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll non-SSE: %v", err)
	}
	_ = reader.Close()

	// Output should contain the original text.
	if !strings.Contains(string(out), "just some plain text") {
		t.Errorf("non-SSE content should pass through, got: %q", string(out))
	}
}

// TestEnforceSSEReader_NestedLLPrevention verifies that consecutive << prefixes
// are handled correctly (first << flushed when second << arrives).
func TestEnforceSSEReader_NestedLLPrevention(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	engine := newTestEngine()

	tokenizer := tokenize.New(engine, tokenize.WithLogger(logger))
	_, _ = tokenizer.Tokenize("user@example.com")
	tokenized, _ := tokenizer.Tokenize("user@example.com")
	token := extractToken(tokenized)

	// Send content with two << prefixes - the first one is partial data without >>
	// and the second starts a valid token.
	chunk := []byte("data: First prefix << then valid token " + token + "\n\n")

	reader := newEnforceSSEReader(EnforceSSEConfig{
		Upstream:    io.NopCloser(bytes.NewReader(chunk)),
		Engine:      engine,
		Logger:      logger,
		PIILogging:  false,
		Host:        "chatgpt.com",
		ContentType: "text/event-stream",
		Tokenizer:   tokenizer,
	})

	out, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll nested <<: %v", err)
	}
	_ = reader.Close()

	output := string(out)
	if !strings.Contains(output, "user@example.com") {
		t.Errorf("valid token after << prefix should be rehydrated: %q", output)
	}
}

// TestEnforceSSEReader_NoZeroNilReturn verifies the io.Reader contract:
// Read must never return (0, nil). This regression test validates the fix
// for PR-002 by sending data in small chunks that don't form complete SSE
// frames until multiple reads — the for loop must continue reading rather
// than breaking and returning (0, nil).
func TestEnforceSSEReader_NoZeroNilReturn(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	engine := newTestEngine()

	tokenizer := tokenize.New(engine, tokenize.WithLogger(logger))
	_, _ = tokenizer.Tokenize("user@example.com")
	tokenized, _ := tokenizer.Tokenize("user@example.com")
	token := extractToken(tokenized)

	// Split a complete SSE frame into tiny 1-byte chunks. Each Read
	// returns data but no complete frame boundary — the loop must keep
	// reading from upstream until a frame boundary is detected.
	fullFrame := []byte("data: Hello " + token + "\n\n")
	reader := newEnforceSSEReader(EnforceSSEConfig{
		Upstream:    io.NopCloser(&chunkedReader{data: fullFrame, chunkSize: 1}),
		Engine:      engine,
		Logger:      logger,
		PIILogging:  false,
		Host:        "chatgpt.com",
		ContentType: "text/event-stream",
		Tokenizer:   tokenizer,
	})

	// io.ReadAll internally uses io.Copy, which busy-loops on (0, nil).
	out, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll chunked SSE: %v", err)
	}
	_ = reader.Close()

	output := string(out)
	if !strings.Contains(output, "user@example.com") {
		t.Errorf("chunked SSE should produce rehydrated output, got: %q", output)
	}
}

// chunkedReader reads data in fixed-size chunks to simulate network chunking.
type chunkedReader struct {
	data      []byte
	pos       int
	chunkSize int
}

func (r *chunkedReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	end := r.pos + r.chunkSize
	if end > len(r.data) {
		end = len(r.data)
	}
	n := copy(p, r.data[r.pos:end])
	r.pos = end
	return n, nil
}

// TestEnforceSSEReader_EmptyStream verifies empty SSE streams.
func TestEnforceSSEReader_EmptyStream(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	engine := newTestEngine()

	tokenizer := tokenize.New(engine, tokenize.WithLogger(logger))

	reader := newEnforceSSEReader(EnforceSSEConfig{
		Upstream:    io.NopCloser(bytes.NewReader([]byte{})),
		Engine:      engine,
		Logger:      logger,
		PIILogging:  false,
		Host:        "chatgpt.com",
		ContentType: "text/event-stream",
		Tokenizer:   tokenizer,
	})

	out, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll empty SSE: %v", err)
	}
	_ = reader.Close()

	if len(out) != 0 {
		t.Errorf("empty SSE should produce no output, got %d bytes", len(out))
	}
}
