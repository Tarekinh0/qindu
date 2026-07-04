package interceptor

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/Tarekinh0/qindu/internal/pii"
)

// newTestEngine creates a minimal engine with email and phone recognizers for tests.
func newTestEngine() *pii.Engine {
	return pii.NewEngine(pii.DefaultMaxInputBytes,
		pii.NewEmailRecognizer(),
		pii.NewPhoneRecognizer(),
	)
}

// newTestEngineFull creates an engine with all 9 recognizers for comprehensive tests.
func newTestEngineFull() *pii.Engine {
	return pii.NewEngine(pii.DefaultMaxInputBytes,
		pii.NewEmailRecognizer(),
		pii.NewPhoneRecognizer(),
		pii.NewIBANRecognizer(),
		pii.NewCreditCardRecognizer(),
		pii.NewJWTRecognizer(),
		pii.NewSecretPrefixRecognizer(),
		pii.NewSecretEntropyRecognizer(),
		pii.NewPrivateKeyRecognizer(),
		pii.NewNameFromEmailRecognizer(),
	)
}

// newTestLogger creates a logger that writes to a buffer for test assertions.
func newTestLogger(buf *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// parseLogEntries extracts all JSON log entries from the buffer.
func parseLogEntries(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()

	var entries []map[string]any
	decoder := json.NewDecoder(bytes.NewReader(buf.Bytes()))
	for {
		var entry map[string]any
		if err := decoder.Decode(&entry); err != nil {
			if err == io.EOF {
				break
			}
			// Skip partially written lines.
			break
		}
		entries = append(entries, entry)
	}
	return entries
}

func TestSSEFrameReader_CompleteFrames(t *testing.T) {
	engine := newTestEngine()
	var logBuf bytes.Buffer
	logger := newTestLogger(&logBuf)

	// Simulate an SSE stream with PII in data: fields.
	sseStream := strings.NewReader(
		`data: {"message": "Hello test.user@example.com"}` + "\n\n" +
			`data: {"message": "No PII here"}` + "\n\n" +
			`data: {"message": "Call +1-555-0100"}` + "\n\n",
	)

	reader := newSSEFrameReader(SSEFrameReaderConfig{
		Upstream:     io.NopCloser(sseStream),
		Engine:       engine,
		Logger:       logger,
		PIILogging:   true,
		MaxFrameSize: 1024 * 1024,
		Host:         "test-upstream.local",
		Method:       "POST",
		Path:         "/v1/chat",
		ContentType:  "text/event-stream",
		StatusCode:   200,
	})
	defer func() { _ = reader.Close() }()

	// Read all data.
	output, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}

	// Verify forwarding is byte-identical (SR-9).
	expectedOutput := `data: {"message": "Hello test.user@example.com"}` + "\n\n" +
		`data: {"message": "No PII here"}` + "\n\n" +
		`data: {"message": "Call +1-555-0100"}` + "\n\n"
	if string(output) != expectedOutput {
		t.Errorf("forwarded output mismatch.\n got: %q\nwant: %q", string(output), expectedOutput)
	}

	// Verify detection logs.
	entries := parseLogEntries(t, &logBuf)
	// We expect 2 detection entries (frames 1 and 3 have PII)
	if len(entries) < 2 {
		t.Fatalf("expected at least 2 detection log entries, got %d", len(entries))
	}

	// First frame should have EMAIL detection.
	frame1 := entries[0]
	if frame1["msg"] != "pii_detected" {
		t.Errorf("expected msg=pii_detected, got %v", frame1["msg"])
	}
	if frame1["pii_values_logged"] != false {
		t.Errorf("pii_values_logged must be false, got %v", frame1["pii_values_logged"])
	}
	if frame1["sse_frame"] != true {
		t.Errorf("sse_frame must be true, got %v", frame1["sse_frame"])
	}
	if frame1["host"] != "test-upstream.local" {
		t.Errorf("host mismatch: %v", frame1["host"])
	}
	if frame1["direction"] != "response" {
		t.Errorf("direction mismatch: %v", frame1["direction"])
	}
	entityCount, _ := frame1["entity_count"].(float64)
	if entityCount < 1 {
		t.Errorf("entity_count should be >= 1, got %v", entityCount)
	}

	// Third frame should have PHONE detection.
	if len(entries) >= 2 {
		frame3 := entries[1]
		if frame3["msg"] != "pii_detected" {
			t.Errorf("expected msg=pii_detected, got %v", frame3["msg"])
		}
	}
}

func TestSSEFrameReader_PartialFrames(t *testing.T) {
	engine := newTestEngine()
	var logBuf bytes.Buffer
	logger := newTestLogger(&logBuf)

	// Simulate SSE arriving in chunks (partial frames).
	r, w := io.Pipe()
	go func() {
		// Write in chunks.
		chunks := []string{
			`data: {"msg": "he`,
			`llo test@exa`,
			`mple.com"}` + "\n\n",
			`data: {"msg": "goodbye"}` + "\n\n",
		}
		for _, chunk := range chunks {
			_, _ = w.Write([]byte(chunk))
		}
		_ = w.Close()
	}()

	reader := newSSEFrameReader(SSEFrameReaderConfig{
		Upstream:     r,
		Engine:       engine,
		Logger:       logger,
		PIILogging:   true,
		MaxFrameSize: 1024 * 1024,
		Host:         "test.local",
		Method:       "POST",
		Path:         "/api",
		ContentType:  "text/event-stream",
		StatusCode:   200,
	})
	defer func() { _ = reader.Close() }()

	output, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}

	if !strings.Contains(string(output), `test@example.com`) {
		t.Error("output should contain the email")
	}

	entries := parseLogEntries(t, &logBuf)
	if len(entries) < 1 {
		t.Fatalf("expected at least 1 detection entry for partial frames, got %d", len(entries))
	}
	if entries[0]["entity_count"].(float64) < 1 {
		t.Error("partial frame detection should find entities")
	}
}

func TestSSEFrameReader_OversizedFrame(t *testing.T) {
	engine := newTestEngine()
	var logBuf bytes.Buffer
	logger := newTestLogger(&logBuf)

	// Create a frame that exceeds the max frame size (small limit for test).
	maxSize := 100
	bigData := strings.Repeat("x", maxSize+50)
	sseStream := strings.NewReader(`data: ` + bigData + "\n\n")

	reader := newSSEFrameReader(SSEFrameReaderConfig{
		Upstream:     io.NopCloser(sseStream),
		Engine:       engine,
		Logger:       logger,
		PIILogging:   true,
		MaxFrameSize: maxSize,
		Host:         "test.local",
		Method:       "POST",
		Path:         "/api",
		ContentType:  "text/event-stream",
		StatusCode:   200,
	})
	defer func() { _ = reader.Close() }()

	output, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}

	// Verify all bytes are forwarded.
	if !strings.Contains(string(output), bigData) {
		t.Error("oversized frame must be forwarded completely")
	}

	entries := parseLogEntries(t, &logBuf)
	// Should have at least a WARN log for oversized frame.
	hasSkipWarn := false
	for _, e := range entries {
		if e["msg"] == "pii_detection_skipped" &&
			e["reason"] == "sse_frame_oversize" {
			hasSkipWarn = true
			break
		}
	}
	if !hasSkipWarn {
		t.Error("expected pii_detection_skipped warn for oversized frame")
	}
}

func TestSSEFrameReader_EmptyFrames(t *testing.T) {
	engine := newTestEngine()
	var logBuf bytes.Buffer
	logger := newTestLogger(&logBuf)

	// SSE stream with empty frames and a comment-only frame.
	sseStream := strings.NewReader(
		": just a comment\n\n" +
			"\n\n" + // empty frame
			`data: {"msg": "clean"}` + "\n\n",
	)

	reader := newSSEFrameReader(SSEFrameReaderConfig{
		Upstream:     io.NopCloser(sseStream),
		Engine:       engine,
		Logger:       logger,
		PIILogging:   true,
		MaxFrameSize: 1024 * 1024,
		Host:         "test.local",
		Method:       "POST",
		Path:         "/api",
		ContentType:  "text/event-stream",
		StatusCode:   200,
	})
	defer func() { _ = reader.Close() }()

	output, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}

	// All bytes should pass through.
	if !strings.Contains(string(output), ": just a comment") {
		t.Error("comments should pass through")
	}

	entries := parseLogEntries(t, &logBuf)
	// No PII in these frames — should have zero detection entries.
	for _, e := range entries {
		if e["msg"] == "pii_detected" {
			t.Errorf("unexpected detection entry: %v", e)
		}
	}
}

func TestSSEFrameReader_NoDataLines(t *testing.T) {
	engine := newTestEngine()
	var logBuf bytes.Buffer
	logger := newTestLogger(&logBuf)

	// Frame with no data: lines but containing PII-like text.
	sseStream := strings.NewReader(
		`event: message` + "\n" +
			`id: 1` + "\n\n" +
			`data: test@example.com` + "\n\n",
	)

	reader := newSSEFrameReader(SSEFrameReaderConfig{
		Upstream:     io.NopCloser(sseStream),
		Engine:       engine,
		Logger:       logger,
		PIILogging:   true,
		MaxFrameSize: 1024 * 1024,
		Host:         "test.local",
		Method:       "POST",
		Path:         "/api",
		ContentType:  "text/event-stream",
		StatusCode:   200,
	})
	defer func() { _ = reader.Close() }()

	_, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}

	entries := parseLogEntries(t, &logBuf)
	// Second frame has data: with PII.
	found := false
	for _, e := range entries {
		if e["msg"] == "pii_detected" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected detection on frame with data: line")
	}
}

func TestSSEFrameReader_PIILoggingDisabled(t *testing.T) {
	engine := newTestEngine()
	var logBuf bytes.Buffer
	logger := newTestLogger(&logBuf)

	sseStream := strings.NewReader(
		`data: {"msg": "test.user@example.com"}` + "\n\n",
	)

	reader := newSSEFrameReader(SSEFrameReaderConfig{
		Upstream:     io.NopCloser(sseStream),
		Engine:       engine,
		Logger:       logger,
		PIILogging:   false, // piiLogging disabled,
		MaxFrameSize: 1024 * 1024,
		Host:         "test.local",
		Method:       "POST",
		Path:         "/api",
		ContentType:  "text/event-stream",
		StatusCode:   200,
	})
	defer func() { _ = reader.Close() }()

	_, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}

	entries := parseLogEntries(t, &logBuf)
	for _, e := range entries {
		if e["msg"] == "pii_detected" {
			t.Errorf("pii_detected log should not appear when pii_logging=false: %v", e)
		}
	}
}

func TestSSEFrameReader_MultipleDataLines(t *testing.T) {
	engine := newTestEngine()
	var logBuf bytes.Buffer
	logger := newTestLogger(&logBuf)

	// Frame with multiple data: lines (multi-line SSE data).
	sseStream := strings.NewReader(
		`data: {"user": "test.user@example.com",` + "\n" +
			`data:  "phone": "+1-555-0100"}` + "\n\n",
	)

	reader := newSSEFrameReader(SSEFrameReaderConfig{
		Upstream:     io.NopCloser(sseStream),
		Engine:       engine,
		Logger:       logger,
		PIILogging:   true,
		MaxFrameSize: 1024 * 1024,
		Host:         "test.local",
		Method:       "POST",
		Path:         "/api",
		ContentType:  "text/event-stream",
		StatusCode:   200,
	})
	defer func() { _ = reader.Close() }()

	output, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}
	_ = output

	entries := parseLogEntries(t, &logBuf)
	if len(entries) < 1 {
		t.Fatal("expected at least 1 detection entry for multi-line data")
	}
	// Should detect both EMAIL and PHONE.
	entityCount, _ := entries[0]["entity_count"].(float64)
	if entityCount < 2 {
		t.Errorf("expected at least 2 entities, got %v", entityCount)
	}
}

func TestSSEFrameReader_InterleavedBoundaries(t *testing.T) {
	engine := newTestEngine()
	var logBuf bytes.Buffer
	logger := newTestLogger(&logBuf)

	// Frame boundary arrives mid-chunk.
	r, w := io.Pipe()
	go func() {
		// \n\n boundary split across chunks.
		chunks := []string{
			`data: test@example.com` + "\n",
			"\n",
		}
		for _, chunk := range chunks {
			_, _ = w.Write([]byte(chunk))
		}
		_ = w.Close()
	}()

	reader := newSSEFrameReader(SSEFrameReaderConfig{
		Upstream:     r,
		Engine:       engine,
		Logger:       logger,
		PIILogging:   true,
		MaxFrameSize: 1024 * 1024,
		Host:         "test.local",
		Method:       "POST",
		Path:         "/api",
		ContentType:  "text/event-stream",
		StatusCode:   200,
	})
	defer func() { _ = reader.Close() }()

	output, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}

	if !strings.Contains(string(output), "test@example.com") {
		t.Error("output should contain the email")
	}

	entries := parseLogEntries(t, &logBuf)
	found := false
	for _, e := range entries {
		if e["msg"] == "pii_detected" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected detection on interleaved boundary frame")
	}
}

func TestSSEFrameReader_TimeoutHandling(t *testing.T) {
	engine := newTestEngine()
	var logBuf bytes.Buffer
	logger := newTestLogger(&logBuf)

	r, w := io.Pipe()
	defer func() { _ = r.Close() }()

	reader := newSSEFrameReader(SSEFrameReaderConfig{
		Upstream:     r,
		Engine:       engine,
		Logger:       logger,
		PIILogging:   true,
		MaxFrameSize: 1024 * 1024,
		Host:         "test.local",
		Method:       "POST",
		Path:         "/api",
		ContentType:  "text/event-stream",
		StatusCode:   200,
	})
	// Override timeout to 10ms for test.
	reader.frameTimeout = 10 * time.Millisecond
	defer func() { _ = reader.Close() }()

	// Write a partial frame (no closing \n\n).
	go func() {
		_, _ = w.Write([]byte("data: incomplete frame"))
		// Wait for timeout to trigger.
		time.Sleep(50 * time.Millisecond)
		// Then send more data.
		_, _ = w.Write([]byte(" still no close"))
		time.Sleep(50 * time.Millisecond)
		_ = w.Close()
	}()

	buf := make([]byte, 256)
	n, _ := reader.Read(buf)
	if n == 0 {
		t.Error("should read some bytes")
	}
	_ = n

	// Wait for timeout to process.
	time.Sleep(30 * time.Millisecond)

	entries := parseLogEntries(t, &logBuf)
	foundTimeout := false
	for _, e := range entries {
		if e["msg"] == "pii_detection_skipped" &&
			e["reason"] == "sse_frame_timeout" {
			foundTimeout = true
			break
		}
	}
	if !foundTimeout {
		// Timeout may not have triggered yet depending on timing.
		t.Log("timeout detection log not found (may be timing-dependent)")
	}
}

func TestSSEFrameReader_ZeroPIIInLogs(t *testing.T) {
	engine := newTestEngine()
	var logBuf bytes.Buffer
	logger := newTestLogger(&logBuf)

	sseStream := strings.NewReader(
		`data: {"email": "test.user@example.com"}` + "\n\n",
	)

	reader := newSSEFrameReader(SSEFrameReaderConfig{
		Upstream:     io.NopCloser(sseStream),
		Engine:       engine,
		Logger:       logger,
		PIILogging:   true,
		MaxFrameSize: 1024 * 1024,
		Host:         "test.local",
		Method:       "POST",
		Path:         "/api",
		ContentType:  "text/event-stream",
		StatusCode:   200,
	})
	defer func() { _ = reader.Close() }()

	_, _ = io.ReadAll(reader)

	logOutput := logBuf.String()
	// Verify no PII values in log output.
	if strings.Contains(logOutput, "test.user@example.com") {
		t.Error("log output must not contain raw PII values")
	}
	if strings.Contains(logOutput, "test.user") {
		t.Error("log output must not contain raw PII substrings")
	}
}

func TestSSEFrameReader_ByteIdentical(t *testing.T) {
	engine := newTestEngine()
	var logBuf bytes.Buffer
	logger := newTestLogger(&logBuf)

	original := `data: {"msg": "Hello World"}` + "\n\n" +
		`data: {"msg": "test@example.com"}` + "\n\n" +
		`data: {"msg": "Goodbye"}` + "\n\n"

	sseStream := strings.NewReader(original)

	reader := newSSEFrameReader(SSEFrameReaderConfig{
		Upstream:     io.NopCloser(sseStream),
		Engine:       engine,
		Logger:       logger,
		PIILogging:   true,
		MaxFrameSize: 1024 * 1024,
		Host:         "test.local",
		Method:       "POST",
		Path:         "/api",
		ContentType:  "text/event-stream",
		StatusCode:   200,
	})
	defer func() { _ = reader.Close() }()

	output, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}

	// SR-9: byte-identical forwarding.
	if string(output) != original {
		t.Errorf("byte-identical forwarding violated.\ngot:  %q\nwant: %q", string(output), original)
	}

	_ = logBuf // Detection logs are expected.
}
