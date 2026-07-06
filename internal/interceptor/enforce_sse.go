package interceptor

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"unicode/utf8"

	"github.com/Tarekinh0/qindu/internal/pii"
	"github.com/Tarekinh0/qindu/internal/tokenize"
)

// enforceSSEMaxFrameSize is the maximum SSE frame size for enforce mode (256 KiB).
const enforceSSEMaxFrameSize = 256 * 1024

// enforceSSESlidingBufferSize is the sliding buffer size for reassembling
// tokens split across SSE chunk boundaries. 4KB provides ample margin
// for the largest possible token (<<PRIVATE_KEY_999>> ≈ 30 bytes).
// SR-CISO-4: capped at 4096 bytes.
const enforceSSESlidingBufferSize = 4096

// EnforceSSEConfig holds configuration for creating an EnforceSSEReader.
type EnforceSSEConfig struct {
	Upstream    io.ReadCloser
	Engine      *pii.Engine
	Logger      *slog.Logger
	PIILogging  bool
	Host        string
	Method      string
	Path        string
	ContentType string
	StatusCode  int
	// Tokenizer is the per-connection tokenizer used for Rehydrate().
	// SSE always uses blind rehydration on frame data: payloads (DD-4).
	// ResponseTextExtractor is designed for full JSON response bodies, not
	// SSE data: fragments — never use it in the SSE path (PR-001).
	Tokenizer *tokenize.Tokenizer
}

// EnforceSSEReader wraps an upstream SSE response body and rehydrates
// tokens (<<TYPE_N>>) back to PII values on each frame's data: payload.
//
// It uses a sliding buffer (< 4KB) to reassemble tokens split across
// SSE chunk boundaries (SR-CISO-4, R-004 response mitigation).
//
// All bytes are read from upstream, rehydrated, and written to the caller.
// Frame formatting (event:, data:, etc.) passes through unchanged.
// Only data: payload contents are rehydrated.
//
// Aggregated monitor_scan with rehydrated_count is emitted on stream end.
type EnforceSSEReader struct {
	upstream    io.ReadCloser
	br          *bufio.Reader
	engine      *pii.Engine
	logger      *slog.Logger
	host        string
	method      string
	path        string
	contentType string
	statusCode  int
	tokenizer   *tokenize.Tokenizer
	// Aggregated stats for monitor_scan.
	aggregatedSummary  map[string]int
	aggregatedCount    int
	totalBytesAnalyzed int
	rehydratedCount    int
	piiLogging         bool
	monitorScanEmitted bool
	doneMarkerSeen     bool
	// Sliding buffer for reassembling split tokens (SR-CISO-4).
	slidingBuf []byte
	// Output buffer: modified frames ready to be read by caller.
	outputBuf bytes.Buffer
	// Internal raw accumulator for SSE frame detection.
	rawAccum     bytes.Buffer
	maxFrameSize int
	hasFrameData bool
	// readBuf is a pre-allocated read buffer reused across Read() calls
	// to avoid per-call allocation and GC pressure.
	readBuf []byte
}

// newEnforceSSEReader creates a new EnforceSSEReader from config.
func newEnforceSSEReader(cfg EnforceSSEConfig) *EnforceSSEReader {
	maxSize := enforceSSEMaxFrameSize
	return &EnforceSSEReader{
		upstream:          cfg.Upstream,
		br:                bufio.NewReader(cfg.Upstream),
		engine:            cfg.Engine,
		logger:            cfg.Logger,
		piiLogging:        cfg.PIILogging,
		host:              cfg.Host,
		method:            cfg.Method,
		path:              cfg.Path,
		contentType:       cfg.ContentType,
		statusCode:        cfg.StatusCode,
		tokenizer:         cfg.Tokenizer,
		aggregatedSummary: make(map[string]int),
		slidingBuf:        make([]byte, 0, enforceSSESlidingBufferSize),
		maxFrameSize:      maxSize,
		readBuf:           make([]byte, 4096),
	}
}

// Read reads rehydrated SSE bytes into p.
//
// The enforce SSE reader maintains an output buffer of rehydrated frames.
// On each call, it reads new bytes from upstream, accumulates them, detects
// complete SSE frames, rehydrates tokens in data: payloads, and writes the
// modified frame bytes to the output buffer.
//
// Returns io.EOF when upstream is exhausted and all buffered data has been read.
func (r *EnforceSSEReader) Read(p []byte) (int, error) {
	// 1. Drain output buffer first.
	if r.outputBuf.Len() > 0 {
		return r.outputBuf.Read(p)
	}

	// 2. Read from upstream and process frames until we have output or EOF.
	for r.outputBuf.Len() == 0 {
		n, err := r.br.Read(r.readBuf)
		if n > 0 {
			r.rawAccum.Write(r.readBuf[:n])
			r.hasFrameData = true

			// Check oversize.
			if r.rawAccum.Len() > r.maxFrameSize {
				r.logger.Warn("enforce_sse_frame_oversize",
					"reason", "sse_frame_oversize",
					"direction", "response",
					"host", r.host,
					"bytes_received", r.rawAccum.Len(),
					"bytes_limit", r.maxFrameSize,
					"pii_values_logged", false,
				)
				// Flush raw accumulator as-is (no rehydration possible).
				r.outputBuf.Write(r.rawAccum.Bytes())
				r.rawAccum.Reset()
				r.hasFrameData = false
				continue
			}

			// Process all complete frames in the accumulator.
			r.processCompleteFrames()
		}

		if err == io.EOF {
			// Flush any remaining partial frame data as-is.
			if r.rawAccum.Len() > 0 {
				r.logger.Debug("enforce_sse_partial_frame_on_close",
					"reason", "sse_partial_frame_on_close",
					"direction", "response",
					"host", r.host,
					"bytes_remaining", r.rawAccum.Len(),
					"pii_values_logged", false,
				)
				r.outputBuf.Write(r.rawAccum.Bytes())
				r.rawAccum.Reset()
			}
			if !r.monitorScanEmitted {
				r.emitAndCleanup()
			}
			// Return whatever we have, plus EOF.
			if r.outputBuf.Len() > 0 {
				nout, _ := r.outputBuf.Read(p)
				return nout, io.EOF
			}
			return 0, io.EOF
		}

		if err != nil {
			return 0, err
		}

		// If we have no output after reading, the for loop naturally continues
		// to read more from upstream. We must never return (0, nil) — that
		// violates the io.Reader contract and causes io.Copy to busy-loop.
		//
		// The loop exits when outputBuf has data (via the for condition) or
		// when an error/EOF occurs (handled above).
	}

	// 3. Return from output buffer.
	if r.outputBuf.Len() > 0 {
		return r.outputBuf.Read(p)
	}
	// outputBuf should never be empty here — either we got an error/EOF
	// and returned above, or processCompleteFrames populated outputBuf
	// and the for loop exited. But guard defensively:
	return 0, io.ErrUnexpectedEOF
}

// processCompleteFrames detects frame boundaries in the raw accumulator,
// rehydrates tokens in each complete frame, and writes modified bytes to output.
func (r *EnforceSSEReader) processCompleteFrames() {
	content := r.rawAccum.Bytes()
	frameEnd := 0

	for {
		idx, boundaryLen := nextFrameBoundary(content[frameEnd:])
		if idx < 0 {
			break
		}
		frameStart := frameEnd
		frameEnd += idx + boundaryLen

		// Extract and process the complete frame.
		frameData := content[frameStart:frameEnd]
		modified := r.rehydrateFrame(frameData)

		// Run PII detection on the frame for aggregated logging.
		r.detectFrameForLogging(string(frameData))

		// Write modified frame to output buffer.
		r.outputBuf.Write(modified)
	}

	// Remove processed frames, keep remainder.
	if frameEnd > 0 {
		remaining := make([]byte, len(content)-frameEnd)
		copy(remaining, content[frameEnd:])
		r.rawAccum.Reset()
		if len(remaining) > 0 {
			r.rawAccum.Write(remaining)
		} else {
			r.hasFrameData = false
		}
	}
}

// rehydrateFrame takes raw SSE frame bytes and returns modified bytes
// with tokens in data: payloads rehydrated to original PII values.
// Non-data lines pass through unchanged.
func (r *EnforceSSEReader) rehydrateFrame(rawFrame []byte) []byte {
	frameStr := string(rawFrame)
	if !utf8.ValidString(frameStr) {
		return rawFrame
	}

	// Normalize CRLF to LF.
	normalized := strings.ReplaceAll(frameStr, "\r\n", "\n")
	lines := strings.Split(normalized, "\n")

	var result strings.Builder
	result.Grow(len(rawFrame) + 64)

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(trimmed, "data:") {
			data := strings.TrimSpace(strings.TrimPrefix(trimmed, "data:"))
			// SSE always uses blind rehydration (DD-4). ResponseTextExtractor
			// is for full JSON response bodies only — never for SSE fragments.
			rehydrated := r.rehydrateWithSlidingBuffer(data)
			result.WriteString(fmt.Sprintf("data: %s\n", rehydrated))
		} else if trimmed != "" {
			// Pass through other lines (event:, id:, retry:, comments, etc.).
			result.WriteString(line)
			result.WriteByte('\n')
		}
		// Empty trimmed lines (blank lines within frame) are ignored.
	}

	// PR-002: Restore SSE frame separator — required by the text/event-stream
	// protocol. The browser's EventSource parser requires a blank line (\n\n)
	// between frames to dispatch events. Without this, consecutive frames
	// are treated as a single event and may never fire onmessage.
	result.WriteByte('\n')

	return []byte(result.String())
}

// rehydrateWithSlidingBuffer applies Rehydrate() with sliding buffer support.
//
// The sliding buffer handles tokens split across SSE chunk boundaries.
// If the data ends with a partial token prefix (<<[A-Z_]*), the remainder
// is held in the sliding buffer and prepended to the next chunk.
//
// SR-CISO-4: buffer capped at 4KB. On overflow, buffer is flushed as-is
// and a WARN is logged (pii_values_logged: false). Buffer content is
// NEVER logged.
func (r *EnforceSSEReader) rehydrateWithSlidingBuffer(data string) string {
	// Prepend sliding buffer contents.
	if len(r.slidingBuf) > 0 {
		data = string(r.slidingBuf) + data
		r.slidingBuf = r.slidingBuf[:0]
	}

	// Count tokens before rehydration.
	beforeCount := r.countTokensInString(data)

	// Rehydrate the combined string.
	rehydrated := r.tokenizer.Rehydrate(data)

	// Count tokens after rehydration. Only tokens that were consumed
	// (present before, absent after) are counted as successful rehydrations.
	afterCount := r.countTokensInString(rehydrated)
	r.rehydratedCount += (beforeCount - afterCount)

	// Check for partial token at the end (<< prefix without closing >>).
	lastOpen := strings.LastIndex(data, "<<")
	if lastOpen >= 0 {
		closingIdx := strings.Index(data[lastOpen:], ">>")
		if closingIdx < 0 {
			// No closing >> — partial token at end.
			remainder := data[lastOpen:]
			if len(remainder) > enforceSSESlidingBufferSize {
				// Buffer overflow: flush as-is, log warning (SR-CISO-4).
				r.logger.Warn("enforce_sse_sliding_buffer_overflow",
					"reason", "partial_token_too_large",
					"remainder_len", len(remainder),
					"max_buffer", enforceSSESlidingBufferSize,
					"pii_values_logged", false,
				)
				return rehydrated
			}
			// Store remainder for next chunk.
			r.slidingBuf = append(r.slidingBuf[:0], remainder...)
		}
	}

	return rehydrated
}

// countTokensInString counts <<TYPE_N>> token patterns in a string.
func (r *EnforceSSEReader) countTokensInString(s string) int {
	count := 0
	for i := 0; i < len(s); i++ {
		if i+4 < len(s) && s[i] == '<' && s[i+1] == '<' {
			end := strings.Index(s[i:], ">>")
			if end >= 4 {
				token := s[i : i+end+2]
				if looksLikeToken(token) {
					count++
				}
				i += end + 1
			}
		}
	}
	return count
}

// looksLikeToken returns true if the string looks like a <<TYPE_N>> token.
func looksLikeToken(s string) bool {
	if len(s) < 6 || s[:2] != "<<" || s[len(s)-2:] != ">>" {
		return false
	}
	inner := s[2 : len(s)-2]
	usIdx := strings.LastIndex(inner, "_")
	if usIdx < 1 || usIdx >= len(inner)-1 {
		return false
	}
	typePart := inner[:usIdx]
	for _, c := range typePart {
		if !((c >= 'A' && c <= 'Z') || c == '_') {
			return false
		}
	}
	counterPart := inner[usIdx+1:]
	for _, c := range counterPart {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// detectFrameForLogging runs PII detection on SSE frame text for aggregated
// monitor_scan logging. This is informational only — bytes are already rehydrated.
func (r *EnforceSSEReader) detectFrameForLogging(rawFrame string) {
	frameText := extractSSEData(rawFrame)
	if frameText == "" {
		return
	}

	if strings.TrimSpace(frameText) == "[DONE]" {
		r.doneMarkerSeen = true
		return
	}

	r.totalBytesAnalyzed += len(frameText)

	entities, err := r.engine.Detect(frameText)
	if err != nil {
		return
	}

	for _, e := range entities {
		r.aggregatedSummary[string(e.Type)]++
	}
	r.aggregatedCount += len(entities)
}

// emitAndCleanup atomically emits the aggregated monitor_scan and zeros
// the sliding buffer (SR-CISO-4: zero on close).
func (r *EnforceSSEReader) emitAndCleanup() {
	if r.monitorScanEmitted {
		return
	}
	r.monitorScanEmitted = true

	// Zero the sliding buffer to clear partial PII tokens from memory (SR-CISO-4).
	for i := range r.slidingBuf {
		r.slidingBuf[i] = 0
	}
	r.slidingBuf = nil

	result := "clean"
	if r.aggregatedCount > 0 {
		result = "pii_found"
	}

	args := []any{
		"direction", "response",
		"result", result,
		"bytes_analyzed", r.totalBytesAnalyzed,
		"pii_values_logged", false,
		"sse_frame", true,
	}
	if r.rehydratedCount > 0 {
		args = append(args, "rehydrated_count", r.rehydratedCount)
	}
	if r.aggregatedCount > 0 {
		args = append(args, "entity_count", r.aggregatedCount)
		if r.piiLogging && r.aggregatedSummary != nil {
			args = append(args, "entity_summary", r.aggregatedSummary)
		}
	}
	if r.host != "" {
		args = append(args, "host", r.host)
	}
	if r.method != "" {
		args = append(args, "method", r.method)
	}
	if r.path != "" {
		args = append(args, "path", r.path)
	}
	if r.statusCode > 0 {
		args = append(args, "status_code", r.statusCode)
	}
	if r.contentType != "" {
		args = append(args, "content_type", r.contentType)
	}

	r.logger.Info("monitor_scan", args...)
}

// Close closes the underlying upstream reader and cleans up resources.
// Emits the aggregated monitor_scan if not already emitted.
// Zeros the sliding buffer (SR-CISO-4).
func (r *EnforceSSEReader) Close() error {
	r.rawAccum.Reset()
	r.outputBuf.Reset()
	r.emitAndCleanup()
	return r.upstream.Close()
}
