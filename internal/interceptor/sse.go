package interceptor

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/Tarekinh0/qindu/internal/pii"
)

// DefaultMaxSSEFrameSize is the default maximum size for SSE frame detection (64 KiB).
// This is decoupled from the engine's max input size (DefaultMaxInputBytes, 1 MiB)
// to allow independent tuning (PR-101).
const DefaultMaxSSEFrameSize = 64 * 1024

// defaultFrameTimeout is the maximum time to wait for a complete SSE frame (SR-7).
const defaultFrameTimeout = 30 * time.Second

// SSEFrameReaderConfig holds all configuration for creating an SSEFrameReader.
// Uses a struct to avoid the 9-positional-parameter constructor anti-pattern (PR-102).
type SSEFrameReaderConfig struct {
	Upstream     io.ReadCloser
	Engine       *pii.Engine
	Logger       *slog.Logger
	PIILogging   bool
	MaxFrameSize int
	Host         string
	Method       string
	Path         string
	ContentType  string
	StatusCode   int
}

// SSEFrameReader wraps an upstream response body and processes SSE frames
// for PII detection on a per-frame basis. Every byte passes through to the
// caller unmodified. Detection runs on a copy of the frame data.
//
// Per-frame processing:
//   - Accumulates bytes until a delimiter is found (LF or CRLF frame boundary)
//   - Extracts data lines from the frame content
//   - Runs PII detection on the extracted text
//   - If entities are found and piiLogging is enabled: emits structured log entry
//   - Frame buffer is reset after processing
//   - If a frame exceeds maxFrameSize: skip detection, WARN, forward bytes, reset
//   - If a frame doesn't complete within frameTimeout: WARN, skip detection, forward, reset
type SSEFrameReader struct {
	upstream     io.ReadCloser
	engine       *pii.Engine
	logger       *slog.Logger
	piiLogging   bool
	maxFrameSize int

	// Frame accumulation buffer.
	frameBuf bytes.Buffer

	// For timeout tracking on incomplete frames.
	frameStartTime time.Time
	frameTimeout   time.Duration
	hasFrameData   bool

	// Metadata for log entries (set at construction time).
	host        string
	method      string
	path        string
	contentType string
	statusCode  int

	// Read buffer for the upstream reader.
	br *bufio.Reader
}

// newSSEFrameReader creates a new SSE frame reader from a configuration struct (PR-102).
func newSSEFrameReader(cfg SSEFrameReaderConfig) *SSEFrameReader {
	return &SSEFrameReader{
		upstream:     cfg.Upstream,
		engine:       cfg.Engine,
		logger:       cfg.Logger,
		piiLogging:   cfg.PIILogging,
		maxFrameSize: cfg.MaxFrameSize,
		frameTimeout: defaultFrameTimeout,
		host:         cfg.Host,
		method:       cfg.Method,
		path:         cfg.Path,
		contentType:  cfg.ContentType,
		statusCode:   cfg.StatusCode,
		br:           bufio.NewReader(cfg.Upstream),
	}
}

// Read reads bytes from the upstream SSE stream, forwards them to the caller,
// and accumulates a copy for per-frame PII detection.
//
// Frame boundaries are detected for both LF (\n\n) and CRLF (\r\n\r\n) line endings.
// On frame boundary, detection runs synchronously on the accumulated frame content
// (after the bytes have been returned to the caller for forwarding).
func (r *SSEFrameReader) Read(p []byte) (int, error) {
	n, err := r.br.Read(p)

	if n > 0 {
		// Start frame timer if this is the first data for a new frame.
		if !r.hasFrameData {
			r.frameStartTime = time.Now()
			r.hasFrameData = true
		}

		// Append to frame accumulator.
		written, writeErr := r.frameBuf.Write(p[:n])
		if writeErr != nil || written != n {
			r.logger.Warn("pii_detection_skipped",
				"reason", "sse_frame_buffer_error",
				"direction", "response",
				"host", r.host,
				"sse_frame", true,
			)
			r.frameBuf.Reset()
			r.hasFrameData = false
			return n, err
		}

		// Check frame size limit (SR-7).
		if r.frameBuf.Len() > r.maxFrameSize {
			r.logger.Warn("pii_detection_skipped",
				"reason", "sse_frame_oversize",
				"direction", "response",
				"host", r.host,
				"bytes_received", r.frameBuf.Len(),
				"bytes_limit", r.maxFrameSize,
				"sse_frame", true,
			)
			r.frameBuf.Reset()
			r.hasFrameData = false
			return n, err
		}

		// Check for frame boundary.
		// Process ALL complete frames, not just the last one.
		content := r.frameBuf.Bytes()
		frameEnd := 0
		for {
			idx, boundaryLen := nextFrameBoundary(content[frameEnd:])
			if idx < 0 {
				break
			}
			frameStart := frameEnd
			frameEnd += idx + boundaryLen

			// Extract complete frame.
			frameData := make([]byte, frameEnd-frameStart)
			copy(frameData, content[frameStart:frameEnd])

			// Run detection on the frame content.
			r.detectFrame(frameData)
		}

		// Remove processed frames from buffer, keeping any remainder.
		if frameEnd > 0 {
			remaining := content[frameEnd:]
			r.frameBuf.Reset()
			if len(remaining) > 0 {
				r.frameBuf.Write(remaining)
				r.hasFrameData = true
			} else {
				r.hasFrameData = false
			}
		} else {
			// No frame boundary found — check timeout (SR-7).
			if r.hasFrameData && time.Since(r.frameStartTime) > r.frameTimeout {
				r.logger.Warn("pii_detection_skipped",
					"reason", "sse_frame_timeout",
					"direction", "response",
					"host", r.host,
					"bytes_received", r.frameBuf.Len(),
					"timeout_seconds", int(r.frameTimeout.Seconds()),
					"sse_frame", true,
				)
				r.frameBuf.Reset()
				r.hasFrameData = false
			}
		}
	}

	// On EOF, flush any remaining partial frame data (DPO-R6: no detection on partial).
	if err == io.EOF && r.frameBuf.Len() > 0 {
		r.logger.Debug("pii_detection_skipped",
			"reason", "sse_partial_frame_on_close",
			"direction", "response",
			"host", r.host,
			"bytes_remaining", r.frameBuf.Len(),
			"sse_frame", true,
		)
		r.frameBuf.Reset()
		r.hasFrameData = false
	}

	return n, err
}

// Close closes the underlying upstream reader.
func (r *SSEFrameReader) Close() error {
	r.frameBuf.Reset()
	r.hasFrameData = false
	return r.upstream.Close()
}

// detectFrame runs PII detection on an SSE frame and logs results if entities are found.
// It extracts data: lines from the frame content before running detection.
// Panics in the engine are recovered regardless of piiLogging flag.
// Detection is gated on piiLogging to avoid wasted CPU (PR-103).
func (r *SSEFrameReader) detectFrame(rawFrame []byte) {
	// Extract text content from SSE data lines.
	frameText := extractSSEData(string(rawFrame))
	if frameText == "" {
		return
	}

	// Skip detection entirely when pii_logging is disabled (PR-103).
	if !r.piiLogging {
		return
	}

	// Run detection with panic recovery.
	// A panic in Engine.Detect must never crash the reader goroutine.
	var entities []pii.Entity
	var detectErr error

	func() {
		defer func() {
			if rec := recover(); rec != nil {
				detectErr = fmt.Errorf("engine panic: %v", rec)
			}
		}()
		entities, detectErr = r.engine.Detect(frameText)
	}()

	if detectErr != nil {
		r.logger.Warn("pii_detection_skipped",
			"reason", "sse_frame_engine_error",
			"direction", "response",
			"host", r.host,
			"error", detectErr.Error(),
			"sse_frame", true,
		)
		return
	}

	if len(entities) == 0 {
		return
	}

	// Build structured log entry using the shared helper (PR-106).
	args := buildLogEntry(r.host, "response", r.method, r.path,
		r.statusCode, r.contentType, entities, len(frameText), true)

	r.logger.Info("pii_detected", args...)
}

// extractSSEData parses SSE frame content and extracts text from data: lines.
// Returns the concatenated text content of all data: lines.
// Returns empty string if no data: lines are found (PR-104: no fallback to raw frame).
//
// SSE format: lines starting with "data:" (with optional leading space) contain
// the payload. Other lines (event:, id:, retry:, comments starting with :) are ignored.
// Multiple data: lines within a frame are joined with newlines.
// Handles both LF (\n) and CRLF (\r\n) line endings (PR-008).
func extractSSEData(rawFrame string) string {
	// Normalize CRLF to LF before splitting.
	normalized := strings.ReplaceAll(rawFrame, "\r\n", "\n")
	lines := strings.Split(normalized, "\n")
	var dataLines []string

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "data:") {
			data := strings.TrimPrefix(trimmed, "data:")
			data = strings.TrimSpace(data)
			dataLines = append(dataLines, data)
		}
	}

	if len(dataLines) == 0 {
		// No data: lines found — return empty string (PR-104).
		// Control frames (comments, event:, id:) have no meaningful PII
		// content and should not be scanned.
		return ""
	}

	return strings.Join(dataLines, "\n")
}

// nextFrameBoundary finds the first occurrence of a frame boundary in the buffer.
// Recognizes both LF (\n\n) and CRLF (\r\n\r\n) delimiters.
// Returns the starting index of the boundary and its length (2 for \n\n, 4 for \r\n\r\n),
// or (-1, 0) if no boundary is found.
func nextFrameBoundary(data []byte) (int, int) {
	// Check LF boundary first (most common).
	if idx := bytes.Index(data, []byte("\n\n")); idx >= 0 {
		// Verify this is not part of a CRLF boundary. If it's \r\n\n, we want
		// to treat it as LF. The \r before \n\n would be part of the previous line.
		return idx, 2
	}

	// Check CRLF boundary.
	if idx := bytes.Index(data, []byte("\r\n\r\n")); idx >= 0 {
		return idx, 4
	}

	return -1, 0
}
