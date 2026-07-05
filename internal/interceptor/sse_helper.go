package interceptor

import (
	"bufio"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Tarekinh0/qindu/internal/pii"
	"github.com/Tarekinh0/qindu/internal/providers"
)

// DefaultMaxProviderSSEFrameSize is the default max frame size for provider SSE (256 KiB).
// Larger than MonitorInterceptor's 64 KiB because JSON Patch frames can be bulkier.
const DefaultMaxProviderSSEFrameSize = 256 * 1024

// defaultProviderFrameTimeout is the default per-frame timeout for provider SSE (30s).
const defaultProviderFrameTimeout = 30 * time.Second

// maxSSEFieldLen is the max length for event:/id: field values (CS-11-08).
const maxSSEFieldLen = 256

// maxSSEEventTypeLen is the max length for event type strings (CS-11-09).
// Note: maxEventTypeLenForLog in internal/providers/chatgpt/plugin.go serves a
// different purpose — it controls log output truncation for event type names,
// while this constant controls input validation in the agnostic SSE layer.
// Both are 128 bytes but operate in different contexts.
const maxSSEEventTypeLen = 128

// maxRetryMs is the max allowed retry value in milliseconds (5 minutes).
const maxRetryMs = 300000

// ProviderSSEConfig holds configuration for creating a ProviderSSEReader.
type ProviderSSEConfig struct {
	Upstream     io.ReadCloser
	Engine       *pii.Engine
	Logger       *slog.Logger
	PIILogging   bool
	MaxFrameSize int
	FrameTimeout time.Duration
	Host         string
	Method       string
	Path         string
	ContentType  string
	StatusCode   int
	PluginName   string
	// Session is the per-connection plugin session for SSE event handling.
	Session providers.ProviderPluginSession
}

// ProviderSSEReader wraps an upstream SSE response body and processes frames
// through a provider plugin for text extraction and PII detection.
//
// It mirrors SSEFrameReader's byte-forwarding pattern but delegates text
// extraction to the plugin instead of using raw extractSSEData().
//
// All bytes pass through unmodified (monitor mode). PII detection runs on
// text extracted by the plugin. Aggregated results are logged at stream end.
//
// Frame accumulation is delegated to the shared sseFrameAccumulator (PR-002).
type ProviderSSEReader struct {
	acc                *sseFrameAccumulator
	upstream           io.ReadCloser
	engine             *pii.Engine
	logger             *slog.Logger
	host               string
	method             string
	path               string
	contentType        string
	pluginName         string
	statusCode         int
	aggregatedSummary  map[string]int
	aggregatedCount    int
	totalBytesAnalyzed int
	piiLogging         bool
	monitorScanEmitted bool
	doneMarkerSeen     bool
	degraded           bool
	sessionEnded       bool
	session            providers.ProviderPluginSession
}

// newProviderSSEReader creates a new ProviderSSEReader from a config struct.
// Uses the shared sseFrameAccumulator for frame buffering and boundary detection (PR-002).
func newProviderSSEReader(cfg ProviderSSEConfig) *ProviderSSEReader {
	timeout := cfg.FrameTimeout
	if timeout <= 0 {
		timeout = defaultProviderFrameTimeout
	}
	maxSize := cfg.MaxFrameSize
	if maxSize <= 0 {
		maxSize = DefaultMaxProviderSSEFrameSize
	}

	br := bufio.NewReader(cfg.Upstream)
	acc := &sseFrameAccumulator{
		br:      br,
		maxSize: maxSize,
		timeout: timeout,
		logger:  cfg.Logger,
		host:    cfg.Host,
		extra:   []any{"provider", cfg.PluginName},
	}

	return &ProviderSSEReader{
		acc:               acc,
		upstream:          cfg.Upstream,
		engine:            cfg.Engine,
		logger:            cfg.Logger,
		piiLogging:        cfg.PIILogging,
		host:              cfg.Host,
		method:            cfg.Method,
		path:              cfg.Path,
		contentType:       cfg.ContentType,
		pluginName:        cfg.PluginName,
		statusCode:        cfg.StatusCode,
		session:           cfg.Session,
		aggregatedSummary: make(map[string]int),
	}
}

// Read reads bytes from the upstream SSE stream, forwards them to the caller,
// and processes complete SSE frames through the provider plugin for PII detection.
//
// Delegates frame accumulation to sseFrameAccumulator.readFrames (PR-002).
// On EOF, flushes partial frame data and emits the aggregated monitor_scan entry.
func (r *ProviderSSEReader) Read(p []byte) (int, error) {
	n, err := r.acc.readFrames(p, func(rawFrame []byte) {
		// Copy frame data to avoid TOCTOU risk if callbacks become async (PR-104).
		frameData := make([]byte, len(rawFrame))
		copy(frameData, rawFrame)

		r.processFrame(frameData)

		if r.doneMarkerSeen && !r.monitorScanEmitted {
			r.emitAndCleanup()
		}
	})

	// On EOF, flush any remaining partial frame and emit aggregated log.
	if err == io.EOF && !r.monitorScanEmitted {
		if r.acc.remainingBytes() > 0 {
			args := []any{
				"reason", "sse_partial_frame_on_close",
				"direction", "response",
				"host", r.host,
				"bytes_remaining", r.acc.remainingBytes(),
				"sse_frame", true,
			}
			args = append(args, r.acc.extra...)
			r.logger.Debug("pii_detection_skipped", args...)
			r.acc.reset()
		}

		r.emitAndCleanup()
	}

	return n, err
}

// emitAndCleanup atomically emits the aggregated monitor_scan and ends the plugin
// session. Both actions are guarded by a single idempotency check to prevent any
// possible inconsistency between the two separate guards (PR-104).
func (r *ProviderSSEReader) emitAndCleanup() {
	if r.monitorScanEmitted {
		return
	}
	r.monitorScanEmitted = true
	if r.session != nil && !r.sessionEnded {
		r.session.StreamEnded()
		r.sessionEnded = true
	}
	r.emitAggregatedMonitorScanLocked()
}

// emitAggregatedMonitorScanLocked emits the monitor_scan without its own
// idempotency check — emitAndCleanup already handles that gate (PR-104).
func (r *ProviderSSEReader) emitAggregatedMonitorScanLocked() {
	result := "clean"
	if r.aggregatedCount > 0 {
		result = "pii_found"
	}

	emitMonitorScan(r.logger, MonitorScanArgs{
		Direction:     "response",
		Result:        result,
		BytesAnalyzed: r.totalBytesAnalyzed,
		EntityCount:   r.aggregatedCount,
		EntitySummary: r.aggregatedSummary,
		PIILogging:    r.piiLogging,
		SSEFrame:      true,
		Host:          r.host,
		Method:        r.method,
		Path:          r.path,
		StatusCode:    r.statusCode,
		ContentType:   r.contentType,
	})
}

// Close closes the underlying upstream reader and cleans up the plugin session.
// Calls StreamEnded() to release the document tree and other mutable state (PR-001).
// Emits the aggregated monitor_scan if not already emitted.
func (r *ProviderSSEReader) Close() error {
	r.acc.reset()
	r.emitAndCleanup()
	return r.upstream.Close()
}

// processFrame parses an SSE frame, extracts text via the plugin, and runs PII detection.
// If the plugin panics, it recovers and falls back to raw-byte forwarding (CS-11-05).
func (r *ProviderSSEReader) processFrame(rawFrame []byte) {
	// Validate UTF-8 before processing (CS-11-02).
	frameStr := string(rawFrame)
	if !utf8.ValidString(frameStr) {
		args := []any{
			"reason", "sse_frame_invalid_utf8",
			"direction", "response",
			"host", r.host,
			"sse_frame", true,
		}
		args = append(args, r.acc.extra...)
		r.logger.Warn("pii_detection_skipped", args...)
		return
	}

	// Parse SSE frame: extract event type and data lines.
	eventType, dataLines := parseSSEFrame(frameStr)

	// Check for [DONE] marker.
	if len(dataLines) > 0 && strings.TrimSpace(strings.Join(dataLines, "")) == "[DONE]" {
		r.doneMarkerSeen = true
		return
	}

	// Validate event type (CS-11-09).
	eventType = validateEventType(eventType)

	var textToScan string

	if r.degraded {
		// Degraded mode: plugin is unreliable; use raw SSE data extraction for all
		// subsequent frames (consistent behavior, PR-102).
		textToScan = extractSSEData(frameStr)
	} else {
		// Join data lines (SSE spec: multiple data: lines are joined with \n).
		dataStr := strings.Join(dataLines, "\n")
		if dataStr == "" {
			return
		}

		dataBytes := []byte(dataStr)

		// Recover from plugin panics (CS-11-05).
		func() {
			defer func() {
				if rec := recover(); rec != nil {
					r.logger.Error("provider_plugin_panic",
						"plugin", r.pluginName,
						"method", "HandleSSEEvent",
						"panic", fmt.Sprintf("%v", rec),
					)
					r.degraded = true
				}
			}()
			textToScan = r.session.HandleSSEEvent(eventType, dataBytes)
		}()

		// If plugin panicked and we degraded, fall back to raw text extraction
		// for this frame (subsequent frames will use the degraded branch above).
		if r.degraded && textToScan == "" {
			textToScan = extractSSEData(frameStr)
		}
	}

	// Validate returned text (CS-11-09).
	textToScan = validateExtractedText(textToScan)

	// Run PII detection on extracted text.
	if textToScan == "" {
		return
	}

	r.totalBytesAnalyzed += len(textToScan)

	// Run detection with panic recovery using simple defer pattern (PR-103).
	entities, detectErr := r.detectFrame(textToScan)
	if detectErr != nil {
		args := []any{
			"reason", "sse_frame_engine_error",
			"direction", "response",
			"host", r.host,
			"error", detectErr.Error(),
			"sse_frame", true,
		}
		args = append(args, r.acc.extra...)
		r.logger.Warn("pii_detection_skipped", args...)
		return
	}

	// Accumulate entity types.
	if len(entities) > 0 {
		for _, e := range entities {
			r.aggregatedSummary[string(e.Type)]++
		}
		r.aggregatedCount += len(entities)
	}
}

// detectFrame runs PII detection on text from an SSE frame with panic recovery.
// Uses simple named-return + defer pattern (PR-103).
func (r *ProviderSSEReader) detectFrame(frameText string) (entities []pii.Entity, err error) {
	defer func() {
		if rec := recover(); rec != nil {
			entities = nil
			err = fmt.Errorf("engine panic: %v", rec)
		}
	}()
	entities, err = r.engine.Detect(frameText)
	return
}

// parseSSEFrame parses a raw SSE frame string and extracts the event type and data lines.
// event type is from the event: line. data lines are from data: lines.
// Returns event type (may be empty) and a slice of data line contents.
func parseSSEFrame(frameStr string) (eventType string, dataLines []string) {
	// Normalize CRLF to LF.
	normalized := strings.ReplaceAll(frameStr, "\r\n", "\n")
	lines := strings.Split(normalized, "\n")

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		// Parse event: line (CS-11-08).
		if strings.HasPrefix(trimmed, "event:") {
			val := strings.TrimSpace(strings.TrimPrefix(trimmed, "event:"))
			// Truncate to max field length.
			if len(val) > maxSSEFieldLen {
				val = val[:maxSSEFieldLen]
			}
			eventType = val
			continue
		}

		// Parse data: line.
		if strings.HasPrefix(trimmed, "data:") {
			data := strings.TrimSpace(strings.TrimPrefix(trimmed, "data:"))
			dataLines = append(dataLines, data)
			continue
		}

		// Parse id: line (CS-11-08) — truncate to max field length.
		if strings.HasPrefix(trimmed, "id:") {
			// id values are metadata only — ignore for detection.
			continue
		}

		// Parse retry: line (CS-11-08) — validate numeric value.
		if strings.HasPrefix(trimmed, "retry:") {
			// retry values are configuration metadata — ignore for detection.
			continue
		}

		// Comments (starting with :) are ignored.
	}

	return eventType, dataLines
}

// validateEventType ensures the event type string meets CS-11-09 requirements.
// Returns the sanitized event type, or empty string if invalid.
func validateEventType(et string) string {
	if et == "" {
		return ""
	}
	if len(et) > maxSSEEventTypeLen {
		et = et[:maxSSEEventTypeLen]
	}
	// Only printable ASCII (space to ~) allowed — strip others.
	var b strings.Builder
	for _, r := range et {
		if r >= 32 && r < 127 {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// validateExtractedText validates text returned by the plugin (CS-11-09).
// Returns the text or empty string if invalid. The caller is responsible for
// ensuring the text length does not exceed the engine's max input length
// (truncation happens at the engine layer, not here).
func validateExtractedText(text string) string {
	if text == "" {
		return ""
	}
	// Check UTF-8 validity.
	if !utf8.ValidString(text) {
		return ""
	}
	return text
}
