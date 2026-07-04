// Package interceptor provides implementations of the proxy.Interceptor interface
// for PII detection, tokenization, and traffic inspection.
package interceptor

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/Tarekinh0/qindu/internal/pii"
)

// maxLogPathLen is the maximum length for the path field in detection logs.
const maxLogPathLen = 512

// combinedReadCloser wraps an io.Reader and an io.Closer, delegating Read()
// to the reader and Close() to the closer. This ensures proper resource
// lifecycle management on the oversize-body path where a MultiReader is
// composed with a still-open upstream body.
type combinedReadCloser struct {
	io.Reader
	closer io.Closer
}

func (c *combinedReadCloser) Close() error {
	return c.closer.Close()
}

// MonitorInterceptor inspects HTTP bodies for PII using a detection engine,
// logs structured detection results (zero PII values), and forwards all
// traffic unmodified. It implements the proxy.Interceptor interface.
//
// The detection engine is shared across all connections and must be concurrent-safe
// (pii.Engine already handles this via sync.RWMutex).
type MonitorInterceptor struct {
	scanPaths   []string
	engine      *pii.Engine
	logger      *slog.Logger
	maxInputLen int
	piiLogging  bool
}

// NewMonitorInterceptor creates a new MonitorInterceptor.
//
// Returns an error if scanPaths is empty to prevent silent fallback to
// stale defaults. The caller (policy.Config.Validate) guarantees non-empty
// scan paths in production.
//
// Parameters:
//   - engine: the PII detection engine (shared instance, concurrent-safe)
//   - piiLogging: controls whether entity_summary is included in logs; engine still runs
//   - logger: structured JSON logger for detection log output
//   - scanPaths: list of URL path substrings to scan (case-insensitive); paths not
//     matching this whitelist are skipped entirely
func NewMonitorInterceptor(engine *pii.Engine, piiLogging bool, logger *slog.Logger, scanPaths []string) (*MonitorInterceptor, error) {
	if len(scanPaths) == 0 {
		return nil, fmt.Errorf("monitor: scanPaths must be non-empty — config validation guarantees this in production")
	}
	return &MonitorInterceptor{
		engine:      engine,
		logger:      logger,
		maxInputLen: engine.MaxInputLen(),
		piiLogging:  piiLogging,
		scanPaths:   scanPaths,
	}, nil
}

// shouldScanPath returns true if the given URL path matches any configured scan path
// substring (case-insensitive).
func (m *MonitorInterceptor) shouldScanPath(path string) bool {
	lower := strings.ToLower(path)
	for _, sp := range m.scanPaths {
		if strings.Contains(lower, strings.ToLower(sp)) {
			return true
		}
	}
	return false
}

// InterceptRequest processes an HTTP request before forwarding to upstream.
//
// It reads the full request body, runs PII detection, emits a structured log
// entry per message, and returns a new body reader with the exact same bytes.
// If the URL path does not match any configured scan path, the body is forwarded
// without scanning and no log entry is emitted.
// If the body exceeds the engine limit, detection is skipped and the original
// body is returned unchanged (no monitor_scan entry).
func (m *MonitorInterceptor) InterceptRequest(req *http.Request) (*http.Request, io.ReadCloser, error) {
	host := req.Host
	reqPath := sanitizeLogPath(req.URL.Path)

	// Path whitelist check: skip non-conversation endpoints entirely (no scan, no log).
	if !m.shouldScanPath(reqPath) {
		return req, req.Body, nil
	}

	// Defensive: handle nil body.
	if req.Body == nil {
		return req, req.Body, nil
	}

	// Content-Length pre-check before buffering (SR-1). Skip when unknown (chunked: -1).
	if req.ContentLength >= 0 && req.ContentLength > int64(m.maxInputLen) {
		m.logger.Warn("pii_detection_skipped",
			"reason", "oversize",
			"direction", "request",
			"host", host,
			"method", req.Method,
			"path", reqPath,
			"content_length", req.ContentLength,
			"bytes_limit", m.maxInputLen,
		)
		return req, req.Body, nil
	}

	// Read capped body via LimitReader. The original body is NOT closed here —
	// the oversize path needs it still open for MultiReader.
	limitReader := io.LimitReader(req.Body, int64(m.maxInputLen+1))
	bodyBytes, readErr := io.ReadAll(limitReader)
	if readErr != nil {
		_ = req.Body.Close()
		return nil, nil, fmt.Errorf("reading request body: %w", readErr)
	}

	// If body exceeded the limit, return combined reader with still-open original body.
	if len(bodyBytes) > m.maxInputLen {
		m.logger.Warn("pii_detection_skipped",
			"reason", "oversize",
			"direction", "request",
			"host", host,
			"method", req.Method,
			"path", reqPath,
			"bytes_limit", m.maxInputLen,
		)
		// req.Body has been partially consumed (maxInputLen+1 bytes).
		// Remaining bytes are still in req.Body. MultiReader concatenates them.
		// Use combinedReadCloser to propagate Close() to the underlying body.
		combinedReader := io.MultiReader(
			bytes.NewReader(bodyBytes),
			req.Body,
		)
		return req, &combinedReadCloser{combinedReader, req.Body}, nil
	}

	// Body fits within limit — close original body since we consumed it all.
	_ = req.Body.Close()

	// Run detection — engine always runs when path matches (even when pii_logging=false,
	// because we need the result for the monitor_scan entry).
	var entities []pii.Entity
	var detectErr error
	entities, detectErr = m.detect(string(bodyBytes))
	if detectErr != nil {
		m.logger.Warn("pii_detection_skipped",
			"reason", "engine_error",
			"direction", "request",
			"host", host,
			"method", req.Method,
			"path", reqPath,
			"error", detectErr.Error(),
		)
		return req, io.NopCloser(bytes.NewReader(bodyBytes)), nil
	}

	// Always emit a monitor_scan entry per message (Bug 2 fix).
	m.logMonitorScan(entities, host, "request", req.Method, reqPath, 0, "", len(bodyBytes))

	return req, io.NopCloser(bytes.NewReader(bodyBytes)), nil
}

// InterceptResponse processes an HTTP response before forwarding to the browser.
//
// It inspects Content-Type to decide whether to analyze the body, handles SSE
// streams via per-frame detection with aggregated logging, and skips
// binary/non-text content types. If the URL path does not match any configured
// scan path, the body is forwarded without scanning and no log entry is emitted.
// All traffic passes through unmodified.
func (m *MonitorInterceptor) InterceptResponse(resp *http.Response) (*http.Response, io.ReadCloser, error) {
	host := ""
	path := ""
	method := ""
	if resp.Request != nil {
		host = resp.Request.Host
		if resp.Request.URL != nil {
			path = sanitizeLogPath(resp.Request.URL.Path)
		}
		method = resp.Request.Method
	}

	// Path whitelist check: skip non-conversation endpoints entirely (no scan, no log).
	if !m.shouldScanPath(path) {
		return resp, resp.Body, nil
	}

	// Defensive: handle nil body.
	if resp.Body == nil {
		return resp, resp.Body, nil
	}

	// Check Content-Type to determine if we should analyze.
	contentType := resp.Header.Get("Content-Type")
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		mediaType = "" // If parsing fails, treat as unknown (skip).
	}

	// Determine the action based on content type.
	action := classifyContentType(mediaType)

	switch action {
	case ctSkip:
		m.logger.Debug("pii_detection_skipped",
			"reason", "binary_or_unsupported_content_type",
			"direction", "response",
			"host", host,
			"content_type", sanitizeContentTypeForLog(mediaType),
		)
		return resp, resp.Body, nil

	case ctSSE:
		// Create SSE frame reader for per-frame detection with aggregated logging.
		frameReader := newSSEFrameReader(SSEFrameReaderConfig{
			Upstream:     resp.Body,
			Engine:       m.engine,
			Logger:       m.logger,
			PIILogging:   m.piiLogging,
			MaxFrameSize: DefaultMaxSSEFrameSize,
			Host:         host,
			Method:       method,
			Path:         path,
			ContentType:  sanitizeContentTypeForLog(mediaType),
			StatusCode:   resp.StatusCode,
		})
		return resp, frameReader, nil

	case ctAnalyze:
		// Analyze full body (non-streaming text/json).
		// Content-Length pre-check (SR-1). Skip when unknown (chunked: -1).
		if resp.ContentLength >= 0 && resp.ContentLength > int64(m.maxInputLen) {
			m.logger.Warn("pii_detection_skipped",
				"reason", "oversize",
				"direction", "response",
				"host", host,
				"content_length", resp.ContentLength,
				"bytes_limit", m.maxInputLen,
				"content_type", sanitizeContentTypeForLog(mediaType),
			)
			return resp, resp.Body, nil
		}

		// Read capped body without closing the original reader.
		limitReader := io.LimitReader(resp.Body, int64(m.maxInputLen+1))
		bodyBytes, readErr := io.ReadAll(limitReader)
		if readErr != nil {
			_ = resp.Body.Close()
			return nil, nil, fmt.Errorf("reading response body: %w", readErr)
		}

		if len(bodyBytes) > m.maxInputLen {
			oversizeArgs := []any{
				"reason", "oversize",
				"direction", "response",
				"host", host,
				"bytes_limit", m.maxInputLen,
				"content_type", sanitizeContentTypeForLog(mediaType),
			}
			if resp.ContentLength < 0 {
				oversizeArgs = append(oversizeArgs, "content_length_known", false)
			}
			m.logger.Warn("pii_detection_skipped", oversizeArgs...)
			// Use combinedReadCloser to propagate Close() to the underlying body.
			combinedReader := io.MultiReader(
				bytes.NewReader(bodyBytes),
				resp.Body,
			)
			return resp, &combinedReadCloser{combinedReader, resp.Body}, nil
		}

		// Body fits — close original since we consumed it all.
		_ = resp.Body.Close()

		// Run detection — engine always runs when path matches.
		var entities []pii.Entity
		var detectErr error
		entities, detectErr = m.detect(string(bodyBytes))
		if detectErr != nil {
			m.logger.Warn("pii_detection_skipped",
				"reason", "engine_error",
				"direction", "response",
				"host", host,
				"content_type", sanitizeContentTypeForLog(mediaType),
				"error", detectErr.Error(),
			)
			return resp, io.NopCloser(bytes.NewReader(bodyBytes)), nil
		}

		// Always emit a monitor_scan entry per message (Bug 2 fix).
		m.logMonitorScan(entities, host, "response", method,
			path, resp.StatusCode, sanitizeContentTypeForLog(mediaType),
			len(bodyBytes))

		return resp, io.NopCloser(bytes.NewReader(bodyBytes)), nil

	default:
		// Unknown action — skip defensively.
		m.logger.Debug("pii_detection_skipped",
			"reason", "unknown_content_type",
			"direction", "response",
			"host", host,
			"content_type", sanitizeContentTypeForLog(mediaType),
		)
		return resp, resp.Body, nil
	}
}

// detect runs the engine and recovers from panics (SR-16).
// Returns the detected entities and any error. The error is guaranteed to be PII-free.
func (m *MonitorInterceptor) detect(text string) ([]pii.Entity, error) {
	var entities []pii.Entity
	var err error

	func() {
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("engine panic: %v", r)
			}
		}()
		entities, err = m.engine.Detect(text)
	}()

	return entities, err
}

// logMonitorScan emits a single monitor_scan structured log entry per message.
// Every scanned message produces exactly one entry with result "clean" or "pii_found".
// This replaces the old per-detection pii_detected format (Bug 2 fix).
//
// When pii_logging is true: entity_count and entity_summary are included for pii_found.
// When pii_logging is false: entity_count and entity_summary are omitted (privacy).
// pii_values_logged is always false.
func (m *MonitorInterceptor) logMonitorScan(
	entities []pii.Entity,
	host, direction, method, path string,
	statusCode int, contentType string,
	bytesAnalyzed int,
) {
	// Determine result before constructing args to avoid fragile index mutation.
	result := "clean"
	if len(entities) > 0 {
		result = "pii_found"
	}

	args := []any{
		"direction", direction,
		"result", result,
		"bytes_analyzed", bytesAnalyzed,
		"pii_values_logged", false,
	}

	if len(entities) > 0 {
		args = append(args, "entity_count", len(entities))
		if m.piiLogging {
			// Include entity_summary when pii_logging is enabled.
			entitySummary := buildEntitySummary(entities)
			args = append(args, "entity_summary", entitySummary)
		}
	}

	// Add HTTP metadata.
	if host != "" {
		args = append(args, "host", host)
	}
	if method != "" {
		args = append(args, "method", method)
	}
	if path != "" {
		args = append(args, "path", path)
	}
	if statusCode > 0 {
		args = append(args, "status_code", statusCode)
	}
	if contentType != "" {
		args = append(args, "content_type", contentType)
	}

	m.logger.Info("monitor_scan", args...)
}

// buildEntitySummary creates a count map of entity types for log aggregation.
// Used by both MonitorInterceptor.logMonitorScan and SSEFrameReader for the
// aggregated monitor_scan entry.
func buildEntitySummary(entities []pii.Entity) map[string]int {
	summary := make(map[string]int)
	for _, e := range entities {
		summary[string(e.Type)]++
	}
	return summary
}

// --- Content-Type classification ---

type ctAction int

const (
	ctSkip    ctAction = iota // Do not analyze.
	ctAnalyze                 // Analyze full body (non-streaming).
	ctSSE                     // Analyze via SSE frame reader.
)

// classifyContentType determines what action to take for a given media type.
// It applies the content-type decision tree from the story.
func classifyContentType(mediaType string) ctAction {
	if mediaType == "" {
		// Missing Content-Type: skip defensively (DPO-R9).
		return ctSkip
	}

	// text/event-stream: use SSE frame reader.
	if mediaType == "text/event-stream" {
		return ctSSE
	}

	// application/json: analyze.
	if mediaType == "application/json" {
		return ctAnalyze
	}

	// text/* (except text/event-stream, already handled): analyze.
	if strings.HasPrefix(mediaType, "text/") {
		return ctAnalyze
	}

	// Skip binary types.
	skipPrefixes := []string{
		"image/",
		"audio/",
		"video/",
	}
	for _, prefix := range skipPrefixes {
		if strings.HasPrefix(mediaType, prefix) {
			return ctSkip
		}
	}

	if mediaType == "application/octet-stream" {
		return ctSkip
	}
	if mediaType == "multipart/form-data" {
		return ctSkip
	}

	// Any other unknown type: skip defensively.
	return ctSkip
}

// --- Helpers ---

// sanitizeLogPath truncates the URL path to maxLogPathLen bytes (SR-3).
// Truncation is UTF-8 safe: the cut point is at the last valid rune boundary
// before or at maxLogPathLen.
// The input must already be a path-only value (req.URL.Path), without query string.
func sanitizeLogPath(path string) string {
	if len(path) <= maxLogPathLen {
		return path
	}
	// Walk backwards from maxLogPathLen to find a valid rune boundary.
	trunc := maxLogPathLen
	for trunc > 0 && !utf8.RuneStart(path[trunc]) {
		trunc--
	}
	if trunc == 0 {
		return ""
	}
	return path[:trunc]
}

// sanitizeContentTypeForLog extracts only the media type portion (SR-5).
// For "text/plain; charset=utf-8", returns "text/plain".
// If parsing fails, returns the input as-is (PII-safe since Content-Type is metadata).
func sanitizeContentTypeForLog(mediaType string) string {
	if mediaType == "" {
		return mediaType
	}
	// Already parsed by mime.ParseMediaType — just ensure lowercase.
	return strings.ToLower(strings.TrimSpace(mediaType))
}
