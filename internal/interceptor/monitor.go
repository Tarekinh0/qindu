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
// composed with a still-open upstream body (PR-002).
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
	engine      *pii.Engine
	logger      *slog.Logger
	maxInputLen int
	piiLogging  bool
}

// NewMonitorInterceptor creates a new MonitorInterceptor.
//
// Parameters:
//   - engine: the PII detection engine (shared instance, concurrent-safe)
//   - piiLogging: if false, all PII detection log entries are suppressed
//   - logger: structured JSON logger for detection log output
//
// The engine's max input size is read directly from the engine instance,
// eliminating the redundant parameter (PR-102).
func NewMonitorInterceptor(engine *pii.Engine, piiLogging bool, logger *slog.Logger) *MonitorInterceptor {
	return &MonitorInterceptor{
		engine:      engine,
		logger:      logger,
		maxInputLen: engine.MaxInputLen(),
		piiLogging:  piiLogging,
	}
}

// InterceptRequest processes an HTTP request before forwarding to upstream.
//
// It reads the full request body, runs PII detection, emits a structured log
// entry if entities are found (and pii_logging is enabled), and returns a new
// body reader with the exact same bytes. If the body exceeds the engine limit,
// detection is skipped and the original body is returned unchanged.
func (m *MonitorInterceptor) InterceptRequest(req *http.Request) (*http.Request, io.ReadCloser, error) {
	host := req.Host

	// Defensive: handle nil body.
	if req.Body == nil {
		return req, req.Body, nil
	}

	// Content-Length pre-check before buffering (SR-1).
	if req.ContentLength > int64(m.maxInputLen) {
		m.logger.Warn("pii_detection_skipped",
			"reason", "oversize",
			"direction", "request",
			"host", host,
			"method", req.Method,
			"path", sanitizeLogPath(req.URL.Path),
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
		req.Body.Close()
		return nil, nil, fmt.Errorf("reading request body: %w", readErr)
	}

	// If body exceeded the limit, return combined reader with still-open original body.
	if len(bodyBytes) > m.maxInputLen {
		m.logger.Warn("pii_detection_skipped",
			"reason", "oversize",
			"direction", "request",
			"host", host,
			"method", req.Method,
			"path", sanitizeLogPath(req.URL.Path),
			"bytes_limit", m.maxInputLen,
		)
		// req.Body has been partially consumed (maxInputLen+1 bytes).
		// Remaining bytes are still in req.Body. MultiReader concatenates them.
		// Use combinedReadCloser to propagate Close() to the underlying body (PR-002).
		combinedReader := io.MultiReader(
			bytes.NewReader(bodyBytes),
			req.Body,
		)
		return req, &combinedReadCloser{combinedReader, req.Body}, nil
	}

	// Body fits within limit — close original body since we consumed it all.
	req.Body.Close()

	// Run detection only when pii_logging is enabled (PR-103).
	var entities []pii.Entity
	if m.piiLogging {
		var detectErr error
		entities, detectErr = m.detect(string(bodyBytes))
		if detectErr != nil {
			m.logger.Warn("pii_detection_skipped",
				"reason", "engine_error",
				"direction", "request",
				"host", host,
				"method", req.Method,
				"path", sanitizeLogPath(req.URL.Path),
				"error", detectErr.Error(),
			)
			return req, io.NopCloser(bytes.NewReader(bodyBytes)), nil
		}
	}

	if len(entities) > 0 {
		m.logDetection(entities, host, "request", req.Method,
			sanitizeLogPath(req.URL.Path), 0, "", len(bodyBytes), false)
	}

	return req, io.NopCloser(bytes.NewReader(bodyBytes)), nil
}

// InterceptResponse processes an HTTP response before forwarding to the browser.
//
// It inspects Content-Type to decide whether to analyze the body, handles SSE
// streams via per-frame detection, and skips binary/non-text content types.
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
		// Create SSE frame reader for per-frame detection.
		// Use the decoupled SSE frame size limit, not the engine input limit (PR-101).
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
		// Content-Length pre-check (SR-1).
		if resp.ContentLength > int64(m.maxInputLen) {
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
			resp.Body.Close()
			return nil, nil, fmt.Errorf("reading response body: %w", readErr)
		}

		if len(bodyBytes) > m.maxInputLen {
			m.logger.Warn("pii_detection_skipped",
				"reason", "oversize",
				"direction", "response",
				"host", host,
				"bytes_limit", m.maxInputLen,
				"content_type", sanitizeContentTypeForLog(mediaType),
			)
			// Use combinedReadCloser to propagate Close() to the underlying body (PR-002).
			combinedReader := io.MultiReader(
				bytes.NewReader(bodyBytes),
				resp.Body,
			)
			return resp, &combinedReadCloser{combinedReader, resp.Body}, nil
		}

		// Body fits — close original since we consumed it all.
		resp.Body.Close()

		// Run detection only when pii_logging is enabled (PR-103).
		var entities []pii.Entity
		if m.piiLogging {
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
		}

		if len(entities) > 0 {
			m.logDetection(entities, host, "response", method,
				path, resp.StatusCode, sanitizeContentTypeForLog(mediaType),
				len(bodyBytes), false)
		}

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

// logDetection emits a structured detection log entry if pii_logging is enabled.
// All fields are PII-free per DPO-R1. When pii_logging is false, this is a no-op.
func (m *MonitorInterceptor) logDetection(
	entities []pii.Entity,
	host, direction, method, path string,
	statusCode int, contentType string,
	bytesAnalyzed int, sseFrame bool,
) {
	if !m.piiLogging {
		return
	}

	args := buildLogEntry(host, direction, method, path,
		statusCode, contentType, entities, bytesAnalyzed, sseFrame)

	m.logger.Info("pii_detected", args...)
}

// --- Shared log entry builders ---

// buildLogEntry constructs the complete log argument slice for detection entries.
// Used by both MonitorInterceptor.logDetection and SSEFrameReader.detectFrame
// to eliminate duplicate metadata-building code (PR-106).
//
// Builds the full args slice: [host, direction, entity_count, entity_summary,
// entities, bytes_analyzed, pii_values_logged, ...method, path, status_code,
// content_type, sse_frame].
func buildLogEntry(host, direction, method, path string, statusCode int,
	contentType string, entities []pii.Entity, bytesAnalyzed int, sseFrame bool,
) []any {
	args := buildEntityLogArgs(entities, bytesAnalyzed, sseFrame)

	// Prepend shared metadata.
	args = append([]any{
		"host", host,
		"direction", direction,
	}, args...)

	// Add HTTP metadata fields when available.
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

	return args
}

// buildEntityLogArgs constructs the entity metadata portion of a detection log entry.
// Used by buildLogEntry to avoid duplication (PR-005, PR-106).
//
// Returns a slice of key-value pairs suitable for slog: [entity_count, entity_summary,
// entities, bytes_analyzed, pii_values_logged, ...sse_frame].
func buildEntityLogArgs(entities []pii.Entity, bytesAnalyzed int, sseFrame bool) []any {
	entitySummary := make(map[string]int)
	entityList := make([]map[string]any, 0, len(entities))

	for _, e := range entities {
		entitySummary[string(e.Type)]++
		entityList = append(entityList, map[string]any{
			"type":       string(e.Type),
			"source":     string(e.Source),
			"confidence": e.Confidence,
			"pos":        fmt.Sprintf("%d-%d", e.Start, e.End),
		})
	}

	args := []any{
		"entity_count", len(entities),
		"entity_summary", entitySummary,
		"entities", entityList,
		"bytes_analyzed", bytesAnalyzed,
		"pii_values_logged", false,
	}

	if sseFrame {
		args = append(args, "sse_frame", true)
	}

	return args
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
// before or at maxLogPathLen (PR-007).
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
