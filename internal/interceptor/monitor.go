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
	"github.com/Tarekinh0/qindu/internal/providers"
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
	engine      *pii.Engine
	logger      *slog.Logger
	scanPaths   []string
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

	// Delegate to shared body scanner (PR-100).
	_, newBody, scanErr := scanBody(req.Body, req.ContentLength, bodyScanConfig{
		engine:      m.engine,
		logger:      m.logger,
		maxInputLen: m.maxInputLen,
		piiLogging:  m.piiLogging,
		host:        host,
		method:      req.Method,
		path:        reqPath,
		direction:   "request",
		// extractor nil → full body scanning (MonitorInterceptor mode).
	})

	if scanErr != nil {
		return nil, nil, fmt.Errorf("reading request body: %w", scanErr)
	}

	return req, newBody, nil
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
		// Delegate to shared body scanner (PR-100).
		sanitizedCT := sanitizeContentTypeForLog(mediaType)
		_, newBody, scanErr := scanBody(resp.Body, resp.ContentLength, bodyScanConfig{
			engine:      m.engine,
			logger:      m.logger,
			maxInputLen: m.maxInputLen,
			piiLogging:  m.piiLogging,
			host:        host,
			method:      method,
			path:        path,
			direction:   "response",
			statusCode:  resp.StatusCode,
			contentType: sanitizedCT,
		})
		if scanErr != nil {
			return nil, nil, fmt.Errorf("reading response body: %w", scanErr)
		}
		return resp, newBody, nil

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

// MonitorScanArgs holds all fields for a monitor_scan structured log entry.
// Used by MonitorInterceptor, ProviderInterceptor, SSEFrameReader, and ProviderSSEReader
// to emit identically formatted log entries (PR-101: consolidated from 3 duplicate implementations).
type MonitorScanArgs struct {
	Direction     string
	Result        string
	BytesAnalyzed int
	EntityCount   int
	EntitySummary map[string]int
	PIILogging    bool
	SSEFrame      bool
	Host          string
	Method        string
	Path          string
	StatusCode    int
	ContentType   string
}

// emitMonitorScan emits a single monitor_scan structured log entry.
// Format is shared by all interceptor types (MonitorInterceptor, ProviderInterceptor,
// SSEFrameReader, ProviderSSEReader) to ensure identical log format (CS-11-10).
func emitMonitorScan(logger *slog.Logger, args MonitorScanArgs) {
	argsSlice := []any{
		"direction", args.Direction,
		"result", args.Result,
		"bytes_analyzed", args.BytesAnalyzed,
		"pii_values_logged", false,
	}

	if args.SSEFrame {
		argsSlice = append(argsSlice, "sse_frame", true)
	}

	if args.EntityCount > 0 {
		argsSlice = append(argsSlice, "entity_count", args.EntityCount)
		if args.PIILogging && args.EntitySummary != nil {
			argsSlice = append(argsSlice, "entity_summary", args.EntitySummary)
		}
	}

	if args.Host != "" {
		argsSlice = append(argsSlice, "host", args.Host)
	}
	if args.Method != "" {
		argsSlice = append(argsSlice, "method", args.Method)
	}
	if args.Path != "" {
		argsSlice = append(argsSlice, "path", args.Path)
	}
	if args.StatusCode > 0 {
		argsSlice = append(argsSlice, "status_code", args.StatusCode)
	}
	if args.ContentType != "" {
		argsSlice = append(argsSlice, "content_type", args.ContentType)
	}

	logger.Info("monitor_scan", argsSlice...)
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

// --- Shared body scanner (PR-100: eliminates ~300 lines of duplication
//     between MonitorInterceptor and ProviderInterceptor) ---

// bodyScanConfig holds configuration for the shared body-scanner helper.
type bodyScanConfig struct {
	engine      *pii.Engine
	logger      *slog.Logger
	maxInputLen int
	piiLogging  bool
	host        string
	method      string
	path        string
	direction   string
	statusCode  int
	contentType string
	// extractor returns text segments from body bytes for PII scanning.
	// nil means scan the full body as a single text blob (MonitorInterceptor mode).
	extractor func([]byte) []providers.TextSegment
	// rewriter transforms body bytes for forward compatibility (enforce mode).
	// nil means return body unchanged.
	rewriter func([]byte, []providers.TextSegment) []byte
}

// scanBody performs the full body-read/detect/log workflow shared by both
// MonitorInterceptor and ProviderInterceptor for non-SSE request/response
// body analysis.
//
// It handles Content-Length pre-check, LimitReader consumption, oversize
// detection with combined reader fallback, text extraction, PII detection,
// and monitor_scan log emission.
//
// Returns the detected entities (for caller's optional use) and the
// replacement body reader (which MUST be closed by the caller or the proxy
// framework). On oversize, the returned reader is a combined reader that
// owns the original body's Close; the entities slice will be nil.
func scanBody(body io.ReadCloser, contentLength int64, cfg bodyScanConfig) ([]pii.Entity, io.ReadCloser, error) {
	// Content-Length pre-check (skip detection, forward body untouched).
	if contentLength >= 0 && contentLength > int64(cfg.maxInputLen) {
		cfg.logger.Warn("pii_detection_skipped",
			"reason", "oversize",
			"direction", cfg.direction,
			"host", cfg.host,
			"method", cfg.method,
			"path", cfg.path,
			"content_length", contentLength,
			"bytes_limit", cfg.maxInputLen,
		)
		return nil, body, nil
	}

	result := readBodyBytes(body, cfg.maxInputLen)
	if result.err != nil {
		return nil, nil, result.err
	}

	if result.oversize {
		cfg.logger.Warn("pii_detection_skipped",
			"reason", "oversize",
			"direction", cfg.direction,
			"host", cfg.host,
			"method", cfg.method,
			"path", cfg.path,
			"bytes_limit", cfg.maxInputLen,
		)
		return nil, result.combined, nil
	}

	bodyBytes := result.bodyBytes
	if bodyBytes == nil {
		return nil, io.NopCloser(bytes.NewReader(nil)), nil
	}

	// Extract text segments: use configured extractor, or fall back to full body.
	var segments []providers.TextSegment
	if cfg.extractor != nil {
		segments = cfg.extractor(bodyBytes)
	} else {
		// MonitorInterceptor mode: scan full body as a single segment.
		segments = []providers.TextSegment{
			{Start: 0, End: len(bodyBytes), Text: string(bodyBytes)},
		}
	}

	// Validate segments (CS-11-09).
	totalSegments := len(segments)
	segments = validateTextSegments(segments, len(bodyBytes))
	if dropped := totalSegments - len(segments); dropped > 0 {
		cfg.logger.Warn("text_segments_filtered",
			"reason", "invalid_segment_bounds_or_content",
			"direction", cfg.direction,
			"host", cfg.host,
			"dropped", dropped,
			"valid", len(segments),
			"total", totalSegments,
		)
	}

	// Run PII detection on extracted segments.
	var allEntities []pii.Entity
	for _, seg := range segments {
		entities, detectErr := detectWithEngine(cfg.engine, seg.Text)
		if detectErr != nil {
			cfg.logger.Warn("pii_detection_skipped",
				"reason", "engine_error",
				"direction", cfg.direction,
				"host", cfg.host,
				"method", cfg.method,
				"path", cfg.path,
				"error", detectErr.Error(),
			)
			continue
		}
		allEntities = append(allEntities, entities...)
	}

	// Emit monitor_scan log entry (identical format for both interceptors).
	emitMonitorScan(cfg.logger, MonitorScanArgs{
		Direction:     cfg.direction,
		Result:        resultLabel(allEntities),
		BytesAnalyzed: len(bodyBytes),
		EntityCount:   len(allEntities),
		EntitySummary: buildEntitySummaryCond(allEntities, cfg.piiLogging),
		PIILogging:    cfg.piiLogging,
		Host:          cfg.host,
		Method:        cfg.method,
		Path:          cfg.path,
		StatusCode:    cfg.statusCode,
		ContentType:   cfg.contentType,
	})

	// Rewrite body if a rewriter is configured (ProviderInterceptor enforce mode).
	rewritten := bodyBytes
	if cfg.rewriter != nil {
		rewritten = cfg.rewriter(bodyBytes, segments)
	}

	return allEntities, io.NopCloser(bytes.NewReader(rewritten)), nil
}

// resultLabel returns the monitor_scan result label for the given entities.
func resultLabel(entities []pii.Entity) string {
	if len(entities) > 0 {
		return "pii_found"
	}
	return "clean"
}

// buildEntitySummaryCond builds an entity summary map only if piiLogging is enabled.
func buildEntitySummaryCond(entities []pii.Entity, piiLogging bool) map[string]int {
	if !piiLogging || len(entities) == 0 {
		return nil
	}
	return buildEntitySummary(entities)
}

// bodyReadResult holds the outcome of reading and validating a body.
type bodyReadResult struct {
	bodyBytes []byte        // body content (if fits within limit)
	combined  io.ReadCloser // combined reader (if oversize, nil otherwise)
	oversize  bool          // true if body exceeded the limit
	err       error         // fatal I/O error
}

// readBodyBytes reads and validates a request/response body against size limits,
// returning the raw bytes if within limits, or a combined reader if oversize.
//
// After calling, the caller must:
//   - Close the original body ONLY if result.oversize is false AND result.err is nil
//     (the combined reader owns the original body's Close in the oversize case).
//   - NOT close the original body if result.oversize is true (the combined reader
//     will close it).
//
// Must not be used concurrently on the same body.
func readBodyBytes(body io.ReadCloser, maxLen int) bodyReadResult {
	if body == nil {
		return bodyReadResult{bodyBytes: nil}
	}

	limitReader := io.LimitReader(body, int64(maxLen+1))
	bodyBytes, readErr := io.ReadAll(limitReader)
	if readErr != nil {
		_ = body.Close()
		return bodyReadResult{err: fmt.Errorf("reading body: %w", readErr)}
	}

	if len(bodyBytes) > maxLen {
		combinedReader := io.MultiReader(
			bytes.NewReader(bodyBytes),
			body,
		)
		return bodyReadResult{
			combined: &combinedReadCloser{combinedReader, body},
			oversize: true,
		}
	}

	// Body fits — close original since we consumed it all.
	_ = body.Close()
	return bodyReadResult{bodyBytes: bodyBytes}
}

// detectWithEngine runs PII detection on a text string with panic recovery.
// Shared by all interceptor types.
func detectWithEngine(engine *pii.Engine, text string) (entities []pii.Entity, err error) {
	defer func() {
		if r := recover(); r != nil {
			entities = nil
			err = fmt.Errorf("engine panic: %v", r)
		}
	}()
	entities, err = engine.Detect(text)
	return
}

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
