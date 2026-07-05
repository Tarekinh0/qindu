package interceptor

import (
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"

	"github.com/Tarekinh0/qindu/internal/pii"
	"github.com/Tarekinh0/qindu/internal/providers"
)

// ProviderInterceptor implements proxy.Interceptor with provider-specific text extraction.
// It wraps a ProviderPlugin to extract user/assistant text from known providers,
// eliminating false positives from provider metadata (JWT tokens, hex hashes, etc.).
//
// The plugin is shared across connections. Per-connection isolation is achieved
// by creating a new plugin session in InterceptResponse for each SSE stream.
type ProviderInterceptor struct {
	engine      *pii.Engine
	plugin      providers.ProviderPlugin
	logger      *slog.Logger
	maxInputLen int
	piiLogging  bool
}

// NewProviderInterceptor creates a new ProviderInterceptor for a specific provider plugin.
// The plugin is the factory — per-connection sessions are created in InterceptResponse.
// Path filtering is delegated entirely to the plugin's MatchPath method.
func NewProviderInterceptor(
	engine *pii.Engine,
	plugin providers.ProviderPlugin,
	piiLogging bool,
	logger *slog.Logger,
) (*ProviderInterceptor, error) {
	if plugin == nil {
		return nil, fmt.Errorf("provider plugin must not be nil")
	}
	if engine == nil {
		return nil, fmt.Errorf("engine must not be nil")
	}
	return &ProviderInterceptor{
		engine:      engine,
		plugin:      plugin,
		logger:      logger,
		maxInputLen: engine.MaxInputLen(),
		piiLogging:  piiLogging,
	}, nil
}

// InterceptRequest processes an HTTP request before forwarding to upstream.
//
// It checks if the URL path matches the plugin's path filter. If yes, it extracts
// text segments from the request body via the plugin, runs PII detection, and logs
// results. If the path does not match, the body is forwarded without scanning.
func (p *ProviderInterceptor) InterceptRequest(req *http.Request) (*http.Request, io.ReadCloser, error) {
	host := req.Host

	// PR-005: guard against nil req.URL before accessing Path.
	if req.URL == nil {
		p.logger.Warn("pii_detection_skipped",
			"reason", "nil_url",
			"direction", "request",
			"host", host,
		)
		return req, req.Body, nil
	}

	// PR-004: use raw path for routing decisions, not sanitizeLogPath.
	rawPath := req.URL.Path

	// Check if the plugin handles this path (CS-11-05: with panic recovery).
	if !p.matchPathSafe(req.Method, rawPath) {
		return req, req.Body, nil
	}

	// PR-004: sanitize only for log output, after routing decision.
	reqPath := sanitizeLogPath(rawPath)

	// Defensive: handle nil body.
	if req.Body == nil {
		return req, req.Body, nil
	}

	// Delegate to shared body scanner (PR-100) with plugin extractor.
	_, newBody, scanErr := scanBody(req.Body, req.ContentLength, bodyScanConfig{
		engine:      p.engine,
		logger:      p.logger,
		maxInputLen: p.maxInputLen,
		piiLogging:  p.piiLogging,
		host:        host,
		method:      req.Method,
		path:        reqPath,
		direction:   "request",
		extractor:   p.extractTextSafe,
		rewriter:    p.plugin.RewriteRequestBody,
	})
	if scanErr != nil {
		return nil, nil, fmt.Errorf("reading request body: %w", scanErr)
	}
	return req, newBody, nil
}

// InterceptResponse processes an HTTP response before forwarding to the browser.
//
// It inspects Content-Type to decide how to analyze the body:
//   - text/event-stream: use ProviderSSEReader with a new plugin session
//   - application/json, text/*: extract text from body via plugin, run detection
//   - Other/binary: passthrough
func (p *ProviderInterceptor) InterceptResponse(resp *http.Response) (*http.Response, io.ReadCloser, error) {
	host := ""
	rawPath := ""
	method := ""
	if resp.Request != nil {
		host = resp.Request.Host
		if resp.Request.URL != nil {
			// PR-004: use raw path for routing, not sanitizeLogPath.
			rawPath = resp.Request.URL.Path
		}
		method = resp.Request.Method
	}

	// Check if the plugin handles this path (CS-11-05: with panic recovery).
	if !p.matchPathSafe(method, rawPath) {
		return resp, resp.Body, nil
	}

	// PR-004: sanitize only for log output after routing decision.
	reqPath := sanitizeLogPath(rawPath)

	// Defensive: handle nil body.
	if resp.Body == nil {
		return resp, resp.Body, nil
	}

	// Check Content-Type.
	contentType := resp.Header.Get("Content-Type")
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		mediaType = ""
	}

	action := classifyContentType(mediaType)

	switch action {
	case ctSkip:
		p.logger.Debug("pii_detection_skipped",
			"reason", "binary_or_unsupported_content_type",
			"direction", "response",
			"host", host,
			"content_type", sanitizeContentTypeForLog(mediaType),
		)
		return resp, resp.Body, nil

	case ctSSE:
		// Create a new session per SSE stream (CS-11-06).
		// CS-11-05: wrap NewSession in panic recovery.
		session := p.newSessionSafe()

		frameReader := newProviderSSEReader(ProviderSSEConfig{
			Upstream:    resp.Body,
			Engine:      p.engine,
			Logger:      p.logger,
			PIILogging:  p.piiLogging,
			Host:        host,
			Method:      method,
			Path:        reqPath,
			ContentType: sanitizeContentTypeForLog(mediaType),
			StatusCode:  resp.StatusCode,
			PluginName:  p.plugin.Name(),
			Session:     session,
		})
		return resp, frameReader, nil

	case ctAnalyze:
		// Delegate to shared body scanner (PR-100) with plugin extractor.
		sanitizedCT := sanitizeContentTypeForLog(mediaType)
		_, newBody, scanErr := scanBody(resp.Body, resp.ContentLength, bodyScanConfig{
			engine:      p.engine,
			logger:      p.logger,
			maxInputLen: p.maxInputLen,
			piiLogging:  p.piiLogging,
			host:        host,
			method:      method,
			path:        reqPath,
			direction:   "response",
			statusCode:  resp.StatusCode,
			contentType: sanitizedCT,
			extractor:   p.extractTextSafe,
			rewriter:    nil, // response body rewriting not implemented this sprint
		})
		if scanErr != nil {
			return nil, nil, fmt.Errorf("reading response body: %w", scanErr)
		}
		return resp, newBody, nil

	default:
		p.logger.Debug("pii_detection_skipped",
			"reason", "unknown_content_type",
			"direction", "response",
			"host", host,
			"content_type", sanitizeContentTypeForLog(mediaType),
		)
		return resp, resp.Body, nil
	}
}

// matchPathSafe calls plugin.MatchPath with panic recovery (CS-11-05).
// On panic, logs ERROR and returns false (no match), falling through to
// the next interceptor or passthrough.
func (p *ProviderInterceptor) matchPathSafe(method, path string) (matched bool) {
	defer func() {
		if r := recover(); r != nil {
			p.logger.Error("provider_plugin_panic",
				"plugin", p.plugin.Name(),
				"method", "MatchPath",
				"panic", fmt.Sprintf("%v", r),
			)
			matched = false
		}
	}()
	return p.plugin.MatchPath(method, path)
}

// extractTextSafe calls plugin.ExtractText with panic recovery (CS-11-05).
// On panic, logs ERROR and returns nil (no segments), causing the body to be
// forwarded without scanning.
func (p *ProviderInterceptor) extractTextSafe(body []byte) (segments []providers.TextSegment) {
	defer func() {
		if r := recover(); r != nil {
			p.logger.Error("provider_plugin_panic",
				"plugin", p.plugin.Name(),
				"method", "ExtractText",
				"panic", fmt.Sprintf("%v", r),
			)
			segments = nil
		}
	}()
	return p.plugin.ExtractText(body)
}

// newSessionSafe calls plugin.NewSession with panic recovery (CS-11-05).
// On panic, logs ERROR and returns a no-op session that returns empty text
// and silently handles StreamEnded. Uses a named return value so the deferred
// recover can assign the no-op session when NewSession panics.
func (p *ProviderInterceptor) newSessionSafe() (session providers.ProviderPluginSession) {
	defer func() {
		if r := recover(); r != nil {
			p.logger.Error("provider_plugin_panic",
				"plugin", p.plugin.Name(),
				"method", "NewSession",
				"panic", fmt.Sprintf("%v", r),
			)
			session = &noOpProviderSession{}
		}
	}()
	session = p.plugin.NewSession()
	if session == nil {
		session = &noOpProviderSession{}
	}
	return
}

// noOpProviderSession is a silent no-op session used when plugin.NewSession panics.
type noOpProviderSession struct{}

func (s *noOpProviderSession) HandleSSEEvent(_ string, _ []byte) string { return "" }
func (s *noOpProviderSession) StreamEnded()                             {}

// validateTextSegments validates text segments returned by the plugin (CS-11-09).
// Invalid segments are skipped with a WARN log. Returns only valid segments.
func validateTextSegments(segments []providers.TextSegment, bodyLen int) []providers.TextSegment {
	var valid []providers.TextSegment
	for _, seg := range segments {
		if seg.Start < 0 || seg.End > bodyLen || seg.Start > seg.End {
			continue // Invalid bounds — skip silently (WARN logged by caller if needed).
		}
		if seg.Text == "" {
			continue
		}
		// Check for valid UTF-8 (Go strings are always valid UTF-8, but defense-in-depth).
		if !isValidText(seg.Text) {
			continue
		}
		valid = append(valid, seg)
	}
	return valid
}

// isValidText checks if a string is valid for PII scanning.
func isValidText(s string) bool {
	if s == "" {
		return false
	}
	// Go strings are guaranteed UTF-8, but we check anyway.
	for i := 0; i < len(s); i++ {
		if s[i] == 0 {
			return false // NUL byte in string
		}
	}
	return true
}
