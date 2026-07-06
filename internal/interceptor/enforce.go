package interceptor

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"strconv"

	"github.com/Tarekinh0/qindu/internal/pii"
	"github.com/Tarekinh0/qindu/internal/providers"
	"github.com/Tarekinh0/qindu/internal/tokenize"
)

// maxBodyReadMargin is the extra bytes allowed when pre-reading body for the
// enforce_transform log beyond maxInputLen. Accounts for the fact that tokenization
// and rehydration can change body sizes (e.g., PII values longer than token patterns).
// PR-002: prevents unbounded memory from io.ReadAll on response/request bodies.
const maxBodyReadMargin = 1024

// EnforceInterceptor implements proxy.Interceptor for the enforce pipeline.
// It tokenizes PII in requests and rehydrates tokens in responses.
//
// Unlike MonitorInterceptor and ProviderInterceptor, EnforceInterceptor actively
// modifies HTTP body bytes: PII → <<TYPE_N>> on request egress, <<TYPE_N>> → PII
// on response ingress.
//
// Fields:
//   - engine: shared PII detection engine
//   - plugin: optional provider plugin for surgical text extraction
//   - logger: structured JSON logger with pii_values_logged: false
//   - piiLogging: controls entity_summary in monitor_scan logs
//   - tokenizeFunc: optional per-connection tokenizer function (read from context)
//   - rehydrateFunc: optional per-connection rehydration function (read from context)
type EnforceInterceptor struct {
	engine      *pii.Engine
	plugin      providers.ProviderPlugin // nil for full-body scanning fallback
	logger      *slog.Logger
	maxInputLen int
	piiLogging  bool
}

// NewEnforceInterceptor creates a new EnforceInterceptor.
func NewEnforceInterceptor(
	engine *pii.Engine,
	plugin providers.ProviderPlugin,
	piiLogging bool,
	logger *slog.Logger,
) (*EnforceInterceptor, error) {
	if engine == nil {
		return nil, fmt.Errorf("engine must not be nil")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &EnforceInterceptor{
		engine:      engine,
		plugin:      plugin,
		logger:      logger,
		maxInputLen: engine.MaxInputLen(),
		piiLogging:  piiLogging,
	}, nil
}

// InterceptRequest tokenizes PII in the request body before forwarding to upstream.
//
// Flow:
//  1. Get tokenizer from request context (fail-closed: return error if missing).
//  2. Path guard: skip non-conversation endpoints (no scan, no tokenization).
//  3. Pre-read request body to measure body_bytes_in.
//  4. Extract text segments (plugin or full-body fallback).
//  5. Tokenize segments via scanBody's tokenize callback.
//  6. Rewrite body via replaceSegments with tokenized segments.
//  7. Log monitor_scan with tokenized_count.
//  8. Emit enforce_transform DEBUG log with entity summary and byte sizes.
//
// Returns 502-level error if tokenizer is missing (fail-closed, never passthrough).
func (e *EnforceInterceptor) InterceptRequest(req *http.Request) (*http.Request, io.ReadCloser, error) {
	// Get tokenizer from context (SR-CISO-10: per-request isolation).
	tokenizer := tokenize.TokenizerFromContext(req.Context())
	if tokenizer == nil {
		// Fail-closed: no tokenizer means PII cannot be tokenized.
		e.logger.Error("enforce_request_rejected",
			"reason", "tokenizer_missing",
			"pii_values_logged", false,
		)
		return nil, nil, fmt.Errorf("enforce: tokenizer not found in request context — connection must be established via handleMITM")
	}

	host := req.Host
	reqPath := sanitizeLogPath(req.URL.Path)

	// Path guard: skip non-conversation endpoints entirely (no scan, no tokenization).
	// This is critical for endpoints like sentinel/challenge paths that contain
	// encrypted payloads — scanning those produces false-positive PII detections
	// and tokenization corrupts the challenge, causing upstream 500 errors.
	// Matches the behavior of ProviderInterceptor which has the same guard.
	if e.plugin != nil && req.URL != nil && !e.matchRequestPath(req.Method, req.URL.Path) {
		return req, req.Body, nil
	}

	// Pre-read request body to measure body_bytes_in for the enforce_transform log.
	// Capped at maxInputLen + margin to bound memory usage (PR-002).
	// The +1024 margin accounts for token/PII length differences in tokenization
	// (longest PII value may exceed longest token pattern).
	// scanBody further caps processing at maxInputLen via LimitReader.
	var bodyBytesIn int
	var bodyReader io.ReadCloser
	if req.Body != nil {
		rawBytes, readErr := io.ReadAll(io.LimitReader(req.Body, int64(e.maxInputLen+maxBodyReadMargin)))
		req.Body.Close()
		if readErr != nil {
			return nil, nil, fmt.Errorf("reading request body: %w", readErr)
		}
		bodyBytesIn = len(rawBytes)
		bodyReader = io.NopCloser(bytes.NewReader(rawBytes))
	} else {
		bodyReader = req.Body
	}

	// Determine extractor: plugin or full-body fallback.
	var extractor func([]byte) []providers.TextSegment
	if e.plugin != nil && req.URL != nil && e.matchRequestPath(req.Method, req.URL.Path) {
		extractor = e.extractTextSafe
	}

	// Tokenize callback: runs detection + tokenization on extracted text segments.
	tokenizeFn := func(segments []providers.TextSegment) []providers.TextSegment {
		for i := range segments {
			tokenized, err := tokenizer.Tokenize(segments[i].Text)
			if err != nil {
				e.logger.Warn("enforce_tokenize_error",
					"reason", "tokenizer_error",
					"error", err.Error(),
					"pii_values_logged", false,
				)
				continue // keep original text on error
			}
			segments[i].Text = tokenized
		}
		return segments
	}

	// Rewriter: replace PII with tokens in the body.
	rewriter := func(body []byte, segments []providers.TextSegment) []byte {
		return replaceSegments(body, segments)
	}

	entities, newBody, scanErr := scanBody(bodyReader, int64(bodyBytesIn), bodyScanConfig{
		engine:      e.engine,
		logger:      e.logger,
		maxInputLen: e.maxInputLen,
		piiLogging:  e.piiLogging,
		host:        host,
		method:      req.Method,
		path:        reqPath,
		direction:   "request",
		extractor:   extractor,
		tokenize:    tokenizeFn,
		rewriter:    rewriter,
	})

	if scanErr != nil {
		return nil, nil, fmt.Errorf("reading request body: %w", scanErr)
	}

	// Buffer the tokenized body to compute the actual length after modification.
	// PII tokenization changes body size (e.g., "test.user@example.com" (21 chars)
	// → "<<EMAIL_1>>" (11 chars)). The Content-Length header and req.ContentLength
	// must match the modified body or Go's HTTP layer rejects the request with
	// "http: ContentLength=N with Body length M".
	tokenizedBytes, readErr := io.ReadAll(newBody)
	newBody.Close()
	if readErr != nil {
		return nil, nil, fmt.Errorf("buffer tokenized body: %w", readErr)
	}

	// AC-5, AC-6: Emit enforce_transform DEBUG log event with entity counts,
	// byte sizes, and pii_values_logged: false. No PII values in the log.
	bodyBytesOut := len(tokenizedBytes)
	e.logger.Debug("enforce_transform",
		"host", host,
		"path", reqPath,
		"detected_count", len(entities),
		"entity_summary", buildEntitySummary(entities),
		"body_bytes_in", bodyBytesIn,
		"body_bytes_out", bodyBytesOut,
		"pii_values_logged", false,
	)

	newLen := int64(len(tokenizedBytes))
	req.ContentLength = newLen
	req.Header.Set("Content-Length", strconv.FormatInt(newLen, 10))
	req.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(tokenizedBytes)), nil
	}

	return req, io.NopCloser(bytes.NewReader(tokenizedBytes)), nil
}

// InterceptResponse rehydrates tokens in the response body before forwarding to the browser.
//
// Flow:
//  1. Get tokenizer from request context (fail-closed).
//  2. For SSE: create enforceSSEReader wrapping the response body.
//  3. For JSON: scan body with rehydrate callback.
//  4. For binary/other: passthrough unchanged.
func (e *EnforceInterceptor) InterceptResponse(resp *http.Response) (*http.Response, io.ReadCloser, error) {
	// Get tokenizer from context (SR-CISO-10: per-request isolation).
	tokenizer := tokenize.TokenizerFromContext(resp.Request.Context())
	if tokenizer == nil {
		e.logger.Error("enforce_response_rejected",
			"reason", "tokenizer_missing",
			"pii_values_logged", false,
		)
		return nil, nil, fmt.Errorf("enforce: tokenizer not found in request context for response")
	}

	host := ""
	rawPath := ""
	method := ""
	if resp.Request != nil {
		host = resp.Request.Host
		if resp.Request.URL != nil {
			rawPath = resp.Request.URL.Path
		}
		method = resp.Request.Method
	}

	if resp.Body == nil {
		return resp, resp.Body, nil
	}

	// Path guard: skip non-conversation endpoints entirely (no scan, no rehydration).
	// See InterceptRequest for detailed rationale.
	// Match against the request URL path since responses follow the same endpoint.
	if e.plugin != nil && resp.Request != nil && resp.Request.URL != nil &&
		!e.matchRequestPath(resp.Request.Method, resp.Request.URL.Path) {
		return resp, resp.Body, nil
	}

	contentType := resp.Header.Get("Content-Type")
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		mediaType = ""
	}

	action := classifyContentType(mediaType)

	switch action {
	case ctSkip:
		e.logger.Debug("pii_detection_skipped",
			"reason", "binary_or_unsupported_content_type",
			"direction", "response",
			"host", host,
			"content_type", sanitizeContentTypeForLog(mediaType),
		)
		return resp, resp.Body, nil

	case ctSSE:
		// SSE always uses blind rehydration (DD-4). ResponseTextExtractor is
		// designed for full JSON response bodies, not streaming data: fragments.
		// Using it on SSE payloads causes silent rehydration failure (PR-001).

		// Create enforce SSE reader for per-frame rehydration with sliding buffer.
		enforceReader := newEnforceSSEReader(EnforceSSEConfig{
			Upstream:    resp.Body,
			Engine:      e.engine,
			Logger:      e.logger,
			PIILogging:  e.piiLogging,
			Host:        host,
			Method:      method,
			Path:        sanitizeLogPath(rawPath),
			ContentType: sanitizeContentTypeForLog(mediaType),
			StatusCode:  resp.StatusCode,
			Tokenizer:   tokenizer,
		})
		return resp, enforceReader, nil

	case ctAnalyze:
		// Pre-read response body to measure body_bytes_in and count tokens
		// before rehydration. This enables the enforce_transform log.
		// Capped at maxInputLen + margin to bound memory usage (PR-002).
		var bodyBytesIn int
		var bodyReader io.ReadCloser
		var tokenCountBefore int
		if resp.Body != nil {
			rawBytes, readErr := io.ReadAll(io.LimitReader(resp.Body, int64(e.maxInputLen+maxBodyReadMargin)))
			resp.Body.Close()
			if readErr != nil {
				return nil, nil, fmt.Errorf("reading response body: %w", readErr)
			}
			bodyBytesIn = len(rawBytes)
			tokenCountBefore = countTokenPatterns(string(rawBytes))
			bodyReader = io.NopCloser(bytes.NewReader(rawBytes))
		} else {
			bodyReader = resp.Body
		}

		// Determine extractor for response text.
		var extractor func([]byte) []providers.TextSegment
		if e.plugin != nil && resp.Request != nil && resp.Request.URL != nil && e.matchRequestPath(resp.Request.Method, resp.Request.URL.Path) {
			// Use ResponseTextExtractor if available (DR-1).
			if rte, ok := e.plugin.(providers.ResponseTextExtractor); ok {
				extractor = rte.ExtractResponseText
			} else {
				e.logger.Warn("enforce_blind_rehydration",
					"reason", "no_response_text_extractor",
					"pii_values_logged", false,
				)
			}
		}

		// Rehydrate callback: blind Rehydrate() on full body (DD-3).
		rehydrateFn := func(body []byte) []byte {
			return []byte(tokenizer.Rehydrate(string(body)))
		}

		sanitizedCT := sanitizeContentTypeForLog(mediaType)
		_, newBody, scanErr := scanBody(bodyReader, int64(bodyBytesIn), bodyScanConfig{
			engine:      e.engine,
			logger:      e.logger,
			maxInputLen: e.maxInputLen,
			piiLogging:  e.piiLogging,
			host:        host,
			method:      method,
			path:        sanitizeLogPath(rawPath),
			direction:   "response",
			statusCode:  resp.StatusCode,
			contentType: sanitizedCT,
			extractor:   extractor,
			rehydrate:   rehydrateFn,
		})
		if scanErr != nil {
			return nil, nil, fmt.Errorf("reading response body: %w", scanErr)
		}

		// Buffer rehydrated body to compute actual length for Content-Length update.
		// Rehydration replaces <<TYPE_N>> tokens with original PII values, which may
		// have different lengths (e.g., "<<EMAIL_1>>" (11 chars) → "user@example.com"
		// (16 chars)). The response Content-Length must reflect the actual body size.
		rehydratedBytes, readErr := io.ReadAll(newBody)
		newBody.Close()
		if readErr != nil {
			return nil, nil, fmt.Errorf("buffer rehydrated body: %w", readErr)
		}

		// Emit enforce_transform DEBUG log with rehydration count (AC-5, AC-6).
		// rehydration_count = tokens found before rehydration that were successfully replaced.
		bodyBytesOut := len(rehydratedBytes)
		e.logger.Debug("enforce_transform",
			"host", host,
			"path", sanitizeLogPath(rawPath),
			"rehydration_count", tokenCountBefore,
			"body_bytes_in", bodyBytesIn,
			"body_bytes_out", bodyBytesOut,
			"pii_values_logged", false,
		)

		newLen := int64(len(rehydratedBytes))
		resp.ContentLength = newLen
		resp.Header.Set("Content-Length", strconv.FormatInt(newLen, 10))

		return resp, io.NopCloser(bytes.NewReader(rehydratedBytes)), nil

	default:
		e.logger.Debug("pii_detection_skipped",
			"reason", "unknown_content_type",
			"direction", "response",
			"host", host,
			"content_type", sanitizeContentTypeForLog(mediaType),
		)
		return resp, resp.Body, nil
	}
}

// ShouldProcess returns true if the EnforceInterceptor will process this request.
// Delegates to matchRequestPath: returns true when plugin is nil (full-body fallback
// processes all paths), or when the provider plugin matches the conversational endpoint.
// The host parameter is ignored — path matching is provider-internal.
func (e *EnforceInterceptor) ShouldProcess(host, method, path string) bool {
	return e.matchRequestPath(method, path)
}

// matchRequestPath returns true if the plugin handles this method+path, or if
// plugin is nil (full-body scanning fallback processes all paths).
// PR-001: Previously returned false for nil-plugin, but InterceptRequest still
// processed bodies — DebugInterceptor's ShouldProcess guard was silently disabled.
func (e *EnforceInterceptor) matchRequestPath(method, path string) bool {
	if e.plugin == nil {
		return true // full-body fallback processes all paths
	}
	return matchPathSafePlugin(e.plugin, e.logger, method, path)
}

// matchPathSafePlugin calls plugin.MatchPath with panic recovery.
func matchPathSafePlugin(plugin providers.ProviderPlugin, logger *slog.Logger, method, path string) (matched bool) {
	defer func() {
		if r := recover(); r != nil {
			logger.Error("provider_plugin_panic",
				"plugin", plugin.Name(),
				"method_name", "MatchPath",
				"panic", fmt.Sprintf("%v", r),
			)
			matched = false
		}
	}()
	return plugin.MatchPath(method, path)
}

// extractTextSafe calls plugin.ExtractText with panic recovery.
func (e *EnforceInterceptor) extractTextSafe(body []byte) (segments []providers.TextSegment) {
	defer func() {
		if r := recover(); r != nil {
			e.logger.Error("provider_plugin_panic",
				"plugin", e.plugin.Name(),
				"method_name", "ExtractText",
				"panic", fmt.Sprintf("%v", r),
			)
			segments = nil
		}
	}()
	return e.plugin.ExtractText(body)
}
