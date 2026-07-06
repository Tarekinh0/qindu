package interceptor

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/Tarekinh0/qindu/internal/pii"
	"github.com/Tarekinh0/qindu/internal/providers"
	"github.com/Tarekinh0/qindu/internal/tokenize"
)

// testLoggerDiscard returns a logger that discards all output.
func testLoggerDiscard() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// testLoggerCapture returns a logger that writes to a buffer for inspection.
func testLoggerCapture() (*slog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	return logger, &buf
}

// TestEnforceInterceptor_RequestTokenization verifies that PII in the request
// body is tokenized to <<TYPE_N>> before forwarding.
func TestEnforceInterceptor_RequestTokenization(t *testing.T) {
	logger, logBuf := testLoggerCapture()
	engine := newTestEngine()

	ei, err := NewEnforceInterceptor(engine, nil, false, logger)
	if err != nil {
		t.Fatalf("NewEnforceInterceptor: %v", err)
	}

	// Create a tokenizer and inject into context.
	tokenizer := tokenize.New(engine, tokenize.WithLogger(logger))

	bodyContent := `My email is test.user@example.com and phone is +33612345678`
	req := httptest.NewRequest("POST", "https://chatgpt.com/conversation/123", strings.NewReader(bodyContent))
	ctx := tokenize.ContextWithTokenizer(req.Context(), tokenizer)
	req = req.WithContext(ctx)

	newReq, newBody, err := ei.InterceptRequest(req)
	if err != nil {
		t.Fatalf("InterceptRequest failed: %v", err)
	}

	if newBody == nil {
		t.Fatal("InterceptRequest returned nil body")
	}

	bodyBytes, err := io.ReadAll(newBody)
	if err != nil {
		t.Fatalf("reading new body: %v", err)
	}
	newBody.Close()

	bodyStr := string(bodyBytes)

	// PII must NOT be present in the tokenized body.
	if strings.Contains(bodyStr, "test.user@example.com") {
		t.Error("PII email found in tokenized body — must be replaced with token")
	}
	if strings.Contains(bodyStr, "+33612345678") {
		t.Error("PII phone found in tokenized body — must be replaced with token")
	}

	// Verify <<EMAIL_1>> or similar token is present.
	if !strings.Contains(bodyStr, "<<EMAIL_") || !strings.Contains(bodyStr, ">>") {
		t.Errorf("tokenized body does not contain expected token pattern: %s", bodyStr)
	}

	// Verify new request is the same request pointer.
	if newReq != req {
		t.Error("InterceptRequest should return the same request pointer")
	}

	// Verify log contains tokenized_count or entity_count (depending on format).
	logOutput := logBuf.String()
	if !strings.Contains(logOutput, "monitor_scan") {
		t.Error("log should contain monitor_scan")
	}
}

// TestEnforceInterceptor_ResponseRehydration verifies that tokens in the
// response body are rehydrated back to original PII values.
func TestEnforceInterceptor_ResponseRehydration(t *testing.T) {
	logger, logBuf := testLoggerCapture()
	engine := newTestEngine()

	ei, err := NewEnforceInterceptor(engine, nil, false, logger)
	if err != nil {
		t.Fatalf("NewEnforceInterceptor: %v", err)
	}

	// Tokenizer with pre-populated mapping.
	tokenizer := tokenize.New(engine, tokenize.WithLogger(logger))
	tokenizedText, err := tokenizer.Tokenize("user@example.com")
	if err != nil {
		t.Fatalf("Tokenize: %v", err)
	}

	// Build a response containing the token.
	responseBody := `Your registered email is ` + tokenizedText
	req := httptest.NewRequest("GET", "https://chatgpt.com/conversation/abc", strings.NewReader(""))
	ctx := tokenize.ContextWithTokenizer(req.Context(), tokenizer)
	req = req.WithContext(ctx)

	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(responseBody)),
		Request:    req,
	}

	newResp, newBody, err := ei.InterceptResponse(resp)
	if err != nil {
		t.Fatalf("InterceptResponse failed: %v", err)
	}

	bodyBytes, err := io.ReadAll(newBody)
	if err != nil {
		t.Fatalf("reading response body: %v", err)
	}
	newBody.Close()

	bodyStr := string(bodyBytes)

	// The token should be rehydrated to the original PII.
	if !strings.Contains(bodyStr, "user@example.com") {
		t.Errorf("response body does not contain rehydrated PII: %s", bodyStr)
	}

	// The raw token should NOT appear (unless it was unknown token passed through).
	// In this test, it should be rehydrated.
	if strings.Contains(bodyStr, "<<EMAIL_") {
		t.Error("response body still contains token — should be rehydrated")
	}

	// Verify response pointer is same.
	if newResp != resp {
		t.Error("InterceptResponse should return same response pointer")
	}

	// Verify log contains rehydrated_count.
	logOutput := logBuf.String()
	if !strings.Contains(logOutput, "monitor_scan") {
		t.Error("log should contain monitor_scan")
	}
}

// TestEnforceInterceptor_MissingTokenizerFailClosed verifies that the
// interceptor returns an error when the tokenizer is missing from the context.
func TestEnforceInterceptor_MissingTokenizerFailClosed(t *testing.T) {
	logger, logBuf := testLoggerCapture()
	engine := newTestEngine()

	ei, err := NewEnforceInterceptor(engine, nil, false, logger)
	if err != nil {
		t.Fatalf("NewEnforceInterceptor: %v", err)
	}

	// Request WITHOUT tokenizer in context.
	req := httptest.NewRequest("POST", "https://chatgpt.com/conversation/x", strings.NewReader("some text"))
	// Intentionally not injecting tokenizer.

	_, _, err = ei.InterceptRequest(req)
	if err == nil {
		t.Fatal("expected error when tokenizer is missing from context")
	}
	if !strings.Contains(err.Error(), "tokenizer") {
		t.Errorf("error should mention tokenizer, got: %v", err)
	}

	// Verify log contains reason.
	logOutput := logBuf.String()
	if !strings.Contains(logOutput, "enforce_request_rejected") {
		t.Error("log should contain enforce_request_rejected")
	}
	if !strings.Contains(logOutput, "pii_values_logged") {
		t.Error("log should contain pii_values_logged")
	}
}

// TestEnforceInterceptor_UnknownTokenPassThrough verifies that unknown tokens
// in response bodies are passed through unchanged.
func TestEnforceInterceptor_UnknownTokenPassThrough(t *testing.T) {
	logger, _ := testLoggerCapture()
	engine := newTestEngine()

	ei, err := NewEnforceInterceptor(engine, nil, false, logger)
	if err != nil {
		t.Fatalf("NewEnforceInterceptor: %v", err)
	}

	tokenizer := tokenize.New(engine, tokenize.WithLogger(logger))

	responseBody := `Unknown token: <<EMAIL_999>> should stay as-is`
	req := httptest.NewRequest("GET", "https://chatgpt.com/conversation/x", strings.NewReader(""))
	ctx := tokenize.ContextWithTokenizer(req.Context(), tokenizer)
	req = req.WithContext(ctx)

	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(responseBody)),
		Request:    req,
	}

	_, newBody, err := ei.InterceptResponse(resp)
	if err != nil {
		t.Fatalf("InterceptResponse: %v", err)
	}

	bodyBytes, _ := io.ReadAll(newBody)
	newBody.Close()

	bodyStr := string(bodyBytes)
	if !strings.Contains(bodyStr, "<<EMAIL_999>>") {
		t.Errorf("unknown token should pass through unchanged: %s", bodyStr)
	}
}

// TestEnforceInterceptor_BinaryContentTypePassthrough verifies that binary
// content types are passed through without modification.
func TestEnforceInterceptor_BinaryContentTypePassthrough(t *testing.T) {
	logger, _ := testLoggerCapture()
	engine := newTestEngine()

	ei, err := NewEnforceInterceptor(engine, nil, false, logger)
	if err != nil {
		t.Fatalf("NewEnforceInterceptor: %v", err)
	}

	tokenizer := tokenize.New(engine, tokenize.WithLogger(logger))

	binaryContent := []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A}
	req := httptest.NewRequest("GET", "https://chatgpt.com/image", strings.NewReader(""))
	ctx := tokenize.ContextWithTokenizer(req.Context(), tokenizer)
	req = req.WithContext(ctx)

	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"image/png"}},
		Body:       io.NopCloser(bytes.NewReader(binaryContent)),
		Request:    req,
	}

	_, newBody, err := ei.InterceptResponse(resp)
	if err != nil {
		t.Fatalf("InterceptResponse: %v", err)
	}

	returnedBytes, _ := io.ReadAll(newBody)
	newBody.Close()

	if !bytes.Equal(returnedBytes, binaryContent) {
		t.Errorf("binary content should pass through unchanged: got %v, want %v", returnedBytes, binaryContent)
	}
}

// TestEnforceInterceptor_NilBodyPassthrough verifies nil response body is handled.
func TestEnforceInterceptor_NilBodyPassthrough(t *testing.T) {
	logger, _ := testLoggerCapture()
	engine := newTestEngine()

	ei, err := NewEnforceInterceptor(engine, nil, false, logger)
	if err != nil {
		t.Fatalf("NewEnforceInterceptor: %v", err)
	}

	tokenizer := tokenize.New(engine, tokenize.WithLogger(logger))

	req := httptest.NewRequest("GET", "https://chatgpt.com/conversation", strings.NewReader(""))
	ctx := tokenize.ContextWithTokenizer(req.Context(), tokenizer)
	req = req.WithContext(ctx)

	resp := &http.Response{
		StatusCode: 204,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       nil,
		Request:    req,
	}

	newResp, newBody, err := ei.InterceptResponse(resp)
	if err != nil {
		t.Fatalf("InterceptResponse with nil body: %v", err)
	}
	if newResp != resp {
		t.Error("should return same response for nil body")
	}
	if newBody != nil {
		t.Error("body should remain nil for nil input")
	}
}

// TestEnforceInterceptor_EmptyBody tokenizes/rehydrates empty bodies correctly.
func TestEnforceInterceptor_EmptyBody(t *testing.T) {
	logger, _ := testLoggerCapture()
	engine := newTestEngine()

	ei, err := NewEnforceInterceptor(engine, nil, false, logger)
	if err != nil {
		t.Fatalf("NewEnforceInterceptor: %v", err)
	}

	tokenizer := tokenize.New(engine, tokenize.WithLogger(logger))

	// Empty request body.
	req := httptest.NewRequest("POST", "https://chatgpt.com/conversation/x", strings.NewReader(""))
	ctx := tokenize.ContextWithTokenizer(req.Context(), tokenizer)
	req = req.WithContext(ctx)

	_, newBody, err := ei.InterceptRequest(req)
	if err != nil {
		t.Fatalf("InterceptRequest with empty body: %v", err)
	}

	if newBody == nil {
		t.Fatal("empty body should return a reader, not nil")
	}

	bodyBytes, _ := io.ReadAll(newBody)
	newBody.Close()
	if len(bodyBytes) != 0 {
		t.Errorf("empty body should remain empty, got %d bytes", len(bodyBytes))
	}
}

// TestEnforceInterceptor_ContentLengthUpdatedAfterTokenization verifies that
// Content-Length is recalculated after PII tokenization shrinks the request body.
// Without this fix, Go's HTTP layer rejects the request with
// "http: ContentLength=N with Body length M".
func TestEnforceInterceptor_ContentLengthUpdatedAfterTokenization(t *testing.T) {
	logger, _ := testLoggerCapture()
	engine := newTestEngine()

	ei, err := NewEnforceInterceptor(engine, nil, false, logger)
	if err != nil {
		t.Fatalf("NewEnforceInterceptor: %v", err)
	}

	tokenizer := tokenize.New(engine, tokenize.WithLogger(logger))

	// Body with PII that will be tokenized (shrinks):
	// "test.user@example.com" (21 chars) → "<<EMAIL_1>>" (11 chars), shrink by 10
	bodyContent := `My email is test.user@example.com and phone is +33612345678`
	originalLen := int64(len(bodyContent))

	req := httptest.NewRequest("POST", "https://chatgpt.com/conversation/123", strings.NewReader(bodyContent))
	req.ContentLength = originalLen
	req.Header.Set("Content-Length", strconv.FormatInt(originalLen, 10))
	ctx := tokenize.ContextWithTokenizer(req.Context(), tokenizer)
	req = req.WithContext(ctx)

	newReq, newBody, err := ei.InterceptRequest(req)
	if err != nil {
		t.Fatalf("InterceptRequest failed: %v", err)
	}
	if newBody == nil {
		t.Fatal("InterceptRequest returned nil body")
	}

	// Read the new body to get actual length.
	bodyBytes, err := io.ReadAll(newBody)
	if err != nil {
		t.Fatalf("reading new body: %v", err)
	}
	newBody.Close()
	actualLen := int64(len(bodyBytes))

	// Verify body actually shrank (tokenization replaces long PII with short tokens).
	if actualLen >= originalLen {
		t.Errorf("tokenized body should be shorter than original: original=%d, tokenized=%d", originalLen, actualLen)
	}

	// Verify ContentLength is updated.
	if newReq.ContentLength != actualLen {
		t.Errorf("ContentLength = %d, want %d (actual body length)", newReq.ContentLength, actualLen)
	}

	// Verify Content-Length header is updated.
	if cl := newReq.Header.Get("Content-Length"); cl != strconv.FormatInt(actualLen, 10) {
		t.Errorf("Content-Length header = %q, want %q", cl, strconv.FormatInt(actualLen, 10))
	}

	// Verify GetBody returns a functional reader with correct bytes.
	if newReq.GetBody == nil {
		t.Fatal("GetBody must not be nil after tokenization")
	}
	getBodyReader, err := newReq.GetBody()
	if err != nil {
		t.Fatalf("GetBody returned error: %v", err)
	}
	getBodyBytes, _ := io.ReadAll(getBodyReader)
	getBodyReader.Close()
	if !bytes.Equal(getBodyBytes, bodyBytes) {
		t.Errorf("GetBody returned different bytes: got %d bytes, want %d bytes", len(getBodyBytes), len(bodyBytes))
	}
}

// TestEnforceInterceptor_ResponseContentLengthUpdatedAfterRehydration verifies
// that Content-Length is recalculated after rehydration changes the response body size.
func TestEnforceInterceptor_ResponseContentLengthUpdatedAfterRehydration(t *testing.T) {
	logger, _ := testLoggerCapture()
	engine := newTestEngine()

	ei, err := NewEnforceInterceptor(engine, nil, false, logger)
	if err != nil {
		t.Fatalf("NewEnforceInterceptor: %v", err)
	}

	// Pre-populate tokenizer with a known PII→token mapping.
	tokenizer := tokenize.New(engine, tokenize.WithLogger(logger))
	tokenizedText, err := tokenizer.Tokenize("user@example.com")
	if err != nil {
		t.Fatalf("Tokenize: %v", err)
	}

	// Build a response containing the token. After rehydration,
	// "<<EMAIL_1>>" (11 chars) → "user@example.com" (16 chars), body grows by 5.
	responseBody := `Your email is ` + tokenizedText
	originalLen := int64(len(responseBody))

	req := httptest.NewRequest("GET", "https://chatgpt.com/conversation/abc", strings.NewReader(""))
	ctx := tokenize.ContextWithTokenizer(req.Context(), tokenizer)
	req = req.WithContext(ctx)

	resp := &http.Response{
		StatusCode:    200,
		Header:        http.Header{"Content-Type": []string{"application/json"}},
		Body:          io.NopCloser(strings.NewReader(responseBody)),
		ContentLength: originalLen,
		Request:       req,
	}
	resp.Header.Set("Content-Length", strconv.FormatInt(originalLen, 10))

	newResp, newBody, err := ei.InterceptResponse(resp)
	if err != nil {
		t.Fatalf("InterceptResponse failed: %v", err)
	}

	bodyBytes, err := io.ReadAll(newBody)
	if err != nil {
		t.Fatalf("reading new body: %v", err)
	}
	newBody.Close()
	actualLen := int64(len(bodyBytes))

	// Verify body grew (rehydration replaces short tokens with longer PII).
	if actualLen <= originalLen {
		t.Errorf("rehydrated body should be longer than tokenized: original=%d, rehydrated=%d", originalLen, actualLen)
	}

	// Verify ContentLength is updated.
	if newResp.ContentLength != actualLen {
		t.Errorf("ContentLength = %d, want %d (actual body length)", newResp.ContentLength, actualLen)
	}

	// Verify Content-Length header is updated.
	if cl := newResp.Header.Get("Content-Length"); cl != strconv.FormatInt(actualLen, 10) {
		t.Errorf("Content-Length header = %q, want %q", cl, strconv.FormatInt(actualLen, 10))
	}
}

// TestEnforceInterceptor_NoPIIBodyContentLengthUnchanged verifies that when
// the body does not contain PII and the length doesn't change, Content-Length
// is still set correctly (equals the unchanged body length).
func TestEnforceInterceptor_NoPIIBodyContentLengthUnchanged(t *testing.T) {
	logger, _ := testLoggerCapture()
	engine := newTestEngine()

	ei, err := NewEnforceInterceptor(engine, nil, false, logger)
	if err != nil {
		t.Fatalf("NewEnforceInterceptor: %v", err)
	}

	tokenizer := tokenize.New(engine, tokenize.WithLogger(logger))

	// Body with no PII — length should not change.
	bodyContent := `Hello, how are you today?`
	originalLen := int64(len(bodyContent))

	req := httptest.NewRequest("POST", "https://chatgpt.com/conversation/123", strings.NewReader(bodyContent))
	req.ContentLength = originalLen
	req.Header.Set("Content-Length", strconv.FormatInt(originalLen, 10))
	ctx := tokenize.ContextWithTokenizer(req.Context(), tokenizer)
	req = req.WithContext(ctx)

	newReq, newBody, err := ei.InterceptRequest(req)
	if err != nil {
		t.Fatalf("InterceptRequest failed: %v", err)
	}

	bodyBytes, _ := io.ReadAll(newBody)
	newBody.Close()
	actualLen := int64(len(bodyBytes))

	// Content-Length must match the actual body size (should be unchanged).
	if newReq.ContentLength != actualLen {
		t.Errorf("ContentLength = %d, want %d", newReq.ContentLength, actualLen)
	}
	if newReq.ContentLength != originalLen {
		t.Errorf("ContentLength changed even though body was not modified: got %d, want %d", newReq.ContentLength, originalLen)
	}
	if cl := newReq.Header.Get("Content-Length"); cl != strconv.FormatInt(actualLen, 10) {
		t.Errorf("Content-Length header = %q, want %q", cl, strconv.FormatInt(actualLen, 10))
	}

	// GetBody must be set even for unchanged bodies.
	if newReq.GetBody == nil {
		t.Error("GetBody must not be nil even when body is unchanged")
	}
}

// pathGuardPlugin is a minimal ProviderPlugin for testing path-based guards
// in the EnforceInterceptor. It matches only conversation paths and uses
// full-body extraction (like the fallback in scanBody) so tokenization
// behavior is observable in tests.
type pathGuardPlugin struct {
	name string
}

func (p *pathGuardPlugin) Name() string { return p.name }
func (p *pathGuardPlugin) MatchPath(_, path string) bool {
	return strings.Contains(path, "/conversation")
}
func (p *pathGuardPlugin) ExtractText(body []byte) []providers.TextSegment {
	return []providers.TextSegment{{Start: 0, End: len(body), Text: string(body)}}
}
func (p *pathGuardPlugin) RewriteRequestBody(_ []byte, _ []providers.TextSegment) []byte { return nil }
func (p *pathGuardPlugin) NewSession() providers.ProviderPluginSession                   { return &noOpProviderSession{} }

// TestEnforceInterceptor_PathGuardRequestSkipsNonConversation verifies that
// InterceptRequest returns the body unchanged for paths the plugin does not
// handle (e.g., /backend-anon/sentinel/chat-requirements/finalize).
// Without this guard, sentinel challenge payloads get false-positive PII
// detection and tokenization, causing upstream 500 errors.
func TestEnforceInterceptor_PathGuardRequestSkipsNonConversation(t *testing.T) {
	logger, logBuf := testLoggerCapture()
	engine := newTestEngine()
	plugin := &pathGuardPlugin{name: "test-plugin"}

	ei, err := NewEnforceInterceptor(engine, plugin, false, logger)
	if err != nil {
		t.Fatalf("NewEnforceInterceptor: %v", err)
	}

	bodyContent := `My email is test.user@example.com and phone is +33612345678`
	// Use a sentinel path — does NOT contain "/conversation", so plugin rejects it.
	req := httptest.NewRequest("POST", "https://chatgpt.com/backend-anon/sentinel/chat-requirements/finalize", strings.NewReader(bodyContent))

	tokenizer := tokenize.New(engine, tokenize.WithLogger(logger))
	ctx := tokenize.ContextWithTokenizer(req.Context(), tokenizer)
	req = req.WithContext(ctx)

	newReq, newBody, err := ei.InterceptRequest(req)
	if err != nil {
		t.Fatalf("InterceptRequest failed: %v", err)
	}
	if newBody == nil {
		t.Fatal("InterceptRequest returned nil body")
	}

	bodyBytes, err := io.ReadAll(newBody)
	if err != nil {
		t.Fatalf("reading new body: %v", err)
	}
	newBody.Close()

	bodyStr := string(bodyBytes)

	// PII must REMAIN in clear text — no tokenization for non-conversation paths.
	if !strings.Contains(bodyStr, "test.user@example.com") {
		t.Error("PII email missing from body — should NOT have been tokenized for non-conversation path")
	}
	if !strings.Contains(bodyStr, "+33612345678") {
		t.Error("PII phone missing from body — should NOT have been tokenized for non-conversation path")
	}

	// No monitor_scan or enforce_transform should have been logged.
	logOutput := logBuf.String()
	if strings.Contains(logOutput, "monitor_scan") {
		t.Error("monitor_scan log found for non-conversation path — should not scan")
	}
	if strings.Contains(logOutput, "enforce_transform") {
		t.Error("enforce_transform log found for non-conversation path — should not transform")
	}

	// The returned request must be the same request object.
	if newReq != req {
		t.Error("InterceptRequest returned different request object for non-conversation path")
	}
}

// TestEnforceInterceptor_PathGuardRequestProcessesConversation verifies that
// InterceptRequest still tokenizes PII for conversation paths (the normal
// behavior is preserved after the path guard addition).
func TestEnforceInterceptor_PathGuardRequestProcessesConversation(t *testing.T) {
	logger, logBuf := testLoggerCapture()
	engine := newTestEngine()
	plugin := &pathGuardPlugin{name: "test-plugin"}

	ei, err := NewEnforceInterceptor(engine, plugin, false, logger)
	if err != nil {
		t.Fatalf("NewEnforceInterceptor: %v", err)
	}

	bodyContent := `My email is test.user@example.com`
	// Use a conversation path — plugin matches it.
	req := httptest.NewRequest("POST", "https://chatgpt.com/backend-anon/f/conversation/abc-123", strings.NewReader(bodyContent))

	tokenizer := tokenize.New(engine, tokenize.WithLogger(logger))
	ctx := tokenize.ContextWithTokenizer(req.Context(), tokenizer)
	req = req.WithContext(ctx)

	newReq, newBody, err := ei.InterceptRequest(req)
	if err != nil {
		t.Fatalf("InterceptRequest failed: %v", err)
	}
	if newBody == nil {
		t.Fatal("InterceptRequest returned nil body")
	}

	bodyBytes, err := io.ReadAll(newBody)
	if err != nil {
		t.Fatalf("reading new body: %v", err)
	}
	newBody.Close()

	bodyStr := string(bodyBytes)

	// PII must be tokenized for conversation paths.
	if strings.Contains(bodyStr, "test.user@example.com") {
		t.Error("PII email still in body — should have been tokenized for conversation path")
	}
	if !strings.Contains(bodyStr, "<<EMAIL_") {
		t.Error("token not found in body — tokenization should have occurred")
	}

	// monitor_scan and enforce_transform should be logged.
	logOutput := logBuf.String()
	if !strings.Contains(logOutput, "monitor_scan") {
		t.Error("monitor_scan log missing for conversation path")
	}
	if !strings.Contains(logOutput, "enforce_transform") {
		t.Error("enforce_transform log missing for conversation path")
	}

	// Content-Length must be updated for tokenized body.
	if newReq.ContentLength != int64(len(bodyBytes)) {
		t.Errorf("ContentLength = %d, want %d", newReq.ContentLength, len(bodyBytes))
	}
}

// TestEnforceInterceptor_PathGuardResponseSkipsNonConversation verifies that
// InterceptResponse returns the body unchanged for paths the plugin does not
// handle.
func TestEnforceInterceptor_PathGuardResponseSkipsNonConversation(t *testing.T) {
	logger, logBuf := testLoggerCapture()
	engine := newTestEngine()
	plugin := &pathGuardPlugin{name: "test-plugin"}

	ei, err := NewEnforceInterceptor(engine, plugin, false, logger)
	if err != nil {
		t.Fatalf("NewEnforceInterceptor: %v", err)
	}

	// Response body containing a token that would be rehydrated if scanned.
	bodyContent := `{"status":"ok","text":"Hello <<EMAIL_1>>"}`
	// Use a sentinel path — does NOT contain "/conversation".
	req := httptest.NewRequest("POST", "https://chatgpt.com/backend-anon/sentinel/chat-requirements/finalize", strings.NewReader("original request"))
	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
		Body:    io.NopCloser(strings.NewReader(bodyContent)),
		Request: req,
	}

	tokenizer := tokenize.New(engine, tokenize.WithLogger(logger))
	ctx := tokenize.ContextWithTokenizer(req.Context(), tokenizer)
	resp.Request = resp.Request.WithContext(ctx)

	returnedResp, newBody, err := ei.InterceptResponse(resp)
	if err != nil {
		t.Fatalf("InterceptResponse failed: %v", err)
	}
	if newBody == nil {
		t.Fatal("InterceptResponse returned nil body")
	}

	bodyBytes, err := io.ReadAll(newBody)
	if err != nil {
		t.Fatalf("reading new body: %v", err)
	}
	newBody.Close()

	bodyStr := string(bodyBytes)

	// Body must be unchanged — no rehydration for non-conversation paths.
	if bodyStr != bodyContent {
		t.Errorf("body was modified for non-conversation path:\n  got:  %q\n  want: %q", bodyStr, bodyContent)
	}

	// No monitor_scan or enforce_transform should have been logged.
	logOutput := logBuf.String()
	if strings.Contains(logOutput, "monitor_scan") {
		t.Error("monitor_scan log found for non-conversation response — should not scan")
	}
	if strings.Contains(logOutput, "enforce_transform") {
		t.Error("enforce_transform log found for non-conversation response — should not transform")
	}

	// The returned response must be the same object.
	if returnedResp != resp {
		t.Error("InterceptResponse returned different response object for non-conversation path")
	}
}

// TestEnforceInterceptor_PathGuard_NilPlugin still processes the body via
// full-body fallback (no plugin means no path to guard against).
func TestEnforceInterceptor_PathGuard_NilPlugin(t *testing.T) {
	logger, logBuf := testLoggerCapture()
	engine := newTestEngine()

	// nil plugin — path guard checks e.plugin != nil before skipping
	ei, err := NewEnforceInterceptor(engine, nil, false, logger)
	if err != nil {
		t.Fatalf("NewEnforceInterceptor: %v", err)
	}

	bodyContent := `My email is test.user@example.com`
	// Sentinel path but no plugin — full-body scanning should still apply.
	req := httptest.NewRequest("POST", "https://chatgpt.com/backend-anon/sentinel/chat-requirements/finalize", strings.NewReader(bodyContent))

	tokenizer := tokenize.New(engine, tokenize.WithLogger(logger))
	ctx := tokenize.ContextWithTokenizer(req.Context(), tokenizer)
	req = req.WithContext(ctx)

	_, newBody, err := ei.InterceptRequest(req)
	if err != nil {
		t.Fatalf("InterceptRequest failed: %v", err)
	}

	bodyBytes, err := io.ReadAll(newBody)
	if err != nil {
		t.Fatalf("reading new body: %v", err)
	}
	newBody.Close()

	bodyStr := string(bodyBytes)

	// With nil plugin, the guard does NOT trigger. Full-body scanning applies
	// and PII should be tokenized.
	if strings.Contains(bodyStr, "test.user@example.com") {
		t.Error("PII email still in body — should have been tokenized with nil plugin (full-body fallback)")
	}
	if !strings.Contains(bodyStr, "<<EMAIL_") {
		t.Error("token not found in body — tokenization should have occurred with nil plugin")
	}

	// monitor_scan and enforce_transform should be logged (unlike with the path guard).
	logOutput := logBuf.String()
	if !strings.Contains(logOutput, "monitor_scan") {
		t.Error("monitor_scan log missing for nil-plugin case — full-body scanning should apply")
	}
}

// TestEnforceInterceptor_ShouldProcess_NilPlugin returns true so that the
// DebugInterceptor correctly buffers and records nil-plugin (full-body fallback) mode.
// PR-001: matchRequestPath returns true when plugin==nil to match InterceptRequest behavior.
func TestEnforceInterceptor_ShouldProcess_NilPlugin(t *testing.T) {
	logger, _ := testLoggerCapture()
	engine := newTestEngine()

	// nil plugin — full-body fallback processes all paths.
	ei, err := NewEnforceInterceptor(engine, nil, false, logger)
	if err != nil {
		t.Fatalf("NewEnforceInterceptor: %v", err)
	}

	if !ei.ShouldProcess("chatgpt.com", "POST", "/backend-anon/sentinel/chat-requirements/finalize") {
		t.Error("ShouldProcess should return true for nil-plugin (full-body fallback processes all paths)")
	}
	if !ei.ShouldProcess("chatgpt.com", "POST", "/backend-anon/f/conversation") {
		t.Error("ShouldProcess should return true for nil-plugin (any path)")
	}
	if !ei.ShouldProcess("chatgpt.com", "GET", "/ces/v1/t") {
		t.Error("ShouldProcess should return true for nil-plugin (telemetry path too)")
	}
}

// TestEnforceInterceptor_ShouldProcess_WithPlugin respects the plugin's MatchPath.
// PR-001 companion: with a real plugin, ShouldProcess delegates to MatchPath.
func TestEnforceInterceptor_ShouldProcess_WithPlugin(t *testing.T) {
	logger, _ := testLoggerCapture()
	engine := newTestEngine()

	plugin := &pathGuardPlugin{name: "test-plugin"}
	ei, err := NewEnforceInterceptor(engine, plugin, false, logger)
	if err != nil {
		t.Fatalf("NewEnforceInterceptor: %v", err)
	}

	if !ei.ShouldProcess("chatgpt.com", "POST", "/backend-anon/f/conversation") {
		t.Error("ShouldProcess should return true for conversation path")
	}
	if !ei.ShouldProcess("chatgpt.com", "POST", "/backend-anon/f/conversation/abc-123") {
		t.Error("ShouldProcess should return true for conversation sub-path")
	}
	if ei.ShouldProcess("chatgpt.com", "POST", "/backend-anon/sentinel/chat-requirements/finalize") {
		t.Error("ShouldProcess should return false for sentinel path")
	}
}

// TestEnforceInterceptor_BodyPreReadCap verifies that the request body pre-read
// is capped at maxInputLen + margin (PR-002).
func TestEnforceInterceptor_BodyPreReadCap(t *testing.T) {
	logger, _ := testLoggerCapture()
	// Use a small maxInputLen to test the cap without generating huge strings.
	engine := pii.NewEngine(100, // small max input
		pii.NewEmailRecognizer(),
		pii.NewPhoneRecognizer(),
	)
	plugin := &pathGuardPlugin{name: "test-plugin"}

	ei, err := NewEnforceInterceptor(engine, plugin, false, logger)
	if err != nil {
		t.Fatalf("NewEnforceInterceptor: %v", err)
	}
	// maxInputLen = 100, margin = 1024, cap = 1124

	// Generate a body larger than the cap.
	largeBody := strings.Repeat("x", ei.maxInputLen+maxBodyReadMargin+500) // ~1624 bytes
	req := httptest.NewRequest("POST", "https://chatgpt.com/backend-anon/f/conversation", strings.NewReader(largeBody))

	tokenizer := tokenize.New(engine, tokenize.WithLogger(logger))
	ctx := tokenize.ContextWithTokenizer(req.Context(), tokenizer)
	req = req.WithContext(ctx)

	_, newBody, err := ei.InterceptRequest(req)
	if err != nil {
		t.Fatalf("InterceptRequest with large body: %v", err)
	}

	bodyBytes, _ := io.ReadAll(newBody)
	newBody.Close()

	// Body should be truncated by the pre-read LimitReader (maxInputLen + margin).
	// scanBody will further cap at maxInputLen (100), so the final body should be ~100 bytes.
	// The exact size depends on tokenization but it must be much less than the original.
	if len(bodyBytes) >= len(largeBody) {
		t.Errorf("body should be capped: got %d bytes, original was %d", len(bodyBytes), len(largeBody))
	}
	// Verify the body was capped at or near maxInputLen (with margin for token pattern expansion).
	if len(bodyBytes) > ei.maxInputLen+maxBodyReadMargin {
		t.Errorf("body too large after cap: %d bytes, max expected %d", len(bodyBytes), ei.maxInputLen+maxBodyReadMargin)
	}
}
