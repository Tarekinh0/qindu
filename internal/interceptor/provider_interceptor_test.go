package interceptor

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Tarekinh0/qindu/internal/pii"
	"github.com/Tarekinh0/qindu/internal/providers"
	"github.com/Tarekinh0/qindu/internal/testutils"
)

// mockPlugin is a test double for providers.ProviderPlugin.
type mockPlugin struct {
	name    string
	session func() providers.ProviderPluginSession
}

func (m *mockPlugin) Name() string { return m.name }
func (m *mockPlugin) MatchPath(method, path string) bool {
	return strings.Contains(strings.ToLower(path), "/conversation")
}
func (m *mockPlugin) ExtractText(body []byte) []providers.TextSegment {
	return []providers.TextSegment{
		{Start: 0, End: len(body), Text: string(body)},
	}
}
func (m *mockPlugin) RewriteRequestBody(body []byte, segments []providers.TextSegment) []byte {
	return body
}
func (m *mockPlugin) NewSession() providers.ProviderPluginSession {
	if m.session != nil {
		return m.session()
	}
	return &mockSession{}
}

// mockSession is a test double for providers.ProviderPluginSession.
type mockSession struct {
	eventType string
	data      []byte
}

func (s *mockSession) HandleSSEEvent(eventType string, data []byte) string {
	s.eventType = eventType
	s.data = data
	return string(data)
}
func (s *mockSession) StreamEnded() {}

// mustNewProviderInterceptor creates a ProviderInterceptor for tests.
func mustNewProviderInterceptor(t *testing.T, engine *pii.Engine, plugin providers.ProviderPlugin, logger *slog.Logger) *ProviderInterceptor {
	t.Helper()
	pi, err := NewProviderInterceptor(engine, plugin, true, logger)
	if err != nil {
		t.Fatalf("NewProviderInterceptor: %v", err)
	}
	return pi
}

// newResponseRequest is a convenience alias for testutils.NewResponseRequest.
// Deprecated: use testutils.NewResponseRequest directly.
// Kept for backward compatibility with existing test code.
var newResponseRequest = testutils.NewResponseRequest

// PT-7 + PT-8: Monitor_scan format and zero PII in logs.
func TestProviderInterceptor_MonitorScanFormat(t *testing.T) {
	engine := newTestEngine()
	var logBuf bytes.Buffer
	logger := newTestLogger(&logBuf)
	plugin := &mockPlugin{name: "test-plugin"}
	pi := mustNewProviderInterceptor(t, engine, plugin, logger)

	body := `{"email": "test.user@example.com", "message": "hello"}`
	req := httptest.NewRequest("POST", "/v1/conversation", strings.NewReader(body))
	req.Host = "api.openai.com"

	_, newBody, err := pi.InterceptRequest(req)
	if err != nil {
		t.Fatalf("InterceptRequest failed: %v", err)
	}
	defer func() { _ = newBody.Close() }()

	returnedBytes, _ := io.ReadAll(newBody)
	if string(returnedBytes) != body {
		t.Errorf("body not byte-identical.\n got: %q\nwant: %q", string(returnedBytes), body)
	}

	entries := testutils.ParseLogEntries(t, &logBuf)
	var scanEntries []map[string]any
	for _, e := range entries {
		if e["msg"] == "monitor_scan" {
			scanEntries = append(scanEntries, e)
		}
	}
	if len(scanEntries) != 1 {
		t.Fatalf("expected exactly 1 monitor_scan entry, got %d", len(scanEntries))
	}

	entry := scanEntries[0]

	// Verify required fields (PT-7: same format as MonitorInterceptor).
	if entry["pii_values_logged"] != false {
		t.Errorf("pii_values_logged must be false, got %v", entry["pii_values_logged"])
	}
	if entry["direction"] != "request" {
		t.Errorf("direction should be 'request', got %v", entry["direction"])
	}
	if entry["result"] != "pii_found" {
		t.Errorf("result should be 'pii_found', got %v", entry["result"])
	}
	if ec, _ := entry["entity_count"].(float64); ec < 1 {
		t.Errorf("entity_count should be >= 1, got %v", ec)
	}
	if _, ok := entry["entity_summary"]; !ok {
		t.Errorf("entity_summary should be present when pii_logging=true")
	}
	// PR-003: provider field intentionally excluded for format parity with MonitorInterceptor.
	if _, ok := entry["provider"]; ok {
		t.Error("provider field must not appear in monitor_scan (format parity with MonitorInterceptor)")
	}

	// PT-8: No PII in log output.
	logOutput := logBuf.String()
	if strings.Contains(logOutput, "test.user@example.com") {
		t.Error("log output must not contain raw PII values")
	}
}

// PT-12: RewriteRequestBody returns identity.
func TestProviderInterceptor_RewriteRequestBodyIdentity(t *testing.T) {
	engine := newTestEngine()
	var logBuf bytes.Buffer
	logger := newTestLogger(&logBuf)
	plugin := &mockPlugin{name: "test-plugin"}
	pi := mustNewProviderInterceptor(t, engine, plugin, logger)

	body := []byte(`{"test": "data"}`)
	req := httptest.NewRequest("POST", "/v1/conversation", bytes.NewReader(body))
	req.Host = "test.local"

	_, newBody, err := pi.InterceptRequest(req)
	if err != nil {
		t.Fatalf("InterceptRequest failed: %v", err)
	}
	defer func() { _ = newBody.Close() }()

	returned, _ := io.ReadAll(newBody)
	if !bytes.Equal(returned, body) {
		t.Error("rewritten body must be byte-identical to original (DPO-R5.2)")
	}
}

// PT-13: Non-conversation path bypassed.
func TestProviderInterceptor_NonConversationPathBypassed(t *testing.T) {
	engine := newTestEngine()
	var logBuf bytes.Buffer
	logger := newTestLogger(&logBuf)
	plugin := &mockPlugin{name: "test-plugin"}
	pi := mustNewProviderInterceptor(t, engine, plugin, logger)

	body := `{"email": "test.user@example.com"}`
	req := httptest.NewRequest("POST", "/ces/v1/t", strings.NewReader(body))
	req.Host = "test.local"

	_, newBody, err := pi.InterceptRequest(req)
	if err != nil {
		t.Fatalf("InterceptRequest failed: %v", err)
	}
	defer func() { _ = newBody.Close() }()

	returnedBytes, _ := io.ReadAll(newBody)
	if string(returnedBytes) != body {
		t.Errorf("body was modified, expected passthrough")
	}

	entries := testutils.ParseLogEntries(t, &logBuf)
	for _, e := range entries {
		if e["msg"] == "monitor_scan" {
			t.Error("non-conversation path should not produce monitor_scan entry")
		}
	}
}

// PT-14: ChatGPT metadata — no false positives (AC-3, AC-4).
func TestProviderInterceptor_ChatGPTMetadata_NoFalsePositives(t *testing.T) {
	engine := newTestEngineFull()
	var logBuf bytes.Buffer
	logger := newTestLogger(&logBuf)

	metaFilterPlugin := &metadataFilterPlugin{name: "chatgpt"}
	pi := mustNewProviderInterceptor(t, engine, metaFilterPlugin, logger)

	// Request with JWT in metadata — should NOT be detected as PII.
	body := `{"type": "resume_conversation_token", "token": "eyJhbGciOiJIUzI1NiJ9.test.sig"}`
	req := httptest.NewRequest("POST", "/v1/conversation", strings.NewReader(body))
	req.Host = "chatgpt.com"

	_, newBody, err := pi.InterceptRequest(req)
	if err != nil {
		t.Fatalf("InterceptRequest failed: %v", err)
	}
	defer func() { _ = newBody.Close() }()
	_ = newBody

	entries := testutils.ParseLogEntries(t, &logBuf)
	for _, e := range entries {
		if e["msg"] == "monitor_scan" {
			if e["result"] == "pii_found" {
				t.Error("metadata should not produce pii_found (false positive)")
			}
		}
	}
}

// metadataFilterPlugin is a test double that simulates ChatGPT metadata filtering.
type metadataFilterPlugin struct {
	name string
}

func (m *metadataFilterPlugin) Name() string { return m.name }
func (m *metadataFilterPlugin) MatchPath(method, path string) bool {
	return strings.Contains(strings.ToLower(path), "/conversation")
}
func (m *metadataFilterPlugin) ExtractText(body []byte) []providers.TextSegment {
	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil
	}
	if t, ok := raw["type"].(string); ok {
		switch t {
		case "resume_conversation_token", "delta_encoding", "message_marker":
			return nil
		}
	}
	return []providers.TextSegment{{Start: 0, End: len(body), Text: string(body)}}
}
func (m *metadataFilterPlugin) RewriteRequestBody(body []byte, segments []providers.TextSegment) []byte {
	return body
}
func (m *metadataFilterPlugin) NewSession() providers.ProviderPluginSession {
	return &mockSession{}
}

// Test SSE response processing through ProviderInterceptor.
func TestProviderInterceptor_SSEResponse(t *testing.T) {
	engine := newTestEngine()
	var logBuf bytes.Buffer
	logger := newTestLogger(&logBuf)
	plugin := &mockPlugin{name: "test-plugin"}
	pi := mustNewProviderInterceptor(t, engine, plugin, logger)

	sseBody := strings.NewReader(
		`data: {"msg": "test.user@example.com"}` + "\n\n" +
			`data: {"msg": "No PII here"}` + "\n\n",
	)

	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Content-Type": []string{"text/event-stream"},
		},
		Body:    io.NopCloser(sseBody),
		Request: newResponseRequest("POST", "chatgpt.com", "/v1/conversation"),
	}

	_, newBody, err := pi.InterceptResponse(resp)
	if err != nil {
		t.Fatalf("InterceptResponse failed: %v", err)
	}
	defer func() { _ = newBody.Close() }()

	output, err := io.ReadAll(newBody)
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}

	if !strings.Contains(string(output), "test.user@example.com") {
		t.Error("SSE output must contain the original data")
	}

	entries := testutils.ParseLogEntries(t, &logBuf)
	var scanEntries []map[string]any
	for _, e := range entries {
		if e["msg"] == "monitor_scan" {
			scanEntries = append(scanEntries, e)
		}
	}
	if len(scanEntries) != 1 {
		t.Fatalf("expected exactly 1 monitor_scan for SSE stream, got %d", len(scanEntries))
	}
	if scanEntries[0]["sse_frame"] != true {
		t.Error("SSE monitor_scan should have sse_frame=true")
	}
}

// Test that non-SSE text content type uses body extraction.
func TestProviderInterceptor_JSONResponse(t *testing.T) {
	engine := newTestEngine()
	var logBuf bytes.Buffer
	logger := newTestLogger(&logBuf)
	plugin := &mockPlugin{name: "test-plugin"}
	pi := mustNewProviderInterceptor(t, engine, plugin, logger)

	jsonBody := strings.NewReader(`{"result": "Contact test.user@example.com"}`)

	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
		Body:    io.NopCloser(jsonBody),
		Request: newResponseRequest("POST", "chatgpt.com", "/v1/conversation"),
	}

	_, newBody, err := pi.InterceptResponse(resp)
	if err != nil {
		t.Fatalf("InterceptResponse failed: %v", err)
	}
	defer func() { _ = newBody.Close() }()

	output, err := io.ReadAll(newBody)
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}

	if !strings.Contains(string(output), "test.user@example.com") {
		t.Error("JSON response body must pass through unchanged")
	}

	entries := testutils.ParseLogEntries(t, &logBuf)
	var scanEntries []map[string]any
	for _, e := range entries {
		if e["msg"] == "monitor_scan" {
			scanEntries = append(scanEntries, e)
		}
	}
	if len(scanEntries) != 1 {
		t.Fatalf("expected 1 monitor_scan for JSON response, got %d", len(scanEntries))
	}
}

// Test path mismatch for response — non-conversation path.
func TestProviderInterceptor_ResponseNonConversationPath(t *testing.T) {
	engine := newTestEngine()
	var logBuf bytes.Buffer
	logger := newTestLogger(&logBuf)
	plugin := &mockPlugin{name: "test-plugin"}
	pi := mustNewProviderInterceptor(t, engine, plugin, logger)

	jsonBody := strings.NewReader(`{"email": "test.user@example.com"}`)

	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
		Body:    io.NopCloser(jsonBody),
		Request: newResponseRequest("POST", "chatgpt.com", "/ces/v1/t"),
	}

	_, newBody, err := pi.InterceptResponse(resp)
	if err != nil {
		t.Fatalf("InterceptResponse failed: %v", err)
	}
	defer func() { _ = newBody.Close() }()

	entries := testutils.ParseLogEntries(t, &logBuf)
	for _, e := range entries {
		if e["msg"] == "monitor_scan" {
			t.Error("non-conversation path should not produce monitor_scan")
		}
	}
	_ = newBody
}

// PT-8: No PII in any log output from ProviderInterceptor.
func TestProviderInterceptor_NoPIIInAnyLog(t *testing.T) {
	engine := newTestEngine()
	var logBuf bytes.Buffer
	logger := newTestLogger(&logBuf)
	plugin := &mockPlugin{name: "test-plugin"}
	pi := mustNewProviderInterceptor(t, engine, plugin, logger)

	body := `{"email": "super.secret@example.com"}`
	req := httptest.NewRequest("POST", "/v1/conversation", strings.NewReader(body))
	req.Host = "test.local"

	_, newBody, _ := pi.InterceptRequest(req)
	defer func() { _ = newBody.Close() }()

	// Also test SSE response.
	sseBody := strings.NewReader(`data: {"phone": "+1-555-0199"}` + "\n\n")
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
		Body:       io.NopCloser(sseBody),
		Request:    newResponseRequest("POST", "test.local", "/v1/conversation"),
	}
	_, respBody, _ := pi.InterceptResponse(resp)
	defer func() { _ = respBody.Close() }()
	_, _ = io.ReadAll(respBody)

	logOutput := logBuf.String()

	piiValues := []string{
		"super.secret@example.com",
		"+1-555-0199",
		"super.secret",
		"555-0199",
	}

	for _, pii := range piiValues {
		if strings.Contains(logOutput, pii) {
			t.Errorf("log output must not contain raw PII: %q", pii)
		}
	}
}

// Test that pii_logging=false omits entity_summary.
func TestProviderInterceptor_PIILoggingDisabled(t *testing.T) {
	engine := newTestEngine()
	var logBuf bytes.Buffer
	logger := newTestLogger(&logBuf)
	plugin := &mockPlugin{name: "test-plugin"}

	pi, err := NewProviderInterceptor(engine, plugin, false, logger)
	if err != nil {
		t.Fatalf("NewProviderInterceptor: %v", err)
	}

	body := `{"email": "test.user@example.com"}`
	req := httptest.NewRequest("POST", "/v1/conversation", strings.NewReader(body))
	req.Host = "test.local"

	_, newBody, _ := pi.InterceptRequest(req)
	defer func() { _ = newBody.Close() }()

	entries := testutils.ParseLogEntries(t, &logBuf)
	for _, e := range entries {
		if e["msg"] == "monitor_scan" && e["result"] == "pii_found" {
			if _, ok := e["entity_count"]; !ok {
				t.Error("entity_count must be present even with pii_logging=false")
			}
			if _, ok := e["entity_summary"]; ok {
				t.Error("entity_summary must be omitted when pii_logging=false")
			}
		}
	}
}

// Test that nil body is handled for requests.
func TestProviderInterceptor_NilRequestBody(t *testing.T) {
	engine := newTestEngine()
	var logBuf bytes.Buffer
	logger := newTestLogger(&logBuf)
	plugin := &mockPlugin{name: "test-plugin"}
	pi := mustNewProviderInterceptor(t, engine, plugin, logger)

	req := httptest.NewRequest("POST", "/v1/conversation", http.NoBody)
	req.Host = "test.local"

	_, newBody, err := pi.InterceptRequest(req)
	if err != nil {
		t.Fatalf("InterceptRequest with http.NoBody should not error: %v", err)
	}
	// http.NoBody should pass through (body is empty, forwarded as-is).
	if newBody == nil {
		t.Error("http.NoBody should return a body reader (even if empty)")
	}
	// Read the returned body — should be empty.
	data, readErr := io.ReadAll(newBody)
	if readErr != nil {
		t.Errorf("reading returned body: %v", readErr)
	}
	if len(data) != 0 {
		t.Errorf("expected empty body, got %d bytes", len(data))
	}
	newBody.Close()
}

// Test text segment validation (CS-11-09, SEC-11-T10).
func TestProviderInterceptor_ValidateTextSegments(t *testing.T) {
	segments := []providers.TextSegment{
		{Start: 0, End: 5, Text: "valid"},
		{Start: 10, End: 5, Text: "invalid"},     // start > end → skip
		{Start: -1, End: 5, Text: "invalid"},     // negative start → skip
		{Start: 0, End: 100, Text: "outofrange"}, // end > bodyLen → skip
		{Start: 0, End: 3, Text: ""},             // empty text → skip
	}

	valid := validateTextSegments(segments, 10) // bodyLen=10: last segment end=100 > 10, skipped
	if len(valid) != 1 {
		t.Errorf("expected 1 valid segment, got %d: %v", len(valid), valid)
	}
	if valid[0].Text != "valid" {
		t.Errorf("expected 'valid', got %q", valid[0].Text)
	}
}

// SEC-11-T11: Verify all log output from ProviderInterceptor has no PII.
func TestProviderInterceptor_ZeroPIIInAllLogs(t *testing.T) {
	engine := newTestEngine()
	var logBuf bytes.Buffer
	logger := newTestLogger(&logBuf)
	plugin := &mockPlugin{name: "test-plugin"}
	pi := mustNewProviderInterceptor(t, engine, plugin, logger)

	body := `{"email": "alice@example.com", "phone": "+1-555-0123"}`
	req := httptest.NewRequest("POST", "/v1/conversation", strings.NewReader(body))
	req.Host = "test.local"

	_, newBody, _ := pi.InterceptRequest(req)
	if newBody != nil {
		newBody.Close()
	}

	logOutput := logBuf.String()

	piiPatterns := []string{
		"alice@example.com",
		"+1-555-0123",
		"alice",
		"555-0123",
	}

	for _, pattern := range piiPatterns {
		if strings.Contains(logOutput, pattern) {
			t.Errorf("all log output must not contain raw PII: %q found", pattern)
		}
	}

	// Verify entity_summary format.
	entries := testutils.ParseLogEntries(t, &logBuf)
	for _, e := range entries {
		if e["msg"] == "monitor_scan" {
			if summary, ok := e["entity_summary"].(map[string]any); ok {
				for k, v := range summary {
					if !isValidEntityType(k) {
						t.Errorf("entity_summary key must be entity type, got %q", k)
					}
					if _, ok := v.(float64); !ok {
						t.Errorf("entity_summary value for %q must be numeric", k)
					}
				}
			}
		}
	}
}

// Test that multiple connections get independent sessions (CS-11-06, SEC-11-T8).
func TestProviderInterceptor_IndependentSessions(t *testing.T) {
	engine := newTestEngine()
	var logBuf1, logBuf2 bytes.Buffer
	logger1 := newTestLogger(&logBuf1)
	logger2 := newTestLogger(&logBuf2)
	plugin := &mockPlugin{name: "test-plugin"}

	pi1 := mustNewProviderInterceptor(t, engine, plugin, logger1)
	pi2 := mustNewProviderInterceptor(t, engine, plugin, logger2)

	sse1 := strings.NewReader(`data: {"msg": "user1@example.com"}` + "\n\n")
	sse2 := strings.NewReader(`data: {"msg": "user2@example.com"}` + "\n\n")

	resp1 := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
		Body:       io.NopCloser(sse1),
		Request:    newResponseRequest("POST", "chatgpt.com", "/v1/conversation"),
	}
	resp2 := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
		Body:       io.NopCloser(sse2),
		Request:    newResponseRequest("POST", "chatgpt.com", "/v1/conversation"),
	}

	_, body1, _ := pi1.InterceptResponse(resp1)
	_, body2, _ := pi2.InterceptResponse(resp2)
	_, _ = io.ReadAll(body1)
	_, _ = io.ReadAll(body2)
	body1.Close()
	body2.Close()

	logOutput1 := logBuf1.String()
	logOutput2 := logBuf2.String()

	if strings.Contains(logOutput1, "user2@example.com") {
		t.Error("connection 1 log must not contain connection 2's PII (cross-contamination)")
	}
	if strings.Contains(logOutput2, "user1@example.com") {
		t.Error("connection 2 log must not contain connection 1's PII (cross-contamination)")
	}
}

// Test oversize request body handling.
func TestProviderInterceptor_OversizeRequestBody(t *testing.T) {
	engine := newTestEngine()
	var logBuf bytes.Buffer
	logger := newTestLogger(&logBuf)
	plugin := &mockPlugin{name: "test-plugin"}
	pi := mustNewProviderInterceptor(t, engine, plugin, logger)

	// Create a body larger than DefaultMaxInputBytes (1 MiB).
	body := strings.Repeat("x", pii.DefaultMaxInputBytes+100)
	req := httptest.NewRequest("POST", "/v1/conversation", strings.NewReader(body))
	req.Host = "test.local"

	_, newBody, err := pi.InterceptRequest(req)
	if err != nil {
		t.Fatalf("InterceptRequest should not error on oversize: %v", err)
	}
	defer func() { _ = newBody.Close() }()

	returned, _ := io.ReadAll(newBody)
	if string(returned) != body {
		t.Error("oversized body must be forwarded completely")
	}

	// Should have a skip warning.
	entries := testutils.ParseLogEntries(t, &logBuf)
	hasSkip := false
	for _, e := range entries {
		if e["msg"] == "pii_detection_skipped" && e["reason"] == "oversize" {
			hasSkip = true
			break
		}
	}
	if !hasSkip {
		t.Error("expected oversize skip warning")
	}
}

// Test binary content type skipped in response.
func TestProviderInterceptor_BinaryContentTypeResponse(t *testing.T) {
	engine := newTestEngine()
	var logBuf bytes.Buffer
	logger := newTestLogger(&logBuf)
	plugin := &mockPlugin{name: "test-plugin"}
	pi := mustNewProviderInterceptor(t, engine, plugin, logger)

	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Content-Type": []string{"image/png"},
		},
		Body:    io.NopCloser(strings.NewReader("binary")),
		Request: newResponseRequest("GET", "chatgpt.com", "/v1/conversation"),
	}

	_, newBody, err := pi.InterceptResponse(resp)
	if err != nil {
		t.Fatalf("InterceptResponse failed: %v", err)
	}
	defer func() { _ = newBody.Close() }()

	// Should pass through without detection.
	entries := testutils.ParseLogEntries(t, &logBuf)
	for _, e := range entries {
		if e["msg"] == "monitor_scan" {
			t.Error("binary content type should not produce monitor_scan")
		}
	}
	_ = newBody
}

// Test that nil response body is handled gracefully.
func TestProviderInterceptor_NilResponseBody(t *testing.T) {
	engine := newTestEngine()
	var logBuf bytes.Buffer
	logger := newTestLogger(&logBuf)
	plugin := &mockPlugin{name: "test-plugin"}
	pi := mustNewProviderInterceptor(t, engine, plugin, logger)

	resp := &http.Response{
		StatusCode: 200,
		Body:       nil,
		Request:    newResponseRequest("POST", "chatgpt.com", "/v1/conversation"),
	}

	_, newBody, err := pi.InterceptResponse(resp)
	if err != nil {
		t.Fatalf("InterceptResponse with nil body should not error: %v", err)
	}
	if newBody != nil {
		t.Error("nil body should return nil body")
	}
}

// Test constructor validation.
func TestNewProviderInterceptor_NilPlugin(t *testing.T) {
	engine := newTestEngine()
	var logBuf bytes.Buffer
	logger := newTestLogger(&logBuf)

	_, err := NewProviderInterceptor(engine, nil, true, logger)
	if err == nil {
		t.Error("expected error for nil plugin")
	}
}

// Test constructor validation for nil engine.
func TestNewProviderInterceptor_NilEngine(t *testing.T) {
	var logBuf bytes.Buffer
	logger := newTestLogger(&logBuf)
	plugin := &mockPlugin{name: "test"}

	_, err := NewProviderInterceptor(nil, plugin, true, logger)
	if err == nil {
		t.Error("expected error for nil engine")
	}
}
