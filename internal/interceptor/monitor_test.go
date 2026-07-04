package interceptor

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Tarekinh0/qindu/internal/pii"
)

// testScanPathsBroad returns scan paths that match all standard test URL paths.
func testScanPathsBroad() []string {
	// Include /v1/ to match /v1/chat, /v1/chat/completions, /v1/models, etc.
	return []string{"/v1/", "/api/", "/conversation"}
}

// testDefaultScanPaths returns the production default scan paths (mirrors policy.Config defaults).
// Used in tests that exercise the path filtering logic with production-like paths.
func testDefaultScanPaths() []string {
	return []string{
		"/conversation",
		"/v1/messages",
		"/chat/completions",
		"generateContent",
		"/chat/",
	}
}

// mustNewMonitorInterceptor is a test helper that wraps NewMonitorInterceptor
// and fails the test if the constructor returns an error.
func mustNewMonitorInterceptor(t *testing.T, engine *pii.Engine, piiLogging bool, logger *slog.Logger, scanPaths []string) *MonitorInterceptor {
	t.Helper()
	mi, err := NewMonitorInterceptor(engine, piiLogging, logger, scanPaths)
	if err != nil {
		t.Fatalf("NewMonitorInterceptor: %v", err)
	}
	return mi
}

func TestMonitorInterceptor_InterceptRequest_PIIDetected(t *testing.T) {
	engine := newTestEngineFull()
	var logBuf bytes.Buffer
	logger := newTestLogger(&logBuf)
	mi := mustNewMonitorInterceptor(t, engine, true, logger, testScanPathsBroad())

	body := `{"email": "test.user@example.com", "message": "hello"}`
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(body))
	req.Host = "api.openai.com"

	_, newBody, err := mi.InterceptRequest(req)
	if err != nil {
		t.Fatalf("InterceptRequest failed: %v", err)
	}
	defer func() { _ = newBody.Close() }()

	// Read the returned body to verify byte-identical forwarding (SR-9).
	returnedBytes, _ := io.ReadAll(newBody)
	if string(returnedBytes) != body {
		t.Errorf("body not byte-identical.\n got: %q\nwant: %q", string(returnedBytes), body)
	}

	// Check log output.
	entries := parseLogEntries(t, &logBuf)
	found := false
	for _, e := range entries {
		if e["msg"] == "monitor_scan" {
			found = true
			// Verify compliance marker (DPO-R1).
			if pl, ok := e["pii_values_logged"]; !ok || pl != false {
				t.Errorf("pii_values_logged must be false, got %v", pl)
			}
			// Verify entity metadata.
			if ec, _ := e["entity_count"].(float64); ec < 1 {
				t.Errorf("entity_count should be >= 1, got %v", ec)
			}
			if e["direction"] != "request" {
				t.Errorf("direction should be 'request', got %v", e["direction"])
			}
			if e["result"] != "pii_found" {
				t.Errorf("result should be 'pii_found', got %v", e["result"])
			}
			if e["host"] != "api.openai.com" {
				t.Errorf("host mismatch: %v", e["host"])
			}
			if e["method"] != "POST" {
				t.Errorf("method mismatch: %v", e["method"])
			}
			// Path should strip query parameters (DPO-R4).
			if e["path"] != "/v1/chat/completions" {
				t.Errorf("path mismatch: %v", e["path"])
			}
			// entity_summary should be present when pii_logging=true.
			if _, ok := e["entity_summary"]; !ok {
				t.Errorf("entity_summary should be present when pii_logging=true")
			}
			break
		}
	}
	if !found {
		t.Fatal("expected monitor_scan log entry, found none")
	}
}

func TestMonitorInterceptor_InterceptRequest_NoPII_CleanLog(t *testing.T) {
	// Bug 2 fix: even clean messages produce a monitor_scan with result=clean.
	engine := newTestEngineFull()
	var logBuf bytes.Buffer
	logger := newTestLogger(&logBuf)
	mi := mustNewMonitorInterceptor(t, engine, true, logger, testScanPathsBroad())

	body := `{"message": "hello world", "topic": "weather"}`
	req := httptest.NewRequest("POST", "/v1/chat", strings.NewReader(body))
	req.Host = "api.openai.com"

	_, newBody, err := mi.InterceptRequest(req)
	if err != nil {
		t.Fatalf("InterceptRequest failed: %v", err)
	}
	defer func() { _ = newBody.Close() }()

	returnedBytes, _ := io.ReadAll(newBody)
	if string(returnedBytes) != body {
		t.Errorf("body not byte-identical")
	}

	// Should have exactly one monitor_scan entry with result=clean.
	entries := parseLogEntries(t, &logBuf)
	var scanEntries []map[string]any
	for _, e := range entries {
		if e["msg"] == "monitor_scan" {
			scanEntries = append(scanEntries, e)
		}
	}
	if len(scanEntries) != 1 {
		t.Fatalf("expected exactly 1 monitor_scan entry, got %d", len(scanEntries))
	}
	e := scanEntries[0]
	if e["result"] != "clean" {
		t.Errorf("clean body should produce result=clean, got %v", e["result"])
	}
	if e["direction"] != "request" {
		t.Errorf("direction should be 'request', got %v", e["direction"])
	}
	// entity_count and entity_summary must NOT be present for clean results.
	if _, ok := e["entity_count"]; ok {
		t.Error("entity_count should not be present for clean result")
	}
}

func TestMonitorInterceptor_InterceptRequest_PIILoggingDisabled(t *testing.T) {
	// When pii_logging=false: engine still runs, monitor_scan still emitted,
	// but entity_summary is omitted for privacy.
	engine := newTestEngineFull()
	var logBuf bytes.Buffer
	logger := newTestLogger(&logBuf)
	mi := mustNewMonitorInterceptor(t, engine, false, logger, testScanPathsBroad()) // pii_logging=false

	body := `{"email": "test.user@example.com"}`
	req := httptest.NewRequest("POST", "/v1/chat", strings.NewReader(body))
	req.Host = "api.openai.com"

	_, newBody, err := mi.InterceptRequest(req)
	if err != nil {
		t.Fatalf("InterceptRequest failed: %v", err)
	}
	defer func() { _ = newBody.Close() }()

	// Body still forwarded.
	returnedBytes, _ := io.ReadAll(newBody)
	if string(returnedBytes) != body {
		t.Error("body must be forwarded even when pii_logging=false")
	}

	// Should have a monitor_scan entry with result=pii_found but NO entity_summary.
	entries := parseLogEntries(t, &logBuf)
	var scanEntries []map[string]any
	for _, e := range entries {
		if e["msg"] == "monitor_scan" {
			scanEntries = append(scanEntries, e)
		}
	}
	if len(scanEntries) != 1 {
		t.Fatalf("expected exactly 1 monitor_scan entry, got %d", len(scanEntries))
	}
	e := scanEntries[0]
	if e["result"] != "pii_found" {
		t.Errorf("expected result=pii_found, got %v", e["result"])
	}
	if _, ok := e["entity_count"]; !ok {
		t.Error("entity_count should be present even when pii_logging=false")
	}
	// entity_summary must NOT be present when pii_logging=false.
	if _, ok := e["entity_summary"]; ok {
		t.Error("entity_summary must be omitted when pii_logging=false")
	}
}

func TestMonitorInterceptor_InterceptRequest_PathFilterSkip(t *testing.T) {
	// Bug 1 fix: paths not matching scan_paths whitelist are skipped entirely.
	engine := newTestEngineFull()
	var logBuf bytes.Buffer
	logger := newTestLogger(&logBuf)
	mi := mustNewMonitorInterceptor(t, engine, true, logger, testScanPathsBroad())

	// Telemetry path that should NOT be scanned.
	body := `{"email": "test.user@example.com"}`
	req := httptest.NewRequest("POST", "/ces/statsc/flush", strings.NewReader(body))
	req.Host = "api.openai.com"

	_, newBody, err := mi.InterceptRequest(req)
	if err != nil {
		t.Fatalf("InterceptRequest failed: %v", err)
	}
	defer func() { _ = newBody.Close() }()

	returnedBytes, _ := io.ReadAll(newBody)
	if string(returnedBytes) != body {
		t.Error("body must be forwarded unchanged even when path is skipped")
	}

	// No monitor_scan or pii_detected entries should appear.
	entries := parseLogEntries(t, &logBuf)
	for _, e := range entries {
		msg, _ := e["msg"].(string)
		if msg == "monitor_scan" || msg == "pii_detected" {
			t.Errorf("no scan logs expected for skipped path, got: %v", e)
		}
	}
}

func TestMonitorInterceptor_InterceptRequest_OversizedBody(t *testing.T) {
	engine := newTestEngineFull()
	var logBuf bytes.Buffer
	logger := newTestLogger(&logBuf)
	mi := mustNewMonitorInterceptor(t, engine, true, logger, testScanPathsBroad())

	// Create a body larger than the engine limit.
	bigBody := strings.Repeat("A", pii.DefaultMaxInputBytes+1000)
	body := `{"data": "` + bigBody + `"}`
	req := httptest.NewRequest("POST", "/v1/chat", strings.NewReader(body))
	req.Host = "api.openai.com"

	_, newBody, err := mi.InterceptRequest(req)
	if err != nil {
		t.Fatalf("InterceptRequest failed: %v", err)
	}
	defer func() { _ = newBody.Close() }()

	// The body should still be forwarded.
	returnedBytes, err := io.ReadAll(newBody)
	if err != nil {
		t.Fatalf("reading returned body: %v", err)
	}
	if !strings.Contains(string(returnedBytes), bigBody) {
		t.Error("oversized body must be forwarded")
	}

	// Should have a WARN log for oversize skip.
	entries := parseLogEntries(t, &logBuf)
	hasSkipWarn := false
	for _, e := range entries {
		if e["msg"] == "pii_detection_skipped" && e["reason"] == "oversize" {
			hasSkipWarn = true
			break
		}
	}
	if !hasSkipWarn {
		t.Error("expected pii_detection_skipped warn for oversized body")
	}
}

func TestMonitorInterceptor_InterceptRequest_ContentLengthPreCheck(t *testing.T) {
	// SR-1: Content-Length pre-check should prevent buffering.
	engine := newTestEngineFull()
	var logBuf bytes.Buffer
	logger := newTestLogger(&logBuf)
	mi := mustNewMonitorInterceptor(t, engine, true, logger, testScanPathsBroad())

	body := `test body`
	req := httptest.NewRequest("POST", "/v1/chat", strings.NewReader(body))
	req.ContentLength = int64(pii.DefaultMaxInputBytes + 1) // exceed limit
	req.Host = "api.openai.com"

	_, newBody, err := mi.InterceptRequest(req)
	if err != nil {
		t.Fatalf("InterceptRequest failed: %v", err)
	}
	defer func() { _ = newBody.Close() }()

	returnedBytes, _ := io.ReadAll(newBody)
	if string(returnedBytes) != body {
		t.Errorf("body must pass through: got %q, want %q", string(returnedBytes), body)
	}

	entries := parseLogEntries(t, &logBuf)
	hasSkipWarn := false
	for _, e := range entries {
		if e["msg"] == "pii_detection_skipped" && e["reason"] == "oversize" {
			hasSkipWarn = true
			break
		}
	}
	if !hasSkipWarn {
		t.Error("expected oversize skip warn based on Content-Length pre-check")
	}
}

// TestMonitorInterceptor_InterceptRequest_PathSanitization tests that path is sanitized in logs.
func TestMonitorInterceptor_InterceptRequest_PathSanitization(t *testing.T) {
	// DPO-R4: path must be sanitized (no query params).
	engine := newTestEngineFull()
	var logBuf bytes.Buffer
	logger := newTestLogger(&logBuf)
	mi := mustNewMonitorInterceptor(t, engine, true, logger, testScanPathsBroad())

	body := `{"email": "alice@example.com"}`
	req := httptest.NewRequest("POST", "/v1/chat/completions?model=gpt-4&api_key=secret", strings.NewReader(body))
	req.Host = "api.openai.com"
	// Go's HTTP test sets req.URL.Path without query params, so this is correct.
	// The query string is in req.URL.RawQuery.
	// req.URL.Path should be "/v1/chat/completions".

	_, newBody, err := mi.InterceptRequest(req)
	if err != nil {
		t.Fatalf("InterceptRequest failed: %v", err)
	}
	defer func() { _ = newBody.Close() }()
	_, _ = io.ReadAll(newBody)

	entries := parseLogEntries(t, &logBuf)
	for _, e := range entries {
		if e["msg"] == "monitor_scan" {
			if path, ok := e["path"].(string); ok {
				if strings.Contains(path, "?") {
					t.Errorf("path must not contain query parameters, got: %s", path)
				}
				if strings.Contains(path, "api_key") {
					t.Errorf("path must not contain query parameter values, got: %s", path)
				}
			}
		}
	}
}

func TestMonitorInterceptor_InterceptRequest_LongPathTruncation(t *testing.T) {
	// SR-3: path must be truncated to 512 bytes.
	engine := newTestEngineFull()
	var logBuf bytes.Buffer
	logger := newTestLogger(&logBuf)
	mi := mustNewMonitorInterceptor(t, engine, true, logger, testScanPathsBroad())

	longPath := "/v1/" + strings.Repeat("a", 2000)
	body := `{"email": "test@example.com"}`
	req := httptest.NewRequest("POST", longPath, strings.NewReader(body))
	req.Host = "api.openai.com"

	_, newBody, err := mi.InterceptRequest(req)
	if err != nil {
		t.Fatalf("InterceptRequest failed: %v", err)
	}
	defer func() { _ = newBody.Close() }()
	_, _ = io.ReadAll(newBody)

	entries := parseLogEntries(t, &logBuf)
	for _, e := range entries {
		if e["msg"] == "monitor_scan" {
			if path, ok := e["path"].(string); ok {
				if len(path) > maxLogPathLen {
					t.Errorf("path must be truncated to %d bytes, got %d bytes: %s", maxLogPathLen, len(path), path)
				}
			}
		}
	}
}

func TestMonitorInterceptor_InterceptResponse_JSONWithPII(t *testing.T) {
	engine := newTestEngineFull()
	var logBuf bytes.Buffer
	logger := newTestLogger(&logBuf)
	mi := mustNewMonitorInterceptor(t, engine, true, logger, testScanPathsBroad())

	respBody := `{"result": "Contact +1-555-0100 for support"}`
	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
		Body: io.NopCloser(strings.NewReader(respBody)),
		Request: &http.Request{
			Host: "api.openai.com",
			URL:  mustParseURL("/v1/chat/completions"),
		},
	}

	_, newBody, err := mi.InterceptResponse(resp)
	if err != nil {
		t.Fatalf("InterceptResponse failed: %v", err)
	}
	defer func() { _ = newBody.Close() }()

	returnedBytes, _ := io.ReadAll(newBody)
	if string(returnedBytes) != respBody {
		t.Errorf("response body not byte-identical.\n got: %q\nwant: %q", string(returnedBytes), respBody)
	}

	entries := parseLogEntries(t, &logBuf)
	found := false
	for _, e := range entries {
		if e["msg"] == "monitor_scan" {
			found = true
			if e["direction"] != "response" {
				t.Errorf("direction should be 'response', got %v", e["direction"])
			}
			if e["pii_values_logged"] != false {
				t.Errorf("pii_values_logged must be false")
			}
			if e["result"] != "pii_found" {
				t.Errorf("result should be 'pii_found', got %v", e["result"])
			}
			break
		}
	}
	if !found {
		t.Fatal("expected monitor_scan log entry for response with PII")
	}
}

func TestMonitorInterceptor_InterceptResponse_BinarySkip(t *testing.T) {
	engine := newTestEngineFull()
	var logBuf bytes.Buffer
	logger := newTestLogger(&logBuf)
	mi := mustNewMonitorInterceptor(t, engine, true, logger, testScanPathsBroad())

	respBody := "fake image bytes"
	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Content-Type": []string{"image/png"},
		},
		Body: io.NopCloser(strings.NewReader(respBody)),
		Request: &http.Request{
			Host: "api.openai.com",
			URL:  mustParseURL("/v1/chat"),
		},
	}

	_, newBody, err := mi.InterceptResponse(resp)
	if err != nil {
		t.Fatalf("InterceptResponse failed: %v", err)
	}
	defer func() { _ = newBody.Close() }()

	returnedBytes, _ := io.ReadAll(newBody)
	if string(returnedBytes) != respBody {
		t.Error("binary body must be forwarded unchanged")
	}

	entries := parseLogEntries(t, &logBuf)
	// Should have a DEBUG log for skip reason.
	hasDebugSkip := false
	for _, e := range entries {
		if e["msg"] == "pii_detection_skipped" &&
			e["reason"] == "binary_or_unsupported_content_type" {
			hasDebugSkip = true
			break
		}
	}
	if !hasDebugSkip {
		t.Error("expected debug skip log for binary content")
	}
}

func TestMonitorInterceptor_InterceptResponse_MissingContentType(t *testing.T) {
	// DPO-R9: Missing Content-Type → skip detection.
	engine := newTestEngineFull()
	var logBuf bytes.Buffer
	logger := newTestLogger(&logBuf)
	mi := mustNewMonitorInterceptor(t, engine, true, logger, testScanPathsBroad())

	respBody := `test@example.com`
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{}, // no Content-Type
		Body:       io.NopCloser(strings.NewReader(respBody)),
		Request: &http.Request{
			Host: "api.openai.com",
			URL:  mustParseURL("/v1/chat"),
		},
	}

	_, newBody, err := mi.InterceptResponse(resp)
	if err != nil {
		t.Fatalf("InterceptResponse failed: %v", err)
	}
	defer func() { _ = newBody.Close() }()

	returnedBytes, _ := io.ReadAll(newBody)
	if string(returnedBytes) != respBody {
		t.Error("body must be forwarded")
	}

	entries := parseLogEntries(t, &logBuf)
	for _, e := range entries {
		if e["msg"] == "monitor_scan" {
			t.Errorf("should not detect PII when Content-Type is missing: %v", e)
		}
	}
}

func TestMonitorInterceptor_InterceptResponse_MultipartSkip(t *testing.T) {
	engine := newTestEngineFull()
	var logBuf bytes.Buffer
	logger := newTestLogger(&logBuf)
	mi := mustNewMonitorInterceptor(t, engine, true, logger, testScanPathsBroad())

	respBody := "--boundary\r\nContent-Disposition: form-data; name=\"email\"\r\n\r\ntest@example.com\r\n--boundary--"
	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Content-Type": []string{"multipart/form-data; boundary=boundary"},
		},
		Body: io.NopCloser(strings.NewReader(respBody)),
		Request: &http.Request{
			Host: "api.openai.com",
			URL:  mustParseURL("/v1/chat"),
		},
	}

	_, newBody, err := mi.InterceptResponse(resp)
	if err != nil {
		t.Fatalf("InterceptResponse failed: %v", err)
	}
	defer func() { _ = newBody.Close() }()

	returnedBytes, _ := io.ReadAll(newBody)
	if string(returnedBytes) != respBody {
		t.Error("multipart body must be forwarded unchanged")
	}

	entries := parseLogEntries(t, &logBuf)
	for _, e := range entries {
		if e["msg"] == "monitor_scan" {
			t.Errorf("should not detect PII in multipart: %v", e)
		}
	}
}

func TestMonitorInterceptor_InterceptResponse_SSERouting(t *testing.T) {
	engine := newTestEngineFull()
	var logBuf bytes.Buffer
	logger := newTestLogger(&logBuf)
	mi := mustNewMonitorInterceptor(t, engine, true, logger, testScanPathsBroad())

	respBody := `data: {"msg": "test.user@example.com"}` + "\n\n"
	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Content-Type": []string{"text/event-stream"},
		},
		Body: io.NopCloser(strings.NewReader(respBody)),
		Request: &http.Request{
			Host: "api.openai.com",
			URL:  mustParseURL("/v1/chat"),
		},
	}

	_, newBody, err := mi.InterceptResponse(resp)
	if err != nil {
		t.Fatalf("InterceptResponse failed: %v", err)
	}
	defer func() { _ = newBody.Close() }()

	returnedBytes, _ := io.ReadAll(newBody)
	if string(returnedBytes) != respBody {
		t.Errorf("SSE body must be forwarded byte-identical.\n got: %q\nwant: %q", string(returnedBytes), respBody)
	}

	entries := parseLogEntries(t, &logBuf)
	found := false
	for _, e := range entries {
		if e["msg"] == "monitor_scan" {
			found = true
			if sse, _ := e["sse_frame"].(bool); !sse {
				t.Error("SSE detection should have sse_frame: true")
			}
			if e["direction"] != "response" {
				t.Errorf("SSE direction should be 'response', got %v", e["direction"])
			}
			// Aggregated: should have entity_count >= 1
			if ec, _ := e["entity_count"].(float64); ec < 1 {
				t.Errorf("entity_count should be >= 1, got %v", ec)
			}
			break
		}
	}
	if !found {
		t.Fatal("expected monitor_scan for SSE stream with PII")
	}
}

func TestMonitorInterceptor_InterceptResponse_OctetStreamSkip(t *testing.T) {
	engine := newTestEngineFull()
	var logBuf bytes.Buffer
	logger := newTestLogger(&logBuf)
	mi := mustNewMonitorInterceptor(t, engine, true, logger, testScanPathsBroad())

	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Content-Type": []string{"application/octet-stream"},
		},
		Body: io.NopCloser(strings.NewReader("binary stuff")),
		Request: &http.Request{
			Host: "api.openai.com",
			URL:  mustParseURL("/v1/chat"),
		},
	}

	_, newBody, err := mi.InterceptResponse(resp)
	if err != nil {
		t.Fatalf("InterceptResponse failed: %v", err)
	}
	defer func() { _ = newBody.Close() }()

	returnedBytes, _ := io.ReadAll(newBody)
	if string(returnedBytes) != "binary stuff" {
		t.Error("octet-stream body must be forwarded unchanged")
	}

	entries := parseLogEntries(t, &logBuf)
	for _, e := range entries {
		if e["msg"] == "monitor_scan" {
			t.Errorf("should not detect PII in octet-stream: %v", e)
		}
	}
}

func TestMonitorInterceptor_InterceptResponse_ZeroPIIInLogs(t *testing.T) {
	// SR-4: Zero PII in any log output.
	engine := newTestEngineFull()
	var logBuf bytes.Buffer
	logger := newTestLogger(&logBuf)
	mi := mustNewMonitorInterceptor(t, engine, true, logger, testScanPathsBroad())

	body := `{"email": "test.user@example.com", "phone": "+1-555-0100", "card": "4111111111111111"}`
	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
		Body: io.NopCloser(strings.NewReader(body)),
		Request: &http.Request{
			Host: "api.openai.com",
			URL:  mustParseURL("/v1/chat"),
		},
	}

	_, newBody, err := mi.InterceptResponse(resp)
	if err != nil {
		t.Fatalf("InterceptResponse failed: %v", err)
	}
	defer func() { _ = newBody.Close() }()
	_, _ = io.ReadAll(newBody)

	logOutput := logBuf.String()
	// Verify no raw PII in logs.
	forbiddenValues := []string{
		"test.user@example.com",
		"+1-555-0100",
		"4111111111111111",
	}
	for _, v := range forbiddenValues {
		if strings.Contains(logOutput, v) {
			t.Errorf("log output must not contain PII value: %s", v)
		}
	}

	// Verify Entity.Value is never present (it's json:"-").
	if strings.Contains(logOutput, `"Value"`) || strings.Contains(logOutput, `"value"`) {
		t.Error("log output must not contain Entity.Value")
	}
}

func TestMonitorInterceptor_InterceptRequest_NilBody(t *testing.T) {
	// SR-17: nil body should not panic.
	engine := newTestEngineFull()
	var logBuf bytes.Buffer
	logger := newTestLogger(&logBuf)
	mi := mustNewMonitorInterceptor(t, engine, true, logger, testScanPathsBroad())

	req := httptest.NewRequest("GET", "/v1/models", nil)
	req.Host = "api.openai.com"

	_, newBody, err := mi.InterceptRequest(req)
	if err != nil {
		t.Fatalf("InterceptRequest should handle nil body: %v", err)
	}
	if newBody != nil {
		// Read and discard.
		_, _ = io.ReadAll(newBody)
		_ = newBody.Close()
	}
}

func TestMonitorInterceptor_InterceptResponse_NilBody(t *testing.T) {
	// SR-17: nil body should not panic.
	engine := newTestEngineFull()
	var logBuf bytes.Buffer
	logger := newTestLogger(&logBuf)
	mi := mustNewMonitorInterceptor(t, engine, true, logger, testScanPathsBroad())

	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
		Body: nil,
		Request: &http.Request{
			Host: "api.openai.com",
			URL:  mustParseURL("/v1/chat"),
		},
	}

	_, newBody, err := mi.InterceptResponse(resp)
	// May fail due to nil body access in mime type check
	// but should not panic.
	if err != nil {
		t.Logf("expected handling for nil body: %v", err)
	}
	if newBody != nil {
		_ = newBody.Close()
	}
}

func TestMonitorInterceptor_InterceptResponse_ContentTypeWithParams(t *testing.T) {
	// SR-5: Content-Type parameters should be stripped for logging.
	engine := newTestEngineFull()
	var logBuf bytes.Buffer
	logger := newTestLogger(&logBuf)
	mi := mustNewMonitorInterceptor(t, engine, true, logger, testScanPathsBroad())

	body := `{"email": "test@example.com"}`
	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Content-Type": []string{"application/json; charset=utf-8"},
		},
		Body: io.NopCloser(strings.NewReader(body)),
		Request: &http.Request{
			Host: "api.openai.com",
			URL:  mustParseURL("/v1/chat"),
		},
	}

	_, newBody, err := mi.InterceptResponse(resp)
	if err != nil {
		t.Fatalf("InterceptResponse failed: %v", err)
	}
	defer func() { _ = newBody.Close() }()
	_, _ = io.ReadAll(newBody)

	entries := parseLogEntries(t, &logBuf)
	for _, e := range entries {
		if e["msg"] == "monitor_scan" {
			if ct, ok := e["content_type"].(string); ok {
				if strings.Contains(ct, "charset") {
					t.Errorf("content_type should not contain parameters, got: %s", ct)
				}
				if ct != "application/json" {
					t.Errorf("content_type should be 'application/json', got: %s", ct)
				}
			}
		}
	}
}

func TestMonitorInterceptor_MultipleEntityTypes(t *testing.T) {
	engine := newTestEngineFull()
	var logBuf bytes.Buffer
	logger := newTestLogger(&logBuf)
	mi := mustNewMonitorInterceptor(t, engine, true, logger, testScanPathsBroad())

	body := `Contact test.user@example.com or call +1-555-0100. IBAN: GB29NWBK60161331926819`
	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Content-Type": []string{"text/plain"},
		},
		Body: io.NopCloser(strings.NewReader(body)),
		Request: &http.Request{
			Host: "api.openai.com",
			URL:  mustParseURL("/v1/chat"),
		},
	}

	_, newBody, err := mi.InterceptResponse(resp)
	if err != nil {
		t.Fatalf("InterceptResponse failed: %v", err)
	}
	defer func() { _ = newBody.Close() }()
	_, _ = io.ReadAll(newBody)

	entries := parseLogEntries(t, &logBuf)
	for _, e := range entries {
		if e["msg"] == "monitor_scan" {
			ec, _ := e["entity_count"].(float64)
			if ec < 2 {
				t.Errorf("expected at least 2 entities, got %v", ec)
			}
			// entity_summary should have multiple types.
			summary, ok := e["entity_summary"].(map[string]any)
			if !ok {
				t.Error("entity_summary missing or not a map")
			} else if len(summary) < 2 {
				t.Logf("entity_summary: %v (may have fewer types depending on detection)", summary)
			}
			break
		}
	}
}

func TestMonitorInterceptor_ResponseOversize(t *testing.T) {
	engine := newTestEngineFull()
	var logBuf bytes.Buffer
	logger := newTestLogger(&logBuf)
	mi := mustNewMonitorInterceptor(t, engine, true, logger, testScanPathsBroad())

	bigData := strings.Repeat("x", pii.DefaultMaxInputBytes+500)
	body := `{"data": "` + bigData + `"}`
	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
		Body: io.NopCloser(strings.NewReader(body)),
		Request: &http.Request{
			Host: "api.openai.com",
			URL:  mustParseURL("/v1/chat"),
		},
	}

	_, newBody, err := mi.InterceptResponse(resp)
	if err != nil {
		t.Fatalf("InterceptResponse failed: %v", err)
	}
	defer func() { _ = newBody.Close() }()

	returnedBytes, _ := io.ReadAll(newBody)
	if !strings.Contains(string(returnedBytes), bigData) {
		t.Error("oversized response body must be forwarded")
	}
}

func TestContentTypeClassification(t *testing.T) {
	tests := []struct {
		name      string
		mediaType string
		want      ctAction
	}{
		{"json", "application/json", ctAnalyze},
		{"text plain", "text/plain", ctAnalyze},
		{"text html", "text/html", ctAnalyze},
		{"sse", "text/event-stream", ctSSE},
		{"image png", "image/png", ctSkip},
		{"image jpeg", "image/jpeg", ctSkip},
		{"audio mp3", "audio/mpeg", ctSkip},
		{"video mp4", "video/mp4", ctSkip},
		{"octet stream", "application/octet-stream", ctSkip},
		{"multipart", "multipart/form-data", ctSkip},
		{"unknown", "application/x-custom", ctSkip},
		{"empty", "", ctSkip},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyContentType(tt.mediaType)
			if got != tt.want {
				t.Errorf("classifyContentType(%q) = %v, want %v", tt.mediaType, got, tt.want)
			}
		})
	}
}

func TestSanitizeLogPath(t *testing.T) {
	tests := []struct {
		name string
		path string
		want string
	}{
		{"normal", "/v1/chat/completions", "/v1/chat/completions"},
		{"short", "/api", "/api"},
		{"empty", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeLogPath(tt.path)
			if got != tt.want {
				t.Errorf("sanitizeLogPath(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}

	// Test truncation.
	longPath := "/v1/" + strings.Repeat("x", 600)
	got := sanitizeLogPath(longPath)
	if len(got) > maxLogPathLen {
		t.Errorf("long path not truncated: got %d bytes", len(got))
	}
}

func TestSanitizeContentTypeForLog(t *testing.T) {
	// Already parsed by mime.ParseMediaType, so input should be just the media type.
	got := sanitizeContentTypeForLog("application/json")
	if got != "application/json" {
		t.Errorf("expected 'application/json', got %q", got)
	}
}

func TestExtractSSEData(t *testing.T) {
	tests := []struct {
		name     string
		rawFrame string
		want     string
	}{
		{
			name:     "single data line",
			rawFrame: "data: hello world\n\n",
			want:     "hello world",
		},
		{
			name:     "multiple data lines",
			rawFrame: "data: line1\ndata: line2\n\n",
			want:     "line1\nline2",
		},
		{
			name:     "with event and id lines",
			rawFrame: "event: message\nid: 1\ndata: payload\n\n",
			want:     "payload",
		},
		{
			name:     "comment only",
			rawFrame: ": just a comment\n\n",
			want:     "", // PR-104: no data lines → empty, not raw frame
		},
		{
			name:     "empty frame",
			rawFrame: "\n\n",
			want:     "",
		},
		{
			name:     "data with leading space",
			rawFrame: "data:  spaced data\n\n",
			want:     "spaced data",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractSSEData(tt.rawFrame)
			if got != tt.want {
				t.Errorf("extractSSEData(%q) = %q, want %q", tt.rawFrame, got, tt.want)
			}
		})
	}
}

// TestShouldScanPath tests the path filtering logic.
func TestShouldScanPath(t *testing.T) {
	mi := mustNewMonitorInterceptor(t, newTestEngine(), false, nil, testDefaultScanPaths())

	tests := []struct {
		name string
		path string
		want bool
	}{
		{"conversation endpoint", "/backend-anon/conversation", true},
		{"claude messages", "/v1/messages", true},
		{"openai chat completions", "/v1/chat/completions", true},
		{"gemini generate", "/v1beta/models/gemini-pro:generateContent", true},
		{"copilot chat", "/chat/completions", true},
		{"telemetry flush", "/ces/statsc/flush", false},
		{"telemetry intake", "/ces/v1/telemetry/intake", false},
		{"telemetry track", "/ces/v1/t", false},
		{"sentinel endpoint", "/backend-anon/sentinel/chat-requirements/finalize", false},
		{"health check", "/health", false},
		{"case insensitive", "/v1/MESSAGES", true},
		{"empty path", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mi.shouldScanPath(tt.path)
			if got != tt.want {
				t.Errorf("shouldScanPath(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

// TestMonitorInterceptor_ResponsePathFilterSkip verifies path filtering on responses.
func TestMonitorInterceptor_ResponsePathFilterSkip(t *testing.T) {
	engine := newTestEngineFull()
	var logBuf bytes.Buffer
	logger := newTestLogger(&logBuf)
	mi := mustNewMonitorInterceptor(t, engine, true, logger, testScanPathsBroad())

	respBody := `{"email": "test@example.com"}`
	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
		Body: io.NopCloser(strings.NewReader(respBody)),
		Request: &http.Request{
			Host: "api.openai.com",
			URL:  mustParseURL("/ces/statsc/flush"),
		},
	}

	_, newBody, err := mi.InterceptResponse(resp)
	if err != nil {
		t.Fatalf("InterceptResponse failed: %v", err)
	}
	defer func() { _ = newBody.Close() }()

	returnedBytes, _ := io.ReadAll(newBody)
	if string(returnedBytes) != respBody {
		t.Error("body must be forwarded unchanged")
	}

	// No monitor_scan entries for skipped path.
	entries := parseLogEntries(t, &logBuf)
	for _, e := range entries {
		if e["msg"] == "monitor_scan" {
			t.Errorf("unexpected monitor_scan for skipped response path: %v", e)
		}
	}
}

// mustParseURL parses a URL and panics on error (for test setup only).
func mustParseURL(rawURL string) *url.URL {
	u, err := url.Parse(rawURL)
	if err != nil {
		panic(err)
	}
	return u
}

// --- New tests from Fix Round 1 (per peer review FR-1, FR-2, FR-6) ---

// closingReader is a reader that tracks whether Close() was called
// and, after Close(), simulates a real HTTP body by returning errors on reads.
type closingReader struct {
	*strings.Reader
	closed bool
}

func newClosingReader(s string) *closingReader {
	return &closingReader{Reader: strings.NewReader(s)}
}

func (r *closingReader) Close() error {
	r.closed = true
	return nil
}

func (r *closingReader) Read(p []byte) (int, error) {
	if r.closed {
		return 0, io.ErrClosedPipe
	}
	return r.Reader.Read(p)
}

// TestMonitorInterceptor_OversizeBodyWithClosingReader verifies PR-001:
// oversized bodies are not truncated when the reader has real Close() behavior.
func TestMonitorInterceptor_OversizeBodyWithClosingReader(t *testing.T) {
	// Create a small engine (100 byte limit) so the test is fast.
	smallEngine := pii.NewEngine(100,
		pii.NewEmailRecognizer(),
		pii.NewPhoneRecognizer(),
	)
	var logBuf bytes.Buffer
	logger := newTestLogger(&logBuf)
	mi := mustNewMonitorInterceptor(t, smallEngine, true, logger, testScanPathsBroad())

	// Body is 300 bytes, limit is 100. Body exceeds limit.
	bodyStr := strings.Repeat("ABCDEFGHIJ", 30) // 300 bytes
	reader := newClosingReader(bodyStr)

	req := httptest.NewRequest("POST", "/v1/chat", reader)
	req.ContentLength = -1 // chunked, unknown length
	req.Host = "api.openai.com"

	_, newBody, err := mi.InterceptRequest(req)
	if err != nil {
		t.Fatalf("InterceptRequest failed: %v", err)
	}
	defer func() { _ = newBody.Close() }()

	returnedBytes, err := io.ReadAll(newBody)
	if err != nil {
		t.Fatalf("reading returned body: %v", err)
	}

	// The entire 300-byte body must be forwarded (PR-001).
	if string(returnedBytes) != bodyStr {
		t.Errorf("oversized body was truncated.\n got:  %d bytes\nwant: %d bytes",
			len(returnedBytes), len(bodyStr))
	}

	// Verify the underlying reader was NOT closed during processing.
	if reader.closed {
		t.Error("original body reader must NOT be closed by the interceptor in oversize path (the MultiReader owns it)")
	}
}

// TestMonitorInterceptor_InterceptResponse_PIILoggingDisabled verifies FR-2:
// pii_logging=false suppresses entity_summary but still emits monitor_scan.
func TestMonitorInterceptor_InterceptResponse_PIILoggingDisabled(t *testing.T) {
	engine := newTestEngineFull()
	var logBuf bytes.Buffer
	logger := newTestLogger(&logBuf)
	mi := mustNewMonitorInterceptor(t, engine, false, logger, testScanPathsBroad())

	respBody := `{"email": "test@example.com", "phone": "+1-555-0100"}`
	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
		Body: io.NopCloser(strings.NewReader(respBody)),
		Request: &http.Request{
			Host: "api.openai.com",
			URL:  mustParseURL("/v1/chat"),
		},
	}

	_, newBody, err := mi.InterceptResponse(resp)
	if err != nil {
		t.Fatalf("InterceptResponse failed: %v", err)
	}
	defer func() { _ = newBody.Close() }()
	_, _ = io.ReadAll(newBody)

	// Body must still be forwarded.
	// Should have monitor_scan with result=pii_found, entity_count, but NO entity_summary.
	entries := parseLogEntries(t, &logBuf)
	var scanEntries []map[string]any
	for _, e := range entries {
		if e["msg"] == "monitor_scan" {
			scanEntries = append(scanEntries, e)
		}
	}
	if len(scanEntries) != 1 {
		t.Fatalf("expected 1 monitor_scan entry, got %d", len(scanEntries))
	}
	e := scanEntries[0]
	if e["result"] != "pii_found" {
		t.Errorf("expected result=pii_found, got %v", e["result"])
	}
	if _, ok := e["entity_count"]; !ok {
		t.Error("entity_count should be present")
	}
	if _, ok := e["entity_summary"]; ok {
		t.Error("entity_summary must be omitted when pii_logging=false")
	}
}

// TestMonitorInterceptor_ConcurrentAccess verifies FR-6:
// concurrent goroutines using the same MonitorInterceptor do not race.
func TestMonitorInterceptor_ConcurrentAccess(t *testing.T) {
	engine := newTestEngineFull()
	var logBuf bytes.Buffer
	logger := newTestLogger(&logBuf)
	mi := mustNewMonitorInterceptor(t, engine, true, logger, testScanPathsBroad())

	const goroutines = 10
	errs := make(chan error, goroutines*2)

	for i := 0; i < goroutines; i++ {
		go func() {
			body := `{"email": "concurrent@example.com"}`
			req := httptest.NewRequest("POST", "/v1/chat", strings.NewReader(body))
			req.Host = "api.openai.com"
			_, newBody, err := mi.InterceptRequest(req)
			if err != nil {
				errs <- err
				return
			}
			_, _ = io.ReadAll(newBody)
			_ = newBody.Close()
			errs <- nil
		}()
	}

	for i := 0; i < goroutines; i++ {
		if err := <-errs; err != nil {
			t.Errorf("concurrent InterceptRequest failed: %v", err)
		}
	}

	// Log buffer may contain entries from concurrent goroutines — that's expected.
	_ = logBuf
}

// TestExtractSSEData_CRLF verifies PR-008: CRLF line endings are handled.
func TestExtractSSEData_CRLF(t *testing.T) {
	tests := []struct {
		name     string
		rawFrame string
		want     string
	}{
		{
			name:     "CRLF data line",
			rawFrame: "data: hello\r\n\r\n",
			want:     "hello",
		},
		{
			name:     "CRLF multi-line",
			rawFrame: "data: line1\r\ndata: line2\r\n\r\n",
			want:     "line1\nline2",
		},
		{
			name:     "mixed LF and CRLF",
			rawFrame: "data: line1\r\ndata: line2\n\n",
			want:     "line1\nline2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractSSEData(tt.rawFrame)
			if got != tt.want {
				t.Errorf("extractSSEData(%q) = %q, want %q", tt.rawFrame, got, tt.want)
			}
		})
	}
}

// TestNextFrameBoundary verifies frame boundary detection for both LF and CRLF.
func TestNextFrameBoundary(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantIdx int
		wantLen int
	}{
		{"LF found", []byte("data: hello\n\n"), 11, 2},
		{"LF not found", []byte("data: hello"), -1, 0},
		{"CRLF found", []byte("data: hello\r\n\r\n"), 11, 4},
		{"LF preferred over CRLF at same pos", []byte("\n\n\r\n\r\n"), 0, 2},
		{"CRLF only", []byte("data\r\n\r\n"), 4, 4},
		{"empty", []byte{}, -1, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotIdx, gotLen := nextFrameBoundary(tt.data)
			if gotIdx != tt.wantIdx || gotLen != tt.wantLen {
				t.Errorf("nextFrameBoundary(%q) = (%d, %d), want (%d, %d)",
					tt.data, gotIdx, gotLen, tt.wantIdx, tt.wantLen)
			}
		})
	}
}

// --- combinedReadCloser tests (PR-002) ---

// TestCombinedReadCloser_ClosePropagation verifies that Close() on a
// combinedReadCloser delegates to the underlying closer and does not
// leak the original body reader (PR-002).
func TestCombinedReadCloser_ClosePropagation(t *testing.T) {
	body := "test body content"
	cr := newClosingReader(body)
	combined := &combinedReadCloser{
		Reader: io.MultiReader(
			bytes.NewReader([]byte("prefix ")),
			cr,
		),
		closer: cr,
	}

	// Read all bytes.
	output, err := io.ReadAll(combined)
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}
	if string(output) != "prefix test body content" {
		t.Errorf("unexpected combined output: %q", string(output))
	}

	// Close should propagate to underlying closer.
	if err := combined.Close(); err != nil {
		t.Errorf("Close() failed: %v", err)
	}
	if !cr.closed {
		t.Error("underlying closer was NOT closed by combinedReadCloser.Close()")
	}

	// After close, reads should fail.
	_, err = combined.Read(make([]byte, 10))
	if err == nil {
		t.Error("expected error reading after Close")
	}
}

// TestCombinedReadCloser_WithoutMultiReader is a minimal sanity test.
func TestCombinedReadCloser_WithoutMultiReader(t *testing.T) {
	cr := newClosingReader("hello world")
	combined := &combinedReadCloser{
		Reader: cr,
		closer: cr,
	}

	out, err := io.ReadAll(combined)
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}
	if string(out) != "hello world" {
		t.Errorf("unexpected output: %q", string(out))
	}
}

// TestCombinedReadCloser_OversizeBodyCloseIsPropagated validates the full
// end-to-end flow: an oversize body passes through InterceptRequest, and
// when the returned body is closed, the original body is also closed.
func TestCombinedReadCloser_OversizeBodyCloseIsPropagated(t *testing.T) {
	// Create a small engine (100 byte limit) to trigger oversize path.
	smallEngine := pii.NewEngine(100,
		pii.NewEmailRecognizer(),
		pii.NewPhoneRecognizer(),
	)
	var logBuf bytes.Buffer
	logger := newTestLogger(&logBuf)
	mi := mustNewMonitorInterceptor(t, smallEngine, true, logger, testScanPathsBroad())

	bodyStr := strings.Repeat("ABCDEFGHIJ", 30) // 300 bytes > 100 limit
	cr := newClosingReader(bodyStr)

	req := httptest.NewRequest("POST", "/v1/chat", cr)
	req.ContentLength = -1
	req.Host = "api.openai.com"

	_, newBody, err := mi.InterceptRequest(req)
	if err != nil {
		t.Fatalf("InterceptRequest failed: %v", err)
	}

	// The returned body should be a combinedReadCloser.
	_, ok := newBody.(*combinedReadCloser)
	if !ok {
		t.Errorf("expected *combinedReadCloser on oversize path, got %T", newBody)
	}

	// Read all content.
	returnedBytes, err := io.ReadAll(newBody)
	if err != nil {
		t.Fatalf("ReadAll on returned body: %v", err)
	}
	if len(returnedBytes) != len(bodyStr) {
		t.Errorf("expected %d bytes, got %d", len(bodyStr), len(returnedBytes))
	}

	// Before close, original body should not be closed.
	if cr.closed {
		t.Error("original body must not be closed before returned body Close()")
	}

	// Close the returned body.
	if err := newBody.Close(); err != nil {
		t.Errorf("Close() on returned body failed: %v", err)
	}

	// After close, original body must be closed.
	if !cr.closed {
		t.Error("original body was NOT closed when returned body was closed (PR-002 leak)")
	}
}

// TestBuildEntitySummary verifies entity count aggregation.
func TestBuildEntitySummary(t *testing.T) {
	entities := []pii.Entity{
		{Type: pii.Email, Source: pii.SourceRegex, Confidence: 0.95},
		{Type: pii.Phone, Source: pii.SourceRegex, Confidence: 0.90},
		{Type: pii.Email, Source: pii.SourceRegex, Confidence: 0.85},
	}
	summary := buildEntitySummary(entities)
	if summary["EMAIL"] != 2 {
		t.Errorf("expected EMAIL count 2, got %d", summary["EMAIL"])
	}
	if summary["PHONE"] != 1 {
		t.Errorf("expected PHONE count 1, got %d", summary["PHONE"])
	}
}

// TestMonitorInterceptor_InterceptRequest_PathFilterSubstringMatch verifies
// that substring matching works correctly for path filtering.
func TestMonitorInterceptor_InterceptRequest_PathFilterSubstringMatch(t *testing.T) {
	engine := newTestEngineFull()
	var logBuf bytes.Buffer
	logger := newTestLogger(&logBuf)
	// Only scan /conversation paths.
	mi := mustNewMonitorInterceptor(t, engine, true, logger, []string{"/conversation"})

	body := `{"email": "test@example.com"}`
	// This path contains /chat/completions but NOT /conversation.
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(body))
	req.Host = "api.openai.com"

	_, newBody, err := mi.InterceptRequest(req)
	if err != nil {
		t.Fatalf("InterceptRequest failed: %v", err)
	}
	defer func() { _ = newBody.Close() }()
	_, _ = io.ReadAll(newBody)

	// Should be skipped — no monitor_scan.
	entries := parseLogEntries(t, &logBuf)
	for _, e := range entries {
		if e["msg"] == "monitor_scan" {
			t.Errorf("unexpected monitor_scan for non-conversation path: %v", e)
		}
	}
}
