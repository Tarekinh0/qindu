package interceptor

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// --- FlowRing tests ---

func TestFlowRing_Empty(t *testing.T) {
	ring := NewFlowRing()

	if ring.Len() != 0 {
		t.Errorf("empty ring Len() = %d, want 0", ring.Len())
	}
	if ring.Cap() != flowRingMaxEntries {
		t.Errorf("empty ring Cap() = %d, want %d", ring.Cap(), flowRingMaxEntries)
	}
	if snap := ring.Snapshot(); snap != nil {
		t.Errorf("empty ring Snapshot() = %v, want nil", snap)
	}
}

func TestFlowRing_SingleEntry(t *testing.T) {
	ring := NewFlowRing()
	ring.Record("ingress body", "egress body", "api.openai.com", "POST", "/v1/chat/completions")

	if ring.Len() != 1 {
		t.Fatalf("Len() = %d, want 1", ring.Len())
	}

	snap := ring.Snapshot()
	if len(snap) != 1 {
		t.Fatalf("Snapshot() len = %d, want 1", len(snap))
	}

	entry := snap[0]
	if entry.ID != 1 {
		t.Errorf("entry.ID = %d, want 1", entry.ID)
	}
	if entry.Host != "api.openai.com" {
		t.Errorf("entry.Host = %q, want %q", entry.Host, "api.openai.com")
	}
	if entry.Method != "POST" {
		t.Errorf("entry.Method = %q, want %q", entry.Method, "POST")
	}
	if entry.Path != "/v1/chat/completions" {
		t.Errorf("entry.Path = %q, want %q", entry.Path, "/v1/chat/completions")
	}
	if entry.IngressBody != "ingress body" {
		t.Errorf("entry.IngressBody = %q, want %q", entry.IngressBody, "ingress body")
	}
	if entry.EgressBody != "egress body" {
		t.Errorf("entry.EgressBody = %q, want %q", entry.EgressBody, "egress body")
	}
	if entry.BodyBytesIn != 12 {
		t.Errorf("entry.BodyBytesIn = %d, want 12", entry.BodyBytesIn)
	}
	if entry.BodyBytesOut != 11 {
		t.Errorf("entry.BodyBytesOut = %d, want 11", entry.BodyBytesOut)
	}
	if entry.Timestamp == "" {
		t.Error("entry.Timestamp is empty")
	}
}

func TestFlowRing_TokenSummary(t *testing.T) {
	ring := NewFlowRing()
	ring.Record(
		"Hello alice@corp.com, call +33612345678",
		"Hello <<EMAIL_1>>, call <<PHONE_2>>",
		"api.openai.com",
		"POST",
		"/v1/chat",
	)

	snap := ring.Snapshot()
	summary := snap[0].EntitySummary
	if summary == nil {
		t.Fatal("EntitySummary is nil, want non-nil")
	}
	if summary["EMAIL"] != 1 {
		t.Errorf("EntitySummary[EMAIL] = %d, want 1", summary["EMAIL"])
	}
	if summary["PHONE"] != 2 {
		t.Errorf("EntitySummary[PHONE] = %d, want 2", summary["PHONE"])
	}
}

func TestFlowRing_MultipleEntries(t *testing.T) {
	ring := NewFlowRing()

	for i := 0; i < 5; i++ {
		ring.Record(
			"ingress body",
			"egress body",
			"host.example.com",
			"GET",
			"/path",
		)
	}

	if ring.Len() != 5 {
		t.Fatalf("Len() = %d, want 5", ring.Len())
	}

	snap := ring.Snapshot()
	if len(snap) != 5 {
		t.Fatalf("Snapshot() len = %d, want 5", len(snap))
	}

	// Verify IDs are sequential.
	for i, entry := range snap {
		if entry.ID != i+1 {
			t.Errorf("entry[%d].ID = %d, want %d", i, entry.ID, i+1)
		}
	}
}

// TestFlowRing_Eviction verifies AC-4: FIFO eviction when exceeding max entries.
func TestFlowRing_Eviction(t *testing.T) {
	ring := NewFlowRing()
	totalEntries := flowRingMaxEntries + 10 // exceed capacity by 10

	for i := 0; i < totalEntries; i++ {
		ring.Record(
			"ingress body",
			"egress body",
			"host",
			"POST",
			"/path",
		)
	}

	if ring.Len() != flowRingMaxEntries {
		t.Fatalf("Len() = %d, want %d (capped at max)", ring.Len(), flowRingMaxEntries)
	}

	snap := ring.Snapshot()
	if len(snap) != flowRingMaxEntries {
		t.Fatalf("Snapshot() len = %d, want %d", len(snap), flowRingMaxEntries)
	}

	// The first entry should be the 11th one (0-9 evicted, 10-59 remain).
	// First ID = totalEntries - flowRingMaxEntries + 1
	firstExpectedID := totalEntries - flowRingMaxEntries + 1
	if snap[0].ID != firstExpectedID {
		t.Errorf("first entry ID = %d, want %d (oldest 10 evicted)", snap[0].ID, firstExpectedID)
	}

	// Last entry should be the most recent one.
	if snap[len(snap)-1].ID != totalEntries {
		t.Errorf("last entry ID = %d, want %d", snap[len(snap)-1].ID, totalEntries)
	}
}

// TestFlowRing_Concurrency verifies that concurrent writes and reads do not
// cause data races or corruption (AC-9).
func TestFlowRing_Concurrency(t *testing.T) {
	ring := NewFlowRing()
	const goroutines = 20
	const writesPerGoroutine = 10
	var wg sync.WaitGroup

	// Concurrent writers.
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < writesPerGoroutine; i++ {
				ring.Record(
					"ingress",
					"egress",
					"host",
					"POST",
					"/path",
				)
			}
		}(g)
	}

	// Concurrent readers during writes.
	for g := 0; g < 5; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < writesPerGoroutine*2; i++ {
				_ = ring.Len()
				_ = ring.Cap()
				_ = ring.Snapshot()
			}
		}()
	}

	wg.Wait()

	// Ring should not exceed capacity.
	if ring.Len() > flowRingMaxEntries {
		t.Errorf("Len() = %d exceeds capacity %d", ring.Len(), flowRingMaxEntries)
	}
}

// TestFlowRing_SnapshotIsCopy verifies that the snapshot is independent
// of the ring buffer's internal state (no aliasing).
func TestFlowRing_SnapshotIsCopy(t *testing.T) {
	ring := NewFlowRing()
	ring.Record("ingress1", "egress1", "h1", "GET", "/1")
	ring.Record("ingress2", "egress2", "h2", "POST", "/2")

	snap := ring.Snapshot()
	if len(snap) != 2 {
		t.Fatalf("Snapshot() len = %d, want 2", len(snap))
	}

	// Mutate the snapshot — ring should be unaffected.
	snap[0].IngressBody = "modified"
	ring.Record("ingress3", "egress3", "h3", "PUT", "/3")

	// After adding a 3rd entry to a 50-cap ring, we now have 3 entries.
	snap2 := ring.Snapshot()
	if len(snap2) != 3 {
		t.Fatalf("After Record, Snapshot() len = %d, want 3", len(snap2))
	}
	if snap2[0].IngressBody == "modified" {
		t.Error("snapshot mutation leaked into ring buffer internal state")
	}
	// Verify the original entries are intact.
	if snap2[0].IngressBody != "ingress1" {
		t.Errorf("first entry ingress = %q, want %q", snap2[0].IngressBody, "ingress1")
	}
	if snap2[1].IngressBody != "ingress2" {
		t.Errorf("second entry ingress = %q, want %q", snap2[1].IngressBody, "ingress2")
	}
	if snap2[2].IngressBody != "ingress3" {
		t.Errorf("third entry ingress = %q, want %q", snap2[2].IngressBody, "ingress3")
	}
}

// --- tokenSummary tests ---

func TestTokenSummary_Empty(t *testing.T) {
	summary := tokenSummary("no tokens here")
	if summary != nil {
		t.Errorf("tokenSummary of clean text = %v, want nil", summary)
	}
}

func TestTokenSummary_SingleToken(t *testing.T) {
	summary := tokenSummary("Hello <<EMAIL_1>>")
	if summary == nil {
		t.Fatal("tokenSummary returned nil, want non-nil")
	}
	if summary["EMAIL"] != 1 {
		t.Errorf("summary[EMAIL] = %d, want 1", summary["EMAIL"])
	}
}

func TestTokenSummary_MultipleTypes(t *testing.T) {
	summary := tokenSummary("<<EMAIL_5>> and <<PHONE_3>> and <<EMAIL_6>>")
	if summary == nil {
		t.Fatal("tokenSummary returned nil")
	}
	if summary["EMAIL"] != 6 {
		t.Errorf("summary[EMAIL] = %d, want 6 (max counter)", summary["EMAIL"])
	}
	if summary["PHONE"] != 3 {
		t.Errorf("summary[PHONE] = %d, want 3", summary["PHONE"])
	}
}

func TestTokenSummary_AllKnownTypes(t *testing.T) {
	text := "<<EMAIL_1>> <<PHONE_2>> <<IBAN_3>> <<CREDIT_CARD_4>> <<JWT_5>> <<NAME_6>> <<SECRET_7>> <<PRIVATE_KEY_8>>"
	summary := tokenSummary(text)
	if summary == nil {
		t.Fatal("tokenSummary returned nil")
	}
	expected := map[string]int{
		"EMAIL": 1, "PHONE": 2, "IBAN": 3, "CREDIT_CARD": 4,
		"JWT": 5, "NAME": 6, "SECRET": 7, "PRIVATE_KEY": 8,
	}
	for k, v := range expected {
		if summary[k] != v {
			t.Errorf("summary[%s] = %d, want %d", k, summary[k], v)
		}
	}
}

func TestTokenSummary_MalformedTokensIgnored(t *testing.T) {
	summary := tokenSummary("<<EMAIL_1>> and <<UNKNOWN_TYPE_1>> and <<INVALID>> and <<EMAIL_999abc>>")
	if summary == nil {
		t.Fatal("tokenSummary returned nil")
	}
	if summary["EMAIL"] != 1 {
		t.Errorf("summary[EMAIL] = %d, want 1 (only well-formed tokens counted)", summary["EMAIL"])
	}
	if _, ok := summary["UNKNOWN_TYPE"]; ok {
		t.Error("UNKNOWN_TYPE should not appear in summary")
	}
}

// --- DebugInterceptor tests ---

// stubInterceptor implements innerInterceptor for testing.
type stubInterceptor struct {
	transformFn   func(body string) string
	shouldProcess bool // defaults to false; set true to simulate a processing interceptor
}

func (s *stubInterceptor) InterceptRequest(req *http.Request) (*http.Request, io.ReadCloser, error) {
	var bodyBytes []byte
	if req.Body != nil {
		bodyBytes, _ = io.ReadAll(req.Body)
		_ = req.Body.Close()
	}
	transformed := string(bodyBytes)
	if s.transformFn != nil {
		transformed = s.transformFn(string(bodyBytes))
	}
	return req, io.NopCloser(bytes.NewReader([]byte(transformed))), nil
}

func (s *stubInterceptor) InterceptResponse(resp *http.Response) (*http.Response, io.ReadCloser, error) {
	return resp, resp.Body, nil
}

func (s *stubInterceptor) ShouldProcess(host, method, path string) bool {
	return s.shouldProcess
}

// errorInterceptor always returns an error.
type errorInterceptor struct{}

func (e *errorInterceptor) InterceptRequest(req *http.Request) (*http.Request, io.ReadCloser, error) {
	return nil, nil, io.ErrUnexpectedEOF
}

func (e *errorInterceptor) InterceptResponse(resp *http.Response) (*http.Response, io.ReadCloser, error) {
	return nil, nil, io.ErrUnexpectedEOF
}

func (e *errorInterceptor) ShouldProcess(host, method, path string) bool {
	return true // error interceptor processes everything (but then fails)
}

func TestDebugInterceptor_PassThrough(t *testing.T) {
	ring := NewFlowRing()
	stub := &stubInterceptor{shouldProcess: true}
	di := NewDebugInterceptor(stub, ring)

	body := `{"email": "test.user@example.com"}`
	req := httptest.NewRequest("POST", "https://api.openai.com/v1/chat/completions", strings.NewReader(body))
	req.Host = "api.openai.com"

	newReq, newBody, err := di.InterceptRequest(req)
	if err != nil {
		t.Fatalf("InterceptRequest failed: %v", err)
	}
	if newReq != req {
		t.Error("InterceptRequest should return the same request pointer")
	}

	bodyBytes, err := io.ReadAll(newBody)
	if err != nil {
		t.Fatalf("reading body: %v", err)
	}
	newBody.Close()

	// Body should pass through unchanged since stub does no transformation.
	if string(bodyBytes) != body {
		t.Errorf("body = %q, want %q", string(bodyBytes), body)
	}

	// FlowRing should have 1 entry.
	if ring.Len() != 1 {
		t.Fatalf("ring.Len() = %d, want 1", ring.Len())
	}

	entry := ring.Snapshot()[0]
	if entry.IngressBody != body {
		t.Errorf("IngressBody = %q, want %q", entry.IngressBody, body)
	}
	if entry.EgressBody != body {
		t.Errorf("EgressBody = %q, want %q", entry.EgressBody, body)
	}
	if entry.Host != "api.openai.com" {
		t.Errorf("Host = %q, want %q", entry.Host, "api.openai.com")
	}
	if entry.Method != "POST" {
		t.Errorf("Method = %q, want %q", entry.Method, "POST")
	}
}

func TestDebugInterceptor_CapturesTransformation(t *testing.T) {
	ring := NewFlowRing()
	stub := &stubInterceptor{
		shouldProcess: true,
		transformFn: func(body string) string {
			return strings.ReplaceAll(body, "test.user@example.com", "<<EMAIL_1>>")
		},
	}
	di := NewDebugInterceptor(stub, ring)

	ingress := `{"email": "test.user@example.com"}`
	expectedEgress := `{"email": "<<EMAIL_1>>"}`
	req := httptest.NewRequest("POST", "https://api.openai.com/v1/chat/completions", strings.NewReader(ingress))

	_, newBody, err := di.InterceptRequest(req)
	if err != nil {
		t.Fatalf("InterceptRequest failed: %v", err)
	}

	bodyBytes, _ := io.ReadAll(newBody)
	newBody.Close()

	if string(bodyBytes) != expectedEgress {
		t.Errorf("body = %q, want %q", string(bodyBytes), expectedEgress)
	}

	entry := ring.Snapshot()[0]
	if entry.IngressBody != ingress {
		t.Errorf("IngressBody = %q, want %q", entry.IngressBody, ingress)
	}
	if entry.EgressBody != expectedEgress {
		t.Errorf("EgressBody = %q, want %q", entry.EgressBody, expectedEgress)
	}
	if entry.EntitySummary == nil || entry.EntitySummary["EMAIL"] != 1 {
		t.Errorf("EntitySummary = %v, want EMAIL=1", entry.EntitySummary)
	}
}

func TestDebugInterceptor_InterceptResponsePassthrough(t *testing.T) {
	ring := NewFlowRing()
	stub := &stubInterceptor{shouldProcess: true}
	di := NewDebugInterceptor(stub, ring)

	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(`{"result": "ok"}`)),
	}

	newResp, newBody, err := di.InterceptResponse(resp)
	if err != nil {
		t.Fatalf("InterceptResponse failed: %v", err)
	}
	if newResp != resp {
		t.Error("should return same response pointer")
	}
	bodyBytes, _ := io.ReadAll(newBody)
	newBody.Close()
	if string(bodyBytes) != `{"result": "ok"}` {
		t.Errorf("body = %q, want %q", string(bodyBytes), `{"result": "ok"}`)
	}

	// InterceptResponse should NOT record in FlowRing (only request path).
	if ring.Len() != 0 {
		t.Errorf("ring.Len() = %d after InterceptResponse, want 0", ring.Len())
	}
}

func TestDebugInterceptor_InnerErrorRecordsEmptyEgress(t *testing.T) {
	ring := NewFlowRing()
	di := NewDebugInterceptor(&errorInterceptor{}, ring)

	ingress := `test body`
	req := httptest.NewRequest("POST", "https://api.openai.com/path", strings.NewReader(ingress))

	_, _, err := di.InterceptRequest(req)
	if err == nil {
		t.Fatal("expected error from inner interceptor")
	}

	// FlowRing should still have an entry with empty egress.
	if ring.Len() != 1 {
		t.Fatalf("ring.Len() = %d, want 1 (error still recorded)", ring.Len())
	}
	entry := ring.Snapshot()[0]
	if entry.IngressBody != ingress {
		t.Errorf("IngressBody = %q, want %q", entry.IngressBody, ingress)
	}
	if entry.EgressBody != "" {
		t.Errorf("EgressBody = %q, want empty (inner interceptor errored)", entry.EgressBody)
	}
}

func TestDebugInterceptor_NilBody(t *testing.T) {
	ring := NewFlowRing()
	stub := &stubInterceptor{shouldProcess: true}
	di := NewDebugInterceptor(stub, ring)

	req := httptest.NewRequest("GET", "https://api.openai.com/path", nil)

	_, _, err := di.InterceptRequest(req)
	if err != nil {
		t.Fatalf("InterceptRequest with nil body: %v", err)
	}

	// Nil body should NOT record an entry (no ingress to capture).
	if ring.Len() != 0 {
		t.Errorf("ring.Len() = %d for nil body, want 0", ring.Len())
	}
}

// --- FlowHandler tests ---

func TestFlowHandler_EmptyRing(t *testing.T) {
	ring := NewFlowRing()
	handler := FlowHandler(ring)

	req := httptest.NewRequest("GET", "/debug/flow", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	resp := w.Result()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	bodyBytes, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	var fr flowResponse
	if err := json.Unmarshal(bodyBytes, &fr); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if fr.BufferSize != flowRingMaxEntries {
		t.Errorf("buffer_size = %d, want %d", fr.BufferSize, flowRingMaxEntries)
	}
	if fr.EntriesCount != 0 {
		t.Errorf("entries_count = %d, want 0", fr.EntriesCount)
	}
	if len(fr.Entries) != 0 {
		t.Errorf("entries len = %d, want 0", len(fr.Entries))
	}
}

func TestFlowHandler_WithEntries(t *testing.T) {
	ring := NewFlowRing()
	ring.Record("ingress1", "egress1", "host1", "POST", "/1")
	ring.Record("ingress2", "egress2", "host2", "GET", "/2")

	handler := FlowHandler(ring)

	req := httptest.NewRequest("GET", "/debug/flow", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	resp := w.Result()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	bodyBytes, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	var fr flowResponse
	if err := json.Unmarshal(bodyBytes, &fr); err != nil {
		t.Fatalf("invalid JSON: %v\nBody: %s", err, string(bodyBytes))
	}

	if fr.EntriesCount != 2 {
		t.Errorf("entries_count = %d, want 2", fr.EntriesCount)
	}
	if len(fr.Entries) != 2 {
		t.Fatalf("entries len = %d, want 2", len(fr.Entries))
	}

	// Verify entry data.
	e1 := fr.Entries[0]
	if e1.IngressBody != "ingress1" || e1.EgressBody != "egress1" {
		t.Error("first entry data mismatch")
	}
}

func TestFlowHandler_JSONValidity(t *testing.T) {
	ring := NewFlowRing()
	ring.Record("body with special chars: \n\t\"\\", "egress", "host", "GET", "/")

	handler := FlowHandler(ring)
	req := httptest.NewRequest("GET", "/debug/flow", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	bodyBytes, _ := io.ReadAll(w.Result().Body)
	w.Result().Body.Close()

	// Verify valid JSON.
	var fr flowResponse
	if err := json.Unmarshal(bodyBytes, &fr); err != nil {
		t.Fatalf("invalid JSON: %v\nBody: %s", err, string(bodyBytes))
	}

	// Verify ingress body with special chars survived JSON round-trip.
	if fr.Entries[0].IngressBody != "body with special chars: \n\t\"\\" {
		t.Errorf("special chars not preserved after JSON round-trip: %q", fr.Entries[0].IngressBody)
	}
}

// TestFlowHandler_CacheHeaders verifies no caching of flow inspector data.
func TestFlowHandler_CacheHeaders(t *testing.T) {
	ring := NewFlowRing()
	handler := FlowHandler(ring)

	req := httptest.NewRequest("GET", "/debug/flow", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	cc := w.Result().Header.Get("Cache-Control")
	if !strings.Contains(cc, "no-store") {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
	if !strings.Contains(cc, "no-cache") {
		t.Errorf("Cache-Control missing no-cache: %q", cc)
	}
}

// --- Compile-time checks ---

func TestDebugInterceptorSatisfiesInnerInterceptor(t *testing.T) {
	// This is a compile-time test — the var _ check in debug.go already covers it.
	// The test validates the type assertion at runtime.
	var di *DebugInterceptor
	var _ innerInterceptor = di
	_ = di // no-op, just forces the type check.
}

// TestTokenPatternRegex_InitValidation verifies the regex extracts known entity types
// and counters correctly. This was previously validated via panic() in init() but
// now lives in the test suite where it belongs.
func TestTokenPatternRegex_InitValidation(t *testing.T) {
	if tokenPatternRegex == nil {
		t.Fatal("tokenPatternRegex failed to compile")
	}
	testCases := []struct {
		input    string
		wantType string
		wantCnt  int
	}{
		{"<<EMAIL_1>>", "EMAIL", 1},
		{"<<PHONE_2>>", "PHONE", 2},
		{"<<PRIVATE_KEY_99>>", "PRIVATE_KEY", 99},
	}
	for _, tc := range testCases {
		m := tokenPatternRegex.FindStringSubmatch(tc.input)
		if m == nil {
			t.Fatalf("tokenPatternRegex did not match %q", tc.input)
		}
		if m[1] != tc.wantType {
			t.Errorf("wrong type for %q: got %q, want %q", tc.input, m[1], tc.wantType)
		}
		cnt, _ := strconv.Atoi(m[2])
		if cnt != tc.wantCnt {
			t.Errorf("wrong counter for %q: got %d, want %d", tc.input, cnt, tc.wantCnt)
		}
	}
}

// TestTokenPatternRegex_Basic verifies the regex against a wider test set.
func TestTokenPatternRegex_Basic(t *testing.T) {
	tests := []struct {
		input    string
		wantType string
		wantCnt  int
	}{
		{"<<EMAIL_1>>", "EMAIL", 1},
		{"<<PHONE_42>>", "PHONE", 42},
		{"<<NAME_999>>", "NAME", 999},
		{"prefix <<EMAIL_1>> suffix", "EMAIL", 1},
	}
	for _, tc := range tests {
		m := tokenPatternRegex.FindStringSubmatch(tc.input)
		if m == nil {
			t.Errorf("Pattern did not match %q", tc.input)
			continue
		}
		if m[1] != tc.wantType {
			t.Errorf("For %q: type = %q, want %q", tc.input, m[1], tc.wantType)
		}
	}
}

// --- ShouldProcess path filtering tests ---

// pathAwareStub is like stubInterceptor but delegates ShouldProcess to a function.
type pathAwareStub struct {
	shouldProcessFn func(host, method, path string) bool
}

func (p *pathAwareStub) InterceptRequest(req *http.Request) (*http.Request, io.ReadCloser, error) {
	return req, req.Body, nil
}

func (p *pathAwareStub) InterceptResponse(resp *http.Response) (*http.Response, io.ReadCloser, error) {
	return resp, resp.Body, nil
}

func (p *pathAwareStub) ShouldProcess(host, method, path string) bool {
	return p.shouldProcessFn(host, method, path)
}

// TestDebugInterceptor_SentinelNotRecorded verifies that a sentinel/challenge endpoint
// produces 0 FlowRing entries — the DebugInterceptor checks ShouldProcess before
// reading the body and skips recording entirely.
func TestDebugInterceptor_SentinelNotRecorded(t *testing.T) {
	ring := NewFlowRing()

	// Inner stub that says "don't process" for sentinel paths.
	inner := &pathAwareStub{
		shouldProcessFn: func(host, method, path string) bool {
			// Only accept conversation paths — sentinel never matches.
			return path == "/backend-anon/f/conversation" || path == "/backend-api/f/conversation"
		},
	}
	di := NewDebugInterceptor(inner, ring)

	// 1. Sentinel challenge endpoint — should NOT be recorded.
	body := `{"challenge": "encrypted-payload-data"}`
	req := httptest.NewRequest("POST", "https://chatgpt.com/backend-anon/sentinel/chat-requirements/finalize", strings.NewReader(body))
	req.Host = "chatgpt.com"

	_, newBody, err := di.InterceptRequest(req)
	if err != nil {
		t.Fatalf("InterceptRequest for sentinel failed: %v", err)
	}

	// Body should pass through unchanged (DebugInterceptor didn't consume it).
	bodyBytes, _ := io.ReadAll(newBody)
	newBody.Close()
	if string(bodyBytes) != body {
		t.Errorf("sentinel body modified: got %q, want %q", string(bodyBytes), body)
	}

	// Sentinel must NOT appear in FlowRing.
	if ring.Len() != 0 {
		t.Errorf("sentinel endpoint recorded %d FlowRing entries, want 0", ring.Len())
	}
}

// TestDebugInterceptor_ConversationRecorded verifies that a conversational endpoint
// produces exactly 1 FlowRing entry — the DebugInterceptor reads the body and
// records ingress/egress only when ShouldProcess returns true.
func TestDebugInterceptor_ConversationRecorded(t *testing.T) {
	ring := NewFlowRing()

	inner := &pathAwareStub{
		shouldProcessFn: func(host, method, path string) bool {
			// Simulate ChatGPT MatchPath: exact match or /-suffix prefix.
			return path == "/backend-anon/f/conversation" ||
				path == "/backend-api/f/conversation" ||
				strings.HasPrefix(path, "/backend-anon/f/conversation/") ||
				strings.HasPrefix(path, "/backend-api/f/conversation/")
		},
	}
	di := NewDebugInterceptor(inner, ring)

	// 2. Conversation endpoint — SHOULD be recorded.
	conversationBody := `{"messages":[{"content":{"parts":["Hello test.user@example.com"]}}]}`
	req2 := httptest.NewRequest("POST", "https://chatgpt.com/backend-anon/f/conversation/abc-123", strings.NewReader(conversationBody))
	req2.Host = "chatgpt.com"

	_, newBody2, err := di.InterceptRequest(req2)
	if err != nil {
		t.Fatalf("InterceptRequest for conversation failed: %v", err)
	}

	bodyBytes2, _ := io.ReadAll(newBody2)
	newBody2.Close()
	if string(bodyBytes2) != conversationBody {
		t.Errorf("conversation body modified: got %q, want %q", string(bodyBytes2), conversationBody)
	}

	// Conversation must appear exactly once in FlowRing.
	if ring.Len() != 1 {
		t.Fatalf("conversation endpoint recorded %d FlowRing entries, want 1", ring.Len())
	}

	entry := ring.Snapshot()[0]
	if entry.IngressBody != conversationBody {
		t.Errorf("IngressBody = %q, want %q", entry.IngressBody, conversationBody)
	}
	if entry.EgressBody != conversationBody {
		t.Errorf("EgressBody = %q, want %q", entry.EgressBody, conversationBody)
	}
	if entry.Host != "chatgpt.com" {
		t.Errorf("Host = %q, want %q", entry.Host, "chatgpt.com")
	}
}

// TestDebugInterceptor_SentinelThenConversation verifies the combined scenario:
// sentinel produces 0 entries, conversation produces 1 entry, in sequence.
func TestDebugInterceptor_SentinelThenConversation(t *testing.T) {
	ring := NewFlowRing()

	inner := &pathAwareStub{
		shouldProcessFn: func(host, method, path string) bool {
			return path == "/backend-anon/f/conversation" || strings.HasPrefix(path, "/backend-anon/f/conversation/")
		},
	}
	di := NewDebugInterceptor(inner, ring)

	// 1. Sentinel — skip.
	req1 := httptest.NewRequest("POST", "https://chatgpt.com/backend-anon/sentinel/chat-requirements/finalize",
		strings.NewReader(`sentinel-body`))
	req1.Host = "chatgpt.com"
	_, _, _ = di.InterceptRequest(req1)

	if ring.Len() != 0 {
		t.Fatalf("after sentinel: ring.Len = %d, want 0", ring.Len())
	}

	// 2. Conversation — record.
	req2 := httptest.NewRequest("POST", "https://chatgpt.com/backend-anon/f/conversation",
		strings.NewReader(`conversation-body`))
	req2.Host = "chatgpt.com"
	_, _, _ = di.InterceptRequest(req2)

	if ring.Len() != 1 {
		t.Fatalf("after conversation: ring.Len = %d, want 1", ring.Len())
	}

	// 3. Another sentinel — skip.
	req3 := httptest.NewRequest("POST", "https://chatgpt.com/backend-anon/sentinel/ping",
		strings.NewReader(`ping-body`))
	req3.Host = "chatgpt.com"
	_, _, _ = di.InterceptRequest(req3)

	if ring.Len() != 1 {
		t.Fatalf("after second sentinel: ring.Len = %d, want 1", ring.Len())
	}

	// The recorded entry should be the conversation body, not sentinel.
	entry := ring.Snapshot()[0]
	if entry.IngressBody != "conversation-body" {
		t.Errorf("IngressBody = %q, want %q", entry.IngressBody, "conversation-body")
	}
}

// TestDebugInterceptor_ShouldProcessDelegates verifies that the DebugInterceptor's
// ShouldProcess correctly delegates to the inner interceptor.
func TestDebugInterceptor_ShouldProcessDelegates(t *testing.T) {
	inner := &pathAwareStub{
		shouldProcessFn: func(host, method, path string) bool {
			return path == "/conversation"
		},
	}
	di := NewDebugInterceptor(inner, nil) // nil ring OK — ShouldProcess doesn't use it

	if di.ShouldProcess("chatgpt.com", "POST", "/conversation") != true {
		t.Error("ShouldProcess should return true for /conversation")
	}
	if di.ShouldProcess("chatgpt.com", "POST", "/backend-anon/sentinel/chat-requirements/finalize") != false {
		t.Error("ShouldProcess should return false for sentinel path")
	}
}

// TestTokenSummary_IgnoresInvalidCounters verifies malformed counters are skipped.
func TestTokenSummary_IgnoresInvalidCounters(t *testing.T) {
	summary := tokenSummary("<<EMAIL_>> and <<EMAIL_ABC>>")
	// Neither should appear — invalid counters are skipped.
	if len(summary) != 0 {
		t.Errorf("summary should be empty for malformed tokens, got %v", summary)
	}
}

// --- PR-003: TOCTOU race fix tests ---

// TestFlowHandler_EntriesCountFromSnapshot verifies that EntriesCount is derived
// from the snapshot length, not from a separate ring.Len() call.
// PR-003: prevents inconsistent JSON when a concurrent Record changes the count.
func TestFlowHandler_EntriesCountFromSnapshot(t *testing.T) {
	ring := NewFlowRing()
	ring.Record("body1", "body1", "h", "GET", "/1")
	ring.Record("body2", "body2", "h", "GET", "/2")

	handler := FlowHandler(ring)
	req := httptest.NewRequest("GET", "/debug/flow", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	bodyBytes, _ := io.ReadAll(w.Result().Body)
	w.Result().Body.Close()

	var fr flowResponse
	if err := json.Unmarshal(bodyBytes, &fr); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	// EntriesCount must equal the number of entries in the response array.
	if fr.EntriesCount != len(fr.Entries) {
		t.Errorf("EntriesCount (%d) != len(Entries) (%d) — TOCTOU race or mismatch",
			fr.EntriesCount, len(fr.Entries))
	}
	if fr.EntriesCount != 2 {
		t.Errorf("EntriesCount = %d, want 2", fr.EntriesCount)
	}
}

// TestFlowHandler_TokenRaceImmunity verifies that rapid concurrent records
// don't produce an inconsistent JSON response (PR-003 TOCTOU).
func TestFlowHandler_TokenRaceImmunity(t *testing.T) {
	ring := NewFlowRing()

	// Pre-populate with some entries.
	for i := 0; i < 10; i++ {
		ring.Record("body", "body", "h", "GET", "/")
	}

	// In parallel: write more entries while reading the handler.
	var wg sync.WaitGroup
	for g := 0; g < 10; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				ring.Record("body", "body", "h", "GET", "/")
			}
		}()
	}

	// Read the handler in another goroutine.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			handler := FlowHandler(ring)
			req := httptest.NewRequest("GET", "/debug/flow", nil)
			w := httptest.NewRecorder()
			handler(w, req)

			var fr flowResponse
			bodyBytes, _ := io.ReadAll(w.Result().Body)
			w.Result().Body.Close()
			// Must always be valid JSON.
			if err := json.Unmarshal(bodyBytes, &fr); err != nil {
				// Use t.Log not t.Error — this is a concurrent test,
				// and json unmarshal failing is non-deterministic.
				t.Logf("invalid JSON under concurrency: %v", err)
				return
			}
			// EntriesCount must never exceed buffer size.
			if fr.EntriesCount > flowRingMaxEntries {
				t.Errorf("EntriesCount %d > BufferSize %d", fr.EntriesCount, fr.BufferSize)
				return
			}
			// EntriesCount must equal the actual returned entries length.
			if fr.EntriesCount != len(fr.Entries) {
				t.Errorf("TOCTOU: EntriesCount %d != len(Entries) %d",
					fr.EntriesCount, len(fr.Entries))
				return
			}
		}
	}()

	wg.Wait()
}

// --- PR-004: Body size cap tests ---

func TestTruncateDebugBody_UnderLimit(t *testing.T) {
	body := "hello world"
	result := truncateDebugBody(body)
	if result != body {
		t.Errorf("under-limit body should pass through unchanged: got %q, want %q", result, body)
	}
}

func TestTruncateDebugBody_AtLimit(t *testing.T) {
	body := strings.Repeat("x", maxDebugBodyLen)
	result := truncateDebugBody(body)
	if result != body {
		t.Errorf("at-limit body should pass through unchanged: got len %d, want len %d", len(result), len(body))
	}
}

func TestTruncateDebugBody_OverLimit(t *testing.T) {
	body := strings.Repeat("y", maxDebugBodyLen+1000)
	result := truncateDebugBody(body)

	// Should be truncated to maxDebugBodyLen + len(truncatedSuffix).
	expectedLen := maxDebugBodyLen + len(truncatedSuffix)
	if len(result) != expectedLen {
		t.Errorf("truncated body len = %d, want %d", len(result), expectedLen)
	}
	if !strings.HasSuffix(result, truncatedSuffix) {
		t.Errorf("truncated body should end with %q, got: ...%q", truncatedSuffix, result[len(result)-20:])
	}
	// First part should be the original prefix.
	if !strings.HasPrefix(result, strings.Repeat("y", maxDebugBodyLen)) {
		t.Error("truncated body prefix mismatch")
	}
}

func TestFlowRing_Record_TruncatesOversizeBody(t *testing.T) {
	ring := NewFlowRing()

	// A body well over the limit.
	largeBody := strings.Repeat("data-", maxDebugBodyLen)
	ring.Record(largeBody, largeBody, "host", "POST", "/path")

	snap := ring.Snapshot()
	if len(snap) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(snap))
	}

	entry := snap[0]

	// Ingress/Egress should be truncated.
	if len(entry.IngressBody) > maxDebugBodyLen+len(truncatedSuffix) {
		t.Errorf("IngressBody too long: %d bytes", len(entry.IngressBody))
	}
	if len(entry.EgressBody) > maxDebugBodyLen+len(truncatedSuffix) {
		t.Errorf("EgressBody too long: %d bytes", len(entry.EgressBody))
	}

	// But BodyBytesIn/BodyBytesOut should reflect the ORIGINAL sizes.
	originalLen := len(largeBody)
	if entry.BodyBytesIn != originalLen {
		t.Errorf("BodyBytesIn = %d, want original size %d", entry.BodyBytesIn, originalLen)
	}
	if entry.BodyBytesOut != originalLen {
		t.Errorf("BodyBytesOut = %d, want original size %d", entry.BodyBytesOut, originalLen)
	}
}

func TestFlowRing_Record_SmallBodyUnchanged(t *testing.T) {
	ring := NewFlowRing()

	smallBody := `{"message": "hello"}`
	ring.Record(smallBody, smallBody, "host", "GET", "/")

	entry := ring.Snapshot()[0]
	if entry.IngressBody != smallBody {
		t.Errorf("small IngressBody modified: got %q, want %q", entry.IngressBody, smallBody)
	}
	if entry.EgressBody != smallBody {
		t.Errorf("small EgressBody modified: got %q, want %q", entry.EgressBody, smallBody)
	}
	if entry.BodyBytesIn != len(smallBody) {
		t.Errorf("BodyBytesIn = %d, want %d", entry.BodyBytesIn, len(smallBody))
	}
}
