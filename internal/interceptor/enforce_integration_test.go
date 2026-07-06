package interceptor

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Tarekinh0/qindu/internal/tokenize"
)

// TestEnforceInterceptor_Integration_RoundTrip verifies the full enforce pipeline
// with a mock AI upstream server:
//  1. Tokenize PII in request body
//  2. Forward to mock AI server (which receives tokenized text only)
//  3. Mock AI server echoes back the tokenized text in its response
//  4. Rehydrate tokens back to original PII in the response
//  5. Verify final response body contains original PII, not tokens
func TestEnforceInterceptor_Integration_RoundTrip(t *testing.T) {
	logger, logBuf := testLoggerCapture()
	engine := newTestEngine()

	// Create EnforceInterceptor with nil plugin (full-body scanning fallback).
	ei, err := NewEnforceInterceptor(engine, nil, false, logger)
	if err != nil {
		t.Fatalf("NewEnforceInterceptor: %v", err)
	}

	// Build a mock AI server that:
	// - Records the request body it receives
	// - Returns a response that echoes back tokens from the request
	var upstreamReceivedBody string
	mockAI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, readErr := io.ReadAll(r.Body)
		if readErr != nil {
			t.Errorf("mock server read error: %v", readErr)
		}
		upstreamReceivedBody = string(bodyBytes)

		// Echo the received body back — this simulates an AI response
		// where the model "quotes" information containing tokens.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"model": "gpt-mock", "response": "I received: ` + upstreamReceivedBody + `"}`))
	}))
	defer mockAI.Close()

	// Create a fresh tokenizer (no pre-population — tokenization happens in the interceptor via the engine).
	tokenizer := tokenize.New(engine, tokenize.WithLogger(logger))

	originalPII := "test.user@example.com"
	requestBodyContent := `My email is ` + originalPII + ` and I need help`

	// ----- Request Phase -----
	// Use httptest.NewRequest for the interceptor request (it sets up request properly).
	req := httptest.NewRequest("POST", "https://api.example.com/v1/chat", strings.NewReader(requestBodyContent))
	req.Host = "api.example.com"
	ctx := tokenize.ContextWithTokenizer(req.Context(), tokenizer)
	req = req.WithContext(ctx)

	newReq, tokenizedBodyReader, err := ei.InterceptRequest(req)
	if err != nil {
		t.Fatalf("InterceptRequest: %v", err)
	}
	if newReq == nil {
		t.Fatal("InterceptRequest returned nil request")
	}

	// Read the tokenized body that would be sent upstream.
	tokenizedBytes, err := io.ReadAll(tokenizedBodyReader)
	if err != nil {
		t.Fatalf("reading tokenized body: %v", err)
	}
	tokenizedBodyReader.Close()

	tokenizedBody := string(tokenizedBytes)
	t.Logf("tokenized body: %s", tokenizedBody)

	// Verify PII is NOT in the tokenized body.
	if strings.Contains(tokenizedBody, originalPII) {
		t.Errorf("PII %q must NOT appear in tokenized request body: %s", originalPII, tokenizedBody)
	}
	// Verify a token IS present.
	if !strings.Contains(tokenizedBody, "<<EMAIL_") {
		t.Errorf("tokenized body must contain at least one <<EMAIL_N>> token: %s", tokenizedBody)
	}

	// ----- Forward Phase -----
	// Simulate the proxy forwarding the tokenized body to the upstream.
	// Use http.NewRequest (not httptest.NewRequest) for client requests.
	mockReq, err := http.NewRequest("POST", mockAI.URL+"/v1/chat", strings.NewReader(tokenizedBody))
	if err != nil {
		t.Fatalf("creating upstream request: %v", err)
	}
	mockReq.Host = "api.example.com"
	mockClient := &http.Client{}
	mockResp, err := mockClient.Do(mockReq)
	if err != nil {
		t.Fatalf("mock upstream request: %v", err)
	}
	defer mockResp.Body.Close()

	// Verify the upstream server received the tokenized body (no PII).
	if strings.Contains(upstreamReceivedBody, originalPII) {
		t.Errorf("upstream server received raw PII: %s", upstreamReceivedBody)
	}
	if !strings.Contains(upstreamReceivedBody, "<<EMAIL_") {
		t.Errorf("upstream server did not receive token: %s", upstreamReceivedBody)
	}

	// ----- Response Phase -----
	// Build a response that the interceptor will rehydrate.
	resp := &http.Response{
		StatusCode: mockResp.StatusCode,
		Header:     mockResp.Header,
		Body:       mockResp.Body,
		Request:    req, // original request with tokenizer context
	}

	newResp, rehydratedBodyReader, err := ei.InterceptResponse(resp)
	if err != nil {
		t.Fatalf("InterceptResponse: %v", err)
	}
	if newResp == nil {
		t.Fatal("InterceptResponse returned nil response")
	}

	rehydratedBytes, err := io.ReadAll(rehydratedBodyReader)
	if err != nil {
		t.Fatalf("reading rehydrated body: %v", err)
	}
	rehydratedBodyReader.Close()
	rehydratedBody := string(rehydratedBytes)

	// Verify the original PII is restored in the final response.
	if !strings.Contains(rehydratedBody, originalPII) {
		t.Errorf("rehydrated response must contain original PII %q: %s", originalPII, rehydratedBody)
	}
	// Verify raw tokens are NOT present (they should be rehydrated).
	if strings.Contains(rehydratedBody, "<<EMAIL_") {
		t.Errorf("rehydrated response must NOT contain raw tokens: %s", rehydratedBody)
	}

	// Verify the log output is present but contains no PII.
	logOutput := logBuf.String()
	if strings.Contains(logOutput, originalPII) {
		t.Error("log output must not contain raw PII")
	}
}

// TestEnforceInterceptor_Integration_MultiplePII verifies the pipeline
// handles multiple PII entities (email + phone) in a single request/response round-trip.
func TestEnforceInterceptor_Integration_MultiplePII(t *testing.T) {
	logger, logBuf := testLoggerCapture()
	engine := newTestEngine()

	ei, err := NewEnforceInterceptor(engine, nil, false, logger)
	if err != nil {
		t.Fatalf("NewEnforceInterceptor: %v", err)
	}

	var upstreamReceivedBody string
	mockAI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, _ := io.ReadAll(r.Body)
		upstreamReceivedBody = string(bodyBytes)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// Echo the received tokens back as part of the response.
		_, _ = w.Write([]byte(`{"reply": "Here is your info: ` + upstreamReceivedBody + `"}`))
	}))
	defer mockAI.Close()

	tokenizer := tokenize.New(engine, tokenize.WithLogger(logger))

	pii1 := "bob@example.com"
	pii2 := "+33612345678"

	// Request with multiple PII.
	requestBodyContent := `Contact: ` + pii1 + ` or ` + pii2
	req := httptest.NewRequest("POST", "https://api.example.com/v1/chat", strings.NewReader(requestBodyContent))
	req.Host = "api.example.com"
	ctx := tokenize.ContextWithTokenizer(req.Context(), tokenizer)
	req = req.WithContext(ctx)

	_, tokenizedBodyReader, err := ei.InterceptRequest(req)
	if err != nil {
		t.Fatalf("InterceptRequest: %v", err)
	}
	tokenizedBytes, _ := io.ReadAll(tokenizedBodyReader)
	tokenizedBodyReader.Close()
	tokenizedBody := string(tokenizedBytes)

	// Neither PII should be in the tokenized body.
	if strings.Contains(tokenizedBody, pii1) {
		t.Errorf("PII %q must not be in tokenized body", pii1)
	}
	if strings.Contains(tokenizedBody, pii2) {
		t.Errorf("PII %q must not be in tokenized body", pii2)
	}

	// Forward to mock AI.
	mockReq, err := http.NewRequest("POST", mockAI.URL+"/v1/chat", strings.NewReader(tokenizedBody))
	if err != nil {
		t.Fatalf("creating upstream request: %v", err)
	}
	mockReq.Host = "api.example.com"
	mockClient := &http.Client{}
	mockResp, err := mockClient.Do(mockReq)
	if err != nil {
		t.Fatalf("mock upstream: %v", err)
	}
	defer mockResp.Body.Close()

	// Neither PII should reach upstream.
	if strings.Contains(upstreamReceivedBody, pii1) {
		t.Errorf("upstream received PII %q", pii1)
	}
	if strings.Contains(upstreamReceivedBody, pii2) {
		t.Errorf("upstream received PII %q", pii2)
	}

	// Rehydrate.
	resp := &http.Response{
		StatusCode: mockResp.StatusCode,
		Header:     mockResp.Header,
		Body:       mockResp.Body,
		Request:    req,
	}
	_, rehydratedReader, err := ei.InterceptResponse(resp)
	if err != nil {
		t.Fatalf("InterceptResponse: %v", err)
	}
	rehydratedBytes, _ := io.ReadAll(rehydratedReader)
	rehydratedReader.Close()
	rehydratedBody := string(rehydratedBytes)

	// Both PII values must be restored.
	if !strings.Contains(rehydratedBody, pii1) {
		t.Errorf("rehydrated response missing PII %q: %s", pii1, rehydratedBody)
	}
	if !strings.Contains(rehydratedBody, pii2) {
		t.Errorf("rehydrated response missing PII %q: %s", pii2, rehydratedBody)
	}

	// Verify no PII in logs.
	logOutput := logBuf.String()
	if strings.Contains(logOutput, pii1) {
		t.Error("log output must not contain raw PII")
	}
	if strings.Contains(logOutput, pii2) {
		t.Error("log output must not contain raw PII")
	}
}

// TestEnforceInterceptor_Integration_NoPIIPassthrough verifies that when
// no PII is present, the body passes through unmodified.
func TestEnforceInterceptor_Integration_NoPIIPassthrough(t *testing.T) {
	logger, _ := testLoggerCapture()
	engine := newTestEngine()

	ei, err := NewEnforceInterceptor(engine, nil, false, logger)
	if err != nil {
		t.Fatalf("NewEnforceInterceptor: %v", err)
	}

	mockAI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"reply": "` + string(bodyBytes) + `"}`))
	}))
	defer mockAI.Close()

	tokenizer := tokenize.New(engine, tokenize.WithLogger(logger))

	// Request without PII.
	original := "Hello, how are you today?"
	req := httptest.NewRequest("POST", "https://api.example.com/v1/chat", strings.NewReader(original))
	req.Host = "api.example.com"
	ctx := tokenize.ContextWithTokenizer(req.Context(), tokenizer)
	req = req.WithContext(ctx)

	_, tokenizedReader, err := ei.InterceptRequest(req)
	if err != nil {
		t.Fatalf("InterceptRequest: %v", err)
	}
	tokenizedBytes, _ := io.ReadAll(tokenizedReader)
	tokenizedReader.Close()

	// Body without PII should be unchanged.
	if string(tokenizedBytes) != original {
		t.Errorf("body without PII should be unchanged: got %q, want %q", string(tokenizedBytes), original)
	}
}

// TestEnforceInterceptor_Integration_MissingTokenizerRejected verifies
// that the enforce interceptor rejects requests when the tokenizer is
// missing from context (fail-closed).
func TestEnforceInterceptor_Integration_MissingTokenizerRejected(t *testing.T) {
	logger, _ := testLoggerCapture()
	engine := newTestEngine()

	ei, err := NewEnforceInterceptor(engine, nil, false, logger)
	if err != nil {
		t.Fatalf("NewEnforceInterceptor: %v", err)
	}

	req := httptest.NewRequest("POST", "https://chatgpt.com/conversation/123", strings.NewReader("PII here"))
	// Deliberately NOT injecting tokenizer into context.

	_, _, err = ei.InterceptRequest(req)
	if err == nil {
		t.Fatal("expected error when tokenizer is missing from context")
	}
	if !strings.Contains(err.Error(), "tokenizer") {
		t.Errorf("error should mention tokenizer: %v", err)
	}
}
