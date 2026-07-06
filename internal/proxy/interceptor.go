// Package proxy implements the Qindu HTTP/S proxy with MITM and blind tunnel capabilities.
package proxy

import (
	"io"
	"net/http"
)

// Interceptor defines the pipeline interface for request/response processing.
// Implementations can inspect, modify, or pass through HTTP traffic.
//
// Future implementations (PIIInterceptor) will wrap the body readers for
// PII tokenization and rehydration without buffering complete bodies.
type Interceptor interface {
	// InterceptRequest processes an HTTP request before forwarding to upstream.
	// Returns the (possibly modified) request and a new body reader.
	// The returned io.ReadCloser replaces the request body for forwarding.
	InterceptRequest(req *http.Request) (*http.Request, io.ReadCloser, error)

	// InterceptResponse processes an HTTP response before forwarding to the browser.
	// Returns the (possibly modified) response and a new body reader.
	// The returned io.ReadCloser replaces the response body for forwarding.
	InterceptResponse(resp *http.Response) (*http.Response, io.ReadCloser, error)

	// ShouldProcess returns true if the interceptor intends to process (scan, tokenize,
	// or rehydrate) traffic for the given host, method, and URL path.
	//
	// Callers MUST call ShouldProcess before reading the request body. This allows
	// wrappers (e.g., DebugInterceptor) to avoid buffering bodies for endpoints
	// that will be passed through unmodified (sentinel/challenge, telemetry, static assets).
	//
	// Parameters:
	//   - host: the request Host header value (used by providerDispatcher for routing)
	//   - method: HTTP method (GET, POST, etc.)
	//   - path: URL path (e.g., /backend-anon/f/conversation)
	//
	// Returns false when the body can be safely passed through without inspection.
	// Returns true when the interceptor will scan, tokenize, or rehydrate the body.
	ShouldProcess(host, method, path string) bool
}

// NoOpInterceptor is an Interceptor that passes all traffic through unmodified.
// It is strictly transparent: no buffering, no inspection, no modification.
// Used in QINDU-0001 as a placeholder for future PIIInterceptor.
type NoOpInterceptor struct{}

// InterceptRequest returns the request and body unchanged.
func (n *NoOpInterceptor) InterceptRequest(req *http.Request) (*http.Request, io.ReadCloser, error) {
	return req, req.Body, nil
}

// InterceptResponse returns the response and body unchanged.
func (n *NoOpInterceptor) InterceptResponse(resp *http.Response) (*http.Response, io.ReadCloser, error) {
	return resp, resp.Body, nil
}

// ShouldProcess returns false for all paths — NoOpInterceptor never inspects bodies.
// Callers should not buffer bodies for this interceptor.
func (n *NoOpInterceptor) ShouldProcess(host, method, path string) bool {
	return false
}
