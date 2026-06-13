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
