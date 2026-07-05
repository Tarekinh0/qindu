// Package testutils provides shared test helpers used across Qindu test suites.
// This is a regular (non-_test) package so helpers can be imported by any
// test package without polluting production code.
//
// IMPORTANT: DO NOT import from production code. This package is for testing only.
package testutils

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"testing"
)

// ParseLogEntries extracts all JSON log entries from a bytes.Buffer.
// Used by interceptor and provider plugin tests to assert on structured log output.
func ParseLogEntries(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()

	var entries []map[string]any
	decoder := json.NewDecoder(bytes.NewReader(buf.Bytes()))
	for {
		var entry map[string]any
		if err := decoder.Decode(&entry); err != nil {
			if err == io.EOF {
				break
			}
			// Skip partially written lines.
			break
		}
		entries = append(entries, entry)
	}
	return entries
}

// MustParseURL parses a URL from a raw string and panics on error.
// For test setup only — never used in production code.
func MustParseURL(rawURL string) *url.URL {
	u, err := url.Parse(rawURL)
	if err != nil {
		panic(err)
	}
	return u
}

// NewResponseRequest creates a minimal *http.Request for use in http.Response.Request
// during tests. The URL is parsed from path using MustParseURL.
// For test setup only — never used in production code.
func NewResponseRequest(method, host, path string) *http.Request {
	return &http.Request{
		Method: method,
		Host:   host,
		URL:    MustParseURL(path),
	}
}
