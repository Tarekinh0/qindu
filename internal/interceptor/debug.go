package interceptor

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"sync"
	"time"
)

// flowRingMaxEntries is the maximum number of entries in the flow ring buffer.
const flowRingMaxEntries = 50

// maxDebugBodyLen is the maximum number of bytes stored per body (ingress and egress)
// in a FlowEntry. Bodies exceeding this limit are truncated with a "[truncated]" suffix.
// Caps memory usage at ~6.4 MB for a full ring buffer (50 entries × 2 bodies × 64KB).
// PR-004: prevents a single large request from consuming disproportionate memory.
const maxDebugBodyLen = 64 * 1024

// tokenPatternRegex matches <<TYPE_N>> token patterns for entity summary extraction.
// Captures TYPE (e.g., "EMAIL") and N (the counter).
var tokenPatternRegex = regexp.MustCompile(`<<([A-Z][A-Z_]*[A-Z])_(\d+)>>`)

// FlowEntry represents a single ingress/egress body pair in the flow inspector.
type FlowEntry struct {
	ID            int            `json:"id"`
	Timestamp     string         `json:"timestamp"`
	Host          string         `json:"host"`
	Method        string         `json:"method"`
	Path          string         `json:"path"`
	IngressBody   string         `json:"ingress_body"`
	EgressBody    string         `json:"egress_body"`
	EntitySummary map[string]int `json:"entity_summary"`
	BodyBytesIn   int            `json:"body_bytes_in"`
	BodyBytesOut  int            `json:"body_bytes_out"`
}

// FlowRing is a thread-safe ring buffer of FlowEntry values.
// It stores up to flowRingMaxEntries entries in FIFO order.
// When the buffer is full, the oldest entry is evicted.
//
// DD-2: Uses sync.Mutex (not RWMutex) because the handler reads and the
// interceptor writes with low contention.
// DD-3: Stores PII in clear text in memory — gated behind debug.flow_inspector
// (default false), localhost-only, no disk persistence.
type FlowRing struct {
	mu      sync.Mutex
	entries []FlowEntry
	nextID  int
}

// NewFlowRing creates a new empty FlowRing.
func NewFlowRing() *FlowRing {
	return &FlowRing{
		entries: make([]FlowEntry, 0, flowRingMaxEntries),
		nextID:  1,
	}
}

// Record adds a new ingress/egress pair to the ring buffer.
// If the buffer is full, the oldest entry is evicted (FIFO).
// Each body is capped at maxDebugBodyLen bytes to bound memory usage (PR-004).
// BodyBytesIn/BodyBytesOut capture the original (pre-truncation) sizes so the
// operator can see the true byte count even when the body is truncated.
// The entity summary is derived from token patterns in the egress body
// — this means it only contains type counts, never PII values.
func (fr *FlowRing) Record(ingressBody, egressBody string, host, method, path string) {
	fr.mu.Lock()
	defer fr.mu.Unlock()

	// Capture original sizes before truncation (PR-004).
	origBytesIn := len(ingressBody)
	origBytesOut := len(egressBody)

	// PR-004: cap per-entry body size to prevent memory blowout from large requests.
	ingressBody = truncateDebugBody(ingressBody)
	egressBody = truncateDebugBody(egressBody)

	entry := FlowEntry{
		ID:            fr.nextID,
		Timestamp:     time.Now().UTC().Format(time.RFC3339),
		Host:          host,
		Method:        method,
		Path:          path,
		IngressBody:   ingressBody,
		EgressBody:    egressBody,
		EntitySummary: tokenSummary(egressBody),
		BodyBytesIn:   origBytesIn,
		BodyBytesOut:  origBytesOut,
	}
	fr.nextID++

	if len(fr.entries) >= flowRingMaxEntries {
		// Evict oldest: shift left by one.
		copy(fr.entries, fr.entries[1:])
		fr.entries[len(fr.entries)-1] = entry
	} else {
		fr.entries = append(fr.entries, entry)
	}
}

// Snapshot returns a copy of the current entries in insertion order (oldest first).
// Returns nil if the ring buffer is empty.
func (fr *FlowRing) Snapshot() []FlowEntry {
	fr.mu.Lock()
	defer fr.mu.Unlock()

	if len(fr.entries) == 0 {
		return nil
	}

	result := make([]FlowEntry, len(fr.entries))
	copy(result, fr.entries)
	return result
}

// Len returns the current number of entries in the ring buffer.
func (fr *FlowRing) Len() int {
	fr.mu.Lock()
	defer fr.mu.Unlock()
	return len(fr.entries)
}

// Cap returns the maximum capacity of the ring buffer.
func (fr *FlowRing) Cap() int {
	return flowRingMaxEntries
}

// flowResponse is the JSON structure returned by the /debug/flow endpoint.
type flowResponse struct {
	Entries      []FlowEntry `json:"entries"`
	BufferSize   int         `json:"buffer_size"`
	EntriesCount int         `json:"entries_count"`
}

// FlowHandler returns an HTTP handler that serves the flow inspector JSON.
// The handler is intended to be mounted behind a localhost-only check at
// the proxy level (see handleHTTP in proxy.go).
//
// Response: 200 OK with JSON body containing the ring buffer snapshot.
// The handler always returns a valid JSON response even if the buffer is empty,
// ensuring the endpoint contract is stable.
func FlowHandler(ring *FlowRing) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")

		entries := ring.Snapshot()
		if entries == nil {
			entries = []FlowEntry{}
		}

		// PR-003: EntriesCount derived from snapshot length, not ring.Len(),
		// to prevent TOCTOU race where Len() captures a different count
		// than the slices returned by Snapshot().
		resp := flowResponse{
			Entries:      entries,
			BufferSize:   ring.Cap(),
			EntriesCount: len(entries),
		}

		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			// Can't write error header after body started; log but don't panic.
			// This is extremely rare — only happens on connection drops.
			_ = err
		}
	}
}

// truncatedSuffix is appended when a debug body exceeds maxDebugBodyLen.
const truncatedSuffix = "...[truncated]"

// truncateDebugBody caps a body string at maxDebugBodyLen bytes.
// Bodies within the limit are returned unchanged. Oversized bodies are truncated
// with the truncatedSuffix appended. BodyBytesIn/BodyBytesOut reflect the original
// (pre-truncation) size so the operator can see the full byte count.
// PR-004: bounds per-entry memory usage in the FlowRing.
func truncateDebugBody(s string) string {
	if len(s) <= maxDebugBodyLen {
		return s
	}
	return s[:maxDebugBodyLen] + truncatedSuffix
}

// tokenSummary extracts entity type counts from token patterns in the given text.
// For example, "Hello <<EMAIL_1>> and <<PHONE_2>>" returns {"EMAIL": 1, "PHONE": 1}.
// Only known entity types (EMAIL, PHONE, IBAN, etc.) are counted.
// Never returns PII values — only entity types and counts.
// Returns nil if no tokens are found.
func tokenSummary(text string) map[string]int {
	matches := tokenPatternRegex.FindAllStringSubmatch(text, -1)
	if len(matches) == 0 {
		return nil
	}

	summary := make(map[string]int)
	for _, m := range matches {
		entityType := m[1]
		// Filter: only count known entity types from the pii package.
		if !isKnownDebugEntityType(entityType) {
			continue
		}
		count, err := strconv.Atoi(m[2])
		if err != nil {
			continue // malformed counter — skip
		}
		// Track the maximum counter seen for each type.
		if existing, ok := summary[entityType]; !ok || count > existing {
			summary[entityType] = count
		}
	}
	if len(summary) == 0 {
		return nil
	}
	return summary
}

// knownDebugEntityTypes is a set of recognized PII entity types for filtering
// token pattern matches. Only tokens of these types are counted in entity summaries.
var knownDebugEntityTypes = map[string]bool{
	"EMAIL":       true,
	"PHONE":       true,
	"IBAN":        true,
	"CREDIT_CARD": true,
	"JWT":         true,
	"NAME":        true,
	"SECRET":      true,
	"PRIVATE_KEY": true,
}

// isKnownDebugEntityType returns true if the entity type string corresponds
// to a known PII entity type.
func isKnownDebugEntityType(entityType string) bool {
	return knownDebugEntityTypes[entityType]
}

// innerInterceptor is a locally-defined interface matching proxy.Interceptor.
// Defining it here avoids a circular import between the interceptor and proxy packages.
type innerInterceptor interface {
	InterceptRequest(req *http.Request) (*http.Request, io.ReadCloser, error)
	InterceptResponse(resp *http.Response) (*http.Response, io.ReadCloser, error)
	ShouldProcess(host, method, path string) bool
}

// DebugInterceptor wraps an inner Interceptor and records ingress/egress body
// pairs into a FlowRing.
//
// Design Decisions:
//   - DD-1: Wraps the real interceptor, zero impact on handleMITM or forwardHTTPRoundTrip.
//   - Implements the Interceptor interface for transparent drop-in.
//   - InterceptRequest captures the original body (ingress) and the transformed
//     body (egress), recording both in the FlowRing before returning the egress
//     body to the caller.
//   - InterceptResponse delegates directly to the inner interceptor without
//     recording (the flow inspector focuses on request transformation).
type DebugInterceptor struct {
	inner innerInterceptor
	ring  *FlowRing
}

// NewDebugInterceptor creates a DebugInterceptor wrapping the given inner interceptor.
func NewDebugInterceptor(inner innerInterceptor, ring *FlowRing) *DebugInterceptor {
	return &DebugInterceptor{
		inner: inner,
		ring:  ring,
	}
}

// ShouldProcess delegates to the inner interceptor's ShouldProcess.
// This is used by InterceptRequest to avoid buffering bodies for endpoints
// that will be passed through unmodified (sentinel/challenge, telemetry, static assets).
func (d *DebugInterceptor) ShouldProcess(host, method, path string) bool {
	return d.inner.ShouldProcess(host, method, path)
}

// InterceptRequest captures ingress/egress body pairs and records them in the FlowRing.
//
// Flow:
//  0. Check ShouldProcess — if the inner interceptor would skip this path,
//     pass through without reading the body or recording in the FlowRing.
//  1. Read the original request body fully → ingressBytes.
//  2. Replace req.Body with a reader over ingressBytes.
//  3. Call inner.InterceptRequest(req) → (newReq, egressBody, err).
//  4. Read egressBody fully → egressBytes.
//  5. Record ingressBytes + egressBytes + metadata in FlowRing.
//  6. Return newReq and a fresh reader over egressBytes.
//
// Errors from the inner interceptor are propagated. On error, the flow entry
// is recorded with an empty egress body so the operator can see what was
// attempted.
//
// Requests with no body (nil or http.NoBody) are passed through without
// recording — there is nothing to inspect.
func (d *DebugInterceptor) InterceptRequest(req *http.Request) (*http.Request, io.ReadCloser, error) {
	if req.Body == nil || req.Body == http.NoBody {
		return d.inner.InterceptRequest(req)
	}

	// 0. Path filter: skip bodies for endpoints the inner interceptor won't process.
	// This prevents sentinel/challenge payloads, telemetry, and static assets from
	// being buffered in memory and recorded in the FlowRing.
	host := req.Host
	reqPath := ""
	if req.URL != nil {
		reqPath = req.URL.Path
	}
	if !d.inner.ShouldProcess(host, req.Method, reqPath) {
		return d.inner.InterceptRequest(req)
	}

	// 1. Read original body.
	ingressBytes, err := io.ReadAll(req.Body)
	if closeErr := req.Body.Close(); closeErr != nil {
		_ = closeErr
	}
	if err != nil {
		return nil, nil, fmt.Errorf("debug: reading ingress body: %w", err)
	}

	// If body is empty (0 bytes), pass through without recording.
	if len(ingressBytes) == 0 {
		req.Body = io.NopCloser(bytes.NewReader(ingressBytes))
		return d.inner.InterceptRequest(req)
	}

	// 2. Replace body for inner interceptor.
	req.Body = io.NopCloser(bytes.NewReader(ingressBytes))

	// 3. Call inner interceptor.
	newReq, egressBody, interceptorErr := d.inner.InterceptRequest(req)
	if interceptorErr != nil {
		// Record with empty egress — operator sees what was attempted.
		d.ring.Record(
			string(ingressBytes),
			"",
			host,
			req.Method,
			reqPath,
		)
		return nil, nil, interceptorErr
	}

	// 4. Read egress body.
	egressBytes, readErr := io.ReadAll(egressBody)
	if closeErr := egressBody.Close(); closeErr != nil {
		_ = closeErr
	}
	if readErr != nil {
		d.ring.Record(
			string(ingressBytes),
			"",
			host,
			req.Method,
			reqPath,
		)
		return nil, nil, fmt.Errorf("debug: reading egress body: %w", readErr)
	}

	// 5. Record in FlowRing.
	d.ring.Record(
		string(ingressBytes),
		string(egressBytes),
		host,
		req.Method,
		reqPath,
	)

	// 6. Return fresh reader over egress bytes.
	return newReq, io.NopCloser(bytes.NewReader(egressBytes)), nil
}

// InterceptResponse delegates to the inner interceptor without recording.
// The flow inspector focuses on request transformation (ingress → egress).
func (d *DebugInterceptor) InterceptResponse(resp *http.Response) (*http.Response, io.ReadCloser, error) {
	return d.inner.InterceptResponse(resp)
}

// Compile-time interface check: DebugInterceptor satisfies innerInterceptor.
var _ innerInterceptor = (*DebugInterceptor)(nil)
