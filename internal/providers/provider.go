// Package providers defines the provider-agnostic plugin interface and shared types
// for AI provider adapters. Each provider (ChatGPT, Claude, Gemini) implements
// ProviderPlugin to isolate provider-specific JSON schema knowledge from the
// agnostic interceptor layer that owns byte I/O, SSE framing, and PII detection.
package providers

// TextSegment identifies a span of text extracted from a request or response body
// that should be scanned for PII. The Start/End fields index into the original
// byte slice. The Text field is a copy (Go string), not a reference to a shared
// buffer (DPO-R4.1).
type TextSegment struct {
	Start int    // Byte offset in original body
	End   int    // Byte offset (exclusive)
	Text  string // Text content (copied, not a buffer reference)
}

// ProviderPlugin defines the contract for a provider-specific adapter.
// It covers path matching, request body text extraction, SSE event handling,
// and request body rewriting. For SSE streaming, NewSession creates a fresh
// per-connection session (CS-11-06).
//
// The agnostic interceptor calls these methods without knowledge of the
// provider's JSON structure. The plugin is the sole source of truth for
// where user/assistant text lives in the provider's protocol.
type ProviderPlugin interface {
	// Name returns the provider identifier string (e.g., "chatgpt").
	// This is a configuration-derived label, never derived from request data (DPO-R3.3).
	Name() string

	// MatchPath returns true if this plugin handles the given HTTP method and URL path.
	// For ChatGPT: matches /backend-anon/f/conversation and /backend-api/f/conversation.
	// Non-conversation endpoints (telemetry, sentinel pings, static assets) return false.
	MatchPath(method, path string) bool

	// ExtractText returns text segments from the raw request or response body.
	// For ChatGPT: locates messages[].content.parts[] in the JSON.
	// The returned segments' Start/End index into the body byte slice.
	// This method is direction-agnostic — it works on both request and response bodies.
	ExtractText(body []byte) []TextSegment

	// RewriteRequestBody returns the rewritten request body.
	// In this sprint (monitor mode only), returns the original body unchanged (DPO-R5.2).
	// The segments parameter contains the text segments extracted by ExtractText,
	// for forward compatibility with enforce mode (QINDU-0009).
	RewriteRequestBody(body []byte, segments []TextSegment) []byte

	// NewSession creates a new per-connection session for processing an SSE response stream.
	// Each SSE stream (HTTP connection) gets its own session, ensuring plugin state
	// isolation across concurrent connections (CS-11-06). The session holds the
	// document tree and other per-stream state.
	NewSession() ProviderPluginSession
}

// ResponseTextExtractor is an optional interface for provider plugins
// that support surgical text extraction from response bodies.
// If a plugin does not implement this, the interceptor falls back to
// extractAllStringValues (conservative but safe).
type ResponseTextExtractor interface {
	// ExtractResponseText returns text segments from a response body.
	// The returned segments identify user-content byte ranges for surgical
	// rehydration — only these ranges are rehydrated, not metadata fields.
	// Returns nil or empty slice for metadata-only responses.
	ExtractResponseText(body []byte) []TextSegment
}

// ProviderPluginSession handles SSE events for a single HTTP response stream.
// The session holds per-stream state (e.g., JSON Patch document tree for ChatGPT)
// and is discarded when the stream ends ([DONE], EOF, or error).
//
// The agnostic SSE helper calls HandleSSEEvent for each complete SSE frame,
// receiving the text to scan. In monitor mode, bytes pass through unmodified.
type ProviderPluginSession interface {
	// HandleSSEEvent processes an SSE event and returns the text that should be
	// scanned for PII. eventType is from the SSE event: line or the JSON type field
	// (if the plugin extracts it). data is the raw data: line content (parsed from SSE
	// frame). The plugin must NOT retain references to data after returning (DPO-R4.2).
	//
	// Returns textToScan: the user/assistant text to scan for PII (empty if none).
	// Bytes pass through unmodified in monitor mode; data rewriting will be added
	// in a future sprint (QINDU-0009 enforce mode).
	HandleSSEEvent(eventType string, data []byte) (textToScan string)

	// StreamEnded signals that the SSE stream has ended (via [DONE] marker, EOF, or error).
	// The session must deterministically clear all mutable state (DPO-R2.2).
	StreamEnded()
}
