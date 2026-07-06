package chatgpt

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"unicode/utf8"

	"github.com/Tarekinh0/qindu/internal/providers"
)

func init() {
	providers.Register("chatgpt", func(logger *slog.Logger) providers.ProviderPlugin {
		return NewChatGPTPlugin(logger)
	})
}

// ChatGPTPlugin implements the ProviderPlugin interface for ChatGPT web.
// It isolates all ChatGPT-specific JSON schema knowledge behind the agnostic
// provider interface.
type ChatGPTPlugin struct {
	name   string
	logger *slog.Logger
}

// NewChatGPTPlugin creates a new ChatGPTPlugin.
// The logger is used for WARN/DEBUG entries about unrecognized event types
// and degraded mode transitions.
func NewChatGPTPlugin(logger *slog.Logger) *ChatGPTPlugin {
	return &ChatGPTPlugin{
		name:   "chatgpt",
		logger: logger,
	}
}

// Name returns the provider identifier.
func (p *ChatGPTPlugin) Name() string {
	return p.name
}

// conversationPaths are the URL paths that identify ChatGPT conversation endpoints.
// These are the only paths where request bodies and SSE responses are scanned for PII.
// The paths must match exactly or with an additional / segment suffix
// (e.g., /backend-anon/f/conversation/abc-123). Superstrings like
// /backend-anon/f/conversationXYZ must NOT match (PR-001, PR-201).
var conversationPaths = []string{
	"/backend-anon/f/conversation",
	"/backend-api/f/conversation",
}

// MatchPath returns true for ChatGPT conversation endpoints.
// Non-conversation paths (telemetry /ces/v1/t, sentinel pings, static assets)
// return false, causing the interceptor to bypass scanning entirely.
// Uses exact path match with trailing-slash extension to avoid false matches:
//   - /backend-anon/f/conversation       → true (exact match)
//   - /backend-anon/f/conversation/abc   → true (path with sub-segment)
//   - /backend-anon/f/conversationXYZ    → false (superstring, different path)
func (p *ChatGPTPlugin) MatchPath(method, path string) bool {
	lower := strings.ToLower(path)
	for _, prefix := range conversationPaths {
		if lower == prefix || strings.HasPrefix(lower, prefix+"/") {
			return true
		}
	}
	return false
}

// ExtractText locates text in messages[].content.parts[] from the
// request or response body JSON. Each string value in the parts arrays is returned as
// a TextSegment with byte offsets into the original body.
// This method is direction-agnostic and works for both requests and responses (PR-102).
//
// Text positions are found by searching the raw body bytes for the extracted strings.
// If a string cannot be reliably located (e.g., unusual JSON escaping), it is skipped
// with a WARN log (PR-103).
func (p *ChatGPTPlugin) ExtractText(body []byte) []providers.TextSegment {
	// Parse the request JSON to find messages[].content.parts[].
	var request struct {
		Messages []struct {
			Content struct {
				Parts []string `json:"parts"`
			} `json:"content"`
		} `json:"messages"`
	}

	if err := json.Unmarshal(body, &request); err != nil {
		// Not valid JSON or wrong format — no text to extract.
		return nil
	}

	var allParts []string
	for _, msg := range request.Messages {
		allParts = append(allParts, msg.Content.Parts...)
	}

	return p.extractParts(body, allParts)
}

// RewriteRequestBody returns the original request body unchanged in this sprint.
// The segments parameter is accepted for forward compatibility with enforce mode.
func (p *ChatGPTPlugin) RewriteRequestBody(body []byte, segments []providers.TextSegment) []byte {
	return body
}

// NewSession creates a new per-connection SSE session with a fresh document tree.
func (p *ChatGPTPlugin) NewSession() providers.ProviderPluginSession {
	return newChatGPTSession(p.logger)
}

// ExtractResponseText implements the optional providers.ResponseTextExtractor interface.
// It parses a response body JSON and extracts text from message.content.parts[].
// Returns nil/empty for metadata-only responses (prepare, sentinel, etc.).
// This enables surgical rehydration — only user-content byte ranges are rehydrated,
// not metadata fields (DPO DR-1).
func (p *ChatGPTPlugin) ExtractResponseText(body []byte) []providers.TextSegment {
	// Parse the response to find the top-level message content path.
	var response struct {
		Message *struct {
			Content struct {
				Parts []string `json:"parts"`
			} `json:"content"`
		} `json:"message"`
	}

	if err := json.Unmarshal(body, &response); err != nil {
		return nil
	}

	if response.Message == nil {
		return nil
	}

	return p.extractParts(body, response.Message.Content.Parts)
}

// extractParts is a helper shared by ExtractText and ExtractResponseText.
// It searches for part strings within the raw body bytes.
func (p *ChatGPTPlugin) extractParts(body []byte, parts []string) []providers.TextSegment {
	var segments []providers.TextSegment
	lastPos := 0
	for _, part := range parts {
		if part == "" {
			continue
		}
		partBytes := []byte(part)
		start := bytesIndexFrom(body, partBytes, lastPos)
		if start >= 0 {
			lastPos = start + len(partBytes)
			segments = append(segments, providers.TextSegment{
				Start: start,
				End:   lastPos,
				Text:  part,
			})
		} else {
			p.logger.Warn("chatgpt_plugin_text_not_found",
				"reason", "text_offset_not_found",
				"text_len", len(part),
				"body_len", len(body),
			)
		}
	}
	return segments
}

// chatGPTSession holds per-SSE-stream state for the ChatGPT plugin.
// It maintains the JSON Patch document tree and tracks unrecognized event types.
// Session methods are called from a single goroutine (the SSE read loop).
// No synchronization needed (PR-101).
type chatGPTSession struct {
	tree              *patchTree
	logger            *slog.Logger
	unknownEventsSeen map[string]bool // deduplicates WARN logs per stream
	streamEnded       bool
}

// newChatGPTSession creates a fresh session for a new SSE stream.
func newChatGPTSession(logger *slog.Logger) *chatGPTSession {
	return &chatGPTSession{
		tree:              newPatchTree(),
		logger:            logger,
		unknownEventsSeen: make(map[string]bool),
	}
}

// HandleSSEEvent processes an SSE event and returns text to scan.
// eventType is from the event: line or JSON type field. data is the raw data: line content.
// Only textToScan is returned — bytes pass through unmodified in monitor mode (PR-102).
func (s *chatGPTSession) HandleSSEEvent(eventType string, data []byte) string {
	if s.streamEnded {
		return ""
	}

	// Try to parse the data as JSON to determine the event structure.
	var rawJSON map[string]any
	if err := json.Unmarshal(data, &rawJSON); err != nil {
		// Not JSON — cannot extract text from it.
		return ""
	}

	// Determine the event type from JSON if the SSE event: line didn't provide one.
	if eventType == "" {
		if t, ok := rawJSON["type"].(string); ok {
			eventType = t
		}
	}

	// Check for JSON Patch operations first (have an "o" field).
	if op, ok := rawJSON["o"].(string); ok {
		text, err := s.handlePatchOperation(op, rawJSON)
		if err != nil {
			s.logger.Warn("chatgpt_plugin_degraded",
				"reason", "patch_tree_error",
				"op", op,
				"error", err.Error(),
			)
		}
		return text
	}

	// Handle typed events.
	switch eventType {
	case "input_message":
		return s.handleInputMessage(rawJSON)

	case "delta_encoding", "resume_conversation_token", "message_marker":
		// Metadata events — no text to scan.
		return ""

	case "":
		// No event type and no operation — this is an unrecognized event format.
		// Fall back to scanning all string values (DPO-R1.1).
		s.logUnknownEvent("(empty)")
		return strings.Join(s.extractAllStringValues(rawJSON), " ")

	default:
		// Unrecognized event type — fall back to scanning all string values (DPO-R1.1).
		s.logUnknownEvent(eventType)
		return strings.Join(s.extractAllStringValues(rawJSON), " ")
	}
}

// StreamEnded signals the end of the SSE stream. The document tree is cleared.
func (s *chatGPTSession) StreamEnded() {
	s.streamEnded = true
	if s.tree != nil {
		s.tree.clear()
		s.tree = nil
	}
}

// handlePatchOperation processes a JSON Patch operation from the raw JSON data.
// Constructs patchOp directly from the map to avoid double serialization (PR-005).
func (s *chatGPTSession) handlePatchOperation(op string, rawJSON map[string]any) (string, error) {
	var ops []patchOp

	if op == "patch" {
		// Batch of sub-operations: parse from the "ops" array.
		opsRaw, ok := rawJSON["ops"]
		if !ok {
			return "", nil
		}
		opsArr, ok := opsRaw.([]any)
		if !ok {
			return "", nil
		}
		for _, subRaw := range opsArr {
			subMap, ok := subRaw.(map[string]any)
			if !ok {
				continue
			}
			subOpStr, _ := subMap["o"].(string)
			ops = append(ops, patchOp{
				Op:    subOpStr,
				Path:  mapGetString(subMap, "p"),
				Value: subMap["v"],
			})
		}
	} else {
		ops = []patchOp{{
			Op:    op,
			Path:  mapGetString(rawJSON, "p"),
			Value: rawJSON["v"],
		}}
	}

	return s.tree.applyOps(ops)
}

// handleInputMessage processes an input_message event.
// It initializes the document tree with the message structure and extracts
// text from content.parts[] for PII scanning.
func (s *chatGPTSession) handleInputMessage(rawJSON map[string]any) string {
	im, ok := rawJSON["input_message"].(map[string]any)
	if !ok {
		return ""
	}

	// Validate content structure BEFORE storing in the tree (PR-204).
	content, ok := im["content"].(map[string]any)
	if !ok {
		return ""
	}

	parts, ok := content["parts"].([]any)
	if !ok {
		return ""
	}

	// Initialize the document tree with the validated message structure.
	// This sets up the paths that subsequent JSON Patch operations (append, replace)
	// will target: /message/content/parts/0, /message/content/parts/1, etc.
	// We store it under root["message"] to match the path prefix ChatGPT uses.
	messageNode := make(map[string]any)
	messageNode["content"] = content
	if s.tree != nil && !s.tree.degraded {
		if _, err := s.tree.setAt(s.tree.root, "message", messageNode); err != nil {
			s.logger.Warn("chatgpt_plugin_degraded",
				"reason", "patch_tree_error",
				"op", "input_message_setAt",
				"error", err.Error(),
			)
			s.tree.degraded = true
			return ""
		}
	}

	var textParts []string
	for _, part := range parts {
		if str, ok := part.(string); ok {
			textParts = append(textParts, str)
		}
	}

	return strings.Join(textParts, " ")
}

// extractAllStringValues recursively extracts all string values from a JSON structure.
// Used as a conservative fallback for unrecognized event types (DPO-R1.1).
// Returns a slice of strings to avoid trailing whitespace artifacts (PR-006).
func (s *chatGPTSession) extractAllStringValues(obj any) []string {
	switch v := obj.(type) {
	case string:
		return []string{v}
	case map[string]any:
		var result []string
		for _, val := range v {
			result = append(result, s.extractAllStringValues(val)...)
		}
		return result
	case []any:
		var result []string
		for _, val := range v {
			result = append(result, s.extractAllStringValues(val)...)
		}
		return result
	default:
		return nil
	}
}

// logUnknownEvent logs a WARN message for unrecognized event types.
// Each event type is logged at most once per stream (DPO-R1.2).
// The log entry contains only the event type name (metadata) — never the event data.
func (s *chatGPTSession) logUnknownEvent(eventType string) {
	if s.unknownEventsSeen[eventType] {
		return
	}
	s.unknownEventsSeen[eventType] = true
	s.logger.Warn("chatgpt_plugin_unrecognized_event",
		"event_type", sanitizeEventTypeForLog(eventType),
		"fallback", "all_string_scan",
	)
}

// maxEventTypeLenForLog is the max length for event type strings in logs (PR-205).
// Note: maxSSEEventTypeLen in internal/interceptor/sse_helper.go serves a different
// purpose — it controls input validation in the agnostic SSE layer, while this
// constant controls log output truncation. Both are 128 bytes.
const maxEventTypeLenForLog = 128

// sanitizeEventTypeForLog ensures the event type is safe to log.
// Truncates to maxEventTypeLenForLog bytes (UTF-8 safe) and strips control
// characters (CS-11-09, PR-103).
func sanitizeEventTypeForLog(et string) string {
	if len(et) > maxEventTypeLenForLog {
		trunc := maxEventTypeLenForLog
		for trunc > 0 && !utf8.RuneStart(et[trunc]) {
			trunc--
		}
		et = et[:trunc]
	}
	// Strip non-printable characters.
	var b strings.Builder
	for _, r := range et {
		if r >= 32 && r < 127 {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// mapGetString returns the string value for a key from a map.
// Returns empty string if the key is missing, nil, or not a string.
func mapGetString(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	v, ok := m[key]
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return s
}

// bytesIndexFrom searches for a byte slice in a byte slice starting from
// the given offset and returns its start index. Returns -1 if not found.
// Uses bytes.Index from the standard library (PR-102).
func bytesIndexFrom(body, search []byte, searchFrom int) int {
	if searchFrom >= len(body) || searchFrom < 0 || len(search) == 0 {
		return -1
	}
	idx := bytes.Index(body[searchFrom:], search)
	if idx < 0 {
		return -1
	}
	return searchFrom + idx
}
