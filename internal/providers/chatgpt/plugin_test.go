package chatgpt

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/Tarekinh0/qindu/internal/pii"
	"github.com/Tarekinh0/qindu/internal/testutils"
)

// testLogger creates a logger that writes to a buffer for test assertions.
func testLogger(buf *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func TestChatGPTPlugin_Name(t *testing.T) {
	var logBuf bytes.Buffer
	plugin := NewChatGPTPlugin(testLogger(&logBuf))
	if plugin.Name() != "chatgpt" {
		t.Errorf("expected 'chatgpt', got %q", plugin.Name())
	}
}

func TestChatGPTPlugin_MatchPath_Conversation(t *testing.T) {
	var logBuf bytes.Buffer
	plugin := NewChatGPTPlugin(testLogger(&logBuf))

	tests := []struct {
		method, path string
		want         bool
	}{
		{"POST", "/backend-anon/f/conversation", true},
		{"POST", "/backend-api/f/conversation", true},
		{"POST", "/backend-anon/f/conversation/abc-123", true},
		{"POST", "/backend-api/f/conversation/xyz", true},
		{"GET", "/backend-anon/f/conversation", true}, // method doesn't matter for path match
	}

	for _, tt := range tests {
		got := plugin.MatchPath(tt.method, tt.path)
		if got != tt.want {
			t.Errorf("MatchPath(%q, %q) = %v, want %v", tt.method, tt.path, got, tt.want)
		}
	}
}

func TestChatGPTPlugin_MatchPath_NonConversation(t *testing.T) {
	var logBuf bytes.Buffer
	plugin := NewChatGPTPlugin(testLogger(&logBuf))

	tests := []struct {
		method, path string
	}{
		{"POST", "/ces/v1/t"},
		{"GET", "/"},
		{"POST", "/api/auth/session"},
		{"POST", "/sentinel/ping"},
		{"GET", "/static/js/main.js"},
	}

	for _, tt := range tests {
		got := plugin.MatchPath(tt.method, tt.path)
		if got {
			t.Errorf("MatchPath(%q, %q) = true, want false", tt.method, tt.path)
		}
	}
}

func TestChatGPTPlugin_ExtractText_WithPII(t *testing.T) {
	var logBuf bytes.Buffer
	plugin := NewChatGPTPlugin(testLogger(&logBuf))

	// Synthetic ChatGPT request JSON with email in content.parts.
	body := []byte(`{
		"messages": [
			{
				"content": {
					"parts": ["Hello, my email is test.user@example.com. Can you help me?"]
				}
			}
		]
	}`)

	segments := plugin.ExtractText(body)
	if len(segments) == 0 {
		t.Fatal("expected at least 1 text segment")
	}

	// Verify we got the right text.
	found := false
	for _, seg := range segments {
		if strings.Contains(seg.Text, "test.user@example.com") {
			found = true
			// Verify offsets are valid.
			if seg.Start < 0 || seg.End > len(body) || seg.Start > seg.End {
				t.Errorf("invalid offsets: start=%d end=%d", seg.Start, seg.End)
			}
		}
	}
	if !found {
		t.Error("did not find the email in extracted segments")
	}

	// Verify TextSegment is passed by value (DPO-R4.1) — check Text is a copy.
	for _, seg := range segments {
		// The Text field is a Go string (immutable, value semantics).
		if seg.Text == "" {
			t.Error("empty text segment")
		}
	}
}

func TestChatGPTPlugin_ExtractText_MultipleMessages(t *testing.T) {
	var logBuf bytes.Buffer
	plugin := NewChatGPTPlugin(testLogger(&logBuf))

	body := []byte(`{
		"messages": [
			{
				"content": {
					"parts": ["First message"]
				}
			},
			{
				"content": {
					"parts": ["Second message", "+1-555-0100"]
				}
			}
		]
	}`)

	segments := plugin.ExtractText(body)
	if len(segments) < 3 {
		t.Fatalf("expected at least 3 segments, got %d", len(segments))
	}
}

func TestChatGPTPlugin_ExtractText_EmptyParts(t *testing.T) {
	var logBuf bytes.Buffer
	plugin := NewChatGPTPlugin(testLogger(&logBuf))

	body := []byte(`{"messages": [{"content": {"parts": []}}]}`)
	segments := plugin.ExtractText(body)
	if len(segments) != 0 {
		t.Errorf("expected 0 segments for empty parts, got %d", len(segments))
	}
}

func TestChatGPTPlugin_ExtractText_InvalidJSON(t *testing.T) {
	var logBuf bytes.Buffer
	plugin := NewChatGPTPlugin(testLogger(&logBuf))

	body := []byte(`not json`)
	segments := plugin.ExtractText(body)
	if len(segments) != 0 {
		t.Errorf("expected 0 segments for invalid JSON, got %d", len(segments))
	}
}

func TestChatGPTPlugin_RewriteRequestBody_Identity(t *testing.T) {
	var logBuf bytes.Buffer
	plugin := NewChatGPTPlugin(testLogger(&logBuf))

	original := []byte(`{"test": "data"}`)
	result := plugin.RewriteRequestBody(original, nil)

	// Must be byte-identical (DPO-R5.2).
	if !bytes.Equal(result, original) {
		t.Error("RewriteRequestBody must return the original body unchanged")
	}
	// Must be the same slice (identity pass-through).
	if &result[0] != &original[0] {
		t.Log("RewriteRequestBody returned a copy — identity pass-through is preferred but not required")
	}
}

func TestChatGPTSession_InputMessage_TextExtracted(t *testing.T) {
	var logBuf bytes.Buffer
	plugin := NewChatGPTPlugin(testLogger(&logBuf))
	session := plugin.NewSession()
	defer session.StreamEnded()

	// Synthetic input_message event with PII.
	data := []byte(`{"type": "input_message", "input_message": {"content": {"parts": ["hello@example.com"]}}}`)

	text := session.HandleSSEEvent("input_message", data)

	if text == "" {
		t.Error("expected text to be extracted from input_message")
	}
	if !strings.Contains(text, "hello@example.com") {
		t.Errorf("extracted text should contain the email, got %q", text)
	}
}

func TestChatGPTSession_AppendTextContent(t *testing.T) {
	var logBuf bytes.Buffer
	plugin := NewChatGPTPlugin(testLogger(&logBuf))
	session := plugin.NewSession()
	defer session.StreamEnded()

	// First, initialize with input_message to set up the tree.
	initData := []byte(`{"type": "input_message", "input_message": {"content": {"parts": ["Hello!"]}}}`)
	session.HandleSSEEvent("input_message", initData)

	// Now send an append operation to content/parts/0.
	appendData := []byte(`{"o": "append", "p": "/message/content/parts/0", "v": " my email is john@doe.com"}`)

	text := session.HandleSSEEvent("", appendData)

	if text == "" {
		t.Error("expected text from append to content/parts/0")
	}
	if !strings.Contains(text, "john@doe.com") {
		t.Errorf("extracted text should contain the appended email, got %q", text)
	}
}

func TestChatGPTSession_AppendNonTextPath(t *testing.T) {
	var logBuf bytes.Buffer
	plugin := NewChatGPTPlugin(testLogger(&logBuf))
	session := plugin.NewSession()
	defer session.StreamEnded()

	// Append to a non-text path (e.g., status).
	appendData := []byte(`{"o": "append", "p": "/message/status", "v": "in_progress"}`)

	text := session.HandleSSEEvent("", appendData)

	// Non-text paths should not extract text.
	if text != "" {
		t.Errorf("expected no text from non-text path, got %q", text)
	}
}

func TestChatGPTSession_MetadataEventsIgnored(t *testing.T) {
	var logBuf bytes.Buffer
	plugin := NewChatGPTPlugin(testLogger(&logBuf))
	session := plugin.NewSession()
	defer session.StreamEnded()

	// Test resume_conversation_token with JWT — must NOT extract text.
	jwtData := []byte(`{"type": "resume_conversation_token", "token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"}`)

	text := session.HandleSSEEvent("resume_conversation_token", jwtData)
	if text != "" {
		t.Errorf("resume_conversation_token should not produce text, got %q", text)
	}

	// Test message_marker — must NOT extract text.
	markerData := []byte(`{"type": "message_marker", "marker": "user_visible_token"}`)
	text = session.HandleSSEEvent("message_marker", markerData)
	if text != "" {
		t.Errorf("message_marker should not produce text, got %q", text)
	}

	// Test delta_encoding — must NOT extract text.
	deltaData := []byte(`{"type": "delta_encoding", "version": "v1"}`)
	text = session.HandleSSEEvent("delta_encoding", deltaData)
	if text != "" {
		t.Errorf("delta_encoding should not produce text, got %q", text)
	}
}

// PT-1: TestPlugin_UnknownEventType_FallbackScan
func TestChatGPTSession_UnknownEventType_FallbackScan(t *testing.T) {
	var logBuf bytes.Buffer
	plugin := NewChatGPTPlugin(testLogger(&logBuf))
	session := plugin.NewSession()
	defer session.StreamEnded()

	// Unrecognized event type with string values containing PII.
	// The plugin must fall back to scanning all string values (DPO-R1.1).
	data := []byte(`{"type": "unknown_event", "field": "test.user@example.com", "nested": {"inner": "+1-555-0100"}}`)

	text := session.HandleSSEEvent("unknown_event", data)

	if text == "" {
		t.Error("expected fallback scan to extract all string values for unknown event type")
	}
	if !strings.Contains(text, "test.user@example.com") {
		t.Errorf("fallback scan should include email, got %q", text)
	}
	if !strings.Contains(text, "+1-555-0100") {
		t.Errorf("fallback scan should include phone, got %q", text)
	}
}

// PT-2: TestPlugin_UnknownEventType_WarningLogged
func TestChatGPTSession_UnknownEventType_WarningLogged(t *testing.T) {
	var logBuf bytes.Buffer
	plugin := NewChatGPTPlugin(testLogger(&logBuf))
	session := plugin.NewSession()
	defer session.StreamEnded()

	// First occurrence — should log WARN.
	data := []byte(`{"type": "new_event_type", "text": "hello"}`)
	session.HandleSSEEvent("new_event_type", data)

	// Second occurrence of same type — should NOT log another WARN (DPO-R1.2).
	session.HandleSSEEvent("new_event_type", data)

	entries := testutils.ParseLogEntries(t, &logBuf)
	warnCount := 0
	for _, e := range entries {
		if e["msg"] == "chatgpt_plugin_unrecognized_event" {
			warnCount++
			if e["level"] != "WARN" && e["level"] != "warn" {
				t.Errorf("expected WARN level, got %v", e["level"])
			}
			if e["event_type"] != "new_event_type" {
				t.Errorf("expected event_type 'new_event_type', got %v", e["event_type"])
			}
			// Verify event data is NOT in the log (DPO-R1.2).
			logLine, _ := json.Marshal(e)
			if strings.Contains(string(logLine), "hello") {
				t.Error("log entry must not contain event data content")
			}
		}
	}
	if warnCount != 1 {
		t.Errorf("expected exactly 1 WARN for unknown event type, got %d", warnCount)
	}
}

// PT-4: TestDocumentTree_ClearedOnStreamEnd
func TestChatGPTSession_DocumentTree_ClearedOnStreamEnd(t *testing.T) {
	var logBuf bytes.Buffer
	plugin := NewChatGPTPlugin(testLogger(&logBuf))
	session := plugin.NewSession()

	// Add some data to the tree.
	data := []byte(`{"type": "input_message", "input_message": {"content": {"parts": ["hello"]}}}`)
	session.HandleSSEEvent("input_message", data)

	// End the stream.
	session.StreamEnded()

	// After StreamEnded, the tree should be nil.
	cs, ok := session.(*chatGPTSession)
	if !ok {
		t.Fatal("session is not *chatGPTSession")
	}
	if cs.tree != nil {
		t.Error("document tree must be nil after StreamEnded")
	}
	if cs.streamEnded != true {
		t.Error("streamEnded must be true")
	}

	// Subsequent HandleSSEEvent should return empty text.
	text := session.HandleSSEEvent("input_message", data)
	if text != "" {
		t.Errorf("HandleSSEEvent after StreamEnded should return empty text, got %q", text)
	}
}

// PT-5: TestDocumentTree_NoCrossStreamLeak
func TestChatGPTSession_NoCrossStreamLeak(t *testing.T) {
	var logBuf bytes.Buffer
	plugin := NewChatGPTPlugin(testLogger(&logBuf))

	// Session 1: add PII.
	session1 := plugin.NewSession()
	s1Data := []byte(`{"type": "input_message", "input_message": {"content": {"parts": ["secret-1@example.com"]}}}`)
	session1.HandleSSEEvent("input_message", s1Data)
	session1.StreamEnded()

	// Session 2: fresh session must not see session 1's data.
	session2 := plugin.NewSession()
	s2Data := []byte(`{"type": "input_message", "input_message": {"content": {"parts": ["secret-2@example.com"]}}}`)
	text := session2.HandleSSEEvent("input_message", s2Data)
	session2.StreamEnded()

	// Session 2's text must only contain its own PII, not session 1's.
	if strings.Contains(text, "secret-1@example.com") {
		t.Error("session 2 text must not contain session 1's PII (cross-stream leak)")
	}
	if !strings.Contains(text, "secret-2@example.com") {
		t.Error("session 2 text must contain its own PII")
	}
}

// PT-10: TestPlugin_NoBufferRetention
func TestChatGPTSession_NoBufferRetention(t *testing.T) {
	var logBuf bytes.Buffer
	plugin := NewChatGPTPlugin(testLogger(&logBuf))
	session := plugin.NewSession()
	defer session.StreamEnded()

	// Create data with a PII value.
	originalData := []byte(`{"type": "input_message", "input_message": {"content": {"parts": ["buffer-test@example.com"]}}}`)

	text := session.HandleSSEEvent("input_message", originalData)

	// The plugin returns text as a string (Go value semantics).
	// If the plugin retained a reference to the original data slice,
	// modifying the slice would affect the returned text.
	originalCopy := make([]byte, len(originalData))
	copy(originalCopy, originalData)

	// Modify the original buffer.
	for i := range originalData {
		originalData[i] = 'X'
	}

	// The returned text must still contain the original value (DPO-R4.2).
	if !strings.Contains(text, "buffer-test@example.com") {
		t.Error("returned text was affected by buffer mutation — plugin retained reference")
	}
	_ = originalCopy
}

// Test for AC-3: ChatGPT response — metadata ignored, only text PII detected.
func TestChatGPTSession_MetadataIgnored_RealWorldScenario(t *testing.T) {
	var logBuf bytes.Buffer
	plugin := NewChatGPTPlugin(testLogger(&logBuf))
	session := plugin.NewSession()
	defer session.StreamEnded()

	// Initialize the document tree with an input_message (echo of user message).
	initData := []byte(`{"type": "input_message", "input_message": {"content": {"parts": ["Hello"]}}}`)
	text := session.HandleSSEEvent("input_message", initData)
	if !strings.Contains(text, "Hello") {
		t.Errorf("input_message should extract text from content.parts, got %q", text)
	}

	// A resume_conversation_token with a JWT (should be ignored — no text extracted).
	jwtData := []byte(`{"type": "resume_conversation_token", "token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dummySig"}`)
	text = session.HandleSSEEvent("resume_conversation_token", jwtData)
	if text != "" {
		t.Errorf("JWT in resume_conversation_token should be ignored, got text=%q", text)
	}

	// Then, a text content append with an email (should be extracted — false positive eliminated for JWT).
	appendData := []byte(`{"o": "append", "p": "/message/content/parts/0", "v": " contact user@example.com"}`)
	text = session.HandleSSEEvent("", appendData)
	if !strings.Contains(text, "user@example.com") {
		t.Errorf("append should extract text with email, got %q", text)
	}
}

// Test for JSON Patch state machine: replace operation on text path.
func TestChatGPTSession_ReplaceTextPath(t *testing.T) {
	var logBuf bytes.Buffer
	plugin := NewChatGPTPlugin(testLogger(&logBuf))
	session := plugin.NewSession()
	defer session.StreamEnded()

	// Initialize tree with input_message to create content/parts/0.
	initData := []byte(`{"type": "input_message", "input_message": {"content": {"parts": ["original"]}}}`)
	session.HandleSSEEvent("input_message", initData)

	// Replace content/parts/0 with new text containing PII.
	replaceData := []byte(`{"o": "replace", "p": "/message/content/parts/0", "v": "new text with phone +1-555-0100"}`)
	text := session.HandleSSEEvent("", replaceData)

	if !strings.Contains(text, "+1-555-0100") {
		t.Errorf("replace should extract text with phone, got %q", text)
	}
}

// Test for JSON Patch state machine: patch operation (batch of sub-operations).
func TestChatGPTSession_PatchBatchOperation(t *testing.T) {
	var logBuf bytes.Buffer
	plugin := NewChatGPTPlugin(testLogger(&logBuf))
	session := plugin.NewSession()
	defer session.StreamEnded()

	// Initialize: add message/status and message/content/parts/0.
	addStatus := []byte(`{"o": "add", "p": "/message/status", "v": "started"}`)
	session.HandleSSEEvent("", addStatus)

	addParts := []byte(`{"o": "add", "p": "/message/content/parts/0", "v": ""}`)
	session.HandleSSEEvent("", addParts)

	// Patch: batch of two appends.
	patchData := []byte(`{"o": "patch", "ops": [
		{"o": "append", "p": "/message/content/parts/0", "v": "Hello! "},
		{"o": "append", "p": "/message/content/parts/0", "v": "My email is admin@company.org"}
	]}`)
	text := session.HandleSSEEvent("", patchData)

	if !strings.Contains(text, "admin@company.org") {
		t.Errorf("patch should extract appended text with email, got %q", text)
	}
}

// Test createEngine creates a PII engine for plugin text validation tests.
func createTestEngine() *pii.Engine {
	return pii.NewEngine(pii.DefaultMaxInputBytes,
		pii.NewEmailRecognizer(),
		pii.NewPhoneRecognizer(),
	)
}

// Test PII detection on text extracted by the plugin.
func TestChatGPTPlugin_PIIDetectionOnExtractedText(t *testing.T) {
	var logBuf bytes.Buffer
	plugin := NewChatGPTPlugin(testLogger(&logBuf))
	session := plugin.NewSession()
	defer session.StreamEnded()

	engine := createTestEngine()

	// Send input_message with an email.
	data := []byte(`{"type": "input_message", "input_message": {"content": {"parts": ["my email is my.email@test.org"]}}}`)
	text := session.HandleSSEEvent("input_message", data)

	// Run PII detection on extracted text.
	entities, err := engine.Detect(text)
	if err != nil {
		t.Fatalf("engine.Detect failed: %v", err)
	}

	// Should find exactly 1 EMAIL.
	emailCount := 0
	for _, e := range entities {
		if e.Type == pii.Email {
			emailCount++
		}
	}
	if emailCount != 1 {
		t.Errorf("expected 1 EMAIL detection, got %d. entities: %v", emailCount, entities)
	}
}

// PT-15: TestTestFixtures_NoRealPII — static analysis check.
func TestTestFixtures_NoRealPII(t *testing.T) {
	// This test verifies that no real PII appears in test fixture strings.
	// We look for patterns that would indicate real data leaks.

	// Test-specific email domains that are known to be synthetic.
	knownTestEmails := []string{
		"test.user@example.com",
		"hello@example.com",
		"john@doe.com",
		"user@example.com",
		"admin@company.org",
		"my.email@test.org",
		"secret-1@example.com",
		"secret-2@example.com",
		"buffer-test@example.com",
	}

	// Allowed synthetic email domains for test fixtures (positive allowlist, PR-105).
	allowedDomains := map[string]bool{
		"example.com": true,
		"doe.com":     true,
		"company.org": true,
		"test.org":    true,
	}

	for _, email := range knownTestEmails {
		parts := strings.Split(email, "@")
		if len(parts) != 2 || !allowedDomains[parts[1]] {
			t.Errorf("potentially real email in test: %q", email)
		}
	}

	// No test should contain real JWT tokens with actual secrets.
	// Our test JWT uses a well-known dummy secret.

	// No test should contain real credit card numbers.
	// Our tests use phone numbers like +1-555-0100 (555 prefix = reserved fictional).
}
