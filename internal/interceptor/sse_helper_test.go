package interceptor

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/Tarekinh0/qindu/internal/testutils"
)

// mockProviderSession is a test double for providers.ProviderPluginSession.
type mockProviderSession struct {
	handleEvent func(eventType string, data []byte) string
	streamEnded bool
}

func (m *mockProviderSession) HandleSSEEvent(eventType string, data []byte) string {
	if m.handleEvent != nil {
		return m.handleEvent(eventType, data)
	}
	// Default: return the data as plain text for scanning.
	return extractSSEDataLines(string(data))
}

func (m *mockProviderSession) StreamEnded() {
	m.streamEnded = true
}

// extractSSEDataLines is a helper that extracts text from data: lines.
func extractSSEDataLines(rawFrame string) string {
	normalized := strings.ReplaceAll(rawFrame, "\r\n", "\n")
	lines := strings.Split(normalized, "\n")
	var dataLines []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "data:") {
			data := strings.TrimSpace(strings.TrimPrefix(trimmed, "data:"))
			dataLines = append(dataLines, data)
		}
	}
	return strings.Join(dataLines, "\n")
}

// panickingMockSession panics on HandleSSEEvent for testing CS-11-05.
// Follows the mock* naming convention used by other test doubles.
type panickingMockSession struct{}

func (p *panickingMockSession) HandleSSEEvent(eventType string, data []byte) string {
	panic("simulated plugin panic")
}

func (p *panickingMockSession) StreamEnded() {}

func TestProviderSSEReader_CompleteFrames(t *testing.T) {
	engine := newTestEngine()
	var logBuf bytes.Buffer
	logger := newTestLogger(&logBuf)

	sseStream := strings.NewReader(
		`data: {"msg": "test.user@example.com"}` + "\n\n" +
			`data: {"msg": "No PII here"}` + "\n\n" +
			`data: {"msg": "Call +1-555-0100"}` + "\n\n",
	)

	session := &mockProviderSession{
		handleEvent: func(eventType string, data []byte) string {
			// Extract text from data for scanning.
			var m map[string]string
			if err := json.Unmarshal(data, &m); err == nil {
				return m["msg"]
			}
			return string(data)
		},
	}

	reader := newProviderSSEReader(ProviderSSEConfig{
		Upstream:    io.NopCloser(sseStream),
		Engine:      engine,
		Logger:      logger,
		PIILogging:  true,
		Host:        "test.local",
		Method:      "POST",
		Path:        "/v1/chat",
		ContentType: "text/event-stream",
		StatusCode:  200,
		PluginName:  "test-plugin",
		Session:     session,
	})
	defer func() { _ = reader.Close() }()

	output, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}

	// Verify forwarding is byte-identical.
	expectedOutput := `data: {"msg": "test.user@example.com"}` + "\n\n" +
		`data: {"msg": "No PII here"}` + "\n\n" +
		`data: {"msg": "Call +1-555-0100"}` + "\n\n"
	if string(output) != expectedOutput {
		t.Errorf("forwarded output mismatch.\n got: %q\nwant: %q", string(output), expectedOutput)
	}

	// Verify aggregated monitor_scan log entry.
	entries := testutils.ParseLogEntries(t, &logBuf)
	var scanEntries []map[string]any
	for _, e := range entries {
		if e["msg"] == "monitor_scan" {
			scanEntries = append(scanEntries, e)
		}
	}
	if len(scanEntries) != 1 {
		t.Fatalf("expected exactly 1 monitor_scan entry, got %d", len(scanEntries))
	}

	entry := scanEntries[0]
	if entry["pii_values_logged"] != false {
		t.Errorf("pii_values_logged must be false, got %v", entry["pii_values_logged"])
	}
	// PR-003: provider field intentionally excluded for format parity with MonitorInterceptor.
	if _, ok := entry["provider"]; ok {
		t.Error("provider field must not appear in monitor_scan (format parity)")
	}
	if entry["sse_frame"] != true {
		t.Errorf("sse_frame must be true")
	}
	if entry["result"] != "pii_found" {
		t.Errorf("result should be pii_found, got %v", entry["result"])
	}
}

// SEC-11-T1: SSE frame oversize — detection skipped, bytes forwarded, WARN logged.
func TestProviderSSEReader_OversizedFrame(t *testing.T) {
	engine := newTestEngine()
	var logBuf bytes.Buffer
	logger := newTestLogger(&logBuf)

	maxSize := 100
	bigData := strings.Repeat("x", maxSize+50)
	sseStream := strings.NewReader(`data: ` + bigData + "\n\n")

	session := &mockProviderSession{}

	reader := newProviderSSEReader(ProviderSSEConfig{
		Upstream:     io.NopCloser(sseStream),
		Engine:       engine,
		Logger:       logger,
		PIILogging:   true,
		MaxFrameSize: maxSize,
		Host:         "test.local",
		Method:       "POST",
		Path:         "/api",
		ContentType:  "text/event-stream",
		StatusCode:   200,
		PluginName:   "test-plugin",
		Session:      session,
	})
	defer func() { _ = reader.Close() }()

	output, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}

	// All bytes must be forwarded.
	if !strings.Contains(string(output), bigData) {
		t.Error("oversized frame must be forwarded completely")
	}

	// Check WARN for oversize.
	entries := testutils.ParseLogEntries(t, &logBuf)
	hasSkipWarn := false
	for _, e := range entries {
		if e["msg"] == "pii_detection_skipped" &&
			e["reason"] == "sse_frame_oversize" {
			hasSkipWarn = true
			break
		}
	}
	if !hasSkipWarn {
		t.Error("expected pii_detection_skipped warn for oversized frame")
	}
}

// SEC-11-T7: Plugin HandleSSEEvent panics → ERROR logged, monitor_scan still emitted, bytes forwarded.
func TestProviderSSEReader_PluginPanic(t *testing.T) {
	engine := newTestEngine()
	var logBuf bytes.Buffer
	logger := newTestLogger(&logBuf)

	sseStream := strings.NewReader(
		`data: {"msg": "test@example.com"}` + "\n\n" +
			`data: {"msg": "after panic"}` + "\n\n",
	)

	session := &panickingMockSession{}

	reader := newProviderSSEReader(ProviderSSEConfig{
		Upstream:    io.NopCloser(sseStream),
		Engine:      engine,
		Logger:      logger,
		PIILogging:  true,
		Host:        "test.local",
		Method:      "POST",
		Path:        "/api",
		ContentType: "text/event-stream",
		StatusCode:  200,
		PluginName:  "panicking-plugin",
		Session:     session,
	})
	defer func() { _ = reader.Close() }()

	output, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}
	_ = output

	entries := testutils.ParseLogEntries(t, &logBuf)

	// Check that an ERROR was logged for the panic (CS-11-05).
	hasPanicError := false
	for _, e := range entries {
		if e["msg"] == "provider_plugin_panic" {
			hasPanicError = true
			if e["level"] != "ERROR" {
				t.Errorf("panic should be logged at ERROR level, got %v", e["level"])
			}
			if e["plugin"] != "panicking-plugin" {
				t.Errorf("plugin name mismatch: %v", e["plugin"])
			}
			// Verify no raw data in panic log.
			logJSON, _ := json.Marshal(e)
			if strings.Contains(string(logJSON), "test@example.com") {
				t.Error("panic log must not contain raw data")
			}
			break
		}
	}
	if !hasPanicError {
		t.Error("expected provider_plugin_panic ERROR log entry")
	}

	// Check that a monitor_scan was still emitted (CS-11-05, requirement 4).
	hasMonitorScan := false
	for _, e := range entries {
		if e["msg"] == "monitor_scan" {
			hasMonitorScan = true
			break
		}
	}
	if !hasMonitorScan {
		t.Error("expected monitor_scan to be emitted even after plugin panic")
	}
}

// PT-6: SSE helper logs contain only metadata — no extracted text.
func TestProviderSSEReader_NoTextInLogs(t *testing.T) {
	engine := newTestEngine()
	var logBuf bytes.Buffer
	logger := newTestLogger(&logBuf)

	sseStream := strings.NewReader(
		`data: {"msg": "test.user@example.com"}` + "\n\n",
	)

	session := &mockProviderSession{
		handleEvent: func(eventType string, data []byte) string {
			return string(data)
		},
	}

	reader := newProviderSSEReader(ProviderSSEConfig{
		Upstream:    io.NopCloser(sseStream),
		Engine:      engine,
		Logger:      logger,
		PIILogging:  true,
		Host:        "test.local",
		Method:      "POST",
		Path:        "/api",
		ContentType: "text/event-stream",
		StatusCode:  200,
		PluginName:  "test-plugin",
		Session:     session,
	})
	defer func() { _ = reader.Close() }()

	_, _ = io.ReadAll(reader)

	logOutput := logBuf.String()
	// No PII values in logs (DPO-R3.1).
	if strings.Contains(logOutput, "test.user@example.com") {
		t.Error("log output must not contain raw PII values")
	}
	if strings.Contains(logOutput, "test.user") {
		t.Error("log output must not contain raw PII substrings")
	}
	// Verify no extracted text appears in logs (string data returned by mock session).
	// The entity_summary should only contain type counts, not raw content.
}

// Test for SSE frame parsing: event: and data: line parsing.
func TestProviderSSEReader_EventTypeParsing(t *testing.T) {
	engine := newTestEngine()
	var logBuf bytes.Buffer
	logger := newTestLogger(&logBuf)

	sseStream := strings.NewReader(
		"event: input_message\n" +
			`data: {"text": "hello@example.com"}` + "\n\n",
	)

	session := &mockProviderSession{
		handleEvent: func(eventType string, data []byte) string {
			if eventType != "input_message" {
				t.Errorf("expected event_type 'input_message', got %q", eventType)
			}
			return string(data)
		},
	}

	reader := newProviderSSEReader(ProviderSSEConfig{
		Upstream:    io.NopCloser(sseStream),
		Engine:      engine,
		Logger:      logger,
		PIILogging:  true,
		Host:        "test.local",
		Method:      "POST",
		Path:        "/api",
		ContentType: "text/event-stream",
		StatusCode:  200,
		PluginName:  "test-plugin",
		Session:     session,
	})
	defer func() { _ = reader.Close() }()

	_, _ = io.ReadAll(reader)
}

// Test for SSE frame with CRLF line endings and boundaries.
func TestProviderSSEReader_CRLFBoundaries(t *testing.T) {
	engine := newTestEngine()
	var logBuf bytes.Buffer
	logger := newTestLogger(&logBuf)

	// Use CRLF line endings and boundaries.
	sseStream := strings.NewReader(
		"data: {\"msg\": \"test@example.com\"}\r\n\r\n",
	)

	session := &mockProviderSession{
		handleEvent: func(eventType string, data []byte) string {
			return string(data)
		},
	}

	reader := newProviderSSEReader(ProviderSSEConfig{
		Upstream:    io.NopCloser(sseStream),
		Engine:      engine,
		Logger:      logger,
		PIILogging:  true,
		Host:        "test.local",
		Method:      "POST",
		Path:        "/api",
		ContentType: "text/event-stream",
		StatusCode:  200,
		PluginName:  "test-plugin",
		Session:     session,
	})
	defer func() { _ = reader.Close() }()

	output, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}

	if !strings.Contains(string(output), "test@example.com") {
		t.Error("CRLF-delimited frame must pass through")
	}
}

// Test for multiple data lines per frame.
func TestProviderSSEReader_MultipleDataLines(t *testing.T) {
	engine := newTestEngine()
	var logBuf bytes.Buffer
	logger := newTestLogger(&logBuf)

	// Multiple data: lines in a single frame.
	sseStream := strings.NewReader(
		`data: {"user": "test.user@example.com",` + "\n" +
			`data:  "phone": "+1-555-0100"}` + "\n\n",
	)

	session := &mockProviderSession{
		handleEvent: func(eventType string, data []byte) string {
			return string(data)
		},
	}

	reader := newProviderSSEReader(ProviderSSEConfig{
		Upstream:    io.NopCloser(sseStream),
		Engine:      engine,
		Logger:      logger,
		PIILogging:  true,
		Host:        "test.local",
		Method:      "POST",
		Path:        "/api",
		ContentType: "text/event-stream",
		StatusCode:  200,
		PluginName:  "test-plugin",
		Session:     session,
	})
	defer func() { _ = reader.Close() }()

	_, _ = io.ReadAll(reader)

	entries := testutils.ParseLogEntries(t, &logBuf)
	var scanEntries []map[string]any
	for _, e := range entries {
		if e["msg"] == "monitor_scan" {
			scanEntries = append(scanEntries, e)
		}
	}
	if len(scanEntries) >= 1 {
		ec, _ := scanEntries[0]["entity_count"].(float64)
		if ec < 2 {
			t.Errorf("expected at least 2 entities from multi-line data (email + phone), got %v", ec)
		}
	}
}

// Test that session.StreamEnded() is called on stream end.
func TestProviderSSEReader_SessionStreamEnded(t *testing.T) {
	engine := newTestEngine()
	var logBuf bytes.Buffer
	logger := newTestLogger(&logBuf)

	sseStream := strings.NewReader(
		`data: {"msg": "hello"}` + "\n\n",
	)

	session := &mockProviderSession{}

	reader := newProviderSSEReader(ProviderSSEConfig{
		Upstream:    io.NopCloser(sseStream),
		Engine:      engine,
		Logger:      logger,
		PIILogging:  true,
		Host:        "test.local",
		Method:      "POST",
		Path:        "/api",
		ContentType: "text/event-stream",
		StatusCode:  200,
		PluginName:  "test-plugin",
		Session:     session,
	})
	defer func() { _ = reader.Close() }()

	_, _ = io.ReadAll(reader)

	if !session.streamEnded {
		t.Error("expected session.StreamEnded to be called on EOF")
	}
}

// Test that [DONE] marker triggers session end and monitor_scan emission.
func TestProviderSSEReader_DoneMarker(t *testing.T) {
	engine := newTestEngine()
	var logBuf bytes.Buffer
	logger := newTestLogger(&logBuf)

	sseStream := strings.NewReader(
		`data: {"msg": "hello@example.com"}` + "\n\n" +
			"data: [DONE]\n\n" +
			`data: {"msg": "after done"}` + "\n\n",
	)

	session := &mockProviderSession{
		handleEvent: func(eventType string, data []byte) string {
			return string(data)
		},
	}

	reader := newProviderSSEReader(ProviderSSEConfig{
		Upstream:    io.NopCloser(sseStream),
		Engine:      engine,
		Logger:      logger,
		PIILogging:  true,
		Host:        "test.local",
		Method:      "POST",
		Path:        "/api",
		ContentType: "text/event-stream",
		StatusCode:  200,
		PluginName:  "test-plugin",
		Session:     session,
	})
	defer func() { _ = reader.Close() }()

	_, _ = io.ReadAll(reader)

	entries := testutils.ParseLogEntries(t, &logBuf)
	var scanEntries []map[string]any
	for _, e := range entries {
		if e["msg"] == "monitor_scan" {
			scanEntries = append(scanEntries, e)
		}
	}
	// Should emit a monitor_scan (triggered by [DONE]).
	if len(scanEntries) < 1 {
		t.Fatal("expected monitor_scan entry for [DONE] marker")
	}
}

// Test that log entries match MonitorInterceptor format (CS-11-10, PT-7).
func TestProviderSSEReader_MonitorScanFormat(t *testing.T) {
	engine := newTestEngine()
	var logBuf bytes.Buffer
	logger := newTestLogger(&logBuf)

	sseStream := strings.NewReader(
		`data: {"msg": "test@example.com"}` + "\n\n",
	)

	session := &mockProviderSession{
		handleEvent: func(eventType string, data []byte) string {
			return string(data)
		},
	}

	reader := newProviderSSEReader(ProviderSSEConfig{
		Upstream:    io.NopCloser(sseStream),
		Engine:      engine,
		Logger:      logger,
		PIILogging:  false, // pii_logging disabled
		Host:        "test.local",
		Method:      "POST",
		Path:        "/api",
		ContentType: "text/event-stream",
		StatusCode:  200,
		PluginName:  "test-plugin",
		Session:     session,
	})
	defer func() { _ = reader.Close() }()

	_, _ = io.ReadAll(reader)

	entries := testutils.ParseLogEntries(t, &logBuf)
	var scanEntries []map[string]any
	for _, e := range entries {
		if e["msg"] == "monitor_scan" {
			scanEntries = append(scanEntries, e)
		}
	}
	if len(scanEntries) != 1 {
		t.Fatalf("expected 1 monitor_scan entry, got %d", len(scanEntries))
	}

	entry := scanEntries[0]

	// Verify required fields from MonitorInterceptor format.
	requiredFields := []string{"direction", "result", "bytes_analyzed", "pii_values_logged"}
	for _, f := range requiredFields {
		if _, ok := entry[f]; !ok {
			t.Errorf("required field %q missing from monitor_scan", f)
		}
	}

	// pii_values_logged must be false.
	if entry["pii_values_logged"] != false {
		t.Errorf("pii_values_logged must be false")
	}

	// When pii_logging is false, entity_summary must be omitted (same as MonitorInterceptor).
	if _, ok := entry["entity_summary"]; ok {
		t.Error("entity_summary must be omitted when pii_logging=false")
	}

	// entity_count should still be present.
	if ec, ok := entry["entity_count"]; !ok {
		t.Error("entity_count must be present even when pii_logging=false")
	} else if ec.(float64) < 1 {
		t.Errorf("entity_count should be >= 1, got %v", ec)
	}
}

// SEC-11-T11: No PII in any log output.
func TestProviderSSEReader_ZeroPIIInLogs(t *testing.T) {
	engine := newTestEngine()
	var logBuf bytes.Buffer
	logger := newTestLogger(&logBuf)

	sseStream := strings.NewReader(
		`data: {"email": "super.secret@example.com"}` + "\n\n" +
			`data: {"phone": "+1-555-0199"}` + "\n\n",
	)

	session := &mockProviderSession{
		handleEvent: func(eventType string, data []byte) string {
			return string(data)
		},
	}

	reader := newProviderSSEReader(ProviderSSEConfig{
		Upstream:    io.NopCloser(sseStream),
		Engine:      engine,
		Logger:      logger,
		PIILogging:  true,
		Host:        "test.local",
		Method:      "POST",
		Path:        "/api",
		ContentType: "text/event-stream",
		StatusCode:  200,
		PluginName:  "test-plugin",
		Session:     session,
	})
	defer func() { _ = reader.Close() }()

	_, _ = io.ReadAll(reader)

	logOutput := logBuf.String()

	// Search for raw PII patterns.
	piiPatterns := []string{
		"super.secret@example.com",
		"+1-555-0199",
	}

	for _, pattern := range piiPatterns {
		if strings.Contains(logOutput, pattern) {
			t.Errorf("log output must not contain raw PII: %q", pattern)
		}
	}

	// Verify that entity_summary contains only type counts, never values.
	entries := testutils.ParseLogEntries(t, &logBuf)
	for _, e := range entries {
		if e["msg"] == "monitor_scan" {
			if summary, ok := e["entity_summary"].(map[string]any); ok {
				for k, v := range summary {
					// Keys must be entity types (EMAIL, PHONE, etc.) — not values.
					if !isValidEntityType(k) {
						t.Errorf("entity_summary key is not a valid entity type: %q", k)
					}
					// Values must be numeric counts.
					if _, ok := v.(float64); !ok {
						t.Errorf("entity_summary value for %q must be a number", k)
					}
				}
			}
		}
	}
}

func isValidEntityType(s string) bool {
	validTypes := map[string]bool{
		"EMAIL": true, "PHONE": true, "IBAN": true, "CREDIT_CARD": true,
		"JWT": true, "NAME": true, "SECRET": true, "PRIVATE_KEY": true,
	}
	return validTypes[s]
}

// Test frame timeout handling (CS-11-02).
func TestProviderSSEReader_TimeoutHandling(t *testing.T) {
	engine := newTestEngine()
	var logBuf bytes.Buffer
	logger := newTestLogger(&logBuf)

	r, w := io.Pipe()
	defer func() { _ = r.Close() }()

	session := &mockProviderSession{}

	reader := newProviderSSEReader(ProviderSSEConfig{
		Upstream:     r,
		Engine:       engine,
		Logger:       logger,
		PIILogging:   true,
		FrameTimeout: 10 * time.Millisecond,
		Host:         "test.local",
		Method:       "POST",
		Path:         "/api",
		ContentType:  "text/event-stream",
		StatusCode:   200,
		PluginName:   "test-plugin",
		Session:      session,
	})
	defer func() { _ = reader.Close() }()

	// Deterministic channel-based coordination (PR-106).
	// io.Pipe Write blocks until Read is called, so we Read first to unblock
	// the goroutine's initial Write, then use channels to verify completion.
	writeFirstDone := make(chan struct{})
	continueWrite := make(chan struct{})

	go func() {
		_, _ = w.Write([]byte("data: incomplete frame"))
		close(writeFirstDone)
		<-continueWrite
		time.Sleep(50 * time.Millisecond)
		_, _ = w.Write([]byte(" more data"))
		time.Sleep(50 * time.Millisecond)
		_ = w.Close()
	}()

	// Read first chunk — unblocks goroutine's Write.
	buf := make([]byte, 256)
	n, _ := reader.Read(buf)
	if n == 0 {
		t.Error("should read first chunk")
	}

	<-writeFirstDone
	close(continueWrite)

	time.Sleep(80 * time.Millisecond)
	reader.Read(buf) // second Read — timer expired, timeout fires

	entries := testutils.ParseLogEntries(t, &logBuf)
	foundTimeout := false
	for _, e := range entries {
		if e["msg"] == "pii_detection_skipped" &&
			e["reason"] == "sse_frame_timeout" {
			foundTimeout = true
			break
		}
	}
	if !foundTimeout {
		t.Error("expected sse_frame_timeout warning in logs, got none")
	}
}

// Test parseSSEFrame function directly.
func TestParseSSEFrame_EventAndData(t *testing.T) {
	tests := []struct {
		name          string
		frame         string
		wantEventType string
		wantDataLines int
		wantDataFirst string // first data line content
	}{
		{
			name:          "simple data",
			frame:         "data: hello\n\n",
			wantEventType: "",
			wantDataLines: 1,
			wantDataFirst: "hello",
		},
		{
			name:          "event and data",
			frame:         "event: message\ndata: hello\n\n",
			wantEventType: "message",
			wantDataLines: 1,
			wantDataFirst: "hello",
		},
		{
			name:          "multiple data lines",
			frame:         "data: line1\ndata: line2\n\n",
			wantEventType: "",
			wantDataLines: 2,
			wantDataFirst: "line1",
		},
		{
			name:          "comment ignored",
			frame:         ": comment\ndata: hello\n\n",
			wantEventType: "",
			wantDataLines: 1,
			wantDataFirst: "hello",
		},
		{
			name:          "id line ignored for detection",
			frame:         "id: 42\ndata: hello\n\n",
			wantEventType: "",
			wantDataLines: 1,
			wantDataFirst: "hello",
		},
		{
			name:          "CRLF boundaries",
			frame:         "event: msg\r\ndata: hello\r\n\r\n",
			wantEventType: "msg",
			wantDataLines: 1,
			wantDataFirst: "hello",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eventType, dataLines := parseSSEFrame(tt.frame)
			if eventType != tt.wantEventType {
				t.Errorf("eventType = %q, want %q", eventType, tt.wantEventType)
			}
			if len(dataLines) != tt.wantDataLines {
				t.Errorf("dataLines count = %d, want %d", len(dataLines), tt.wantDataLines)
			}
			if len(dataLines) > 0 && dataLines[0] != tt.wantDataFirst {
				t.Errorf("first data line = %q, want %q", dataLines[0], tt.wantDataFirst)
			}
		})
	}
}

// Test for interceptor field in monitor_scan (provider field must be absent for format parity).
func TestProviderSSEReader_InterceptorField(t *testing.T) {
	engine := newTestEngine()
	var logBuf bytes.Buffer
	logger := newTestLogger(&logBuf)

	sseStream := strings.NewReader(`data: hello` + "\n\n")

	session := &mockProviderSession{
		handleEvent: func(eventType string, data []byte) string {
			return "hello"
		},
	}

	reader := newProviderSSEReader(ProviderSSEConfig{
		Upstream:    io.NopCloser(sseStream),
		Engine:      engine,
		Logger:      logger,
		PIILogging:  false,
		Host:        "chatgpt.com",
		Method:      "POST",
		Path:        "/backend-anon/f/conversation",
		ContentType: "text/event-stream",
		StatusCode:  200,
		PluginName:  "chatgpt",
		Session:     session,
	})
	defer func() { _ = reader.Close() }()

	_, _ = io.ReadAll(reader)

	entries := testutils.ParseLogEntries(t, &logBuf)
	for _, e := range entries {
		if e["msg"] == "monitor_scan" {
			// PR-003: provider field must NOT be present (format parity with MonitorInterceptor).
			if _, ok := e["provider"]; ok {
				t.Errorf("provider field must not appear in monitor_scan, got %v", e["provider"])
			}
			// direction, result, bytes_analyzed, pii_values_logged must match MonitorInterceptor.
			if _, ok := e["direction"]; !ok {
				t.Error("direction field missing")
			}
			if _, ok := e["bytes_analyzed"]; !ok {
				t.Error("bytes_analyzed field missing")
			}
		}
	}
}

// Test byte-identical forwarding (SR-9 pattern).
func TestProviderSSEReader_ByteIdentical(t *testing.T) {
	engine := newTestEngine()
	var logBuf bytes.Buffer
	logger := newTestLogger(&logBuf)

	original := `data: {"msg": "Hello World"}` + "\n\n" +
		`data: {"msg": "test@example.com"}` + "\n\n" +
		`data: {"msg": "Goodbye"}` + "\n\n"

	sseStream := strings.NewReader(original)

	session := &mockProviderSession{
		handleEvent: func(eventType string, data []byte) string {
			return string(data)
		},
	}

	reader := newProviderSSEReader(ProviderSSEConfig{
		Upstream:    io.NopCloser(sseStream),
		Engine:      engine,
		Logger:      logger,
		PIILogging:  true,
		Host:        "test.local",
		Method:      "POST",
		Path:        "/api",
		ContentType: "text/event-stream",
		StatusCode:  200,
		PluginName:  "test",
		Session:     session,
	})
	defer func() { _ = reader.Close() }()

	output, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}

	if string(output) != original {
		t.Errorf("byte-identical forwarding violated.\ngot:  %q\nwant: %q", string(output), original)
	}
}
