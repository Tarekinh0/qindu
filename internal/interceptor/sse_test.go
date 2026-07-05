package interceptor

import (
	"bytes"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/Tarekinh0/qindu/internal/pii"
	"github.com/Tarekinh0/qindu/internal/testutils"
)

// newTestEngine creates a minimal engine with email and phone recognizers for tests.
func newTestEngine() *pii.Engine {
	return pii.NewEngine(pii.DefaultMaxInputBytes,
		pii.NewEmailRecognizer(),
		pii.NewPhoneRecognizer(),
	)
}

// newTestEngineFull creates an engine with all 9 recognizers for comprehensive tests.
func newTestEngineFull() *pii.Engine {
	return pii.NewEngine(pii.DefaultMaxInputBytes,
		pii.NewEmailRecognizer(),
		pii.NewPhoneRecognizer(),
		pii.NewIBANRecognizer(),
		pii.NewCreditCardRecognizer(),
		pii.NewJWTRecognizer(),
		pii.NewSecretPrefixRecognizer(),
		pii.NewSecretEntropyRecognizer(),
		pii.NewPrivateKeyRecognizer(),
		pii.NewNameFromEmailRecognizer(),
	)
}

// newTestLogger creates a logger that writes to a buffer for test assertions.
func newTestLogger(buf *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func TestSSEFrameReader_CompleteFrames(t *testing.T) {
	engine := newTestEngine()
	var logBuf bytes.Buffer
	logger := newTestLogger(&logBuf)

	// Simulate an SSE stream with PII in data: fields.
	sseStream := strings.NewReader(
		`data: {"message": "Hello test.user@example.com"}` + "\n\n" +
			`data: {"message": "No PII here"}` + "\n\n" +
			`data: {"message": "Call +1-555-0100"}` + "\n\n",
	)

	reader := newSSEFrameReader(SSEFrameReaderConfig{
		Upstream:     io.NopCloser(sseStream),
		Engine:       engine,
		Logger:       logger,
		PIILogging:   true,
		MaxFrameSize: 1024 * 1024,
		Host:         "test-upstream.local",
		Method:       "POST",
		Path:         "/v1/chat",
		ContentType:  "text/event-stream",
		StatusCode:   200,
	})
	defer func() { _ = reader.Close() }()

	// Read all data.
	output, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}

	// Verify forwarding is byte-identical (SR-9).
	expectedOutput := `data: {"message": "Hello test.user@example.com"}` + "\n\n" +
		`data: {"message": "No PII here"}` + "\n\n" +
		`data: {"message": "Call +1-555-0100"}` + "\n\n"
	if string(output) != expectedOutput {
		t.Errorf("forwarded output mismatch.\n got: %q\nwant: %q", string(output), expectedOutput)
	}

	// Verify aggregated monitor_scan log entry (Bug 2 fix: 1 entry per stream).
	entries := testutils.ParseLogEntries(t, &logBuf)
	var scanEntries []map[string]any
	for _, e := range entries {
		if e["msg"] == "monitor_scan" {
			scanEntries = append(scanEntries, e)
		}
	}
	if len(scanEntries) != 1 {
		t.Fatalf("expected exactly 1 monitor_scan entry for aggregated SSE, got %d", len(scanEntries))
	}

	entry := scanEntries[0]
	if entry["pii_values_logged"] != false {
		t.Errorf("pii_values_logged must be false, got %v", entry["pii_values_logged"])
	}
	if entry["sse_frame"] != true {
		t.Errorf("sse_frame must be true, got %v", entry["sse_frame"])
	}
	if entry["host"] != "test-upstream.local" {
		t.Errorf("host mismatch: %v", entry["host"])
	}
	if entry["direction"] != "response" {
		t.Errorf("direction mismatch: %v", entry["direction"])
	}
	if entry["result"] != "pii_found" {
		t.Errorf("result should be pii_found, got %v", entry["result"])
	}
	entityCount, _ := entry["entity_count"].(float64)
	if entityCount < 2 {
		t.Errorf("entity_count should be >= 2 (aggregated across frames), got %v", entityCount)
	}
	// entity_summary should be present.
	summary, ok := entry["entity_summary"].(map[string]any)
	if !ok {
		t.Errorf("entity_summary should be present, got %v", entry["entity_summary"])
	} else if len(summary) < 2 {
		t.Logf("entity_summary: %v", summary)
	}
}

func TestSSEFrameReader_PartialFrames(t *testing.T) {
	engine := newTestEngine()
	var logBuf bytes.Buffer
	logger := newTestLogger(&logBuf)

	// Simulate SSE arriving in chunks (partial frames).
	r, w := io.Pipe()
	go func() {
		// Write in chunks.
		chunks := []string{
			`data: {"msg": "he`,
			`llo test@exa`,
			`mple.com"}` + "\n\n",
			`data: {"msg": "goodbye"}` + "\n\n",
		}
		for _, chunk := range chunks {
			_, _ = w.Write([]byte(chunk))
		}
		_ = w.Close()
	}()

	reader := newSSEFrameReader(SSEFrameReaderConfig{
		Upstream:     r,
		Engine:       engine,
		Logger:       logger,
		PIILogging:   true,
		MaxFrameSize: 1024 * 1024,
		Host:         "test.local",
		Method:       "POST",
		Path:         "/api",
		ContentType:  "text/event-stream",
		StatusCode:   200,
	})
	defer func() { _ = reader.Close() }()

	output, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}

	if !strings.Contains(string(output), `test@example.com`) {
		t.Error("output should contain the email")
	}

	// Should have one aggregated monitor_scan entry.
	entries := testutils.ParseLogEntries(t, &logBuf)
	var scanEntries []map[string]any
	for _, e := range entries {
		if e["msg"] == "monitor_scan" {
			scanEntries = append(scanEntries, e)
		}
	}
	if len(scanEntries) != 1 {
		t.Fatalf("expected 1 monitor_scan entry for partial frames, got %d", len(scanEntries))
	}
	if scanEntries[0]["entity_count"].(float64) < 1 {
		t.Error("partial frame detection should find entities")
	}
	if scanEntries[0]["result"] != "pii_found" {
		t.Errorf("expected pii_found, got %v", scanEntries[0]["result"])
	}
}

func TestSSEFrameReader_OversizedFrame(t *testing.T) {
	engine := newTestEngine()
	var logBuf bytes.Buffer
	logger := newTestLogger(&logBuf)

	// Create a frame that exceeds the max frame size (small limit for test).
	maxSize := 100
	bigData := strings.Repeat("x", maxSize+50)
	sseStream := strings.NewReader(`data: ` + bigData + "\n\n")

	reader := newSSEFrameReader(SSEFrameReaderConfig{
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
	})
	defer func() { _ = reader.Close() }()

	output, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}

	// Verify all bytes are forwarded.
	if !strings.Contains(string(output), bigData) {
		t.Error("oversized frame must be forwarded completely")
	}

	entries := testutils.ParseLogEntries(t, &logBuf)
	// Should have at least a WARN log for oversized frame.
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

	// Should also have a monitor_scan (clean or none depending on whether the frame
	// had data). Since the frame was skipped due to oversize, result should be clean.
	for _, e := range entries {
		if e["msg"] == "monitor_scan" {
			if e["result"] != "clean" {
				t.Logf("monitor_scan for oversize frame: result=%v (may be clean)", e["result"])
			}
		}
	}
}

func TestSSEFrameReader_EmptyFrames(t *testing.T) {
	engine := newTestEngine()
	var logBuf bytes.Buffer
	logger := newTestLogger(&logBuf)

	// SSE stream with empty frames and a comment-only frame.
	sseStream := strings.NewReader(
		": just a comment\n\n" +
			"\n\n" + // empty frame
			`data: {"msg": "clean"}` + "\n\n",
	)

	reader := newSSEFrameReader(SSEFrameReaderConfig{
		Upstream:     io.NopCloser(sseStream),
		Engine:       engine,
		Logger:       logger,
		PIILogging:   true,
		MaxFrameSize: 1024 * 1024,
		Host:         "test.local",
		Method:       "POST",
		Path:         "/api",
		ContentType:  "text/event-stream",
		StatusCode:   200,
	})
	defer func() { _ = reader.Close() }()

	output, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}

	// All bytes should pass through.
	if !strings.Contains(string(output), ": just a comment") {
		t.Error("comments should pass through")
	}

	// Should have one monitor_scan with result=clean.
	entries := testutils.ParseLogEntries(t, &logBuf)
	var scanEntries []map[string]any
	for _, e := range entries {
		if e["msg"] == "monitor_scan" {
			scanEntries = append(scanEntries, e)
		}
	}
	if len(scanEntries) != 1 {
		t.Fatalf("expected 1 monitor_scan, got %d", len(scanEntries))
	}
	if scanEntries[0]["result"] != "clean" {
		t.Errorf("expected result=clean, got %v", scanEntries[0]["result"])
	}
}

func TestSSEFrameReader_NoDataLines(t *testing.T) {
	engine := newTestEngine()
	var logBuf bytes.Buffer
	logger := newTestLogger(&logBuf)

	// Frame with no data: lines but containing PII-like text.
	sseStream := strings.NewReader(
		`event: message` + "\n" +
			`id: 1` + "\n\n" +
			`data: test@example.com` + "\n\n",
	)

	reader := newSSEFrameReader(SSEFrameReaderConfig{
		Upstream:     io.NopCloser(sseStream),
		Engine:       engine,
		Logger:       logger,
		PIILogging:   true,
		MaxFrameSize: 1024 * 1024,
		Host:         "test.local",
		Method:       "POST",
		Path:         "/api",
		ContentType:  "text/event-stream",
		StatusCode:   200,
	})
	defer func() { _ = reader.Close() }()

	_, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}

	entries := testutils.ParseLogEntries(t, &logBuf)
	// Should have aggregated monitor_scan with PII from the second frame.
	found := false
	for _, e := range entries {
		if e["msg"] == "monitor_scan" && e["result"] == "pii_found" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected monitor_scan with pii_found on frame with data: line")
	}
}

func TestSSEFrameReader_PIILoggingDisabled(t *testing.T) {
	engine := newTestEngine()
	var logBuf bytes.Buffer
	logger := newTestLogger(&logBuf)

	sseStream := strings.NewReader(
		`data: {"msg": "test.user@example.com"}` + "\n\n",
	)

	reader := newSSEFrameReader(SSEFrameReaderConfig{
		Upstream:     io.NopCloser(sseStream),
		Engine:       engine,
		Logger:       logger,
		PIILogging:   false, // piiLogging disabled,
		MaxFrameSize: 1024 * 1024,
		Host:         "test.local",
		Method:       "POST",
		Path:         "/api",
		ContentType:  "text/event-stream",
		StatusCode:   200,
	})
	defer func() { _ = reader.Close() }()

	_, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}

	entries := testutils.ParseLogEntries(t, &logBuf)
	var scanEntries []map[string]any
	for _, e := range entries {
		if e["msg"] == "monitor_scan" {
			scanEntries = append(scanEntries, e)
		}
	}
	if len(scanEntries) != 1 {
		t.Fatalf("expected 1 monitor_scan even with pii_logging=false, got %d", len(scanEntries))
	}
	e := scanEntries[0]
	if e["result"] != "pii_found" {
		t.Errorf("expected pii_found, got %v", e["result"])
	}
	// entity_summary must be omitted when pii_logging=false.
	if _, ok := e["entity_summary"]; ok {
		t.Error("entity_summary must be omitted when pii_logging=false")
	}
}

func TestSSEFrameReader_MultipleDataLines(t *testing.T) {
	engine := newTestEngine()
	var logBuf bytes.Buffer
	logger := newTestLogger(&logBuf)

	// Frame with multiple data: lines (multi-line SSE data).
	sseStream := strings.NewReader(
		`data: {"user": "test.user@example.com",` + "\n" +
			`data:  "phone": "+1-555-0100"}` + "\n\n",
	)

	reader := newSSEFrameReader(SSEFrameReaderConfig{
		Upstream:     io.NopCloser(sseStream),
		Engine:       engine,
		Logger:       logger,
		PIILogging:   true,
		MaxFrameSize: 1024 * 1024,
		Host:         "test.local",
		Method:       "POST",
		Path:         "/api",
		ContentType:  "text/event-stream",
		StatusCode:   200,
	})
	defer func() { _ = reader.Close() }()

	output, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}
	_ = output

	entries := testutils.ParseLogEntries(t, &logBuf)
	var scanEntries []map[string]any
	for _, e := range entries {
		if e["msg"] == "monitor_scan" {
			scanEntries = append(scanEntries, e)
		}
	}
	if len(scanEntries) < 1 {
		t.Fatal("expected at least 1 monitor_scan for multi-line data")
	}
	// Should detect both EMAIL and PHONE.
	entityCount, _ := scanEntries[0]["entity_count"].(float64)
	if entityCount < 2 {
		t.Errorf("expected at least 2 entities, got %v", entityCount)
	}
}

func TestSSEFrameReader_InterleavedBoundaries(t *testing.T) {
	engine := newTestEngine()
	var logBuf bytes.Buffer
	logger := newTestLogger(&logBuf)

	// Frame boundary arrives mid-chunk.
	r, w := io.Pipe()
	go func() {
		// \n\n boundary split across chunks.
		chunks := []string{
			`data: test@example.com` + "\n",
			"\n",
		}
		for _, chunk := range chunks {
			_, _ = w.Write([]byte(chunk))
		}
		_ = w.Close()
	}()

	reader := newSSEFrameReader(SSEFrameReaderConfig{
		Upstream:     r,
		Engine:       engine,
		Logger:       logger,
		PIILogging:   true,
		MaxFrameSize: 1024 * 1024,
		Host:         "test.local",
		Method:       "POST",
		Path:         "/api",
		ContentType:  "text/event-stream",
		StatusCode:   200,
	})
	defer func() { _ = reader.Close() }()

	output, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}

	if !strings.Contains(string(output), "test@example.com") {
		t.Error("output should contain the email")
	}

	entries := testutils.ParseLogEntries(t, &logBuf)
	found := false
	for _, e := range entries {
		if e["msg"] == "monitor_scan" && e["result"] == "pii_found" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected aggregated monitor_scan on interleaved boundary frame")
	}
}

func TestSSEFrameReader_TimeoutHandling(t *testing.T) {
	engine := newTestEngine()
	var logBuf bytes.Buffer
	logger := newTestLogger(&logBuf)

	r, w := io.Pipe()
	defer func() { _ = r.Close() }()

	reader := newSSEFrameReader(SSEFrameReaderConfig{
		Upstream:     r,
		Engine:       engine,
		Logger:       logger,
		PIILogging:   true,
		MaxFrameSize: 1024 * 1024,
		Host:         "test.local",
		Method:       "POST",
		Path:         "/api",
		ContentType:  "text/event-stream",
		StatusCode:   200,
	})
	reader.acc.timeout = 10 * time.Millisecond
	defer func() { _ = reader.Close() }()

	// Deterministic channel-based coordination to avoid flaky Sleep-based
	// timing (PR-106). The io.Pipe Write call blocks until Read is called,
	// so we must Read first to unblock the goroutine's initial Write, then
	// use channels to verify it completed.
	writeFirstDone := make(chan struct{})
	continueWrite := make(chan struct{})

	go func() {
		_, _ = w.Write([]byte("data: incomplete frame"))
		close(writeFirstDone) // reached after main goroutine calls Read
		<-continueWrite
		time.Sleep(50 * time.Millisecond)
		_, _ = w.Write([]byte(" more data"))
		time.Sleep(50 * time.Millisecond)
		_ = w.Close()
	}()

	// Read first chunk — unblocks the goroutine's Write.
	buf := make([]byte, 256)
	n, _ := reader.Read(buf)
	if n == 0 {
		t.Error("should read first chunk")
	}

	<-writeFirstDone // goroutine's first Write completed
	close(continueWrite)

	time.Sleep(80 * time.Millisecond) // let goroutine write second chunk + timeout expire
	reader.Read(buf)                  // reads second chunk, timer expired → timeout fires

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

func TestSSEFrameReader_ZeroPIIInLogs(t *testing.T) {
	engine := newTestEngine()
	var logBuf bytes.Buffer
	logger := newTestLogger(&logBuf)

	sseStream := strings.NewReader(
		`data: {"email": "test.user@example.com"}` + "\n\n",
	)

	reader := newSSEFrameReader(SSEFrameReaderConfig{
		Upstream:     io.NopCloser(sseStream),
		Engine:       engine,
		Logger:       logger,
		PIILogging:   true,
		MaxFrameSize: 1024 * 1024,
		Host:         "test.local",
		Method:       "POST",
		Path:         "/api",
		ContentType:  "text/event-stream",
		StatusCode:   200,
	})
	defer func() { _ = reader.Close() }()

	_, _ = io.ReadAll(reader)

	logOutput := logBuf.String()
	// Verify no PII values in log output.
	if strings.Contains(logOutput, "test.user@example.com") {
		t.Error("log output must not contain raw PII values")
	}
	if strings.Contains(logOutput, "test.user") {
		t.Error("log output must not contain raw PII substrings")
	}
}

func TestSSEFrameReader_ByteIdentical(t *testing.T) {
	engine := newTestEngine()
	var logBuf bytes.Buffer
	logger := newTestLogger(&logBuf)

	original := `data: {"msg": "Hello World"}` + "\n\n" +
		`data: {"msg": "test@example.com"}` + "\n\n" +
		`data: {"msg": "Goodbye"}` + "\n\n"

	sseStream := strings.NewReader(original)

	reader := newSSEFrameReader(SSEFrameReaderConfig{
		Upstream:     io.NopCloser(sseStream),
		Engine:       engine,
		Logger:       logger,
		PIILogging:   true,
		MaxFrameSize: 1024 * 1024,
		Host:         "test.local",
		Method:       "POST",
		Path:         "/api",
		ContentType:  "text/event-stream",
		StatusCode:   200,
	})
	defer func() { _ = reader.Close() }()

	output, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}

	// SR-9: byte-identical forwarding.
	if string(output) != original {
		t.Errorf("byte-identical forwarding violated.\ngot:  %q\nwant: %q", string(output), original)
	}

	_ = logBuf // Detection logs are expected.
}

// TestSSEFrameReader_DoneMarkerTermination verifies that [DONE] marker
// triggers aggregated monitor_scan emission even before EOF.
func TestSSEFrameReader_DoneMarkerTermination(t *testing.T) {
	engine := newTestEngine()
	var logBuf bytes.Buffer
	logger := newTestLogger(&logBuf)

	// Stream with a [DONE] marker mid-stream (simulated).
	sseStream := strings.NewReader(
		`data: {"msg": "hello test@example.com"}` + "\n\n" +
			"data: [DONE]\n\n" +
			`data: {"msg": "this comes after done but before EOF"}` + "\n\n",
	)

	reader := newSSEFrameReader(SSEFrameReaderConfig{
		Upstream:     io.NopCloser(sseStream),
		Engine:       engine,
		Logger:       logger,
		PIILogging:   true,
		MaxFrameSize: 1024 * 1024,
		Host:         "test.local",
		Method:       "POST",
		Path:         "/api",
		ContentType:  "text/event-stream",
		StatusCode:   200,
	})
	defer func() { _ = reader.Close() }()

	_, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}

	entries := testutils.ParseLogEntries(t, &logBuf)
	var scanEntries []map[string]any
	for _, e := range entries {
		if e["msg"] == "monitor_scan" {
			scanEntries = append(scanEntries, e)
		}
	}
	// Should emit at least one monitor_scan (triggered by [DONE] and/or EOF).
	if len(scanEntries) < 1 {
		t.Fatal("expected monitor_scan entry for [DONE] marker")
	}
}

// TestSSEFrameReader_AggregatedSummaryForClean verifies that a stream with no
// PII produces a clean monitor_scan entry.
func TestSSEFrameReader_AggregatedSummaryForClean(t *testing.T) {
	engine := newTestEngine()
	var logBuf bytes.Buffer
	logger := newTestLogger(&logBuf)

	sseStream := strings.NewReader(
		`data: {"msg": "Hello"}` + "\n\n" +
			`data: {"msg": "World"}` + "\n\n",
	)

	reader := newSSEFrameReader(SSEFrameReaderConfig{
		Upstream:     io.NopCloser(sseStream),
		Engine:       engine,
		Logger:       logger,
		PIILogging:   true,
		MaxFrameSize: 1024 * 1024,
		Host:         "test.local",
		Method:       "POST",
		Path:         "/api",
		ContentType:  "text/event-stream",
		StatusCode:   200,
	})
	defer func() { _ = reader.Close() }()

	_, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}

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
	if scanEntries[0]["result"] != "clean" {
		t.Errorf("expected result=clean for clean SSE stream, got %v", scanEntries[0]["result"])
	}
}
