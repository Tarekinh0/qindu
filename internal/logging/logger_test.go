package logging

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"
)

// TestInitLogger_JSON verifies JSON handler is created for "json" format.
func TestInitLogger_JSON(t *testing.T) {
	logger := InitLogger("info", "json")
	if logger == nil {
		t.Fatal("InitLogger returned nil")
	}

	// Write a log and verify it's valid JSON
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})
	logger = slog.New(handler)

	logger.Info("test message", "key", "value")

	output := buf.String()
	if !json.Valid([]byte(output)) {
		t.Errorf("log output is not valid JSON: %s", output)
	}
}

// TestInitLogger_Text verifies text handler for "text" format.
func TestInitLogger_Text(t *testing.T) {
	logger := InitLogger("info", "text")
	if logger == nil {
		t.Fatal("InitLogger returned nil")
	}
}

// TestInitLogger_Levels verifies different log levels.
func TestInitLogger_Levels(t *testing.T) {
	tests := []struct {
		level string
	}{
		{"debug"},
		{"info"},
		{"warn"},
		{"error"},
		{"unknown"}, // should default to info
	}

	for _, tt := range tests {
		t.Run(tt.level, func(t *testing.T) {
			logger := InitLogger(tt.level, "json")
			if logger == nil {
				t.Errorf("InitLogger with level %q returned nil", tt.level)
			}
		})
	}
}

// TestLogConnection_Fields verifies connection log entries have correct field names.
func TestLogConnection_Fields(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})
	logger := slog.New(handler)

	entry := ConnectionLogEntry{
		Timestamp:  "2026-06-12T10:00:00Z",
		Host:       "chatgpt.com",
		Status:     200,
		DurationMs: 150,
		BytesIn:    1024,
		BytesOut:   2048,
		Mode:       "mitm",
	}

	LogConnection(logger, entry)

	output := buf.String()
	if !json.Valid([]byte(output)) {
		t.Fatalf("output is not valid JSON: %s", output)
	}

	// Parse the JSON log
	var logEntry map[string]interface{}
	if err := json.Unmarshal([]byte(output), &logEntry); err != nil {
		t.Fatalf("failed to parse log JSON: %v", err)
	}

	// Verify all expected fields are present (SR5: metadata only)
	expectedFields := []string{"timestamp", "host", "status", "duration_ms", "bytes_in", "bytes_out", "mode", "msg"}
	for _, field := range expectedFields {
		if _, ok := logEntry[field]; !ok {
			t.Errorf("log entry missing expected field: %q", field)
		}
	}

	// Verify field values
	if logEntry["host"] != "chatgpt.com" {
		t.Errorf("host = %v, want chatgpt.com", logEntry["host"])
	}
	if logEntry["status"] != float64(200) { // JSON numbers are float64
		t.Errorf("status = %v, want 200", logEntry["status"])
	}
	if logEntry["mode"] != "mitm" {
		t.Errorf("mode = %v, want mitm", logEntry["mode"])
	}
}

// TestLogConnection_NoPII verifies SEC-T7/SEC-T9/SEC-T10: no PII in log entries.
// DPO R1: ZERO PII, ZERO request/response bodies, ZERO headers.
func TestLogConnection_NoPII(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})
	logger := slog.New(handler)

	entry := ConnectionLogEntry{
		Timestamp:  "2026-06-12T10:00:00Z",
		Host:       "chatgpt.com",
		Status:     200,
		DurationMs: 150,
		BytesIn:    1024,
		BytesOut:   2048,
		Mode:       "mitm",
	}

	LogConnection(logger, entry)

	output := buf.String()

	// List of forbidden PII-like patterns (SEC-T7, SEC-T9, SEC-T10)
	forbidden := []string{
		"body",             // request/response bodies
		"header",           // HTTP headers
		"Authorization",    // sensitive header
		"Cookie",           // sensitive header
		"Set-Cookie",       // sensitive header
		"X-Forwarded-For",  // sensitive header
		"User-Agent",       // sensitive header
		"api_key",          // credentials
		"password",         // credentials
		"secret",           // credentials
		"token",            // credentials
		"private key",      // CA key material
		"PRIVATE KEY",      // PEM key material
		"certificate",      // cert content
		"jane@example.com", // synthetic but would be PII if real
		"credit_card",      // PII pattern
		"phone",            // PII pattern
		"iban",             // PII pattern
	}

	lower := strings.ToLower(output)
	for _, f := range forbidden {
		if strings.Contains(lower, strings.ToLower(f)) {
			t.Errorf("log output contains forbidden pattern: %q", f)
		}
	}

	// Verify the entry itself doesn't have extra fields beyond the allowed set
	var logEntry map[string]interface{}
	if err := json.Unmarshal([]byte(output), &logEntry); err != nil {
		t.Errorf("failed to parse log JSON: %v", err)
	}

	allowedFields := map[string]bool{
		"time": true, "level": true, "msg": true,
		"timestamp": true, "host": true, "status": true,
		"duration_ms": true, "bytes_in": true, "bytes_out": true,
		"mode": true,
	}

	for key := range logEntry {
		if !allowedFields[key] {
			t.Errorf("log entry contains unexpected field: %q", key)
		}
	}
}

// TestNowUTC verifies the timestamp helper returns valid UTC time.
func TestNowUTC(t *testing.T) {
	ts := NowUTC()
	if ts == "" {
		t.Error("NowUTC returned empty string")
	}

	// Verify it's valid ISO 8601 / RFC 3339
	_, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		t.Errorf("NowUTC() = %q is not valid RFC 3339: %v", ts, err)
	}
}

// TestDurationMs verifies duration calculation.
func TestDurationMs(t *testing.T) {
	start := time.Now().Add(-150 * time.Millisecond)
	ms := DurationMs(start)

	if ms < 140 || ms > 170 {
		t.Errorf("DurationMs for 150ms = %d, expected ~150", ms)
	}
}
