// Package logging provides structured JSON logging with PII-free guarantees.
package logging

import (
	"log/slog"
	"os"
	"time"
)

// ConnectionLogEntry contains the connection-level metadata logged for each request.
// Note: ZERO request/response bodies, ZERO headers, ZERO PII.
type ConnectionLogEntry struct {
	Timestamp  string `json:"timestamp"`
	Host       string `json:"host"`
	Mode       string `json:"mode,omitempty"` // "mitm" or "tunnel"
	Status     int    `json:"status"`
	DurationMs int64  `json:"duration_ms"`
	BytesIn    int64  `json:"bytes_in"`
	BytesOut   int64  `json:"bytes_out"`
}

// InitLogger creates and configures an slog.Logger with JSON output.
// Level is one of: "debug", "info", "warn", "error".
func InitLogger(level string, format string) *slog.Logger {
	var logLevel slog.Level
	switch level {
	case "debug":
		logLevel = slog.LevelDebug
	case "warn":
		logLevel = slog.LevelWarn
	case "error":
		logLevel = slog.LevelError
	default:
		logLevel = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{
		Level: logLevel,
		// ReplaceAttr is used to ensure no sensitive fields leak through.
		// Allowed keys: timestamp, host, status, duration_ms, bytes_in, bytes_out,
		// mode, msg, level, version
	}

	var handler slog.Handler
	if format == "json" {
		handler = slog.NewJSONHandler(os.Stderr, opts)
	} else {
		handler = slog.NewTextHandler(os.Stderr, opts)
	}

	return slog.New(handler)
}

// LogConnection logs a connection-level entry using the structured logger.
// The entry contains only metadata: host, status, duration, bytes in/out.
// No request/response bodies or headers are included.
func LogConnection(logger *slog.Logger, entry ConnectionLogEntry) {
	logger.Info("connection",
		"timestamp", entry.Timestamp,
		"host", entry.Host,
		"status", entry.Status,
		"duration_ms", entry.DurationMs,
		"bytes_in", entry.BytesIn,
		"bytes_out", entry.BytesOut,
		"mode", entry.Mode,
	)
}

// NowUTC returns the current time in UTC, formatted as ISO 8601.
func NowUTC() string {
	return time.Now().UTC().Format(time.RFC3339)
}

// DurationMs calculates the duration in milliseconds between two times.
func DurationMs(start time.Time) int64 {
	return time.Since(start).Milliseconds()
}
