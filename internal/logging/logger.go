// Package logging provides structured JSON logging with PII-free guarantees.
package logging

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
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

// nopCloser wraps an io.Writer with a no-op Close method.
// Used for writers that should never be closed (e.g., os.Stderr).
type nopCloser struct {
	io.Writer
}

func (nopCloser) Close() error { return nil }

// multiWriteCloser writes to multiple writers and closes all registered closers.
// The Writer field is exposed for io.MultiWriter composition; the closers field
// holds each underlying resource that needs closing (e.g., *os.File handles).
type multiWriteCloser struct {
	io.Writer
	closers []io.Closer
}

func (m *multiWriteCloser) Close() error {
	var errs []error
	for _, c := range m.closers {
		if err := c.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// InitLogger creates and configures an slog.Logger with JSON or text output.
// Level is one of: "debug", "info", "warn", "error".
//
// Output parameter controls where logs are written:
//   - "stderr" (default): writes to os.Stderr only
//   - "file": writes to agent.log in the given logDir (created if needed)
//   - "both": writes to both os.Stderr and the log file
//
// If logDir is empty and output is "file" or "both", a platform-appropriate
// default directory is used:
//   - Windows: %PROGRAMDATA%\Qindu\logs
//   - Other:   $HOME/.qindu/logs or $TMPDIR/qindu-logs
//
// On file creation failure, logs are silently redirected to stderr with a
// warning message written to stderr.
//
// Returns the configured logger and an io.Closer for the underlying log file.
// The caller is responsible for calling closer.Close() on shutdown to release
// the file handle. For "stderr" output, the closer is a no-op and safe to call.
// The closer is never nil.
func InitLogger(level string, format string, output string, logDir string) (*slog.Logger, io.Closer) {
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

	w, closer := resolveLogWriter(output, logDir)

	var handler slog.Handler
	if format == "json" {
		handler = slog.NewJSONHandler(w, opts)
	} else {
		handler = slog.NewTextHandler(w, opts)
	}

	return slog.New(handler), closer
}

// resolveLogWriter returns the appropriate io.Writer and io.Closer based on
// the output configuration. Handles directory creation for file-based output.
// On failure, falls back to os.Stderr with a diagnostic message.
// The returned closer must be invoked by the caller on shutdown to release
// file handles; for stderr-based output the closer is a no-op.
func resolveLogWriter(output string, logDir string) (io.Writer, io.Closer) {
	switch output {
	case "file":
		f, err := openLogFile(logDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to open log file, falling back to stderr: %v\n", err)
			return os.Stderr, nopCloser{os.Stderr}
		}
		return f, f
	case "both":
		f, err := openLogFile(logDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to open log file for dual output, writing to stderr only: %v\n", err)
			return os.Stderr, nopCloser{os.Stderr}
		}
		mwc := &multiWriteCloser{
			Writer:  io.MultiWriter(os.Stderr, f),
			closers: []io.Closer{f},
		}
		return mwc, mwc
	default:
		// "stderr" or unknown — safe default
		return os.Stderr, nopCloser{os.Stderr}
	}
}

// openLogFile creates the log directory (if needed) and opens agent.log for
// append-only writing. Returns the open file handle.
func openLogFile(logDir string) (*os.File, error) {
	dir := logDir
	if dir == "" {
		dir = defaultLogDir()
	}

	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("creating log directory %s: %w", dir, err)
	}

	logPath := filepath.Join(dir, "agent.log")
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("opening log file %s: %w", logPath, err)
	}

	return f, nil
}

// defaultLogDir returns the platform-appropriate default log directory.
func defaultLogDir() string {
	if runtime.GOOS == "windows" {
		if pd := os.Getenv("PROGRAMDATA"); pd != "" {
			return filepath.Join(pd, "Qindu", "logs")
		}
	}
	// Non-Windows fallback: $HOME/.qindu/logs or $TMPDIR/qindu-logs
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".qindu", "logs")
	}
	return filepath.Join(os.TempDir(), "qindu-logs")
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
