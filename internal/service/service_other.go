//go:build !windows

package service

import (
	"fmt"
	"log/slog"
	"net/http"
)

// RunService is a no-op on non-Windows platforms.
func RunService(name string, server *http.Server, logger *slog.Logger) error {
	_ = name
	_ = server
	_ = logger
	return fmt.Errorf("windows service not available on this platform")
}

// IsServiceSession always returns false on non-Windows platforms.
func IsServiceSession() (bool, error) {
	return false, nil
}
