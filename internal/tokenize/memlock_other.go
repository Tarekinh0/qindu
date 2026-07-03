//go:build !linux && !windows

package tokenize

import "log/slog"

// initLockedArena is a no-op fallback for unsupported platforms.
// Memory locking is not available; the token↔PII mapping may be written to swap.
func initLockedArena(logger *slog.Logger) *piiArena {
	logger.Warn("memory locking not available on this platform; token-PII mapping may be written to swap. See documentation.",
		"pii_values_logged", false,
	)
	return nil
}
