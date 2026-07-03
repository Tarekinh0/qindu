//go:build linux

package tokenize

import (
	"log/slog"

	"golang.org/x/sys/unix"
)

// initLockedArena creates a dedicated locked memory buffer for PII values
// using mmap + mlock. This is a targeted approach that locks only the PII
// data arena (defaultArenaSize bytes), avoiding the process-wide mlockall
// which would lock all goroutine stacks, GC metadata, TLS buffers, etc.
//
// All PII values are copied into this locked buffer, and the map stores
// string slices referencing the locked region. This ensures PII values
// never exist in swappable heap pages.
//
// If locking fails (e.g., insufficient RLIMIT_MEMLOCK), a PII-free WARNING
// is logged and the proxy continues operating without memory locking.
func initLockedArena(logger *slog.Logger) *piiArena {
	buf, err := unix.Mmap(-1, 0, defaultArenaSize, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANONYMOUS)
	if err != nil {
		logger.Warn("memory locking failed: mmap error; token-PII mapping may be written to swap. See documentation.",
			"error", err.Error(),
			"pii_values_logged", false,
		)
		return nil
	}

	err = unix.Mlock(buf)
	if err != nil {
		unix.Munmap(buf)
		logger.Warn("memory locking failed: mlock error; token-PII mapping may be written to swap. See documentation.",
			"error", err.Error(),
			"pii_values_logged", false,
		)
		return nil
	}

	logger.Debug("memory locking enabled (mmap+mlock arena)", "pii_values_logged", false)
	return &piiArena{
		buf:    buf,
		offset: 0,
	}
}
