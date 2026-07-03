//go:build windows

package tokenize

import (
	"log/slog"
	"unsafe"

	"golang.org/x/sys/windows"
)

// initLockedArena initializes memory locking for the token↔PII store.
// On Windows, we allocate a dedicated buffer via VirtualAlloc with MEM_COMMIT,
// then call VirtualLock on the entire buffer to prevent it from being paged
// to the pagefile.
//
// All PII values are copied into this locked buffer, and the map stores
// string slices referencing the locked region. This ensures PII values
// never exist in swappable heap pages.
//
// The arena size (defaultArenaSize = 4 MiB) is sized to accommodate
// ~20,000 entries at ~200 bytes average, far exceeding typical conversation
// volumes for a single conversation scope.
//
// If locking fails (e.g., missing SeLockMemoryPrivilege or exhausted working set),
// a PII-free WARNING is logged and the proxy continues operating.
// In this state, PII mapping pages are eligible for swap.
func initLockedArena(logger *slog.Logger) *piiArena {
	// Allocate a committed, readable/writable buffer.
	addr, err := windows.VirtualAlloc(
		0,
		defaultArenaSize,
		windows.MEM_COMMIT|windows.MEM_RESERVE,
		windows.PAGE_READWRITE,
	)
	if err != nil || addr == 0 {
		logger.Warn("memory locking failed: VirtualAlloc error; token-PII mapping may be written to pagefile. See documentation.",
			"error", err.Error(),
			"pii_values_logged", false,
		)
		return nil
	}

	// Lock the pages so they cannot be paged to disk.
	err = windows.VirtualLock(addr, defaultArenaSize)
	if err != nil {
		windows.VirtualFree(addr, 0, windows.MEM_RELEASE)
		logger.Warn("memory locking failed: VirtualLock error; token-PII mapping may be written to pagefile. See documentation.",
			"error", err.Error(),
			"pii_values_logged", false,
		)
		return nil
	}

	// Convert the raw pointer to a Go slice backed by the locked region.
	buf := unsafe.Slice((*byte)(unsafe.Pointer(addr)), defaultArenaSize)
	logger.Debug("memory locking enabled (VirtualLock)", "pii_values_logged", false)

	return &piiArena{
		buf:    buf,
		offset: 0,
	}
}
