//go:build windows

package crypto

import (
	"io/fs"
	"os"
)

// validateKeyFilePermissions returns nil on Windows.
// Windows ACLs from the profile directory handle access control —
// the user's %LOCALAPPDATA% is already restricted to the user + SYSTEM.
// Unix permission bits (os.Stat().Mode().Perm()) do not map cleanly to
// Windows ACLs, so checking them would produce false positives.
func validateKeyFilePermissions(path string) error {
	_ = path
	return nil
}

// checkFileMode always returns true on Windows.
// Windows does not enforce Unix-style permission bits; actual access control
// is via ACLs. Since ACL verification is complex and requires platform-specific
// syscalls, we accept the file mode as-is.
func checkFileMode(path string, expected fs.FileMode) (bool, error) {
	_, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	// On Windows, permission bits from os.Stat are unreliable.
	// Accept whatever the OS reports — real security comes from ACLs.
	return true, nil
}
