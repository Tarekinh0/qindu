//go:build !windows

package crypto

import (
	"fmt"
	"os"
)

// validateKeyFilePermissions checks that the key file has mode exactly 0600.
// Refuses to proceed if permissions are broader.
func validateKeyFilePermissions(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("crypto: failed to stat key file: %w", err)
	}

	mode := info.Mode().Perm()
	if mode != 0600 {
		return fmt.Errorf("crypto: key file %s has unsafe permissions %04o, expected 0600. "+
			"Fix with: chmod 0600 %s", path, mode, path)
	}

	return nil
}

// setPlatformACL is a no-op on Unix — chmod 0600 is sufficient.
func setPlatformACL(path string) error {
	return nil
}
