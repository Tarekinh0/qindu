//go:build !windows

package crypto

import (
	"fmt"
	"io/fs"
	"os"
)

// validateKeyFilePermissions checks that the key file has mode exactly 0600.
// On Unix, this is the primary access control mechanism — broad permissions
// mean other users on the system can read the AES key, defeating vault encryption.
// Hard rejection on Unix.
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

// checkFileMode reports whether the file at path has exactly the expected permissions.
// Used by key file permission validation tests.
func checkFileMode(path string, expected fs.FileMode) (bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	return info.Mode().Perm() == expected, nil
}
