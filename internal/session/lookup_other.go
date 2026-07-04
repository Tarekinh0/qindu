//go:build !windows

package session

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// LookupVaultPath returns the per-user vault directory path.
// On Linux: $XDG_DATA_HOME/qindu/ or ~/.local/share/qindu/
// On macOS: ~/Library/Application Support/Qindu/
//
// Does NOT perform network operations.
func LookupVaultPath() (*ResolvedUser, error) {
	var baseDir string

	if runtime.GOOS == "darwin" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("session: cannot determine home directory: %w", err)
		}
		baseDir = filepath.Join(home, "Library", "Application Support", "Qindu")
	} else {
		// Linux and other Unix: XDG_DATA_HOME or ~/.local/share
		baseDir = xdgDataHome()
		baseDir = filepath.Join(baseDir, "qindu")
	}

	return &ResolvedUser{
		VaultPath: baseDir,
		KeyPath:   filepath.Join(baseDir, "vault.key"),
		DBPath:    filepath.Join(baseDir, "vault.db"),
	}, nil
}

// xdgDataHome returns $XDG_DATA_HOME or ~/.local/share.
func xdgDataHome() string {
	if dir := os.Getenv("XDG_DATA_HOME"); dir != "" {
		return dir
	}
	home, err := os.UserHomeDir()
	if err != nil {
		// Extreme fallback — shouldn't happen on modern OS.
		return filepath.Join(os.TempDir(), ".local", "share")
	}
	return filepath.Join(home, ".local", "share")
}
