//go:build !windows

package session

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// LookupVaultPathForPort resolves the vault path for a connection.
// On non-Windows platforms, ignores the port and returns the current user's vault path.
// srcPort is accepted for API compatibility but is unused on this platform.
func LookupVaultPathForPort(srcPort uint16, opts ...interface{}) (*ResolvedUser, error) {
	return LookupVaultPath()
}

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
		var err error
		baseDir, err = xdgDataHome()
		if err != nil {
			return nil, err
		}
		baseDir = filepath.Join(baseDir, "qindu")
	}

	return &ResolvedUser{
		VaultPath: baseDir,
		KeyPath:   filepath.Join(baseDir, "vault.key"),
		DBPath:    filepath.Join(baseDir, "vault.db"),
	}, nil
}

// xdgDataHome returns $XDG_DATA_HOME or ~/.local/share.
// If neither is available, returns an error instead of falling back to a temp
// directory (PR-005 — fixes insecure /tmp fallback).
func xdgDataHome() (string, error) {
	if dir := os.Getenv("XDG_DATA_HOME"); dir != "" {
		return dir, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("session: cannot determine home directory (HOME unset): %w", err)
	}
	return filepath.Join(home, ".local", "share"), nil
}
