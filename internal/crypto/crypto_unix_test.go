//go:build !windows

package crypto

import (
	"os"
	"path/filepath"
	"testing"
)

// tempKeyPathUnix returns a temp path for tests that check file permissions.
func tempKeyPathUnix(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "vault.key")
}

// =============================================================================
// T-805: Key file permissions (Unix 0600) — Unix-only test
// =============================================================================

func TestKeyFileCreatedWith0600(t *testing.T) {
	path := tempKeyPathUnix(t)
	svc, err := New(path)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	defer func() { _ = svc.Close() }()

	ok, err := checkFileMode(path, 0600)
	if err != nil {
		t.Fatalf("stat key file: %v", err)
	}
	if !ok {
		info, _ := os.Stat(path)
		t.Errorf("T-805 FAIL: vault.key expected 0600, got %04o", info.Mode().Perm())
	}
}

// =============================================================================
// T-806: Pre-existing wide permissions key file → error — Unix-only test
// =============================================================================

func TestKeyFileRejectsWidePermissions(t *testing.T) {
	path := tempKeyPathUnix(t)
	// Create a valid 32-byte key file with wide permissions (0644).
	key := make([]byte, KeySize)
	if err := os.WriteFile(path, key, 0644); err != nil {
		t.Fatalf("setup: %v", err)
	}

	_, err := New(path)
	if err == nil {
		t.Error("T-806 FAIL: expected error for wide permissions")
	}
}
