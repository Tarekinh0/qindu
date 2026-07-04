package session

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestLookupVaultPath_ReturnsValidPaths(t *testing.T) {
	u, err := LookupVaultPath()
	if err != nil {
		t.Fatalf("LookupVaultPath: %v", err)
	}

	if u.VaultPath == "" {
		t.Error("VaultPath must not be empty")
	}
	if u.KeyPath == "" {
		t.Error("KeyPath must not be empty")
	}
	if u.DBPath == "" {
		t.Error("DBPath must not be empty")
	}

	// Verify paths are absolute.
	if !filepath.IsAbs(u.VaultPath) {
		t.Errorf("VaultPath must be absolute, got %q", u.VaultPath)
	}
	if !filepath.IsAbs(u.KeyPath) {
		t.Errorf("KeyPath must be absolute, got %q", u.KeyPath)
	}
	if !filepath.IsAbs(u.DBPath) {
		t.Errorf("DBPath must be absolute, got %q", u.DBPath)
	}

	// KeyPath and DBPath are children of VaultPath.
	if filepath.Dir(u.KeyPath) != u.VaultPath {
		t.Errorf("KeyPath parent must be VaultPath: KeyPath=%q, VaultPath=%q",
			u.KeyPath, u.VaultPath)
	}
	if filepath.Dir(u.DBPath) != u.VaultPath {
		t.Errorf("DBPath parent must be VaultPath: DBPath=%q, VaultPath=%q",
			u.DBPath, u.VaultPath)
	}
}

func TestLookupVaultPath_UsesXdgDataHome(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("macOS uses ~/Library/Application Support, tested separately")
	}

	// Save and restore XDG_DATA_HOME.
	origXdg := os.Getenv("XDG_DATA_HOME")
	defer os.Setenv("XDG_DATA_HOME", origXdg)

	// Set XDG_DATA_HOME to a custom value.
	customXdg := filepath.Join(os.TempDir(), "test-xdg-qindu")
	os.Setenv("XDG_DATA_HOME", customXdg)

	u, err := LookupVaultPath()
	if err != nil {
		t.Fatalf("LookupVaultPath: %v", err)
	}

	expectedBase := filepath.Join(customXdg, "qindu")
	if u.VaultPath != expectedBase {
		t.Errorf("with XDG_DATA_HOME=%s: expected VaultPath=%q, got %q",
			customXdg, expectedBase, u.VaultPath)
	}
}

func TestLookupVaultPath_UsesHomeFallback(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("macOS uses ~/Library/Application Support, tested separately")
	}

	// Save and restore XDG_DATA_HOME.
	origXdg := os.Getenv("XDG_DATA_HOME")
	defer os.Setenv("XDG_DATA_HOME", origXdg)

	// Unset XDG_DATA_HOME so the fallback to ~/.local/share is used.
	os.Unsetenv("XDG_DATA_HOME")

	u, err := LookupVaultPath()
	if err != nil {
		t.Fatalf("LookupVaultPath: %v", err)
	}

	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("cannot determine home directory: %v", err)
	}

	expectedBase := filepath.Join(home, ".local", "share", "qindu")
	if u.VaultPath != expectedBase {
		t.Errorf("with XDG_DATA_HOME unset: expected VaultPath=%q, got %q",
			expectedBase, u.VaultPath)
	}
}

func TestLookupVaultPath_DarwinUsesApplicationSupport(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS-specific test")
	}

	u, err := LookupVaultPath()
	if err != nil {
		t.Fatalf("LookupVaultPath: %v", err)
	}

	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("cannot determine home directory: %v", err)
	}

	expectedBase := filepath.Join(home, "Library", "Application Support", "Qindu")
	if u.VaultPath != expectedBase {
		t.Errorf("on macOS: expected VaultPath=%q, got %q", expectedBase, u.VaultPath)
	}
}

func TestLookupVaultPath_Idempotent(t *testing.T) {
	u1, err := LookupVaultPath()
	if err != nil {
		t.Fatalf("LookupVaultPath (first): %v", err)
	}

	u2, err := LookupVaultPath()
	if err != nil {
		t.Fatalf("LookupVaultPath (second): %v", err)
	}

	if u1.VaultPath != u2.VaultPath {
		t.Errorf("consecutive calls must return the same path: %q vs %q",
			u1.VaultPath, u2.VaultPath)
	}
	if u1.KeyPath != u2.KeyPath {
		t.Errorf("consecutive calls must return the same key path: %q vs %q",
			u1.KeyPath, u2.KeyPath)
	}
	if u1.DBPath != u2.DBPath {
		t.Errorf("consecutive calls must return the same DB path: %q vs %q",
			u1.DBPath, u2.DBPath)
	}
}
