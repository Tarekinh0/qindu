package vault

import (
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Tarekinh0/qindu/internal/session"
)

// =============================================================================
// VaultManager tests — lazy per-user vault creation and lifecycle management
// =============================================================================

// testResolvedUser returns a ResolvedUser for test vault paths in the given temp dir.
// Sets VaultPath to tempDir, KeyPath to tempDir/vault.key, DBPath to tempDir/vault.db.
func testResolvedUser(tempDir string) *session.ResolvedUser {
	return &session.ResolvedUser{
		VaultPath: tempDir,
		KeyPath:   filepath.Join(tempDir, "vault.key"),
		DBPath:    filepath.Join(tempDir, "vault.db"),
	}
}

// =============================================================================
// GetOrCreate — basic creation and cache hit
// =============================================================================

func TestVaultManager_GetOrCreate_CreatesVault(t *testing.T) {
	dir := t.TempDir()
	vm := NewVaultManager(1*time.Hour, 30*time.Minute, testLogger())
	defer vm.Shutdown()

	resolved := testResolvedUser(dir)
	v, err := vm.GetOrCreate(resolved, 0)
	if err != nil {
		t.Fatalf("GetOrCreate failed: %v", err)
	}
	if v == nil {
		t.Fatal("expected non-nil vault")
	}

	// Verify vault works — persist and retrieve a token.
	scope := Scope{Provider: "chatgpt", ConversationID: "test-conv-vm"}
	v.Persist(scope, "<<EMAIL_1>>", []byte("vm-test@example.com"))
	time.Sleep(100 * time.Millisecond)

	entries, err := v.GetConversation(v.ctx, scope)
	if err != nil {
		t.Fatalf("GetConversation failed: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
}

func TestVaultManager_GetOrCreate_ReturnsCacheHit(t *testing.T) {
	dir := t.TempDir()
	vm := NewVaultManager(1*time.Hour, 30*time.Minute, testLogger())
	defer vm.Shutdown()

	resolved := testResolvedUser(dir)

	// First call creates the vault.
	v1, err := vm.GetOrCreate(resolved, 0)
	if err != nil {
		t.Fatalf("GetOrCreate (first): %v", err)
	}

	// Second call should return the same vault instance.
	v2, err := vm.GetOrCreate(resolved, 0)
	if err != nil {
		t.Fatalf("GetOrCreate (second): %v", err)
	}

	if v1 != v2 {
		t.Error("GetOrCreate returned different vault instances for the same user path")
	}

	if vm.vaultCount() != 1 {
		t.Errorf("expected 1 vault in manager, got %d", vm.vaultCount())
	}
}

func TestVaultManager_GetOrCreate_DifferentUsers(t *testing.T) {
	dir1 := t.TempDir()
	dir2 := t.TempDir()
	vm := NewVaultManager(1*time.Hour, 30*time.Minute, testLogger())
	defer vm.Shutdown()

	user1 := testResolvedUser(dir1)
	user2 := testResolvedUser(dir2)

	v1, err := vm.GetOrCreate(user1, 0)
	if err != nil {
		t.Fatalf("GetOrCreate user1: %v", err)
	}
	v2, err := vm.GetOrCreate(user2, 0)
	if err != nil {
		t.Fatalf("GetOrCreate user2: %v", err)
	}

	if v1 == v2 {
		t.Error("different users should get different vault instances")
	}
	if vm.vaultCount() != 2 {
		t.Errorf("expected 2 vaults in manager, got %d", vm.vaultCount())
	}
}

// =============================================================================
// Double-create race — concurrent GetOrCreate for same user
// =============================================================================

func TestVaultManager_GetOrCreate_ConcurrentDeduplication(t *testing.T) {
	dir := t.TempDir()
	vm := NewVaultManager(1*time.Hour, 30*time.Minute, testLogger())
	defer vm.Shutdown()

	resolved := testResolvedUser(dir)

	var wg sync.WaitGroup
	var mu sync.Mutex
	results := make([]*Vault, 0, 10)

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v, err := vm.GetOrCreate(resolved, 0)
			if err != nil {
				t.Errorf("GetOrCreate goroutine failed: %v", err)
				return
			}
			mu.Lock()
			results = append(results, v)
			mu.Unlock()
		}()
	}
	wg.Wait()

	if len(results) < 10 {
		t.Fatalf("expected 10 successful vaults, got %d", len(results))
	}

	// All results should point to the same vault instance.
	first := results[0]
	for i := 1; i < len(results); i++ {
		if results[i] != first {
			t.Errorf("goroutine %d got different vault instance", i)
		}
	}
	if vm.vaultCount() != 1 {
		t.Errorf("expected exactly 1 vault after concurrent dedup, got %d", vm.vaultCount())
	}
}

// =============================================================================
// Shutdown — closes all vaults and stops eviction goroutine
// =============================================================================

func TestVaultManager_Shutdown_ClosesAll(t *testing.T) {
	dir1 := t.TempDir()
	dir2 := t.TempDir()
	vm := NewVaultManager(1*time.Hour, 30*time.Minute, testLogger())

	user1 := testResolvedUser(dir1)
	user2 := testResolvedUser(dir2)

	_, err := vm.GetOrCreate(user1, 0)
	if err != nil {
		t.Fatalf("GetOrCreate user1: %v", err)
	}
	_, err = vm.GetOrCreate(user2, 0)
	if err != nil {
		t.Fatalf("GetOrCreate user2: %v", err)
	}

	if vm.vaultCount() != 2 {
		t.Fatalf("expected 2 vaults before shutdown, got %d", vm.vaultCount())
	}

	vm.Shutdown()

	if vm.vaultCount() != 0 {
		t.Errorf("expected 0 vaults after shutdown, got %d", vm.vaultCount())
	}
}

// =============================================================================
// Idle eviction — vaults unused beyond timeout are closed
// =============================================================================

func TestVaultManager_Eviction_ClosesIdleVaults(t *testing.T) {
	dir1 := t.TempDir()
	dir2 := t.TempDir()

	// Use a very short idle timeout for testing.
	vm := NewVaultManager(1*time.Hour, 1*time.Millisecond, testLogger())
	defer vm.Shutdown()

	user1 := testResolvedUser(dir1)
	user2 := testResolvedUser(dir2)

	// Create both vaults.
	_, err := vm.GetOrCreate(user1, 0)
	if err != nil {
		t.Fatalf("GetOrCreate user1: %v", err)
	}
	_, err = vm.GetOrCreate(user2, 0)
	if err != nil {
		t.Fatalf("GetOrCreate user2: %v", err)
	}

	// Touch user2's vault (updates lastUsed) AFTER a short sleep
	// so user1's lastUsed is definitely older.
	time.Sleep(10 * time.Millisecond)
	_, err = vm.GetOrCreate(user2, 0)
	if err != nil {
		t.Fatalf("GetOrCreate user2 (touch): %v", err)
	}

	// Force immediate eviction of idle vaults.
	// user1 should be idle, user2 was just touched.
	vm.evictIdle()

	// After eviction, user1 should be gone, user2 should remain.
	if vm.vaultCount() != 1 {
		t.Errorf("expected 1 vault after partial eviction, got %d", vm.vaultCount())
	}

	// Verify user2 is the one that survived.
	_, err = vm.GetOrCreate(user2, 0)
	if err != nil {
		t.Fatalf("GetOrCreate user2 after eviction should still work: %v", err)
	}
}

// =============================================================================
// redactHomePath tests
// =============================================================================

func TestRedactHomePath(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		contains string // substring the result must contain
		excludes string // substring the result must NOT contain
	}{
		{
			name:     "empty path",
			path:     "",
			contains: "",
			excludes: "",
		},
		{
			name:     "unrelated path",
			path:     "/etc/passwd",
			contains: "/etc/passwd",
			excludes: "",
		},
		{
			name:     "path with no prefix match",
			path:     "/opt/qindu/vault.db",
			contains: "/opt/qindu/vault.db",
			excludes: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := redactHomePath(tc.path)
			if tc.contains != "" && !strings.Contains(result, tc.contains) {
				t.Errorf("expected result to contain %q, got %q", tc.contains, result)
			}
			if tc.excludes != "" && strings.Contains(result, tc.excludes) {
				t.Errorf("expected result to NOT contain %q, got %q", tc.excludes, result)
			}
		})
	}
}

// =============================================================================
// createUserVault — Unix/platform test (runs on all platforms)
// =============================================================================

func TestCreateUserVault_Success(t *testing.T) {
	dir := t.TempDir()
	resolved := testResolvedUser(dir)

	v, err := createUserVault(resolved, 1*time.Hour, testLogger(), 0)
	if err != nil {
		t.Fatalf("createUserVault failed: %v", err)
	}
	defer v.Close()

	// Verify the vault is functional.
	scope := Scope{Provider: "chatgpt", ConversationID: "test-create"}
	v.Persist(scope, "<<EMAIL_1>>", []byte("hello@example.com"))
	time.Sleep(100 * time.Millisecond)

	entries, err := v.GetConversation(v.ctx, scope)
	if err != nil {
		t.Fatalf("GetConversation: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("expected 1 entry, got %d", len(entries))
	}
}

func TestCreateUserVault_ReopenExisting(t *testing.T) {
	dir := t.TempDir()
	resolved := testResolvedUser(dir)

	// Create first vault and write data.
	v1, err := createUserVault(resolved, 1*time.Hour, testLogger(), 0)
	if err != nil {
		t.Fatalf("createUserVault (first): %v", err)
	}

	scope := Scope{Provider: "claude", ConversationID: "test-reopen"}
	v1.Persist(scope, "<<PHONE_1>>", []byte("+33123456789"))
	time.Sleep(100 * time.Millisecond)
	v1.Close()

	// Reopen by calling createUserVault again on the same path.
	v2, err := createUserVault(resolved, 1*time.Hour, testLogger(), 0)
	if err != nil {
		t.Fatalf("createUserVault (second): %v", err)
	}
	defer v2.Close()

	// The previously persisted data should still be there.
	entries, err := v2.GetConversation(v2.ctx, scope)
	if err != nil {
		t.Fatalf("GetConversation on reopened vault: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry after reopen, got %d", len(entries))
	}
	if string(entries[0].Value) != "+33123456789" {
		t.Errorf("value mismatch: got %q, expected %q", string(entries[0].Value), "+33123456789")
	}
}

// =============================================================================
// VaultManager — idle timeout default
// =============================================================================

func TestVaultManager_DefaultIdleTimeout(t *testing.T) {
	vm := NewVaultManager(1*time.Hour, 0, testLogger()) // 0 means use default
	defer vm.Shutdown()

	if vm.idleTimeout != DefaultIdleTimeout {
		t.Errorf("expected idle timeout %v when 0 passed, got %v", DefaultIdleTimeout, vm.idleTimeout)
	}
}

func TestVaultManager_CustomIdleTimeout(t *testing.T) {
	customTimeout := 5 * time.Minute
	vm := NewVaultManager(1*time.Hour, customTimeout, testLogger())
	defer vm.Shutdown()

	if vm.idleTimeout != customTimeout {
		t.Errorf("expected idle timeout %v, got %v", customTimeout, vm.idleTimeout)
	}
}

// =============================================================================
// GetOrCreate with error path (missing directory parents that can't be created)
// =============================================================================

func TestVaultManager_GetOrCreate_ErrorOnInvalidPath(t *testing.T) {
	// Use a resolved user with a path containing a null byte, which
	// always causes os.MkdirAll to fail on all platforms.
	resolved := &session.ResolvedUser{
		VaultPath: "/tmp/qindu-test/\x00invalid",
		KeyPath:   "/tmp/qindu-test/\x00invalid/vault.key",
		DBPath:    "/tmp/qindu-test/\x00invalid/vault.db",
	}

	vm := NewVaultManager(1*time.Hour, 30*time.Minute, testLogger())
	defer vm.Shutdown()

	_, err := vm.GetOrCreate(resolved, 0)
	if err == nil {
		t.Error("expected error for invalid path, got nil")
	}
	if vm.vaultCount() != 0 {
		t.Errorf("expected 0 vaults after failed creation, got %d", vm.vaultCount())
	}
}
