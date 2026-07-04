package vault

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/Tarekinh0/qindu/internal/crypto"
)

// testLogger returns a logger that discards all output for test noise reduction.
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// setupTestVault creates a temporary vault with a real bbolt DB and crypto service.
func setupTestVault(t *testing.T, ttl time.Duration) (*Vault, func()) {
	t.Helper()
	dir := t.TempDir()

	// Create crypto key.
	keyPath := filepath.Join(dir, "vault.key")
	cryptoService, err := crypto.New(keyPath)
	if err != nil {
		t.Fatalf("crypto.New: %v", err)
	}

	// Open bbolt DB.
	dbPath := filepath.Join(dir, "vault.db")
	db, err := bolt.Open(dbPath, 0600, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		cryptoService.Close()
		t.Fatalf("bolt.Open: %v", err)
	}

	// Ensure the tokens bucket exists.
	if err := db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte("tokens"))
		return err
	}); err != nil {
		db.Close()
		cryptoService.Close()
		t.Fatalf("create bucket: %v", err)
	}

	vault, err := New(db, cryptoService, ttl, testLogger())
	if err != nil {
		db.Close()
		cryptoService.Close()
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	vault.Run(ctx)

	cleanup := func() {
		cancel()
		vault.Close()
	}
	return vault, cleanup
}

// =============================================================================
// T-1: PersistAndRetrieve — write, decrypt from bbolt, verify value
// =============================================================================

func TestPersistAndRetrieve(t *testing.T) {
	vault, cleanup := setupTestVault(t, 1*time.Hour)
	defer cleanup()

	scope := Scope{Provider: "chatgpt", ConversationID: "test-conv-001"}
	token := "<<EMAIL_1>>"
	piiValue := []byte("alice@example.com")

	if err := vault.Persist(scope, token, piiValue); err != nil {
		t.Fatalf("Persist: %v", err)
	}

	// Give the async writer time to flush.
	time.Sleep(100 * time.Millisecond)

	// Read directly from bbolt and verify the value is encrypted.
	var rawValue []byte
	vault.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("tokens"))
		if b == nil {
			t.Fatal("bucket does not exist")
		}
		key := conversationKey(scope, token)
		rawValue = b.Get([]byte(key))
		return nil
	})

	if rawValue == nil {
		t.Fatal("value not found in bbolt")
	}

	// Verify the raw value does NOT contain the PII plaintext.
	if string(rawValue) == string(piiValue) {
		t.Error("T-1 FAIL: PII value stored in plaintext in bbolt")
	}

	// Decrypt and verify.
	decrypted, err := vault.crypto.Decrypt(rawValue)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(decrypted) != string(piiValue) {
		t.Errorf("T-1 FAIL: decrypted value mismatch: got %q, want %q", string(decrypted), string(piiValue))
	}
}

// =============================================================================
// T-803 / T-3: AsyncNonBlocking — fill channel, verify proxy not blocked (SR-802)
// =============================================================================

func TestAsyncNonBlocking(t *testing.T) {
	vault, cleanup := setupTestVault(t, 1*time.Hour)
	defer cleanup()

	scope := Scope{Provider: "chatgpt", ConversationID: "test-conv-async"}

	// Send more writes than the channel capacity to verify non-blocking behavior.
	// Channel buffer is 1024, send 2000 writes.
	const burstSize = 2000
	var wg sync.WaitGroup
	errs := make(chan error, burstSize)

	start := time.Now()
	for i := 0; i < burstSize; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			tokenStr := "<<EMAIL_" + itoa(idx+1) + ">>"
			if err := vault.Persist(scope, tokenStr, []byte("test@example.com")); err != nil {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)

	elapsed := time.Since(start)

	// All 2000 sends should complete quickly — the non-blocking send means
	// no goroutine should have blocked waiting for the channel.
	if elapsed > 5*time.Second {
		t.Errorf("T-803 FAIL: 2000 Persist calls took %v, expected <5s (indicating blocking sends)", elapsed)
	}

	// Count channel sends that failed (they should have dropped gracefully).
	droppedErrors := 0
	for range errs {
		droppedErrors++
	}
	if droppedErrors > 0 {
		t.Logf("info: %d writes dropped due to full channel (expected under burst)", droppedErrors)
	}
}

// itoa is a simple int-to-string helper (avoid importing strconv for a test helper).
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

// =============================================================================
// T-808: TestShutdownDrain — write N entries, close, verify no hang (SR-806)
// =============================================================================

func TestShutdownDrain(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "vault.key")
	dbPath := filepath.Join(dir, "vault.db")

	cryptoService, err := crypto.New(keyPath)
	if err != nil {
		t.Fatalf("crypto.New: %v", err)
	}

	db, err := bolt.Open(dbPath, 0600, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		cryptoService.Close()
		t.Fatalf("bolt.Open: %v", err)
	}

	if err := db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte("tokens"))
		return err
	}); err != nil {
		db.Close()
		cryptoService.Close()
		t.Fatalf("create bucket: %v", err)
	}

	vault, err := New(db, cryptoService, 1*time.Hour, testLogger())
	if err != nil {
		db.Close()
		cryptoService.Close()
		t.Fatalf("New: %v", err)
	}

	scope := Scope{Provider: "claude", ConversationID: "test-conv-drain"}
	const numWrites = 50

	for i := 0; i < numWrites; i++ {
		tokenStr := "<<EMAIL_" + itoa(i+1) + ">>"
		if err := vault.Persist(scope, tokenStr, []byte("drain-test@example.com")); err != nil {
			vault.Close()
			t.Fatalf("Persist %d: %v", i, err)
		}
	}

	// Close the vault — should drain all pending writes without hanging.
	vault.Close()
	t.Logf("drain test: %d writes submitted before close, no panic/timeout", numWrites)
}

// =============================================================================
// T-814: TestConcurrentPersist — goroutines, race-free (go test -race)
// =============================================================================

func TestConcurrentPersist(t *testing.T) {
	vault, cleanup := setupTestVault(t, 1*time.Hour)
	defer cleanup()

	scope := Scope{Provider: "chatgpt", ConversationID: "test-conv-race"}
	const numGoroutines = 50

	var wg sync.WaitGroup
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			tokenStr := "<<EMAIL_" + itoa(idx) + ">>"
			val := []byte("race-test-" + itoa(idx) + "@example.com")
			_ = vault.Persist(scope, tokenStr, val)
		}(i)
	}
	wg.Wait()

	// Wait for async writes to flush.
	time.Sleep(200 * time.Millisecond)

	// Verify we can list conversations without races.
	_, err := vault.ListConversations(context.Background())
	if err != nil {
		t.Errorf("ListConversations after concurrent writes: %v", err)
	}
}

// =============================================================================
// TTL tests
// =============================================================================

// TestTTLExpiry — short TTL (1ms), write, sleep, verify purged.
func TestTTLExpiry(t *testing.T) {
	vault, cleanup := setupTestVault(t, 1*time.Millisecond)
	defer cleanup()

	scope := Scope{Provider: "chatgpt", ConversationID: "test-conv-expire"}
	token := "<<EMAIL_1>>"
	value := []byte("expire-test@example.com")

	if err := vault.Persist(scope, token, value); err != nil {
		t.Fatalf("Persist: %v", err)
	}

	// Create metadata so PurgeExpired can scan __meta__ keys for conversation age.
	if err := vault.UpdateMeta(scope, NewMetadata(scope.Provider)); err != nil {
		t.Fatalf("UpdateMeta: %v", err)
	}

	// Wait for async writes + TTL to expire.
	time.Sleep(100 * time.Millisecond)

	// Purge expired.
	purged, err := vault.PurgeExpired(context.Background())
	if err != nil {
		t.Fatalf("PurgeExpired: %v", err)
	}
	if purged < 1 {
		t.Error("expected at least 1 conversation purged with 1ms TTL")
	}

	// Verify the entry is gone from bbolt.
	var exists bool
	vault.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("tokens"))
		if b == nil {
			return nil
		}
		key := conversationKey(scope, token)
		if b.Get([]byte(key)) != nil {
			exists = true
		}
		return nil
	})
	if exists {
		t.Error("T-4 FAIL: expired entry still exists in bbolt")
	}
}

// TestInfiniteTTLNeverPurges verifies that TTL=0 prevents purging.
func TestInfiniteTTLNeverPurges(t *testing.T) {
	vault, cleanup := setupTestVault(t, 0) // infinite TTL
	defer cleanup()

	scope := Scope{Provider: "chatgpt", ConversationID: "test-conv-infinite"}
	token := "<<EMAIL_1>>"
	value := []byte("infinite@example.com")

	if err := vault.Persist(scope, token, value); err != nil {
		t.Fatalf("Persist: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	// With infinite TTL, PurgeExpired should not remove anything.
	purged, err := vault.PurgeExpired(context.Background())
	if err != nil {
		t.Fatalf("PurgeExpired: %v", err)
	}
	if purged != 0 {
		t.Errorf("expected 0 purged with infinite TTL, got %d", purged)
	}
}

// TestStartupSweep — create expired entries in bbolt, New() → verify gone.
func TestStartupSweep(t *testing.T) {
	dir := t.TempDir()

	// Create crypto key.
	keyPath := filepath.Join(dir, "vault.key")
	cryptoService, err := crypto.New(keyPath)
	if err != nil {
		t.Fatalf("crypto.New: %v", err)
	}

	// Open bbolt DB.
	dbPath := filepath.Join(dir, "vault.db")
	db, err := bolt.Open(dbPath, 0600, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		cryptoService.Close()
		t.Fatalf("bolt.Open: %v", err)
	}

	// Create bucket and insert expired metadata manually.
	scope := Scope{Provider: "chatgpt", ConversationID: "test-startup-sweep"}

	if err := db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte("tokens"))
		if err != nil {
			return err
		}

		// Create metadata with an old timestamp (24h ago).
		oldMeta := NewMetadata("chatgpt")
		oldMeta.CreatedAt = time.Now().Add(-25 * time.Hour).Unix()
		metaData, _ := json.Marshal(oldMeta)
		metaKey := conversationKey(scope, metaKeySuffix)
		if err := b.Put([]byte(metaKey), metaData); err != nil {
			return err
		}

		// Also add a token entry (encrypted).
		plainValue := []byte("sweep-test@example.com")
		encValue, err := cryptoService.Encrypt(plainValue)
		if err != nil {
			return err
		}
		tokenKey := conversationKey(scope, "<<EMAIL_1>>")
		return b.Put([]byte(tokenKey), encValue)
	}); err != nil {
		db.Close()
		cryptoService.Close()
		t.Fatalf("setup bbolt: %v", err)
	}

	// Now create the vault with a 24h TTL — startup sweep should purge the expired entry.
	vault, err := New(db, cryptoService, 24*time.Hour, testLogger())
	if err != nil {
		db.Close()
		cryptoService.Close()
		t.Fatalf("New: %v", err)
	}
	defer vault.Close()

	// Verify the expired conversation is gone.
	convs, err := vault.ListConversations(context.Background())
	if err != nil {
		t.Fatalf("ListConversations: %v", err)
	}
	if len(convs) > 0 {
		t.Errorf("startup sweep: expected 0 conversations after purge, got %d", len(convs))
	}
}

// =============================================================================
// DPO-R3 Data Subject Rights API tests
// =============================================================================

// TestPurgeAll removes all conversations.
func TestPurgeAll(t *testing.T) {
	vault, cleanup := setupTestVault(t, 1*time.Hour)
	defer cleanup()

	// Write some data.
	scope := Scope{Provider: "chatgpt", ConversationID: "test-purge-all"}
	if err := vault.Persist(scope, "<<EMAIL_1>>", []byte("purge@example.com")); err != nil {
		t.Fatalf("Persist: %v", err)
	}
	time.Sleep(100 * time.Millisecond)

	// Purge all.
	if err := vault.PurgeAll(context.Background()); err != nil {
		t.Fatalf("PurgeAll: %v", err)
	}

	// Verify empty.
	convs, err := vault.ListConversations(context.Background())
	if err != nil {
		t.Fatalf("ListConversations: %v", err)
	}
	if len(convs) > 0 {
		t.Errorf("PurgeAll: expected 0 conversations, got %d", len(convs))
	}
}

// TestDeleteConversation removes a specific conversation.
func TestDeleteConversation(t *testing.T) {
	vault, cleanup := setupTestVault(t, 1*time.Hour)
	defer cleanup()

	scope1 := Scope{Provider: "chatgpt", ConversationID: "conv-to-keep"}
	scope2 := Scope{Provider: "claude", ConversationID: "conv-to-delete"}

	if err := vault.Persist(scope1, "<<EMAIL_1>>", []byte("keep@example.com")); err != nil {
		t.Fatalf("Persist scope1: %v", err)
	}
	if err := vault.Persist(scope2, "<<EMAIL_1>>", []byte("delete@example.com")); err != nil {
		t.Fatalf("Persist scope2: %v", err)
	}
	time.Sleep(100 * time.Millisecond)

	// Delete only scope2.
	if err := vault.DeleteConversation(context.Background(), scope2); err != nil {
		t.Fatalf("DeleteConversation: %v", err)
	}

	// Verify scope2 is gone.
	var exists bool
	vault.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("tokens"))
		if b == nil {
			return nil
		}
		if b.Get([]byte(conversationKey(scope2, "<<EMAIL_1>>"))) != nil {
			exists = true
		}
		return nil
	})
	if exists {
		t.Error("DeleteConversation: deleted conversation still exists")
	}

	// Verify scope1 still exists.
	vault.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("tokens"))
		if b == nil {
			return nil
		}
		if b.Get([]byte(conversationKey(scope1, "<<EMAIL_1>>"))) == nil {
			t.Error("DeleteConversation: kept conversation was deleted")
		}
		return nil
	})
}

// =============================================================================
// T-813: UUID v4 format validation
// =============================================================================

func TestNewConversationID_UUIDv4Format(t *testing.T) {
	const count = 1000
	ids := make(map[string]bool, count)

	for i := 0; i < count; i++ {
		id, err := NewConversationID()
		if err != nil {
			t.Fatalf("NewConversationID %d: %v", i, err)
		}

		// Check format: 8-4-4-4-12 hex digits.
		if len(id) != 36 {
			t.Errorf("T-813 FAIL: UUID length %d != 36 for %q", len(id), id)
		}

		// Check version nibble (13th character, after first hyphen = index 14).
		// Format: xxxxxxxx-xxxx-Vxxx-xxxx-xxxxxxxxxxxx
		// V is at position 14 (0-indexed).
		if id[14] != '4' {
			t.Errorf("T-813 FAIL: UUID version nibble is %c, expected '4' in %q", id[14], id)
		}

		// Check variant nibble (19th character = index 19).
		// Variant bits must be 10xx, so character must be 8,9,a,b or A,B.
		v := id[19]
		if !(v == '8' || v == '9' || v == 'a' || v == 'b' || v == 'A' || v == 'B') {
			t.Errorf("T-813 FAIL: UUID variant invalid: got %c in %q", v, id)
		}

		// Check uniqueness.
		if ids[id] {
			t.Errorf("T-813 FAIL: duplicate UUID generated: %q", id)
		}
		ids[id] = true
	}

	if len(ids) != count {
		t.Errorf("T-813 FAIL: expected %d unique UUIDs, got %d", count, len(ids))
	}
}

// =============================================================================
// Test that vault Close is idempotent (DPO-R7)
// =============================================================================

func TestCloseIdempotent(t *testing.T) {
	vault, cleanup := setupTestVault(t, 1*time.Hour)
	cleanup() // first close

	// Second close should not panic.
	vault.Close()
	vault.Close() // triple-check
}

// =============================================================================
// Test bbolt file permissions (T-810)
// =============================================================================

func TestBoltDBFilePermissions(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "vault.db")
	db, err := bolt.Open(dbPath, 0600, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		t.Fatalf("bolt.Open: %v", err)
	}
	defer db.Close()

	// Check file permissions on Unix.
	info, err := os.Stat(dbPath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	perm := info.Mode().Perm()
	if perm != 0600 {
		t.Errorf("T-810 FAIL: vault.db expected mode 0600, got %04o", perm)
	}
}

// =============================================================================
// Test metadata integrity (DPO-R12)
// =============================================================================

func TestMetadataIntegrity(t *testing.T) {
	// Metadata creation and marshaling.
	meta := NewMetadata("chatgpt")

	if meta.Provider != "chatgpt" {
		t.Errorf("expected provider 'chatgpt', got %q", meta.Provider)
	}
	if meta.CreatedAt <= 0 {
		t.Error("created_at should be a positive timestamp")
	}
	if meta.UpdatedAt != meta.CreatedAt {
		t.Error("updated_at should equal created_at at creation")
	}
	if meta.Status != StatusActive {
		t.Errorf("expected status 'active', got %q", meta.Status)
	}
	if meta.PIICount != 0 {
		t.Errorf("expected pii_count 0, got %d", meta.PIICount)
	}

	// Marshal and unmarshal round-trip.
	data, err := json.Marshal(meta)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	restored, err := UnmarshalMetadata(data)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if restored.Provider != meta.Provider {
		t.Errorf("round-trip: provider mismatch")
	}
	if restored.CreatedAt != meta.CreatedAt {
		t.Errorf("round-trip: created_at mismatch")
	}
}

// =============================================================================
// Test scope functions
// =============================================================================

func TestConversationKeyFormat(t *testing.T) {
	scope := Scope{Provider: "chatgpt", ConversationID: "abc-123"}
	key := conversationKey(scope, "<<EMAIL_1>>")
	expected := "chatgpt/abc-123/<<EMAIL_1>>"
	if key != expected {
		t.Errorf("expected key %q, got %q", expected, key)
	}
}

func TestScopePrefixFormat(t *testing.T) {
	scope := Scope{Provider: "claude", ConversationID: "def-456"}
	prefix := scopePrefix(scope)
	expected := "claude/def-456/"
	if prefix != expected {
		t.Errorf("expected prefix %q, got %q", expected, prefix)
	}
}
