package vault

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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
		_ = cryptoService.Close()
		t.Fatalf("bolt.Open: %v", err)
	}

	// Ensure the tokens bucket exists.
	if upErr := db.Update(func(tx *bolt.Tx) error {
		_, bktErr := tx.CreateBucketIfNotExists([]byte(BucketTokens))
		return bktErr
	}); upErr != nil {
		_ = db.Close()
		_ = cryptoService.Close()
		t.Fatalf("create bucket: %v", upErr)
	}

	vault, err := New(db, cryptoService, ttl, testLogger())
	if err != nil {
		_ = db.Close()
		_ = cryptoService.Close()
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

	vault.Persist(scope, token, piiValue)

	// Give the async writer time to flush.
	time.Sleep(100 * time.Millisecond)

	// AC-2: Verify the value is encrypted at rest by reading directly from bbolt.
	// This is the only place in tests where direct bbolt access is justified —
	// we need to confirm the raw bytes on disk do NOT contain plaintext PII.
	var rawValue []byte
	if err := vault.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(BucketTokens))
		if b == nil {
			t.Fatal("bucket does not exist")
		}
		key := conversationKey(scope, token)
		rawValue = b.Get([]byte(key))
		return nil
	}); err != nil {
		t.Fatalf("bbolt View: %v", err)
	}

	if rawValue == nil {
		t.Fatal("value not found in bbolt")
	}

	// Verify the raw value does NOT contain the PII plaintext (AC-2).
	if string(rawValue) == string(piiValue) {
		t.Error("T-1 FAIL: PII value stored in plaintext in bbolt")
	}

	// Use public API GetConversation for the round-trip verification.
	entries, err := vault.GetConversation(context.Background(), scope)
	if err != nil {
		t.Fatalf("GetConversation: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if string(entries[0].Value) != string(piiValue) {
		t.Errorf("T-1 FAIL: decrypted value mismatch: got %q, want %q", string(entries[0].Value), string(piiValue))
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

	start := time.Now()
	for i := 0; i < burstSize; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			tokenStr := "<<EMAIL_" + strconv.Itoa(idx+1) + ">>"
			vault.Persist(scope, tokenStr, []byte("test@example.com"))
		}(i)
	}
	wg.Wait()

	elapsed := time.Since(start)

	// All 2000 sends should complete quickly — the non-blocking send means
	// no goroutine should have blocked waiting for the channel.
	if elapsed > 5*time.Second {
		t.Errorf("T-803 FAIL: 2000 Persist calls took %v, expected <5s (indicating blocking sends)", elapsed)
	}
}

// =============================================================================
// T-808: TestShutdownDrain — write N entries, close, verify all writes committed
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
		_ = cryptoService.Close()
		t.Fatalf("bolt.Open: %v", err)
	}

	if upErr := db.Update(func(tx *bolt.Tx) error {
		_, bktErr := tx.CreateBucketIfNotExists([]byte(BucketTokens))
		return bktErr
	}); upErr != nil {
		_ = db.Close()
		_ = cryptoService.Close()
		t.Fatalf("create bucket: %v", upErr)
	}

	vault, err := New(db, cryptoService, 1*time.Hour, testLogger())
	if err != nil {
		_ = db.Close()
		_ = cryptoService.Close()
		t.Fatalf("New: %v", err)
	}

	// PR-104: Start background goroutines before writing.
	vault.Run(context.Background())

	scope := Scope{Provider: "claude", ConversationID: "test-conv-drain"}
	const numWrites = 50

	for i := 0; i < numWrites; i++ {
		tokenStr := "<<EMAIL_" + strconv.Itoa(i+1) + ">>"
		vault.Persist(scope, tokenStr, []byte("drain-test@example.com"))
	}

	// Close the vault — should drain all pending writes before returning.
	vault.Close()
	// Note: no cancel() needed — vault.Close() internally cancels the context
	// derived from ctx, and goroutines already exited after wg.Wait().

	// Reopen the DB for verification (vault.Close() closes it).
	// AC-2: Direct bbolt access required to verify ciphertext at rest
	// (i.e., to confirm all writes were committed to disk before Close() returned).
	// The closed vault cannot serve GetConversation(), so we must read
	// the DB directly for this specific drain-verification assertion.
	db2, err := bolt.Open(dbPath, 0600, &bolt.Options{Timeout: 1 * time.Second, ReadOnly: true})
	if err != nil {
		t.Fatalf("bolt.Open for verification: %v", err)
	}
	defer func() { _ = db2.Close() }()

	var count int
	_ = db2.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(BucketTokens))
		if b == nil {
			return nil
		}
		c := b.Cursor()
		prefix := scopePrefix(scope)
		for k, _ := c.Seek([]byte(prefix)); k != nil && strings.HasPrefix(string(k), prefix); k, _ = c.Next() {
			keyStr := string(k)
			if !strings.HasSuffix(keyStr, "/"+metaKeySuffix) {
				count++
			}
		}
		return nil
	})

	if count < numWrites {
		t.Errorf("T-808 FAIL: expected at least %d token writes committed, got %d", numWrites, count)
	}
	t.Logf("drain test: %d writes submitted before close, %d committed", numWrites, count)
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
			tokenStr := "<<EMAIL_" + strconv.Itoa(idx) + ">>"
			val := []byte("race-test-" + strconv.Itoa(idx) + "@example.com")
			vault.Persist(scope, tokenStr, val)
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

	vault.Persist(scope, token, value)

	// Create metadata so PurgeExpired can scan __meta__ keys for conversation age.
	vault.UpdateMeta(scope, NewMetadata(scope.Provider))

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

	// Use public API to verify the conversation is gone (PR-003).
	entries, err := vault.GetConversation(context.Background(), scope)
	if err != nil {
		t.Fatalf("GetConversation: %v", err)
	}
	if entries != nil {
		t.Error("T-4 FAIL: expired conversation still exists (GetConversation returned entries)")
	}
}

// TestInfiniteTTLNeverPurges verifies that TTL=0 prevents purging.
func TestInfiniteTTLNeverPurges(t *testing.T) {
	vault, cleanup := setupTestVault(t, 0) // infinite TTL
	defer cleanup()

	scope := Scope{Provider: "chatgpt", ConversationID: "test-conv-infinite"}
	token := "<<EMAIL_1>>"
	value := []byte("infinite@example.com")

	vault.Persist(scope, token, value)

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
		_ = cryptoService.Close()
		t.Fatalf("bolt.Open: %v", err)
	}

	// Create bucket and insert expired metadata manually.
	scope := Scope{Provider: "chatgpt", ConversationID: "test-startup-sweep"}

	if upErr := db.Update(func(tx *bolt.Tx) error {
		b, bktErr := tx.CreateBucketIfNotExists([]byte(BucketTokens))
		if bktErr != nil {
			return bktErr
		}

		// Create metadata with an old timestamp (24h ago).
		oldMeta := NewMetadata("chatgpt")
		oldMeta.CreatedAt = time.Now().Add(-25 * time.Hour).Unix()
		metaData, _ := json.Marshal(oldMeta)
		metaKey := conversationKey(scope, metaKeySuffix)
		if putErr := b.Put([]byte(metaKey), metaData); putErr != nil {
			return putErr
		}

		// Also add a token entry (encrypted).
		plainValue := []byte("sweep-test@example.com")
		encValue, encErr := cryptoService.Encrypt(plainValue)
		if encErr != nil {
			return encErr
		}
		tokenKey := conversationKey(scope, "<<EMAIL_1>>")
		return b.Put([]byte(tokenKey), encValue)
	}); upErr != nil {
		_ = db.Close()
		_ = cryptoService.Close()
		t.Fatalf("setup bbolt: %v", upErr)
	}

	// Now create the vault with a 24h TTL — startup sweep should purge the expired entry.
	vault, err := New(db, cryptoService, 24*time.Hour, testLogger())
	if err != nil {
		_ = db.Close()
		_ = cryptoService.Close()
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
	vault.Persist(scope, "<<EMAIL_1>>", []byte("purge@example.com"))
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

	vault.Persist(scope1, "<<EMAIL_1>>", []byte("keep@example.com"))
	vault.Persist(scope2, "<<EMAIL_1>>", []byte("delete@example.com"))
	time.Sleep(100 * time.Millisecond)

	// Delete only scope2.
	if err := vault.DeleteConversation(context.Background(), scope2); err != nil {
		t.Fatalf("DeleteConversation: %v", err)
	}

	// PR-003: Use public API to verify scope2 is gone.
	entries, err := vault.GetConversation(context.Background(), scope2)
	if err != nil {
		t.Fatalf("GetConversation(scope2): %v", err)
	}
	if entries != nil {
		t.Error("DeleteConversation: deleted conversation still exists (GetConversation returned entries)")
	}

	// PR-003: Use public API to verify scope1 still exists.
	entries, err = vault.GetConversation(context.Background(), scope1)
	if err != nil {
		t.Fatalf("GetConversation(scope1): %v", err)
	}
	if len(entries) == 0 {
		t.Error("DeleteConversation: kept conversation disappeared (GetConversation returned nil/empty)")
	}
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
		if v != '8' && v != '9' && v != 'a' && v != 'b' && v != 'A' && v != 'B' {
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
	defer func() { _ = db.Close() }()

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
	var restored Metadata
	if err := json.Unmarshal(data, &restored); err != nil {
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

// =============================================================================
// PR-108: End-to-end restart round-trip test
// =============================================================================

// TestRestartRoundTrip verifies AC-1 across sessions:
// New→persist→close→reopen→retrieve (PR-108).
func TestRestartRoundTrip(t *testing.T) {
	dir := t.TempDir()

	keyPath := filepath.Join(dir, "vault.key")
	dbPath := filepath.Join(dir, "vault.db")

	// ── Session 1: Create, write, close ──
	cryptoService1, err := crypto.New(keyPath)
	if err != nil {
		t.Fatalf("crypto.New: %v", err)
	}

	db1, err := bolt.Open(dbPath, 0600, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		_ = cryptoService1.Close()
		t.Fatalf("bolt.Open: %v", err)
	}
	if upErr := db1.Update(func(tx *bolt.Tx) error {
		_, bktErr := tx.CreateBucketIfNotExists([]byte(BucketTokens))
		return bktErr
	}); upErr != nil {
		_ = db1.Close()
		_ = cryptoService1.Close()
		t.Fatalf("create bucket: %v", upErr)
	}

	vault1, err := New(db1, cryptoService1, 1*time.Hour, testLogger())
	if err != nil {
		_ = db1.Close()
		_ = cryptoService1.Close()
		t.Fatalf("New: %v", err)
	}
	ctx1, cancel1 := context.WithCancel(context.Background())
	defer cancel1()
	vault1.Run(ctx1)

	scope := Scope{Provider: "chatgpt", ConversationID: "roundtrip-conv-001"}
	expectedValues := map[string]string{
		"<<EMAIL_1>>": "alice@example.com",
		"<<PHONE_1>>": "+33123456789",
		"<<IBAN_1>>":  "FR7612345678901234567890123",
	}

	for token, piiValue := range expectedValues {
		vault1.Persist(scope, token, []byte(piiValue))
	}

	// Wait for writes to flush, then close session 1.
	time.Sleep(200 * time.Millisecond)
	vault1.Close()
	// Close() already cancels context internally — no separate cancel1() needed.

	// ── Session 2: Reopen and retrieve ──
	cryptoService2, err := crypto.New(keyPath) // reopens existing key
	if err != nil {
		t.Fatalf("crypto.New (session 2): %v", err)
	}
	defer func() { _ = cryptoService2.Close() }()

	db2, err := bolt.Open(dbPath, 0600, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		t.Fatalf("bolt.Open (session 2): %v", err)
	}
	defer func() { _ = db2.Close() }()

	vault2, err := New(db2, cryptoService2, 1*time.Hour, testLogger())
	if err != nil {
		t.Fatalf("New (session 2): %v", err)
	}
	defer vault2.Close()

	// Retrieve entries via GetConversation (PR-002).
	entries, err := vault2.GetConversation(context.Background(), scope)
	if err != nil {
		t.Fatalf("GetConversation: %v", err)
	}

	if len(entries) != len(expectedValues) {
		t.Fatalf("PR-108 FAIL: expected %d entries, got %d", len(expectedValues), len(entries))
	}

	found := make(map[string]string)
	for _, e := range entries {
		found[e.Token] = string(e.Value)
	}

	for token, expectedValue := range expectedValues {
		if found[token] != expectedValue {
			t.Errorf("PR-108 FAIL: token %q = %q, expected %q", token, found[token], expectedValue)
		}
	}

	// Also verify metadata was automatically created with correct counts.
	convs, err := vault2.ListConversations(context.Background())
	if err != nil {
		t.Fatalf("ListConversations: %v", err)
	}
	if len(convs) != 1 {
		t.Fatalf("PR-108 FAIL: expected 1 active conversation after reopen, got %d", len(convs))
	}
	meta := convs[0]
	if meta.PIICount != len(expectedValues) {
		t.Errorf("PR-108 FAIL: metadata pii_count = %d, expected %d", meta.PIICount, len(expectedValues))
	}
	if len(meta.PIITypes) != 3 { // EMAIL, PHONE, IBAN
		t.Errorf("PR-108 FAIL: metadata pii_types count = %d, expected 3", len(meta.PIITypes))
	}
}

// =============================================================================
// PR-001: Metadata integrity test (AC-13)
// =============================================================================

func TestMetadataAutoUpdate(t *testing.T) {
	vault, cleanup := setupTestVault(t, 1*time.Hour)
	defer cleanup()

	scope := Scope{Provider: "chatgpt", ConversationID: "meta-auto-conv"}

	// Persist tokens of different types.
	vault.Persist(scope, "<<EMAIL_1>>", []byte("alice@example.com"))
	vault.Persist(scope, "<<EMAIL_2>>", []byte("bob@example.com")) // same type, count++
	vault.Persist(scope, "<<PHONE_1>>", []byte("+33123456789"))
	vault.Persist(scope, "<<IBAN_1>>", []byte("FR7612345678901234567890123"))

	time.Sleep(200 * time.Millisecond)

	// Retrieve metadata.
	convs, err := vault.ListConversations(context.Background())
	if err != nil {
		t.Fatalf("ListConversations: %v", err)
	}
	if len(convs) != 1 {
		t.Fatalf("expected 1 conversation, got %d", len(convs))
	}
	meta := convs[0]

	if meta.PIICount != 4 {
		t.Errorf("PR-001 FAIL: pii_count = %d, expected 4", meta.PIICount)
	}
	if len(meta.PIITypes) != 3 { // EMAIL, PHONE, IBAN (deduplicated)
		t.Errorf("PR-001 FAIL: pii_types count = %d, expected 3", len(meta.PIITypes))
	}
	if meta.UpdatedAt < meta.CreatedAt {
		t.Error("PR-001 FAIL: updated_at should be >= created_at after writes")
	}
	if meta.Status != StatusActive {
		t.Errorf("PR-001 FAIL: expected status active, got %q", meta.Status)
	}
}

// =============================================================================
// PR-002: GetConversation access-time TTL check (AC-3)
// =============================================================================

func TestGetConversationReturnsEntries(t *testing.T) {
	vault, cleanup := setupTestVault(t, 1*time.Hour)
	defer cleanup()

	scope := Scope{Provider: "chatgpt", ConversationID: "get-conv-001"}
	vault.Persist(scope, "<<EMAIL_1>>", []byte("alice@example.com"))
	vault.Persist(scope, "<<PHONE_1>>", []byte("+33123456789"))

	time.Sleep(200 * time.Millisecond)

	entries, err := vault.GetConversation(context.Background(), scope)
	if err != nil {
		t.Fatalf("GetConversation: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("PR-002 FAIL: expected 2 entries, got %d", len(entries))
	}

	for _, e := range entries {
		if e.Token == "" || len(e.Value) == 0 || e.Type == "" {
			t.Errorf("PR-002 FAIL: incomplete entry: token=%q type=%q len(value)=%d",
				e.Token, e.Type, len(e.Value))
		}
	}
}

func TestGetConversationAutoPurgeExpired(t *testing.T) {
	vault, cleanup := setupTestVault(t, 1*time.Millisecond)
	defer cleanup()

	scope := Scope{Provider: "chatgpt", ConversationID: "get-conv-expired"}
	vault.Persist(scope, "<<EMAIL_1>>", []byte("expire-me@example.com"))

	time.Sleep(200 * time.Millisecond)

	// Access-time check: GetConversation should detect expiry and auto-purge.
	entries, err := vault.GetConversation(context.Background(), scope)
	if err != nil {
		t.Fatalf("GetConversation: %v", err)
	}
	if entries != nil {
		t.Errorf("PR-002 FAIL: expected nil entries for expired conversation, got %d", len(entries))
	}

	// Verify the conversation was actually deleted.
	convs, err := vault.ListConversations(context.Background())
	if err != nil {
		t.Fatalf("ListConversations: %v", err)
	}
	if len(convs) != 0 {
		t.Errorf("PR-002 FAIL: expected 0 conversations after auto-purge, got %d", len(convs))
	}
}

func TestGetConversationNotFound(t *testing.T) {
	vault, cleanup := setupTestVault(t, 1*time.Hour)
	defer cleanup()

	scope := Scope{Provider: "chatgpt", ConversationID: "nonexistent"}
	entries, err := vault.GetConversation(context.Background(), scope)
	if err != nil {
		t.Fatalf("GetConversation: %v", err)
	}
	if entries != nil {
		t.Errorf("PR-002 FAIL: expected nil entries for nonexistent conversation")
	}
}

// =============================================================================
// Test provider validation (PR-106)
// =============================================================================

func TestProviderRejectsSlash(t *testing.T) {
	vault, cleanup := setupTestVault(t, 1*time.Hour)
	defer cleanup()

	// Persist with a provider name containing "/" should be rejected.
	scope := Scope{Provider: "azure/openai", ConversationID: "test-slash"}
	vault.Persist(scope, "<<EMAIL_1>>", []byte("test@example.com"))

	time.Sleep(100 * time.Millisecond)

	// Verify nothing was written.
	convs, err := vault.ListConversations(context.Background())
	if err != nil {
		t.Fatalf("ListConversations: %v", err)
	}
	if len(convs) > 0 {
		t.Errorf("PR-106 FAIL: expected 0 conversations for rejected provider, got %d", len(convs))
	}
}

// =============================================================================
// Test extractPIIType
// =============================================================================

func TestExtractPIIType(t *testing.T) {
	tests := []struct {
		token    string
		expected string
		valid    bool
	}{
		{"<<EMAIL_1>>", "EMAIL", true},
		{"<<PHONE_42>>", "PHONE", true},
		{"<<CREDIT_CARD_3>>", "CREDIT_CARD", true},
		{"<<IBAN_1>>", "IBAN", true},
		{"", "", false},
		{"not-a-token", "", false},
		{"<<MISSING_CLOSE", "", false},
		{"<INVALID_1>>", "", false},
		{"<<NO_NUMBER>>", "", false},
	}

	for _, tc := range tests {
		result, ok := extractPIIType(tc.token)
		if ok != tc.valid {
			t.Errorf("extractPIIType(%q): expected valid=%v, got valid=%v", tc.token, tc.valid, ok)
		}
		if ok && result != tc.expected {
			t.Errorf("extractPIIType(%q): expected %q, got %q", tc.token, tc.expected, result)
		}
	}
}
