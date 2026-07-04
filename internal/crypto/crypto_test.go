package crypto

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// tempKeyPath returns a temporary path for vault.key in a test directory.
func tempKeyPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "vault.key")
}

// =============================================================================
// T-801: Nonce uniqueness (SR-801)
// =============================================================================

func TestNonceUniqueness(t *testing.T) {
	svc, err := New(tempKeyPath(t))
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	defer func() { _ = svc.Close() }()

	nonces := make(map[[nonceSize]byte]bool)
	const count = 10000

	for i := 0; i < count; i++ {
		plaintext := []byte("test data " + string(rune('0'+i%10)))
		ciphertext, err := svc.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("encrypt %d: %v", i, err)
		}
		if len(ciphertext) < nonceSize {
			t.Fatalf("ciphertext too short at %d: %d < %d", i, len(ciphertext), nonceSize)
		}
		var n [nonceSize]byte
		copy(n[:], ciphertext[:nonceSize])
		if nonces[n] {
			t.Errorf("T-801 FAIL: nonce collision at iteration %d", i)
		}
		nonces[n] = true
	}

	if len(nonces) != count {
		t.Errorf("T-801 FAIL: expected %d unique nonces, got %d", count, len(nonces))
	}
}

// =============================================================================
// T-802 / T16: Encrypt/decrypt round-trip (SR-801)
// =============================================================================

func TestEncryptDecryptRoundtrip(t *testing.T) {
	svc, err := New(tempKeyPath(t))
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	defer func() { _ = svc.Close() }()

	cases := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"single byte", []byte("x")},
		{"typical email", []byte("alice@example.com")},
		{"typical 200 bytes", bytes.Repeat([]byte("a"), 200)},
		{"large 4KB", bytes.Repeat([]byte("b"), 4096)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ct, err := svc.Encrypt(tc.data)
			if err != nil {
				t.Fatalf("Encrypt: %v", err)
			}

			// Ciphertext should be longer than plaintext (nonce + tag).
			if len(ct) < nonceSize+16 {
				t.Errorf("ciphertext too short: %d bytes (nonce+min.tag=28)", len(ct))
			}

			pt, err := svc.Decrypt(ct)
			if err != nil {
				t.Fatalf("Decrypt: %v", err)
			}

			if !bytes.Equal(pt, tc.data) {
				t.Errorf("round-trip mismatch: got %v, want %v", pt, tc.data)
			}
		})
	}
}

// =============================================================================
// T-802 / T17: Tampered ciphertext must fail decryption
// =============================================================================

func TestDecryptTampered(t *testing.T) {
	svc, err := New(tempKeyPath(t))
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	defer func() { _ = svc.Close() }()

	plaintext := []byte("sensitive data")
	ct, err := svc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Flip a bit in the tag area (last byte).
	tampered := make([]byte, len(ct))
	copy(tampered, ct)
	tampered[len(tampered)-1] ^= 0x01

	_, err = svc.Decrypt(tampered)
	if err == nil {
		t.Error("T-802/T17 FAIL: expected decryption failure for tampered ciphertext")
	}

	// Flip a bit in the nonce.
	tampered2 := make([]byte, len(ct))
	copy(tampered2, ct)
	tampered2[0] ^= 0x01

	_, err = svc.Decrypt(tampered2)
	if err == nil {
		t.Error("expected decryption failure for tampered nonce")
	}
}

// =============================================================================
// T-805: Key file permissions (Unix 0600)
// =============================================================================

func TestKeyFileCreatedWith0600(t *testing.T) {
	path := tempKeyPath(t)
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
// T-806: Pre-existing wide permissions key file → error
// =============================================================================

func TestKeyFileRejectsWidePermissions(t *testing.T) {
	path := tempKeyPath(t)
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

// =============================================================================
// T-812: Key generation entropy — 100 keys must be unique
// =============================================================================

func TestKeyGenerationEntropy(t *testing.T) {
	keys := make(map[[KeySize]byte]bool)
	for i := 0; i < 100; i++ {
		path := tempKeyPath(t)
		svc, err := New(path)
		if err != nil {
			t.Fatalf("New %d: %v", i, err)
		}

		var k [KeySize]byte
		copy(k[:], svc.key)
		if keys[k] {
			t.Errorf("T-812 FAIL: duplicate key at iteration %d (astronomically unlikely)", i)
		}
		keys[k] = true
		_ = svc.Close()
	}

	if len(keys) != 100 {
		t.Errorf("T-812 FAIL: expected 100 unique keys, got %d", len(keys))
	}
}

// =============================================================================
// T-812 / DPO-R6: Key must be exactly 32 bytes
// =============================================================================

func TestKeyRejectsWrongSize(t *testing.T) {
	path := tempKeyPath(t)

	// Write a 16-byte key (too short).
	if err := os.WriteFile(path, bytes.Repeat([]byte{0x42}, 16), 0600); err != nil {
		t.Fatalf("setup: %v", err)
	}

	_, err := New(path)
	if err == nil {
		t.Error("expected error for 16-byte key")
	}

	// Write a 64-byte key (too long).
	if writeErr := os.WriteFile(path, bytes.Repeat([]byte{0x42}, 64), 0600); writeErr != nil {
		t.Fatalf("setup: %v", writeErr)
	}

	_, err = New(path)
	if err == nil {
		t.Error("expected error for 64-byte key")
	}
}

// =============================================================================
// DPO-R6: Decrypt with wrong key must fail
// =============================================================================

func TestDecryptWrongKey(t *testing.T) {
	svc1, err := New(tempKeyPath(t))
	if err != nil {
		t.Fatalf("New svc1: %v", err)
	}
	defer func() { _ = svc1.Close() }()

	svc2, err := New(tempKeyPath(t))
	if err != nil {
		t.Fatalf("New svc2: %v", err)
	}
	defer func() { _ = svc2.Close() }()

	ct, err := svc1.Encrypt([]byte("secret"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	_, err = svc2.Decrypt(ct)
	if err == nil {
		t.Error("DPO-R6 FAIL: expected decryption failure with wrong key")
	}
}

// =============================================================================
// DPO-R6: Test ciphertext too short error
// =============================================================================

func TestDecryptTooShort(t *testing.T) {
	svc, err := New(tempKeyPath(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = svc.Close() }()

	_, err = svc.Decrypt([]byte{})
	if err == nil {
		t.Error("expected error for empty ciphertext")
	}

	_, err = svc.Decrypt([]byte{0x00, 0x01}) // 2 bytes, too short for nonce
	if err == nil {
		t.Error("expected error for 2-byte ciphertext")
	}
}

// =============================================================================
// Key zeroing on Close: after Close, key material is zeroed
// =============================================================================

func TestKeyZeroedOnClose(t *testing.T) {
	svc, err := New(tempKeyPath(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if svc.key == nil || len(svc.key) != KeySize {
		t.Fatalf("key not initialized")
	}

	// Verify key is non-zero before close.
	allZero := true
	for _, b := range svc.key {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Fatal("key should be non-zero random bytes before Close")
	}

	_ = svc.Close()

	// Verify key is nil'd.
	if svc.key != nil {
		t.Error("key should be nil after Close")
	}
}

// =============================================================================
// Verify that Encrypt produces distinct ciphertexts for same plaintext
// =============================================================================

func TestEncryptDistinctCiphertexts(t *testing.T) {
	svc, err := New(tempKeyPath(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = svc.Close() }()

	plaintext := []byte("same data")
	seen := make(map[string]bool)

	for i := 0; i < 100; i++ {
		ct, err := svc.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("Encrypt %d: %v", i, err)
		}
		s := string(ct)
		if seen[s] {
			t.Errorf("duplicate ciphertext at iteration %d (nonce reuse!)", i)
		}
		seen[s] = true
	}
}
