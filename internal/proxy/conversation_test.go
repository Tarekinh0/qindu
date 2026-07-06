package proxy

import (
	"strings"
	"testing"
)

// TestDeriveConversationID_ChatGPTURLPath verifies UUID extraction
// from a standard ChatGPT conversation URL path.
func TestDeriveConversationID_ChatGPTURLPath(t *testing.T) {
	convID := deriveConversationID("/backend-api/conversation/550e8400-e29b-41d4-a716-446655440000")
	if convID == "" {
		t.Fatal("deriveConversationID returned empty string")
	}

	// The SHA-256 hash in hex should be 64 characters.
	if len(convID) != 64 {
		t.Errorf("expected SHA-256 hex hash (64 chars), got %d chars: %s", len(convID), convID)
	}

	// Verify it's all hex characters.
	for _, c := range convID {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("conversation ID contains non-hex character: %c in %s", c, convID)
		}
	}
}

// TestDeriveConversationID_NonConversationPath verifies fallback to random UUID
// for paths without a conversation UUID.
func TestDeriveConversationID_NonConversationPath(t *testing.T) {
	// Path with no UUID.
	convID := deriveConversationID("/api/chat/completions")
	if convID == "" {
		t.Fatal("deriveConversationID returned empty string for non-conversation path")
	}

	// For non-conversation paths, we get a random UUID v4 (36 chars).
	if len(convID) != 36 {
		t.Errorf("expected random UUID v4 (36 chars), got %d chars: %s", len(convID), convID)
	}

	// Verify it's a valid UUID format.
	parts := strings.Split(convID, "-")
	if len(parts) != 5 {
		t.Errorf("expected UUID format (5 dash-separated parts), got: %s", convID)
	}
}

// TestDeriveConversationID_DeterministicSameUUID verifies that the same
// UUID in the URL path produces the same hash.
func TestDeriveConversationID_DeterministicSameUUID(t *testing.T) {
	uuid := "550e8400-e29b-41d4-a716-446655440000"
	path := "/backend-api/conversation/" + uuid

	id1 := deriveConversationID(path)
	id2 := deriveConversationID(path)

	if id1 != id2 {
		t.Errorf("same UUID should produce identical hash: %s vs %s", id1, id2)
	}
}

// TestDeriveConversationID_DifferentUUIDsDifferentHashes verifies
// that different UUIDs produce different hashes.
func TestDeriveConversationID_DifferentUUIDsDifferentHashes(t *testing.T) {
	uuid1 := "550e8400-e29b-41d4-a716-446655440000"
	uuid2 := "660e8400-e29b-41d4-a716-446655440001"
	path1 := "/backend-api/conversation/" + uuid1
	path2 := "/backend-api/conversation/" + uuid2

	id1 := deriveConversationID(path1)
	id2 := deriveConversationID(path2)

	if id1 == id2 {
		t.Error("different UUIDs should produce different hashes")
	}
}

// TestDeriveConversationID_EmptyPath verifies fallback for empty path.
func TestDeriveConversationID_EmptyPath(t *testing.T) {
	convID := deriveConversationID("")
	if convID == "" {
		t.Fatal("deriveConversationID returned empty string for empty path")
	}
	if len(convID) != 36 {
		t.Errorf("expected random UUID v4 (36 chars) for empty path, got %d chars", len(convID))
	}
}

// TestDeriveConversationID_MalformedUUID verifies fallback for malformed paths.
func TestDeriveConversationID_MalformedUUID(t *testing.T) {
	// Path with something that looks like a UUID but is too short.
	convID := deriveConversationID("/conversation/abc-123")
	if convID == "" {
		t.Fatal("deriveConversationID returned empty for malformed path")
	}
	// Should fall back to random UUID (36 chars).
	if len(convID) != 36 {
		t.Errorf("expected random UUID v4 fallback, got %d chars", len(convID))
	}
}

// TestDeriveConversationID_NULBytePath verifies rejection of paths with NUL bytes.
func TestDeriveConversationID_NULBytePath(t *testing.T) {
	// Path containing NUL byte should fall back to random UUID.
	convID := deriveConversationID("/conversation/\x00550e8400-e29b-41d4-a716-446655440000")
	if convID == "" {
		t.Fatal("deriveConversationID returned empty for NUL byte path")
	}
	if len(convID) != 36 {
		t.Errorf("NUL byte path should fall back to random UUID, got %d chars", len(convID))
	}
}

// TestDeriveConversationID_LongPath verifies that extremely long paths
// are handled safely (bounded to maxPathLenForUUID).
func TestDeriveConversationID_LongPath(t *testing.T) {
	longPath := "/conversation/" + strings.Repeat("x", 5000)
	convID := deriveConversationID(longPath)
	if convID == "" {
		t.Fatal("deriveConversationID returned empty for long path")
	}
	// Should fall back to random UUID since no valid UUID in the first 2048 bytes.
	if len(convID) != 36 {
		t.Errorf("expected random UUID fallback for long path, got %d chars", len(convID))
	}
}

// TestDeriveConversationID_CaseInsensitiveUUID verifies UUID extraction
// is case-insensitive.
func TestDeriveConversationID_CaseInsensitiveUUID(t *testing.T) {
	uuid := "550E8400-E29B-41D4-A716-446655440000"
	path := "/backend-api/conversation/" + uuid

	convID := deriveConversationID(path)
	if convID == "" || len(convID) != 64 {
		t.Errorf("expected SHA-256 hash for uppercase UUID, got %d chars", len(convID))
	}
}

// TestDeriveConversationID_ControlCharacters verifies paths with control
// characters fall back to random UUID.
func TestDeriveConversationID_ControlCharacters(t *testing.T) {
	convID := deriveConversationID("/conversation/\x01550e8400-e29b-41d4-a716-446655440000")
	if convID == "" {
		t.Fatal("deriveConversationID returned empty for control char path")
	}
	if len(convID) != 36 {
		t.Errorf("control char path should fall back to random UUID, got %d chars", len(convID))
	}
}

// TestVaultScopeKey verifies the vault scope key format.
func TestVaultScopeKey(t *testing.T) {
	key := vaultScopeKey("chatgpt", "abc123")
	if key != "chatgpt:abc123" {
		t.Errorf("vaultScopeKey = %q, want %q", key, "chatgpt:abc123")
	}
}

// TestRandomUUIDv4_Uniqueness verifies random UUIDs are unique.
func TestRandomUUIDv4_Uniqueness(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 1000; i++ {
		u := randomUUIDv4()
		if seen[u] {
			t.Errorf("duplicate UUID generated: %s", u)
		}
		seen[u] = true
	}
}

// TestRandomUUIDv4_Format verifies random UUID v4 format.
func TestRandomUUIDv4_Format(t *testing.T) {
	u := randomUUIDv4()
	parts := strings.Split(u, "-")
	if len(parts) != 5 {
		t.Errorf("expected 5 parts, got %d: %s", len(parts), u)
	}
	if len(parts[0]) != 8 || len(parts[1]) != 4 || len(parts[2]) != 4 ||
		len(parts[3]) != 4 || len(parts[4]) != 12 {
		t.Errorf("invalid UUID part lengths: %s", u)
	}
	// Version 4: the 13th character (first char of 3rd part) should be '4'.
	if parts[2][0] != '4' {
		t.Errorf("UUID v4 should have version '4' at position 13, got: %s", u)
	}
}
