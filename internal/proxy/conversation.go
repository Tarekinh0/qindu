package proxy

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

// uuidPattern matches a standard UUID v4/v7 format anchored to path boundaries.
// Linear-time regex, no backtracking vulnerabilities (SR-CISO-2).
// Format: 8-4-4-4-12 hex digits with hyphens, surrounded by / or string boundaries.
var uuidPattern = regexp.MustCompile(`(?:^|/)([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})(?:/|$)`)

// maxPathLenForUUID is the maximum path length to search for a conversation UUID.
// Defense-in-depth beyond HTTP server limits (SR-CISO-1, SR-CISO-2).
const maxPathLenForUUID = 2048

// deriveConversationID extracts a conversation UUID from the URL path,
// hashes it with SHA-256 for the vault scope, and returns the hex-encoded hash.
//
// Flow:
//  1. Validate the path (NUL bytes, control characters, length) — SR-CISO-2.
//  2. Search for a UUID pattern in the path.
//  3. If found: SHA-256 hash the lowercase UUID → hex string.
//  4. If not found: generate a random UUID v4 via crypto/rand → use as-is.
//
// Returns the conversation ID string (SHA-256 hex hash or random UUID).
// Never returns an empty string.
//
// SR-CISO-1: Uses SHA-256 (crypto/sha256) for deterministic scope derivation.
// SR-CISO-2: Validates path before extraction, caps path length, uses linear-time regex.
func deriveConversationID(urlPath string) string {
	// Validate path: reject NUL bytes and control characters (SR-CISO-2).
	if strings.IndexByte(urlPath, 0) >= 0 {
		return randomUUIDv4()
	}
	for _, r := range urlPath {
		if r < 0x20 && r != '\t' && r != '\n' && r != '\r' {
			return randomUUIDv4()
		}
	}

	// Cap path length for UUID extraction (SR-CISO-1).
	searchPath := urlPath
	if len(searchPath) > maxPathLenForUUID {
		searchPath = searchPath[:maxPathLenForUUID]
	}

	// Search for UUID pattern (SR-CISO-2: linear-time regex, no backtracking).
	// The regex has a capture group for the UUID, anchored to path boundaries
	// to prevent matching hex substrings in non-UUID contexts.
	submatch := uuidPattern.FindStringSubmatch(searchPath)
	if len(submatch) < 2 {
		return randomUUIDv4()
	}
	match := submatch[1] // the UUID capture group

	// Validate the extracted UUID: must be exactly 36 characters (8-4-4-4-12).
	if len(match) != 36 {
		return randomUUIDv4()
	}

	// Hash with SHA-256 for deterministic vault scope (SR-CISO-1).
	hashed := sha256.Sum256([]byte(strings.ToLower(match)))
	return hex.EncodeToString(hashed[:])
}

// vaultScopeKey returns the vault scope key: "{Provider}:{ConversationID}".
// Used as the conversation lookup key in the vault (SR-CISO-1).
func vaultScopeKey(provider, conversationID string) string {
	return fmt.Sprintf("%s:%s", provider, conversationID)
}

// randomUUIDv4 generates a random UUID v4 using crypto/rand.
// Returns a string in standard UUID format (8-4-4-4-12).
func randomUUIDv4() string {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		// crypto/rand.Read can fail only on broken systems.
		// Fall back to a deterministic zero-filled UUID as last resort.
		return "00000000-0000-4000-8000-000000000000"
	}
	// Set version 4 bits.
	buf[6] = (buf[6] & 0x0f) | 0x40
	// Set variant bits.
	buf[8] = (buf[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		buf[0:4], buf[4:6], buf[6:8], buf[8:10], buf[10:16])
}
