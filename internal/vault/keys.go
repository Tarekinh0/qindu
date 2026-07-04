package vault

import (
	"crypto/rand"
	"fmt"
	"strings"
)

// metaKeySuffix is the suffix appended to conversation scopes to form the
// __meta__ key in bbolt. This key stores per-conversation metadata as
// plaintext JSON (no PII values).
const metaKeySuffix = "__meta__"

// BucketTokens is the bbolt bucket name for the vault's encrypted PII store.
// Exported so external callers (e.g., proxy init) can create the bucket
// with the correct name.
const BucketTokens = "tokens"

// conversationKey builds a bbolt key for a token within a conversation.
// Format: {provider}/{uuid}/{token}
func conversationKey(scope Scope, token string) string {
	return scope.Provider + "/" + scope.ConversationID + "/" + token
}

// scopePrefix builds a bbolt key prefix for all entries in a conversation.
// Format: {provider}/{uuid}/
func scopePrefix(scope Scope) string {
	return scope.Provider + "/" + scope.ConversationID + "/"
}

// NewConversationID generates a version-4 UUID using crypto/rand.
// The UUID carries no semantic information and cannot be correlated
// to the user, machine, or provider's conversation ID.
//
// This function provides consistent UUID generation for both interceptor
// and tokenizer packages, enabling vault-independent conversation ID
// creation per DD-8.
func NewConversationID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("vault: failed to generate UUID: %w", err)
	}
	// Set version (4) and variant (RFC 9562).
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10xx

	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// extractPIIType extracts the PII entity type from a token string.
// Tokens follow the format <<TYPE_N>> (e.g., "<<EMAIL_1>>", "<<CREDIT_CARD_3>>").
// Returns the type and true, or empty string and false if the format is unexpected.
func extractPIIType(token string) (string, bool) {
	if !strings.HasPrefix(token, "<<") || !strings.HasSuffix(token, ">>") {
		return "", false
	}
	inner := token[2 : len(token)-2] // strip << and >>
	// Find the last underscore before the counter.
	lastUnderscore := strings.LastIndex(inner, "_")
	if lastUnderscore < 0 {
		return "", false
	}
	// Verify the suffix after the last underscore is numeric.
	for _, ch := range inner[lastUnderscore+1:] {
		if ch < '0' || ch > '9' {
			return "", false
		}
	}
	return inner[:lastUnderscore], true
}
