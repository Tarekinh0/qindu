package vault

// Scope identifies a conversation within the vault.
// It combines the AI provider name and a proxy-generated UUID.
type Scope struct {
	Provider       string // lowercase provider name (e.g., "chatgpt")
	ConversationID string // proxy-generated UUID v4
}

// TokenPersister is the interface for persistent token↔PII storage.
// It is injected into the Tokenizer as an optional subscriber.
// Implementations must be safe for concurrent use.
//
// The Store interface in internal/tokenize remains unchanged —
// TokenPersister is a separate, parallel subscriber that receives
// token assignments asynchronously for persistence.
type TokenPersister interface {
	// Persist stores a token→value mapping for a given conversation scope.
	// Implementations must encrypt the value before writing to disk.
	// Must not block the caller — writes should be asynchronous.
	// Fire-and-forget: errors are handled internally by the implementation
	// (logged) and never propagated to the proxy (DD-10).
	Persist(scope Scope, token string, value []byte)

	// UpdateMeta updates the metadata for a conversation scope.
	// Called to update pii_count, pii_types, updated_at, etc.
	UpdateMeta(scope Scope, meta Metadata)
}
