// Package vault provides encrypted persistent storage for token↔PII mappings
// using bbolt as the storage backend and AES-256-GCM for encryption.
package vault

import (
	"encoding/json"
	"time"
)

// Status represents the lifecycle state of a conversation.
type Status string

const (
	StatusActive  Status = "active"
	StatusExpired Status = "expired"
	StatusPurged  Status = "purged"
)

// Metadata stores per-conversation metadata in plaintext JSON
// under the __meta__ key. This enables efficient TTL enforcement
// and UI browsing without decrypting every value.
//
// No PII values are stored in metadata — only aggregate information
// (counts, types, timestamps, provider name).
type Metadata struct {
	CreatedAt      int64    `json:"created_at"`      // Unix timestamp (seconds)
	UpdatedAt      int64    `json:"updated_at"`      // Unix timestamp (seconds)
	Provider       string   `json:"provider"`        // Lowercase provider name
	ConversationID string   `json:"conversation_id"` // Provider's real conv ID (populated in QINDU-0011)
	Label          string   `json:"label"`           // User-assigned label (QINDU-0011)
	PIICount       int      `json:"pii_count"`       // Total number of PII tokens
	PIITypes       []string `json:"pii_types"`       // Deduplicated entity types
	Status         Status   `json:"status"`          // active | expired | purged
}

// NewMetadata creates Metadata for a new conversation scope.
func NewMetadata(provider string) Metadata {
	now := time.Now().Unix()
	return Metadata{
		CreatedAt: now,
		UpdatedAt: now,
		Provider:  provider,
		Status:    StatusActive,
		PIITypes:  []string{},
	}
}

// MarshalJSON serializes metadata to JSON bytes.
func (m Metadata) MarshalJSON() ([]byte, error) {
	type alias Metadata // avoid infinite recursion
	return json.Marshal((*alias)(&m))
}

// UnmarshalMetadata parses JSON bytes into Metadata.
func UnmarshalMetadata(data []byte) (Metadata, error) {
	var m Metadata
	if err := json.Unmarshal(data, &m); err != nil {
		return Metadata{}, err
	}
	return m, nil
}
