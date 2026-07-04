package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	bolt "go.etcd.io/bbolt"
)

// ListConversations returns metadata for all active (non-expired) conversations.
// Expired conversations are filtered from the result; actual deletion is handled
// by the sweeper.
// Does NOT decrypt or return PII values.
// Respects context cancellation.
func (v *Vault) ListConversations(ctx context.Context) ([]Metadata, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	var results []Metadata

	err := v.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(BucketTokens))
		if b == nil {
			return nil
		}

		c := b.Cursor()
		for k, val := c.First(); k != nil; k, val = c.Next() {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			if !strings.HasSuffix(string(k), "/"+metaKeySuffix) {
				continue
			}

			var meta Metadata
			if err := json.Unmarshal(val, &meta); err != nil {
				continue
			}

			// Filter expired conversations (access-time check layer).
			if isExpired(meta.CreatedAt, v.ttl) {
				continue
			}

			results = append(results, meta)
		}
		return nil
	})

	return results, err
}

// GetConversation retrieves all decrypted token→value entries for a conversation.
// On access, checks TTL: if the conversation has expired, it is auto-purged and
// nil is returned (AC-3 access-time TTL enforcement).
//
// The three-transaction design (View meta → Update delete if expired → View
// entries) is eventually consistent: between the metadata check and the entry
// read, the background sweeper or another goroutine may delete the conversation.
// In that case, step 3 returns an empty slice — harmless, but worth noting.
//
// Respects context cancellation.
func (v *Vault) GetConversation(ctx context.Context, scope Scope) ([]TokenEntry, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// Step 1: Read __meta__ and check expiry.
	metaKey := conversationKey(scope, metaKeySuffix)
	var meta Metadata
	metaExists := false

	if err := v.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(BucketTokens))
		if b == nil {
			return nil
		}
		if raw := b.Get([]byte(metaKey)); raw != nil {
			if err := json.Unmarshal(raw, &meta); err == nil {
				metaExists = true
			}
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("vault: GetConversation metadata read: %w", err)
	}

	if !metaExists {
		return nil, nil // conversation not found
	}

	// Step 2: If expired, auto-purge the entire conversation.
	if isExpired(meta.CreatedAt, v.ttl) {
		if err := v.DeleteConversation(ctx, scope); err != nil {
			v.logger.Error("vault: auto-purge on access failed",
				"provider", scope.Provider,
				"error", err,
				"pii_values_logged", false,
			)
		}
		return nil, nil // expired → not found
	}

	// Step 3: Read and decrypt all token entries.
	prefix := scopePrefix(scope)
	var entries []TokenEntry

	err := v.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(BucketTokens))
		if b == nil {
			return nil
		}

		c := b.Cursor()
		for k, val := c.Seek([]byte(prefix)); k != nil && strings.HasPrefix(string(k), prefix); k, val = c.Next() {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			keyStr := string(k)
			// Skip the __meta__ key.
			if strings.HasSuffix(keyStr, "/"+metaKeySuffix) {
				continue
			}

			// Decrypt the value.
			decrypted, err := v.crypto.Decrypt(val)
			if err != nil {
				v.logger.Warn("vault: failed to decrypt entry, skipping",
					"key", keyStr,
					"error", err,
					"pii_values_logged", false,
				)
				continue
			}

			// Extract token from key (last component after the last /).
			token := keyStr[strings.LastIndex(keyStr, "/")+1:]
			piiType, _ := extractPIIType(token)

			entries = append(entries, TokenEntry{
				Token: token,
				Value: decrypted,
				Type:  piiType,
			})
		}
		return nil
	})

	return entries, err
}
