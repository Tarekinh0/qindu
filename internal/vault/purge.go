package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"
)

// sweeperLoop periodically scans all __meta__ keys and purges expired conversations.
// Interval: min(ttl/7, 24h), minimum 1h.
func (v *Vault) sweeperLoop() {
	defer v.wg.Done()

	interval := sweepInterval(v.ttl)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	v.logger.Info("vault background sweeper started",
		"interval", interval.String(),
		"pii_values_logged", false,
	)

	for {
		select {
		case <-ticker.C:
			v.logger.Info("vault sweep: starting background sweep",
				"pii_values_logged", false,
			)
			purged, err := v.PurgeExpired(v.ctx)
			if err != nil {
				v.logger.Error("vault sweep: error during background sweep",
					"error", err,
					"pii_values_logged", false,
				)
			} else {
				v.logger.Info("vault sweep: purged N expired conversations",
					"purged_count", purged,
					"pii_values_logged", false,
				)
			}

		case <-v.ctx.Done():
			v.logger.Info("vault background sweeper stopped",
				"pii_values_logged", false,
			)
			return
		}
	}
}

// sweepExpired is the startup sweep: purges all expired conversations.
// Uses a caller-provided context; a timeout is applied in New() to prevent
// startup sweeps from blocking agent initialization indefinitely.
func (v *Vault) sweepExpired(ctx context.Context) error {
	_, err := v.PurgeExpired(ctx)
	return err
}

// PurgeExpired removes all conversations where now - created_at > ttl.
// Returns the count of purged conversations.
// Respects context cancellation: checks ctx.Err() before the transaction
// and between cursor iterations.
func (v *Vault) PurgeExpired(ctx context.Context) (int, error) {
	if v.ttl <= 0 {
		return 0, nil // infinite TTL, nothing to purge
	}

	// Check context before starting expensive operation.
	if err := ctx.Err(); err != nil {
		return 0, err
	}

	purged := 0
	err := v.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(BucketTokens))
		if b == nil {
			return nil
		}

		// Find all __meta__ keys and check their creation time.
		var expiredPrefixes []string

		c := b.Cursor()
		for k, val := c.First(); k != nil; k, val = c.Next() {
			// Check context periodically during long scans.
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			keyStr := string(k)
			// Only process __meta__ keys.
			if !strings.HasSuffix(keyStr, "/"+metaKeySuffix) {
				continue
			}

			// Extract prefix: {provider}/{uuid}/
			prefixEnd := len(keyStr) - len(metaKeySuffix) // remove "/__meta__"
			prefix := keyStr[:prefixEnd]

			var meta Metadata
			if err := json.Unmarshal(val, &meta); err != nil {
				v.logger.Debug("vault: could not parse metadata, skipping",
					"key", keyStr,
					"error", err,
				)
				continue
			}

			if isExpired(meta.CreatedAt, v.ttl) {
				expiredPrefixes = append(expiredPrefixes, prefix)
			}
		}

		// Delete all keys under expired prefixes.
		for _, prefix := range expiredPrefixes {
			// Check context before each deletion pass.
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			c := b.Cursor()
			for k, _ := c.Seek([]byte(prefix)); k != nil && strings.HasPrefix(string(k), prefix); k, _ = c.Next() {
				if err := c.Delete(); err != nil {
					return fmt.Errorf("delete expired key %s: %w", string(k), err)
				}
			}
			purged++
		}

		return nil
	})

	return purged, err
}

// PurgeAll removes all conversations and metadata from the vault.
// The vault remains open and operational after this call — the tokens
// bucket is recreated in the same transaction so subsequent Persist()
// calls succeed.
// Respects context cancellation.
func (v *Vault) PurgeAll(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return v.db.Update(func(tx *bolt.Tx) error {
		if err := tx.DeleteBucket([]byte(BucketTokens)); err != nil {
			return err
		}
		_, err := tx.CreateBucket([]byte(BucketTokens))
		return err
	})
}

// DeleteConversation removes all entries for a specific conversation, including metadata.
// Respects context cancellation.
func (v *Vault) DeleteConversation(ctx context.Context, scope Scope) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	prefix := scopePrefix(scope)

	return v.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(BucketTokens))
		if b == nil {
			return nil
		}

		c := b.Cursor()
		for k, _ := c.Seek([]byte(prefix)); k != nil && strings.HasPrefix(string(k), prefix); k, _ = c.Next() {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			if err := c.Delete(); err != nil {
				return fmt.Errorf("delete key %s: %w", string(k), err)
			}
		}
		return nil
	})
}
