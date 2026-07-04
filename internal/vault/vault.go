package vault

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/Tarekinh0/qindu/internal/crypto"
)

// metaKeySuffix is the suffix for metadata keys in bbolt.
const metaKeySuffix = "__meta__"

// asyncChannelBuffer is the capacity of the buffered channel for async writes.
// Chosen to handle burst traffic without blocking the proxy.
const asyncChannelBuffer = 1024

// writeOp represents a pending write operation.
type writeOp struct {
	scope Scope
	token string
	value []byte
	meta  bool // true if this is a metadata update
}

// Vault is the encrypted persistent store for token↔PII mappings.
// It implements TokenPersister and uses bbolt for on-disk storage
// with AES-256-GCM encryption for all PII values.
//
// The vault receives writes asynchronously: Persist() sends to a buffered
// channel, and a background goroutine encrypts and commits to bbolt.
// This ensures the proxy thread never blocks on disk I/O.
//
// Safe for concurrent use.
type Vault struct {
	db      *bolt.DB
	crypto  *crypto.Service
	ttl     time.Duration
	logger  *slog.Logger
	writeCh chan writeOp
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	closeMu sync.Mutex
	closed  bool
}

// New creates a new Vault with the given bbolt database, crypto service, and TTL.
//
// On construction:
//  1. A startup sweep purges any expired conversations.
//  2. The background writer goroutine is NOT started here — call Run() to start it.
//
// The database and crypto service must already be initialized.
func New(db *bolt.DB, crypto *crypto.Service, ttl time.Duration, logger *slog.Logger) (*Vault, error) {
	if db == nil {
		return nil, fmt.Errorf("vault: db must not be nil")
	}
	if crypto == nil {
		return nil, fmt.Errorf("vault: crypto service must not be nil")
	}
	if logger == nil {
		logger = slog.Default()
	}

	v := &Vault{
		db:      db,
		crypto:  crypto,
		ttl:     ttl,
		logger:  logger,
		writeCh: make(chan writeOp, asyncChannelBuffer),
	}

	// Startup sweep: purge expired conversations.
	if err := v.sweepExpired(context.Background()); err != nil {
		v.logger.Warn("vault startup sweep failed", "error", err, "pii_values_logged", false)
	} else {
		v.logger.Info("vault startup sweep complete", "pii_values_logged", false)
	}

	return v, nil
}

// Run starts the background writer goroutine and the periodic TTL sweeper.
// ctx controls the lifetime of both goroutines. Call CancelFunc to stop them.
// Must be called after New, before any writes are enqueued.
func (v *Vault) Run(ctx context.Context) {
	v.ctx, v.cancel = context.WithCancel(ctx)

	v.wg.Add(1)
	go v.writeLoop()

	v.wg.Add(1)
	go v.sweeperLoop()
}

// Persist enqueues a token→value mapping for async write to bbolt.
// Implements TokenPersister. Returns immediately without blocking on disk I/O.
//
// Uses a non-blocking channel send: if the channel is full, the write is dropped
// and a WARNING is logged (PII-free). This prevents back-pressure from disk I/O
// affecting proxy latency (SR-802).
func (v *Vault) Persist(scope Scope, token string, value []byte) error {
	if v.isClosed() {
		return fmt.Errorf("vault: closed")
	}

	op := writeOp{
		scope: scope,
		token: token,
		value: value,
	}

	// Non-blocking send — fire and forget.
	select {
	case v.writeCh <- op:
		return nil
	default:
		// Channel full — drop the write, log WARNING (PII-free).
		v.logger.Warn("vault write dropped: async channel full",
			"provider", scope.Provider,
			"pii_values_logged", false,
		)
		return nil // fire-and-forget: don't propagate error to proxy
	}
}

// UpdateMeta enqueues a metadata update for async write.
// Implements TokenPersister.
func (v *Vault) UpdateMeta(scope Scope, meta Metadata) error {
	if v.isClosed() {
		return fmt.Errorf("vault: closed")
	}

	data, err := json.Marshal(meta)
	if err != nil {
		return fmt.Errorf("vault: failed to marshal metadata: %w", err)
	}

	op := writeOp{
		scope: scope,
		value: data,
		meta:  true,
		token: metaKeySuffix,
	}

	select {
	case v.writeCh <- op:
		return nil
	default:
		v.logger.Warn("vault metadata update dropped: async channel full",
			"provider", scope.Provider,
			"pii_values_logged", false,
		)
		return nil
	}
}

// writeLoop drains the async channel, encrypts values, and commits to bbolt.
// Runs until the channel is closed and drained, or ctx is cancelled.
func (v *Vault) writeLoop() {
	defer v.wg.Done()

	for {
		select {
		case op, ok := <-v.writeCh:
			if !ok {
				// Channel closed — drain complete.
				return
			}
			v.handleWrite(op)

		case <-v.ctx.Done():
			// Context cancelled — drain remaining before exit.
			v.drainRemaining()
			return
		}
	}
}

// handleWrite processes a single write operation: encrypts the value
// (if it's a PII write, not metadata) and writes to bbolt.
func (v *Vault) handleWrite(op writeOp) {
	key := conversationKey(op.scope, op.token)

	var value []byte
	if op.meta {
		value = op.value // metadata is plaintext
	} else {
		// Encrypt the PII value.
		var err error
		value, err = v.crypto.Encrypt(op.value)
		if err != nil {
			v.logger.Error("vault: encrypt failed",
				"provider", op.scope.Provider,
				"error", err,
				"pii_values_logged", false,
			)
			return
		}
	}

	if err := v.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("tokens"))
		if b == nil {
			// Bucket should be created at vault initialization.
			var err error
			b, err = tx.CreateBucketIfNotExists([]byte("tokens"))
			if err != nil {
				return fmt.Errorf("create bucket: %w", err)
			}
		}
		return b.Put([]byte(key), value)
	}); err != nil {
		v.logger.Error("vault: bbolt write failed",
			"provider", op.scope.Provider,
			"error", err,
			"pii_values_logged", false,
		)
	}
}

// drainRemaining drains all pending writes from the channel.
// Called on context cancellation during graceful shutdown.
func (v *Vault) drainRemaining() {
	drained := 0
	for {
		select {
		case op, ok := <-v.writeCh:
			if !ok {
				v.logger.Info("vault: drained pending writes on shutdown",
					"count", drained,
					"pii_values_logged", false,
				)
				return
			}
			v.handleWrite(op)
			drained++
		default:
			v.logger.Info("vault: drained pending writes on shutdown",
				"count", drained,
				"pii_values_logged", false,
			)
			return
		}
	}
}

// sweeperLoop periodically scans all __meta__ keys and purges expired conversations.
// Interval: min(ttl/7, 24h), minimum 1h (per DPO-R2).
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
func (v *Vault) sweepExpired(ctx context.Context) error {
	_, err := v.PurgeExpired(ctx)
	return err
}

// PurgeExpired removes all conversations where now - created_at > ttl.
// Returns the count of purged conversations.
func (v *Vault) PurgeExpired(ctx context.Context) (int, error) {
	if v.ttl <= 0 {
		return 0, nil // infinite TTL, nothing to purge
	}

	purged := 0
	err := v.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("tokens"))
		if b == nil {
			return nil
		}

		// Find all __meta__ keys and check their creation time.
		var expiredPrefixes []string

		c := b.Cursor()
		for k, val := c.First(); k != nil; k, val = c.Next() {
			keyStr := string(k)
			// Only process __meta__ keys, but the write uses ... / ... / __meta__
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
// The vault remains open and operational after this call.
func (v *Vault) PurgeAll(ctx context.Context) error {
	return v.db.Update(func(tx *bolt.Tx) error {
		return tx.DeleteBucket([]byte("tokens"))
	})
}

// ListConversations returns metadata for all active conversations.
// Does NOT decrypt or return PII values.
func (v *Vault) ListConversations(ctx context.Context) ([]Metadata, error) {
	var results []Metadata

	err := v.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("tokens"))
		if b == nil {
			return nil
		}

		c := b.Cursor()
		for k, val := c.First(); k != nil; k, val = c.Next() {
			if !strings.HasSuffix(string(k), "/"+metaKeySuffix) {
				continue
			}

			var meta Metadata
			if err := json.Unmarshal(val, &meta); err != nil {
				continue
			}
			results = append(results, meta)
		}
		return nil
	})

	return results, err
}

// DeleteConversation removes all entries for a specific conversation, including metadata.
func (v *Vault) DeleteConversation(ctx context.Context, scope Scope) error {
	prefix := scopePrefix(scope)

	return v.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("tokens"))
		if b == nil {
			return nil
		}

		c := b.Cursor()
		for k, _ := c.Seek([]byte(prefix)); k != nil && strings.HasPrefix(string(k), prefix); k, _ = c.Next() {
			if err := c.Delete(); err != nil {
				return fmt.Errorf("delete key %s: %w", string(k), err)
			}
		}
		return nil
	})
}

// Close gracefully shuts down the vault:
// 1. Cancels background goroutines
// 2. writeLoop drains remaining buffered writes on context cancellation
// 3. Closes the async channel
// 4. Closes the bbolt database
// 5. Zeros the crypto key in memory
//
// Safe to call multiple times (idempotent).
func (v *Vault) Close() error {
	v.closeMu.Lock()
	defer v.closeMu.Unlock()

	if v.closed {
		return nil
	}
	v.closed = true

	// Cancel background goroutines (stops sweeper, signals writeLoop to drain).
	if v.cancel != nil {
		v.cancel()
	}

	// Close the write channel. If writeLoop is still draining after ctx
	// cancellation, this signals final closure.
	close(v.writeCh)

	// Wait for background goroutines to finish.
	v.wg.Wait()

	v.logger.Info("vault: shutdown complete", "pii_values_logged", false)

	// Close bbolt.
	if v.db != nil {
		if err := v.db.Close(); err != nil {
			v.logger.Error("vault: bbolt close error", "error", err, "pii_values_logged", false)
		}
		v.db = nil
	}

	// Close crypto service (zeros key).
	if v.crypto != nil {
		v.crypto.Close()
		v.crypto = nil
	}

	return nil
}

// isClosed reports whether the vault has been closed.
func (v *Vault) isClosed() bool {
	v.closeMu.Lock()
	defer v.closeMu.Unlock()
	return v.closed
}

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
