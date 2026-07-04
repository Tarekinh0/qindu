package vault

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"
)

// writeLoop drains the async channel, encrypts values, and commits to bbolt.
// Runs until ctx is cancelled. The writeCh is never closed externally;
// ctx cancellation is the sole termination signal.
func (v *Vault) writeLoop() {
	defer v.wg.Done()

	for {
		select {
		case op := <-v.writeCh:
			v.handleWrite(op)

		case <-v.ctx.Done():
			// Context cancelled — drain remaining before exit.
			v.drainRemaining()
			return
		}
	}
}

// handleWrite processes a single write operation: encrypts the value
// (if it's a PII write, not metadata), writes to bbolt, and atomically
// upserts the conversation __meta__ entry for PII token writes.
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
		b := tx.Bucket([]byte(BucketTokens))
		if b == nil {
			// Bucket must exist — created at vault initialization.
			return fmt.Errorf("vault: %s bucket does not exist — vault not properly initialized", BucketTokens)
		}
		if err := b.Put([]byte(key), value); err != nil {
			return err
		}

		// For PII token writes (non-meta), atomically upsert __meta__ (AC-13).
		if !op.meta && op.piiType != "" {
			metaKey := []byte(conversationKey(op.scope, metaKeySuffix))
			v.upsertMetaInTx(b, metaKey, op.scope.Provider, op.piiType)
		}
		return nil
	}); err != nil {
		v.logger.Error("vault: bbolt write failed",
			"provider", op.scope.Provider,
			"error", err,
			"pii_values_logged", false,
		)
	}
}

// upsertMetaInTx atomically reads, updates, and writes the __meta__ entry
// for a conversation within an existing bbolt transaction.
// Increments pii_count, adds the pii_type (deduplicated), and bumps updated_at.
// If no __meta__ exists yet, creates a fresh one with NewMetadata.
func (v *Vault) upsertMetaInTx(b *bolt.Bucket, metaKey []byte, provider string, piiType string) {
	var meta Metadata
	if existing := b.Get(metaKey); existing != nil {
		if err := json.Unmarshal(existing, &meta); err != nil {
			// Corrupted metadata — overwrite with fresh.
			meta = NewMetadata(provider)
		}
	} else {
		meta = NewMetadata(provider)
	}

	meta.PIICount++
	meta.UpdatedAt = time.Now().Unix()

	// Deduplicate pii_types.
	found := false
	for _, t := range meta.PIITypes {
		if t == piiType {
			found = true
			break
		}
	}
	if !found {
		meta.PIITypes = append(meta.PIITypes, piiType)
	}

	updated, err := json.Marshal(meta)
	if err != nil {
		// Metadata marshal failure is non-fatal for the token write.
		return
	}
	if err := b.Put(metaKey, updated); err != nil {
		v.logger.Error("vault: metadata put failed",
			"error", err,
			"pii_values_logged", false,
		)
		// Non-fatal: the token value write already succeeded in the same transaction.
	}
}

// drainRemaining drains all pending writes from the channel.
// Called on context cancellation during graceful shutdown.
// The channel is never closed — we rely on non-blocking select to
// detect emptiness.
func (v *Vault) drainRemaining() {
	drained := 0
	defer func() {
		v.logger.Info("vault: drained pending writes on shutdown",
			"count", drained,
			"pii_values_logged", false,
		)
	}()

	for {
		select {
		case op := <-v.writeCh:
			v.handleWrite(op)
			drained++
		default:
			return
		}
	}
}

// enqueue validates and sends a write operation to the async channel.
// Returns true if the operation was enqueued, false if it was rejected
// (provider validation failure, vault closed, or channel full).
//
// This is the single entry point for all write operations, replacing
// duplicated provider-validation and closed-check logic that was
// previously in Persist() and UpdateMeta() separately.
//
// PR-003: Uses wgInFlight to track in-flight senders. Close() waits for
// in-flight senders to complete before closing bbolt, eliminating the
// TOCTOU window where a sender could pass the closed check but have
// its message orphaned in the channel after writeLoop has exited.
func (v *Vault) enqueue(op writeOp) bool {
	// Validate provider name — reject slashes that would corrupt key structure.
	if strings.Contains(op.scope.Provider, "/") {
		v.logger.Error("vault: write rejected — provider name contains '/'",
			"provider", op.scope.Provider,
			"pii_values_logged", false,
		)
		return false
	}

	v.closeMu.Lock()
	if v.closed {
		v.closeMu.Unlock()
		return false
	}
	// Track this sender so Close() waits for its channel send to complete.
	v.wgInFlight.Add(1)
	ch := v.writeCh
	v.closeMu.Unlock()

	defer v.wgInFlight.Done()

	select {
	case ch <- op:
		return true
	default:
		v.logger.Warn("vault write dropped: async channel full",
			"provider", op.scope.Provider,
			"pii_values_logged", false,
		)
		return false
	}
}

// Persist enqueues a token→value mapping for async write to bbolt.
// Implements TokenPersister. Returns immediately without blocking on disk I/O.
//
// Uses a non-blocking channel send: if the channel is full, the write is dropped
// and a WARNING is logged (PII-free). This prevents back-pressure from disk I/O
// affecting proxy latency (SR-802).
//
// Race-free with Close(): the closeMu is held during the closed-check and
// channel reference grab. The channel is never closed — writeLoop exits via
// ctx cancellation (ctx.Done()), and after closed==true no new Persist()
// calls reach the channel. The channel is garbage-collected when the Vault
// is freed.
func (v *Vault) Persist(scope Scope, token string, value []byte) {
	// extractPIIType is a pure function; called outside the lock
	// to keep the critical section clearly bounded.
	piiType, valid := extractPIIType(token)
	if !valid {
		v.logger.Warn("vault: Persist called with malformed token — metadata will be incomplete",
			"provider", scope.Provider,
			"token_length", len(token),
			"pii_values_logged", false,
		)
	}

	op := writeOp{
		scope:   scope,
		token:   token,
		value:   value,
		piiType: piiType,
	}

	v.enqueue(op)
}

// UpdateMeta enqueues a metadata update for async write.
// Implements TokenPersister.
func (v *Vault) UpdateMeta(scope Scope, meta Metadata) {
	data, err := json.Marshal(meta)
	if err != nil {
		v.logger.Error("vault: failed to marshal metadata",
			"error", err,
			"pii_values_logged", false,
		)
		return
	}

	op := writeOp{
		scope:   scope,
		value:   data,
		meta:    true,
		token:   metaKeySuffix,
		piiType: "",
	}

	v.enqueue(op)
}
