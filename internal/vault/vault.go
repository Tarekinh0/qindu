package vault

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/Tarekinh0/qindu/internal/crypto"
)

// asyncChannelBuffer is the capacity of the buffered channel for async writes.
// Chosen to handle burst traffic without blocking the proxy.
const asyncChannelBuffer = 1024

// startupSweepTimeout bounds the duration of the startup TTL sweep to prevent
// agent initialization from hanging on a large or corrupted database.
const startupSweepTimeout = 30 * time.Second

// writeOp represents a pending write operation.
type writeOp struct {
	scope   Scope
	token   string
	value   []byte
	meta    bool   // true if this is a metadata update
	piiType string // PII entity type extracted from token (e.g., "EMAIL"); empty for meta ops
}

// TokenEntry represents a decrypted token→value pair for a conversation.
type TokenEntry struct {
	Token string // the surrogate token (e.g., "<<EMAIL_1>>")
	Value []byte // the decrypted original PII value
	Type  string // the PII entity type (e.g., "EMAIL")
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
	db         *bolt.DB
	crypto     *crypto.Service
	ttl        time.Duration
	logger     *slog.Logger
	writeCh    chan writeOp
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	wgInFlight sync.WaitGroup // tracks in-flight enqueue senders (PR-003 TOCTOU fix)
	closeMu    sync.Mutex
	closed     bool
}

// New creates a new Vault with the given bbolt database, crypto service, and TTL.
//
// On construction:
//  1. A startup sweep purges any expired conversations (bounded by startupSweepTimeout).
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

	// Startup sweep: purge expired conversations with bounded timeout (PR-103).
	// A context with timeout prevents a corrupted database from blocking
	// agent startup indefinitely.
	sweepCtx, sweepCancel := context.WithTimeout(context.Background(), startupSweepTimeout)
	defer sweepCancel()
	if err := v.sweepExpired(sweepCtx); err != nil {
		v.logger.Warn("vault startup sweep failed",
			"error", err,
			"pii_values_logged", false,
		)
	} else {
		v.logger.Info("vault startup sweep complete",
			"pii_values_logged", false,
		)
	}

	return v, nil
}

// Run starts the background writer goroutine and the periodic TTL sweeper.
//
// Run starts background goroutines. Close() MUST be called to stop them,
// drain pending writes, flush bbolt, and zero the crypto key. Failure to
// call Close() leaks goroutines and may leave data uncommitted.
//
// ctx controls the lifetime of both goroutines. When ctx is cancelled,
// goroutines exit gracefully — but Close() is still required to drain
// pending writes, flush bbolt, and zero the crypto key.
//
// Must be called after New, before any writes are enqueued.
func (v *Vault) Run(ctx context.Context) {
	v.ctx, v.cancel = context.WithCancel(ctx)

	v.wg.Add(1)
	go v.writeLoop()

	v.wg.Add(1)
	go v.sweeperLoop()
}

// Close gracefully shuts down the vault:
// 1. Sets closed flag to reject new writes
// 2. Cancels background goroutines (stops sweeper, signals writeLoop to drain)
// 3. Waits for goroutines to finish draining (writeLoop drains via ctx.Done())
// 4. Waits for in-flight enqueue senders (PR-003 TOCTOU fix)
// 5. Drains any messages sent by in-flight senders after writeLoop exited
// 6. Closes the bbolt database
// 7. Zeros the crypto key in memory
//
// The write channel is intentionally never closed — goroutines exit via
// ctx cancellation, and the closed flag prevents new sends. Closing the
// channel would race with Persist() goroutines that passed the closed check
// (TOCTOU → panic on send to closed channel).
//
// Safe to call multiple times (idempotent).
func (v *Vault) Close() {
	v.closeMu.Lock()
	if v.closed {
		v.closeMu.Unlock()
		return
	}
	v.closed = true
	v.closeMu.Unlock()

	// Cancel background goroutines (stops sweeper, signals writeLoop to drain).
	if v.cancel != nil {
		v.cancel()
	}

	// Wait for goroutines to finish draining.
	v.wg.Wait()

	// Wait for in-flight enqueue senders that passed the closed check
	// before we set closed=true. They may have sent messages to the
	// channel after writeLoop exited. (PR-003)
	v.wgInFlight.Wait()

	// Drain any messages that in-flight senders deposited after writeLoop
	// drained and exited. After wgInFlight.Wait() returns, no new sends
	// can occur (closed==true blocks new callers, all in-flight done).
	v.drainRemaining()

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
}
