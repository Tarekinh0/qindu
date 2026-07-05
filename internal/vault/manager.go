package vault

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Tarekinh0/qindu/internal/session"
)

// DefaultIdleTimeout is the default idle timeout for vault eviction: 30 minutes.
const DefaultIdleTimeout = 30 * time.Minute

// EvictionCheckInterval is how often the background eviction goroutine runs: 10 minutes.
const EvictionCheckInterval = 10 * time.Minute

// vaultEntry tracks a per-user vault and its last access time.
type vaultEntry struct {
	vault    *Vault
	lastUsed time.Time
	path     string // for logging, redacted before output
}

// VaultManager manages per-user vault instances with lazy creation
// and idle-timeout eviction. Safe for concurrent use.
type VaultManager struct {
	mu          sync.Mutex
	vaults      map[string]*vaultEntry   // keyed by ResolvedUser.VaultPath
	creating    map[string]chan struct{} // signals for in-progress creation (per path)
	ttl         time.Duration            // PII data TTL from config
	idleTimeout time.Duration
	logger      *slog.Logger
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
}

// NewVaultManager creates a VaultManager that manages per-user vaults.
// ttl is the PII data TTL passed to each vault on creation.
// idleTimeout is how long a vault can be unused before eviction.
// If idleTimeout <= 0, DefaultIdleTimeout is used.
func NewVaultManager(ttl, idleTimeout time.Duration, logger *slog.Logger) *VaultManager {
	if idleTimeout <= 0 {
		idleTimeout = DefaultIdleTimeout
	}
	if logger == nil {
		logger = slog.Default()
	}
	ctx, cancel := context.WithCancel(context.Background())
	vm := &VaultManager{
		vaults:      make(map[string]*vaultEntry),
		creating:    make(map[string]chan struct{}),
		ttl:         ttl,
		idleTimeout: idleTimeout,
		logger:      logger,
		ctx:         ctx,
		cancel:      cancel,
	}
	// Start background eviction goroutine.
	vm.wg.Add(1)
	go vm.evictionLoop()
	return vm
}

// GetOrCreate returns the vault for the given resolved user. If the vault
// doesn't exist in the manager, it is created using the platform-specific
// createUserVault function. token is the impersonation token on Windows
// (zero on Unix or console mode).
//
// Concurrent callers for the same path are serialized: only one goroutine
// performs creation, others wait for it and receive the same vault.
//
// Safe for concurrent use. Returns an error if vault creation fails
// (e.g., impersonation failure, disk full).
func (vm *VaultManager) GetOrCreate(resolved *session.ResolvedUser, token uintptr) (*Vault, error) {
	path := resolved.VaultPath

	// Fast path: vault already exists.
	vm.mu.Lock()
	if entry, ok := vm.vaults[path]; ok {
		entry.lastUsed = time.Now()
		vm.mu.Unlock()
		return entry.vault, nil
	}

	// Check if another goroutine is already creating this vault.
	if waitCh, creating := vm.creating[path]; creating {
		vm.mu.Unlock()
		// Wait for the creator to finish.
		<-waitCh
		// Re-check: the vault should now exist.
		vm.mu.Lock()
		if entry, ok := vm.vaults[path]; ok {
			entry.lastUsed = time.Now()
			vm.mu.Unlock()
			return entry.vault, nil
		}
		// Creator failed — register ourselves as the new creator.
		// This prevents a thundering herd: if multiple goroutines were
		// waiting on the same channel, only one will register as the
		// new creator here; the others will become waiters on the new
		// channel (cascaded deduplication).
		vm.creating[path] = make(chan struct{})
		vm.mu.Unlock()
	} else {
		// Register ourselves as the creator.
		vm.creating[path] = make(chan struct{})
		vm.mu.Unlock()
	}

	// Slow path: create vault (no lock held — I/O).
	v, err := createUserVault(resolved, vm.ttl, vm.logger, token)

	// Signal waiters and clean up the creation sentinel.
	vm.mu.Lock()
	ch := vm.creating[path]
	delete(vm.creating, path)
	if ch != nil {
		close(ch)
	}

	if err != nil {
		vm.mu.Unlock()
		return nil, err
	}

	// Double-check: another goroutine may have created it while we were
	// working (e.g., waiter that retried after a previous creator failed).
	if entry, ok := vm.vaults[path]; ok {
		vm.mu.Unlock()
		v.Close() // discard the duplicate
		entry.lastUsed = time.Now()
		return entry.vault, nil
	}
	vm.vaults[path] = &vaultEntry{
		vault:    v,
		lastUsed: time.Now(),
		path:     path,
	}
	vm.mu.Unlock()
	return v, nil
}

// Shutdown closes all managed vaults and stops the eviction goroutine.
// Must be called exactly once before process exit.
func (vm *VaultManager) Shutdown() {
	vm.cancel()
	vm.wg.Wait()

	vm.mu.Lock()
	defer vm.mu.Unlock()
	for path, entry := range vm.vaults {
		vm.logger.Info("vault: closing user vault on shutdown",
			"path", redactHomePath(path),
			"pii_values_logged", false,
		)
		entry.vault.Close()
		delete(vm.vaults, path)
	}
	vm.logger.Info("vault: all user vaults closed",
		"pii_values_logged", false,
	)
}

// vaultCount returns the number of active vaults (for testing).
func (vm *VaultManager) vaultCount() int {
	vm.mu.Lock()
	defer vm.mu.Unlock()
	return len(vm.vaults)
}

// evictionLoop periodically evicts idle vaults.
func (vm *VaultManager) evictionLoop() {
	defer vm.wg.Done()
	ticker := time.NewTicker(EvictionCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-vm.ctx.Done():
			return
		case <-ticker.C:
			vm.evictIdle()
		}
	}
}

// evictIdle closes vaults whose lastUsed time exceeds the idle timeout.
func (vm *VaultManager) evictIdle() {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	cutoff := time.Now().Add(-vm.idleTimeout)
	for path, entry := range vm.vaults {
		if entry.lastUsed.Before(cutoff) {
			vm.logger.Info("vault: closing idle user vault",
				"path", redactHomePath(path),
				"idle_since", entry.lastUsed.Format(time.RFC3339),
				"pii_values_logged", false,
			)
			entry.vault.Close()
			delete(vm.vaults, path)
		}
	}
}

// redactHomePath replaces the user's home directory prefix with "~" (Unix)
// or "%LOCALAPPDATA%" (Windows) to avoid logging usernames in filesystem paths.
// If the path does not start with a known home directory prefix, it is returned
// unchanged.
func redactHomePath(path string) string {
	if localAppData := os.Getenv("LOCALAPPDATA"); localAppData != "" {
		if after, ok := strings.CutPrefix(path, localAppData); ok {
			return "%LOCALAPPDATA%" + after
		}
	}
	if homeDir, err := os.UserHomeDir(); err == nil && homeDir != "" {
		if after, ok := strings.CutPrefix(path, homeDir); ok {
			return "~" + after
		}
	}
	return path
}
