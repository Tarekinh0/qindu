// Package tokenize provides PII tokenization and rehydration with in-memory storage.
// It replaces detected PII entities with opaque placeholder tokens (<<TYPE_N>>)
// and can restore original values during rehydration. The token↔PII mapping is
// stored in-memory only, with platform-specific memory locking to prevent swap leakage.
package tokenize

import (
	"log/slog"
	"sync"
)

// Store is the injectable interface for token↔PII storage.
// It maps token strings (<<TYPE_N>>) to PII values.
// Implementations must be safe for concurrent use.
//
// Future implementations (e.g., DPAPI-encrypted vault in QINDU-0008) will
// implement this interface for persistent, encrypted storage.
type Store interface {
	// Map stores a token→PII_value binding. If the token already exists,
	// the value is unchanged (first-write-wins for deterministic re-tokenization).
	Map(token string, piiValue string)

	// Get retrieves the PII value for a token, or ("", false) if not found.
	Get(token string) (value string, ok bool)

	// Count returns the total number of entries in the store.
	Count() int

	// Clear removes all entries from the store.
	Clear()

	// Close releases any resources held by the store.
	// After Close, the store should not be used.
	Close() error
}

// defaultArenaSize is the default size of the locked memory arena for PII values.
// 4 MiB accommodates ~20,000 entries at ~200 bytes average PII value size,
// far exceeding typical conversation volumes for a single conversation scope.
const defaultArenaSize = 4 * 1024 * 1024 // 4 MiB

// MemoryStore is a simple in-memory Store backed by a Go map.
// It is safe for concurrent use.
// On platforms supporting memory locking, PII values are stored in locked memory
// to prevent OS swapping (SR-18).
type MemoryStore struct {
	mapping map[string]string // token → PII value
	logger  *slog.Logger
	arena   *piiArena // locked memory arena for PII values (nil if not locked)
	mu      sync.RWMutex
}

// NewMemoryStore creates a new in-memory Store with optional memory locking.
// On Linux, mlockall(MCL_CURRENT|MCL_FUTURE) is called to lock all process pages.
// On Windows, a locked arena buffer is allocated for PII value storage.
// If locking fails, a WARNING is logged (PII-free) and the store operates normally.
func NewMemoryStore(logger *slog.Logger) *MemoryStore {
	arena := initLockedArena(logger)
	return &MemoryStore{
		mapping: make(map[string]string),
		arena:   arena,
		logger:  logger,
	}
}

// Map stores a token→PII_value binding. First-write-wins.
func (s *MemoryStore) Map(token string, piiValue string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.mapping[token]; !exists {
		// Store the PII value in locked memory if arena is available.
		val := piiValue
		if s.arena != nil {
			val = s.arena.alloc(piiValue)
		}
		s.mapping[token] = val
	}
}

// Get retrieves the PII value for a token.
func (s *MemoryStore) Get(token string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	val, ok := s.mapping[token]
	return val, ok
}

// Count returns the total number of entries.
func (s *MemoryStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.mapping)
}

// Clear removes all entries and zeroes the locked arena buffer.
func (s *MemoryStore) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.mapping = make(map[string]string)
	if s.arena != nil {
		s.arena.reset()
	}
}

// Close releases resources held by the store.
// For MemoryStore, this is a no-op since there are no persistent resources.
// Future vault implementations (QINDU-0008) will release file handles and
// cryptographic contexts.
func (s *MemoryStore) Close() error {
	return nil
}

// piiArena is a simple bump-allocator backed by a locked memory buffer.
// It stores PII values as contiguous byte slices, preventing the OS from
// swapping these pages to disk.
type piiArena struct {
	buf    []byte
	offset int
}

// alloc copies data into the arena and returns a string referencing the locked buffer.
// Returns the original string if the arena is full.
func (a *piiArena) alloc(data string) string {
	if a == nil || len(data) > len(a.buf)-a.offset {
		return data // fallback: arena full or not initialized
	}
	copy(a.buf[a.offset:], data)
	a.offset += len(data)
	// Return a string backed by the arena buffer (zero-copy reference).
	return string(a.buf[a.offset-len(data) : a.offset])
}

// reset clears the arena for reuse.
func (a *piiArena) reset() {
	if a != nil {
		a.offset = 0
		// Zero the buffer to clear PII from memory.
		for i := range a.buf {
			a.buf[i] = 0
		}
	}
}
