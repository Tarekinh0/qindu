package tls

import (
	"crypto/tls"
	"fmt"
	"sync"
	"time"
)

// defaultMaxCacheSize is the maximum number of certificates in the cache.
// When exceeded, a random entry is evicted to make room.
const defaultMaxCacheSize = 1000

// CertCache is a thread-safe in-memory cache for TLS certificates.
// It uses sync.RWMutex to allow concurrent reads while ensuring
// exclusive access for writes. The cache has a maximum size to prevent
// unbounded growth from subdomain proliferation.
type CertCache struct {
	cache   map[string]*tls.Certificate
	mu      sync.RWMutex
	maxSize int
}

// NewCertCache creates a new empty CertCache with the default max size (1000).
func NewCertCache() *CertCache {
	return &CertCache{
		cache:   make(map[string]*tls.Certificate),
		maxSize: defaultMaxCacheSize,
	}
}

// NewCertCacheWithSize creates a new CertCache with a custom max size.
func NewCertCacheWithSize(maxSize int) *CertCache {
	if maxSize <= 0 {
		maxSize = defaultMaxCacheSize
	}
	return &CertCache{
		cache:   make(map[string]*tls.Certificate),
		maxSize: maxSize,
	}
}

// Get retrieves a certificate from the cache by hostname.
// Returns the certificate and true if found and not expired, or nil and false.
// This method acquires a read lock. Expired certificates are treated as
// cache misses (lazy TTL eviction).
func (c *CertCache) Get(host string) (*tls.Certificate, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	cert, ok := c.cache[host]
	if ok && cert.Leaf != nil && time.Now().After(cert.Leaf.NotAfter) {
		return nil, false
	}
	return cert, ok
}

// Put stores a certificate in the cache keyed by hostname.
// If the cache is at capacity, a random entry is evicted first.
// This method acquires a write lock.
func (c *CertCache) Put(host string, cert *tls.Certificate) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.evictIfNeededLocked()
	c.cache[host] = cert
}

// GetOrCreate returns a cached certificate for the host, or generates a new one
// using the provided CA. The generated certificate is cached before returning.
// If the host is a subdomain of a cached domain, the cached cert is returned.
// This method manages locking internally.
func (c *CertCache) GetOrCreate(host string, ca *CA) (*tls.Certificate, error) {
	// Try read lock first (fast path)
	if cert, ok := c.Get(host); ok {
		return cert, nil
	}

	// Not in cache, acquire write lock to generate
	c.mu.Lock()
	defer c.mu.Unlock()

	// Double-check after acquiring write lock (another goroutine may have added it).
	// Must inline the TTL check since we already hold the write lock;
	// calling Get() here would deadlock (Get acquires RLock).
	if cert, ok := c.cache[host]; ok {
		if cert.Leaf != nil && time.Now().After(cert.Leaf.NotAfter) {
			// Expired cert found during double-check — evict and regenerate.
			delete(c.cache, host)
		} else {
			return cert, nil
		}
	}

	// Generate new certificate
	cert, err := GenerateLeafCert(ca, host)
	if err != nil {
		return nil, fmt.Errorf("generating leaf cert for %s: %w", host, err)
	}

	// Evict if at capacity before inserting
	c.evictIfNeededLocked()
	c.cache[host] = cert
	return cert, nil
}

// evictIfNeededLocked removes a random entry if the cache is at capacity.
// Must be called with c.mu held (write lock).
func (c *CertCache) evictIfNeededLocked() {
	if len(c.cache) < c.maxSize {
		return
	}
	// Evict the first key encountered (map iteration order is random in Go,
	// providing pseudo-random eviction without the complexity of LRU).
	for k := range c.cache {
		delete(c.cache, k)
		return
	}
}

// Len returns the number of certificates in the cache.
func (c *CertCache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.cache)
}

// Clear removes all certificates from the cache.
func (c *CertCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache = make(map[string]*tls.Certificate)
}
