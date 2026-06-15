package tls

import (
	"sync"
	"testing"
)

// TestCertCache_GetSet verifies basic get/put operations.
func TestCertCache_GetSet(t *testing.T) {
	cache := NewCertCache()
	ca, _, err := GenerateCA("Test CA", 1, nil)
	if err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}

	// Generate a cert and cache it
	cert, err := GenerateLeafCert(ca, "chatgpt.com")
	if err != nil {
		t.Fatalf("GenerateLeafCert failed: %v", err)
	}

	// Should not exist initially
	if _, ok := cache.Get("chatgpt.com"); ok {
		t.Error("cert should not exist before put")
	}

	// Put and get
	cache.Put("chatgpt.com", cert)

	cached, ok := cache.Get("chatgpt.com")
	if !ok {
		t.Error("cert should exist after put")
	}
	if cached != cert {
		t.Error("cached cert should be the same pointer")
	}
}

// TestCertCache_GetOrCreate verifies lazy generation and caching.
func TestCertCache_GetOrCreate(t *testing.T) {
	cache := NewCertCache()
	ca, _, err := GenerateCA("Test CA", 1, nil)
	if err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}

	// First call should generate and cache
	cert1, err := cache.GetOrCreate("chatgpt.com", ca)
	if err != nil {
		t.Fatalf("GetOrCreate 1 failed: %v", err)
	}

	// Second call should return cached version
	cert2, err := cache.GetOrCreate("chatgpt.com", ca)
	if err != nil {
		t.Fatalf("GetOrCreate 2 failed: %v", err)
	}

	// Should be the same pointer (same cached object)
	if cert1 != cert2 {
		t.Error("GetOrCreate should return same cached certificate")
	}

	if cache.Len() != 1 {
		t.Errorf("cache should have 1 entry, got %d", cache.Len())
	}
}

// TestCertCache_ConcurrentReadWrite verifies SR8/SEC-T5: thread safety under concurrent access.
func TestCertCache_ConcurrentReadWrite(t *testing.T) {
	cache := NewCertCache()
	ca, _, err := GenerateCA("Test CA", 1, nil)
	if err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}

	// Pre-populate with one entry
	_, err = cache.GetOrCreate("chatgpt.com", ca)
	if err != nil {
		t.Fatalf("pre-populate failed: %v", err)
	}

	var wg sync.WaitGroup
	domains := []string{
		"chatgpt.com", "claude.ai", "gemini.ai",
		"openai.com", "bard.ai", "copilot.microsoft.com",
	}

	// Concurrent reads
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for _, d := range domains {
				cache.Get(d)
			}
		}()
	}

	// Concurrent writes (GetOrCreate)
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			for _, d := range domains {
				cache.GetOrCreate(d, ca)
			}
		}(i)
	}

	wg.Wait()

	// All domains should be in cache after concurrent access
	for _, d := range domains {
		if _, ok := cache.Get(d); !ok {
			t.Errorf("domain %s should be in cache after concurrent access", d)
		}
	}
}

// TestCertCache_ConcurrentSameKey verifies concurrent writes to the same key are safe.
func TestCertCache_ConcurrentSameKey(t *testing.T) {
	cache := NewCertCache()
	ca, _, err := GenerateCA("Test CA", 1, nil)
	if err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}

	var wg sync.WaitGroup
	const goroutines = 50

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := cache.GetOrCreate("chatgpt.com", ca)
			if err != nil {
				t.Errorf("GetOrCreate failed: %v", err)
			}
		}()
	}

	wg.Wait()

	if cache.Len() != 1 {
		t.Errorf("cache should have exactly 1 entry after concurrent writes, got %d", cache.Len())
	}
}

// TestCertCache_Len verifies the Len method.
func TestCertCache_Len(t *testing.T) {
	cache := NewCertCache()
	ca, _, err := GenerateCA("Test CA", 1, nil)
	if err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}

	if l := cache.Len(); l != 0 {
		t.Errorf("empty cache Len() = %d, want 0", l)
	}

	cache.GetOrCreate("a.com", ca)
	cache.GetOrCreate("b.com", ca)

	if l := cache.Len(); l != 2 {
		t.Errorf("cache Len() = %d, want 2", l)
	}
}

// TestCertCache_Clear verifies the Clear method.
func TestCertCache_Clear(t *testing.T) {
	cache := NewCertCache()
	ca, _, err := GenerateCA("Test CA", 1, nil)
	if err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}

	cache.GetOrCreate("a.com", ca)
	cache.GetOrCreate("b.com", ca)

	cache.Clear()

	if l := cache.Len(); l != 0 {
		t.Errorf("cache after Clear() Len() = %d, want 0", l)
	}
}

// TestCertCache_NilCache verifies behavior with edge cases.
func TestCertCache_NilCache(t *testing.T) {
	cache := NewCertCache()

	// Get on empty cache
	if cert, ok := cache.Get("nonexistent.com"); ok || cert != nil {
		t.Error("Get on empty cache should return nil, false")
	}
}
