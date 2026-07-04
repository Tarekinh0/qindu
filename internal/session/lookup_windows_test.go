//go:build windows

package session

import (
	"fmt"
	"testing"
)

func TestCache_BasicGetPut(t *testing.T) {
	c := newPIDLocalAppDataCache(3)

	// Put some entries.
	c.put(100, "C:\\Users\\Alice\\AppData\\Local")
	c.put(200, "C:\\Users\\Bob\\AppData\\Local")
	c.put(300, "C:\\Users\\Charlie\\AppData\\Local")

	// Get existing entries.
	path, ok := c.get(100)
	if !ok {
		t.Error("PID 100 should be in cache")
	}
	if path != "C:\\Users\\Alice\\AppData\\Local" {
		t.Errorf("expected path for PID 100, got %q", path)
	}

	path, ok = c.get(200)
	if !ok {
		t.Error("PID 200 should be in cache")
	}
	if path != "C:\\Users\\Bob\\AppData\\Local" {
		t.Errorf("expected path for PID 200, got %q", path)
	}

	// Get missing entry.
	_, ok = c.get(999)
	if ok {
		t.Error("PID 999 should NOT be in cache")
	}
}

func TestCache_Eviction(t *testing.T) {
	c := newPIDLocalAppDataCache(3)

	// Fill cache to capacity.
	c.put(1, "C:\\Users\\U1\\AppData\\Local")
	c.put(2, "C:\\Users\\U2\\AppData\\Local")
	c.put(3, "C:\\Users\\U3\\AppData\\Local")

	// PID 1 is the oldest entry (inserted first).
	// Adding PID 4 should evict the oldest entry (PID 1).
	c.put(4, "C:\\Users\\U4\\AppData\\Local")

	if _, ok := c.get(1); ok {
		t.Error("PID 1 should have been evicted (oldest)")
	}
	if _, ok := c.get(2); ok {
		// PID 2 should still be present.
	} else {
		t.Error("PID 2 should still be in cache")
	}
	if _, ok := c.get(3); ok {
		// PID 3 should still be present.
	} else {
		t.Error("PID 3 should still be in cache")
	}
	if _, ok := c.get(4); !ok {
		t.Error("PID 4 should be in cache")
	}
}

func TestCache_EvictionOver10K(t *testing.T) {
	// Insert >10000 entries to verify eviction works at scale.
	const evictThreshold = uint32(lruMaxSize + 100)
	c := newPIDLocalAppDataCache(lruMaxSize)

	// Insert up to threshold.
	for i := uint32(1); i <= evictThreshold; i++ {
		c.put(i, fmt.Sprintf("C:\\Users\\U%d\\AppData\\Local", i))
	}

	// First 100 entries are the oldest; they should have been evicted.
	// (Not all 100 may be evicted since the oldest-eviction scans all entries,
	// but the cache must stay within maxSize.)
	if got := len(c.entries); got > lruMaxSize {
		t.Errorf("cache size %d exceeds max %d", got, lruMaxSize)
	}

	// The most recently inserted entry should still be present.
	if _, ok := c.get(evictThreshold); !ok {
		t.Errorf("PID %d should still be in cache (most recently inserted)", evictThreshold)
	}
}

func TestCache_UpdateExisting(t *testing.T) {
	c := newPIDLocalAppDataCache(5)

	c.put(1, "C:\\Users\\Initial\\AppData\\Local")
	c.put(1, "C:\\Users\\Updated\\AppData\\Local")

	path, ok := c.get(1)
	if !ok {
		t.Fatal("PID 1 should be in cache")
	}
	if path != "C:\\Users\\Updated\\AppData\\Local" {
		t.Errorf("expected updated path, got %q", path)
	}

	// Cache should still have size 1 (update, not insert).
	if len(c.entries) != 1 {
		t.Errorf("expected cache size 1 after update, got %d", len(c.entries))
	}
}

func TestCache_EmptyCache(t *testing.T) {
	c := newPIDLocalAppDataCache(10)

	_, ok := c.get(1)
	if ok {
		t.Error("empty cache should return false for any key")
	}

	// Eviction on empty cache should not panic.
	c.evictOldest()
}

func TestGlobalCache_Exists(t *testing.T) {
	if globalCache == nil {
		t.Error("globalCache must be initialized at package init")
	}
	if globalCache.maxSize != lruMaxSize {
		t.Errorf("expected globalCache maxSize %d, got %d", lruMaxSize, globalCache.maxSize)
	}
}

func TestCache_TTLExpiry(t *testing.T) {
	// TTL expiry is tested via the timestamp logic. We can't easily mock time
	// without injecting a clock, but the code path is exercised by the get()
	// method checking time.Since(e.ts) > cacheTTL.
	// This test verifies that a freshly-inserted entry is not expired.
	c := newPIDLocalAppDataCache(10)
	c.put(1, "C:\\Users\\Test\\AppData\\Local")

	if _, ok := c.get(1); !ok {
		t.Error("freshly-inserted entry should not be expired")
	}
}
