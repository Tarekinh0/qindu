//go:build windows

package session

import (
	"fmt"
	"testing"
)

func TestLRUCache_BasicGetPut(t *testing.T) {
	c := newPIDSIDCache(3)

	// Put some entries.
	c.put(100, "S-1-5-21-100")
	c.put(200, "S-1-5-21-200")
	c.put(300, "S-1-5-21-300")

	// Get existing entries.
	sid, ok := c.get(100)
	if !ok {
		t.Error("PID 100 should be in cache")
	}
	if sid != "S-1-5-21-100" {
		t.Errorf("expected SID for PID 100, got %q", sid)
	}

	sid, ok = c.get(200)
	if !ok {
		t.Error("PID 200 should be in cache")
	}
	if sid != "S-1-5-21-200" {
		t.Errorf("expected SID for PID 200, got %q", sid)
	}

	// Get missing entry.
	_, ok = c.get(999)
	if ok {
		t.Error("PID 999 should NOT be in cache")
	}
}

func TestLRUCache_Eviction(t *testing.T) {
	c := newPIDSIDCache(3)

	// Fill cache to capacity.
	c.put(1, "S-1-5-21-1")
	c.put(2, "S-1-5-21-2")
	c.put(3, "S-1-5-21-3")

	// PID 1 is LRU (inserted first).
	// Adding PID 4 should evict PID 1.
	c.put(4, "S-1-5-21-4")

	if _, ok := c.get(1); ok {
		t.Error("PID 1 should have been evicted (LRU)")
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

	// Access PID 2 to make it MRU, then evict — PID 3 should be evicted next.
	c.get(2)
	c.put(5, "S-1-5-21-5")
	if _, ok := c.get(3); ok {
		t.Error("PID 3 should have been evicted (LRU after accessing PID 2)")
	}
	if _, ok := c.get(2); !ok {
		t.Error("PID 2 should still be in cache (recently accessed)")
	}
}

func TestLRUCache_EvictionOver10K(t *testing.T) {
	// Insert >10000 entries to verify LRU eviction works at scale.
	const evictThreshold = lruMaxSize + 100
	c := newPIDSIDCache(lruMaxSize)

	// Insert up to threshold.
	for i := uint32(1); i <= evictThreshold; i++ {
		c.put(i, fmt.Sprintf("S-1-5-21-%d", i))
	}

	// First 100 entries should have been evicted.
	for i := uint32(1); i <= 100; i++ {
		if _, ok := c.get(i); ok {
			t.Errorf("PID %d should have been evicted (cache limited to %d)", i, lruMaxSize)
		}
	}

	// The last 100 entries (most recently inserted) should still be present.
	for i := uint32(evictThreshold - 99); i <= evictThreshold; i++ {
		if _, ok := c.get(i); !ok {
			t.Errorf("PID %d should still be in cache (most recently inserted)", i)
		}
	}

	// Verify cache size does not exceed max.
	if len(c.entries) > lruMaxSize {
		t.Errorf("cache size %d exceeds max %d", len(c.entries), lruMaxSize)
	}
}

func TestLRUCache_UpdateExisting(t *testing.T) {
	c := newPIDSIDCache(5)

	c.put(1, "S-1-5-21-init")
	c.put(1, "S-1-5-21-updated")

	sid, ok := c.get(1)
	if !ok {
		t.Fatal("PID 1 should be in cache")
	}
	if sid != "S-1-5-21-updated" {
		t.Errorf("expected updated SID, got %q", sid)
	}

	// Cache should still have size 1 (update, not insert).
	if len(c.entries) != 1 {
		t.Errorf("expected cache size 1 after update, got %d", len(c.entries))
	}
}

func TestLRUCache_EmptyCache(t *testing.T) {
	c := newPIDSIDCache(10)

	_, ok := c.get(1)
	if ok {
		t.Error("empty cache should return false for any key")
	}

	// Eviction on empty cache should not panic.
	c.evictLRU()
}

func TestGlobalCache_Exists(t *testing.T) {
	if globalCache == nil {
		t.Error("globalCache must be initialized at package init")
	}
	if globalCache.maxSize != lruMaxSize {
		t.Errorf("expected globalCache maxSize %d, got %d", lruMaxSize, globalCache.maxSize)
	}
}
