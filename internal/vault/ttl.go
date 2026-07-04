package vault

import (
	"time"
)

// isExpired returns true if the conversation created at `createdAt` has exceeded
// the TTL duration. ttl of 0 means infinite (never expires).
func isExpired(createdAt int64, ttl time.Duration) bool {
	if ttl <= 0 {
		return false // infinite TTL
	}
	age := time.Since(time.Unix(createdAt, 0))
	return age > ttl
}

// sweepInterval returns the background sweeper interval based on TTL.
// The sweeper runs at min(ttl/7, 24h). For infinite TTL (0), defaults to 24h.
// Minimum interval is 1h to avoid excessive scanning.
func sweepInterval(ttl time.Duration) time.Duration {
	if ttl <= 0 {
		return 24 * time.Hour
	}
	interval := ttl / 7
	if interval < 1*time.Hour {
		interval = 1 * time.Hour
	}
	if interval > 24*time.Hour {
		interval = 24 * time.Hour
	}
	return interval
}
