// Package constants holds shared configuration constants used across Qindu packages.
package constants

import "time"

// GracefulShutdownTimeout is the maximum time to wait for connections to drain
// during graceful shutdown of the HTTP proxy server.
const GracefulShutdownTimeout = 30 * time.Second
