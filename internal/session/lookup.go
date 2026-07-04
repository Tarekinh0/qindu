// Package session provides platform-specific user session resolution
// for per-user vault isolation.
//
// On Windows (service mode): resolves PID from TCP/UDP tables to a user SID,
// then derives the per-user vault path via SHGetKnownFolderPath.
// On Linux/macOS: uses $HOME or $XDG_DATA_HOME to determine the vault path.
package session

// ResolvedUser holds the result of a user session lookup.
type ResolvedUser struct {
	VaultPath string // absolute path to the per-user vault directory
	KeyPath   string // absolute path to the vault key file
	DBPath    string // absolute path to the vault database file
}
