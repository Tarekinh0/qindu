//go:build windows

package session

import (
	"fmt"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// lruMaxSize is the maximum number of entries in the PID→LocalAppData cache (SR-803).
const lruMaxSize = 10000

// cacheTTL is the maximum age of a cached entry before it's considered stale.
// PID recycling by the OS means a cached entry could be for a different process
// after the original exits. 60 seconds is a safe bound: a new connection from
// the same PID within 60s is almost certainly the same process, and the TTL
// is short enough that PID recycling won't cause incorrect user attribution.
const cacheTTL = 60 * time.Second

// cacheEntry stores the resolved LocalAppData path for a PID and the time
// it was cached.
type cacheEntry struct {
	localAppData string
	ts           time.Time
}

// pidLocalAppDataCache caches PID → LocalAppData path mappings.
// This avoids repeated OpenProcess/OpenProcessToken/SHGetKnownFolderPath
// syscalls for the same PID on subsequent connections.
//
// Uses a simple map with sync.Mutex (not RWMutex) since reads may need to
// delete stale entries. Eviction is oldest-first when the map exceeds maxSize.
//
// Not persisted to disk. Safe for concurrent use.
type pidLocalAppDataCache struct {
	mu      sync.Mutex
	entries map[uint32]cacheEntry
	maxSize int
}

// newPIDLocalAppDataCache creates a new cache with the given max size.
func newPIDLocalAppDataCache(maxSize int) *pidLocalAppDataCache {
	return &pidLocalAppDataCache{
		entries: make(map[uint32]cacheEntry),
		maxSize: maxSize,
	}
}

// get returns the cached LocalAppData path for a PID, or ("", false).
// Entries older than cacheTTL are considered stale and evicted.
func (c *pidLocalAppDataCache) get(pid uint32) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	e, ok := c.entries[pid]
	if !ok {
		return "", false
	}
	if time.Since(e.ts) > cacheTTL {
		delete(c.entries, pid)
		return "", false
	}
	return e.localAppData, true
}

// put stores a PID→LocalAppData mapping. Evicts the oldest entry if cache is full.
func (c *pidLocalAppDataCache) put(pid uint32, localAppData string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries[pid] = cacheEntry{
		localAppData: localAppData,
		ts:           time.Now(),
	}

	if len(c.entries) > c.maxSize {
		c.evictOldest()
	}
}

// evictOldest removes the entry with the earliest timestamp.
// Must be called with c.mu held.
func (c *pidLocalAppDataCache) evictOldest() {
	var oldestPid uint32
	var oldestTs time.Time
	first := true
	for pid, e := range c.entries {
		if first || e.ts.Before(oldestTs) {
			oldestPid = pid
			oldestTs = e.ts
			first = false
		}
	}
	if !first {
		delete(c.entries, oldestPid)
	}
}

// Global PID→LocalAppData cache shared across all lookups.
var globalCache = newPIDLocalAppDataCache(lruMaxSize)

// LookupOption configures vault path resolution behavior.
type LookupOption func(*lookupConfig)

// lookupConfig holds parameterized settings for vault path resolution.
type lookupConfig struct {
	cache *pidLocalAppDataCache
}

// WithCache injects a cache for PID→LocalAppData mappings.
// When nil, the globalCache is used. Intended for test isolation.
func WithCache(cache *pidLocalAppDataCache) LookupOption {
	return func(cfg *lookupConfig) {
		if cache != nil {
			cfg.cache = cache
		}
	}
}

// ---------------------------------------------------------------------------
// MIB_TCPROW_OWNER_PID — row from GetExtendedTcpTable with owning PID.
// ---------------------------------------------------------------------------

type mibTCPRowOwnerPID struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
	OwningPid  uint32
}

// mibUDPRowOwnerPID — row from GetExtendedUdpTable with owning PID.
type mibUDPRowOwnerPID struct {
	LocalAddr uint32
	LocalPort uint32
	OwningPid uint32
}

const (
	tcpTableOwnerPIDAll = 5 // TCP_TABLE_OWNER_PID_ALL
	udpTableOwnerPID    = 1 // UDP_TABLE_OWNER_PID
	afInet              = 2 // AF_INET
)

var (
	modiphlpapi = syscall.NewLazyDLL("iphlpapi.dll")
	//sys getExtendedTcpTable(tcpTable unsafe.Pointer, size *uint32, order bool, ulAf uint32, tableClass uint32, reserved uint32) (ret error) = iphlpapi.GetExtendedTcpTable
	procGetExtendedTcpTable = modiphlpapi.NewProc("GetExtendedTcpTable")
	//sys getExtendedUdpTable(udpTable unsafe.Pointer, size *uint32, order bool, ulAf uint32, tableClass uint32, reserved uint32) (ret error) = iphlpapi.GetExtendedUdpTable
	procGetExtendedUdpTable = modiphlpapi.NewProc("GetExtendedUdpTable")

	modshell32               = syscall.NewLazyDLL("shell32.dll")
	procSHGetKnownFolderPath = modshell32.NewProc("SHGetKnownFolderPath")
)

// lookupPIDFromPort finds the PID owning a connection on the given local port.
// Queries both TCP and UDP tables (DD-13). TCP is checked first since HTTP CONNECT
// traffic is TCP-based; UDP is checked as a fallback for QUIC/HTTP3 connections.
func lookupPIDFromPort(srcPort uint16) (uint32, error) {
	pid, err := lookupPIDFromTCPPort(srcPort)
	if err == nil {
		return pid, nil
	}

	pid, err = lookupPIDFromUDPPort(srcPort)
	if err == nil {
		return pid, nil
	}

	return 0, fmt.Errorf("session: no TCP or UDP connection found for port %d", srcPort)
}

// lookupPIDFromTCPPort finds the PID owning a TCP connection on the given local port.
// Uses GetExtendedTcpTable to enumerate TCP connections.
func lookupPIDFromTCPPort(srcPort uint16) (uint32, error) {
	// First call to get required buffer size.
	var bufSize uint32
	ret, _, _ := procGetExtendedTcpTable.Call(
		0, // pTcpTable = nil
		uintptr(unsafe.Pointer(&bufSize)),
		1, // order = true (sort)
		uintptr(afInet),
		uintptr(tcpTableOwnerPIDAll),
		0, // reserved
	)
	if ret != uintptr(syscall.ERROR_INSUFFICIENT_BUFFER) {
		return 0, fmt.Errorf("session: GetExtendedTcpTable sizing failed: %d", ret)
	}

	// Allocate buffer.
	buf := make([]byte, bufSize)

	// Second call to fill the table.
	ret, _, _ = procGetExtendedTcpTable.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&bufSize)),
		1,
		uintptr(afInet),
		uintptr(tcpTableOwnerPIDAll),
		0,
	)
	if ret != 0 {
		return 0, fmt.Errorf("session: GetExtendedTcpTable failed: %d", ret)
	}

	// Parse table: first 4 bytes = numEntries, then array of MIB_TCPROW_OWNER_PID.
	if len(buf) < 4 {
		return 0, fmt.Errorf("session: TCP table too short")
	}
	numEntries := *(*uint32)(unsafe.Pointer(&buf[0]))
	rowSize := uint32(unsafe.Sizeof(mibTCPRowOwnerPID{}))
	rowsStart := 4 // skip DWORD

	for i := uint32(0); i < numEntries; i++ {
		offset := rowsStart + int(i*rowSize)
		if offset+int(rowSize) > len(buf) {
			break
		}
		row := (*mibTCPRowOwnerPID)(unsafe.Pointer(&buf[offset]))
		// LocalPort is in network byte order (big-endian) within the uint32.
		// Swap bytes to get host byte order port.
		actualPort := uint16(row.LocalPort>>8) | uint16(row.LocalPort<<8)
		if actualPort == srcPort {
			return row.OwningPid, nil
		}
	}

	return 0, fmt.Errorf("session: no TCP connection found for port %d", srcPort)
}

// lookupPIDFromUDPPort finds the PID owning a UDP socket on the given local port.
// Uses GetExtendedUdpTable to enumerate UDP connections.
// UDP is unlikely for HTTP CONNECT but possible for QUIC/HTTP3 (DD-13).
func lookupPIDFromUDPPort(srcPort uint16) (uint32, error) {
	// First call to get required buffer size.
	var bufSize uint32
	ret, _, _ := procGetExtendedUdpTable.Call(
		0, // pUdpTable = nil
		uintptr(unsafe.Pointer(&bufSize)),
		1, // order = true (sort)
		uintptr(afInet),
		uintptr(udpTableOwnerPID),
		0, // reserved
	)
	if ret != uintptr(syscall.ERROR_INSUFFICIENT_BUFFER) {
		return 0, fmt.Errorf("session: GetExtendedUdpTable sizing failed: %d", ret)
	}

	// Allocate buffer.
	buf := make([]byte, bufSize)

	// Second call to fill the table.
	ret, _, _ = procGetExtendedUdpTable.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&bufSize)),
		1,
		uintptr(afInet),
		uintptr(udpTableOwnerPID),
		0,
	)
	if ret != 0 {
		return 0, fmt.Errorf("session: GetExtendedUdpTable failed: %d", ret)
	}

	// Parse table: first 4 bytes = numEntries, then array of MIB_UDPROW_OWNER_PID.
	if len(buf) < 4 {
		return 0, fmt.Errorf("session: UDP table too short")
	}
	numEntries := *(*uint32)(unsafe.Pointer(&buf[0]))
	rowSize := uint32(unsafe.Sizeof(mibUDPRowOwnerPID{}))
	rowsStart := 4 // skip DWORD

	for i := uint32(0); i < numEntries; i++ {
		offset := rowsStart + int(i*rowSize)
		if offset+int(rowSize) > len(buf) {
			break
		}
		row := (*mibUDPRowOwnerPID)(unsafe.Pointer(&buf[offset]))
		// LocalPort is in network byte order (big-endian) within the uint32.
		actualPort := uint16(row.LocalPort>>8) | uint16(row.LocalPort<<8)
		if actualPort == srcPort {
			return row.OwningPid, nil
		}
	}

	return 0, fmt.Errorf("session: no UDP socket found for port %d", srcPort)
}

// LookupVaultPath returns the vault path for the current user.
// Uses the current process user's profile path.
// For service mode with per-user isolation (connection context required),
// use LookupVaultPathForPort instead.
func LookupVaultPath() (*ResolvedUser, error) {
	return lookupCurrentUserVaultPath()
}

// lookupCurrentUserVaultPath returns the vault path for the current user
// using %LOCALAPPDATA%.
func lookupCurrentUserVaultPath() (*ResolvedUser, error) {
	localAppData, err := windows.KnownFolderPath(windows.FOLDERID_LocalAppData, windows.KF_FLAG_DEFAULT)
	if err != nil {
		return nil, fmt.Errorf("session: failed to get LocalAppData: %w", err)
	}

	baseDir := localAppData + "\\Qindu"
	return &ResolvedUser{
		VaultPath: baseDir,
		KeyPath:   baseDir + "\\vault.key",
		DBPath:    baseDir + "\\vault.db",
	}, nil
}

// LookupVaultPathForPort resolves the vault path for a connection from the given source port.
// Finds the PID from both TCP and UDP tables (DD-13), resolves to the user's LocalAppData
// path via OpenProcessToken + SHGetKnownFolderPath, and derives the vault path.
//
// Options:
//   - WithCache(*pidLocalAppDataCache): inject a test cache. Defaults to globalCache if nil.
//
// On failure, returns an error. Caller must close the connection.
// There is NO fallback to a machine-level vault (SR-805).
func LookupVaultPathForPort(srcPort uint16, opts ...LookupOption) (*ResolvedUser, error) {
	cfg := lookupConfig{cache: globalCache}
	for _, o := range opts {
		o(&cfg)
	}

	// Find PID from TCP table (checked first) or UDP table (fallback).
	pid, err := lookupPIDFromPort(srcPort)
	if err != nil {
		return nil, fmt.Errorf("session: cannot resolve PID for port %d: %w", srcPort, err)
	}

	return resolvePathFromPID(pid, cfg.cache)
}

// resolvePathFromPID resolves a PID to a user's LocalAppData and vault path.
// Uses SHGetKnownFolderPath with the process token to determine the correct
// LocalAppData path regardless of drive letter or Windows localization (PR-003).
// cache is the PID→LocalAppData cache to use (nil defaults to globalCache).
func resolvePathFromPID(pid uint32, cache *pidLocalAppDataCache) (*ResolvedUser, error) {
	if cache == nil {
		cache = globalCache
	}
	// Check cache first (TTL-aware, PR-001, PR-106).
	if cached, ok := cache.get(pid); ok {
		return buildResolvedUser(cached), nil
	}

	// Open the process.
	handle, err := windows.OpenProcess(
		windows.PROCESS_QUERY_LIMITED_INFORMATION,
		false,
		pid,
	)
	if err != nil {
		return nil, fmt.Errorf("session: OpenProcess(PID=%d) failed: %w", pid, err)
	}
	defer windows.CloseHandle(handle)

	// Open the process token.
	var token windows.Token
	err = windows.OpenProcessToken(handle, windows.TOKEN_QUERY|0x0004, &token) // 0x0004 = TOKEN_IMPERSONATE
	if err != nil {
		return nil, fmt.Errorf("session: OpenProcessToken(PID=%d) failed: %w", pid, err)
	}
	defer token.Close()

	// Get LocalAppData for this user using SHGetKnownFolderPath with the
	// user's token. This correctly resolves the path regardless of drive
	// letter, user profile directory location, or Windows localization (PR-003).
	localAppData, err := getLocalAppDataForToken(token)
	if err != nil {
		return nil, err
	}

	// Cache the mapping (PR-001, PR-106: TTL-aware, sync.Mutex).
	cache.put(pid, localAppData)

	return buildResolvedUser(localAppData), nil
}

// getLocalAppDataForToken calls SHGetKnownFolderPath with FOLDERID_LocalAppData
// using the specified token. Returns the absolute path to the user's
// AppData\Local directory.
func getLocalAppDataForToken(token windows.Token) (string, error) {
	var pszPath *uint16
	r0, _, _ := procSHGetKnownFolderPath.Call(
		uintptr(unsafe.Pointer(windows.FOLDERID_LocalAppData)),
		uintptr(windows.KF_FLAG_CREATE),
		uintptr(token),
		uintptr(unsafe.Pointer(&pszPath)),
	)
	if r0 != 0 {
		return "", fmt.Errorf("session: SHGetKnownFolderPath failed: HRESULT 0x%x", r0)
	}
	defer windows.CoTaskMemFree(unsafe.Pointer(pszPath))
	return windows.UTF16PtrToString(pszPath), nil
}

// buildResolvedUser constructs a ResolvedUser from a LocalAppData path.
func buildResolvedUser(localAppData string) *ResolvedUser {
	baseDir := localAppData + "\\Qindu"
	return &ResolvedUser{
		VaultPath: baseDir,
		KeyPath:   baseDir + "\\vault.key",
		DBPath:    baseDir + "\\vault.db",
	}
}
