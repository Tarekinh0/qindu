//go:build windows

package session

import (
	"fmt"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// lruMaxSize is the maximum number of entries in the PID→SID LRU cache (SR-803).
const lruMaxSize = 10000

// nolruEntry represents an entry in the PID→SID LRU cache.
type nolruEntry struct {
	pid  uint32
	sid  string
	prev *nolruEntry
	next *nolruEntry
}

// pidSIDCache is an LRU cache for PID→SID mappings.
// Not persisted to disk. Evicts least-recently-used entries when full.
// Safe for concurrent use (guarded by mu).
type pidSIDCache struct {
	mu      sync.RWMutex
	entries map[uint32]*nolruEntry
	head    *nolruEntry
	tail    *nolruEntry
	maxSize int
}

// newPIDSIDCache creates a new LRU cache with the given max size.
func newPIDSIDCache(maxSize int) *pidSIDCache {
	return &pidSIDCache{
		entries: make(map[uint32]*nolruEntry),
		maxSize: maxSize,
	}
}

// get returns the cached SID for a PID, or ("", false).
// Moves the entry to the front (most recently used).
func (c *pidSIDCache) get(pid uint32) (string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	e, ok := c.entries[pid]
	if !ok {
		return "", false
	}
	c.moveToFront(e)
	return e.sid, true
}

// put stores a PID→SID mapping. Evicts LRU if cache is full.
func (c *pidSIDCache) put(pid uint32, sid string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if e, ok := c.entries[pid]; ok {
		e.sid = sid
		c.moveToFront(e)
		return
	}

	if len(c.entries) >= c.maxSize {
		c.evictLRU()
	}

	e := &nolruEntry{pid: pid, sid: sid}
	c.entries[pid] = e
	c.pushFront(e)
}

// moveToFront moves an existing entry to the front (MRU).
func (c *pidSIDCache) moveToFront(e *nolruEntry) {
	if c.head == e {
		return
	}
	// Unlink.
	if e.prev != nil {
		e.prev.next = e.next
	}
	if e.next != nil {
		e.next.prev = e.prev
	}
	if c.tail == e {
		c.tail = e.prev
	}
	// Push to front.
	e.prev = nil
	e.next = c.head
	if c.head != nil {
		c.head.prev = e
	}
	c.head = e
	if c.tail == nil {
		c.tail = e
	}
}

// pushFront adds a new entry at the front (MRU).
func (c *pidSIDCache) pushFront(e *nolruEntry) {
	e.prev = nil
	e.next = c.head
	if c.head != nil {
		c.head.prev = e
	}
	c.head = e
	if c.tail == nil {
		c.tail = e
	}
}

// evictLRU removes the least-recently-used entry (at tail).
func (c *pidSIDCache) evictLRU() {
	if c.tail == nil {
		return
	}
	delete(c.entries, c.tail.pid)
	if c.tail.prev != nil {
		c.tail.prev.next = nil
	}
	c.tail = c.tail.prev
	if c.tail == nil {
		c.head = nil
	}
}

// Global PID→SID cache shared across all lookups.
var globalCache = newPIDSIDCache(lruMaxSize)

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

const (
	tcpTableOwnerPIDAll = 5 // TCP_TABLE_OWNER_PID_ALL
	afInet              = 2 // AF_INET
)

var (
	modiphlpapi = syscall.NewLazyDLL("iphlpapi.dll")
	//sys getExtendedTcpTable(tcpTable unsafe.Pointer, size *uint32, order bool, ulAf uint32, tableClass uint32, reserved uint32) (ret error) = iphlpapi.GetExtendedTcpTable
	procGetExtendedTcpTable = modiphlpapi.NewProc("GetExtendedTcpTable")
)

// lookupPIDFromPort finds the PID owning a TCP connection on the given local port.
// Uses GetExtendedTcpTable to enumerate TCP connections.
func lookupPIDFromPort(srcPort uint16) (uint32, error) {
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
// Finds the PID from the TCP table, resolves to user SID, and derives the vault path.
//
// On failure, returns an error. Caller must close the connection.
// There is NO fallback to a machine-level vault (SR-805).
func LookupVaultPathForPort(srcPort uint16) (*ResolvedUser, error) {
	// Find PID from TCP table.
	pid, err := lookupPIDFromPort(srcPort)
	if err != nil {
		return nil, fmt.Errorf("session: cannot resolve PID for port %d: %w", srcPort, err)
	}

	return resolvePathFromPID(pid)
}

// resolvePathFromPID resolves a PID to a user SID and vault path.
func resolvePathFromPID(pid uint32) (*ResolvedUser, error) {
	// Check LRU cache first.
	if cachedSID, ok := globalCache.get(pid); ok {
		return resolvePathFromSID(cachedSID)
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
	err = windows.OpenProcessToken(handle, windows.TOKEN_QUERY, &token)
	if err != nil {
		return nil, fmt.Errorf("session: OpenProcessToken(PID=%d) failed: %w", pid, err)
	}
	defer token.Close()

	// Get the token user SID.
	tokenUser, err := token.GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("session: GetTokenUser(PID=%d) failed: %w", pid, err)
	}

	sidStr := tokenUser.User.Sid.String()

	// Cache the mapping.
	globalCache.put(pid, sidStr)

	return resolvePathFromSID(sidStr)
}

// resolvePathFromSID derives the vault path for a given SID string.
// Uses LookupAccountSid to convert the SID to a username, then constructs
// the standard profile path: C:\Users\{username}\AppData\Local\Qindu.
func resolvePathFromSID(sidStr string) (*ResolvedUser, error) {
	sid, err := windows.StringToSid(sidStr)
	if err != nil {
		return nil, fmt.Errorf("session: invalid SID %s: %w", sidStr, err)
	}

	// Look up the username from the SID via LookupAccountSid.
	// Standard two-call pattern: first call with nil buffers to get sizes.
	var nameLen, domainLen uint32
	var sidNameUse uint32
	_ = windows.LookupAccountSid(nil, sid, nil, &nameLen, nil, &domainLen, &sidNameUse)
	// First call is expected to fail with ERROR_INSUFFICIENT_BUFFER (122);
	// nameLen and domainLen are populated with the required buffer sizes.

	nameBuf := make([]uint16, nameLen)
	domainBuf := make([]uint16, domainLen)

	err = windows.LookupAccountSid(nil, sid, &nameBuf[0], &nameLen, &domainBuf[0], &domainLen, &sidNameUse)
	if err != nil {
		return nil, fmt.Errorf("session: LookupAccountSid failed for %s: %w", sidStr, err)
	}

	username := windows.UTF16ToString(nameBuf)
	baseDir := fmt.Sprintf("C:\\Users\\%s\\AppData\\Local\\Qindu", username)

	return &ResolvedUser{
		VaultPath: baseDir,
		KeyPath:   baseDir + "\\vault.key",
		DBPath:    baseDir + "\\vault.db",
	}, nil
}
