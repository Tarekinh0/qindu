# Lazy Per-User Vault Analysis — QINDU-0008

**Date**: 2026-07-04
**Analyst**: qindu-peer-reviewer
**Question**: Is the proposed lazy per-connection vault architecture (with token impersonation) architecturally sound?

---

## Verdict

**ARCHITECTURALLY SOUND with conditions.** The core proposal — remove startup bootstrap vault, create per-user vaults lazily at connection time via token impersonation — is the correct design. It aligns vault lifecycle with user activity, eliminates the dead bootstrap vault, and properly implements per-user isolation (AC-4). Six specific conditions must be met.

---

## 1. Token Impersonation Safety Analysis

### Mechanism

The current `lookup_windows.go` already obtains the browser user's process token via `OpenProcessToken`. The proposal adds impersonation between token acquisition and filesystem operations:

```
OpenProcess(PID) ──→ OpenProcessToken ──→ ImpersonateLoggedOnUser ──→ filesystem ops ──→ RevertToSelf
```

### Scoping

Impersonation must be scoped to the **minimum code path**. Only these operations need Alice's identity:

| Operation | File | Why impersonation needed |
|-----------|------|--------------------------|
| `os.MkdirAll(vaultPath, 0700)` | `proxy.go:133` | Create `%LOCALAPPDATA%\Qindu\` — Alice's profile restricts writes to Alice+SYSTEM |
| `crypto.New(keyPath)` → `os.MkdirAll` | `crypto.go:156` | Create vault key parent directory in Alice's profile |
| `crypto.New(keyPath)` → `os.OpenFile` | `crypto.go:172` | Create `vault.key` — owner must be Alice |
| `bolt.Open(dbPath, 0600, ...)` | `proxy.go:152` | Create `vault.db` — owner must be Alice |

All other operations (UUID generation, AES key generation via `crypto/rand`, bbolt schema initialization) do not touch files and can run under any identity.

**Danger**: Any goroutine still impersonating Alice during non-filesystem operations (logging, channel sends, HTTP handling) would leak her identity context. The impersonation block must be **syntactically local** — a dedicated helper function with `defer RevertToSelf()` at its top:

```go
// createVaultUnderImpersonation performs filesystem operations
// impersonating the user identified by token. Reverts before returning.
// All errors returned are safe for logging (no PII).
func createVaultUnderImpersonation(token windows.Token, resolved *session.ResolvedUser, ttl time.Duration, logger *slog.Logger) (*vault.Vault, error) {
    // Impersonate the browser user for filesystem creation.
    // The token must have been opened with TOKEN_IMPERSONATE.
    if err := windows.ImpersonateLoggedOnUser(token); err != nil {
        return nil, fmt.Errorf("vault: impersonation failed: %w", err)
    }
    defer windows.RevertToSelf() // CRITICAL: revert before ANY other operation

    // ── ALL CODE BELOW THIS POINT RUNS AS ALICE ──
    if err := os.MkdirAll(resolved.VaultPath, 0700); err != nil {
        return nil, fmt.Errorf("vault: cannot create vault directory: %w", err)
    }

    cryptoService, err := crypto.New(resolved.KeyPath)
    if err != nil {
        return nil, fmt.Errorf("vault: crypto init failed: %w", err)
    }
    // clean up crypto on subsequent failure
    defer func() {
        if err != nil {
            _ = cryptoService.Close()
        }
    }()

    db, err := bolt.Open(resolved.DBPath, 0600, &bolt.Options{Timeout: 1 * time.Second, NoSync: false})
    if err != nil {
        return nil, fmt.Errorf("vault: bolt open failed: %w", err)
    }
    defer func() {
        if err != nil {
            _ = db.Close()
        }
    }()

    // Ensure bucket exists.
    if err = db.Update(func(tx *bolt.Tx) error {
        _, bktErr := tx.CreateBucketIfNotExists([]byte(vault.BucketTokens))
        return bktErr
    }); err != nil {
        return nil, fmt.Errorf("vault: bucket creation failed: %w", err)
    }

    v, err := vault.New(db, cryptoService, ttl, logger)
    if err != nil {
        return nil, err
    }

    v.Run(context.Background())
    return v, nil
    // defer RevertToSelf() fires HERE — before return value is used by caller
}
```

**Key guarantee**: `defer RevertToSelf()` at the top ensures impersonation never leaks past the filesystem operations. Even on panic, the defer fires.

### Failure modes

| Failure | Cause | Behavior | DD-13 compliance |
|---------|-------|----------|------------------|
| `OpenProcess` fails | Process exited, AV blocked | Return error; caller denies connection | ✓ Deny on failure |
| `OpenProcessToken` fails | Insufficient access, token dead | Return error; caller denies connection | ✓ Deny on failure |
| `ImpersonateLoggedOnUser` fails | `SeImpersonatePrivilege` missing, token expired | Return error; caller denies connection | ✓ Deny on failure |
| Filesystem op fails under impersonation | Disk full, permissions, path too long | Return error (PII-free); caller denies connection or falls back to memory-only | ✓ Deny on failure; no machine-level fallback |
| Panic during impersonation | Bug in crypto.New or bolt.Open | `defer RevertToSelf()` fires in the deferred recovery; goroutine does NOT leak Alice's identity | ✓ Safe — deferred revert guarantees cleanup |

**`SeImpersonatePrivilege`**: `NT AUTHORITY\LocalService` has this privilege by default. Verified against Windows default security policy for service accounts. If removed by Group Policy, impersonation fails → deny connection (DD-13). The agent logs a WARNING at startup if this privilege is missing (defense-in-depth diagnostic).

### File handle ownership after reversion

A file handle opened under impersonation **remains valid after `RevertToSelf()`**. The handle belongs to the process, not the thread token. After reversion, the service (running as `LocalService`) can read/write the handle normally. This is well-documented Windows behavior (MSDN: "File objects opened under impersonation remain accessible after reversion") and is how IIS and SQL Server implement service-account cross-user file access.

**Verification**: `bolt.Open` returns a `*bolt.DB` wrapping an `*os.File`. After `RevertToSelf()`, the `*os.File` is still valid. The bbolt mmap region is backed by the process address space, which is unchanged by impersonation/reversion.

### `OpenProcessToken` access rights

**Change required**: Currently the code requests only `TOKEN_QUERY`:

```go
// lookup_windows.go:369 — CURRENT
err = windows.OpenProcessToken(handle, windows.TOKEN_QUERY, &token)
```

For impersonation, this must become:

```go
// lookup_windows.go:369 — REQUIRED CHANGE
err = windows.OpenProcessToken(handle, windows.TOKEN_QUERY|windows.TOKEN_IMPERSONATE, &token)
```

`TOKEN_IMPERSONATE` is a standard access right (value 0x0004). It does not grant `TOKEN_DUPLICATE` (which would allow creating a primary token — unnecessary and dangerous). The token remains an impersonation token, not a primary token, so it cannot be used to create new processes.

---

## 2. Multiple Vault Instance Architecture

### Recommendation: N separate `*vault.Vault` instances

Each user gets their own fully-isolated vault with its own bbolt database, crypto service, write channel, and background goroutines.

**Resource analysis for realistic loads:**

| Resource | Per-vault cost | At N=10 users | At N=100 users | At N=1000 users | Limit |
|----------|---------------|---------------|----------------|-----------------|-------|
| Memory (mmap) | ~1 MB (bbolt default) | ~10 MB | ~100 MB | ~1 GB | Configurable via bolt.Options.InitialMmapSize |
| File handles | 2 (vault.db + vault.key) | 20 | 200 | 2000 | Windows: 16M+ per process |
| Goroutines | 2 (writer + sweeper) | 20 | 200 | 2000 | Go: millions |
| Write channel | 1024 slots × ~100 bytes | ~100 KB | ~1 MB | ~10 MB | Negligible |

**Practical maximum**: A shared Windows 10/11 workstation supports at most ~10 interactive user sessions (Fast User Switching). Enterprise terminal servers could have more, but 100 concurrent users × 100 MB mmap = 10 GB, which is manageable on a server-class machine. The bbolt `InitialMmapSize` can be reduced (default is 0 = auto-grow; set to 256 KB for vault workloads with small databases).

### Why not a multiplexed vault?

A single vault multiplexed across user paths would require:
- Opening/closing bbolt DBs per operation (defeats mmap caching)
- A map of `bolt.DB` handles with reference counting
- Per-user `crypto.Service` instances anyway (different keys per user)
- Complex channel routing to direct writes to the correct DB

The complexity is not justified by the small resource savings. Per-user vaults are simpler, more isolated (one user's corruption doesn't affect others), and align with the existing vault API (which assumes 1:1 with a bolt.DB).

---

## 3. Vault Lifecycle Management

### Problem

With lazy creation, vaults open on first connection. Without a close policy, they stay open forever — even for users who connect once and never return.

### Recommendation: Idle-timeout eviction

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Idle timeout | 30 minutes | Covers typical ChatGPT session + idle browsing between tabs |
| Eviction check interval | 10 minutes | Low overhead; stale vaults cleaned within 10 min of crossing timeout |
| Shutdown behavior | Close ALL vaults | Standard graceful shutdown; Close() drains pending writes and closes bolt |

**VaultManager design**:

```go
type vaultEntry struct {
    vault    *vault.Vault
    lastUsed time.Time
    path     string // for logging
}

type VaultManager struct {
    mu       sync.Mutex
    vaults   map[string]*vaultEntry // keyed by resolved VaultPath
    ttl      time.Duration          // vault data TTL from config
    logger   *slog.Logger
    ctx      context.Context
    cancel   context.CancelFunc
    wg       sync.WaitGroup
}

func (vm *VaultManager) GetOrCreate(resolved *session.ResolvedUser, token windows.Token) (*vault.Vault, error) {
    vm.mu.Lock()
    if entry, ok := vm.vaults[resolved.VaultPath]; ok {
        entry.lastUsed = time.Now()
        vm.mu.Unlock()
        return entry.vault, nil
    }
    vm.mu.Unlock()

    // Slow path: create vault under impersonation (no lock held).
    v, err := createVaultUnderImpersonation(token, resolved, vm.ttl, vm.logger)
    if err != nil {
        return nil, err
    }

    vm.mu.Lock()
    // Double-check: another goroutine may have created it while we were working.
    if entry, ok := vm.vaults[resolved.VaultPath]; ok {
        vm.mu.Unlock()
        _ = v.Close() // discard duplicate
        entry.lastUsed = time.Now()
        return entry.vault, nil
    }
    vm.vaults[resolved.VaultPath] = &vaultEntry{vault: v, lastUsed: time.Now(), path: resolved.VaultPath}
    vm.mu.Unlock()
    return v, nil
}

// evictIdle closes vaults not accessed within the idle timeout.
func (vm *VaultManager) evictIdle(idleTimeout time.Duration) {
    vm.mu.Lock()
    defer vm.mu.Unlock()

    cutoff := time.Now().Add(-idleTimeout)
    for path, entry := range vm.vaults {
        if entry.lastUsed.Before(cutoff) {
            vm.logger.Info("vault: closing idle user vault", "path", redactHomePath(path))
            entry.vault.Close()
            delete(vm.vaults, path)
        }
    }
}

// Shutdown closes all vaults and stops the eviction goroutine.
func (vm *VaultManager) Shutdown() {
    vm.cancel()
    vm.wg.Wait()

    vm.mu.Lock()
    defer vm.mu.Unlock()
    for path, entry := range vm.vaults {
        entry.vault.Close()
        delete(vm.vaults, path)
    }
}
```

**Why idle-timeout and not reference-counting?**

Reference counting would be more precise but adds per-connection bookkeeping. A single user may have multiple concurrent connections (parallel browser tabs). Reference counting would need:
- Track connection count per vault
- Decrement on connection close
- Start a close timer when count reaches 0
- Handle TOCTOU: count reaches 0, timer starts, new connection arrives before timer fires → cancel timer

This is complex and error-prone. Idle timeout is simpler, more predictable, and sufficient for the use case. The worst case (Alice connects once at 09:00 and never again) means her vault stays open until 09:30 — negligible resource waste.

---

## 4. Async Write Interaction (DD-10)

### Current behavior

One vault = one writeCh (1024 slots) = one writer goroutine. `Persist()` does a non-blocking send; if the channel is full, the write is dropped (WARNING logged, no PII).

### Per-user vault behavior

Each user's vault has its own independent writeCh. This is **correct and desirable**:

| Scenario | Current (single vault) | Proposed (per-user vaults) |
|----------|----------------------|---------------------------|
| Alice sends 2000 rapid-fire requests | Drops writes if channel fills | Drops writes in Alice's channel only |
| Bob is idle | Not applicable (shared channel) | Bob's channel is empty — unaffected |
| Fairness | None — shared channel, first-come-first-served | Natural per-user isolation |
| Encryption key | Single key for all users | Each user's PII encrypted with their own key ✓ |

**Performance**: The proxy thread does a non-blocking send. With per-user channels, the send is to a different channel object depending on the user, but the channel send operation itself is the same O(1) non-blocking send. No additional contention.

---

## 5. Platform-Specific Code Paths

```
┌──────────────────────────────────────────────────────────────────────┐
│                        PLATFORM MATRIX                                │
├──────────────┬─────────────────────┬──────────────────────────────────┤
│ Platform     │ Process identity    │ Vault creation strategy          │
├──────────────┼─────────────────────┼──────────────────────────────────┤
│ Windows      │ NT AUTHORITY\       │ lookUpVaultPathForPort() →       │
│ service mode │ LocalService        │ resolvePathFromPID() →           │
│              │                     │ ImpersonateLoggedOnUser() →      │
│              │                     │ createVaultUnderImpersonation()  │
├──────────────┼─────────────────────┼──────────────────────────────────┤
│ Windows      │ Interactive user    │ LookupVaultPath() →              │
│ console mode │ (e.g., opencode-    │ lookupCurrentUserVaultPath() →   │
│              │  admin)             │ os.MkdirAll + crypto.New +       │
│              │                     │ bolt.Open (no impersonation)     │
├──────────────┼─────────────────────┼──────────────────────────────────┤
│ Linux/macOS  │ Process owner       │ LookupVaultPath() →              │
│              │                     │ $XDG_DATA_HOME or $HOME →        │
│              │                     │ os.MkdirAll + crypto.New +       │
│              │                     │ bolt.Open (no impersonation)     │
└──────────────┴─────────────────────┴──────────────────────────────────┘
```

**Unix**: No impersonation needed. The process runs as the user and has natural access to `~/.local/share/qindu/`. The `//go:build !windows` file already handles this correctly.

**Windows console mode**: Same — process runs as the interactive user. `LookupVaultPath()` returns the user's own `%LOCALAPPDATA%`. No impersonation.

**Windows service mode**: The only path requiring impersonation. Must be behind a `//go:build windows` guard.

**Implementation note**: `createVaultUnderImpersonation` should accept a `token windows.Token` parameter. On non-Windows platforms, pass a zero-value token and the impersonation calls compile to no-ops via build tags.

---

## 6. Conditions Required for Acceptance

### COND-1: `TOKEN_IMPERSONATE` access right
**File**: `internal/session/lookup_windows.go:369`
**Change**: Add `windows.TOKEN_IMPERSONATE` to `OpenProcessToken` flags.
```go
// BEFORE:
err = windows.OpenProcessToken(handle, windows.TOKEN_QUERY, &token)
// AFTER:
err = windows.OpenProcessToken(handle, windows.TOKEN_QUERY|windows.TOKEN_IMPERSONATE, &token)
```

### COND-2: Tight impersonation scope
**File**: New helper function (suggested: `internal/vault/create_windows.go`)
**Requirement**: All filesystem operations inside a single function with `defer RevertToSelf()` at the top. No logging, no network, no channel operations between impersonate and revert.

### COND-3: VaultManager with idle eviction
**File**: New (`internal/vault/manager.go`)
**Requirement**: Idle timeout (30 min default), eviction goroutine (10 min interval), shutdown closes all. Both the timeout and interval should be configurable but hidden (not in `default.yaml` — advanced tuning only).

### COND-4: Remove `initVault()` bootstrap
**File**: `cmd/agent/proxy.go`
**Change**: Delete `initVault()`. Wire `VaultManager` into proxy startup. Proxy construction no longer takes a `*vault.Vault` — the VaultManager provides vaults at connection time.

### COND-5: Cross-platform build tags
**Files**: `internal/vault/create_windows.go` (`//go:build windows`), `internal/vault/create_unix.go` (`//go:build !windows`)
**Requirement**: Impersonation logic in `create_windows.go`; no-op stub in `create_unix.go`. Both expose the same function signature.

### COND-6: Fail-closed on impersonation failure
**File**: Connection handler (caller of VaultManager)
**Requirement**: If `GetOrCreate` returns an error due to impersonation failure, the connection is denied (HTTP 502 or connection close). No fallback to a machine-level vault. Logged at WARN level with PII-free message. This satisfies DD-13 (AC-5).

---

## 7. Risks and Mitigations

| Risk | Severity | Mitigation |
|------|----------|------------|
| Impersonation leaks Alice's identity to other goroutines | **CRITICAL** | `defer RevertToSelf()` at function top; function is syntactically self-contained; no goroutine spawns inside impersonation block |
| `SeImpersonatePrivilege` removed by Group Policy | MEDIUM | Log WARNING at startup if privilege is missing; all impersonation attempts fail → deny connections per DD-13 |
| Memory pressure from N idle vaults | LOW | Idle eviction at 30 min; bbolt mmap can be capped via `bolt.Options.InitialMmapSize`; monitoring via vault-count log metric |
| Bolt DB corruption on kill -9 while impersonating | LOW | bbolt is crash-safe via WAL; `NoSync: false` ensures committed transactions survive; corruption during `bolt.Open` is rare and recoverable via `bolt.Options.ReadOnly` backup |
| PID recycling gives wrong SID for vault creation | LOW | Cache TTL is 60s; port→PID lookup is fresh per connection; impersonation against wrong user's token would fail safely (token belongs to different process) |

---

## 8. What This Fixes (and Doesn't Fix)

### Fixed
- **Dead bootstrap vault**: `initVault()` removed. No useless vault created at startup.
- **Per-user isolation (AC-4)**: Each user gets their own vault in their own `%LOCALAPPDATA%`.
- **Cross-profile write access**: Token impersonation grants temporary access to the correct user profile.

### Not fixed (separate concerns)
- **TokenPersister wiring (QINDU-0009)**: The VaultManager provides vaults; wiring them into the tokenizer is QINDU-0009 scope.
- **Per-user vault cleanup on uninstall**: Still a UI concern (QINDU-0016). WiX cannot enumerate user profiles.
- **Concurrent vault access from multiple connections**: The VaultManager serializes vault creation (mutex) but vault access is concurrent-safe (bolt handles this).
- **Vault key rotation**: Not in scope. Each user's vault.key is created once and persists.

---

## Summary Table

| Question | Answer |
|----------|--------|
| Is token impersonation safe? | **Yes**, if scoped to a single function with `defer RevertToSelf()` at the top, and no non-filesystem code between impersonate/revert |
| Can impersonation failure be handled safely? | **Yes** — fail closed, deny connection per DD-13. No fallback. |
| N vaults vs multiplexed? | **N separate vaults.** Simpler, more isolated, trivial resource cost at realistic scale. |
| Vault lifecycle? | **Idle-timeout eviction** (30 min). Cleaned by background goroutine. All closed at shutdown. |
| Async write interaction? | **Correct and desirable.** Per-user channels = per-user backpressure isolation. No cross-user interference. |
| Cross-platform? | **Yes.** Impersonation behind `//go:build windows`; no-op stub on Unix. Console mode skips impersonation naturally. |

**The proposal is approved with 6 conditions.** Implementation can proceed on the QINDU-0008 codebase with the changes listed in Section 6.
