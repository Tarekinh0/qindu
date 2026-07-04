# QINDU-0008 Peer Review — Blinded, Blank-Slate

**Reviewer**: qindu-peer-reviewer (senior Go developer)
**Date**: 2026-07-04
**Sprint**: QINDU-0008 — Vault local chiffré
**Scope**: `internal/crypto/`, `internal/vault/`, `internal/session/`, `internal/tokenize/tokenizer.go`, `internal/policy/config.go`, `cmd/agent/proxy.go`, `internal/proxy/proxy.go`, `internal/interceptor/monitor.go`, `configs/default.yaml`
**Method**: Blind review against `story.md` only. No DPO/CISO/DevSecOps notes consulted.

---

## Section 1: Scorecard

| Framework | Score | Justification |
|-----------|-------|---------------|
| **Clean Code** | 3/5 | Good naming, well-sized functions. Marred by dead code in `lookup_windows.go` (three unused port-conversion attempts with `_ =` hacks), a placeholder path-construction that silently produces garbage output, and a confusing double-drain in vault.Close(). |
| **Pragmatic Programmer** | 3/5 | Orthogonality between crypto/vault/tokenizer is good. The LRU cache in `session` has no locking — violates "design by contract" for concurrent safety. The `Run(ctx)` API is misleading (ctx ignored). |
| **SOLID** | 4/5 | SRP well-applied: crypto package does one thing, vault does persistence, session does path resolution. ISP respected: TokenPersister has exactly 2 methods. DIP applied: Tokenizer depends on TokenPersister interface, not Vault. OCP through options pattern (`WithPersister`). One violation: `resolvePathFromSID` hardcodes `C:\Users\` — not open for extension. |
| **Go Proverbs** | 3/5 | Errors are wrapped properly with `%w`. No panics in library code. Global mutable state in `globalCache` without synchronization. Dead code with `var _ =` hacks. Channel concurrency in shutdown path is fragile. |
| **Effective Go** | 3/5 | Idiomatic naming, proper use of `defer`, `gofmt`-compliant. Build tags correctly applied. Issues: unused variables suppressed with `_ =`, placeholder code that cannot work, `isClosed()` uses exclusive lock for read. |
| **DDD** | 3/5 | Ubiquitous language: "vault", "persister", "scope", "conversation", "metadata" — well-chosen. Bounded contexts clean between crypto/vault/session. Missing: conversation UUID generation (`NewConversationID`) is exported but never wired into a production code path. The vault bubble exists but the integration seam (monitor interceptor → persister) is an empty pipe. |
| **Code Complete** | 3/5 | Good defensive programming in vault (nil checks, channel full handling, closed checks). Missing: no validation that `Scope.Provider` is non-empty before constructing bbolt keys, no bound on `pii_types` slice growth in metadata, `parseConfigTTL` silently swallows invalid values. |

**Overall**: 3.1/5 — **Below the merge bar. Critical architectural gaps in `session/lookup_windows.go` prevent Windows service-mode vault isolation (AC-4, AC-5). Data races in the global LRU cache violate AC-15.**

---

## Section 2: Critical Findings 🔴

### PR-001: SID path resolution produces garbage paths (placeholder code in production)
- **File**: `internal/session/lookup_windows.go`, lines 306–331
- **Severity**: CRITICAL
- **Affects**: AC-4 (per-user isolation), AC-5 (SID lookup fail → deny)
- **Problem**: `resolvePathFromSID` constructs the vault path by interpolating the SID string directly as a username:

```go
baseDir := fmt.Sprintf("C:\\Users\\%s\\AppData\\Local\\Qindu", sidStr)
```

A SID looks like `S-1-5-21-3623811015-3361044348-30300820-1013`. This produces:
```
C:\Users\S-1-5-21-3623811015-3361044348-30300820-1013\AppData\Local\Qindu
```

This path does not exist. The vault initialization will fail with "cannot create vault directory" (line 81–84 of `proxy.go`), and the proxy will fall back to memory-only mode, silently degrading with no warning that the path was nonsensical. The code even includes a self-incriminating comment: *"This is a placeholder — the actual implementation would use SHGetKnownFolderPath with the user's token."*

**Fix**: Implement proper profile directory resolution. On Windows, you must use `LoadUserProfileW` + `GetUserProfileDirectoryW` or `SHGetKnownFolderPath` with the user's token to get the real `AppData\Local` path for a given SID. The `resolvePathFromSID` function currently receives `sidStr` but throws it away (lines 308–312: `sid, err := windows.StringToSid(sidStr) ... _ = sid`). It must either:
1. Call `SHGetKnownFolderPath` with the user's token (requires the token handle which is closed at line 289 of `resolvePathFromPID` — the SID must be cached *before* token close and path resolution deferred), or
2. Look up the username from SID via `LookupAccountSid`, then construct `C:\Users\{username}\AppData\Local\Qindu`.

Without this fix, the multi-user vault isolation story (AC-4) **cannot be verified** even in a QEMU test.

---

### PR-002: Data race on global LRU cache (`globalCache` — no synchronization)
- **File**: `internal/session/lookup_windows.go`, lines 125–126, 268–301
- **Severity**: CRITICAL
- **Affects**: AC-15 (race-free), AC-16 (SID cache prevents repeated lookups)
- **Problem**: The `globalCache` variable is a package-level shared mutable state:

```go
var globalCache = newPIDSIDCache(lruMaxSize)
```

It is accessed from `resolvePathFromPID()` (line 268: `globalCache.get(pid)`; line 300: `globalCache.put(pid, sidStr)`) without any mutex protection. The `pidSIDCache` struct has no internal locking mechanism — its `get()`, `put()`, `moveToFront()`, `pushFront()`, and `evictLRU()` methods all mutate the linked list (`nolruEntry.prev/next`) and map (`c.entries`) without synchronization.

In a service-mode proxy handling multiple concurrent connections, multiple goroutines will call `resolvePathFromPID` simultaneously. This produces data races on:
- The `map[uint32]*nolruEntry` (concurrent map reads + writes without sync)
- The doubly-linked list pointers (`prev`, `next`, `head`, `tail`)
- The `len(c.entries)` check on line 60

`go test -race` on the windows build tag would fail for any concurrent test of this code.

**Fix**: Add a `sync.RWMutex` to `pidSIDCache` and hold it in `get()` and `put()`. Alternatively, replace the hand-rolled LRU with a concurrency-safe structure. The simplest fix:

```go
type pidSIDCache struct {
    mu      sync.RWMutex
    entries map[uint32]*nolruEntry
    // ...
}

func (c *pidSIDCache) get(pid uint32) (string, bool) {
    c.mu.RLock()
    defer c.mu.RUnlock()
    // ...
}

func (c *pidSIDCache) put(pid uint32, sid string) {
    c.mu.Lock()
    defer c.mu.Unlock()
    // ...
}
```

---

### PR-003: Port byte-order mismatch in TCP table lookup
- **File**: `internal/session/lookup_windows.go`, lines 197–211
- **Severity**: CRITICAL
- **Affects**: AC-4, AC-5 (SID resolution via port)
- **Problem**: The `lookupPIDFromPort` function has three attempts at port conversion, but the one actually used is wrong:

```go
// Line 199: Comment says "LocalPort is in network byte order" — CORRECT
port := uint16(row.LocalPort>>16 | row.LocalPort&0xFFFF)  // _ = port
// Line 203: The correct ntohs for a uint32 in network byte order
port2 := uint16(row.LocalPort>>8 | row.LocalPort<<8)       // _ = port2
// Line 208: The one actually used — WRONG
actualPort := uint16(row.LocalPort)
if actualPort == srcPort {
    return row.OwningPid, nil
}
```

`GetExtendedTcpTable` with `AF_INET` returns `LocalPort` as a `DWORD` (uint32) in **network byte order** where the port occupies the lower 16 bits in network order. Casting to `uint16` truncates the high 16 bits but does NOT convert byte order. On a little-endian machine (x86/x64), `row.LocalPort` for port 8787 (0x2253 in host order, 0x5322 in network order) would be stored as `0x2253` in host memory but `0x5322` in network order. The `uint16()` cast gives `0x5322` (21282 decimal), which will never match `srcPort` (8787).

The code had the correct conversion at line 203 (`row.LocalPort>>8 | row.LocalPort<<8` — a 16-bit byte swap on the lower 16 bits) but intentionally discarded it. This guarantees `lookupPIDFromPort` never finds a match, causing SID resolution to fail for every connection in service mode.

**Fix**: Delete the dead code and use the correct conversion:

```go
// LocalPort is in network byte order (big-endian) within the uint32.
// Swap bytes to get host byte order port.
actualPort := uint16(row.LocalPort>>8) | uint16(row.LocalPort<<8)
if actualPort == srcPort {
    return row.OwningPid, nil
}
```

For `AF_INET`, the `LocalPort` field in `MIB_TCPROW_OWNER_PID` is only meaningful in the lower 16 bits. The correct Windows API pattern is:

```go
actualPort := uint16(row.LocalPort>>8&0xFF | row.LocalPort<<8&0xFF00)
```

---

### PR-004: Concurrent channel drain in vault shutdown — fragile double-consumer pattern
- **File**: `internal/vault/vault.go`, lines 168–186 (`writeLoop`) and 428–491 (`Close`)
- **Severity**: HIGH
- **Affects**: AC-7 (graceful shutdown drains queue)
- **Problem**: The shutdown sequence in `Close()` is:

1. `v.cancel()` → triggers `writeLoop` to call `drainRemaining()`
2. `close(v.writeCh)` → signals no more writes
3. `Close()` enters its own drain loop, reading from the now-closed channel
4. `v.wg.Wait()` → waits for `writeLoop` to finish

Between steps 1 and 3, **both** `writeLoop.drainRemaining()` and `Close()` are reading from `v.writeCh` simultaneously. `drainRemaining()` uses a non-blocking select with a `default` case, so it exits as soon as no items are immediately available. But during the window where both are reading, an item could go to either consumer. If `drainRemaining()` receives an item, `Close()`'s count is off. If both receive, the channel semantics are intact (Go channels are safe for multiple receivers), but the drained count is wrong in logs and the item-handling order is unpredictable.

The real issue is architectural: the shutdown path has **two independent drain mechanisms** that interact unpredictably. `drainRemaining()` in `writeLoop` is redundant because `Close()` already drains.

**Fix**: Simplify. Remove `drainRemaining()` from `writeLoop`. When `ctx` is cancelled, `writeLoop` should simply return (the drain is handled by `Close()`). Or, even better: remove the drain from `Close()` and let `writeLoop` do all draining after `cancel()`. The key is **exactly one goroutine** should drain the channel on shutdown:

```go
func (v *Vault) writeLoop() {
    defer v.wg.Done()
    for {
        select {
        case op, ok := <-v.writeCh:
            if !ok {
                return
            }
            v.handleWrite(op)
        case <-v.ctx.Done():
            // Drain remaining, then return.
            for {
                select {
                case op, ok := <-v.writeCh:
                    if !ok { return }
                    v.handleWrite(op)
                default:
                    return
                }
            }
        }
    }
}
```

And in `Close()`, remove the drain loop entirely — just `close(v.writeCh)` then `v.wg.Wait()`:

```go
func (v *Vault) Close() error {
    v.closeMu.Lock()
    defer v.closeMu.Unlock()
    if v.closed { return nil }
    v.closed = true

    if v.cancel != nil {
        v.cancel()
    }
    close(v.writeCh)
    v.wg.Wait()

    v.logger.Info("vault: shutdown complete", "pii_values_logged", false)

    if v.db != nil {
        v.db.Close()
    }
    if v.crypto != nil {
        v.crypto.Close()
    }
    return nil
}
```

Or, if you want a drain-with-deadline in `Close()` (defense against stuck writes), add it *after* `wg.Wait()` confirms the write loop is done — but since the channel is already closed at that point, there's nothing to drain. The deadline approach in the current code (30s) is good but should be in `writeLoop`'s drain, not in `Close()`.

---

## Section 3: Design Flaws 🟡

### PR-101: TTL validation duplicated with silent fallback
- **File**: `cmd/agent/proxy.go`, lines 184–199; `internal/policy/config.go`, lines 183–217
- **Category**: Duplication / Silent error swallowing
- **Problem**: TTL validation lives in two places: `VaultConfig.Validate()` (authoritative, rejects invalid values at startup) and `parseConfigTTL()` (converts string to `time.Duration`, silently falls back to 168h for any failure). While config validation runs first, the silent fallback in `parseConfigTTL` could mask bugs if a future refactor changes the call order. Invalid TTL values should never reach `parseConfigTTL`, but if they do, the agent starts with no error and a wrong TTL. The defense-in-depth here is backwards — the fallback should be at the outermost layer, not hidden inside a helper.

**Fix**: `parseConfigTTL` should either return `(time.Duration, error)` or be removed entirely in favor of `time.ParseDuration` at the call site after validation. If TTL is empty at this point (shouldn't happen after validation), default to 168h with a WARNING log, not a silent substitution.

---

### PR-102: `isClosed()` acquires exclusive lock
- **File**: `internal/vault/vault.go`, line 494
- **Category**: Performance / Lock contention
- **Problem**: `isClosed()` is called from `Persist()` and `UpdateMeta()` — every single write hits this check. It acquires a full `Lock()` to read a boolean. Since it only reads `v.closed`, it should use `RLock()`. This is on the critical path for proxy performance (AC-6 requires <1ms latency impact).

**Fix**:
```go
func (v *Vault) isClosed() bool {
    v.closeMu.RLock()
    defer v.closeMu.RUnlock()
    return v.closed
}
```

Note: `Close()` sets `v.closed = true` under `Lock()`, so the read-side must use at least `RLock()` for happens-before ordering. Currently `Lock()` works but is unnecessarily exclusive.

---

### PR-103: `vault.Run()` accepts `ctx` but ignores it
- **File**: `internal/vault/vault.go`, lines 94–102
- **Category**: API contract violation
- **Problem**: The method signature suggests the caller controls the vault's goroutine lifecycle via context cancellation:
```go
func (v *Vault) Run(ctx context.Context) {
    v.ctx, v.cancel = context.WithCancel(ctx)
```
But `v.cancel` is only called from `Close()`. If the caller cancels the parent `ctx`, the vault's goroutines continue running because `WithCancel` creates a new child context whose cancel is the only one that matters. The caller's `ctx` is effectively dead code. This is misleading API design.

**Fix**: Either remove the `ctx` parameter (vault manages its own lifecycle) or propagate the parent context cancellation:
```go
func (v *Vault) Run(ctx context.Context) {
    v.ctx, v.cancel = context.WithCancel(ctx)
    // Now if parent ctx is cancelled, v.ctx.Done() fires.
}
```
Then `Close()` calls `v.cancel()` as a proactive shutdown, while parent context cancellation serves as a last-resort timeout.

---

### PR-104: Dead code and `var _ =` hacks in port conversion
- **File**: `internal/session/lookup_windows.go`, lines 199–204
- **Category**: Clean Code — dead code, masked linter warnings
- **Problem**: Three port-conversion attempts, two silenced with `_ =`:
```go
port := uint16(row.LocalPort>>16 | row.LocalPort&0xFFFF)
_ = port  // unused variable suppressed
port2 := uint16(row.LocalPort>>8 | row.LocalPort<<8)
_ = port2 // unused variable suppressed
// ...
actualPort := uint16(row.LocalPort)
```
This is debugging debris that should have been cleaned up before review. The `var _ =` pattern is explicitly called out in the Clean Code evaluation criteria as a red flag.

**Fix**: Remove all but the correct conversion (see PR-003 fix).

---

### PR-105: `resolvePathFromSID` receives SID, parses it, then ignores it
- **File**: `internal/session/lookup_windows.go`, lines 305–331
- **Category**: Dead code / incomplete implementation
- **Problem**: The function parses the SID string on line 308 (`sid, err := windows.StringToSid(sidStr)`) then immediately discards the result (`_ = sid`). The parsed SID is never used to look up the user's profile directory. The entire function is placeholder code labeled as such but shipped in a sprint delivery.

**Fix**: See PR-001 fix. Use the parsed SID to resolve the user's `LOCALAPPDATA` path via Windows API.

---

### PR-106: No validation that `Scope.Provider` is non-empty
- **File**: `internal/vault/vault.go`, lines 502–509
- **Category**: Defensive programming
- **Problem**: `conversationKey()` and `scopePrefix()` construct bbolt keys as `provider + "/" + uuid + "/" + token`. If `provider` is empty (e.g., if `WithProvider("")` is called), the key would be `/{uuid}/{token}`, potentially colliding with other conversations that also have empty providers. The bbolt prefix scan in `PurgeExpired()` uses `strings.HasPrefix` on these keys, so an empty provider would match scans intended for real providers.

**Fix**: Add a non-empty check in `conversationKey()` or validate in `Persist()`:
```go
func (v *Vault) Persist(scope Scope, token string, value []byte) error {
    if scope.Provider == "" {
        return fmt.Errorf("vault: provider must not be empty")
    }
    // ...
}
```
Same for `ConversationID`.

---

### PR-107: Missing `NoSync: false` in bbolt options (DD-2 compliance)
- **File**: `cmd/agent/proxy.go`, line 95; `internal/vault/vault_test.go`, line 38
- **Category**: Adherence to design decisions
- **Problem**: DD-2 explicitly states `NoSync: false`. While `false` is bbolt's default, the decision record calls for an explicit setting as documentation and future-proofing against bbolt version changes. The code uses:
```go
bolt.Open(vaultUser.DBPath, 0600, &bolt.Options{Timeout: 1 * time.Second})
```
without setting `NoSync`. This omission means a future version of bbolt that changes the default would silently affect data durability.

**Fix**:
```go
bolt.Open(vaultUser.DBPath, 0600, &bolt.Options{
    Timeout: 1 * time.Second,
    NoSync:  false, // Explicit per DD-2: fsync every commit
})
```

---

### PR-108: `NewConversationID()` is exported and tested but never called in production code
- **File**: `internal/vault/vault.go`, lines 512–526
- **Category**: Dead production code path
- **Problem**: The function is well-tested (T-813 verifies UUID v4 format) but no production code path calls it. The Tokenizer accepts a `ConversationID` via `WithConversationID()` but no code generates a UUID and passes it. In monitor mode, the Tokenizer is not created (the MonitorInterceptor only runs detection). In future enforce mode (QINDU-0009), the UUID must be generated when a new conversation scope is created.

This is not a bug for the current sprint (monitor mode doesn't write to vault), but it means the end-to-end vault write path is **untestable in integration** — the only way to exercise vault writes is via unit tests that directly call `Vault.Persist()`. The tokenizer→vault integration (DD-10, DD-11) is unit-tested via mock persister but never tested with a real vault.

**Fix**: Not blocking for this sprint, but flag for QINDU-0009. The conversation UUID generation must be wired into the interceptor or proxy when creating a Tokenizer scope.

---

### PR-109: `itoa` test helper reimplements `strconv.Itoa`
- **File**: `internal/vault/vault_test.go`, lines 169–179
- **Category**: Reinventing the wheel
- **Problem**: A hand-rolled integer-to-string function with a comment "avoid importing strconv for a test helper." The `strconv` package is already imported as a transitive dependency through `fmt`. Avoiding an import that costs nothing adds unnecessary code to maintain.

**Fix**: Delete `itoa` and use `strconv.Itoa`. The godoc for `strconv` says *"Package strconv implements conversions to and from string representations of basic data types."* — exactly what's needed. No performance concern in tests.

---

### PR-110: `MonitorInterceptor` never uses its `persister` field
- **File**: `internal/interceptor/monitor.go`, lines 41–48
- **Category**: Dead field / incomplete integration
- **Problem**: The `MonitorInterceptor` stores a `persister vault.TokenPersister` and it's properly injected from `proxy.go` → `selectInterceptor`. However, neither `InterceptRequest` nor `InterceptResponse` ever calls `m.persister.Persist()` or creates a Tokenizer. The persister is wired through but never consumed. This is by design (monitor mode only detects, doesn't tokenize), but it means the vault is a dead pipe in monitor mode — it's initialized and ready but receives zero writes.

This is not a bug for QINDU-0008 (the infrastructure is correctly built), but it means some acceptance criteria (AC-1, AC-6, AC-7) can only be verified in unit tests, not in end-to-end integration tests.

---

## Section 4: Excellence 🟢

### EX-1: `internal/crypto` — textbook Go crypto package
**Files**: `internal/crypto/crypto.go`, `crypto_unix.go`, `crypto_windows.go`

This package is exemplary. The AES-256-GCM implementation is pure stdlib, correctly handling nonce generation, key management, and memory zeroing. Specific highlights:

- **Nonce handling** (lines 83–87): Each `Encrypt()` call generates a fresh 12-byte nonce from `crypto/rand`. The nonce is prepended to ciphertext. This is the correct GCM pattern and prevents the critical nonce-reuse vulnerability called out in the risk assessment.
- **Key zeroing** (lines 218–222): `Close()` zeros the key bytes in memory before nil-ing the reference. Defense-in-depth against cold-boot attacks.
- **Permission enforcement** (`crypto_unix.go`, line 19): Rejects key files with permissions other than `0600`. The error message even tells the user how to fix it (`chmod 0600`).
- **Windows ACL** (`crypto_windows.go`, lines 41–75): Sets `owner+SYSTEM`-only ACL via `SetNamedSecurityInfo`. This is proper Windows security.
- **Test coverage**: 10,000 nonces verified unique (T-801), round-trip tests (T-802), tamper detection (T-802/T17), wrong-key rejection (DPO-R6), 100 unique keys generated (T-812).

The only minor quibble: `dirOf()` (line 172) uses a manual loop over path bytes that handles both `/` and `\` — this works but `filepath.Dir()` would be clearer and platform-correct. The manual loop correctly handles both separators but is slightly less idiomatic.

---

### EX-2: Tokenizer persister integration — clean optional subscriber pattern
**Files**: `internal/tokenize/tokenizer.go`, lines 105–113, 215–221

The `TokenPersister` integration into the Tokenizer is surgically minimal:
- Two lines in `assignTokens()` (lines 215–221): check `t.persister != nil`, construct scope, call `Persist()`, discard error.
- The existing memory store path is untouched.
- The option pattern (`WithPersister`) defaults to nil — all existing tests pass without modification (AC-9).
- The mock persister in tests correctly validates scope, token, and value propagation.

This is exactly how optional cross-cutting concerns should be injected: zero impact on the hot path when absent, clean separation when present. The comment on line 220 *"Persist is non-blocking (buffered channel send)"* is accurate and well-documented.

---

### EX-3: bbolt schema design — clean prefix scanning
**Files**: `internal/vault/vault.go`, lines 500–510

The bbolt key format `{provider}/{uuid}/{__meta__|token}` enables efficient prefix scans for TTL enforcement and conversation deletion without a secondary index. The `PurgeExpired()` implementation (lines 306–362) correctly:
1. Scans `__meta__` keys
2. Extracts the prefix (`provider/uuid/`)
3. Uses a sub-cursor to `Seek(prefix)` and delete all keys with that prefix

This is proper MVCC key design within bbolt's constraints. The use of `/` as a separator enables `strings.HasPrefix` filtering which is linear in key count but acceptable given that vaults are per-user and conversations are bounded.

---

### EX-4: Vault test suite — comprehensive and production-realistic
**Files**: `internal/vault/vault_test.go`

The test suite uses real bbolt databases and crypto service instances (no mocking of the storage layer). This is the right choice for a persistence component — mocking bbolt would hide schema errors. Highlights:
- `TestPersistAndRetrieve` (T-1): Writes through `Persist()`, reads raw bbolt value, verifies it's NOT plaintext, decrypts and verifies.
- `TestAsyncNonBlocking` (T-803): Sends 2000 concurrent writes, verifies <5s completion (non-blocking).
- `TestShutdownDrain` (T-808): Submits writes, calls `Close()`, verifies no hang.
- `TestConcurrentPersist` (T-814): 50 concurrent goroutines, `go test -race` target.
- `TestStartupSweep` (T-5): Pre-populates expired entries in bbolt, then creates vault, verifies sweep purges them.
- `TestCloseIdempotent`: Triple close, no panic.

The `setupTestVault` helper correctly manages the full lifecycle (key generation, bbolt open, vault creation, Run, cleanup). This is production-grade test infrastructure.

---

### EX-5: Config validation — secure by default
**Files**: `internal/policy/config.go`, lines 114–178

The `Validate()` method enforces multiple security invariants at startup:
- Loopback-only binding (lines 121–127): Rejects non-loopback IPs. Correctly handles both `127.0.0.1` and `::1`.
- Valid modes enum (lines 134–139): Rejects unknown modes.
- Vault TTL validation (lines 183–217): Rejects negative, sub-hour, non-integer-hour, and unparseable durations. The error messages are clear (`ttl must be at least 1h, got: "30m"`).

This validates AC-8: the agent refuses to start on invalid config. No lazy validation at request time.

---

## Section 5: Verdict

**VERDICT: FIX_AND_RESUBMIT** ❌

### Rationale

The `internal/crypto` and `internal/vault` packages are production-quality. The test suites are thorough. The integration between Tokenizer and TokenPersister is clean. The async write pattern is correctly implemented.

However, the `internal/session` package — specifically the Windows service-mode path — has **three critical, blocking bugs** that prevent the key acceptance criteria from being met:

1. **PR-001**: SID→path resolution is placeholder code that produces garbage paths. The vault will never initialize correctly in Windows service mode. This blocks AC-4 (per-user isolation) and AC-5 (SID lookup fail → deny).

2. **PR-002**: The global LRU cache has zero synchronization. Concurrent connections produce data races. This violates AC-15 and will cause `go test -race` to fail on Windows.

3. **PR-003**: The port byte-order in TCP table lookup is inverted, guaranteeing the PID lookup never matches. This blocks the entire SID resolution chain.

Additionally, the vault shutdown drain pattern (PR-004) is architecturally fragile and should be simplified before merging.

The five excellence points (EX-1 through EX-5) demonstrate that the core vault infrastructure is solid. The fixes required are surgical — they affect only `internal/session/lookup_windows.go` and the vault `Close()` method. The estimated fix effort is 2–4 hours for an experienced Go developer.

### Required fixes before resubmission

| ID | What | Where |
|----|------|-------|
| PR-001 | Implement real SID→profile path resolution | `lookup_windows.go:306-331` |
| PR-002 | Add `sync.RWMutex` to `pidSIDCache` | `lookup_windows.go:26-30` |
| PR-003 | Fix port byte-order conversion | `lookup_windows.go:199-211` |
| PR-004 | Simplify vault shutdown drain (single consumer) | `vault.go:168-186, 428-491` |

### Recommended before CISO/DPO gates

| ID | What | Where |
|----|------|-------|
| PR-006 | Use `RLock()` in `isClosed()` | `vault.go:494` |
| PR-101 | Remove silent fallback in `parseConfigTTL` | `proxy.go:184-199` |
| PR-104 | Remove dead code / `_ =` hacks in port conversion | `lookup_windows.go:199-204` |
| PR-107 | Add explicit `NoSync: false` to bbolt options | `proxy.go:95` |

### Observation for QINDU-0009

The `NewConversationID()` function and `WithConversationID()` option are correctly implemented but un-wired. The enforce-mode interceptor (QINDU-0009) must call `vault.NewConversationID()` when creating a Tokenizer scope and pass both `provider` and `convID` via the options. The current MonitorInterceptor's `persister` field is a dead pipe — ensure it's activated in enforce mode. Flag this as a QINDU-0009 dependency.

---

**Reviewer signature**: qindu-peer-reviewer  
**Verdict**: FIX_AND_RESUBMIT  
**Next gate**: After fixes → re-invoke blank-slate peer review
