# Peer Review — QINDU-0008: Vault local chiffré

**Reviewer**: qindu-peer-reviewer (blank-slate — fourth session)
**Date**: 2026-07-04
**Scope**: All `.go` files in `internal/crypto/`, `internal/vault/`, `internal/session/`, `internal/tokenize/`, `internal/policy/`, `internal/proxy/`, `internal/interceptor/`, `cmd/agent/`
**Standards Applied**: Clean Code (Martin), Pragmatic Programmer (Hunt/Thomas), SOLID (Uncle Bob), Go Proverbs (Pike), Effective Go, DDD (Evans), Code Complete (McConnell)

---

## Scorecard

| Framework | Grade | Justification |
|-----------|-------|---------------|
| **Clean Code** | B | Good naming, small functions, DRY. Redundant `TokenPersister` field in Proxy struct (unused in current mode). `piiType` extraction discards validity boolean — silent metadata skip. |
| **Pragmatic Programmer** | B− | Strong orthogonality (crypto ⊥ vault ⊥ session). Reversibility: vault is optional, graceful degradation to memory-only. Design-by-contract weakened: `TokenPersister.Persist()` is void (fire-and-forget) — no contract enforcement on errors. |
| **SOLID** | B+ | SRP: well-separated packages (vault, crypto, session, tokenize). ISP: `TokenPersister` interface is lean (2 methods). OCP: `Option` pattern for tokenizer extensibility. DIP: Proxy depends on `TokenPersister` interface, not concrete Vault. Violation: `persister` stored in Proxy but never wired to `MonitorInterceptor` — dead storage in current mode. |
| **Go Proverbs** | B | Errors are handled, never panic. "Don't communicate by sharing memory" — channels used for async writes. "Small interfaces" — `TokenPersister` has 2 methods. Minor: `_ =` discarded on `extractPIIType` — the boolean has meaning (token validity). |
| **Effective Go** | A− | `gofmt`-compliant (verified). Idiomatic naming (`New`, `Close`, `Option`). Consistent `%w` error wrapping. `defer` properly used. No `init()` abuse. |
| **DDD** | B | Bounded contexts aligned with packages. Ubiquitous language: `TokenPersister`, `Scope`, `ConversationID`. Value object: `Scope` is immutable. Entity: `Metadata` is mutable via write path. Issue: `Metadata.Status` enum only has `StatusActive` — expired/purged physically deleted, making the status field a lie for UI consumers unaware of this convention. |
| **Code Complete** | B− | Defensive programming: provider validation in `enqueue`, entity validation in `validateEntities`. CAP violation: `globalCache` in `session` package — global mutable state (mitigated by sync.Mutex, bounded size). TOCTOU race in vault shutdown — `closeMu` released before channel send (acknowledged in comments, but still a defensive gap). |

---

## Critical Findings 🔴

### PR-001: DD-7 Violation — `internal/crypto` uses platform-specific build tags

- **File**: `internal/crypto/crypto_unix.go:1`, `internal/crypto/crypto_windows.go:1`
- **Severity**: HIGH
- **Problem**: Story DD-7 states:

  > *"A single package with no build tags. One implementation, all platforms."*

  The implementation has three files:
  - `crypto.go` — core encrypt/decrypt (no build tags)
  - `crypto_unix.go` (`//go:build !windows`) — validates 0600 permissions
  - `crypto_windows.go` (`//go:build windows`) — ACL manipulation via `advapi32.dll`, `syscall.NewLazyDLL`, unsafe pointer arithmetic

  This directly contradicts DD-7 and drags in `golang.org/x/sys/windows` as a new direct dependency. The Windows ACL code (190 lines of unsafe syscall manipulation in `crypto_windows.go`) was explicitly excluded from scope by DD-7 and DD-9.

- **Fix**: Three options, in order of preference:
  1. **Move ACL logic out of `internal/crypto`**: Create `internal/crypto/acl_unix.go` and `internal/crypto/acl_windows.go` (or `internal/securefile/`). The `crypto.go` stays pure, tag-free, as DD-7 demands. The ACL hook becomes a separate concern.
  2. **Remove Windows ACL entirely**: DD-7 and DD-9 chose file-based key + chmod 0600 as sufficient for all platforms. If Windows needs additional ACL hardening, that's a separate story (QINDU-00XX).
  3. **Amend the story**: If the design decision is overturned, update DD-7 to reflect the new reality. But this violates the existing ADR anchor.

  Also: remove the unused `procInitAcl` and `procAddAccessAllowedAce` global vars from `crypto_windows.go` — they're defined (lines 14–16) but `setKeyFileACL` uses `x/sys/windows` API instead.

- **AC Impact**: AC-10 (cross-platform compatibility) — the encrypt/decrypt core does work cross-platform, but the package as a whole is no longer a "single implementation."

### PR-002: `golang.org/x/sys` leaked as direct dependency

- **File**: `go.mod:7`
- **Severity**: HIGH
- **Problem**: DD-2 predicted 2 direct deps: `go.etcd.io/bbolt` + `golang.org/x/sync`. Actual `go.mod` has:
  ```
  require (
      go.etcd.io/bbolt v1.5.0
      golang.org/x/sys v0.46.0      ← UNEXPECTED
      gopkg.in/yaml.v3 v3.0.1
  )
  ```
  `golang.org/x/sync` is only an *indirect* dependency (from bbolt), present in `go.sum`. AC-14 says "No new indirect dependencies beyond golang.org/x/sync" — that passes. But the *direct* `x/sys` dep was never in the plan and exists solely because of the Windows ACL code from PR-001.

- **Fix**: If PR-001 is resolved by removing or relocating the Windows ACL code, `golang.org/x/sys` drops out of `go.mod` on non-Windows platforms. Run `go mod tidy` after the fix.

### PR-003: TOCTOU data loss window in vault `Close()`

- **File**: `internal/vault/writer.go:164-182` (`enqueue`), `internal/vault/vault.go:140-176` (`Close`)
- **Severity**: HIGH
- **Problem**: The `enqueue()` method (central entry point for all writes) has a TOCTOU race with `Close()`:

  ```
  // enqueue() — thread A
  v.closeMu.Lock()
  if v.closed { return false }    // closed==false, proceed
  ch := v.writeCh                 // grab channel ref
  v.closeMu.Unlock()
  select { case ch <- op: ... }   // ← RACE WINDOW: writeLoop may have already exited
  ```

  Sequence:
  1. `Close()` sets `closed=true`, calls `v.cancel()`
  2. `writeLoop` sees `ctx.Done()`, drains remaining, returns (`wg.Done()`)
  3. `wg.Wait()` returns
  4. `db.Close()` — bbolt closed
  5. Thread A sends to channel → message sits in buffer forever → lost

  The code acknowledges this (comment on line 137: *"Closing it here would race with Persist() goroutines"*) and chooses to never close the channel. While the server-then-vault shutdown ordering (proxy.go lines 88-101) mitigates the race in practice (no new requests after server shutdown), the design is fragile. A future refactor that reorders shutdown or adds a health-check endpoint calling `Persist()` during drain would silently lose data.

- **Fix**: Consider a `sync.WaitGroup` or an atomic count tracking in-flight `enqueue()` calls. `Close()` would wait for in-flight senders before closing bbolt. Alternatively, a `closed` channel (closed once, `select` on both `ch` and `closed` in `enqueue`) would eliminate the race entirely.

- **AC Impact**: AC-7 (shutdown drain) — under current shutdown ordering, drain works correctly. The TOCTOU is a latent fragility, not an active bug.

### PR-004: Unused `TokenPersister` in Proxy for monitor mode

- **File**: `internal/proxy/proxy.go:35,69`
- **Severity**: MEDIUM
- **Problem**: The `Proxy` struct stores a `persister vault.TokenPersister` field and exposes it via `Persister()` method. But in **monitor mode** (the only active mode), the `MonitorInterceptor` does not accept a persister — it only detects/logs PII. The persister is never wired to any tokenizer. It's dead storage in the current code path.

  The only consumer would be the `enforce` interceptor (QINDU-0009, out of scope), which would use the persister for tokenization. This is forward-looking code that violates YAGNI.

- **Fix**: Two clean options:
  1. Move `persister` field into the future enforce interceptor (created in QINDU-0009). Remove it from Proxy.
  2. Keep it but add a clear comment: `// persister is reserved for enforce mode (QINDU-0009). Nil in current monitor-mode path.`
  Option 1 is cleaner.

- **AC Impact**: None in current scope, but adds maintenance burden and confusion about data flow.

---

## Design Flaws 🟡

### PR-101: Global mutable state — `globalCache`

- **Category**: Encapsulation / Global State
- **File**: `internal/session/lookup_windows.go:105`
- **Problem**: `var globalCache = newPIDLocalAppDataCache(lruMaxSize)` is a package-level mutable variable. Violates Code Complete's "no global mutable state" principle. While the cache is bounded (LRU, max 10,000 entries) and mutex-protected, it makes unit testing harder — tests can't inject a mock cache, and concurrent tests share state.
- **Fix**: Add a `WithCache(cache *pidLocalAppDataCache)` option to `resolvePathFromPID` or make `LookupVaultPathForPort` accept a cache parameter. Default to the global if nil. This enables test isolation.

### PR-102: `piiType` extraction silently discards validity

- **Category**: Defensive Programming / Error Handling
- **File**: `internal/vault/writer.go:199`
- **Problem**: `piiType, _ := extractPIIType(token)` discards the boolean. If a malformed token slips through (e.g., from a future caller of the vault API), `piiType` is empty string. In `handleWrite` (writer.go:65), `!op.meta && op.piiType != ""` silently skips metadata updates for that token. The token is still encrypted and stored in bbolt, but the conversation's `pii_count` and `pii_types` become inaccurate — a silent data inconsistency.
- **Fix**: If `extractPIIType` returns `false`, log a WARNING (PII-free: log only the token length, not its content) and still attempt metadata (the type just won't be recorded). Or reject the write entirely — the vault contract is `<<TYPE_N>>` tokens.

### PR-103: `Metadata.Status` field — dead enum with forward-compat lie

- **Category**: Schema / DDD
- **File**: `internal/vault/meta.go:8-12,33`
- **Problem**: The `Status` type has only one constant: `StatusActive = "active"`. `StatusExpired` and `StatusPurged` were removed (PR-109) because the vault physically deletes expired entries. But the `Metadata` struct still has `Status Status \`json:"status"\``, which always serializes as `"active"`. A future UI consumer that reads the JSON and checks `status == "expired"` will never find any — a silent schema contract violation.
- **Fix**: Either remove the `Status` field entirely (if it's never used) or restore `StatusExpired`/`StatusPurged` and add a comment documenting the convention: *"These statuses are set at deletion time only when explicitly requested; by default, expired/purged entries are physically removed."*

### PR-104: `initVault` uses `context.Background()` — un-cancellable root context

- **Category**: Context Management
- **File**: `cmd/agent/proxy.go:189`
- **Problem**: `vaultInst.Run(context.Background())` passes a background context that can never be externally cancelled. `Run()` calls `context.WithCancel(ctx)` internally, storing the cancel function in `v.cancel`. This works — `Close()` calls `v.cancel()`. But the `context.Background()` is misleading: it suggests "this runs forever" when in fact the lifetime is tied to the process. A reader expects a derived context from a shutdown signal.
- **Fix**: Accept a `context.Context` in `initVault` or derive from `signal.NotifyContext`. For now, add a comment: `// Background: actual cancellation via vault.Close() → v.cancel()`. Not blocking.

### PR-105: `TestRestartRoundTrip` — double cancellation

- **Category**: Test Hygiene
- **File**: `internal/vault/vault_test.go:680`
- **Problem**: `vault1.Close()` (line 679) internally cancels context and drains. Then `cancel1()` (line 680) is called — a no-op since the context is already cancelled and the goroutine has exited. This litters the test with dead code and confuses readers about ownership.
- **Fix**: Remove `cancel1()` call. `Close()` owns cancellation. If you want to keep it for documentation, wrap in a comment.

### PR-106: `crypto.Service.Encrypt` — nonce allocated twice

- **Category**: Performance / Allocations
- **File**: `internal/crypto/crypto.go:84,92`
- **Problem**: 
  ```go
  nonce := make([]byte, nonceSize)      // allocation 1
  rand.Read(nonce)
  ciphertext := s.aesGCM.Seal(nonce, nonce, plaintext, nil) // uses nonce as dst
  ```
  The `nonce` slice is allocated separately. `Seal` could allocate its output with `nonce` as prefix. This is standard GCM usage and not a bug, but on a hot path (every vault write) the double allocation is avoidable. Minor — the GCM implementation already handles this efficiently.

### PR-107: `lookupPIDFromPort` — no UDP fallback

- **Category**: Completeness
- **File**: `internal/session/lookup_windows.go:136-189`
- **Problem**: DD-13 specifies *"GetExtendedTcpTable (or GetExtendedUdpTable)"* for SID lookup. Only TCP is implemented (`GetExtendedTcpTable`). If a browser uses UDP for proxy traffic (unlikely for HTTP CONNECT, but possible for QUIC/HTTP3), the lookup fails. The fix is out of scope for this sprint but the function name and interface should reflect TCP-only for clarity.
- **Fix**: Rename to `lookupPIDFromTCPPort` or add a comment documenting the TCP-only limitation. Add a TODO referencing QUIC/HTTP3 support.

### PR-108: `MonitorInterceptor.InterceptResponse` — Content-Length can be -1

- **Category**: Edge Case
- **File**: `internal/interceptor/monitor.go:244`
- **Problem**: `resp.ContentLength > int64(m.maxInputLen)` — when `ContentLength` is -1 (unknown, e.g., chunked transfer encoding), this comparison becomes `-1 > 1048576` which is `false`. So the body is read anyway. This is correct behavior (we want to scan unknown-size bodies), but the `Warn` log on line 245 misleadingly reports a `content_length: -1` only when the body ACTUALLY exceeds maxInputLen after reading (line 264). The pre-check on line 244 silently passes through. No bug, but the log output on line 251 reports `content_length: -1` which is misleading to operators.
- **Fix**: On line 244, skip the pre-check when `ContentLength < 0`. Let the full read handle it. Or include a `content_length_known: false` field in the oversize log on line 265.

---

## Excellence 🟢

### E-001: `pii_values_logged: false` discipline
Every log call across all packages consistently includes `"pii_values_logged", false`. This is ADR-008 compliance at every level — not a single log statement misses it. The discipline is remarkable given the code spans 9 packages.

### E-002: `zeroBytes` key clearing
`crypto.go:209-212` — the `Close()` method zeroes the AES key in memory via `zeroBytes` before nil-ing the reference. Combined with `s.aesGCM = nil`, this is defense-in-depth against cold-boot and memory-scraping attacks. On a Go runtime where the GC may keep key bytes alive in freed memory, `zeroBytes` is the right call.

### E-003: Centralized `enqueue` write path
`writer.go:154-182` — the `enqueue()` method is the single entry point for ALL writes (`Persist` and `UpdateMeta` both route through it). Provider validation (slash rejection) and closed-check are centralized. Previous review cycles had duplicated logic in `Persist()` and `UpdateMeta()` separately — this is a textbook refactoring win.

### E-004: `drainRemaining` with bounded default
`writer.go:127-145` — the drain loop uses a non-blocking `select` with `default` to detect emptiness. This avoids the common anti-pattern of trying to `close()` a channel and racing with senders. Combined with the `for { select { case <-ch: drain; default: return } }` pattern, this is clean and well-commented.

### E-005: Comprehensive test coverage
`vault_test.go` (907 lines), `tokenizer_test.go` (1222 lines), `crypto_test.go` (340 lines) — every AC is tested, including:
- `TestRestartRoundTrip` — end-to-end session restart (AC-1)
- `TestStartupSweep` — pre-seeded expired entries purged at init (AC-3)
- `TestShutdownDrain` — verifies committed writes after Close (AC-7)
- `TestConcurrentPersist` — race-detector passing (AC-15)
- `TestProviderRejectsSlash` — input validation (AC-12)

All 12 test packages pass with `-race -count=1`.

### E-006: `NewConversationID` RFC 9562 UUID v4
`vault/keys.go:38-49` — proper crypto/rand-based UUID generation with correct version (4) and variant (10xx) bits. The `TestNewConversationID_UUIDv4Format` test validates 1000 UUIDs for uniqueness, format, version nibble, and variant — exemplary.

### E-007: Startup sweep timeout
`vault.go:90` — the 30-second `context.WithTimeout` bounding the startup sweep prevents a large/corrupted database from blocking agent initialization indefinitely. This is the kind of defensive detail that separates production code from prototype code.

---

## Verdict

### **FIX_AND_RESUBMIT**

The vault core (encryption, async writes, TTL enforcement, shutdown drain) is solid and well-tested. But two architectural issues must be resolved before CISO/DPO gates:

1. **PR-001 (DD-7 violation)** — `internal/crypto` must not have platform-specific build tags. The ACL logic belongs in its own package or must be removed. This is a story-level design decision that cannot be waived at review time.

2. **PR-002 (dependency leak)** — `golang.org/x/sys` as a new direct dependency was never in the plan. Resolved automatically when PR-001 is fixed.

PR-003 (TOCTOU race) is a design flaw but not a showstopper under current shutdown ordering. PR-004 (dead persister field) is forward-looking code that should be deferred to QINDU-0009.

**After fix**: re-invoke the peer reviewer (blank-slate). No other changes needed for the vault to be production-ready.
