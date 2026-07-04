# Peer Review — QINDU-0008: Vault local chiffré

**Reviewer**: `qindu-peer-reviewer` (fresh session, blank-slate)  
**Date**: 2026-07-04  
**Scope**: `internal/crypto`, `internal/vault`, `internal/session`, `internal/tokenize` (persister integration), `cmd/agent/proxy.go` (vault init/shutdown), `internal/policy/config.go` (TTL validation), `configs/default.yaml`  
**Pre-verified**: `go build ./...` ✅ | `GOOS=windows go build ./internal/session` ✅ | `go vet ./...` ✅ (zero warnings) | `go test -race -count=1 ./...` ✅ (12 pkgs, zero failures, zero races) | `go fmt ./... && git diff --exit-code` ✅

---

## Scorecard

| Framework | Grade | Justification |
|-----------|-------|---------------|
| **Clean Code** (Martin) | 4/5 | Meaningful names, small functions (<40 lines mostly), zero dead code, DRY respected. One concern: `tokenRegex`/`allEntityTypes`/`knownEntityTypes` initialization in `tokenizer.go` relies on Go compiler dependency analysis — declaration order (lines 31, 36, 42) is misleading to a human reader. |
| **Pragmatic Programmer** (Hunt/Thomas) | 4/5 | Strong orthogonality between `crypto`↔`vault`↔`session`. Vault is reversible (nil = memory-only). `WithCache` option uses standard Go functional-options pattern — excellent testability without production leaks. Minor: `initVault` returns `TokenPersister` but caller discards it — unused return value signals incomplete wiring. |
| **SOLID** (Uncle Bob) | 4/5 | SRP: crypto/vault/session/tokenize each have one reason to change. OCP: `TokenPersister` interface is closed for modification, open for extension. ISP: 2-method interfaces (`TokenPersister`, `Interceptor`) — textbook. DIP violation: `internal/tokenize` imports `internal/vault` (for `vault.TokenPersister` and `vault.Scope`). The consumer depends on the implementation package, not the other way around. Mitigated because DD-1 explicitly places the interface in the vault package. |
| **Go Proverbs** (Pike) | 5/5 | Errors always wrapped with `%w`. Channels used for async communication (no shared-memory backpressure). Small interfaces (2 methods). Errors are handled, not just checked — full channel drops are logged, not swallowed. |
| **Effective Go** (Go team) | 5/5 | Idiomatic camelCase, no GetX. Consistent `%w` error wrapping. Build tags (`//go:build windows`, `//go:build !windows`) correct and minimal. No `init()` abuse — only package-level `var` initializers. `defer` used correctly (no defer-in-loop issues). `gofmt` clean. |
| **DDD** (Evans) | 4/5 | Bounded contexts mapped cleanly to packages (`crypto`, `vault`, `session`, `tokenize`, `policy`). Ubiquitous language: "persister", "scope", "conversation", "metadata" — consistent across codebase and story. `Vault` is an aggregate root; `Metadata` is a value object. Minor: `TokenPersister` interface location in `vault` package leaks the domain boundary. |
| **Code Complete** (McConnell) | 4/5 | Strong defensive programming: entity bounds validation, provider-slash rejection, key-file permission checks, UUID format checks, content-length pre-checks before buffering. No magic numbers — `nonceSize=12`, `KeySize=32`, `asyncChannelBuffer=1024`, `lruMaxSize=10000`, `cacheTTL=60s` all named. `gc.evictOldest()` is O(n) on 10K entries — acceptable but not ideal. No global mutable state beyond the explicitly mutex-guarded `globalCache`. |

**Composite**: **4.3/5** — Well-crafted, production-ready code with minor architectural notes.

---

## Critical Findings 🔴

**NONE**. After thorough analysis of all 24 source files, no blocking bugs, data races, security holes, or acceptance-criteria violations were found. The code is sound across all 7 design frameworks.

*However*, I cannot award a "clean" critical section without noting the following observation, which is not a bug but a **linter-level concern**:

---

## Design Flaws 🟡

### PR-100 — `tokenRegex` / `allEntityTypes` declaration order is misleading
- **Category**: Readability / Maintenance trap
- **File**: `internal/tokenize/tokenizer.go`, lines 31–42

The package-level variables are declared in this order:
```go
var tokenRegex = buildTokenPattern()         // line 31 — calls buildTokenPattern() which reads allEntityTypes
var allEntityTypes = []pii.EntityType{...}   // line 36
var knownEntityTypes = func() map[...]bool{...}() // line 42
```

`buildTokenPattern()` references `allEntityTypes`, which is declared **5 lines later**. This works correctly because the Go compiler performs dependency analysis — it detects that `tokenRegex` transitively depends on `allEntityTypes` and initializes `allEntityTypes` first. However, this is invisible to human readers and fragile: a future developer reordering lines or extracting `buildTokenPattern` into a separate file could break the dependency chain and produce an empty regex (`<<()_(\\d+)>>`), silently breaking all token rehydration.

**Fix**: Move `allEntityTypes` above `tokenRegex`:
```go
var allEntityTypes = []pii.EntityType{...}   // must be declared before tokenRegex
var tokenRegex = buildTokenPattern()
var knownEntityTypes = func() map[...]bool{...}()
```
Or better: make the dependency explicit by passing `allEntityTypes` as a parameter to `buildTokenPattern()` so the dependency is visible in the call site.

---

### PR-101 — `TokenPersister` interface lives in the wrong package (DIP violation)
- **Category**: Coupling / SOLID
- **File**: `internal/vault/persister.go`, lines 17–28

`TokenPersister` and `Scope` are defined in `internal/vault`, but consumed by `internal/tokenize`. The Dependency Inversion Principle says interfaces should be defined by the consumer, not the implementer. Currently `internal/tokenize` imports `internal/vault` solely for these two types. If a future persistence backend (e.g., SQLite, in-memory test) wanted to implement `TokenPersister`, it would also need to import `internal/vault`.

**Mitigation**: DD-1 in the story explicitly places the interface in the vault package. This is an accepted design decision for the sprint. The interface has only 2 methods and is unlikely to change frequently.

**Recommendation**: In QINDU-0009, consider extracting `TokenPersister` and `Scope` into `internal/tokenize` (the consumer) and having `vault` import `tokenize`. This inverts the dependency and allows future backends to implement the interface without importing bbolt/vault.

---

### PR-102 — `initVault` returns an unused `TokenPersister` value
- **Category**: API design / Dead return
- **File**: `cmd/agent/proxy.go`, lines 70, 112, 203

```go
// line 70: caller discards TokenPersister
vaultInst, _ := initVault(cfg, logger)

// line 112: function returns TokenPersister
func initVault(...) (*vault.Vault, vault.TokenPersister) {
    ...
    return vaultInst, vaultInst  // line 203
}
```

The second return value is always `vaultInst` itself (the vault implements `TokenPersister`). The caller discards it. This is correct for the current sprint (enforce mode / tokenizer wiring is QINDU-0009), but the dual-return signature signals an intention that is not yet fulfilled. A developer reading the call site might assume the persister IS being wired somewhere.

**Fix**: For this sprint, either:
1. Add a comment on line 70: `// TokenPersister will be wired in QINDU-0009 (enforce mode)`
2. Or drop the second return value until it's actually used, changing the signature to `func initVault(...) *vault.Vault` and returning `return vaultInst` on success or `nil` on failure.

---

### PR-103 — `evictOldest()` is O(n) on a 10K-entry map
- **Category**: Performance / Algorithm choice
- **File**: `internal/session/lookup_windows.go`, lines 88–102

```go
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
```

On every eviction (cache full at 10,000 entries), this scans all 10,000 entries to find the oldest. In the worst case (steady-state with 10K+ connections), this is ~10K map iterations every time a new PID needs caching. For a SID lookup that happens once per connection (not per request), this is unlikely to be a performance bottleneck, but it's a known anti-pattern.

**No fix required for V1** — but if the cache hit rate drops or the connection rate exceeds 1000/s, consider a proper LRU (container/list + map) or a simple ring-buffer eviction.

---

### PR-104 — `Close()` mutates shared state after `wg.Wait()` — benign but worth noting
- **Category**: Concurrency / Code clarity
- **File**: `internal/vault/vault.go`, lines 143–185

After both `wg.Wait()` and `wgInFlight.Wait()` return, the code calls `drainRemaining()` which reads from `v.writeCh`. At this point, no goroutine is writing to the channel (all in-flight tracked by `wgInFlight` have completed, and `closed==true` blocks new callers). The channel read is guaranteed non-blocking. This is correct, but the logic spans 40 lines of mutex, WaitGroup, and channel operations — a state machine diagram in the comment would help future maintainers.

**Recommendation**: Add an ASCII state diagram as a comment block above `Close()` showing the 6-step sequence and which primitives gate each step.

---

### PR-105 — `io/fs` import exists only for test-only helper function
- **Category**: Production code hygiene
- **File**: `internal/crypto/crypto.go`, line 19 (import) and lines 223–229 (function)

```go
func checkFileMode(path string, expected fs.FileMode) (bool, error) {
```

This unexported function is used only in `crypto_test.go`. While Go allows same-package test access to unexported functions, the `"io/fs"` import is dead weight in production builds (Go's compiler elides unused package-level imports, but `fs.FileMode` is referenced in the function signature, so the import is retained).

**No fix required** — the function is 7 lines, the import is minimal, and the test benefits from direct access. This is standard Go testing practice.

---

### PR-106 — `vault.Close()` zeros `v.crypto` key but does not zero the key-file on disk
- **Category**: Defense-in-depth / Data at rest
- **File**: `internal/vault/vault.go`, line 182

```go
if v.crypto != nil {
    v.crypto.Close()  // zeros in-memory key
    v.crypto = nil
}
```

The AES key is zeroed in memory (defense-in-depth), but the `vault.key` file on disk is NOT shredded or overwritten. This is by design — the key file must persist for subsequent sessions (AC-1 requires cross-session retrieval). However, when a user invokes a DPO "right to erasure" (PurgeAll), the key file remains. An attacker with disk access could decrypt old bbolt snapshots if they have the key file.

**Mitigation**: The vault.key file has `0600` permissions and resides in a per-user directory protected by OS ACLs. For V1, this is acceptable. For a future sprint, consider a "key rotation + secure delete" operation for data subject erasure requests.

---

## Excellence 🟢

### EX-1: `internal/crypto/crypto.go` — Textbook AES-GCM implementation
Every detail is correct:
- Fresh random nonce per `Encrypt()` call via `crypto/rand` (line 87) — no nonce reuse risk
- Nonce prepended to ciphertext (line 94): `Seal(nonce, nonce, plaintext, nil)` — elegant single-allocation trick
- `Decrypt()` bounds-checks ciphertext length before slicing (line 102) — no panic on truncated input
- Key zeroed on `Close()` (line 120) — defense-in-depth
- `writeKeyFile()` calls `f.Sync()` + `f.Chmod(0600)` (lines 183–189) — durable + permission-hardened
- Platform-aware permission validation (line 210: Windows skips Unix 0600 check) — pragmatic
- Cross-platform by construction: no CGO, no build tags, no DPAPI dependency

This file alone would pass a cryptographer's review.

---

### EX-2: `internal/vault/vault.go` — Robust TOCTOU-free shutdown sequence
The `Close()` method (lines 143–185) implements a 7-step graceful shutdown that handles a genuinely hard concurrency problem:

1. **Set `closed` flag under mutex** — blocks new `Persist()` callers
2. **Cancel context** — signals `writeLoop` and `sweeperLoop` to exit
3. **`wg.Wait()`** — waits for goroutines to finish draining + exit
4. **`wgInFlight.Wait()`** — waits for in-flight enqueue senders that passed the closed check BEFORE step 1 completed
5. **Second `drainRemaining()`** — drains messages deposited by step-4 senders AFTER `writeLoop` exited
6. **Close bbolt** — safe because all writers have stopped
7. **Close crypto** — zeroes key last

The intentionally-never-closed channel (line 137 comment) is the correct solution to the TOCTOU race between `enqueue` checking `closed` and `writeLoop` receiving. Closing the channel would cause panics in in-flight senders. This is expert-level Go concurrency design.

---

### EX-3: `internal/vault/purge.go` — Context-respecting batch operations
`PurgeExpired()` (lines 67–142) respects `ctx.Done()` at three checkpoints:
- Before the bbolt transaction (line 73)
- Between cursor iterations during the metadata scan (lines 90–94)
- Before each deletion pass (lines 122–127)

This is critical for the `startupSweepTimeout` (30s bounded in `New()`). Without this, a corrupted or massive database could block agent startup indefinitely. The 30s timeout via `context.WithTimeout` at line 91 of `vault.go` + the periodic `ctx.Done()` checks in the cursor loop implement a clean cooperative cancellation pattern.

---

### EX-4: `internal/vault/writer.go` — Atomic metadata upsert in transaction
The `handleWrite()` method (lines 34–76) performs both the token write AND the metadata upsert within a single `v.db.Update()` transaction (line 54). This guarantees:
- The `__meta__.pii_count` is always consistent with the number of token entries (AC-13)
- If the token write succeeds but the metadata write fails, the entire transaction rolls back — no partial state
- The `extractPIIType()` call is outside the lock (line 208) — keeps the critical section bounded

---

### EX-5: `internal/session/lookup_windows.go` — Clean unsafe/syscall encapsulation
The Windows SID lookup code is unavoidable gymnastics with `unsafe.Pointer`, raw syscall tables, and manual buffer parsing. Despite this, the code is:
- Well-commented at every unsafe operation (e.g., line 228: "LocalPort is in network byte order")
- Returns descriptive errors at every failure point (lines 192, 209, 234, etc.)
- Caches results with TTL-aware eviction (line 64: `time.Since(e.ts) > cacheTTL`)
- Has a proper `LookupOption` pattern for test cache injection (lines 108–123)
- Falls back TCP → UDP per DD-13

This is a rare example of Windows syscall code that is both correct and readable.

---

### EX-6: `internal/policy/config.go` — TTL validation whitelist with defense-in-depth
`ParseTTL()` (lines 191–239) implements four layers of validation:
1. Empty → defaults to 168h
2. `"0"` → infinite (accepted)
3. Whitelist switch on `"24h"`, `"168h"`, `"720h"` — any other value rejected with clear error
4. After `time.ParseDuration()`: negative check, sub-hour check, whole-hour check

Layers 4 are redundant given the whitelist, but the code comments explicitly note they are defense-in-depth. This is exactly the kind of paranoia expected in security-critical configuration parsing.

---

## Acceptance Criteria Verification

| AC | Status | Evidence |
|----|--------|----------|
| AC-1 (persist + retrieve) | ✅ | `TestPersistAndRetrieve`, `TestRestartRoundTrip` — cross-session round-trip verified |
| AC-2 (encryption at rest) | ✅ | `TestPersistAndRetrieve` line 111: raw bbolt value ≠ plaintext. Key file 0600 verified in `TestKeyFileCreatedWith0600` |
| AC-3 (TTL enforcement) | ✅ | `TestTTLExpiry`, `TestStartupSweep`, `TestGetConversationAutoPurgeExpired` — all three enforcement layers tested |
| AC-4 (per-user isolation) | ✅ | `internal/session/lookup_windows.go` resolves per-user vault paths via SID → `SHGetKnownFolderPath` |
| AC-5 (SID fail → deny) | ✅ | `resolvePathFromPID` returns error on any failure; no fallback to machine-level path |
| AC-6 (async non-blocking) | ✅ | `TestAsyncNonBlocking` sends 2000 writes with non-blocking channel, completes <5s |
| AC-7 (shutdown drain) | ✅ | `TestShutdownDrain` — 50 writes, all committed before close returns |
| AC-8 (config validation) | ✅ | `ParseTTL` whitelist + negative/sub-hour/whole-hour checks. Invalid values → clear error |
| AC-9 (optional persister) | ✅ | `TestPersister_NilPersisterNoPanic` — nil persister, tokenizer works identically |
| AC-10 (cross-platform crypto) | ✅ | `internal/crypto` has zero build tags. `GOOS=windows go build ./internal/session` passes |
| AC-11 (no PII in logs) | ✅ | Every log call includes `"pii_values_logged", false`. Logged paths redacted via `redactHomePath()` |
| AC-12 (bbolt schema) | ✅ | `TestConversationKeyFormat` verifies `{provider}/{uuid}/{__meta__\|token}` format |
| AC-13 (metadata integrity) | ✅ | `TestMetadataAutoUpdate` — pii_count=4, pii_types deduplicated, updated_at bumped |
| AC-14 (SBOM) | ✅ | `go.mod`: `go.etcd.io/bbolt v1.5.0` direct; only `golang.org/x/sys` and `gopkg.in/yaml.v3` additional direct deps |
| AC-15 (race-free) | ✅ | `go test -race` passes on all 12 packages |
| AC-16 (SID cache) | ✅ | `TestCache_BasicGetPut`, `TestCache_TTLExpiry` — cache hit returns cached value, stale entries evicted |

**All 16 acceptance criteria are satisfied.**

---

## Qindu-Specific Security Checks

| Check | Status | Notes |
|-------|--------|-------|
| No PII in logs/errors/test fixtures | ✅ | `pii_values_logged: false` on every log call; test data uses synthetic addresses (`example.com`, `test.invalid`) |
| No `InsecureSkipVerify` in production paths | ✅ | Only in `mitm.go:82`, guarded by explicit config `upstream_validation: "insecure"`, logged at WARN |
| Loopback-only bind | ✅ | `config.go:125`: `ip.IsLoopback()` check rejects non-loopback addresses |
| DPAPI before disk write | ✅ N/A | Vault uses AES key file (DD-9); CA DPAPI is untouched in `ca_windows.go` |
| Interceptor interface — no full body buffering (required for tokenizer) | ✅ N/A | Monitor mode buffers for detection (by design in QINDU-0007); tokenizer streaming interceptor is QINDU-0009 |
| Certificate cache bounds | ✅ N/A | `internal/tls` not modified in this sprint |
| No hardcoded secrets | ✅ | Verified: no keys, passwords, tokens in source |
| Graceful shutdown drains connections | ✅ | `graceful.go`: `server.Shutdown(ctx)` with 30s timeout before vault close |
| Config validation at startup | ✅ | `LoadConfig` → `Validate()` called before proxy starts |
| No telemetry/analytics/tracking | ✅ | Verified: no HTTP calls to external services, no crash reporting, no usage metrics |

---

## Verdict

### ✅ **MERGE_READY**

This is exceptionally well-crafted code. The vault implementation handles the genuinely hard problems — TOCTOU-free shutdown, async channel draining with in-flight sender tracking, cooperative context cancellation in long-running sweeps — with correctness and clarity. The crypto package is a textbook AES-256-GCM implementation. The Windows SID lookup encapsulates the unavoidable `unsafe`/`syscall` complexity behind a clean interface.

**Reasons for MERGE_READY despite design flaws**:
1. No critical bugs, no data races, no security holes, no AC violations
2. All 16 acceptance criteria are satisfied with passing tests
3. All 12 packages pass `-race` with zero failures
4. The 5 design flaws (PR-100 through PR-106) are all non-blocking — they concern maintainability, not correctness
5. The one DIP concern (PR-101) is an acknowledged design decision per DD-1 in the story

**What should be addressed before QINDU-0009**:
- PR-100 (variable declaration order) — a one-line fix that prevents a silent rehydration failure if the file is refactored
- PR-102 (unused return value) — adds a comment so QINDU-0009 developers see where the persister needs to be wired
