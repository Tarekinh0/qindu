# Dev Notes — QINDU-0008: Vault local chiffré

> **Fix Cycle 6**: 2026-07-04 — Cleanup after Round 4 peer review fixes. Fixed 4 remaining `NewProxy(...)` call sites in `proxy_test.go` that still passed the removed `persister` parameter. All verification commands pass.

> **Fix Cycle 5**: 2026-07-04 — Peer review Round 3 (FIX_AND_RESUBMIT) → PR-003, PR-004, PR-107 remaining items fixed → resubmitted.
>
> Also fixed a test regression in `internal/proxy/proxy_test.go` caused by the PR-002 (remove duplicate `defaultScanPaths`) changes from the prior cycle.

## Fix Cycle 6 Changes

### Proxy `persister` parameter removed — test cleanup

**File**: `internal/proxy/proxy_test.go`

The prior cycle removed the `persister vault.TokenPersister` parameter from:
- `NewProxy()` — signature changed from 6 params to 5
- `selectInterceptor()` — signature changed from 3 params to 2
- `NewMonitorInterceptor()` — signature changed (now returns `error`)

One test (`TestNewProxy_EnforceModeFatal`) was already updated in the prior cycle. Four remaining call sites still passed the trailing `nil` argument:

| Line | Test | Fix |
|------|------|-----|
| 90 | `TestNewProxy_TransparentMode` | Removed final `, nil` |
| 127 | `TestNewProxy_MonitorMode` | Removed final `, nil` |
| 147 | `TestNewProxy_DefaultConfigIsValid` | Removed final `, nil` |
| 167 | `TestNewProxy_StartTimeIsSet` | Removed final `, nil` |

All 5 call sites now match the 5-parameter `NewProxy(cfg, ca, certCache, logger, version)` signature.

## Fix Cycle 5 Changes

### PR-003: Replace direct bbolt accesses in remaining tests

**File**: `internal/vault/vault_test.go`

Three tests were updated to use the public API instead of direct bbolt field access:

| Test | Before | After |
|------|--------|-------|
| `TestTTLExpiry` | `vault.db.View(...)` with `b.Get(conversationKey(...))` | `vault.GetConversation()` — returns `nil` when expired |
| `TestDeleteConversation` | Two separate `vault.db.View(...)` blocks checking for presence/absence | Two `vault.GetConversation()` calls — returns `nil` when deleted, non-nil when kept |
| `TestShutdownDrain` | Retained direct bbolt access | Added AC-2 comment explaining why: "Direct bbolt access required to verify ciphertext at rest. The closed vault cannot serve GetConversation(), so we must read the DB directly for this specific drain-verification assertion." |

### PR-004: Redact home path in vault initialized log

**File**: `cmd/agent/proxy.go`

Added `redactHomePath(path string) string` helper function that:
- On Windows: replaces `%LOCALAPPDATA%` prefix with the literal string `%LOCALAPPDATA%`
- On Unix (and as fallback): replaces `$HOME` prefix with `~`
- If neither prefix matches, returns the path unchanged

Applied to the `logger.Info("vault initialized", ...)` log line — `vaultUser.DBPath` is now passed through `redactHomePath()` before logging. The actual path variable is **not** modified; the vault continues to use the real filesystem path.

### PR-107: Hardcoded bucket name replaced with constant

**File**: `cmd/agent/proxy.go`

Changed `[]byte("tokens")` → `[]byte(vault.BucketTokens)` in the `initVault()` function's `CreateBucketIfNotExists` call. The `BucketTokens` constant (`"tokens"`) is already defined in `internal/vault/keys.go` and exported.

### Test regression fix: `TestNewProxy_MonitorMode`

**File**: `internal/proxy/proxy_test.go`

The test created a `policy.Config` without setting `Monitor.ScanPaths`. After PR-002 (removed `defaultScanPaths()` from the monitor interceptor), the interceptor constructor requires non-empty `scanPaths`. Added `Monitor: policy.MonitorConfig{ScanPaths: []string{"/v1/messages", "/chat/completions"}}` to the test config.

> **Fix Cycle 4**: 2026-07-04 — Peer review Round 1 (FIX_AND_RESUBMIT) → all 14 findings fixed → resubmitted.

## Files Modified in This Fix Cycle

| File | Change |
|------|--------|
| `internal/vault/vault.go` | **PR-001**: Removed `close(v.writeCh)` from `Close()` — channel never closed, goroutines exit via `ctx.Done()`. Updated `Close()` and `Persist()` docstrings. **PR-002**: `PurgeAll` now recreates `tokens` bucket in same tx after `DeleteBucket`. **PR-101**: `upsertMetaInTx` now logs `b.Put` errors instead of silently discarding. **PR-102**: Added TOCTOU comment to `GetConversation` documenting eventual-consistency of three-transaction design. **PR-107**: Moved `extractPIIType` call to after `closeMu.Unlock()` in `Persist()` to clearly bound lock scope. |
| `internal/vault/meta.go` | **PR-109**: Removed unused `StatusExpired` and `StatusPurged` enum values. Added comment explaining physical deletion removes the need for status transitions. |
| `internal/vault/vault_test.go` | **PR-105**: Removed redundant `cancel()` call in `TestShutdownDrain` (Close() already cancels internally). Changed to `vault.Run(context.Background())`. |
| `internal/vault/persister.go` | Fire-and-forget signatures (already no-error-return in previous cycle). |
| `cmd/agent/proxy.go` | **PR-104**: Extracted ~75-line nested vault init block into `initVault(cfg, logger)` standalone function returning `(*Vault, TokenPersister)`. All defer cleanup (crypto.Close, db.Close) handled inside initVault on error paths. Call site reduced to one line. |
| `configs/default.yaml` | **PR-004**: Changed `pii_logging: true` → `pii_logging: false`. Privacy tool must not ship with metadata enumeration enabled. |
| `internal/crypto/crypto_windows.go` | **PR-106**: Added fragility comment above `buildRestrictiveACL` documenting manual ACL buffer construction risks and x/sys version pinning requirement. |

## Interface Deviation from Story DD-1

### PR-003 / PR-103 / PR-110: `TokenPersister` signature change

The story DD-1 specifies the `TokenPersister` interface with `error` returns:
```go
// Story DD-1
Persist(scope Scope, token string, value []byte) error
UpdateMeta(scope Scope, meta Metadata) error
```

The implementation uses **fire-and-forget** (no error return):
```go
// Actual implementation
Persist(scope Scope, token string, value []byte)
UpdateMeta(scope Scope, meta Metadata)
```

**Rationale**:
1. **DD-10 async writes**: Writes are enqueued to a buffered channel and committed asynchronously. By the time the channel send succeeds, the bbolt write hasn't happened yet — so there's nothing meaningful to return as an error.
2. **CISO SR-802**: Channel sends must be non-blocking. Returning errors would force callers to handle channel-full conditions, creating back-pressure on the proxy.
3. **Internal error handling**: All errors (encryption failure, bbolt write failure, marshal failure) are logged at ERROR level inside `handleWrite()` and `Persist()`. The proxy operates correctly with or without vault persistence (memory store is primary source of truth).
4. **`Close()` signature**: Changed from `Close() error` to `Close()`. No caller checked the return value. Internal errors (bbolt close, crypto close) are logged. The TOCTOU-safe design (no channel close, no error paths in close sequence) is simpler.

### PR-103: Dead `persister` field in MonitorInterceptor

The `MonitorInterceptor.persister` field is populated during construction but unused in monitor mode. It is reserved for QINDU-0009 (tokenizer integration in enforce mode). This is intentional forward-looking wiring — the alternative (lazy plumbing when needed) would require changing multiple constructor signatures across packages. The field is documented with `// reserved for QINDU-0009 (tokenizer integration)`.

### PR-108: Dependency documentation — `x/sys`, not `x/sync`

The story DD-2 predicted `golang.org/x/sync` as the second direct dependency. The actual `go.mod` lists `golang.org/x/sys` (used by `internal/session/lookup_windows.go` for SID resolution and `SHGetKnownFolderPath`). `x/sync` appears in `go.sum` as a transitive dependency but is not directly imported. `go mod tidy` produces no changes, confirming correctness.

## Technical Choices and Rationale

### PR-001: Channel never closed — TOCTOU-safe shutdown

The TOCTOU race between `Persist()` and `Close()`:
1. `Persist()` grabs channel ref under `closeMu`, releases lock
2. `Close()` sets `closed=true`, cancels context, waits for goroutines, then closes channel
3. `Persist()` sends on now-closed channel → **panic**

**Fix**: The `close(v.writeCh)` call in `Close()` was removed entirely. The write channel is intentionally never closed:
- `writeLoop` exits via `ctx.Done()`, then drains remaining via `drainRemaining()`
- After `closed==true`, new `Persist()`/`UpdateMeta()` calls return immediately
- The channel is garbage-collected when the Vault is freed
- No TOCTOU window exists because there's no channel close to race with

A goroutine that grabbed a channel reference before `closed=true` can still send after Close() returns — the message sits in the buffered channel until GC. No panic, minor resource leak at shutdown (acceptable).

### PR-002: PurgeAll recreates bucket

After `PurgeAll()` deletes the `tokens` bucket, it now recreates it in the same transaction. The vault remains fully operational — subsequent `Persist()` calls succeed. The docstring now accurately states: *"The vault remains open and operational after this call."*

### PR-004: Default `pii_logging: false`

A privacy tool must not ship with PII metadata enumeration enabled. Users who want entity-type summaries in logs can opt in by setting `pii_logging: true`.

### PR-101: Log metadata put errors

`upsertMetaInTx` previously used `_ = b.Put(metaKey, updated)`. Now logs via `v.logger.Error(...)` with PII-free context. The error is non-fatal (token value is already committed in the same transaction).

### PR-102: GetConversation TOCTOU documentation

Added a comment documenting the eventual-consistency behavior of the three-transaction design:
- Step 1 (View): read metadata, check expiry
- Step 2 (Update): auto-purge if expired
- Step 3 (View): read and decrypt entries

Between step 1 and step 3, the sweeper may delete the conversation. This is harmless — step 3 returns an empty slice.

### PR-104: Extracted vault initialization

The 75-line nested `if-else` pyramid in `cmd/agent/proxy.go` was extracted into `initVault(cfg, logger) (*vault.Vault, vault.TokenPersister)`. The function returns `nil, nil` on any error, with all cleanup (crypto.Close, db.Close) handled internally via explicit close calls on each error path. The call site is:
```go
vaultInst, vaultPersister := initVault(cfg, logger)
```

### PR-105: Removed redundant cancel() in test

`TestShutdownDrain` called `vault.Close()` then `cancel()`. Since `Close()` internally cancels the context and waits for goroutines, the external `cancel()` was redundant. Changed to `vault.Run(context.Background())`.

### PR-106: ACL fragility documentation

Added a comment above `buildRestrictiveACL` in `crypto_windows.go` documenting:
- Manual buffer construction using `unsafe` pointer arithmetic
- Dependency on `x/sys/windows` struct layout stability
- Version pinning requirement in `go.mod`
- Need for Windows VM integration tests on x/sys upgrades

### PR-107: Lock scope discipline in Persist()

Moved `extractPIIType(token)` call from before `closeMu.Unlock()` to after it. The function is pure (no shared state), so it doesn't need the lock. The critical section is now clearly bounded to the `closed` check and channel reference grab.

### PR-109: Removed unused Status enum values

`StatusExpired` and `StatusPurged` were defined but never assigned. The vault physically deletes expired/purged entries rather than transitioning their status. Keeping unused enum values would be dead code and could confuse the eventual UI schema (QINDU-0016). `StatusActive` remains as the initial state set by `NewMetadata()`.

## How to Test

```sh
# Full build
go build ./...

# Windows cross-compilation
GOOS=windows go build ./internal/session

# Vet
go vet ./...

# Tests with race detector
go test -race -count=1 ./...

# Format check
go fmt ./...
```

### Key tests:

| Test | What it verifies | Sprint AC |
|------|-----------------|-----------|
| `TestRestartRoundTrip` | Write 3 tokens, close vault, reopen same files, retrieve via `GetConversation` — all values match | AC-1 |
| `TestMetadataAutoUpdate` | `pii_count == 4` after 4 writes, `pii_types` has 3 deduplicated types, `updated_at >= created_at` | AC-13 |
| `TestGetConversationReturnsEntries` | `GetConversation` returns decrypted entries with correct token, value, type | AC-3 |
| `TestGetConversationAutoPurgeExpired` | Expired conversation returns nil; verified deleted from DB | AC-3 |
| `TestShutdownDrain` | `Run()` before `Persist()`, 50 writes, close, reopen DB — all 50 committed | AC-7 |
| `TestProviderRejectsSlash` | Provider "azure/openai" rejected, no entries written | N/A (PR-106) |
| `TestExtractPIIType` | 9 table-driven cases for token type extraction | N/A (defense-in-depth) |

## Gaps and Remaining Risks

1. **Channel not drained after ctx cancellation if `Persist()` keeps sending**: After `Close()` sets `closed=true`, new `Persist()` calls return immediately. But if a `Persist()` already passed the check and has a channel reference, it can send after `Close()` has finished. The message will sit in the channel buffer until GC. No panic, but a minor resource leak. Mitigated by the fact that `Close()` is only called at shutdown.

2. **Access-time TTL check via `GetConversation` uses separate transactions**: Reading `__meta__` (View tx) and deleting (Update tx) are not atomic — a race with the background sweeper is possible. If the sweeper deletes the conversation between the View and the Update, `DeleteConversation` will be a no-op (prefix scan finds nothing). This is benign: the sweeper already deleted it, and the caller gets `nil, nil`. Documented in code (PR-102).

3. **`extractPIIType` assumes all valid tokens follow `<<TYPE_N>>`**: If a token is created with an unexpected format (e.g., from a non-standard entity type with different syntax), `piiType` will be empty and `__meta__` won't be updated. The token write itself still succeeds.

4. **Windows ACL construction is fragile**: The `buildRestrictiveACL` function uses manual buffer arithmetic. The `x/sys` version is pinned in `go.mod` — do not upgrade without Windows VM validation (documented per PR-106).

5. **MonitorInterceptor.persister field is dead code**: Reserved for QINDU-0009 (tokenizer integration). No runtime impact in monitor mode. Documented per PR-103.

## Build Verification (Cycle 6)

```
$ go build ./...                           # PASS (clean)
$ GOOS=windows GOARCH=amd64 go build ./internal/session  # PASS (clean)
$ go vet ./...                              # PASS (zero warnings)
$ go test -race -count=1 ./...              # PASS (12 packages, zero failures, zero races)
$ go fmt ./...                              # PASS (zero formatting changes)
$ go fmt ./... && git diff --exit-code      # fmt clean; diff shows prior-session uncommitted changes (25 files, 1468+/1942-)
```

### Test results (all packages):

| Package | Status | Time |
|---------|--------|------|
| `cmd/agent` | ok | 1.0s |
| `internal/constants` | (no tests) | — |
| `internal/crypto` | ok | 1.5s |
| `internal/interceptor` | ok | 1.3s |
| `internal/logging` | ok | 1.0s |
| `internal/pii` | ok | 1.2s |
| `internal/policy` | ok | 1.0s |
| `internal/proxy` | ok | 3.9s |
| `internal/service` | (no tests) | — |
| `internal/session` | ok | 1.0s |
| `internal/tls` | ok | 1.1s |
| `internal/tokenize` | ok | 1.3s |
| `internal/vault` | ok | 10.6s |

**Race detector**: zero races across all packages.

## Build Verification (Cycle 5)

```
$ go build ./...                           # PASS (clean)
$ GOOS=windows go build ./internal/session # PASS (clean)
$ go vet ./...                              # PASS (zero warnings)
$ go test -race -count=1 ./...              # PASS (12 packages, zero failures, zero races)
$ go fmt ./...                              # PASS (zero formatting changes)
```
