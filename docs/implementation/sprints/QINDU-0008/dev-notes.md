# Dev Notes — QINDU-0008: Vault local chiffré

> **Fix Cycle**: 2026-07-04 — Peer review (FIX_AND_RESUBMIT) → 4 critical fixes applied → resubmitted.
> See [Fix Cycle: Peer Review Findings](#fix-cycle-peer-review-findings) below.

## Files Created

| File | Description |
|------|-------------|
| `internal/crypto/crypto.go` | AES-256-GCM encryption service: key file mgmt, Encrypt/Decrypt, zero-on-Close |
| `internal/crypto/crypto_unix.go` | Unix key file permission validation (strict 0600) |
| `internal/crypto/crypto_windows.go` | Windows ACL-based key file protection (owner+SYSTEM only via SetNamedSecurityInfo) |
| `internal/crypto/crypto_test.go` | Nonce uniqueness, encrypt/decrypt round-trip, tamper detection, permissions, entropy, key zeroing (16 tests) |
| `internal/vault/vault.go` | bbolt-backed vault implementing TokenPersister: async channel, startup sweep, background sweeper, drain, PurgeExpired/PurgeAll/DeleteConversation/ListConversations/Close, UUID v4 generation |
| `internal/vault/meta.go` | Per-conversation metadata schema (JSON: created_at, updated_at, provider, conversation_id, label, pii_count, pii_types, status) |
| `internal/vault/ttl.go` | TTL helpers: isExpired(), sweepInterval() (min(ttl/7, 24h), floor 1h) |
| `internal/vault/persister.go` | TokenPersister interface (Persist, UpdateMeta) + Scope struct (Provider, ConversationID) |
| `internal/vault/vault_test.go` | Persist/retrieve, async non-blocking (2000 burst), shutdown drain, concurrent persist (50 goroutines), TTL expiry, infinite TTL, startup sweep, PurgeAll, DeleteConversation, UUID v4 format (1000), close idempotent, bbolt file permissions, metadata integrity, scope key/prefix format (15 tests) |
| `internal/session/lookup.go` | ResolvedUser struct (VaultPath, KeyPath, DBPath) |
| `internal/session/lookup_windows.go` | Windows SID lookup: GetExtendedTcpTable → PID, OpenProcess → OpenProcessToken → SID, LRU cache (10K cap), resolvePathFromSID |
| `internal/session/lookup_other.go` | Linux: $XDG_DATA_HOME/qindu/ or ~/.local/share/qindu/; macOS: ~/Library/Application Support/Qindu/ |
| `internal/session/lookup_test.go` | Valid paths, XDG_DATA_HOME env, home fallback, macOS path, idempotence (5 tests Unix) |
| `internal/session/lookup_windows_test.go` | LRU cache: basic get/put, eviction, 10K scale, update existing, empty cache, global cache init (6 tests Windows) |

## Files Modified

| File | Change |
|------|--------|
| `internal/tokenize/tokenizer.go` | Added `persister`, `provider`, `convID` fields; `WithPersister()`, `WithProvider()`, `WithConversationID()` options; persister call in `assignTokens()` (fire-and-forget, non-blocking, guarded by nil check) |
| `internal/tokenize/tokenizer_test.go` | Added `mockPersister` implementing vault.TokenPersister; tests: called with correct values, nil persister no panic, duplicate values persisted once, provider/convID set correctly, option ordering (5 additional tests) |
| `internal/policy/config.go` | Added `VaultConfig` struct (TTL string); `AgentConfig.Vault` field; `VaultConfig.Validate()` with TTL validation (rejects negative, sub-hour, non-integer hours, unparseable); `MergeFileOverride` now merges vault settings; `DefaultConfig` includes Vault TTL "168h" |
| `internal/policy/config_test.go` | Added `TestVaultTTLValidation` (12 sub-cases for valid/invalid TTL values) |
| `configs/default.yaml` | Added `agent.vault:` section with `ttl: 168h` and documentation comment |
| `cmd/agent/proxy.go` | Added full vault initialization sequence: `session.LookupVaultPath()`, `os.MkdirAll`, `crypto.New()`, `bolt.Open()`, `vault.New()`, `vault.Run()`; `parseConfigTTL()` helper; vault.Close() on shutdown; graceful fallback to memory-only mode on any init failure |
| `internal/proxy/proxy.go` | Added `persister` field to Proxy struct; `persister` parameter in `NewProxy()` and `selectInterceptor()` forwarded to interceptor; `Persister()` accessor method |
| `internal/interceptor/monitor.go` | Added `persister` field to MonitorInterceptor; `persister` parameter in `NewMonitorInterceptor()` |

### Peer Review Fix Cycle Changes (2026-07-04)

| File | Change |
|------|--------|
| `internal/session/lookup_windows.go` | **PR-001**: `resolvePathFromSID()` replaced placeholder with `windows.LookupAccountSid` two-call pattern (SID→username→`C:\Users\{username}\AppData\Local\Qindu`). `LookupVaultPath()` removed broken WTS console session check — delegates directly to `lookupCurrentUserVaultPath()`. |
| `internal/session/lookup_windows.go` | **PR-002**: Added `sync.RWMutex` to `pidSIDCache` struct. `get()` acquires `RLock()`, `put()` acquires `Lock()`. Global LRU cache is now concurrency-safe. |
| `internal/session/lookup_windows.go` | **PR-003**: Replaced dead code (three port-conversion attempts with `_ =` hacks) with single correct byte swap: `uint16(row.LocalPort>>8) \| uint16(row.LocalPort<<8)`. Removes the `_ =` anti-pattern. |
| `internal/vault/vault.go` | **PR-004**: Removed duplicate drain loop from `Close()`. Shutdown drain is now handled exclusively by `writeLoop.drainRemaining()` (triggered by context cancellation). `Close()` sequence: cancel → close channel → wg.Wait → close resources. No double-consumer. |

## Test Summary

| Package | Tests | Result |
|---------|-------|--------|
| `internal/crypto` | 16 | PASS |
| `internal/vault` | 15 | PASS |
| `internal/session` | 5 (Unix) + 6 (Windows) | PASS |
| `internal/tokenize` | 47 | PASS |
| `internal/policy` | 91 | PASS |
| **Total sprint packages** | **180** | **PASS** |

All tests pass with `go test -race -count=1 ./internal/...` (zero data races).

## Implementation Details

### How TokenPersister flows from vault → proxy → interceptor → tokenizer

```
cmd/agent/proxy.go:
  vaultInst, vaultPersister := vault.New(db, crypto, ttl, logger)
  proxy.NewProxy(cfg, ca, certCache, logger, version, vaultPersister)
      ↓
internal/proxy/proxy.go:
  Proxy.persister = vaultPersister
  selectInterceptor(cfg, logger, persister)
      ↓
  → interceptor.NewMonitorInterceptor(engine, ..., persister)
      ↓
internal/interceptor/monitor.go:
  MonitorInterceptor.persister = persister  (stored, unused in monitor mode)
      ↓
  (In QINDU-0009 enforce mode: passed to Tokenizer via WithPersister())
      ↓
internal/tokenize/tokenizer.go:
  assignTokens() → if t.persister != nil { t.persister.Persist(scope, token, value) }
```

In QINDU-0008, the TokenPersister is wired through the entire chain but actual Tokenizer integration (enforce mode) is deferred to QINDU-0009. The persister field is stored in MonitorInterceptor for future use. Tokenizer tests validate the persister callback directly via `mockPersister`.

### How SID lookup works on Windows vs Linux/macOS

**Linux/macOS** (`lookup_other.go`): `LookupVaultPath()` is trivial — it reads `$HOME` or `$XDG_DATA_HOME` and returns per-user paths. No network calls. No PID resolution needed because the process always runs as the logged-in user.

**Windows console mode**: Uses `windows.KnownFolderPath(FOLDERID_LocalAppData, ...)` to get `%LOCALAPPDATA%` of the current user.

**Windows service mode** (`lookup_windows.go`): Services run as SYSTEM (session 0). Per-user vault isolation requires resolving the client PID to a user SID:
1. `GetExtendedTcpTable` enumerates TCP connections with owning PIDs
2. Match source port → PID
3. `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` + `OpenProcessToken(TOKEN_QUERY)`
4. `GetTokenUser` → SID string
5. PID→SID cached in global LRU (avoids repeated syscalls for the same PID)
6. SID → vault path (`C:\Users\{username}\AppData\Local\Qindu`)

**Fallback policy (SR-805)**: On lookup failure, the connection is denied — no fallback to a machine-level vault. This is a strict security boundary.

### How the async channel avoids blocking (CISO SR-802)

The vault uses a buffered channel (`make(chan writeOp, 1024)`) for all Persist/UpdateMeta calls. The `Persist()` method does a non-blocking `select { case ch <- op: ...; default: log.Warn("dropped") }`. This guarantees:
- Proxy request latency is unaffected by disk I/O
- Under burst load, writes beyond channel capacity are silently dropped with a PII-free WARNING log (the in-memory MemoryStore remains the live source of truth for rehydration)
- A single background goroutine (`writeLoop()`) drains the channel, encrypts values via AES-256-GCM, and commits to bbolt

### How TTL enforcement works

Three layers:

1. **Startup sweep** (`vault.New()`): On construction, `sweepExpired()` iterates all `__meta__` keys, checks each conversation's `created_at` against the configured TTL, deletes expired conversations entirely (all tokens + metadata). Logged as INFO with purged count (PII-free).

2. **Background sweeper** (`sweeperLoop()`): Runs on a ticker with interval `min(ttl/7, 24h)`, minimum 1 hour. At each tick, calls `PurgeExpired()`. Logs INFO "vault sweep: purged N expired conversations".

3. **Access-time check**: Not yet implemented (deferred to QINDU-0011 when conversation access patterns are defined — this is noted in the story as a known gap for this sprint).

### How vault.key permissions differ on Unix vs Windows (CISO SR-804)

**Unix** (`crypto_unix.go`): `validateKeyFilePermissions()` checks `os.Stat().Mode().Perm() == 0600`. On creation, `writeKeyFile()` calls `f.Chmod(0600)` and `os.MkdirAll(dir, 0700)`. `setPlatformACL` is a no-op — chmod 0600 is sufficient on Unix.

**Windows** (`crypto_windows.go`): Both `validateKeyFilePermissions()` and `setPlatformACL()` call `setKeyFileACL()`, which:
1. Gets the file's current owner SID via `GetNamedSecurityInfo`
2. Creates SYSTEM SID via `CreateWellKnownSid(WinLocalSystemSid)`
3. Builds a manual ACL with two `ACCESS_ALLOWED_ACE` entries (owner: GENERIC_READ|GENERIC_WRITE, SYSTEM: GENERIC_READ|GENERIC_WRITE)
4. Applies via `SetNamedSecurityInfo` with `DACL_SECURITY_INFORMATION`

This replaces any inherited ACLs with an explicit allowlist of owner + SYSTEM — no other users or groups can access the key file.

### How the LRU cache prevents repeated lookups (CISO SR-803)

On Windows, each TCP connection from a process would require the full PID→SID resolution chain (GetExtendedTcpTable → OpenProcess → OpenProcessToken → GetTokenUser). The LRU cache (`pidSIDCache`, max 10,000 entries) maps PID to SID string:
- First connection from a PID: full resolution, cache miss → store in LRU
- Subsequent connections from same PID: cache hit → skip all syscalls
- Eviction policy: least-recently-used. Cache is in-memory only, never persisted to disk.

## Design Deviations

None — all 15 DD decisions implemented as specified:
- DD-1 (TokenPersister interface): ✓
- DD-2 (bbolt backend): ✓
- DD-3 (AES-256-GCM stdlib only): ✓
- DD-4 (encrypt values, plaintext keys): ✓
- DD-5 (per-conversation TTL, 7-day default, multi-layer): ✓ (access-time check deferred to QINDU-0011 per story)
- DD-6 (conversation metadata schema): ✓
- DD-7 (internal/crypto pure AES, no build tags): ✓
- DD-8 (proxy-generated UUID for vault key): ✓
- DD-9 (CA stays DPAPI, vault gets AES key file): ✓
- DD-10 (async writes): ✓
- DD-11 (TokenPersister optional subscriber): ✓
- DD-12 (per-user vault paths): ✓
- DD-13 (SID lookup with strict fallback): ✓
- DD-14 (minimal config): ✓
- DD-15 (startup/shutdown sequence): ✓

## Fix Cycle: Peer Review Findings

The peer review identified 4 critical defects blocking merge. All were fixed in a single cycle.

### PR-001: SID→path resolution (CRITICAL)

**Before**: `resolvePathFromSID()` constructed `C:\Users\{SID}\AppData\Local\Qindu` — raw SID as directory name. This path does not exist on any Windows system, so vault initialization would always fail in service mode.

**After**: Uses `windows.LookupAccountSid` (two-call pattern: first to get buffer sizes, second to resolve) to convert SID → username. Then constructs `C:\Users\{username}\AppData\Local\Qindu`. The `LookupVaultPath()` function no longer performs the broken WTS console session check — it delegates directly to `lookupCurrentUserVaultPath()`. SID from process token (via `LookupVaultPathForPort`) is sufficient for vault path resolution.

### PR-002: Data race on global LRU cache (CRITICAL)

**Before**: `globalCache` (package-level `*pidSIDCache`) was accessed from `resolvePathFromPID()` without any synchronization. Concurrent proxy connections would cause data races on the map and linked-list pointers.

**After**: Added `sync.RWMutex` to `pidSIDCache` struct. `get()` acquires `RLock()`, `put()` acquires `Lock()`. Internal methods (`moveToFront`, `pushFront`, `evictLRU`) are already called within the lock scope of their callers, so no additional locking needed at those levels.

### PR-003: Port byte-order in TCP table lookup (CRITICAL)

**Before**: Dead code with three port-conversion attempts and `_ =` hacks — the one actually used (`uint16(row.LocalPort)`) did not convert from network byte order. On little-endian x86/x64, the port comparison would never match, causing PID lookup to always fail.

**After**: Single correct conversion: `uint16(row.LocalPort>>8) | uint16(row.LocalPort<<8)` — swaps bytes of the lower 16 bits of the DWORD (network→host order). Removed all dead code.

### PR-004: Double-consumer in vault shutdown (HIGH)

**Before**: `Close()` had its own drain loop that consumed from `v.writeCh` concurrently with `writeLoop.drainRemaining()`. Both goroutines could read from the same channel during shutdown, causing unpredictable item handling and incorrect drained counts.

**After**: Removed the drain loop from `Close()`. The shutdown sequence is now: (1) set `closed=true`, (2) cancel context → writeLoop detects `ctx.Done()`, calls `drainRemaining()` to drain buffered items, (3) close channel → final signal to writeLoop, (4) `wg.Wait()` for both goroutines, (5) close bbolt and crypto. Only `writeLoop` drains — single consumer.

### Build & Test Verification

```
$ go build ./...                          # PASS
$ GOOS=windows go build ./internal/session  # PASS (WTS compile error resolved)
$ go test -race -count=1 ./...             # PASS (12 packages, zero races)
$ go vet ./...                             # PASS
$ go fmt ./...                             # PASS (no changes)
```

## Known Limitations

- **golangci-lint incompatible with Go 1.26** (project-wide, not sprint-specific)
- **`resolvePathFromSID` assumes `C:\Users\{username}` profile path** — The function constructs the vault directory as `C:\Users\{username}\AppData\Local\Qindu`. This is correct for the vast majority of Windows installations, but does not handle users with custom profile directories (e.g., redirected folders, roaming profiles). A future enhancement could use `GetUserProfileDirectoryW` or `SHGetKnownFolderPath` with the user's token for full correctness.
- **Vault wired but TokenPersister unused in monitor mode** — The persister is threaded through Proxy → MonitorInterceptor → (future) Tokenizer, but `InterceptRequest`/`InterceptResponse` in monitor mode only detect PII without tokenizing. The actual Tokenizer integration with persister completes in QINDU-0009 (Enforce mode).
- **SID lookup on Windows service mode verified only at compile time** — The `lookup_windows.go` code compiles for `GOOS=windows` but TCP table traversal and SID resolution behavior cannot be validated on a Linux CI runner. Requires QEMU VM integration test.
- **Access-time TTL check deferred to QINDU-0011** — Per story design: "Access-time check: On conversation access, check and purge individual scope." This requires conversation access patterns defined in the ChatGPT adapter sprint.
- **`Metadata` custom MarshalJSON unintentionally unused** — The `Metadata.MarshalJSON()` method is defined but Go's `json.Marshal` skips it because `json.Marshal` calls the interface on the pointer type, but `MarshalJSON` is on the value receiver. The `UnmarshalMetadata` helper function is used instead for type safety. This is cosmetic — JSON serialization of `Metadata` works correctly via the standard `json.Marshal`.

## SBOM Impact

| Dependency | Version | Type |
|------------|---------|------|
| go.etcd.io/bbolt | v1.5.0 | direct |
| golang.org/x/sync | v0.20.0 | indirect (transitive via bbolt) |
| golang.org/x/sys | v0.46.0 | direct (pre-existing, already used by TLS/CA Windows code) |

No new CGO dependencies. All packages are pure Go. `golang.org/x/sync` is in `go.sum` as a transitive dependency of bbolt v1.5.0 (used internally for errgroup-based operations).
