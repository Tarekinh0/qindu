# QINDU-0008: Vault local chiffré

## Status
DRAFT → ready for DPO/CISO design gates

## Backlog Reference
- **ID**: QINDU-0008
- **Title**: Vault local chiffré
- **Dependencies**: QINDU-0006 (Tokenisation)
- **ADR refs**: ADR-003, ADR-004, ADR-008
- **Gates required**: DPO, CISO, QA

## Goal

Provide persistent, encrypted, per-user storage for token↔PII mappings. The vault archives conversations so that:
1. PII never appears in plaintext on disk
2. Conversations can be browsed by the future UI (QINDU-0016)
3. TTL-based auto-expiration respects user privacy
4. Multi-user isolation on shared Windows machines

## Scope

### In scope
- `internal/crypto` — pure AES-256-GCM encryption with key file (all platforms)
- `internal/vault` — bbolt-backed vault implementing `TokenPersister` interface
- `internal/session` — Windows SID lookup (TCP + UDP) with LRU cache for user isolation
- Integration: vault wired into agent startup/shutdown as async subscriber to Tokenizer
- Config: `agent.vault.ttl` (24h, 168h default, 0 = infinite)
- Per-user vault paths on all three platforms
- Metadata schema: `__meta__` key per conversation

### Out of scope
- UI (QINDU-0016)
- CA encryption refactoring (CA stays on DPAPI, untouched)
- Enforce mode integration (QINDU-0009)
- SSE rehydration (QINDU-0010)
- ChatGPT adapter / conversation_id extraction (QINDU-0011)
- Linux/macOS installer packaging (QINDU-0018, QINDU-0019)

## Design Decisions (from grill-me session)

### DD-1: TokenPersister interface
The `Store` interface (`Map/Get/Count/Clear/Close`) stays unchanged — it remains the fast in-memory path. A new, separate `TokenPersister` interface is injected into the Tokenizer as an optional subscriber. The vault implements this interface. The proxy operates identically with or without a vault (nil = memory-only, used in tests).

```go
type TokenPersister interface {
    Persist(scope Scope, token string, value []byte) error
    UpdateMeta(scope Scope, meta Metadata) error
}

type Scope struct {
    Provider       string
    ConversationID string // proxy-generated UUID (DD-8)
}
```

### DD-2: bbolt persistence backend
`go.etcd.io/bbolt` v1.5.0. Pure Go, no CGO, CNCF-graduated. One file per user (`vault.db`), opened at startup, kept open for process lifetime, closed at graceful shutdown. `Timeout: 1s`, `NoSync: false`. SBOM adds 2 direct deps (`bbolt`, `golang.org/x/sync`).

### DD-3: AES-256-GCM via stdlib only
`crypto/aes` + `crypto/cipher` + `crypto/rand`. Hardware-accelerated (AES-NI on x86, ARM Crypto on Apple Silicon). No system crypto library dependencies. No DPAPI — the vault is portable. DPAPI stays in `ca_windows.go` (untouched).

### DD-4: Encrypt values, plaintext keys
bbolt keys (`provider/uuid/token` and `provider/uuid/__meta__`) are plaintext. Values are AES-256-GCM ciphertext. Metadata (provider name, timestamps, PII counts) is not PII — plaintext enables prefix scans for the UI and TTL enforcement without decrypting. An attacker with disk access sees conversation structure but not PII content.

### DD-5: Per-conversation TTL, 7-day default
TTL is at the conversation level, not per-entry. Enforced via `created_at` in `__meta__`. Multi-layered enforcement:
1. **Startup sweep**: On agent start, iterate all `__meta__` keys, purge expired.
2. **Background sweeper**: Goroutine with 4-hour ticker, iterates and purges expired conversations. INFO-level log with count purged (PII-free).
3. **Access-time check**: On conversation access, check and purge individual scope.
Configurable: `agent.vault.ttl: 168h`. Valid: `24h`, `168h` (default), `0` (infinite — WARNING logged at startup). Config comment notes: *"TTL enforcement via startup sweep + background sweeper (4h interval) + access-time check. If proxy is stopped before a sweep fires, data may briefly persist beyond configured TTL."*

### DD-6: Conversation-level metadata
Each conversation gets a `__meta__` key with a JSON value containing:
```json
{
  "created_at": 1750000000,
  "updated_at": 1750000900,
  "provider": "chatgpt",
  "conversation_id": "",
  "label": "",
  "pii_count": 3,
  "pii_types": ["EMAIL", "IBAN"],
  "status": "active"
}
```
`conversation_id` and `label` are populated in later sprints (QINDU-0011). `pii_count` and `pii_types` are materialized at write time for fast UI reads. `status`: `active` | `expired` | `purged`.

### DD-7: `internal/crypto` package — pure AES
No DPAPI extraction. A single package with no build tags:
```go
func New(keyPath string) (*Service, error)  // reads or creates 32-byte key file, chmod 0600
func (s *Service) Encrypt([]byte) ([]byte, error)
func (s *Service) Decrypt([]byte) ([]byte, error)
```
One implementation, all platforms.

### DD-8: Proxy-generated UUID for vault key
The interceptor generates a UUID (`crypto/rand`) at Tokenizer creation time. This UUID is used as the vault conversation key. The provider's real `conversation_id` (e.g., ChatGPT's UUID) is stored as a metadata field when it arrives in the response. No rename, no key migration.

### DD-9: Separate keys — CA stays DPAPI, vault gets AES
CA key encryption (`ca_windows.go`) is untouched. Vault gets its own `vault.key` file (32 random bytes, 0600). On Linux/macOS, this is the AES key. On Windows, the same pattern applies — AES with a key file, not DPAPI.

### DD-10: Async writes
`Map()` writes to MemoryStore (instant, same as today), then enqueues to a buffered channel. A background goroutine drains the channel, encrypts, and writes to bbolt. The proxy thread never blocks on disk. Crash before commit = vault incomplete for that conversation, but the proxy operates fine (MemoryStore is the live source of truth for rehydration).

### DD-11: TokenPersister as optional Tokenizer subscriber
```go
func WithPersister(p TokenPersister) Option { ... }
```
Injected at construction. Nil by default (testing, memory-only mode). In production, the vault is wired in. Two lines in the Tokenizer, Store interface untouched.

### DD-12: Per-user vault isolation
Vault paths are per-user:
```
Windows: %LOCALAPPDATA%\Qindu\vault.db  + vault.key
Linux:   ~/.local/share/qindu/vault.db   + vault.key
macOS:   ~/Library/Application Support/Qindu/vault.db + vault.key
```
Linux and macOS are naturally per-user via `$HOME`. Windows service mode requires SID lookup (DD-13).

### DD-13: SID lookup with strict fallback (TCP + UDP)
On Windows service mode, to determine which user owns a proxy connection:
1. `GetExtendedTcpTable` (or `GetExtendedUdpTable`) → PID from source port
2. `OpenProcess` → `OpenProcessToken` → `GetTokenInformation(TokenUser)` → SID
3. `SHGetKnownFolderPath(FOLDERID_LocalAppData, SID)` → per-user vault path
4. PID→SID mapping cached in in-memory LRU (TTL: connection lifetime)
5. **Fallback: DENY**. If the lookup fails (race, AV blocking, service account → no user profile), close the connection. Do not fall back to machine-level vault. No silent degradation.

### DD-14: Config — minimal
```yaml
agent:
  vault:
    ttl: 168h   # 24h, 168h (7 days, default), 0 = infinite
```
Encryption is mandatory. Paths are auto-detected. No toggle to disable encryption.

### DD-15: Startup and shutdown sequence
```
Startup:
  1. Determine vaukt path (per-user, os-specific)
  2. Create crypto.New(path + "/vault.key")    — or open existing
  3. bolt.Open(path + "/vault.db", 0600, ...)  — Timeout: 1s, NoSync: false
  4. vault.New(db, crypto, config.TTL)
  5. go vault.Run(ctx)                         — background async writer
  6. Wire vault.AsPersister() into proxy       — Tokenizer gets persister
  7. proxy.ListenAndServe()

Shutdown (signal → 30s graceful):
  1. proxy.Shutdown()          — stop accepting new connections
  2. vault.Close()             — drain async channel, commit pending, close bbolt
  3. log.Info("shutdown ok")
  4. os.Exit(0)
```

## Acceptance Criteria

### AC-1: Vault store and retrieve (happy path)
Given a vault with a conversation scope (provider + UUID), when a PII token is persisted, then the raw value is NOT visible in the bbolt file on disk, and the token can be retrieved in a subsequent session.

### AC-2: bbolt file is encrypted at rest
Given a vault at rest (process not running), when an attacker reads `vault.db` and `vault.key`, then the token values in bbolt are AES-256-GCM ciphertext. Metadata keys (provider, UUID, token type) are plaintext. `vault.key` has mode 0600 or stricter.

### AC-3: TTL enforcement
Given a vault with `ttl: 24h` and a conversation created 25 hours ago, then:
- **Startup sweep** purges it on agent start.
- **Background sweeper** purges it within 4 hours of expiry.
- **Access-time check** purges it if the conversation is re-accessed after expiry.
All entries and `__meta__` are deleted. No residual data. Sweeper logs `"vault sweep: purged N expired conversations"` at INFO level (PII-free).

### AC-4: Per-user isolation on Windows
Given two Windows users (Alice and Bob) both using Qindu via the same service, when Alice browses ChatGPT and Bob browses Claude, then Alice's tokens are stored in `C:\Users\Alice\AppData\Local\Qindu\vault.db` and Bob's in `C:\Users\Bob\AppData\Local\Qindu\vault.db`. Each has their own `vault.key`. No cross-contamination.

### AC-5: SID lookup fail → deny
Given a Windows service mode where the SID lookup fails (process exited, AV blocked), when a connection arrives, then the connection is closed with a logged WARNING (PII-free). No fallback to machine-level vault.

### AC-6: Async writes do not block the proxy
Given a proxy handling 100 requests/second with PII tokens, when tokens are persisted, then the proxy's request latency does not increase by more than 1ms at p99 compared to memory-only mode. (Vault writes are fire-and-forget channel sends.)

### AC-7: Graceful shutdown drains the queue
Given a running vault with pending writes in the async channel, when SIGTERM/SIGINT is received, then all pending writes are committed to bbolt before `bolt.DB.Close()` returns. Logged: count of entries flushed.

### AC-8: Config validation
Given invalid TTL values (negative, "15x", "-5h"), when the agent starts, then a clear error message is logged and the agent refuses to start. Valid: `0`, `24h`, `168h`, `720h`. Default: `168h`.

### AC-9: TokenPersister is optional
Given a Tokenizer created WITHOUT a persister (nil), when tokens are assigned, then the Tokenizer operates identically to QINDU-0006 behavior — no vault writes, no errors, no panics. All existing tests pass.

### AC-10: internal/crypto operates cross-platform
Given `internal/crypto` built on Windows, Linux, and macOS, then `Encrypt`/`Decrypt` produce identical ciphertext formats on all platforms, and cross-compilation succeeds (`GOOS=windows/linux/darwin`).

### AC-11: No PII in logs
Given any vault operation (open, close, write, read, expire, error), then no log message contains a PII value, token value, or partial plaintext. All logs use `pii_values_logged: false`. ADR-008 compliant.

### AC-12: bbolt schema correctness
Given a vault with multiple conversations and providers, then the key structure is consistent: `{provider}/{uuid}/{__meta__|token}`. No duplicate `__meta__` keys. `uuid` is a valid version-4 UUID. Provider names are lowercase.

### AC-13: Metadata integrity
Given a conversation with 3 persisted tokens, then `__meta__.pii_count == 3` and `__meta__.pii_types` contains exactly the types detected. `updated_at` is bumped on each additional token write.

### AC-14: SBOM update
Given `go.mod` after implementation, then `go.etcd.io/bbolt` is a direct dependency. No new indirect dependencies beyond `golang.org/x/sync`. `go.sum` entries are verifiable.

### AC-15: Race-free concurrent access
Given a vault with multiple concurrent `Persist()` calls from different goroutines, then `go test -race` passes with zero data races on the vault package.

### AC-16: SID cache prevents repeated lookups
Given the same PID making multiple connections within 60 seconds, then the Windows SID lookup is performed exactly once (first connection), and all subsequent connections reuse the cached PID→SID mapping from the in-memory LRU.

## Architecture Impact

### New packages
```
internal/
├── crypto/
│   ├── crypto.go         (public API: New, Encrypt, Decrypt)
│   └── crypto_test.go
├── vault/
│   ├── vault.go          (bbolt-backed vault, TokenPersister impl)
│   ├── meta.go           (metadata schema, JSON marshal/unmarshal)
│   ├── ttl.go            (TTL enforcement, lazy purge)
│   └── vault_test.go
└── session/
    ├── lookup.go         (interface: ResolveUser(path) → vaultPath)
    ├── lookup_windows.go (TCP + UDP tables, SID resolution, LRU cache)
    ├── lookup_other.go   (os.Getenv HOME/XGD — trivial)
    └── lookup_test.go
```

### Modified packages
```
internal/tokenize/
├── tokenizer.go          (+ TokenPersister field, + WithPersister(), call in assignTokens)
└── tokenizer_test.go     (new tests for persister integration, nil persister path)

cmd/agent/main.go         (startup: crypto.New → vault.New → wire into proxy → shutdown)

configs/default.yaml      (+ agent.vault.ttl: 168h)
```

### Modified interface
```
TokenPersister ← new interface
  ├── Persist(Scope, token, value) error
  └── UpdateMeta(Scope, Metadata) error
```

## Risk Assessment

| Risk | Severity | Mitigation |
|------|----------|------------|
| SID lookup fails under AV | Medium | LRU cache reduces window; deny on failure is safe default |
| bbolt corruption on kill -9 | Low | bbolt is crash-safe (WAL/MMAP); NoSync: false on Windows |
| AES-GCM nonce reuse across writes | Critical | Random nonce (`crypto/rand`), 12 bytes, included in ciphertext prefix |
| PII in bbolt keys (token type) | None | Keys are type identifiers (`<<EMAIL_1>>`), not PII values |
| Linux `memlock` interaction | Low | Vault is disk-backed, independent of `memlock_linux.go` arena |

## Dependencies
- QINDU-0006: `internal/tokenize.Store` and `Tokenizer` (extended with persister)
- QINDU-0001: `cmd/agent/main.go` (startup/shutdown hooks)
- QINDU-0005: `internal/pii.Engine` (unchanged, Tokenizer already depends on it)

## Forbidden
- PII in logs, PII in plaintext on disk
- Cloud sync, remote storage, network calls
- Modifying ADR-003, ADR-004, ADR-008
- Modifying `internal/tls/ca_windows.go` (CA stays DPAPI)
- User accounts, authentication, login UI
- CGO dependencies
