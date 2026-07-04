# CISO Security Requirements — QINDU-0008: Vault local chiffré

- **Sprint**: QINDU-0008
- **Reviewer**: qindu-ciso
- **Date**: 2026-07-04
- **Status**: Design-mode review
- **References**: ADR-003, ADR-004, ADR-008, ADR-009

---

## 1. Attack Surface (New or Modified)

| Surface | Type | Impact |
|---|---|---|
| `internal/crypto` — AES-256-GCM encrypt/decrypt path | New | KEY, PII |
| `vault.key` file on disk (0600) | New | KEY |
| `vault.db` (bbolt file) on disk | New | PII (ciphertext), metadata (plaintext) |
| Async write channel (goroutine + buffered chan) | New | DoS, data loss |
| Windows SID lookup (TCP/UDP tables, OpenProcess, OpenProcessToken) | New | Information disclosure, privilege escalation (race) |
| PID→SID LRU cache (in-memory) | New | Memory exhaustion |
| TokenPersister interface injection into Tokenizer | Modified | PII data flow extension |
| `agent.vault.ttl` config field | New | Config injection |
| bbolt DB file lock acquisition (Timeout: 1s) | New | DoS (startup hang) |

---

## 2. Protected Assets

| Asset | Sensitivity | Storage | Protection |
|---|---|---|---|
| PII values (email, phone, IBAN, CC, JWT, name, secrets, private keys) | **Critical** | Memory (locked arena), bbolt (ciphertext) | AES-256-GCM at rest; mlock in memory |
| AES-256 key (32 bytes) | **Critical** | `vault.key` file (0600), memory | File permissions; crypto/rand generation |
| GCM nonces (12 bytes, per-encrypt) | **High** | Prepended to ciphertext | crypto/rand; never reused |
| bbolt metadata (provider, timestamps, PII types/counts) | **Low** | `vault.db` plaintext keys | By design; no PII in metadata |
| Windows user SID | **Medium** | Memory (LRU cache) | Cache TTL; deny on lookup failure |
| Config TTL value | **Low** | `configs/default.yaml` | Validation at startup |

---

## 3. Threat Model (STRIDE per component)

### 3.1 `internal/crypto` — AES-256-GCM

| Threat | STRIDE | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| GCM nonce reuse (same nonce, same key) | T | Low | **Critical** — complete loss of confidentiality and authenticity for all messages with that nonce | Enforce `crypto/rand.Read()` per Encrypt call; never use deterministic/counter nonces; test for nonce uniqueness |
| Weak key material (non-cryptographic RNG) | T | Low | **Critical** | `crypto/rand.Read()` for key generation; validate key length == 32 before use |
| Key read from `vault.key` by unauthorized local user | I | Medium | **High** | `os.Chmod 0600` on Unix; equivalent restrictive ACL on Windows (`owner: R/W, SYSTEM: R/W, everyone else: DENY`); verify in test |
| Key file truncated/corrupted on disk | T | Low | Medium | Validate `len(key) == 32` on load; regenerate with warning if invalid |
| Timeless decryption oracle (padding oracle via GCM auth tag) | T | Very Low | Low | GCM auth tag is verified before any plaintext is returned; no padding oracles by construction |
| Side-channel via AES-NI timing | I | Very Low | Low | AES-NI is constant-time in hardware; Go stdlib uses hardware acceleration correctly |

### 3.2 bbolt persistence (`vault.db`)

| Threat | STRIDE | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| `vault.db` read by attacker with disk access | I | Medium | **Medium** — values are AES-GCM ciphertext; metadata (provider, timestamps, PII types) is plaintext | Acceptable per DD-4; metadata exposure is documented residual risk |
| bbolt WAL/journal corruption on crash (power loss, kill -9) | T | Low | **Low** | bbolt is crash-safe (MVCC + write-ahead log); `NoSync: false` ensures fsync on commit |
| bbolt file lock contention — second process instance | D | Low | **Medium** — startup blocks for `Timeout: 1s`, then fails | Log clear error; agent refuses to start; never silently fall back to memory-only mode |
| bbolt DB grow unbounded (no TTL enforcement) | D | Low | **Medium** — disk exhaustion | TTL lazy enforcement executed at startup (walk all conversations); periodic background sweep recommended for V2 |
| Malicious bbolt file — crafted db file with extreme bucket counts or key sizes | T | Low | **Medium** | bbolt has built-in mmap bounds checking; additionally, validate on open: `db.Stats().FreeAlloc < maxDBSize`; configurable `max_db_size_mb: 500` (soft cap) |

### 3.3 Async write channel

| Threat | STRIDE | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| Channel overflow — producer faster than consumer (bbolt write latency) | D | Medium | **High** — AC-6 violation if proxy goroutine blocks | **CRITICAL**: Define buffer size (≥ 1024) and overflow behavior explicitly. Two acceptable designs: (a) buffered channel with non-blocking send + drop on full (log WARNING, drop metric), preserving AC-6; (b) unbounded in-memory queue (linked list) — acceptable but risks OOM. **Blocking send is FORBIDDEN** (violates AC-6). |
| Data loss — async writes not committed before process exit | D | Medium | **Medium** | Graceful shutdown (DD-15): drain channel, commit pending, then Close(). Acceptable: crash-kill data loss (MemoryStore is source of truth). |
| Goroutine leak — background writer never exits | D | Low | Medium | Context cancellation via `ctx.Done()`; shutdown sequence: cancel ctx → drain channel → bbolt.Close() |
| Unordered/duplicate writes | T | Low | Low | bbolt transactions are serialised per bucket; `Persist` is idempotent per (provider, uuid, token) key |

### 3.4 Windows SID lookup + LRU cache (`internal/session`)

| Threat | STRIDE | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| PID reuse race (TOCTOU): PID from TCP table reassigned to different process before OpenProcess | S | Low | **High** — wrong user's vault accessed | OpenProcess → verify process image name matches expected browser; if mismatch, deny. Accept that rapid PID reuse is rare on Windows (PIDs increment, wrapping takes ~4M allocations). |
| OpenProcess ACCESS_DENIED (service lacks PROCESS_QUERY_INFORMATION) | D | Low | **Medium** — all connections denied | Fallback: DENY (DD-13). Service must run with sufficient privilege. Document required privileges. |
| LRU cache unbounded growth — long-running service, many short-lived PIDs | D | Medium | **Medium** — memory exhaustion | **MUST**: LRU cache must have a max size (e.g., 10000 entries). Evict least-recently-used. 10k entries × ~200 bytes = ~2 MB — acceptable. Without bound, a DoS via rapid PID churn is possible. |
| SID cache poisoning — attacker injects fake PID→SID mapping | T | Very Low | High | Cache is in-memory only, populated exclusively from trusted WinAPI calls (GetExtendedTcpTable + OpenProcessToken). No network input into cache. Attack surface is local kernel integrity — out of scope. |
| DNS/hostname resolution in SID lookup path | I | N/A | None | No network calls in SID lookup; purely local WinAPI |
| Fallback at machine-level vault if SID lookup fails | E | Medium | **Critical** — cross-user data leak | **FORBIDDEN** (per DD-13). The story explicitly requires DENY on failure. **Any fallback to machine-level vault is a blocking defect.** |

### 3.5 TokenPersister interface injection

| Threat | STRIDE | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| PII passed to Persister logged or leaked | I | Low | **Critical** | Interface contract: `Persist(scope, token, value)` — value is `[]byte`. Implementer MUST encrypt before write. No logging of value. ADR-008: `pii_values_logged: false`. |
| Tokenizer persists before MemoryStore.Map completes | T | Low | Medium | Persist is called AFTER Map (synchronous). Ordering: Map → Persist. If Persist fails, Map already succeeded — proxy works, vault incomplete. Acceptable. |
| Malicious Persister implementation injected in tests | T | N/A | N/A | No production impact; test-only risk |

### 3.6 Config: `agent.vault.ttl`

| Threat | STRIDE | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| TTL = 0 (infinite) leads to unbounded disk growth | D | Medium | **Medium** | Document the risk; recommend `max_db_size_mb` soft cap; periodic sweep in V2 |
| Invalid TTL string accepted (negative, malformed) | T | Low | **Low** | Validate at startup: regex `^(0|[1-9][0-9]*h)$`. Reject on invalid. AC-8 covers this. |
| TTL validation bypass via config load | T | Low | Medium | Config is loaded once at startup from trusted local file (0600). File write requires local admin. |

---

## 4. Blocking Security Requirements (SR-8xx)

These MUST be satisfied before this story can PASS. Violations are blocking.

### SR-801: Non-reuse guarantee for GCM nonces (Critical)

Each call to `Encrypt()` MUST generate a fresh 12-byte nonce via `crypto/rand.Read()`. The nonce MUST be prepended to the ciphertext and extracted on `Decrypt()`. No counter-based, time-based, or deterministic nonce generation is permitted. The implementation MUST include a test that encrypts 10,000 values and verifies all nonces are unique.

**OWASP ASVS**: V6.2.5 (Cryptographic nonces shall be uniquely generated per message)

### SR-802: Async channel overflow MUST NOT block proxy (Critical)

The async write channel from `Persist()` to the background bbolt writer MUST use either:
- (a) A buffered channel of at least capacity 1024 with **non-blocking send** (`select` with `default`), dropping writes on full and logging a WARNING (PII-free) with a `dropped_writes` counter, OR
- (b) An unbounded in-memory queue (e.g., linked list) with a high-water-mark WARNING.

A plain buffered channel `make(chan WriteOp, 1024)` with a blocking `ch <- op` send is **FORBIDDEN** — it violates AC-6 and creates a back-pressure path from bbolt write latency into the proxy's request handling goroutine.

**OWASP ASVS**: V11.1.3 (Verify the application does not become unresponsive under expected load)

### SR-803: LRU cache MUST have a maximum size bound (High)

The PID→SID LRU cache in `internal/session` MUST enforce a maximum entry count (recommended: 10,000). When the cache is full, the least-recently-used entry MUST be evicted before inserting a new one. Without this bound, a long-running Windows service handling connections from many short-lived PIDs (browser tab processes, Electron renderers) could exhaust memory.

**OWASP ASVS**: V11.1.2 (Verify the application limits resource consumption)

### SR-804: vault.key permissions MUST be platform-appropriate (High)

On Unix (Linux/macOS): `vault.key` MUST be created with mode `0600` via `os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0600)`. The permissions MUST be verified before use: if the file has broader permissions, the agent MUST log an ERROR and refuse to start.

On Windows: The file MUST be created with an ACL granting `READ_DATA | WRITE_DATA` to the owner SID and `SYSTEM` only; `Everyone` must be explicitly DENY'd. The implementation MUST test this in `vault_test.go` (Windows build tag). If ACL setting fails, log ERROR and refuse to start.

**OWASP ASVS**: V4.3.2 (Verify that sensitive data stored on the device is encrypted using hardware-backed or OS-managed key storage with appropriate access controls)

### SR-805: SID lookup failure MUST deny connection (High)

If the PID→SID resolution fails for any reason, the connection MUST be closed with a PII-free WARNING log. There MUST be no fallback to:
- A machine-level vault path (`C:\ProgramData\Qindu\vault.db`)
- A default user vault path
- Memory-only mode (different behavior for SID-failed connections vs normal)

The codepath for SID lookup failure MUST be tested (unit + integration on Windows).

### SR-806: Shutdown drain MUST respect hard deadline (Medium)

The `vault.Close()` method MUST drain the async channel and complete all pending bbolt writes. If this takes longer than the remaining time in the 30-second graceful shutdown window, the agent MUST log an ERROR (PII-free) and proceed to `bbolt.Close()`. The agent MUST NOT hang indefinitely on shutdown.

Implementation: `vault.Close(ctx context.Context) error` — if `ctx.Done()` fires, signal the background goroutine to stop draining, then call `bbolt.Close()`.

### SR-807: No PII in any log message (Critical)

Every log statement in `internal/crypto`, `internal/vault`, and `internal/session` MUST comply with ADR-008. Specifically:
- No PII values, tokens, or partial plaintext in any log message at any level
- All operational logs that involve PII processing MUST include `"pii_values_logged", false`
- Log keys MUST use provider names, conversation UUIDs (proxy-generated, not real), and token types (e.g., `"EMAIL"`) — never PII values
- Metadata logs (pii_count, pii_types, created_at) are permitted per DD-4

**OWASP ASVS**: V7.1.2 (Verify that the application does not log sensitive data)

### SR-808: bbolt DB MUST be opened with restrictive permissions (Medium)

`bolt.Open(path, 0600, ...)` — the file mode `0600` ensures only the owner can read the database file. On Windows, this maps to owner-only access via the file's ACL. The test suite MUST verify that when `vault.db` is opened, the file permissions are `0600` on Unix or owner+SYSTEM-only on Windows.

### SR-809: Decrypted PII in vault reads MUST NOT leak to logs or unchecked buffers (Medium)

When the vault decrypts values for reads (future UI, QINDU-0016), the decrypted plaintext MUST:
- Be returned directly to the caller without intermediate logging
- Not be cached in unencrypted form outside MemoryStore's locked arena
- Be zeroed if buffered temporarily (use `[]byte` with explicit zeroing, or rely on GC)

For this sprint (write-only vault), this is forward-looking. The `Decrypt` function must already return `[]byte` (not `string`) to facilitate zeroing in future sprints.

### SR-810: crypto/rand MUST be the sole entropy source (Critical)

Key generation (`vault.key`): MUST use `crypto/rand.Read()` (32 bytes).
Nonce generation (per `Encrypt`): MUST use `crypto/rand.Read()` (12 bytes).
UUID generation (DD-8): MUST use `crypto/rand.Read()` (16 bytes, formatted as UUIDv4).

No fallback to `math/rand`, `time.Now()`, PID, or any other weak source. The implementation MUST NOT attempt to seed or reseed `crypto/rand`.

**OWASP ASVS**: V6.2.1 (Verify that all random numbers are generated using a cryptographically secure random number generator)

---

## 5. Mandatory Security Tests

| ID | Test | Package | Verifies |
|---|---|---|---|
| T-801 | `TestNonceUniqueness` — encrypt 10,000 random values, collect all nonces, verify `len(unique(nonces)) == 10000` | `internal/crypto` | SR-801 |
| T-802 | `TestEncryptDecryptRoundtrip` — encrypt then decrypt, verify plaintext match; tamper with ciphertext, verify decryption fails (auth tag) | `internal/crypto` | SR-801 |
| T-803 | `TestAsyncChannelNonBlocking` — create vault with buffer=1, send 3 writes without consumer, verify no goroutine blocks (use `goroutine` leak detector or timeout) | `internal/vault` | SR-802 |
| T-804 | `TestLRUCacheMaxSize` — insert 20001 entries into cache with maxSize=10000, verify count ≤ 10000, verify oldest entries evicted | `internal/session` | SR-803 |
| T-805 | `TestVaultKeyFilePermissions` — create vault, verify `vault.key` mode is exactly `0600` (Unix) or owner+SYSTEM ACL (Windows) | `internal/crypto` | SR-804 |
| T-806 | `TestVaultKeyFilePermissionsRejectWide` — create `vault.key` with 0644 manually, verify `crypto.New()` returns error | `internal/crypto` | SR-804 |
| T-807 | `TestSIDLookupFailDeny` — mock SID lookup to return error, verify `ResolveUser()` returns error, caller closes connection | `internal/session` | SR-805 |
| T-808 | `TestShutdownDrainWithDeadline` — start vault, enqueue 100 writes, call `Close()` with 10ms deadline, verify bbolt is closed (no hang) | `internal/vault` | SR-806 |
| T-809 | `TestNoPIIInLogs` — grep all log output from crypto, vault, session packages for known PII patterns (email regex, IBAN); verify zero matches | all new packages | SR-807 |
| T-810 | `TestBoltDBFilePermissions` — open vault, verify `vault.db` file mode is `0600` (Unix) or owner+SYSTEM ACL (Windows) | `internal/vault` | SR-808 |
| T-811 | `TestVaultDBOpenTimeout` — open bbolt in another process, attempt to open again, verify error returned within `Timeout + 500ms` | `internal/vault` | SR-808 |
| T-812 | `TestKeyGenerationEntropy` — generate 100 keys, verify all are unique, verify each is 32 bytes | `internal/crypto` | SR-810 |
| T-813 | `TestUUIDv4Format` — generate 1000 UUIDs, verify all match v4 format (version nibble == 4, variant bits correct) | `internal/vault` (or shared util) | SR-810 |
| T-814 | `TestRaceFreeConcurrentPersist` — `go test -race` on vault with 50 concurrent goroutines calling Persist; zero data races (AC-15) | `internal/vault` | AC-15 |
| T-815 | `TestConfigTTLValidation` — test valid values (0, 24h, 168h, 720h), reject invalid (negative, -5h, 15x, empty, "abc") | `cmd/agent` (config) | AC-8 |

---

## 6. Residual Risks

| Risk | Severity | Rationale for Acceptance |
|---|---|---|
| **Metadata in plaintext in bbolt** (provider names, timestamps, PII type counts, per-conversation structure) | **Medium** | Accepted per DD-4. An attacker with disk access learns conversation structure but not PII content. Mitigated by: 0600 file permissions, per-user vault isolation, localhost-only deployment. For V2, consider encrypting metadata too. |
| **AES key in un-mlocked memory** | **Low** | The 32-byte key is not placed in locked memory (unlike PII values in MemoryStore's arena). On Linux without mlockall, the key could be swapped. Accepted because: (a) the key must be in memory continuously for encrypt/decrypt operations; (b) key compromise requires local privilege escalation; (c) mlock for key material is a V2 enhancement. |
| **Random nonce collision over very high volumes** | **Very Low** | AES-GCM with 96-bit random nonces: ~2^48 encryptions before 50% collision probability (birthday bound). At 1000 writes/second, this takes ~2.8 million years. For a local vault, negligible. |
| **bbolt file size unbounded with TTL=0** | **Low** | Documented risk. `TTL=0` (infinite) is an explicit user choice. Future V2 features: max DB size soft cap, manual purge via UI. |
| **PID reuse race in SID lookup** | **Very Low** | Windows PID counter wraps at ~4 million. Browser processes are long-lived (each tab is a renderer process). Race window between `GetExtendedTcpTable` and `OpenProcess` is microseconds. Even if PID reuse occurs, the new process must be a browser connecting through the proxy — extremely unlikely. Fallback: DENY on any mismatch. |
| **Hot key file manipulation** (attacker replaces `vault.key` while agent is running) | **Low** | Agent holds the key in memory at startup. On-disk changes don't affect the running instance until restart. At restart, if key was replaced, old ciphertext becomes unreadable — availability impact only (denial-of-service). The attacker would need write access to `%LOCALAPPDATA%` which implies they are already the user. |
| **Cross-platform chmod 0600 on Windows** | **Low** | Go's `os.Chmod(0600)` on Windows sets the read-only attribute, which is not equivalent to Unix 0600. The Windows ACL implementation (SR-804) must explicitly set owner+SYSTEM ACEs. Risk: if the Windows ACL code is skipped/incorrect, `vault.key` may be readable by other users. Mitigated by `vault_test.go` with Windows build tag testing actual ACLs. |

---

## 7. ADR Compliance Assessment

| ADR | Requirement | Impact | Status |
|---|---|---|---|
| ADR-003 (TLS/CA) | CA stays on DPAPI, vault gets separate AES key | CA is untouched. `vault.key` is separate from CA keys. | ✅ Compliant |
| ADR-004 (Interceptor) | Interceptor interface unchanged | `TokenPersister` is a new interface injected into Tokenizer, not the Interceptor chain. No ADR-004 modification. | ✅ Compliant |
| ADR-008 (Logging) | Zero PII in logs, `pii_values_logged: false` | SR-807 enforces this. All new log statements must comply. | ✅ Must verify |
| ADR-001 (Project structure) | New `internal/` packages | `internal/crypto`, `internal/vault`, `internal/session` all within `internal/`. | ✅ Compliant |
| ADR-005 (Config) | Static YAML, read at startup only | `agent.vault.ttl` added to `default.yaml`. Validated at startup. | ✅ Compliant |
| ADR-009 (Concurrency) | Goroutine per connection, context propagation | Vault async writer is a separate goroutine; context propagated for shutdown. | ✅ Compliant |

No ADR modifications are required by this story. All ADRs are respected.

---

## 8. Dependency Security Review

| Dependency | Version | Origin | Risk |
|---|---|---|---|
| `go.etcd.io/bbolt` | v1.5.0 | CNCF-graduated, well-audited | **Low**. Go stdlib for crypto (no external crypto deps). bbolt is widely used (etcd, Kubernetes). v1.5.0 is the latest release (as of 2026). |
| `golang.org/x/sync` | (transitive, via bbolt) | Go team, reviewed | **Very Low**. Only `errgroup` used by bbolt for internal goroutine management. |

SBOM impact: 2 direct deps (bbolt + x/sync). Acceptable. No CGO, no dynamic linking, no new attack surface from dependency tree.

---

## 9. Verdict

**PASS** — with binding requirements.

The architectural design is sound and respects all ADRs. The separation of the vault's AES key from the CA's DPAPI key is clean. The use of stdlib `crypto/*` packages and bbolt (CNCF-graduated) limits dependency risk. The per-user vault isolation model with DENY-on-failure fallback correctly prevents cross-user data leakage.

However, **three design decisions must be clarified before implementation begins**:

1. **Async channel overflow behavior** (SR-802): The story states the channel is "buffered" but does not specify the overflow strategy. A blocking send would violate AC-6 and create an unacceptable back-pressure path from disk I/O to proxy latency.

2. **LRU cache size bound** (SR-803): The story mentions an "in-memory LRU" but does not specify a maximum size. Without a bound, a long-running service on a multi-user machine could suffer memory exhaustion.

3. **Windows ACL for vault.key** (SR-804): Go's `os.Chmod(0600)` on Windows does not guarantee the same protection as Unix 0600. The implementation must use Windows ACL APIs (`golang.org/x/sys/windows`) to restrict access to owner + SYSTEM only.

These three items are **non-negotiable** and must be addressed in `dev-notes.md` upon implementation, with corresponding tests (T-803, T-804, T-805/T-806).

### Post-Implementation Review Checklist

The following will be verified during Review Mode (`ciso-review.md`):

- [ ] All 15 mandatory security tests pass (T-801 through T-815)
- [ ] `go test -race ./internal/crypto ./internal/vault ./internal/session` passes
- [ ] `go vet ./...` passes on new packages
- [ ] `grep -r "pii_values_logged.*true" internal/crypto internal/vault internal/session` returns empty
- [ ] No PII patterns (email regex, IBAN regex) found in test data strings used outside test assertions
- [ ] `vault.key` is absent from `.gitignore` exceptions (must NOT be committed)
- [ ] `vault.db` and `*.db` are in `.gitignore` (must NOT be committed)
- [ ] bbolt `Timeout` is honored: test that concurrent open fails within expected time
- [ ] Graceful shutdown test: `kill -TERM` (Unix) or `Stop-Service` (Windows), verify bbolt file is consistent after shutdown
- [ ] Config TTL validation rejects edge cases: `"Infinity"`, `"NaN"`, `""`, `"12h30m"`, overflow values

---

## Appendix A: Cryptographic Material Lifecycle

```
Startup:
  crypto.New(vaultKeyPath)
    ├── Does vault.key exist?
    │   ├── YES → os.ReadFile → validate len(key) == 32 → load into memory
    │   └── NO  → crypto/rand.Read(32) → os.WriteFile(vaultKeyPath, key, 0600)
    │                                         └── Windows: SetSecurityInfo(owner+SYSTEM only)
    └── Return *Service{key: []byte}

Per-encrypt (for each vault write):
  nonce := make([]byte, 12)
  crypto/rand.Read(nonce)
  ciphertext := aesGCM.Seal(nil, nonce, plaintext, nil)  // nil = no additional data
  return append(nonce, ciphertext...)                     // prepend nonce

Per-decrypt (for each vault read):
  nonce := ciphertext[:12]
  data  := ciphertext[12:]
  plaintext, err := aesGCM.Open(nil, nonce, data, nil)   // nil = no additional data
  if err != nil → auth failure, return error (tampered data)

Shutdown:
  vault.Close(ctx)
    ├── close(asyncWriteChannel)     // signal no more writes
    ├── drain remaining writes       // background goroutine commits to bbolt
    ├── if ctx.Done() → stop drain  // respect hard deadline
    ├── bbolt.Close()                // fsync + close file
    └── zero crypto.Service.key      // explicit clear from memory (defense-in-depth)
```

---

## Appendix B: Windows SID Lookup Flow with Threat Mitigations

```
Connection arrives at proxy (localhost:8787)
  │
  ├── GetExtendedTcpTable() → find local port → get PID
  │   Threat: PID already exited between table read and OpenProcess
  │
  ├── Check LRU cache for PID→SID mapping
  │   ├── HIT  → use cached SID (within TTL)
  │   └── MISS → proceed
  │
  ├── OpenProcess(PID, PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ)
  │   Threat: PID reused by different process → verify image name
  │   ├── FAIL (ACCESS_DENIED) → DENY connection (log WARNING, no PII)  ← SR-805
  │   └── OK
  │
  ├── Verify process image name (optional defense-in-depth)
  │   ├── GetProcessImageFileName → verify it's a known browser
  │   └── MISMATCH → DENY connection
  │
  ├── OpenProcessToken → GetTokenInformation(TokenUser) → SID
  │   └── FAIL → DENY connection
  │
  ├── SHGetKnownFolderPath(FOLDERID_LocalAppData, SID) → user vault path
  │   └── FAIL → DENY connection  ← NO fallback to machine-level vault!
  │
  ├── Cache PID→SID with LRU eviction (max 10000 entries)
  │
  └── Return user-specific vault path
```

---

*End of CISO requirements for QINDU-0008.*
