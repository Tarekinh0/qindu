# DPO Requirements — QINDU-0008: Vault local chiffré

**Author**: Qindu DPO (Data Protection Officer)
**Review stage**: Design Mode
**Sprint**: QINDU-0008 — Vault local chiffré
**Date**: 2026-07-04
**ADR refs**: ADR-003, ADR-004, ADR-008

---

## 1. Story Summary

QINDU-0008 introduces **persistent, encrypted, per-user vault storage** for token↔PII mappings. Until now (QINDU-0006), the token→PII mapping has been volatile — stored only in process memory, destroyed on termination. The vault adds:

- **AES-256-GCM encryption** via `internal/crypto` — pure Go stdlib, cross-platform, no CGO, no DPAPI dependency. A 32-byte random key stored in `vault.key` (mode 0600) protects the vault at rest.
- **bbolt** (`go.etcd.io/bbolt`) as the persistence backend — one `vault.db` file per user, crash-safe via WAL.
- **Per-conversation scoping** via a proxy-generated UUID (`crypto/rand`). Provider name + UUID form the bbolt key prefix.
- **7-day rolling TTL** (configurable: `24h`, `168h` default, `0` = infinite). Lazy enforcement: expired conversations are purged on access or at startup sweep.
- **Per-user isolation**: Windows SID lookup from TCP/UDP table → PID → process token; Linux/macOS via `$HOME`. No fallback on failure — connection denied.
- **Async writes**: `Map()` writes to the existing in-memory `MemoryStore` instantly, then fire-and-forget queues to a buffered channel. A background goroutine encrypts and commits to bbolt. The proxy thread never blocks on disk I/O.
- **Metadata in plaintext**: bbolt keys (`{provider}/{uuid}/{__meta__|token}`) and metadata JSON values are unencrypted — enabling prefix scans for TTL enforcement and future UI browsing without decrypting every value. PII values in bbolt values are always AES-256-GCM ciphertext.
- **Optional persister**: The `TokenPersister` interface is injected into the Tokenizer. If nil, the proxy operates in memory-only mode (unchanged behavior from QINDU-0006). The `Store` interface is untouched — the persister is a separate, parallel subscriber.

The vault enables conversation history to survive process restarts and power cycles, laying the foundation for QINDU-0013 (history rehydration) and QINDU-0016 (UI with conversation browser).

---

## 2. Data Processed — PII Categories

### 2.1 What the vault stores (encrypted)

All 8 entity types recognized by the PII engine (QINDU-0005) may be persisted:

| Entity Type | GDPR Classification | Stored In Vault? |
|---|---|---|
| `EMAIL` | Personal data (Art. 4(1)) — directly identifies | Yes (encrypted value) |
| `PHONE` | Personal data — directly identifies | Yes (encrypted value) |
| `IBAN` | Personal data — financial, sensitive | Yes (encrypted value) |
| `CREDIT_CARD` | Personal data — financial, highly sensitive | Yes (encrypted value) |
| `NAME` | Personal data — inferred from email local-part | Yes (encrypted value) |
| `JWT` | May contain personal data (claims: email, name, sub) | Yes (encrypted value) |
| `SECRET` | Security credential — may be linked to person's account | Yes (encrypted value) |
| `PRIVATE_KEY` | Authentication material — sensitive | Yes (encrypted value) |

Each entry maps a token string (`<<TYPE_N>>`) to its raw PII value. Both the token (key) and the PII value are stored — the token as a bbolt key, the PII value as encrypted bbolt value.

### 2.2 What the vault stores (plaintext / unencrypted)

Per conversation, a `__meta__` key stores:

| Field | Content | GDPR Sensitivity |
|---|---|---|
| `provider` | AI provider name (e.g., `"chatgpt"`, `"claude"`) | Low — reveals which service was used |
| `conversation_id` | Provider's real conversation ID (populated in QINDU-0011) | Low-Medium — correlates to provider-side records |
| `created_at` | Unix timestamp of conversation start | Low-Medium — reveals when the user was active |
| `updated_at` | Unix timestamp of most recent token write | Low-Medium — reveals activity pattern |
| `pii_count` | Total number of PII tokens in the conversation | Low — aggregate count |
| `pii_types` | Array of entity type strings (e.g., `["EMAIL", "IBAN"]`) | Low-Medium — reveals what categories of PII were shared |
| `status` | One of `active`, `expired`, `purged` | None |
| `label` | User-assigned label (future, QINDU-0011) | Low — user-generated metadata |

**Critical observation**: While none of these fields individually constitutes personal data under Art. 4(1), collectively they form a **metadata profile** of the user's AI usage: which providers, at what times, with what categories of personal data. This metadata is personal data processing information — it reveals facts about the data subject's behavior. The plaintext storage of metadata is a deliberate design choice (DD-4) justified by the need for efficient TTL enforcement and UI browsing. See Section 4 for minimization analysis.

### 2.3 Data NOT stored in the vault

- Conversation message text (prompts, responses) — never persisted, only passes through memory
- HTTP headers, cookies, session tokens
- User IP addresses
- Browser traffic beyond PII tokens
- User identifiers, machine identifiers, device fingerprints
- Log data (separate from vault, covered by ADR-008)

### 2.4 bbolt key structure

```
{provider}/{uuid}/__meta__           → JSON metadata (plaintext)
{provider}/{uuid}/<<EMAIL_1>>        → AES-256-GCM ciphertext
{provider}/{uuid}/<<PHONE_1>>        → AES-256-GCM ciphertext
...
```

The provider name and UUID in the key are plaintext. The token string (`<<TYPE_N>>`) is plaintext — it encodes only entity type and ordinal position, never PII values (SR-2 from QINDU-0006).

---

## 3. Purpose — Why This Processing Is Necessary

The vault serves **three lawful purposes**:

### 3.1 Conversation continuity (core product function)

Without persistence, every process restart amnesia-wipes the token→PII mapping. Conversations started before a restart would have their tokens unresolvable — the user would see raw `<<EMAIL_1>>` in their browser instead of their actual email address. The vault ensures that rehydration works across sessions, power cycles, and OS reboots. This is essential for the core user experience.

**Lawful basis**: The user (data subject) consents to local PII storage by using Qindu. Since Qindu operates exclusively on the user's machine with no external data controller, the consent model is implicit in the act of installing and running the software. PII never leaves the machine — the storage is self-hosted by the data subject.

### 3.2 Conversation history browsing (QINDU-0013, QINDU-0016)

Future sprints will provide a UI that lets users browse past conversations, inspect what PII was tokenized, and manually purge entries. The vault's metadata schema (`__meta__` keys) is designed to support this UI efficiently. Without the vault, the UI would have no data to display.

**Lawful basis**: Same as above — user-consented, local-only processing.

### 3.3 Data protection by default (Art. 25)

The vault's encryption-at-rest protects PII that persists on disk. This is a privacy upgrade over QINDU-0006, where in-memory PII was protected only by process isolation and OS memory protection (with memory locking via mmap+mlock where available). The vault extends protection to cover offline attack scenarios (disk access after process termination).

**Lawful basis**: Art. 25 requires appropriate technical measures. AES-256-GCM encryption with a separate key file is an appropriate measure for local data-at-rest protection.

---

## 4. Minimization Basis — Why Less Would Not Work

### 4.1 Why PII values must be stored at all

The alternative — never persisting PII values — would mean that after a process restart, all rehydration fails permanently. The user would see raw tokens everywhere. The only alternative to storing the PII value is to re-derive it from the original source text, which is not persisted either. The minimal necessary approach is to store exactly what is needed for rehydration: the token→PII mapping.

### 4.2 Why metadata is stored in plaintext (DD-4)

Encrypting metadata would prevent TTL enforcement without decrypting every conversation's `__meta__` entry. Since TTL enforcement runs at startup and on access (potentially across thousands of conversations in a long-running vault), decrypting all metadata on every sweep would impose significant I/O and CPU overhead. The metadata's sensitivity is low (provider names, timestamps, PII counts) — it does not contain PII values. The design trade-off (plaintext metadata for efficient operations vs. fully encrypted vault) is reasonable and proportionate.

However, metadata IS personal data processing information under GDPR. Users must be informed that their AI usage patterns are visible to anyone with disk access (DD-4: "An attacker with disk access sees conversation structure but not PII content"). This is captured in Requirement DPO-R14.

### 4.3 Why 7-day TTL is the default (not shorter)

A 24-hour TTL would be too aggressive — many users interact with AI services on a multi-day cadence. A weekend away would expire all conversation mappings, defeating the continuity purpose. A 7-day default covers a typical workweek plus weekend, providing reasonable continuity while ensuring stale data doesn't accumulate indefinitely.

The `24h` option caters to users with heightened privacy concerns (one-day retention). The `168h` default balances usability and privacy. These options are proportionate.

### 4.4 Why per-conversation TTL (not per-entry TTL)

Per-entry TTL would create inconsistent rehydration: some tokens in a conversation would resolve while others wouldn't, producing garbled output. Conversations are the natural atomic unit — either you can rehydrate a conversation or you can't. Per-conversation TTL respects the conversational context while providing a clean, predictable retention model.

### 4.5 What is minimized

- Conversation text (prompts, responses) is **never persisted** — only the token→PII mapping
- PII values are **encrypted at rest** — the raw values are unreachable without the key
- Metadata is **limited** to provider, timestamps, PII types/counts — no content, no derivative data
- The vault is **scoped** to token→PII mappings only — it doesn't duplicate what the log system stores
- The `TokenPersister` is **optional** — the system operates identically without it (for users who prefer volatility)
- Configurable TTL ensures data doesn't live forever by default

---

## 5. Rights and Freedoms Risks

### 5.1 Risk: `ttl: 0` enables infinite PII retention (HIGH)

**Description**: The configuration option `agent.vault.ttl: 0` disables TTL entirely, storing PII indefinitely. While the user is the data subject and the data is on their own machine, indefinite storage of personal data violates the spirit of storage limitation (Art. 5(1)(e)) and data protection by default (Art. 25). There is no legitimate use case for storing token↔PII mappings forever — conversations older than a few months are unlikely to be revisited.

**DPO assessment**: The `ttl: 0` parameter is a latent privacy trap. Users may set it without understanding that their PII will persist forever on disk. While the default is 168h, offering an "infinite" option without warning is inconsistent with privacy by default.

**Mitigation**: See Requirement **DPO-R1**.

### 5.2 Risk: Lazy TTL enforcement leaves expired data on disk (MEDIUM)

**Description**: TTL enforcement is lazy — it runs at startup and on conversation access. If the proxy runs for weeks without restart and the user never accesses an expired conversation, that conversation's PII remains on disk in decryptable ciphertext. There is no background goroutine that periodically sweeps expired conversations. The user might believe TTL provides automatic cleanup; in practice, it provides cleanup-on-next-access only.

**DPO assessment**: This creates a gap between the user's expectation ("7 days and it's gone") and reality ("gone when I or the system next looks at it"). The difference could be significant: a conversation expired on day 7 might not be accessed until day 30 (or never), leaving PII on disk for 23 extra days.

**Mitigation**: See Requirement **DPO-R2**.

### 5.3 Risk: No explicit data subject rights mechanism (HIGH)

**Description**: The vault provides no API for:
- **Deletion**: The user cannot delete a specific conversation, purge all expired conversations, or wipe the vault entirely — except by manually deleting `vault.db` + `vault.key` from the filesystem.
- **Access**: The user cannot enumerate what PII is stored, which conversations exist, or what entities were tokenized — until QINDU-0016 (UI) ships.
- **Rectification**: The user cannot correct or update PII values in the vault (though this is a niche need for token↔PII mappings).

Under GDPR Art. 17 (right to erasure) and Art. 15 (right of access), data subjects must be able to exercise their rights. While Qindu's local-only architecture changes the practical urgency (the data subject controls the machine), the software should provide mechanisms, not require filesystem surgery.

**DPO assessment**: This is partially mitigated by the fact that QINDU-0016 will provide UI-based management. However, between QINDU-0008 shipping and QINDU-0016 shipping, users have no software-assisted way to exercise their rights. This gap period must be documented, and the sprint must not hinder future rights mechanisms.

**Mitigation**: See Requirement **DPO-R3**.

### 5.4 Risk: `vault.key` and `vault.db` co-located — single point of compromise (MEDIUM)

**Description**: The AES key file (`vault.key`) and the encrypted database (`vault.db`) are stored in the same directory. An attacker with filesystem access to the user's profile directory can obtain both files and decrypt all PII. The encryption protects against offline attacks where the attacker has disk access but not filesystem access (e.g., a stolen hard drive where the OS enforces ACLs), and against casual inspection (a support technician who can list directory contents but not read 0600 files). It does NOT protect against an attacker who has the same OS-level access as the user.

**DPO assessment**: This is an inherent limitation of local encryption — the key must be accessible to the process that needs to decrypt. DPAPI (used for the CA key) provides slightly better protection because the key is bound to the user's Windows credentials and never stored as a raw file. However, DD-9 explicitly chooses AES with a key file over DPAPI for portability. This is a legitimate engineering trade-off, not a defect. The risk is accepted (backlog R-008).

The protection model should be clearly communicated: the vault protects against **offline disk access** (stolen drive, decommissioned machine, post-mortem forensics of the disk), not against **online compromise** (malware running as the user, an attacker with the user's login). This is consistent with the threat model of a local privacy proxy.

### 5.5 Risk: Metadata profile leakage (MEDIUM)

**Description**: The plaintext metadata in bbolt (provider names, timestamps, PII types/counts) reveals:
- Which AI providers the user uses
- Their usage schedule (timestamps)
- What categories of PII they share (EMAIL, PHONE, IBAN counts)
- How frequently they share PII

This is a behavioral fingerprint. Anyone with filesystem access to the vault directory can profile the user's AI usage patterns, even without the decryption key. This is acknowledged in DD-4: "An attacker with disk access sees conversation structure but not PII content."

**DPO assessment**: The metadata exposure is proportional to the operational need (TTL enforcement, UI browsing). The alternatives — encrypting metadata or not storing it — would sacrifice functionality that is central to the vault's purpose. The risk is mitigated by:
- Per-user filesystem ACLs (the vault is in the user's profile directory, which is private on modern OSes)
- TTL-based metadata expiration (old conversations + their metadata are purged together)
- No network exfiltration path (the vault is local-only)

However, users should be aware that their AI usage patterns are visible on their filesystem. See DPO-R14.

### 5.6 Risk: Async write loss on crash (LOW)

**Description**: DD-10 specifies fire-and-forget async writes via a buffered channel. If the process crashes (kill -9, power loss, OS crash) before the background goroutine drains the queue, the pending writes are lost. The vault will be incomplete for that conversation — some tokens persisted, others not.

**DPO assessment**: The `MemoryStore` is the live source of truth for rehydration during the current session. Lost vault writes only affect subsequent sessions (after restart). The worst case is: a conversation that was tokenized but not fully persisted → after restart, partial rehydration → some tokens resolve, others remain as `<<TYPE_N>>`. This is a correctness/UX issue, not a privacy leak — no PII is exposed, only tokens are left unresolved.

The risk is accepted. AC-7 (graceful shutdown drains the queue) mitigates the common case (SIGTERM/SIGINT). Kill -9 and power loss are edge cases that the "live source of truth" design handles gracefully.

### 5.7 Risk: Cross-user contamination on shared Windows machines (LOW)

**Description**: Two Windows users (Alice and Bob) sharing a machine, both using Qindu via the same service. The vault isolation depends on correct SID resolution (DD-13). If the SID lookup fails and the DENY fallback is incorrectly implemented (e.g., a bug that falls through to a machine-level path), Alice's PII could be stored in Bob's vault or vice versa.

**DPO assessment**: DD-13 explicitly mandates DENY on failure — no silent degradation. This is the correct privacy posture. The implementation must be rigorously tested (AC-4, AC-5). The risk is mitigated by the DENY rule and the LRU cache reducing SID lookup frequency.

### 5.8 Risk: AES-GCM nonce reuse (CRITICAL in crypto, LOW probability)

**Description**: AES-GCM fails catastrophically if a (key, nonce) pair is ever reused — the confidentiality of all messages encrypted with that key is compromised, and the authentication tag can be forged. The story's risk assessment correctly identifies this as Critical severity and mitigates it with `crypto/rand` for nonce generation.

**DPO assessment**: `crypto/rand` on all supported platforms reads from the OS CSPRNG (Linux: `getrandom(2)`, Windows: `BCryptGenRandom`, macOS: `SecRandomCopyBytes`). With a 96-bit nonce, the probability of collision is astronomically low (`~2^-96`). The mitigation is sound. The implementation must not introduce any non-deterministic or counter-based nonce scheme — always `crypto/rand`.

### 5.9 Risk: Windows service SID lookup requires elevated privileges (LOW — operational, not privacy)

**Description**: On Windows, `OpenProcess` + `OpenProcessToken` to retrieve a user's SID typically requires `SeDebugPrivilege` or the process to run as the same user. If the Qindu service runs as `SYSTEM`, it has the necessary privileges. If the service runs as a less-privileged account, SID resolution could fail for all connections, triggering DENY and making the vault unusable.

**DPO assessment**: This is an operational/deployment concern, not a privacy concern. The DENY-on-failure behavior (DD-13) is privacy-positive — it prevents data leaks to the wrong user. The deployment model (Windows service as SYSTEM) is already established by QINDU-0002. No privacy action required.

---

## 6. Blocking Points

### 6.1 DPO-B1 — `ttl: 0` (infinite retention) requires explicit safeguards (BLOCKING)

**Status**: BLOCKING unless mitigated.

**Issue**: Allowing `agent.vault.ttl: 0` for infinite PII retention without safeguards violates:
- Storage limitation (Art. 5(1)(e)): "kept … for no longer than is necessary"
- Data protection by default (Art. 25(2)): "by default, only personal data which are necessary for each specific purpose … are processed"

**Required mitigation** (any one of the following, or a combination):

1. **Remove `ttl: 0` entirely**: The maximum TTL should be bounded (e.g., `720h` / 30 days). If a user truly wants permanent storage, they can set a very long TTL and manually manage the vault. This is the strongest mitigation.

2. **Require explicit user acknowledgment**: If `ttl: 0` is configured, the agent MUST emit a WARNING-level log message at startup stating clearly that PII will be stored indefinitely and must be manually deleted. The message must not contain PII values. Additionally, the configuration documentation must flag `ttl: 0` as a privacy-sensitive option.

3. **Convert to opt-in via separate config key**: Instead of `ttl: 0` silently meaning "infinite," introduce a separate boolean `agent.vault.no_expiry: true` that must be explicitly set. The TTL field would then reject `0` (or treat it as default 168h). This makes the choice deliberate and visible.

If **none** of these mitigations is implemented, the sprint is BLOCKED on this issue.

### 6.2 DPO-B2 — Lazy TTL enforcement must include a background sweeper (BLOCKING)

**Status**: BLOCKING unless mitigated.

**Issue**: The story specifies startup sweep and access-time enforcement only. Without a periodic background sweeper, expired PII can remain on disk indefinitely if the conversations are never accessed and the process never restarts.

**Required mitigation**:

A background goroutine must periodically sweep expired conversations. Minimum requirements:
- **Interval**: Sweep every `min(ttl / 7, 24h)` — i.e., at least once per day, or proportionally more frequent for shorter TTLs. For the default 168h TTL, sweep at least every 24h.
- **Granularity**: The sweep scans `__meta__` keys (plaintext, efficient prefix scan), checks `now - created_at > ttl`, and purges expired conversation prefixes atomically.
- **Logging**: Each sweep logs a count of purged conversations at INFO level (expired conversations purged without PII values in the log). At DEBUG level, log the purged conversation UUIDs (UUIDs are not PII).
- **Graceful shutdown**: On SIGTERM/SIGINT, the sweeper goroutine is stopped via context cancellation.

**Alternative**: If a periodic sweeper is deemed too complex for this sprint, the startup sweep MUST be guaranteed to run on EVERY start (not just "at startup" as a side effect of bbolt open). But this is weaker — a 24/7 running proxy still wouldn't sweep expired data. The periodic sweeper is the correct solution.

If no periodic sweeper is implemented, the sprint is BLOCKED on this issue.

### 6.3 DPO-B3 — No test fixture containing real PII (BLOCKING if violated)

**Status**: Blocker at review time (not design time).

**Requirement**: All test data in `internal/crypto/crypto_test.go`, `internal/vault/vault_test.go`, and `internal/session/lookup_test.go` must use exclusively synthetic PII. This follows the same discipline as QINDU-0005 and QINDU-0006. Real PII in test code is a permanent, public data breach (git history is forever).

This is a review-gate requirement — it cannot block the design, but it blocks the sprint at the DPO review gate if violated.

---

## 7. Requirements for DevSecOps

### DPO-R1 — Infinite TTL safeguard (MANDATORY — see DPO-B1)

If `ttl: 0` is not removed:
- Log a WARNING at startup: `"vault TTL set to infinite — PII tokens will persist until manual deletion. See documentation."`
- The config validation code (AC-8) must accept `0` but emit the warning.
- Documentation must state that `ttl: 0` means "PII stored forever."
- Consider a separate config flag `agent.vault.no_expiry` as the explicit gate.

### DPO-R2 — Periodic TTL background sweeper (MANDATORY — see DPO-B2)

Implement a background goroutine (`vault.sweeperLoop`) that:
- Runs on a configurable interval (default: `min(ttl / 7, 24h)`, minimum 1h).
- Scans all `__meta__` keys evaluating `now - created_at > ttl`.
- Purges expired conversation prefixes in a single bbolt transaction.
- Logs `"vault: sweep completed"` with `purged_count` at INFO level. Individual purged UUIDs logged at DEBUG level (UUIDs are not PII).
- Is stoppable via context cancellation for graceful shutdown.
- Does NOT hold a long-lived bbolt transaction (scan, then batch-purge).

### DPO-R3 — Data subject rights: minimum viable API (MANDATORY)

The vault package must expose methods that support data subject rights, even if the UI (QINDU-0016) doesn't call them yet:

```go
// PurgeExpired removes all conversations where now - created_at > ttl.
// Returns the count of purged conversations.
func (v *Vault) PurgeExpired(ctx context.Context) (int, error)

// PurgeAll removes all conversations and metadata, effectively wiping the vault.
// The vault remains open and operational after this call.
func (v *Vault) PurgeAll(ctx context.Context) error

// ListConversations returns metadata for all active conversations.
// Does NOT decrypt or return PII values.
func (v *Vault) ListConversations(ctx context.Context) ([]ConversationMeta, error)

// DeleteConversation removes all entries for a specific conversation, including metadata.
func (v *Vault) DeleteConversation(ctx context.Context, scope Scope) error
```

`PurgeAll` is the critical one — it provides a software-based "wipe my data" command that users and future UIs can invoke. Without it, the only way to exercise the right to erasure is manual filesystem deletion.

These methods must be part of the vault's public API surface, tested, and documented. The `TokenPersister` interface does not need to change — these are vault-specific methods.

### DPO-R4 — Zero PII in logs (MANDATORY — standard for all Qindu sprints)

No log entry from `internal/crypto`, `internal/vault`, or `internal/session` may contain:
- Raw PII values (from `Entity.Value` or the vault)
- Token strings that map PII values (the token format `<<TYPE_N>>` is acceptable — it contains no PII)
- Conversation UUIDs alongside PII counts that could be correlated
- Error messages from crypto operations that might leak plaintext (Go's `crypto/aes` errors are safe — they don't include data)
- File paths that include user home directories containing usernames (use basename or `filepath.Base()`)

Acceptable to log:
- `"vault: opened"` with path (using `filepath.Base()` for the filename, not full path including username)
- `"vault: sweep completed"` with `purged_count`
- `"vault: conversation purged"` with provider name and UUID (DEBUG only)
- `"vault: write enqueued"` with token type (e.g., `EMAIL`) — not the token string itself, unless token string is proven PII-free
- Crypto service initialization (key loaded/generated) without revealing key bytes
- SID resolution outcomes (resolved/denied) without logging the SID itself

Every log entry from the vault package must include `"pii_values_logged", false` (ADR-008 compliance marker).

### DPO-R5 — Key file permissions (MANDATORY)

On all platforms:
- `vault.key` must be created with mode `0600` (owner read/write only).
- If the file already exists, its permissions must be validated at startup. If permissions are wider than `0600`, either:
  - Log a WARNING and tighten them (preferred), or
  - Log an ERROR and refuse to start (acceptable alternative).
- `vault.db` must be created with mode `0600` (owner read/write only) via bbolt's `Open` options.
- On Windows, use explicit ACLs to restrict both files to the current user (SID). The service creates files in the user's `%LOCALAPPDATA%`, which inherits user-restricted ACLs — verify this by testing.

### DPO-R6 — Cryptographic correctness (MANDATORY)

Requirements for `internal/crypto`:
- **Key generation**: 32 bytes from `crypto/rand`. Never use a fixed key, a derivation from a password, or a hardcoded seed.
- **Nonce generation**: 12 bytes from `crypto/rand` per encryption operation. Never use a counter, a timestamp-derived nonce, or any deterministic scheme.
- **Ciphertext format**: `nonce(12) || ciphertext || tag(16)`. Decryption must verify the GCM tag before returning plaintext.
- **Key loading**: If `vault.key` exists, read all 32 bytes. If the file contains != 32 bytes, return a clear error (key corrupted). If the file doesn't exist, generate a new key and write it.
- **No key derivation**: The on-disk key IS the AES key. No PBKDF2, scrypt, bcrypt, or argon2. This is acceptable because the key is machine-generated random bytes, not a human-chosen password.
- **Key zeroing during Close()**: When the crypto service is shut down, zero the key material in memory (overwrite the `[]byte` before it's garbage-collected). This is defense-in-depth — makes key extraction from memory dumps harder.
- **Test: encrypt/decrypt round-trip** for 0-byte, 1-byte, typical (200-byte email), and large (4KB) inputs.
- **Test: decryption with wrong key** → error (authentication failure).
- **Test: decryption with tampered ciphertext** → error (GCM tag mismatch).
- **Test: cross-platform interoperability** — ciphertext produced on Linux must decrypt on Windows/macOS.

### DPO-R7 — bbolt integrity and crash safety (MANDATORY)

- `NoSync: false` — every write is fsync'd. Performance cost is acceptable for privacy data (durability > speed).
- `Timeout: 1s` — if bbolt is locked by another process, timeout with a clear error.
- bbolt file opened with `0600` permissions.
- After `Close()`, the bbolt database handle is nil'd to prevent use-after-close.
- Transaction safety: read transactions use `db.View()`, write transactions use `db.Batch()` or `db.Update()`. No long-lived read transactions that could block writes.
- The vault's `Close()` method must be safe to call multiple times (idempotent).

### DPO-R8 — Per-user isolation verification (MANDATORY)

- On Linux/macOS: `$HOME` is the canonical source of user identity. Vault path derived from `$HOME`.
- On Windows (service mode): SID resolution via TCP/UDP table (DD-13). DENY on any failure.
- The SID LRU cache must have a finite capacity (suggest 1000 entries, LRU eviction) and NOT persist to disk.
- The SID cache key must be `(PID, connection port)` or equivalent. The TTL is connection lifetime (evict on connection close) or a short timeout (60s per AC-16).
- Cross-user test: Two goroutines simulating Alice and Bob, different user profile paths, ensure no value appears in the wrong vault.

### DPO-R9 — Graceful shutdown: drain the async queue (MANDATORY — AC-7)

- On SIGTERM/SIGINT: close the `Persist` channel → drain remaining entries → flush to bbolt → close bbolt → close crypto → exit.
- The drain must be bounded in time — maximum 30 seconds (consistent with QINDU-0001 graceful shutdown).
- If the drain timeout expires, log a WARNING with the number of unflushed entries and exit. The next startup will have a partial vault for those conversations — acceptable per DD-10.
- During drain, the proxy must stop accepting new connections (already handled by proxy.Shutdown() in DD-15).

### DPO-R10 — Config validation: TTL (MANDATORY — AC-8)

```go
type TTLConfig struct {
    TTL string `yaml:"ttl"` // "24h", "168h", "720h", "0" (with DPO-B1 safeguards)
}
```

- Reject: negative durations, non-parseable strings (e.g., `"15x"`, `"forever"`).
- Reject: sub-hour durations (e.g., `"30m"`) — a vault with sub-hour TTL defeats the purpose of persistence and creates excessive churn.
- Accept: `0` (with DPO-B1 safeguards), `24h`, `168h`, `720h`.
- The error message must state the invalid value and accepted format, without PII.

### DPO-R11 — TokenPersister nil-safety (MANDATORY — AC-9)

- When the Tokenizer is created without a persister (nil), all existing behavior is preserved.
- No nil pointer dereference in the Tokenizer's `assignTokens` method.
- The Tokenizer must check `if t.persister != nil` before calling `persister.Persist()`.
- The `TokenPersister` interface must be defined before the Tokenizer uses it (avoid circular imports). Suggested location: `internal/vault/persister.go` or `internal/tokenize/persister.go`.

### DPO-R12 — Metadata integrity (MANDATORY — AC-13)

- `pii_count` must equal the number of token entries (excluding `__meta__`) in the conversation prefix.
- `pii_types` must contain the deduplicated set of entity types across all tokens in the conversation.
- `updated_at` must be bumped on each `Persist()` call, not just on first write.
- If a `Persist()` call fails (bbolt error), metadata must not be updated (no partial metadata). Use a bbolt transaction to keep metadata + value writes atomic.
- `created_at` must never change after initial creation.

### DPO-R13 — No network access, no cloud sync, no telemetry (MANDATORY)

The vault package must not:
- Open any network connections (HTTP, TCP, UDP — except the SID resolution's OS-level API calls)
- Access any remote storage (no S3, no cloud APIs, no WebDAV)
- Transmit telemetry, analytics, or usage statistics
- Send error reports or crash dumps externally
- Embed any tracking identifiers, installation IDs, or user fingerprints

This is a core Qindu non-negotiable rule. The vault operates entirely within the local machine boundary.

### DPO-R14 — User transparency about metadata (MANDATORY)

At startup, when the vault is initialized, emit an INFO-level log:
```
"Vault encryption active. PII values are encrypted at rest (AES-256-GCM). Conversation metadata (provider, timestamps, PII types/counts) is stored in plaintext for efficient TTL enforcement. Anyone with filesystem access to the vault directory can see which AI services you use, when, and what categories of PII were detected. PII values are never stored or transmitted in plaintext."
```

This log entry must include `"pii_values_logged", false`.

### DPO-R15 — Key rotation consideration (RECOMMENDED — not blocking)

**Recommendation**: Document that vault key rotation is NOT supported in V1. If a user suspects their vault key is compromised, they must:
1. Stop the proxy
2. Delete `vault.db` and `vault.key`
3. Restart the proxy (a new key will be generated; a new empty vault will be created)
4. Accept that all historical conversation data is lost

This is a documentation requirement, not a code requirement. The UI sprint (QINDU-0016) should expose this as a "Wipe Vault" button.

### DPO-R16 — Tokens in bbolt keys are NOT PII (VERIFICATION)

**Requirement**: Confirm during review that the token strings stored as bbolt keys (`<<EMAIL_1>>`, `<<PHONE_42>>`) encode zero information about the PII value. The token format was established in QINDU-0006 (SR-2). The review must verify that the vault doesn't introduce any alternative token format that embeds PII (e.g., base64-encoded values, hash-based tokens, or value-derived identifiers).

This should be a code audit item during the DPO review gate, not a new design constraint.

### DPO-R17 — Conversation UUID must be from `crypto/rand` (MANDATORY)

The proxy-generated UUID used as the vault key (DD-8) must be a version-4 UUID generated by reading 16 bytes from `crypto/rand` and setting the version/variant bits per RFC 9562. It must not:
- Use `math/rand` (deterministic, predictable)
- Encode any user, machine, or session identifier
- Be derived from the provider's conversation ID (which could leak info)
- Be a counter or timestamp-based UUID (v1/v6/v7), which could reveal timing information

A pure random UUID v4 is the minimum necessary identifier and carries no semantic information.

---

## 8. Required Privacy Tests

These tests must be present in the implementation's test suite. The QA agent will verify during the validation gate.

| ID | Test | Verifies |
|---|---|---|
| **T1** | Persist a PII value, close vault, reopen vault, retrieve → value recovered | AC-1, DPO-R6 |
| **T2** | Inspect `vault.db` with `hexdump` or `strings` → no raw PII values present | AC-2, DPO-R4 |
| **T3** | Inspect `vault.db` → provider names, UUIDs, PII type strings visible; PII values NOT visible | AC-2, DD-4 |
| **T4** | Create conversation, set ttl=0h (immediate), start vault → conversation purged at startup sweep | AC-3, DPO-R2 |
| **T5** | Create conversation, advance clock past TTL, access conversation → purged, no data returned | AC-3 |
| **T6** | Two users (Alice, Bob) using separate vault paths → Alice's PII not in Bob's vault, Bob's not in Alice's | AC-4, DPO-R8 |
| **T7** | SID lookup failure → connection denied, no fallback to machine-level vault | AC-5 |
| **T8** | Async writes: 100 concurrent `Persist()` calls → proxy latency increase < 1ms p99 | AC-6 |
| **T9** | Graceful shutdown with pending writes → all committed to bbolt before `Close()` returns | AC-7, DPO-R9 |
| **T10** | Invalid TTL values ("-5h", "15x", "0s") → agent refuses to start | AC-8, DPO-R10 |
| **T11** | Tokenizer without persister → identical behavior to QINDU-0006 (no panics, no vault writes) | AC-9, DPO-R11 |
| **T12** | Cross-compile `internal/crypto` for windows/linux/darwin → builds pass; encrypt on Linux, decrypt on Windows | AC-10 |
| **T13** | Vault operations (open, write, close, expire) → no PII in all log levels (DEBUG through ERROR) | AC-11, DPO-R4 |
| **T14** | `go test -race` on `internal/vault` and `internal/session` → zero data races | AC-15 |
| **T15** | Same PID making 5 connections within 60s → SID lookup performed exactly once | AC-16 |
| **T16** | AES-GCM round-trip: encrypt then decrypt → original plaintext recovered (0, 1, 200, 4096 bytes) | DPO-R6 |
| **T17** | AES-GCM tamper detection: flip one bit in ciphertext → decrypt fails with error | DPO-R6 |
| **T18** | `vault.key` created with mode 0600; pre-existing file with 0644 → tightened or rejected | DPO-R5 |
| **T19** | `PurgeAll()` → all bbolt entries removed, empty database, metadata gone | DPO-R3 |
| **T20** | `ListConversations()` → returns metadata without decrypting PII values | DPO-R3 |
| **T21** | Background sweeper: create expired conversation, wait for sweeper interval → conversation purged without explicit access | DPO-R2 |
| **T22** | Crash during async write: kill -9, restart → partial vault for affected conversation, raw PII NOT exposed (ciphertext intact) | DD-10, AC-2 |
| **T23** | `vault.key` file contains exactly 32 bytes; key service rejects != 32 bytes | DPO-R6 |
| **T24** | UUID is valid v4 (RFC 9562) — version bits = 0100, variant bits = 10xx | DPO-R17 |
| **T25** | All test fixtures use synthetic PII only (grep for real email domains, real phone patterns, real IBANs) | DPO-B3 |

---

## 9. Summary of Requirements

| ID | Requirement | Priority | Blocks Design? |
|---|---|---|---|
| **DPO-B1** | `ttl: 0` requires explicit safeguard (remove, warn, or separate flag) | BLOCKING | **YES** |
| **DPO-B2** | Periodic background TTL sweeper (not just lazy/startup) | BLOCKING | **YES** |
| **DPO-B3** | No test fixture with real PII | BLOCKING | At review gate |
| **DPO-R1** | Infinite TTL startup WARNING + documentation | MANDATORY | Depends on B1 resolution |
| **DPO-R2** | Background sweeper goroutine implementation | MANDATORY | Depends on B2 resolution |
| **DPO-R3** | PurgeExpired, PurgeAll, ListConversations, DeleteConversation API | MANDATORY | No |
| **DPO-R4** | Zero PII in logs (ADR-008 compliance marker) | MANDATORY | No |
| **DPO-R5** | Key file permissions (0600, validation, Windows ACLs) | MANDATORY | No |
| **DPO-R6** | Cryptographic correctness (crypto/rand, nonce uniqueness, key zeroing) | MANDATORY | No |
| **DPO-R7** | bbolt integrity (NoSync, Timeout, permissions, transaction safety) | MANDATORY | No |
| **DPO-R8** | Per-user isolation verification (cross-user test) | MANDATORY | No |
| **DPO-R9** | Graceful shutdown drains async queue (bounded 30s) | MANDATORY | No |
| **DPO-R10** | Config validation for TTL values | MANDATORY | No |
| **DPO-R11** | TokenPersister nil-safety (no regression) | MANDATORY | No |
| **DPO-R12** | Metadata integrity (pii_count, pii_types, updated_at atomicity) | MANDATORY | No |
| **DPO-R13** | No network, cloud, telemetry, tracking | MANDATORY | No |
| **DPO-R14** | User transparency log about metadata in plaintext | MANDATORY | No |
| **DPO-R15** | Key rotation documentation | RECOMMENDED | No |
| **DPO-R16** | Token format audit (no PII in bbolt keys) | VERIFICATION | At review gate |
| **DPO-R17** | Conversation UUID must be from `crypto/rand` (v4) | MANDATORY | No |

---

## 10. Verdict

### PASS — WITH CONDITIONS

The QINDU-0008 vault design is **substantially privacy-compliant**. The core architecture — AES-256-GCM encrypted values, per-user isolation via OS-level identity, configurable TTL, optional persister, async writes with in-memory grounding, mandatory encryption — embodies data protection by design (Art. 25). The decision to store metadata in plaintext is a legitimate, proportionate trade-off that enables essential functionality (TTL scanning, UI browsing) without exposing PII values.

**Two design issues must be resolved before implementation can proceed:**

1. **DPO-B1 — `ttl: 0` infinite retention**: The option to store PII forever violates storage limitation and data protection by default. Must be removed, guarded with a warning, or converted to an explicit opt-in.

2. **DPO-B2 — Lazy TTL enforcement**: Without a periodic background sweeper, expired PII can linger on disk indefinitely. A background goroutine that periodically sweeps expired conversations is required.

These are not architectural overhauls — they are targeted additions to the existing design. DPO-B1 requires a config/code change (add a warning or remove the option). DPO-B2 requires adding a goroutine with a ticker and a prefix scan — well within the sprint's scope.

Once these two conditions are satisfied, the sprint can proceed to implementation with confidence.

### What the design gets right

- **Encryption mandatory**: Cannot be toggled off — privacy by default (DD-14).
- **Key separation**: CA key (DPAPI) and vault key (AES) are independent — CA compromise doesn't compromise vault PII, and vice versa (DD-9).
- **Deny on SID failure**: No silent fallback to machine-level vault — privacy-positive failure mode (DD-13).
- **MemoryStore as live source of truth**: Async writes can't lose PII during the current session (DD-10).
- **Per-user, not per-machine**: Vault paths in user profile directories respect OS-level multi-user isolation (DD-12).
- **Optional persister**: The system degrades gracefully without a vault — no mandatory persistence (DD-11).
- **Proxy-generated UUID**: No re-use of provider conversation IDs as vault keys — prevents correlation (DD-8).
- **No DPAPI dependency for vault**: True cross-platform encryption without Windows-specific API coupling (DD-3, DD-9).

### Comparison with previous sprints

| Sprint | Storage | Encryption | TTL | Rights API |
|---|---|---|---|---|
| QINDU-0006 (Tokenization) | Volatile memory | None (memory-locked only) | Process lifetime | Implicit (process death) |
| **QINDU-0008 (Vault)** | **bbolt on disk** | **AES-256-GCM** | **Configurable (24h–720h)** | **Explicit (DPO-R3)** |

This represents a significant privacy upgrade over the volatile-only approach of QINDU-0006.

---

*End of DPO requirements. This document is binding for the QINDU-0008 implementation and review gates.*
*ZERO PII disclosed in this document.*
