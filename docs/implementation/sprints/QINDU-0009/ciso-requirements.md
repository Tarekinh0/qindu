# CISO Security Requirements — QINDU-0009

**Sprint**: Mode Enforce + Réhydratation (non-streaming + SSE)
**Author**: qindu-ciso (Security Reviewer)
**Date**: 2026-07-06
**Verdict**: PASS (conditional on all requirements below)

---

## 1. Attack Surface

### 1.1 New Attack Surface

| ID | Surface | Exposure | Risk |
|---|---|---|---|
| **AS-1** | `EnforceInterceptor` — active body rewriting | Modifies HTTP request/response bodies before egress. First interceptor that *mutates* traffic. Bugs in `replaceSegments` or request rewriting can corrupt JSON, leak PII, or crash the proxy. | HIGH |
| **AS-2** | `VaultManager.GetOrCreate()` wired to `handleMITM` | Every CONNECT now triggers SID resolution and vault creation. Vault creation involves impersonation (`ImpersonateLoggedOnUser` on Windows), filesystem I/O, crypto key loading, and bbolt database open. New failure modes at the connection boundary. | HIGH |
| **AS-3** | SSE rehydration with sliding buffer | Reads untrusted SSE frames from upstream AI, maintains a 4KB sliding buffer, mutates frame bytes before writing to browser. Buffer content contains partial PII tokens. Buffer lifecycle tied to connection. | MEDIUM |
| **AS-4** | Conversation UUID derivation from `req.URL.Path` | Extracts and hashes a UUID from an untrusted URL path. Path length, format, and encoding are attacker-controlled. A malformed path could trigger unexpected behavior in the extraction/hashing logic. | MEDIUM |
| **AS-5** | Tokenizer injection into `http.Request.Context()` | The tokenizer (containing PII mappings, counters, and vault persister reference) is passed via Go context. Context key collision, type confusion, or leaking the tokenizer across goroutines could cause cross-connection PII contamination. | MEDIUM |
| **AS-6** | Config `*bool`/`*string` migration (R-024) | `PIILogging *bool`, `CertCacheEnabled *bool`, `FailMode *string`. Nil pointer dereference in any code path reading these fields will panic the proxy → DoS. Silent config override failures are the current bug being fixed. | MEDIUM |

### 1.2 Modified Attack Surface

| ID | Surface | Change |
|---|---|---|
| **AS-7** | `handleMITM` — SID resolution + vault wiring | Adds TCP→PID→SID resolution per connection, vault lookup/creation, and tokenizer injection. Previously: pure TLS + forward. |
| **AS-8** | `bodyScanConfig` — `tokenize`/`rehydrate` callbacks | New callback fields called within `scanBody()`. Callbacks are invoked *after* body bytes are read and *after* PII detection. The callback implementations (`replaceSegments`, `Rehydrate()`) are security-critical. |
| **AS-9** | `selectInterceptor()` — enforce mode activation | Previously returned an error. Now constructs `EnforceInterceptor` with plugins and vault wiring. |
| **AS-10** | ChatGPT plugin — `ResponseTextExtractor` | Plugin gains response-parsing capability. Parses untrusted JSON from upstream AI. JSON parse depth, key count, and string lengths are attacker-controlled. |

---

## 2. Protected Assets

| Asset | Sensitivity | Protection required |
|---|---|---|
| PII values in HTTP request bodies | CRITICAL | MUST be tokenized to `<<TYPE_N>>` before any byte leaves the proxy to upstream. Must never appear in logs, vault keys, or error messages. |
| PII values in the tokenizer in-memory store (`store.mapping`, `valueToToken`) | CRITICAL | Already in locked memory arena where supported. Map keys on Go heap (R-017). Must never be serialized, logged, or transmitted. |
| Vault encryption key (`crypto.Service.key` — 32-byte AES-256) | CRITICAL | In process memory, zeroed on `Close()`. Key file on disk: 0600 (Unix) or ACL-restricted (Windows). Key is the master secret for all persisted PII. |
| Token↔PII mappings in bbolt vault.db | HIGH | AES-256-GCM encrypted. Without vault.key, the database is opaque. bbolt file permissions: 0600. |
| CA private key (ECDSA P-256, DPAPI-encrypted on disk) | CRITICAL | Unchanged by this sprint. Must ensure enforce mode adds no new paths to the CA key. |
| Windows impersonation token (`token uintptr`) | HIGH | Obtained via `OpenProcessToken(TOKEN_QUERY\|TOKEN_IMPERSONATE)`. Strictly scoped to vault creation filesystem operations. Must never leak to interceptor, forwarding, or logging paths. |
| Conversation vault scope (`{Provider, ConversationID}`) | MEDIUM | Deterministic across connections for the same conversation. Collision resistance depends on hash strength. Cross-conversation collision = PII cross-contamination. |
| SSE sliding buffer content | HIGH | Contains partial PII tokens at chunk boundaries. Must never be logged, serialized, or leaked across connections. Must be zeroed on connection close. |

---

## 3. Threat Model (STRIDE)

### Spoofing

| ID | Threat | Mitigation | Status |
|---|---|---|---|
| **T-S.1** | Attacker crafts URL path to cause conversation UUID collision (e.g., non-UUID path that hashes identically) | Use SHA-256 of the extracted UUID (not the full path). Validate UUID format before hashing. Fallback to `crypto/rand` UUID when path has no conversation ID. | **Requirement: SR-CISO-1** |
| **T-S.2** | Attacker injects `<<TYPE_N>>` token strings into their own prompt that, after rehydration, resolve to PII from a *different* conversation | Per-conversation vault scoping isolates token counters. Even if the same counter `<<EMAIL_1>>` appears in two conversations, they map to different PII (different vault scopes). Collision possible only if SHA-256 output collides (2^-128). | **Requirement: SR-CISO-1** |
| **T-S.3** | AI service crafts a response with tokens it observed in the tokenized request to trigger rehydration | This is the *intended behavior* — the user sees their own PII back. The AI service cannot exfiltrate PII because rehydration is local. The only risk is the AI inferring metadata (how many tokens of each type) — acceptable for V1. | Acceptable |

### Tampering

| ID | Threat | Mitigation | Status |
|---|---|---|---|
| **T-T.1** | `replaceSegments` corrupts the JSON request body when token length differs from PII length | Right-to-left segment processing ensures offset adjustments don't invalidate subsequent positions. Process segments in descending `Start` order (story DD-2 is correct). Must handle edge cases: zero-length PII, token at position 0, token at end of body. | **Requirement: SR-CISO-3** |
| **T-T.2** | Malicious AI service sends SSE frames with tokens split precisely at chunk boundaries to test sliding buffer | Buffer capped at 4KB. Buffer overflow → truncate and WARN (PII-free). Buffer content never logged. Partial token prefix (`<<[A-Z_]*`) used to detect split tokens — bounded regex, no ReDoS. | **Requirement: SR-CISO-4** |
| **T-T.3** | `scanBody` rewriter callback modifies body bytes after extractor has already computed `TextSegment` offsets | The design is: extractor runs on original `bodyBytes` → tokenize/rehydrate runs on `segments.Text` → rewriter uses modified segments + original bodyBytes. This is safe because extractor offsets index into *original* bodyBytes, and replaceSegments processes right-to-left on a copy. Must ensure replaceSegments gets the ORIGINAL body, not the rewritten body. | **Requirement: SR-CISO-3** |
| **T-T.4** | URL path contains NUL bytes, control characters, or is path-traversal-encoded (e.g., `%2e%2e%2f`) | Go's `http.Request.URL.Path` is already decoded by `net/http`. NUL bytes and control characters must be rejected. Path length must be bounded before hashing. | **Requirement: SR-CISO-2** |

### Repudiation

| ID | Threat | Mitigation | Status |
|---|---|---|---|
| **T-R.1** | Async vault writes silently dropped without log evidence | WARN log at `pii_values_logged: false` when buffer overflows. Log MUST include `dropped_count` (counter since last WARN). Log MUST be rate-limited (≤1 per minute). | **Requirement: SR-CISO-6** |
| **T-R.2** | Token write succeeds but the corresponding `tokenized_count`/`rehydrated_count` in `monitor_scan` is incorrect | `scanBody` emits `monitor_scan` from the interceptor goroutine (synchronous). The vault write is async (fire-and-forget). The log counts are derived from detection results, not from vault write success. This is correct — the log reflects what the proxy *did*, not what the vault *persisted*. | Acceptable |

### Information Disclosure

| ID | Threat | Mitigation | Status |
|---|---|---|---|
| **T-I.1** | Vault failure 502 response leaks internal error details (paths, usernames, PII) | `sendBadGateway()` returns a static JSON body: `{"error":"bad_gateway","detail":"upstream connection failed"}`. All new failure paths in `handleMITM` (SID resolution, vault creation) MUST use `sendBadGateway` and never write custom error bodies. | **Requirement: SR-CISO-5** |
| **T-I.2** | Token counters reveal PII volume per conversation type | `<<EMAIL_1>>`, `<<EMAIL_2>>` reveals that 2 email addresses were detected. This is in the request body sent to the AI service — the service can count tokens. Acceptable for V1 (the alternative — random tokens — would break deterministic re-tokenization). | Acceptable |
| **T-I.3** | Error messages from crypto, vault, or session packages include filesystem paths with usernames | `redactHomePath()` already handles common cases (Unix `~`, Windows `%LOCALAPPDATA%`). Must verify that new error paths in `handleMITM` (`vaultManager.GetOrCreate` failure, SID resolution failure) use redacted paths in log messages. | **Requirement: SR-CISO-7** |
| **T-I.4** | `pii_logging: true` in enforce mode leaks entity types in logs | Controlled by `pii_logging` flag (R-024 fix). When `false`, `entity_summary` is absent. When `true`, only type counts (e.g., `{"EMAIL": 2}`), never values. Startup INFO must warn when `pii_logging` is enabled. | **Requirement: SR-CISO-8** |

### Denial of Service

| ID | Threat | Mitigation | Status |
|---|---|---|---|
| **T-D.1** | Vault creation failure → 502 for all enforce connections (total DoS) | Fail-closed is the correct privacy posture. Attacker must be local (localhost-only proxy). Persistent vault failure (disk full, corrupt bbolt) would block all AI access in enforce mode. Mitigation: operator can switch to monitor mode (`agent.mode: monitor`) as a fallback. | Acceptable (fail-closed by design) |
| **T-D.2** | Attacker sends SSE stream with `<<` prefix that never resolves, filling the sliding buffer | Buffer capped at 4KB. When buffer is full and still no complete token: flush buffer to output, WARN (PII-free), reset. Buffer per-connection (not shared). | **Requirement: SR-CISO-4** |
| **T-D.3** | Conversation UUID extraction from path: pathological path causes OOM or CPU exhaustion | Path length bounded by HTTP server (1MB header limit). UUID regex must be linear-time (no backtracking). Hash input is the UUID string (36 chars), not the full path. | **Requirement: SR-CISO-2** |
| **T-D.4** | `*bool`/`*string` nil dereference → proxy panic → crash | Every code path reading `cfg.Logging.PIILogging`, `cfg.TLS.CertCacheEnabled`, `cfg.Agent.FailMode` must use nil-safe dereference with documented defaults. | **Requirement: SR-CISO-9** |

### Elevation of Privilege

| ID | Threat | Mitigation | Status |
|---|---|---|---|
| **T-E.1** | Windows impersonation token leaks outside `createUserVault` | `create_windows.go`: impersonation is scoped to a single function. `defer windows.RevertToSelf()` guarantees thread token restoration before any other proxy code executes. The token is obtained with minimal privileges (`TOKEN_QUERY \| 0x0004`). Token value (`uintptr`) is passed by value, not reference. | Acceptable (well-scoped) |
| **T-E.2** | Impersonation TOCTOU — PID recycled between TCP table lookup and `OpenProcess` | PID cache TTL of 60s reduces repeated lookups. For first lookup: TCP table is queried → port is found → PID extracted. If process exits between table lookup and `OpenProcess`, the call fails (safe). If PID is reused by a different process with a still-alive TCP port (extremely unlikely), `OpenProcess` succeeds for wrong user → vault created in wrong profile. Mitigated by PID recycling behavior (PIDs wrap slowly on Windows). | Acceptable for V1 (documented in R-033) |
| **T-E.3** | Tokenizer leaked across HTTP requests via shared context | Tokenizer is injected per-request into `req.Context()`. If the proxy handler reuses the same context across multiple requests on a keep-alive connection, different conversations could share the same tokenizer (cross-conversation PII contamination). | **Requirement: SR-CISO-10** |

---

## 4. Blocking Security Requirements

### SR-CISO-1: Conversation UUID Cryptographic Hash
**OWASP ASVS**: V2.10.3 (Cryptographic Agility) | **References**: ADR-008, DPO DR-2

- The conversation UUID extracted from the URL path MUST be hashed using **SHA-256** (`crypto/sha256`). FNV, CRC, or non-cryptographic hashes are FORBIDDEN.
- The vault scope key MUST concatenate `{Provider}:{SHA256(uuid)}` to prevent cross-provider collisions. Example: `chatgpt:3f8a...`.
- The fallback per-connection random UUID MUST use `crypto/rand` (`crypto/rand.Read`), NEVER `math/rand`.
- The extracted conversation UUID MUST be validated as a UUID v4/v7 format before hashing. Non-UUID path fragments MUST be rejected (fall back to random UUID).
- Path length MUST be bounded to 2048 bytes before UUID extraction (defense-in-depth beyond HTTP server limits).
- **Rationale**: A weak hash would allow an attacker to craft URL paths that collide on vault scope, causing cross-conversation PII contamination. This is a **BLOCKING** requirement for enforce mode security.

### SR-CISO-2: URL Path Parsing Safety
**OWASP ASVS**: V5.1.4 (Input Validation) | **References**: ADR-002

- The URL path for conversation UUID extraction is **untrusted input** from the browser (and potentially from a compromised AI service redirecting through the proxy).
- The path MUST be validated before UUID extraction: reject paths containing NUL bytes (`\x00`), control characters (< 0x20), or non-ASCII bytes (unless explicitly handling UTF-8).
- The UUID extraction regex MUST be linear-time (no nested quantifiers, no backtracking). A simple pattern like `[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}` is safe.
- Paths without a valid UUID MUST fall back to a `crypto/rand` UUID, not crash or return empty scope.
- The hash input MUST be the extracted UUID bytes, NOT the entire URL path (to avoid hashing attacker-controlled path prefixes).
- **Rationale**: Malformed URL paths could cause unexpected behavior in hash derivation, leading to scope collisions or resource exhaustion.

### SR-CISO-3: replaceSegments Byte-Level Safety
**OWASP ASVS**: V5.3.4 (Output Encoding) | **References**: ADR-004

- `replaceSegments(body []byte, segments []TextSegment) []byte` MUST:
  1. Process segments in **descending `Start` order** (right-to-left) to handle token/PII length differences without invalidating offsets.
  2. Operate on a **mutable copy** of the body, not the original `bodyBytes`.
  3. Handle edge cases: PII at position 0, PII at end of body, zero-length segments, segments with identical text (no-op).
  4. **Validate segment bounds** before replacement: `Start >= 0`, `End > Start`, `End <= len(body)`. Reject invalid segments (log WARN, skip the segment, do not crash).
  5. After replacement, verify the result is valid UTF-8 (or at minimum, valid JSON if the Content-Type is `application/json`).
- `replaceSegments` MUST be called with the **original** body bytes + tokenized segments, never with a previously-rewritten body.
- Segments passed to `replaceSegments` MUST be non-overlapping. The engine guarantees this; add a defense-in-depth overlap check.
- **Rationale**: Byte-offset corruption in JSON request bodies can break the API call (privacy-preserving but broken) or worse, silently truncate or misplace tokens — potentially leaking PII in misaligned fields.

### SR-CISO-4: SSE Sliding Buffer Hardening
**OWASP ASVS**: V5.2.1 (Input Handling) | **References**: ADR-004

- The sliding buffer that reassembles tokens split across SSE chunk boundaries MUST:
  1. Be **capped at 4096 bytes** (4KB). When full: flush buffer to output as-is (unrehydrated partial), WARN with `pii_values_logged: false`, and reset.
  2. Be **per-connection** (never shared across concurrent connections).
  3. Have its **content NEVER logged** — even in DEBUG. The buffer contains partial PII tokens.
  4. Be **zeroed** (overwritten with zeros) on connection close to clear PII from memory.
  5. Detect partial token prefixes using the same `tokenRegex` pattern: a trailing `<<[A-Z_]*` at the end of a chunk indicates a potentially split token. This regex is bounded and linear (no `*` after `*`).
  6. Handle the case where `<<` appears in the stream but is NOT a token (e.g., legitimate text containing `<<`): after 4KB or stream end without a complete `<<TYPE_N>>` match, flush as-is.
- **Rationale**: An attacker who controls the AI service could exploit the sliding buffer to cause memory leaks, log injection, or buffer overflow. The 4KB cap and zero-on-close prevent these.

### SR-CISO-5: Fail-Closed Error Response Leakage
**OWASP ASVS**: V7.4.1 (Error Handling) | **References**: ADR-002, DPO DR-3

- Every error path in `handleMITM` that results in connection denial MUST use `sendBadGateway()` — a **static**, pre-defined 502 JSON response. Custom error bodies containing internal state, paths, stack traces, or PII are FORBIDDEN.
- Specifically, these new failure points in enforce mode:
  1. SID resolution failure (`LookupVaultPathForPort` error)
  2. Vault creation failure (`VaultManager.GetOrCreate` error)
  3. Tokenizer creation failure (engine error)
  ALL must result in `sendBadGateway(browserConn)` — no exceptions.
- The structured log entry for each failure MUST include `pii_values_logged: false` and MUST NOT contain the raw error from the OS (if it may contain paths/usernames). Use sanitized error messages.
- **Rationale**: Error details (filesystem paths, usernames, SID strings) must not be exposed to the browser, even in error responses. The static 502 response prevents information leakage.

### SR-CISO-6: Async Channel Overflow Audit Trail
**OWASP ASVS**: V7.3.2 (Log Integrity) | **References**: R-013, DPO DR-4

- When the vault async write channel (buffer: 1024) is full and a write is dropped:
  1. A WARN log MUST be emitted at `pii_values_logged: false`.
  2. The log MUST include a monotonically incrementing `dropped_count` field (number of dropped writes since the last such WARN).
  3. The log MUST be **rate-limited**: at most one WARN per minute to avoid log flooding under sustained overload.
  4. The log MUST NOT contain any PII values, token values, or tokenized text. Only counters and the scope provider name.
  5. The proxy MUST continue operating in memory-only mode (the in-memory store still has the mapping).
- Test: generate enough concurrent `Persist()` calls to overflow the 1024-entry buffer. Verify WARN is emitted, verify rate limiting.
- **Rationale**: Without rate limiting, a sustained DoS attack could flood the logs (disk exhaustion). Without `dropped_count`, operators cannot assess the extent of persistence loss.

### SR-CISO-7: Path Redaction in Error Logs
**OWASP ASVS**: V7.1.2 (Log Sanitization) | **References**: ADR-008

- All new log entries in `handleMITM`, `EnforceInterceptor`, and SSE rehydration paths that include filesystem paths MUST use `redactHomePath()` before logging.
- Specifically:
  - Vault creation failure: redact `resolved.VaultPath` before logging
  - SID resolution failure: redact any path in the error (may require wrapping the OS error)
  - Crypto key load failure: redact `resolved.KeyPath`
- Verify: `grep` log output for common paths like `/home/`, `/Users/`, `C:\Users\` — none should appear with actual usernames.
- **Rationale**: Usernames in log paths are personal data under GDPR Art. 4(1). QINDU-0008 already implemented `redactHomePath()` — this sprint must ensure all new code paths use it.

### SR-CISO-8: pii_logging Flag Enforcement
**OWASP ASVS**: V7.1.1 (Log Protection) | **References**: R-024, R-029, DPO DR-6

- The `pii_logging` flag (now `*bool` per R-024) MUST actually control log output in enforce mode:
  1. When `pii_logging` is `nil` or `*false`: `entity_summary` MUST NOT appear in `monitor_scan` log entries from `EnforceInterceptor`.
  2. When `pii_logging` is `*true`: `entity_summary` MAY appear (type counts only).
  3. The `EnforceInterceptor` MUST use the same `emitMonitorScan` / `buildEntitySummaryCond` code path as `MonitorInterceptor` — no duplicate log formatting.
  4. At agent startup, if `pii_logging` is `*true`, log an INFO: `"pii_logging is enabled — entity type counts will appear in monitor_scan logs. PII values are never logged."`
- **Rationale**: R-029 documents that `pii_logging` was dead code in QINDU-0001. R-024 fixes the config parsing so `false` is distinguishable from "not set." This sprint must breathe life into both fixes so the flag actually works.

### SR-CISO-9: Config Pointer Nil-Safety (R-024)
**OWASP ASVS**: V1.1.3 (Secure Configuration) | **References**: R-024

- Every code path that reads `cfg.Logging.PIILogging` (`*bool`), `cfg.TLS.CertCacheEnabled` (`*bool`), or `cfg.Agent.FailMode` (`*string`) MUST use nil-safe dereference:
  - `PIILogging`: if nil → default `false`
  - `CertCacheEnabled`: if nil → default `true`
  - `FailMode`: if nil → default `"fail_closed"` for enforce mode, `"fail_open"` for monitor/transparent
- `MergeFileOverride()` MUST check `override.Field != nil` for these three fields, not zero-value checks (`!= false`, `!= ""`). The comment on line 383-386 and 412-414 already documents this bug — it MUST be fixed.
- Config validation MUST reject explicitly-set `fail_mode: "fail_open"` when `agent.mode: "enforce"` — these are incompatible. Return a clear error message at startup.
- **Rationale**: A nil dereference in a config field panics the proxy → total DoS. A missed config override (the old bug) silently ignores the operator's intent.

### SR-CISO-10: Tokenizer Context Isolation
**OWASP ASVS**: V4.1.1 (Access Control) | **References**: ADR-004

- The tokenizer injected into `http.Request.Context()` MUST:
  1. Use a **dedicated unexported context key type** (not a string literal): `type tokenizerCtxKey struct{}`.
  2. Have a **type-safe getter function**: `func getTokenizer(ctx context.Context) *Tokenizer` that returns `nil` if not present.
  3. Be injected **per-request** (each `InterceptRequest` call), not per-connection. If injected at the connection level, keep-alive requests for different conversations would share the same tokenizer.
  4. NEVER be modified by downstream interceptors or response paths — the tokenizer is read-only in the response path (rehydration only, no new tokenization).
  5. The `forwardRequestAndResponse` loop already creates a fresh context per request (via `http.Request.WithContext`). Each request gets its own tokenizer.
- **Rationale**: A shared tokenizer across requests would cause cross-conversation PII contamination: `<<EMAIL_1>>` from Conversation A rehydrating to the email from Conversation B. Context isolation prevents this.

### SR-CISO-11: Config Rejects fail_open in Enforce Mode
**OWASP ASVS**: V4.1.3 (Fail Secure) | **References**: DPO DR-3

- Config validation MUST reject: `agent.mode: "enforce"` combined with `agent.fail_mode: "fail_open"`.
- Error message: `"agent.fail_mode 'fail_open' is incompatible with enforce mode — enforce mode requires fail_closed to prevent PII leakage. Set fail_mode to 'fail_closed' or switch to monitor mode."`
- If `fail_mode` is nil (not set), enforce mode defaults to `"fail_closed"` — no error.
- This check must run in `Config.Validate()` so it blocks startup, not at connection time.
- **Rationale**: `fail_open` in enforce mode would silently forward raw PII to AI services when the vault is unavailable — defeating the entire purpose of the enforce pipeline.

### SR-CISO-12: Impersonation Token Audit (Windows)
**OWASP ASVS**: V4.2.1 (Privilege Management) | **References**: R-033, DPO DR-9

- At agent startup (before the proxy begins accepting connections), detect whether `SeImpersonatePrivilege` is present for the service account.
- If absent in enforce mode: log a WARNING: `"SeImpersonatePrivilege not available — per-user vault isolation disabled. All enforce-mode connections will be rejected."`
- The WARNING must include `pii_values_logged: false`.
- The agent MUST NOT crash if the privilege is absent — it should start and reject connections cleanly (502) rather than panic on the first impersonation attempt.
- **Rationale**: R-033 documents that a GPO can revoke this privilege. Without a startup warning, operators have no indication that all enforce connections will fail.

---

## 5. Mandatory Security Tests

### ST-CISO-1: Token Injection Resistance
- Create a mock AI response containing `<<EMAIL_1>>` (a token never created by the proxy).
- Verify the token passes through unchanged (no rehydration to unknown PII, no crash).
- Create a mock AI response containing `<<EMAIL_1>>` after tokenizing `user@example.com` in the request.
- Verify `<<EMAIL_1>>` rehydrates to `user@example.com` — but ONLY in the correct conversation scope.
- Create a second conversation, tokenize `other@example.com` → `<<EMAIL_1>>`.
- Verify the second conversation's response rehydrates `<<EMAIL_1>>` to `other@example.com`, NOT `user@example.com`.

### ST-CISO-2: replaceSegments Safety
- Test with: token shorter than PII (e.g., `<<EMAIL_1>>` replaces `very.long.email.address@subdomain.example.com`).
- Test with: token longer than PII (e.g., `<<CREDIT_CARD_123>>` replaces `411`).
- Test with: PII at byte offset 0 (start of body).
- Test with: PII at last byte of body.
- Test with: multiple PII in a single body, verify all are replaced correctly.
- Test with: JSON body — verify the result is still valid JSON (no missing commas, unmatched quotes).
- Test with: invalid segment (Start < 0, End > len(body)) — verify WARN is logged, segment is skipped, body is not corrupted.

### ST-CISO-3: Sliding Buffer Robustness
- Send SSE chunk ending with `<<EMA` → verify buffer holds partial token.
- Send next chunk `IL_1>>` → verify token is reassembled and rehydrated.
- Send `<<` with no close for 4KB of subsequent data → verify buffer is flushed, WARN is emitted.
- Send two consecutive `<<` prefixes → verify buffer handles nested `<<` correctly (first `<<` flushed when second `<<` arrives).
- Verify buffer content never appears in logs (grep log output for any fragment of PII values).
- Verify buffer is zeroed after connection close (white-box: inspect arena/Go heap after GC).

### ST-CISO-4: Fail-Closed Error Leakage
- Simulate vault creation failure in `handleMITM`.
- Verify the HTTP response body is EXACTLY `{"error":"bad_gateway","detail":"upstream connection failed"}\n` — not a variant, not a custom message.
- Verify the structured log entry contains `pii_values_logged: false` and does NOT contain the vault path.
- Verify the original request body is never forwarded (no bytes written to upstream writer).

### ST-CISO-5: Config Rejects fail_open in Enforce Mode
- Load config: `agent.mode: enforce`, `agent.fail_mode: fail_open`.
- Verify `Config.Validate()` returns an error.
- Verify the proxy does NOT start (startup is blocked).
- Load config: `agent.mode: enforce`, `agent.fail_mode: fail_closed` (explicit).
- Verify config validation passes.
- Load config: `agent.mode: enforce`, no `fail_mode` set (nil).
- Verify defaults to `fail_closed` and validation passes.

### ST-CISO-6: Config Pointer Nil-Safety
- Load config with NO `pii_logging` field (nil `*bool`).
- Verify proxy starts without panic, `pii_logging` defaults to `false`.
- Load config with `pii_logging: false` (explicit).
- Verify `pii_logging` is `*false`, not nil.
- Load config with `cert_cache_enabled: false` in override file.
- Verify `MergeFileOverride` applies the override (not silently ignored — the old bug).
- Test all three `*bool`/`*string` fields with nil, true, false, and "not present" scenarios.

### ST-CISO-7: Async Channel Overflow Warning
- Create 2000 concurrent `Persist()` calls (channel buffer: 1024).
- Verify WARN log is emitted with `dropped_count > 0`.
- Verify the WARN contains `pii_values_logged: false`.
- Verify the WARN is rate-limited: only one (or two max) warning per minute despite sustained overflow.
- Verify the proxy continues operating (no crash, no goroutine leak).

### ST-CISO-8: Tokenizer Context Isolation
- Create two HTTP requests with different URL paths (different conversation UUIDs).
- Verify each request gets a distinct tokenizer (different counters, different valueToToken maps).
- Tokenize `a@example.com` in Request 1 → `<<EMAIL_1>>`.
- Tokenize `b@example.com` in Request 2 → `<<EMAIL_1>>` (fresh counter).
- Verify Request 1's tokenizer rehydrates `<<EMAIL_1>>` to `a@example.com`, NOT `b@example.com`.
- Verify Request 2's tokenizer rehydrates `<<EMAIL_1>>` to `b@example.com`, NOT `a@example.com`.

### ST-CISO-9: Impersonation Scope Integrity (Windows VM)
- On the Windows QEMU VM, verify that after vault creation, the thread token is restored (check via `whoami` equivalent or process token inspection).
- Simulate impersonation failure: use a PID that doesn't exist.
- Verify the error is caught, 502 is returned, and the thread token is restored (no lingering impersonation).
- Verify `SeImpersonatePrivilege` startup check works: emit WARNING if privilege is absent.

### ST-CISO-10: Conversation UUID Hash Collision Safety
- Generate 10,000 random UUIDs, hash each with SHA-256, verify zero collisions.
- Test two different URL paths containing the same conversation UUID format: verify they produce the same vault scope (deterministic).
- Test two different URL paths with different UUIDs: verify they produce different vault scopes.
- Test URL path with no UUID: verify fallback to `crypto/rand` UUID, verify scope is unique.
- Test URL path with malformed UUID (wrong length, invalid characters): verify fallback to random UUID, verify scope is created.

---

## 6. Residual Risks

| Risk | Status | Notes |
|---|---|---|
| **R-004** (Chunking evasion — request) | ACCEPTED | SSE response chunking resolved in this sprint. Request chunk evasion (PII split across HTTP chunks in outbound request body) remains unresolved. The server-side request body is read by `io.ReadAll` in `scanBody`, which reads the full body — so HTTP chunked transfer encoding IS reassembled by Go's `http.ReadRequest`. Actual risk is low. |
| **R-005** (Core dump PII exposure) | ACCEPTED | Go runtime limitation. PII values exist in memory (arena, heap, stack). A process crash dump could contain PII. Not fixable without custom allocators. |
| **R-013** (Async channel overflow — silent loss) | MITIGATED | SR-CISO-6 requires rate-limited WARN with `dropped_count`. Persistent mapping loss under extreme load remains — but is now auditable. |
| **R-017** (valueToToken PII keys on Go heap) | ACCEPTED | Documented trade-off. The `valueToToken` map stores PII values as map keys outside the mlocked arena. A swap file could contain these. DPO DR-7 retains the WARNING comment. |
| **R-024** (Config bool fields silently ignored) | FIXING | This sprint fixes the `*bool`/`*string` migration. SR-CISO-9 ensures nil-safety. |
| **R-031** (Per-user vault.db not cleaned on uninstall) | ACCEPTED | MSI limitation. Documented in vault creation log. PII is encrypted at rest (AES-256-GCM) — without vault.key, vault.db is opaque. |
| **R-033** (SeImpersonatePrivilege GPO revocation) | MITIGATED | SR-CISO-12 requires startup WARNING. All enforce connections rejected (502) if privilege absent — safe failure mode. |
| **Token format metadata leakage** | ACCEPTED | Sequential counters (`<<EMAIL_1>>`, `<<EMAIL_2>>`) reveal PII volume by type to the AI service. Acceptable for V1. Future: random token identifiers. |
| **Impersonation TOCTOU (PID reuse)** | ACCEPTED | Inherent to the Windows TCP table approach. Mitigated by 60s PID cache TTL, slow PID recycling, and minimal `TOKEN_QUERY` permissions. Worst case: vault created in wrong user profile (PII written to wrong vault). |

---

## 7. Referenced ADRs

- **ADR-002** (CONNECT MITM): `handleMITM` is the wiring point for SID resolution + vault. The 502 error response must match the existing `sendBadGateway` format.
- **ADR-003** (TLS strategy): Enforce mode does not modify the TLS pipeline. CA private key protection is unchanged. Cert cache behavior is unchanged.
- **ADR-004** (Interceptor interface): `EnforceInterceptor` must implement `proxy.Interceptor`. The `bodyScanConfig` callback pattern preserves the interceptor contract.
- **ADR-008** (slog JSON sans PII): Every log entry in new code paths MUST include `pii_values_logged: false` when related to PII processing. The `tokenized_count` and `rehydrated_count` fields are metadata-only (safe).

---

## 8. Verdict

### Verdict: **PASS** (conditional)

The sprint design is security-sound. The key architectural decisions are correct:

1. **Fail-closed by default** (DD-9): Enforce mode always rejects connections when the vault is unavailable. No PII leakage path exists.
2. **Per-conversation vault scoping** (DD-5): Isolates token counters so cross-conversation PII contamination requires a SHA-256 collision (2^-128).
3. **TLS interception unchanged**: The MITM pipeline is unchanged — enforce mode inserts at the HTTP layer after TLS decryption.
4. **Impersonation token scoping** (DD-6): Windows impersonation is strictly bounded to vault creation filesystem operations with `defer RevertToSelf()`.
5. **Config R-024 fix** properly addresses the silent override bug that affects security-relevant fields (`pii_logging`, `cert_cache_enabled`, `fail_mode`).

### Conditions for PASS in implementation review:

1. **SR-CISO-1 through SR-CISO-12**: All 12 security requirements satisfied.
2. **ST-CISO-1 through ST-CISO-10**: All 10 security tests pass.
3. **DPO DR-1 through DR-9**: All DPO privacy requirements (already PASS at design stage) verified in implementation.
4. **DPO PT-ENF-1 through PT-ENF-15**: All 15 DPO privacy tests pass (complementary to CISO tests).
5. **No regression**: All existing monitor/transparent mode tests pass. `golangci-lint` zero issues. `go test -race` clean.
6. **Config validation**: `fail_open` + `enforce` combination is rejected at startup. `*bool`/`*string` nil-safe dereference in all code paths.
7. **Log audit**: `grep` all log output for PII patterns (email regex, phone regex, credit card regex) — zero matches. `pii_values_logged: false` on every PII-related log entry.
