# DPO Privacy Requirements — QINDU-0009

**Sprint**: Mode Enforce + Réhydratation (non-streaming + SSE)
**Author**: qindu-dpo (Privacy Reviewer)
**Date**: 2026-07-06
**Verdict**: PASS (conditional on all requirements below being satisfied in implementation)

---

## 1. Story Summary

QINDU-0009 delivers the **enforce pipeline** — the first sprint where PII is actively blocked from leaving the local machine. It merges the original QINDU-0009 (non-streaming rehydration) and QINDU-0010 (SSE rehydration with sliding buffer) into a single deliverable. The demo milestone: an operator sends a prompt containing an email address through ChatGPT. The proxy tokenizes `john@example.com` to `<<EMAIL_1>>` before the request reaches OpenAI. The vault persists the mapping. The SSE response stream is rehydrated locally — `<<EMAIL_1>>` restored to `john@example.com` in the browser.

The sprint introduces:
- **Enforce mode** (`agent.mode: "enforce"`) with tokenization before egress
- **Per-conversation vault scoping** (`{Provider, ConversationID}`)
- **Non-streaming and SSE response rehydration** with sliding buffer for chunked tokens
- **Fail-closed behavior** (502 on vault failure, zero PII leakage)
- **Config fixes** for `*bool`/`*string` pointer fields (R-024)
- **Optional `ResponseTextExtractor`** plugin interface for surgical response extraction

---

## 2. Data Processed — PII Categories

This sprint processes the following PII categories through the tokenize→rehydrate pipeline:

| Category | Detected by | Risk level | Notes |
|---|---|---|---|
| **EMAIL** | PII Engine (RFC 5322 recognizer) | HIGH | Primary demo category. Must never leave the machine in clear text. |
| **PHONE** | PII Engine (FR/EU/NANP/INTL recognizers) | HIGH | International phone formats. |
| **CREDIT_CARD** | PII Engine (Luhn-validated, 5 issuers) | CRITICAL | PCI-DSS scope. Tokenization prevents card numbers from reaching AI provider. |
| **NAME** | PII Engine (email inference, stop-word filtered) | MEDIUM | Confidence capped at 0.70. May produce false positives or miss real names. |
| **JWT** | PII Engine (structural validation) | MEDIUM | Often metadata, not user PII, but tokenized for defense-in-depth. |
| **SECRET** | PII Engine (70 prefix patterns + entropy) | MEDIUM | API keys, bearer tokens. Critical if user inadvertently pastes secrets into prompt. |
| **PRIVATE_KEY** | PII Engine (7 PEM armor types) | CRITICAL | Absolute must-tokenize. PEM private keys in prompts are catastrophic. |
| **IBAN** | PII Engine (34 countries, MOD-97) | HIGH | Limited by R-023 — accepts missing-country gaps. |

The vault stores the token→PII value mapping encrypted at rest (AES-256-GCM via DPAPI). The in-memory `valueToToken` map stores PII values as keys on the Go heap (R-017).

---

## 3. Purpose — Why This Processing Is Necessary

**Legal basis under GDPR Art. 6(1)(f) — Legitimate Interest**: The purpose of PII processing in this sprint is to prevent personal data from being transmitted to third-party AI services (OpenAI, Cloudflare, etc.) without the user's knowledge or consent. Qindu operates as a **local proxy** — the user installs and controls it. The processing:

1. **Identifies** PII in browser-to-AI traffic
2. **Substitutes** PII with opaque tokens before egress
3. **Persists** token→PII mappings in an encrypted local vault
4. **Restores** PII in AI responses before delivery to the browser

All processing happens on the user's own machine. No data leaves the machine un-tokenized. No external service receives PII in clear text. This is a **privacy-enhancing technology** (PET) — the processing serves the user's own privacy interest.

**GDPR Art. 25 — Data Protection by Design and by Default**: Qindu implements the principle that personal data should not, by default, be accessible to an indefinite number of natural persons. The proxy ensures that only the minimum necessary data (tokens, zero PII) leaves the machine by default.

---

## 4. Minimization Basis — Why Less Would Not Work

The data minimization analysis for each processing step:

| Processing step | Data accessed | Why necessary | What would break without it |
|---|---|---|---|
| **PII Detection** | Full request body text segments | Must identify all PII spans to tokenize. Cannot tokenize what we haven't detected. | PII would leak to AI providers. |
| **Tokenization** | PII values + entity types | Must know the value to create the token↔PII mapping. Must know the type to generate `<<TYPE_N>>` tokens. | Rehydration impossible without knowing what the token represents. |
| **Vault persistence** | Token↔PII mapping (encrypted) | User expects conversation history to be rehydratable across sessions. Without persistence, closing the browser means permanent token visibility in old conversations (unrehydrated `<<EMAIL_1>>` strings). | Tokenized conversation history becomes meaningless after browser restart. User cannot review past conversations. |
| **Rehydration** | Token lookup → PII value | Must restore the original PII for the user to see their own data. The AI response contains echoed tokens that only make sense when rehydrated. | User sees opaque `<<EMAIL_1>>` in AI responses — defeats the purpose of using the AI service. |
| **Conversation scoping** | URL path UUID → hash | Must isolate tokens per conversation to prevent cross-conversation PII leakage. Without scoping, a token from conversation A could be rehydrated with PII from conversation B if the same counter is used. | Cross-conversation PII injection — a data breach under GDPR Art. 32. |
| **Log sanitization** | Entity type counts, byte counts, metadata | Must verify PII is not logged. The log format (`monitor_scan`) already includes `pii_values_logged: false`. | Violation of ADR-008. GDPR Art. 30 records of processing activities would contain PII values. |

**Vault TTL as minimization**: The vault TTL (`24h`, `168h`, `720h`) ensures PII is not retained indefinitely. When TTL expires, the vault sweep purges token→PII mappings. This implements GDPR Art. 5(1)(e) — storage limitation.

---

## 5. Rights and Freedoms Risks

### 5.1 Risk: Blind rehydration on response metadata (MEDIUM)

**DD-3 and DD-4** specify blind `Rehydrate()` on full response bodies and SSE frame `data:` payloads. The rationale ("`<<TYPE_N>>` contains no JSON-breaking characters") addresses JSON integrity but does not address the privacy implication of injecting rehydrated PII into metadata fields.

**Scenario**: If the AI returns a response where a metadata field (e.g., `"title": "Conversation about <<EMAIL_1>>"`) contains a token, blind rehydration will inject the user's email into the conversation title field. This is **not** a data leak (the user is the intended recipient), but it violates the principle of surgical rehydration — PII should only be restored in content fields, not metadata fields that might be surfaced differently in the UI (e.g., conversation list sidebar showing email addresses in titles).

**Mitigation**: The `ResponseTextExtractor` interface exists specifically for this purpose. The ChatGPT plugin must implement `ExtractResponseText` to identify which byte ranges in the response constitute user-facing content vs. metadata. The `EnforceInterceptor` should use this interface when available, and rehydrate only within extracted segments.

**DPO Requirement DR-1**: The `EnforceInterceptor` must NOT blindly `Rehydrate()` on the entire response body. It must:
1. Use `ResponseTextExtractor` if the plugin implements it
2. Rehydrate only within the byte ranges returned by the extractor
3. Fall back to blind rehydration only when no extractor is available, and log a WARN with `pii_values_logged: false` indicating that blind rehydration is in use

### 5.2 Risk: Token collision across conversations (HIGH)

**DD-5** derives the conversation UUID from the URL path hash. If two different conversations happen to hash to the same vault scope, their tokens would collide — `<<EMAIL_1>>` from Conversation A could be rehydrated with PII from Conversation B.

**Analysis**: The ChatGPT URL path format is `/backend-api/f/conversation/<uuid>/`. The story specifies hashing the UUID. A cryptographic hash (SHA-256) of a UUID v4 has a collision probability of 2^-128, which is negligible. However, the fallback path (per-connection random UUID when no conversation ID is in the URL) has a collision probability of 2^-122 for UUID v4 — still negligible.

**DPO Requirement DR-2**: The conversation UUID derivation must use a cryptographic hash (SHA-256) of the URL path UUID. The fallback per-connection random UUID must use `crypto/rand` (not `math/rand`). The vault scope key must concatenate provider name and conversation hash to prevent cross-provider collisions. Test that two different conversation UUIDs produce different vault scopes.

### 5.3 Risk: Vault fail-open silent PII leak (CRITICAL)

**DD-9** specifies that enforce mode is always fail-closed. If the vault is unavailable, the connection is rejected with 502. This is correct. However, the story mentions that `fail_open` defaults are "overridden" for enforce mode. The config override mechanism must be tightly controlled.

**DPO Requirement DR-3**: 
1. The `fail_mode` config field must be `*string` (R-024 fix) — if explicitly set to `"fail_open"` in enforce mode, the config validation must REJECT with an error at startup. Enforce mode and fail-open are fundamentally incompatible — fail-open would silently leak PII.
2. The vault unavailability path must NEVER fall through to a raw-body-forwarding path. Every code path that touches the vault must have an explicit error return that results in 502.
3. The vault failure log entry must include `pii_values_logged: false` and must NOT contain the PII values that would have been written.

### 5.4 Risk: Async channel overflow → silent mapping loss (LOW)

**R-013** documents that under extreme load, the vault's async write buffer (1024 entries) can overflow. When it overflows, the mapping is dropped (WARN logged), and the proxy continues in memory-only mode. PII does not leak, but the mapping is not persisted. If the user subsequently closes the browser, old conversations show unrehydrated tokens.

**DPO Requirement DR-4**: The overflow warning must:
1. NOT contain any PII values or token values — only counters and the fact that writes were dropped
2. Include `pii_values_logged: false`
3. Be logged at WARN level
4. Include the number of dropped writes since the last such warning
5. Be rate-limited (at most one per minute) to avoid log flooding

### 5.5 Risk: PII in `ReplaceAttr` / structured log fields (HIGH)

ADR-008 already establishes that logs must never contain PII values. The `monitor_scan` format with `pii_values_logged: false` is in place. This sprint adds `tokenized_count` and `rehydrated_count` fields. These are counts — safe. But the enforce interceptor also logs errors and warnings that could inadvertently include PII values.

**DPO Requirement DR-5**: Every log call in the new code paths (`EnforceInterceptor`, `replaceSegments`, SSE rehydration, sliding buffer, vault wiring) must:
1. Set `pii_values_logged: false` when the log relates to PII processing
2. NEVER include raw request/response body content, even in DEBUG level
3. NEVER include tokenized/rehydrated text, PII values, or tokens in log attributes
4. Use only sanitized metadata: entity types, counts, byte positions, path segments, provider names
5. The sliding buffer overflow/reset path must be especially careful — the buffer content (partial tokens) must NOT be logged

### 5.6 Risk: Config `pii_logging` flag dead code (MEDIUM)

**R-029** documents that `pii_logging: false` was parsed but had no runtime effect. **R-024** (being fixed this sprint) makes `PIILogging *bool` so `false` is distinguishable from "not set." This sprint must breathe life into this flag.

**DPO Requirement DR-6**: 
1. When `pii_logging` is `false` (explicitly or by default), `entity_summary` must NOT appear in any `monitor_scan` log entry.
2. When `pii_logging` is `true` (explicitly set by operator), `entity_summary` MAY appear.
3. The `EnforceInterceptor` must respect the `pii_logging` flag identically to how `MonitorInterceptor` and `ProviderInterceptor` respect it.
4. Add a startup INFO log: `pii_logging` is `true` — "PII entity type counts will appear in logs. This is metadata only; PII values are never logged."

### 5.7 Risk: `valueToToken` map — PII keys on non-mlocked Go heap (MEDIUM)

**R-017** documents this inherited risk. The `valueToToken` map in the tokenizer stores PII values as map keys on the standard Go heap, outside the mlocked memory arena. A process swap file (pagefile.sys on Windows) could contain these keys in plaintext.

**DPO Requirement DR-7**: This risk is accepted for V1. However, the sprint must:
1. Retain the existing WARNING comment on `valueToToken` ("map keys contain raw PII. Never log, serialize, or print this field.")
2. Ensure no code path in the enforce pipeline serializes, logs, or copies `valueToToken` entries
3. The vault wiring in `handleMITM` must not expose the tokenizer's internal maps to the connection context — only the tokenizer instance itself (which controls its own locking)

### 5.8 Risk: Per-user vault.db not cleaned on uninstall (MEDIUM)

**R-031** documents that the MSI uninstaller runs as SYSTEM and cannot enumerate user profiles to clean per-user vault databases. After uninstall, vault.db and vault.key persist in `%LOCALAPPDATA%\Qindu\`.

**DPO Requirement DR-8**: This is accepted for V1. The sprint must:
1. Document this limitation in the vault creation log: "vault data persists after MSI uninstall — manual cleanup required"
2. The log line must use `pii_values_logged: false`

### 5.9 Risk: SeImpersonatePrivilege GPO revocation → denial of service (MEDIUM)

**R-033** documents that if a GPO revokes `SeImpersonatePrivilege` from the service account, all connections will be denied (fail-closed). This is a privacy-safe failure mode (PII never leaks), but it's a denial of service.

**DPO Requirement DR-9**: The sprint must:
1. At agent startup, detect whether `SeImpersonatePrivilege` is present (inherited requirement from QINDU-0008)
2. If absent, log a WARNING: "SeImpersonatePrivilege not available — per-user vault isolation disabled, all connections will be rejected in enforce mode"
3. The log entry must include `pii_values_logged: false`

---

## 6. Blocking Points

### BLOCK-1: Blind rehydration in responses without surgical extraction ⚠️

**Severity**: MEDIUM

The story's DD-3 and DD-4 specify blind `Rehydrate()` on the full response body and on SSE frame `data:` payloads. While the story does mention the `ResponseTextExtractor` interface as an optional optimization, blind rehydration without context awareness is a privacy regression from the ProviderInterceptor's surgical text extraction approach.

**Resolution required**: The `EnforceInterceptor` must implement segment-aware rehydration using `ResponseTextExtractor` when available. Blind rehydration on the entire body is acceptable only as a fallback when no extractor is available, and must be accompanied by a WARN log entry.

**GDPR basis**: Art. 25 (data protection by design) — the system should, by default, limit PII processing to the minimum necessary. Blindly rehydrating tokens in metadata fields where PII may appear in UI contexts not intended for it constitutes unnecessary processing.

**NOT BLOCKED** — The story already includes DD-11 establishing the `ResponseTextExtractor` interface and states the ChatGPT plugin will implement it. I accept that the interface is available and will be used. My requirement DR-1 ensures surgical rehydration is the primary path.

### BLOCK-2: Request chunking evasion accepted (R-004) ⚠️

**Severity**: LOW (for this sprint)

**R-004** documents that PII split across HTTP request chunks is not detected. QINDU-0010 resolves this for SSE responses via sliding buffer, but request chunking evasion remains unaddressed.

**Resolution**: NOT BLOCKED — R-004 is accepted for V1. The SSE sliding buffer resolves response-side chunk evasion. Request chunking (PII split across chunks in the outbound request body) remains a gap. Document as an accepted risk in this sprint's DPO review notes. Full request-chunk reassembly requires a sprint-level effort (buffer all chunks before detection — conflict with the no-buffering architectural constraint).

---

## 7. Required Privacy Tests

These tests must pass before DPO will sign off on the implementation review:

### PT-ENF-1: Zero PII in outbound request after tokenization
- Send a request containing `john@example.com` through the enforce pipeline
- Verify the request body written to upstream contains `<<EMAIL_1>>` and does NOT contain `john@example.com`
- Verify token→value mapping exists in memory store

### PT-ENF-2: Zero PII in vault.db without vault.key
- After enforcing a request with PII, read vault.db directly
- Verify the file is a bbolt database that is unreadable (AES-256-GCM encrypted) without vault.key
- Verify vault.key permissions are 0600 (Unix) or ACL-restricted (Windows)

### PT-ENF-3: Full rehydration round-trip (non-streaming)
- Tokenize `"My email is john@example.com"` in request
- Create a mock response body containing `"You said your email is <<EMAIL_1>>"`
- Run through `EnforceInterceptor.InterceptResponse`
- Verify response contains `"You said your email is john@example.com"`
- Verify `rehydrated_count: 1` in monitor_scan

### PT-ENF-4: Full rehydration round-trip (SSE with sliding buffer)
- Tokenize PII in request
- Feed SSE chunks containing tokens split across chunk boundaries: chunk 1: `"Your email: <<EMA"`, chunk 2: `"IL_1>> is registered"`
- Verify sliding buffer reassembles `<<EMAIL_1>>` and rehydrates to the original PII value
- Verify browser receives `"Your email: john@example.com is registered"`

### PT-ENF-5: Fail-closed on vault unavailability
- Simulate vault creation failure (e.g., invalid path, disk full)
- Verify connection is rejected with HTTP 502
- Verify the error log contains `pii_values_logged: false`
- Verify no PII leaves the machine un-tokenized (request is never forwarded)

### PT-ENF-6: Log sanitization — zero PII values
- Run the enforce pipeline with a prompt containing `john@example.com`
- Grep all log output for the string `john@example.com`
- Verify zero matches
- Verify all PII-related log entries contain `"pii_values_logged": false`

### PT-ENF-7: Conversation isolation
- Tokenize `john@example.com` in Conversation A
- Tokenize `jane@example.com` in Conversation B
- Verify Conversation A's `<<EMAIL_1>>` rehydrates to `john@example.com` (not `jane@example.com`)
- Verify Conversation B's `<<EMAIL_1>>` rehydrates to `jane@example.com` (not `john@example.com`)
- Verify vault scopes are different for the two conversations

### PT-ENF-8: Metadata field exclusion (ResponseTextExtractor)
- Create a response body where metadata fields contain token-like patterns but no real tokens
- Verify `ResponseTextExtractor` correctly identifies user-content segments
- Verify rehydration only affects user-content segments, not metadata fields

### PT-ENF-9: Unknown token pass-through
- Feed a response containing `<<EMAIL_999>>` (token not in store)
- Verify the token passes through unchanged (no substitution, no error)

### PT-ENF-10: Async channel overflow WARN
- Generate enough concurrent tokenizations to fill the 1024-entry vault write buffer
- Verify a WARN log is emitted when writes are dropped
- Verify the WARN contains `pii_values_logged: false` and does NOT contain PII values
- Verify the proxy continues operating (memory-only mode, no crash)

### PT-ENF-11: Config validation rejects fail_open in enforce mode
- Set `agent.mode: enforce` and `agent.fail_mode: fail_open`
- Verify config validation returns an error at startup
- Verify the proxy does NOT start

### PT-ENF-12: `pii_logging` flag respected in enforce mode
- Set `pii_logging: false`
- Run enforce pipeline with PII
- Verify `entity_summary` is absent from monitor_scan logs
- Set `pii_logging: true`
- Verify `entity_summary` is present (type counts only, never values)

### PT-ENF-13: Vault persistence survives tokenizer lifecycle
- Tokenize PII, verify vault write
- Close the tokenizer (end of connection)
- Create a new tokenizer with the same vault scope
- Verify the new tokenizer can rehydrate tokens from the old session

### PT-ENF-14: ReplaceSegments handles length changes
- Verify `replaceSegments(body, segments)` correctly replaces PII with tokens even when token length differs from PII length (both shorter and longer tokens)
- Verify no byte offset corruption or JSON structure damage
- Test with PII at the start, middle, and end of the body

### PT-ENF-15: SSE degraded mode — no PII in rehydration fallback
- Simulate a plugin panic during SSE handling
- Verify the degraded mode fallback does not leak PII
- Verify the degraded mode still correctly rehydrates tokens in raw SSE data

---

## 8. Inherited DPO Tests from QINDU-0008 (Integration Verification)

These 12 tests were unit-tested at library level in QINDU-0008. They must be verified at integration level in this sprint:

| Test | Integration verification |
|---|---|
| **PT-1** | vault.db unreadable without vault.key — verify with actual vault.db file created during integration test |
| **PT-2** | vault.key permissions — verify on the actual Windows VM (not just unit test mock) |
| **PT-3** | Startup sweep purges expired conversations — verify after setting TTL to 1s and restarting |
| **PT-4** | Background sweeper runs on schedule — verify with TTL=1h, wait, check bbolt content |
| **PT-5** | Access-time check purges expired conversation — verify by accessing then waiting |
| **PT-6** | No PII in bbolt keys — verify by inspecting bbolt with hex viewer on actual vault.db |
| **PT-7** | Log messages with `pii_values_logged: false` contain zero PII |
| **PT-8** | Paths in log messages are redacted — no usernames in filesystem paths |
| **PT-9** | SID lookup failure closes connection (fail-closed) |
| **PT-10** | Per-user vault isolation — two users, two vaults, no cross-access |
| **PT-11** | Async channel backpressure doesn't silently drop PII — covered by PT-ENF-10 |
| **PT-12** | Graceful shutdown drains all pending writes |

---

## 9. Config-Related Privacy Requirements

### CR-1: R-024 Bool Pointer Migration
- `LoggingConfig.PIILogging`: `bool` → `*bool`
- `TLSConfig.CertCacheEnabled`: `bool` → `*bool`
- `AgentConfig.FailMode`: `string` → `*string`
- `MergeFileOverride()` must correctly distinguish "not set" (nil) from "explicitly set to false" (`*false`)

### CR-2: Enforce Mode Fail-Closed Hardening
- `FailMode` default for enforce mode is `"fail_closed"`, regardless of config
- If config explicitly sets `fail_mode: "fail_open"` in enforce mode, reject at startup
- `FailMode` default for monitor/transparent mode remains `"fail_open"` (backward compatible)

### CR-3: Vault TTL Validation
- Vault TTL must continue to validate against the whitelist: `"0"`, `"24h"`, `"168h"`, `"720h"`
- `"0"` (infinite) must log a WARNING at startup in enforce mode (PII retention without expiration)

---

## 10. Verdict and Conditions

### Verdict: PASS

The sprint design is privacy-sound. The critical safeguards are in place:
- Tokenization before egress prevents PII from reaching AI providers
- Fail-closed behavior prevents silent PII leakage when vault is unavailable
- Conversation scoping prevents cross-conversation PII injection
- Log sanitization with `pii_values_logged: false` is carried forward from previous sprints
- The R-024 config fix addresses the silent override bug that could mislead operators about PII logging

### Conditions (must be verified in implementation review):

1. **DR-1**: `EnforceInterceptor` must use `ResponseTextExtractor` for surgical rehydration when available; blind rehydration on full body only as WARN-logged fallback
2. **DR-2**: Conversation UUID must use cryptographic hash (SHA-256) + `crypto/rand` fallback
3. **DR-3**: Config must reject `fail_open` in enforce mode; every vault error path must result in 502 (never raw forward)
4. **DR-5**: Zero PII values in any log output across all new code paths (verify with grep in implementation review)
5. **DR-6**: `pii_logging` flag must actually control `entity_summary` in enforce mode log output
6. **PT-ENF-1** through **PT-ENF-15**: All 15 privacy tests must pass
7. **PT-1** through **PT-12**: Inherited tests must pass at integration level

### Accepted Risks (carried forward):

| Risk | ID | Reason |
|---|---|---|
| Chunking evasion (request side) | R-004 | Accepted for V1. SSE response resolved. Full request-chunk reassembly requires architectural change (buffering). |
| Core dump PII exposure | R-005 | Go runtime limitation. Not fixable without custom allocators or encrypted memory. |
| valueToToken PII keys on Go heap | R-017 | Accepted trade-off. Resolution (dedup-by-hash) deferred to future sprint. |
| Per-user vault.db not cleaned on uninstall | R-031 | MSI limitation. Documented in vault creation log. |
| IBAN/IP_ADDRESS not detected | R-023 | Gap in PII engine. Not in scope for this sprint. |

### Referenced ADRs:
- **ADR-002**: CONNECT MITM architecture — the `handleMITM` wiring point for vault
- **ADR-004**: Interceptor interface — `EnforceInterceptor` must implement `proxy.Interceptor`
- **ADR-008**: Structured logging JSON sans PII — `pii_values_logged: false` must appear in every PII-related log entry

### Referenced Risks:
- **R-004, R-005, R-009, R-013, R-017, R-023, R-024, R-031, R-033** — all inherited by this sprint per the backlog `risks_inherited` field
