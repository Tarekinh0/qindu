# CISO Requirements — QINDU-0006: Tokenisation

**Agent**: qindu-ciso (Chief Information Security Officer)
**Date**: 2026-07-03
**Verdict**: APPROVED_WITH_RECOMMENDATIONS

---

## 1. Attack Surface

### 1.1 New Attack Surface

| ID | Surface | Description | Risk |
|----|---------|-------------|------|
| AS1 | **Token↔PII in-memory mapping** | A Go `map[string]string` (or equivalent) storing `<<TYPE_N>> → raw PII value`. Unencrypted, process-local. Any code path with a reference to the tokenizer can read all PII in the conversation. | HIGH — primary target for memory scraping |
| AS2 | **Rehydration interface** | `rehydrate(text string) string` — accepts AI response text and substitutes tokens back to PII. The sole mechanism by which external (AI-generated) content triggers local PII disclosure. | HIGH — input from untrusted source (AI service) |
| AS3 | **Tokenizer API surface** | Public functions `tokenize(text string) (string, error)` and `rehydrate(text string) string`. These are the ingress/egress points for all PII processing. | MEDIUM — API misuse could bypass protections |
| AS4 | **Token format `<<TYPE_N>>`** | The substitution string format. If the regex for detecting tokens during rehydration is broader than the tokenizer's output format, injection opportunities open. | MEDIUM — format mismatch between tokenize and rehydrate |
| AS5 | **Text substitution engine** | The byte-offset-based replacement algorithm operating right-to-left. Incorrect implementation can leave PII fragments in tokenized output. | CRITICAL — directly violates the core privacy guarantee |
| AS6 | **Conversation lifecycle** | Token counters and mappings are scoped per conversation. If the scope boundary is fuzzy or the API allows accidental cross-conversation retention, PII from Conversation A could leak into Conversation B. | MEDIUM — cross-conversation contamination |
| AS7 | **Error handling paths** | Error messages, panics, or debug output that inadvertently include Entity.Value, mapping contents, or tokenized text. | HIGH — permanent data breach via logs |
| AS8 | **Concurrent access to mapping** | Multiple goroutines reading/writing the mapping simultaneously. Race conditions can map the wrong PII to a token, causing cross-entity PII leakage during rehydration. | CRITICAL — wrong PII presented to user |
| AS9 | **Memory pages in OS swap/pagefile** | The Go heap pages containing the token↔PII mapping can be paged out to disk by the OS virtual memory manager (pagefile.sys on Windows, swap partition on Linux). PII values are stored as plaintext Go strings in those pages. Once swapped, PII persists on disk after process termination and is recoverable via forensic analysis. | HIGH — PII on disk unencrypted, survives process lifetime |

### 1.2 Modified Attack Surface

None. The `internal/pii/` package is consumed as-is (story.md forbids modification). The Engine, Entity, Recognizer, and overlap resolution are read-only dependencies of the tokenizer.

---

## 2. Protected Assets

| Asset | Classification | Storage Location | Exposure Window |
|-------|---------------|-----------------|-----------------|
| Raw PII values (`Entity.Value`) | **PII — Highest sensitivity** | On the call stack during detection/tokenization; persisted in the in-memory mapping | From detection until process termination or GC of unused entries |
| Token↔PII mapping entries | **PII — Highest sensitivity** | In-memory `map[string]string` within the tokenizer struct | Conversation lifetime (process termination = destruction). **Without SR-18, extends beyond process termination**: swapped pages persist in pagefile/swapfile until overwritten by other disk activity. SR-18 (memory locking) mitigates this by preventing the mapping pages from being swapped. |
| Tokenized text (output of `tokenize`) | **Metadata — Medium sensitivity** | In memory; transmitted to AI service over TLS | From tokenization until GC; persists on AI service side indefinitely |
| Token counters (per-type integers) | **Metadata — Low sensitivity** | Stack/struct field within tokenizer | Conversation lifetime |
| Entity type constants (`EMAIL`, `PHONE`, etc.) | **Non-sensitive — Configuration** | Compile-time constants in `internal/pii/entity.go` | Permanent (compile-time) |
| Conversation scope boundary | **Privacy boundary** | Defined by tokenizer instance lifecycle | Instance creation to garbage collection |

---

## 3. Threat Model (STRIDE-LM)

### 3.1 Spoofing

| ID | Threat | Attack Vector | Impact | Mitigation |
|----|--------|--------------|--------|------------|
| **S1** | **Token text masquerading as real token** | User input contains literal `<<EMAIL_1>>` text (e.g., in a code example). The tokenizer may or may not detect it as PII first (QINDU-0005 recognizers are applied before tokenization by the Engine). The rehydrator must correctly handle both cases: if the Engine detected it as an EMAIL entity, it gets tokenized to `<<EMAIL_N>>`; if not detected, the literal `<<EMAIL_1>>` survives into the tokenized output and must NOT be interpreted as a token by the rehydrator. | Medium — double-substitution or spurious rehydration | The rehydrator must match tokens ONLY against the in-memory mapping. A literal `<<EMAIL_1>>` that entered via user text has no mapping entry and must pass through unchanged (AC #5). |
| **S2** | **AI service crafts token-containing response** | AI response includes `<<EMAIL_1>>` to force rehydration of PII into a specific context. The AI service never sees the rehydrated output (rehydration is local-only), so this is NOT a data exfiltration vector. However, it IS a content integrity risk: the AI can structure its response so that restored PII appears in misleading or harmful contexts. | Low — content manipulation, not data theft | The rehydrator must only resolve tokens present in the local mapping (AC #5, AC #7). The AI cannot inject new tokens — it can only reference tokens previously sent to it. The user chose to share the tokenized PII. This is an inherent property of the tokenization model. |

### 3.2 Tampering

| ID | Threat | Attack Vector | Impact | Mitigation |
|----|--------|--------------|--------|------------|
| **T1** | **Mapping corruption via race condition** | Two goroutines concurrently call `tokenize()` — Goroutine A maps `<<EMAIL_1>>` to `alice@example.com`, Goroutine B maps `<<EMAIL_1>>` to `bob@example.com` due to unsynchronized counter increment. | Critical — wrong PII rehydrated into browser | `sync.RWMutex` (or `sync.Mutex`) on all mapping reads/writes. `go test -race` must pass. AC #6 requires concurrent safety. |
| **T2** | **Token counter divergence** | A bug causes the per-type counter to skip values or reset mid-conversation, creating mapping gaps. Rehydration resolves `<<EMAIL_3>>` to the PII that should be at `<<EMAIL_2>>`. | High — wrong PII rehydrated | Counters must be monotonically increasing per-type within a conversation. Unit tests must verify counter determinism (AC #6). |
| **T3** | **Entity offset corruption** | The right-to-left replacement algorithm mutates the byte offsets of earlier entities during substitution if implemented incorrectly (left-to-right). | Critical — PII fragments in tokenized output | Behavioral rule #3 mandates right-to-left replacement. Must be tested with adjacent entities, entities at text boundaries, and entities whose token is longer/shorter than the original. |
| **T4** | **Entity slice mutation** | If the tokenizer sorts or mutates the `[]Entity` slice from `Engine.Detect()`, it could alter the relative order of entities, causing wrong substitutions. | Medium — wrong spans replaced | The tokenizer must treat `Engine.Detect()` output as read-only. Any reordering must be done on a copy. |

### 3.3 Repudiation

Low relevance for this sprint. No persistence, no auditing, no user accounts. Process termination is the sole audit boundary. **No action required.**

### 3.4 Information Disclosure

| ID | Threat | Attack Vector | Impact | Mitigation |
|----|--------|--------------|--------|------------|
| **I1** | **PII in log/error output** | `log.Info("tokenized value", "email", entity.Value)`, `fmt.Errorf("failed to tokenize %s", raw)`, `panic(entity)`, or any `%v`/`%s` format applied to Entity or mapping data. | Critical — PII permanently recorded in log files, CI artifacts, console output | ADR-008 compliance mandatory. Entity already has `json:"-"` on Value plus `SafeString()` and `String()` overrides. Tokenizer must extend this to mapping entries, counters, and tokenized text. Code audit required (DPO R4). |
| **I2** | **Memory dump exposure** | Process crash dump, debugger attachment, or `/proc/self/mem` read exposes the in-memory mapping containing raw PII. | High — all conversation PII readable | Accepted risk per backlog R-005. No encryption in this sprint. QINDU-0008 adds DPAPI-encrypted vault. Full mitigation requires in-memory encryption (future). |
| **I3** | **Token metadata leakage to AI service** | The `<<TYPE_N>>` format reveals entity type (EMAIL vs CREDIT_CARD vs SECRET) and per-type count to the AI provider. | Low — metadata, not PII values | Inherent in the `<<TYPE_N>>` design. Necessary for AI semantic understanding. Accepted (DPO R2 assessment, DPO Risk R2). |
| **I4** | **Go string memory sharing** | Go's `string` type may share backing arrays. If the tokenized output string shares memory with a PII value string (e.g., via substring slicing), PII could persist in the "clean" tokenized string's memory region. | Very Low — local process memory, no egress risk | Accepted. The `<<TYPE_N>>` format makes accidental sharing unlikely. This is a Go runtime property, not an application bug. |
| **I5** | **Token mapping in test output** | Test assertions that print mapping contents (`t.Logf("map: %v", mapping)`) leak synthetic PII into test logs and CI output. Even synthetic data sets a bad precedent. | Medium — training data for bad habits; risk of real PII in future | Tests must log only redacted representations. Assertions on mapping contents should compare specific entries, not dump the entire map. |
| **I6** | **Error messages during rehydration** | `rehydrate()` errors that include the input text (AI response) or the matched token could leak the token↔PII association into logs. | Medium — partial PII exposure | Error paths must use safe messages: `"token <<EMAIL_99>> not found in conversation"` (acceptable — reveals a token exists in the text but not in the mapping) vs `"failed to rehydrate <<EMAIL_1>> (alice@example.com)"` (unacceptable — reveals the PII value). |
| **I7** | **Memory swap leakage via OS pagefile/swapfile** | The OS virtual memory manager swaps rarely-used or memory-pressure-evicted pages to disk (pagefile.sys on Windows, swap partition on Linux). Since the token↔PII mapping stores raw PII values as Go `string` types in the heap, those string contents are plaintext in memory. When swapped, PII exists in plaintext on disk — surviving process termination — and can be recovered via forensic tools (e.g., `volatility`, `strings pagefile.sys`). This bypasses the "in-memory only" guarantee because swapped pages are literally on disk. | **HIGH — PII on disk unencrypted, recoverable post-mortem** | Lock memory pages containing the PII mapping to prevent OS swapping. Windows: `VirtualLock()` (requires `SeLockMemoryPrivilege`, available to admin-elevated processes). Linux (CI/testing): `mlockall(MCL_CURRENT | MCL_FUTURE)` (requires `CAP_IPC_LOCK`). See SR-18. |

### 3.5 Denial of Service

| ID | Threat | Attack Vector | Impact | Mitigation |
|----|--------|--------------|--------|------------|
| **D1** | **Unbounded mapping growth** | Long-running conversation with many unique PII values causes the mapping to grow without bound, exhausting heap memory. | High — process crash, OOM kill | The 1 MiB per-message bound limits PII count per request, but a conversation with thousands of messages can accumulate entries. Accepted for this sprint (DPO R10, process termination is the natural bound). **Recommendation**: Consider a configurable mapping cap (e.g., 10,000 entries) with LRU eviction or graceful error on overflow. Mandatory for QINDU-0008. |
| **D2** | **ReDoS via malicious token-like text** | An AI response containing a crafted string like `<<<<<<<<<<...>>>` (deeply nested angle brackets) could cause catastrophic backtracking if the rehydrator regex is poorly designed. | Medium — goroutine hangs, CPU exhaustion | The token-matching regex must use a strict, linear-time pattern: `<<(EMAIL\|PHONE\|IBAN\|CREDIT_CARD\|JWT\|NAME\|SECRET\|PRIVATE_KEY)_\d+>>`. No backreferences, no nested quantifiers. Must be tested with worst-case inputs. |
| **D3** | **Entity explosion** | A text near the 1 MiB bound containing thousands of overlapping PII entities (before overlap resolution) could cause O(n²) behavior in the substitution algorithm. | Low — Engine overlap resolution limits final entity count | The tokenizer processes the `[]Entity` returned by `Engine.Detect()`, which is already deduplicated by overlap resolution. The entity count post-resolution is bounded by text length divided by minimum entity size. |
| **D4** | **Token counter overflow** | If `N` is an `int` or `uint`, a conversation with billions of unique entities of the same type could overflow the counter. | Very Low — requires ~2³¹ unique entities of one type | Use `uint64` for counters. Even in the worst case (minimum PII length ~5 bytes, 1 MiB input, repeated max-size inputs), this would require ~4.3 × 10⁹ unique 1 MiB inputs to overflow a `uint32`. Use `uint64` for defense-in-depth. |

### 3.6 Elevation of Privilege

Low relevance. The tokenizer is a Go package consumed by the proxy; there is no service boundary, no authentication, no privilege separation within the process. The proxy process runs as the local user. **No action required.**

---

## 4. Blocking Security Requirements (SR-*)

These requirements MUST be satisfied for the CISO review gate to PASS. They are binding constraints on the implementation.

### SR-1 — Zero PII in Tokenized Output (CRITICAL)

**Statement**: The tokenized text must contain absolutely no raw PII values. Every entity detected by the Engine must be fully and correctly replaced by its `<<TYPE_N>>` token.

**Rationale**: This is the fundamental security property. Any PII in the tokenized output egresses to the AI service. Failure here is a data breach.

**Validation criteria**:
- Automated test that feeds text containing all 8 entity types through `tokenize()`.
- Scan the output with the same `Engine.Detect()` recognizers — must return zero entities.
- Scan the output with raw regex patterns for all 8 types — must return zero matches.
- Verify right-to-left replacement correctness with entities at positions [0,5], [5,10], [10,15], adjacent entities, and entities at start/end of text.

**OWASP ASVS mapping**: V7.3.1 (output encoding), V9.1.1 (data protection in transit)

---

### SR-2 — Token Format Contains Zero Encoded PII (CRITICAL)

**Statement**: The token string `<<TYPE_N>>` must not encode, hash, embed, derive from, or correlate with the PII value in any way. The token string MUST be a pure concatenation of `<<`, uppercase `EntityType.String()`, `_`, integer counter, `>>`.

**Rationale**: A token that encodes PII (e.g., base64, hex, hash prefix) would leak information to the AI service. Behavioral rule #4.

**Validation criteria**:
- Code audit: the token generation code path must reference ONLY `Entity.Type` and a counter, NEVER `Entity.Value`.
- Test: two different PII values of the same type and same ordinal position produce identical token strings.
- Test: the token string, when base64-decoded, hex-decoded, or otherwise reversed, does not reveal any PII substring.
- Tokenizer must use the EntityType's `String()` method (default) or the constant directly — never a custom mapping that could leak type semantics through encoding.

**OWASP ASVS mapping**: V6.2.5 (token generation), V7.2.1 (no sensitive data in URL/params)

---

### SR-3 — No PII in Logs, Errors, or Debug Output (CRITICAL)

**Statement**: The tokenizer must never log, print, write to stderr/stdout, include in error messages, or expose through panics:
- Raw PII values (`Entity.Value`, mapping values)
- Tokenized text (input or output)
- Token↔PII mapping entries (keys or values)
- Any substring or derivative of the above

Acceptable to log (per ADR-008): entity counts by type, input size, timing, error types (without PII), and `Entity.SafeString()` representations.

**Rationale**: ADR-008 compliance. Accidental PII in logs is a permanent data breach. Consistent with QINDU-0005 discipline.

**Validation criteria**:
- Grep the tokenizer package for `Value`, `entity.Value`, `%s`/`%v` applied to Entity or mapping data.
- Grep for `log.`, `slog.`, `fmt.Print`, `fmt.Sprintf`, `panic`, and error creation sites.
- Every error message must be inspected: no raw text input, no tokenized text, no mapping entries.
- Test: all error paths produce error messages that, when scanned by QINDU-0005 recognizers, yield zero entities.

**OWASP ASVS mapping**: V7.1.1 (no sensitive data in logs), V7.4.1 (error handling without information leakage)

---

### SR-4 — Concurrent Safety (CRITICAL)

**Statement**: The tokenizer's in-memory state (mapping, counters) must be safe for concurrent access from multiple goroutines. Tokenization and rehydration may be called concurrently (different HTTP requests interleaved). Data races are unacceptable.

**Rationale**: A data race in the mapping could cause:
- Token `<<EMAIL_1>>` mapping to the wrong PII value (cross-entity leakage)
- Counter corruption (duplicate tokens mapping to different PII)
- Go race detector panic (process crash)

AC #6 requires concurrent safety.

**Validation criteria**:
- `go test -race ./...` must pass with zero detected races.
- Test: spawn 10+ goroutines concurrently calling `tokenize()` and `rehydrate()` with overlapping data.
- Test: concurrent writes to the same entity type counter from multiple goroutines must produce unique, monotonically assigned tokens.
- Implementation must use `sync.RWMutex` or `sync.Mutex`. `sync.Map` is NOT sufficient because counters require atomic read-modify-write.
- The mapping AND counters are a single logical unit — they must be protected by the same mutex.

**OWASP ASVS mapping**: V1.6.2 (concurrent access controls), V11.1.1 (thread safety)

---

### SR-5 — Partial Token Pass-Through (HIGH)

**Statement**: During rehydration, token-like strings in the response that do NOT match any entry in the mapping must be left unchanged. The rehydrator must not:
- Strip them (losing information)
- Replace them with empty strings
- Return an error
- Panic

**Rationale**: AC #5. The AI service could include token-like text in code examples, documentation, or responses. Stripping them would corrupt the AI response. Returning an error would allow the AI to probe the mapping (timing side-channel). Panicking would DoS the proxy.

**Validation criteria**:
- Test: `rehydrate("<<EMAIL_99>> Hello")` → `"<<EMAIL_99>> Hello"` when mapping only contains `<<EMAIL_1>>`.
- Test: `rehydrate("<<UNKNOWN_1>>")` → `"<<UNKNOWN_1>>"` — non-existent entity type.
- Test: `rehydrate("<<<<not a token>>>>")` → `"<<<<not a token>>>>"` — malformed.
- Test: `rehydrate("Hello << world >>")` → `"Hello << world >>"` — spacing.
- Behavior must be identical (timing, error) for "no such token" and "not a token pattern at all" — no oracle.

**OWASP ASVS mapping**: V5.1.4 (input validation bypass prevention), V11.1.2 (error handling without oracle)

---

### SR-6 — Token Injection Resistance (HIGH)

**Statement**: The rehydrator must validate tokens against a strict format before performing map lookups. The regex for matching tokens must be exactly as strict as the tokenizer's output format — no broader.

**Rationale**: A loose regex (e.g., `<<.+>>`) would match arbitrary text in AI responses, triggering unnecessary map lookups and potentially causing unexpected behavior. A strict regex (`<<(known_type)_\d+>>`) ensures only legitimate tokens trigger rehydration.

The rehydrator must also ensure that a non-existent token (`<<EMAIL_99999>>` — valid format, not in map) and an invalid token (`<<<malformed>>>`) produce identical external behavior (no error, pass-through). Any differential behavior (different error, timing, log message) could serve as an oracle.

**Validation criteria**:
- The rehydrator regex must match EXACTLY `<<(EMAIL|PHONE|IBAN|CREDIT_CARD|JWT|NAME|SECRET|PRIVATE_KEY)_\d+>>`.
- Entity types must be validated against the known `EntityType` constants from `internal/pii/`.
- No regex-based substitution (e.g., `regexp.ReplaceAllStringFunc`) that could be vulnerable to injection. Prefer a scanner/parser over regex substitution for correctness.
- Test: high-volume of non-token `<<like this>>` patterns in input must not degrade performance or produce errors.

**OWASP ASVS mapping**: V5.1.1 (input validation for all parameters), V5.3.3 (regex safety)

---

### SR-7 — Input Validation and Bounds Checking (HIGH)

**Statement**: The tokenizer must validate all inputs before processing.

**Requirements**:
1. **Size bound**: Inputs exceeding 1 MiB must be rejected via `Engine.Detect()` (pass-through to Engine, which already enforces this bound). The tokenizer must not bypass, re-implement inconsistently, or relax this bound.
2. **Empty input**: Zero-length or whitespace-only input must produce zero-length output with no error.
3. **Nil/boundary**: Empty `[]Entity` from Engine (no PII detected) must produce the original text unchanged.
4. **Token counter integrity**: The tokenizer must not overflow or underflow counters. Use `uint64` for defense-in-depth.
5. **Entity validation**: Before processing, verify that `Entity.Start < Entity.End`, `Entity.End <= len(input)`, and that the `Entity.Type` is a valid `EntityType`. Malformed entities from Engine (should not happen, but defense-in-depth) must not cause panics or incorrect substitution.

**Rationale**: AC #9, AC #7. Input validation is the first line of defense. The tokenizer operates on data from the Engine, which operates on user-provided text — defense-in-depth at every layer.

**Validation criteria**:
- Test: input of 1 MiB + 1 byte → error of type `ErrInputTooLarge`, error message contains only sizes, zero PII patterns.
- Test: empty string, whitespace-only string, `\n\t  ` → all return empty/unchanged with no error.
- Test: input with no PII → returns byte-for-byte identical text.
- Test: entity with `Start > End` → graceful handling (skip entity, log warning with SafeString).
- Test: counter overflow scenario (theoretical, but code path should exist).

**OWASP ASVS mapping**: V5.1.1 (input validation), V5.1.2 (size limits), V5.1.4 (malformed input handling)

---

### SR-8 — Deterministic and Idempotent Tokenization (HIGH)

**Statement**:
1. **Determinism**: The same PII value encountered multiple times within a conversation must produce the same token every time.
2. **Idempotency**: `tokenize(tokenize(text))` must produce the same output as `tokenize(text)`. The tokenizer must not attempt to detect and re-tokenize its own `<<TYPE_N>>` output.

**Rationale**: Behavioral rules #1 and #5, AC #6. Non-deterministic tokenization breaks the round-trip guarantee. Double-tokenization (tokens being re-detected as PII) would create nested tokens like `<<EMAIL_<<EMAIL_1>>>`.

**Validation criteria**:
- Test: `tokenize("alice@example.com bob@example.com")` produces `"<<EMAIL_1>> <<EMAIL_1>>"`.
- Test: `tokenize(tokenize("alice@example.com"))` → `"<<EMAIL_1>>"` (not `"<<EMAIL_<<EMAIL_1>>>>"`).
- Test: tokenize the output of tokenize, then rehydrate — must produce the original text.
- Test: first-tokenization and re-tokenization within the same conversation produce byte-for-byte identical output (AC #6).

**How to achieve idempotency**: The most robust approach is to run `Engine.Detect()` on the raw text BEFORE tokenization. The tokenizer then substitutes spans. Re-tokenizing an already-tokenized text means `Engine.Detect()` would scan the tokenized text and may or may not detect `<<EMAIL_1>>` as PII (depending on recognizer behavior). The safest approach: the tokenizer must NOT re-apply detection to its own output — it must guard against double-processing. Alternatively, the tokenizer could track that it has already processed the text. 

**Recommendation**: The tokenizer should maintain a flag or inspect the text to determine if it's already been tokenized. However, relying on pattern detection is fragile. A cleaner design: the Engine is run on the original text, the tokenizer does the substitution, and upstream callers are responsible for calling tokenize() exactly once per text. The tokenizer's idempotency guarantee (AC #6) is about re-tokenization safety, not about being re-entrant.

**OWASP ASVS mapping**: V6.2.5 (token predictability within session), V5.1.4 (double-processing prevention)

---

### SR-9 — Conversation Scope Isolation (HIGH)

**Statement**: Token counters and mappings must be strictly scoped to a single conversation. A new conversation must start with fresh counters (starting at 1) and an empty mapping. Cross-conversation token reuse must be impossible.

**Rationale**: Behavioral rule #2. If tokens persist across conversations, an observer correlating token usage across AI sessions could profile the user's PII sharing patterns.

**Validation criteria**:
- Test: two separate tokenizer instances (representing two conversations) tokenize the same text → different token sequences (since counters start fresh).
- Test: `<<EMAIL_1>>` in Conversation A maps to `alice@example.com`; the same `<<EMAIL_1>>` in Conversation B maps to `bob@example.com` (or doesn't exist yet).
- The API must provide a clear mechanism for conversation scoping. Options: (a) each conversation creates a new tokenizer instance, or (b) the tokenizer has a `Reset()` or `NewConversation()` method that clears all state.
- If the latter, `Reset()` must be safe to call concurrently (must not race with ongoing tokenize/rehydrate calls).

**OWASP ASVS mapping**: V2.1.1 (session management), V6.2.5 (token uniqueness across sessions)

---

### SR-10 — Right-to-Left Replacement Correctness (HIGH)

**Statement**: The tokenizer must replace PII spans from rightmost (highest byte offset) to leftmost (lowest byte offset). This ensures that earlier entity offsets remain valid during replacement, regardless of whether the token string is longer or shorter than the original PII value.

**Rationale**: Behavioral rule #3. Left-to-right replacement causes offset drift: after replacing entity at position [0,20] with a 12-byte token `<<EMAIL_1>>`, entity at position [25,40] is now at position [17,32] — the substitution would target wrong bytes, potentially leaving PII fragments or corrupting adjacent text.

**Validation criteria**:
- Test: entities at positions [0,20], [25,45] — right-to-left processes [25,45] first, then [0,20], both correctly replaced.
- Test: entities at start and end of very long text (1 MiB).
- Test: PII value longer than its token (e.g., a 100-byte JWT replaced by `<<JWT_1>>` = 10 bytes) — no orphaned trailing bytes.
- Test: PII value shorter than its token (e.g., a 5-byte email `a@b.c` replaced by `<<EMAIL_1>>` = 12 bytes) — no overlap with adjacent text.
- The replacement must use byte offsets (`Entity.Start`, `Entity.End`), not rune offsets. The input text is `string` (UTF-8), and `Entity.Start`/`Entity.End` are byte offsets.
- The tokenizer must construct the output string efficiently — prefer `strings.Builder` or byte-slice manipulation. Avoid repeated string concatenation which is O(n²).

**OWASP ASVS mapping**: V7.3.1 (correct encoding/substitution), V5.1.4 (boundary handling)

---

### SR-11 — No Disk Persistence (MEDIUM)

**Statement**: The token↔PII mapping must not be written to disk in any form — no files, temporary files, SQLite, embedded databases, or `os.WriteFile`. The only storage is an in-memory Go data structure.

**Rationale**: Story.md explicitly scopes persistence to QINDU-0008. Unencrypted persistence would be a severe vulnerability (PII on disk without DPAPI).

**Validation criteria**:
- Code audit: `grep -r "os.Create\|os.WriteFile\|os.OpenFile\|ioutil.WriteFile\|database/sql\|sqlite"` in the tokenizer package returns zero results.
- The tokenizer must not import any filesystem-related packages beyond standard library string/buffer manipulation.

**OWASP ASVS mapping**: V6.1.1 (no cleartext storage), V8.3.1 (sensitive data in memory only)

---

### SR-12 — ReDoS Prevention in Token Regex (MEDIUM)

**Statement**: The regular expression for matching tokens during rehydration must be free of catastrophic backtracking vulnerabilities. It must use only linear-time constructs (character classes, grouping, alternation of fixed strings, bounded repetition).

**Rationale**: A vulnerable regex (e.g., `<<.+>>` with greedy quantifier, or nested `(<<)*`) could cause exponential backtracking on maliciously crafted input, freezing the rehydration goroutine.

**Validation criteria**:
- The regex must be: `<<(EMAIL|PHONE|IBAN|CREDIT_CARD|JWT|NAME|SECRET|PRIVATE_KEY)_\d+>>` (or equivalent compiled form).
- All quantifiers must be possessive or bounded. No `(.+)+` patterns.
- Test: rehydrate a string of 10,000 angle brackets (`<<<<<<<...>>>`) — must complete in linear time (sub-second for 10 KiB).
- Test: rehydrate a string of 10,000 repeated `<<EMAIL_1>>` — must complete in linear time.
- The regex must be compiled once (package-level `var` or `sync.Once`) and reused across all calls.
- Prefer `strings.Index` + manual parsing over regex for performance and safety, particularly for the high-frequency rehydration path. If a scanner/parser is used instead of regex, the same safety properties apply (no backtracking, linear time).

**OWASP ASVS mapping**: V5.3.3 (regex safety), V5.1.1 (input validation)

---

### SR-13 — Package Isolation (MEDIUM)

**Statement**: The tokenizer package must not modify any file in `internal/pii/`. It must use the Engine and Entity types as a consumer/dependency only.

**Rationale**: Story.md "Forbidden" section. The detection layer (`internal/pii/`) is independently tested and verified. Modifying it to suit the tokenizer would create coupling and regression risk.

**Validation criteria**:
- `git diff internal/pii/` after implementation must be empty (modulo any bug fixes approved by the orchestrator).
- The tokenizer must import `github.com/Tarekinh0/qindu/internal/pii` and use only its exported API (`Engine.Detect`, `Entity`, `EntityType` constants, `ErrInputTooLarge`, `IsInputTooLarge`).
- No new types, methods, or interfaces added to `internal/pii/` to support tokenization.

**OWASP ASVS mapping**: V1.1.1 (separation of concerns), V14.1.1 (dependency integrity)

---

### SR-14 — Synthetic Test Data Only (MEDIUM)

**Statement**: All test fixtures, test inputs, expected outputs, and test assertions must use exclusively synthetic PII.

**Rationale**: AC #10. Real PII in the repository is a permanent, public data breach. Consistent with QINDU-0005 discipline.

**Validation criteria**:
- Grep test files for patterns matching real PII (detectable by QINDU-0005 recognizers used as a linting tool).
- All emails use `@example.com`, `@test.invalid`, or other IANA-reserved TLDs.
- All phones use ITU-T reserved ranges or obviously fake patterns.
- All credit cards use standard test numbers (Visa 4111..., Mastercard 5555...).
- All names are obviously fictional.
- All secrets/keys use obviously fake prefixes (e.g., `sk-test-...` for OpenAI-format keys).
- No real PEM blocks, real JWTs, or real IBANs (use financial test suite IBANs like `DE89370400440532013000`).

**OWASP ASVS mapping**: V1.1.4 (test data management)

---

### SR-15 — Entity Type Allowlist for Rehydration (MEDIUM)

**Statement**: The rehydrator must only accept tokens whose `TYPE` component matches a known, valid `EntityType` constant from `internal/pii/`. An AI response containing `<<PASSWORD_1>>`, `<<ACCOUNT_1>>`, or any other unrecognized type must be left as-is.

**Rationale**: The tokenizer only produces tokens from the 8 known entity types. Any other `<<TYPE_N>>` in a response is either:
- Literal text from the AI (e.g., documentation snippet, code example)
- A hallucinated or malicious token injection attempt

Allowing arbitrary `<<TYPE_N>>` lookups expands the attack surface unnecessarily.

**Validation criteria**:
- The rehydrator token regex must enumerate the 8 valid types (or build the pattern dynamically from the `EntityType` constants at init time).
- Test: `rehydrate("<<PASSWORD_1>>")` → `"<<PASSWORD_1>>"` (no map lookup, pass-through).
- Test: `rehydrate("<<CUSTOM_TYPE_1>>")` → `"<<CUSTOM_TYPE_1>>"` (pass-through).
- This should be enforced by the regex itself — no map lookup for invalid types.
- The tokenizer must also validate that `Entity.Type` is one of the 8 known types before generating a token. If an unknown type somehow appears (should not happen, but defense-in-depth), the tokenizer must handle it gracefully (skip that entity, log warning with SafeString).

**OWASP ASVS mapping**: V5.1.1 (allowlist validation), V5.1.5 (input validation against known types)

---

### SR-16 — Error Handling: No Timing or Behavioral Oracle (MEDIUM)

**Statement**: All error and non-error code paths must exhibit uniform external behavior to prevent the AI service from probing the token mapping through differential responses.

**Specific requirements**:
1. **Token not in map** vs **Invalid token format**: Both must produce identical behavior — pass-through, no error logged at INFO or above. At DEBUG level, distinguish them for debugging, but DEBUG is not enabled in production.
2. **Input too large**: Must return immediately with `ErrInputTooLarge`. Must not partially process and then fail.
3. **Empty `[]Entity` from Engine**: Must return input text unchanged. Must not log a warning.
4. **Entity with zero-length span (`Start == End`)**: Must skip silently (or log at DEBUG).
5. **Nil or empty input**: Must return empty string immediately, no error.
6. **All panics must be recovered**: If the tokenizer panics (should never happen), the downstream proxy must handle it. The tokenizer itself should never panic.

**Validation criteria**:
- All code paths are tested with edge-case inputs.
- No differential timing between "valid token, not found" and "invalid token format".
- No `log.Error` or `log.Warn` for expected conditions (missing tokens, invalid formats, no PII detected).

**OWASP ASVS mapping**: V7.4.1 (uniform error handling), V11.1.2 (no information leakage through error messages)

---

### SR-17 — Memory Cleanup on Conversation End (LOW)

**Statement**: When a conversation ends, the mapping and counters must be disposed of. The tokenizer API must provide a mechanism to clear all state.

**Rationale**: While Go GC will eventually reclaim unreachable mapping entries, an explicit `Reset()` or letting the tokenizer instance go out of scope provides a clear security boundary. This prevents accidental retention of mappings beyond their intended lifetime.

**Validation criteria**:
- Either: the tokenizer is designed as a per-conversation instance (discarded when conversation ends), OR it has a `Reset()` method.
- `Reset()` must be safe to call concurrently.
- After `Reset()`, previous tokens must not resolve to any PII.

**OWASP ASVS mapping**: V6.1.3 (session termination), V8.3.4 (memory cleanup)

---

### SR-18 — Memory Locking to Prevent Swap Leakage (HIGH)

**Statement**: The tokenizer (or the proxy process at initialization) must prevent the operating system from swapping memory pages containing the token↔PII mapping to disk. This is achieved through OS-specific memory locking primitives.

**Platform-specific mechanisms**:

| Platform | Primitive | Privilege Required | Notes |
|----------|-----------|-------------------|-------|
| **Windows (production)** | `VirtualLock()` on the memory region holding the mapping | `SeLockMemoryPrivilege` (assigned to Administrators by default; Qindu runs as an admin-elevated Windows service per ARCHITECTURE.md) | Locks specific pages, not all process memory. More targeted than `mlockall`. |
| **Linux (CI/testing)** | `mlockall(MCL_CURRENT \| MCL_FUTURE)` | `CAP_IPC_LOCK` (must be granted to the test process in CI) | Locks all current and future process pages. Aggressive but appropriate for the test environment where the process is short-lived and the PII is synthetic. |

**Scope**: At minimum, the Go heap pages containing the `map[string]string` (token↔PII mapping) must be locked. Locking the entire process address space (`mlockall`) is acceptable for testing/CI but may cause memory pressure in production — a targeted `VirtualLock()` on the mapping is preferred on Windows.

**Fallback behavior**: If memory locking fails (e.g., insufficient privileges, system-imposed limit on locked pages), the tokenizer must:
1. Log a clear **WARNING**-level message: `"memory locking failed: <system error>. Token↔PII mapping may be written to pagefile/swap. See documentation."` — this message must contain **zero PII values**, zero tokenized text, and zero mapping contents.
2. Continue operating normally — a locking failure must NOT prevent the proxy from functioning. The user is warned, but the proxy remains available.
3. Not retry the lock in a tight loop or consume excessive resources attempting recovery.

**Rationale**: SR-11 forbids the tokenizer from writing the mapping to disk, but it does not prevent the OS from doing so through normal virtual memory management. The pagefile/swapfile persists after process termination and can be forensically recovered. This directly contradicts Qindu's core guarantee that PII never exists on disk unencrypted. DPO requirement R12 specifies "no swap file by design" — memory locking is the mechanism that fulfills this requirement.

**Why not encrypted swap?**: While OS-level encrypted swap (e.g., Windows BitLocker-encrypted pagefile, Linux `dm-crypt` swap) would mitigate this, Qindu cannot assume all deployments have encrypted swap enabled. Memory locking provides a process-level guarantee independent of OS configuration.

**Why not in-memory encryption of the mapping?**: Encrypting individual mapping entries in memory (e.g., with a session key) would protect the *contents* but not the presence of PII on swapped pages. Memory locking prevents the pages from hitting disk at all, which is the stronger guarantee. In-memory encryption is deferred to a future sprint and would be complementary, not alternative.

**Validation criteria**:
- Code audit: verify that a platform-appropriate locking primitive (`VirtualLock` on Windows, `mlockall` on Linux) is called at process/tokenizer initialization.
- Code audit: verify that the locked region covers the token↔PII mapping.
- Code audit: verify fallback behavior on locking failure (WARNING log, no PII in message, normal operation continues).
- Test (Linux CI): verify that `mlockall` is called and does not return an error when `CAP_IPC_LOCK` is granted.
- Test (Linux CI): simulate locking failure (e.g., by setting `RLIMIT_MEMLOCK` to 0 or removing `CAP_IPC_LOCK`) and verify the fallback log message is emitted and contains no PII.
- Test (Windows VM, QEMU validation gate): verify that `VirtualLock` is called successfully on the mapping region.

**OWASP ASVS mapping**: V8.3.2 (sensitive data in memory protected from swap), V8.3.4 (memory cleanup — preventing post-mortem recovery), V6.1.1 (no cleartext storage — pagefile is cleartext storage)

---

## 5. Mandatory Security Tests

The following test scenarios are required in the implementation's test suite. The CISO review gate will verify these exist and pass.

| ID | Test Scenario | Verifies SR |
|----|--------------|-------------|
| **ST1** | Tokenize text with 1 email → output contains `<<EMAIL_1>>`, zero raw email anywhere in output | SR-1, SR-2 |
| **ST2** | Tokenize text with 3 emails → `<<EMAIL_1>>`, `<<EMAIL_2>>`, `<<EMAIL_3>>`, each distinct | SR-2, SR-8 |
| **ST3** | Same email appears 3 times in input → same `<<EMAIL_1>>` all 3 places | SR-8 |
| **ST4** | `rehydrate(tokenize(text))` → original text byte-for-byte (round-trip) | SR-1, SR-5, SR-10 |
| **ST5** | `tokenize(tokenize(text))` → `tokenize(text)` (idempotency of tokenization) | SR-8 |
| **ST6** | `rehydrate("<<EMAIL_99>> Hello")` → `"<<EMAIL_99>> Hello"` (unmapped token pass-through) | SR-5, SR-6 |
| **ST7** | `rehydrate("Hello world")` → `"Hello world"` (no tokens, pass-through) | SR-7 |
| **ST8** | Tokenize empty/whitespace-only input → empty/unchanged, no error | SR-7 |
| **ST9** | Tokenize 1 MiB + 1 byte → `ErrInputTooLarge`, error message contains zero PII patterns | SR-3, SR-7 |
| **ST10** | Concurrent tokenize + rehydrate (10+ goroutines) → no data race, correct deterministic output | SR-4 |
| **ST11** | Tokenize text containing all 8 entity types → all replaced, zero raw PII detectable in output | SR-1, SR-15 |
| **ST12** | Right-to-left: 3 adjacent entities at [0,15], [16,30], [31,45] → all correctly replaced | SR-10 |
| **ST13** | PII value longer than its token (100-byte JWT → `<<JWT_1>>`) → no orphaned bytes | SR-10 |
| **ST14** | PII value shorter than its token (5-byte email → `<<EMAIL_1>>`) → no overlap/corruption | SR-10 |
| **ST15** | Tokenized output re-scanned by `Engine.Detect()` → zero entities detected | SR-1 |
| **ST16** | All test data uses synthetic PII only (grep-verify) | SR-14 |
| **ST17** | Token format verification: different PII values, same type, same position → identical token string | SR-2 |
| **ST18** | Error paths produce no PII in error strings (scan with recognizers) | SR-3 |
| **ST19** | No filesystem operations in tokenizer package (code audit) | SR-11 |
| **ST20** | Rehydrator rejects `<<PASSWORD_1>>` (unknown type) → pass-through | SR-15 |
| **ST21** | Rehydrator regex tested with 10 KiB of angle brackets → sub-second completion | SR-12 |
| **ST22** | Two separate tokenizer instances produce independent counter sequences | SR-9 |
| **ST23** | `Reset()` clears all mapping state, previous tokens resolve to nothing | SR-17 |
| **ST24** | Tokenizer does not modify `internal/pii/` (git diff verification) | SR-13 |
| **ST25** | Memory locking invoked: (a) on Linux CI, `mlockall(MCL_CURRENT \| MCL_FUTURE)` is called at initialization and succeeds when `CAP_IPC_LOCK` is granted; (b) locking failure (e.g., `RLIMIT_MEMLOCK=0`) produces a WARNING log message containing zero PII and the proxy continues operating; (c) on Windows VM, `VirtualLock()` is called on the mapping region and succeeds | SR-18 |

---

## 6. Mapping to OWASP ASVS 4.0

| ASVS Requirement | Qindu SR | Rationale |
|-----------------|----------|-----------|
| V1.1.1 (separation of concerns) | SR-13 | Tokenizer is a separate package from detection engine |
| V1.1.4 (test data management) | SR-14 | Synthetic data only in tests |
| V1.6.2 (concurrent access) | SR-4 | `sync.RWMutex` for mapping/counters |
| V2.1.1 (session management) | SR-9, SR-17 | Conversation scoping and cleanup |
| V5.1.1 (input validation) | SR-6, SR-7, SR-12, SR-15 | Strict token format allowlist, size bounds, regex safety |
| V5.1.2 (size limits) | SR-7 | 1 MiB input bound |
| V5.1.4 (input validation bypass) | SR-5, SR-8, SR-10 | Pass-through for unmapped tokens, idempotency, offset correctness |
| V5.1.5 (allowlist validation) | SR-15 | Entity type allowlist for rehydration |
| V5.3.3 (regex safety) | SR-12 | Linear-time regex, no catastrophic backtracking |
| V6.1.1 (no cleartext storage) | SR-11 | No disk persistence |
| V6.1.3 (session termination) | SR-17 | Memory cleanup on conversation end |
| V6.2.5 (token generation) | SR-2, SR-8, SR-9 | Opaque tokens, no encoded PII, deterministic within session, unique across sessions |
| V7.1.1 (no sensitive data in logs) | SR-3 | ADR-008 compliance |
| V7.2.1 (no sensitive data in URLs/params) | SR-2 | Tokens contain zero PII |
| V7.3.1 (output encoding) | SR-1, SR-10 | Correct PII substitution, right-to-left replacement |
| V7.4.1 (error handling) | SR-3, SR-16 | Uniform error handling, no PII in errors |
| V8.3.2 (sensitive data in memory) | SR-11 | Mapping in memory only |
| V8.3.4 (memory cleanup) | SR-17 | Reset/GC on conversation end |
| V9.1.1 (data protection in transit) | SR-1 | Tokenized output contains zero raw PII |
| V11.1.1 (thread safety) | SR-4 | Concurrent-safe mapping and counters |
| V11.1.2 (no info leakage through errors) | SR-5, SR-16 | No oracle for mapping contents |
| V14.1.1 (dependency integrity) | SR-13 | Tokenizer consumes but does not modify `internal/pii/` |
| V8.3.2 (sensitive data in memory protected from swap) | SR-18 | Memory locking prevents pagefile/swap leakage |

---

## 7. Residual Risks (Accepted)

These risks are acknowledged and accepted for QINDU-0006. They are deferred to future sprints or accepted as inherent limitations.

| ID | Risk | Rationale for Acceptance | Future Mitigation |
|----|------|-------------------------|-------------------|
| **R-005** | Memory dump exposure (PII in unencrypted process memory) | Backlog R-005. No in-memory encryption in this sprint. OS-level DAC protects process memory from other users. | QINDU-0008 (DPAPI-encrypted vault at rest). Full mitigation requires in-memory encryption (future enhancement). |
| **R-DOS** | Unbounded mapping growth in long conversations | The 1 MiB per-message bound limits per-request entries. Process termination is the natural bound. For development/early usage, this is acceptable. | QINDU-0008 should introduce configurable mapping cap with LRU/TTL eviction. |
| **R-TYPE-LEAK** | Entity type and count metadata visible to AI service | Inherent in the `<<TYPE_N>>` design. Necessary for AI semantic understanding (the AI needs to know that `<<EMAIL_1>>` is an email address). | No mitigation planned. The privacy-utility tradeoff favors utility here. |
| **R-AI-REORDER** | AI service can restructure tokenized PII in response | The AI can place `<<EMAIL_1>>` in any context within its response. Rehydration will restore the PII value. This is content manipulation, not data exfiltration — the AI never sees the rehydrated result. | No technical mitigation. User education: be aware that AI can control where your PII appears in responses. |
| **R-MEM-SHARING** | Go string memory sharing between tokenized output and PII value | Very low probability given the `<<TYPE_N>>` format. No egress risk (data remains in local process memory). | No mitigation planned. |
| **R-SWAP-FALLBACK** | Memory locking fails at runtime (e.g., `SeLockMemoryPrivilege` not held, `CAP_IPC_LOCK` not granted, RLIMIT_MEMLOCK exhausted) | The fallback behavior in SR-18 requires continuing operation with a warning. In this state, the token↔PII mapping pages ARE eligible for swap — the same risk as before SR-18. | The fallback is a deliberate design choice: availability (proxy must work) trumps swap-hardening. The WARNING log ensures the operator is informed. For environments where this risk is unacceptable, operators must ensure memory locking prerequisites are met. |

---

## 8. Recommendations (Non-Blocking)

These are security hardening measures that are not required for CISO gate passage but would strengthen the implementation.

1. **REC-1 — Mapping size cap**: Add a configurable maximum mapping size (e.g., 10,000 entries). When exceeded, tokenize but don't add new entries (or use LRU eviction). This prevents memory exhaustion from truly pathological conversations. **Should be mandatory for QINDU-0008.**

2. **REC-2 — Audit log for rehydration**: Log every rehydration event at DEBUG level with the token and entity type (never the PII value). This provides an audit trail for debugging token injection or unexpected rehydration behavior.

3. **REC-3 — Token format validation in tokenizer**: The tokenizer should validate that the generated token string matches the expected format before returning it. This is a consistency check that catches format bugs early.

4. **REC-4 — Benchmark for substitution performance**: Measure the throughput of tokenization and rehydration with varying input sizes and entity counts. The right-to-left string building algorithm must not be O(n²).

5. **REC-5 — Tokenizer fuzzing**: While fuzzing is deferred to a future sprint (backlog R-007), the tokenizer's text manipulation path is a prime target. Integration with the existing PII detection engine means fuzzing the full pipeline (recognizers → engine → tokenizer → rehydrator) would be valuable.

6. **REC-6 — Secret/PrivateKey sensitivity hardening**: Tokens for `SECRET` and `PRIVATE_KEY` types represent credentials. Consider logging a WARN-level message when these entity types are detected (with count only, not values), to alert the user that credentials were in their input. The AI service already learns this metadata via the token format, so logging it locally adds no new exposure.

7. **REC-7 — Input text zeroing after tokenization**: If the raw input text is held in a `[]byte` or mutable buffer, consider zeroing it after tokenization to reduce the window where un-tokenized PII exists in memory. In practice, Go strings are immutable, so this requires `unsafe` and is probably not worth it — but worth documenting as a consideration.

---

## 9. Verdict

### APPROVED_WITH_RECOMMENDATIONS (amended)

**Original verdict (2026-07-03)**: The QINDU-0006 sprint design is sound from a security perspective. The core security properties — zero PII in tokenized output, opaque token format, in-memory-only mapping, conversation-scoped counters, and right-to-left replacement — provide a strong security foundation. No design-level security defects were identified that would block the sprint.

**Amendment (2026-07-03, same day)**: A gap was identified in the original threat model: **memory swap leakage** (I7, AS9). The operating system's virtual memory manager can swap pages containing the plaintext token↔PII mapping to disk (pagefile/swapfile), where PII persists after process termination and is forensically recoverable. This was not captured in the original 17 security requirements. The following additions have been made:

- **AS9**: New attack surface — memory pages in OS swap/pagefile
- **I7**: New threat — memory swap leakage via OS pagefile/swapfile (Information Disclosure)
- **SR-18**: New blocking security requirement — memory locking (`VirtualLock` on Windows, `mlockall` on Linux) to prevent swap leakage
- **ST25**: New mandatory security test — verifies memory locking invocation and fallback behavior
- **R-SWAP-FALLBACK**: New residual risk — documented fallback when locking fails
- **OWASP V8.3.2**: Added to ASVS mapping table

### Does This Gap Change the Verdict?

**No — the sprint is NOT BLOCKED.** The verdict remains APPROVED_WITH_RECOMMENDATIONS. Here is the reasoning:

1. **The fix is additive, not architectural**: Memory locking is a ~10-line platform-specific call at process initialization. It does not require redesigning the tokenizer, the mapping, the substitution algorithm, or any API surface. It is a defense-in-depth hardening measure that can be added without changing anything that already exists.

2. **The threat existed before and after my review**: The original R-005 (memory dump exposure) acknowledged that PII in unencrypted process memory is an accepted risk. Swap leakage is a subset of that risk — the pages just happen to land on disk instead of staying in RAM. My original analysis missed it; this amendment corrects that.

3. **The implementation work is well-understood**: Both `VirtualLock()` and `mlockall()` are stable, well-documented OS primitives. The Go standard library provides `golang.org/x/sys/windows` for `VirtualLock` and `golang.org/x/sys/unix` for `mlockall`. The implementation is low-risk and does not introduce new complexity.

4. **Fallback behavior preserves availability**: If memory locking fails, the proxy logs a warning and continues — it does not crash or refuse to start. This means deployment in environments without the required privileges (rare, since Qindu runs as admin-elevated on Windows) still works, just without the swap-hardening.

### Minimum Bar to Pass the CISO Review Gate

For the CISO review gate (post-implementation) to PASS, the implementation must satisfy:

- **All original 17 security requirements (SR-1 through SR-17)** — unchanged
- **The new SR-18 (memory locking)** — added by this amendment
- **All 25 mandatory security tests (ST-1 through ST-25)** — ST-25 is new
- **`go test -race ./...` passes** — unchanged
- **Zero PII in logs, errors, or debug output** — unchanged, now includes the SR-18 fallback warning message
- **No filesystem operations in tokenizer package** — unchanged (SR-11), now extended: the tokenizer must not rely on swap-encrypted filesystems as a substitute for memory locking

### What Would Make This BLOCKING

This sprint would be BLOCKED (verdict changed to BLOCKED) if any of the following were true:

1. **Memory locking required a fundamental redesign of the tokenizer** — it does not.
2. **The locking mechanism introduced a new, unmitigated attack surface** — it does not; the syscalls are well-audited OS primitives.
3. **Memory locking was incompatible with Go's memory model** — it is compatible; Go's garbage collector moves objects, but `VirtualLock` on a `[]byte` backing the mapping (or using `C.CBytes` + `VirtualLock` on a C heap allocation) is a known pattern. A `map[string]string` can be backed by a contiguous `[]byte` for lockable memory, or a C-allocated structure can be used for the mapping.
4. **The implementation could not test memory locking in CI** — it can; Linux CI runners can be granted `CAP_IPC_LOCK` and `mlockall` is testable.

**None of these conditions apply. Therefore the sprint remains APPROVED_WITH_RECOMMENDATIONS and may proceed to implementation with SR-18 included as a binding requirement.**

**Critical attention areas for implementation** (updated):
1. **SR-1 (Zero PII in output)** — The fundamental guarantee. Test exhaustively with all entity types, edge cases, and adjacent entities.
2. **SR-4 (Concurrent safety)** — Data races in the mapping could map wrong PII to tokens. `go test -race` is non-negotiable.
3. **SR-10 (Right-to-left replacement)** — A single off-by-one error here leaves PII in the output. Test with offset precision.
4. **SR-3 (No PII in logs)** — The most likely implementation error. Every format string must be audited.
5. **SR-18 (Memory locking)** — NEW. Must be implemented and tested. The fallback path (locking failure) must not leak PII in the warning message and must not prevent the proxy from starting.

**The sprint may proceed to implementation. The CISO review gate (post-implementation) will verify all 18 security requirements and 25 mandatory security tests.**

---

*End of CISO requirements. This document is binding for the QINDU-0006 implementation and review gates.*
*ZERO PII disclosed in this document.*
