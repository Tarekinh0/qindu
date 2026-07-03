# DPO Requirements — QINDU-0006: Tokenisation

**Agent**: qindu-dpo (Data Protection Officer)
**Date**: 2026-07-03
**Verdict**: APPROVED_WITH_RECOMMENDATIONS

---

## 1. GDPR Compliance Analysis

### 1.1 Data Minimisation — Art. 5(1)(c)

The tokenizer performs substitution of detected PII entities with opaque placeholder tokens (`<<TYPE_N>>`). The substituted (tokenized) text is what leaves the local machine toward external AI services. The raw PII values never egress — they remain exclusively in the in-memory mapping.

This is an exemplary application of data minimisation by design: the external AI service receives only the semantic structure that tokens carry (entity type, ordinal position) and never the personal data itself. The token format `<<TYPE_N>>` encodes zero information about the underlying PII value — no hash, no embedding, no reversible encoding.

The mapping itself is the minimum necessary to fulfil the purpose: it stores only `token → PII_value`, indexed for O(1) lookup during rehydration. No metadata beyond what QINDU-0005's `Entity` struct carries (type, confidence, source, byte offsets) — and that metadata is consumed during tokenization, not persisted in the mapping.

### 1.2 Purpose Limitation — Art. 5(1)(b)

The token↔PII mapping exists for a single, well-defined purpose: rehydrating AI responses on the local machine so the user sees human-readable text rather than tokens. This is a legitimate purpose that directly serves the user's experience and is the core value proposition of Qindu.

**No secondary purposes**: The mapping is not used for analytics, tracking, profiling, or any form of automated decision-making. No data derived from the mapping (counters, entity type frequencies, etc.) shall be exported, aggregated, or persisted beyond the conversation lifetime.

### 1.3 Storage Limitation — Art. 5(1)(e)

The mapping is **volatile (in-memory only)** for this sprint. Storage is bounded by conversation lifetime: when the process terminates, the mapping evaporates. This is the strongest possible form of storage limitation short of not creating the data at all.

However, I note the following nuance:

- **Within a conversation**, the mapping accumulates over successive messages (AC #1: same PII value → same token). There is no mechanism in this sprint to expire individual entries or bound the total size of the mapping.
- The 1 MiB input bound (AC #9) provides an indirect ceiling on mapping size, but a long-running conversation with many messages could accumulate a large in-memory map.

This is acceptable for a sprint that is explicitly "memory-only, no persistence." The vault sprint (QINDU-0008) will introduce TTL-based storage limitation. For now, the process boundary provides a natural, if coarse, retention limit.

### 1.4 Right to Erasure — Art. 17

Erasure is implicit in this sprint: terminating the process destroys all mappings. No explicit erasure mechanism is required because there is no persistent storage.

**Future concern** (not blocking for this sprint): Once QINDU-0008 introduces DPAPI-encrypted persistence, the user must have a mechanism to delete vault entries or wipe the vault entirely. The ARCHITECTURE.md already specifies "Supprimable manuellement" for the vault. This sprint should not hinder that future capability — specifically, the tokenizer's API should be designed such that a future vault-backed token store can implement the same interface.

### 1.5 Privacy by Design — Art. 25

The sprint embodies several Art. 25 principles:

| Principle | How it's applied |
|---|---|
| **Data protection by default** | PII is tokenized before egress by default; no opt-in required |
| **Data protection by design** | Token format carries zero PII; mapping is volatile; rehydration is local-only |
| **Least data egress** | Only tokens leave the machine; raw PII never does |
| **Segregation** | Type counters are independent; EMAIL tokens don't leak information about PHONE counts and vice versa (though both are visible to the AI service) |

---

## 2. Privacy-by-Design Assessment of the Tokenization Approach

### 2.1 Token Format `<<TYPE_N>>`

**What the external AI service can observe**:
- The entity type (EMAIL, PHONE, IBAN, etc.)
- The ordinal position of each entity within its type category (1, 2, 3, ...)
- The total count of each entity type in the conversation (the highest counter value seen)

**What the external AI service CANNOT observe**:
- The actual PII value
- Any hash, encoding, or derivative of the PII value
- Any correlation between entity types (e.g., that `<<EMAIL_1>>` and `<<NAME_1>>` come from the same source email — unless the type counter correlation reveals it)

**Metadata leakage inherent in the design**:
- The AI service learns how many emails, phone numbers, IBANs, etc. were in the user's text. For most conversations, this is low-sensitivity metadata. For certain threat models (e.g., a user pasting a leaked database), the count itself could be revealing.
- The AI service learns that `<<EMAIL_1>>` and `<<EMAIL_2>>` are distinct entities of the same type. It cannot distinguish their values, but it knows they are different.

**Assessment**: This metadata leakage is inherent in any tokenization scheme that preserves semantic replaceability. The alternative (uniform tokens with no type information) would prevent the AI from understanding context (e.g., "send the confirmation to <<TOKEN_42>>" — the AI wouldn't know it's an email). The design strikes a reasonable balance between privacy and utility. ACCEPTABLE.

### 2.2 In-Memory Mapping

**Strengths**:
- Volatile: destroyed on process termination
- No disk persistence (no swap file leakage risk from the mapping itself, though the OS may swap process memory)
- Local-only: never transmitted over the network
- Conversation-scoped: no cross-conversation residue

**Weaknesses**:
- Memory dump exposure (see Risk #1 in Section 4)
- No encryption of the mapping within process memory (accepted for this sprint — vault encryption arrives in QINDU-0008)
- Go garbage collector does not zero freed memory, so deallocated mapping entries may persist in heap memory until overwritten

### 2.3 Reversibility

Rehydration is the process of restoring `<<TYPE_N>>` back to the original PII value. This happens **exclusively on the local machine**, using the in-memory mapping populated during tokenization.

**Critical privacy property**: The AI service cannot inject arbitrary tokens to exfiltrate PII. It can only reference tokens that were sent to it — and those tokens map to PII the user already chose to share (in tokenized form). The rehydration step is a local, deterministic operation that restores what was previously present. The AI service has no API to query the token store.

**Partial token handling** (AC #5): Token-like strings in responses that don't match any stored mapping are left as-is. This prevents the AI from crafting synthetic `<<EMAIL_999>>` tokens to probe the mapping. No information about what IS in the mapping is leaked.

---

## 3. PII Lifecycle in this Sprint

```
┌─────────────────────────────────────────────────────────────────┐
│                        LOCAL MACHINE                            │
│                                                                 │
│  ┌──────────┐    ┌──────────────┐    ┌──────────────────────┐   │
│  │ Browser  │───▶│   QINDU-0006 │    │  In-Memory Mapping   │   │
│  │ (user    │    │   Tokenizer  │    │                      │   │
│  │  types   │    │              │    │  <<EMAIL_1>> → "u@x" │   │
│  │  PII)    │    │  QINDU-0005  │    │  <<PHONE_1>> → "+33" │   │
│  │          │    │  Recognizers │    │  <<IBAN_1>>  → "FR.."│   │
│  └──────────┘    └──────┬───────┘    └──────────┬───────────┘   │
│                         │                       │               │
│                    Tokenized text          Lookup during        │
│                    (no PII)                rehydration          │
│                         │                       ▲               │
│                         ▼                       │               │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                    EGRESS / INGRESS                      │   │
│  │         Tokenized request → AI API                       │   │
│  │         Token-containing response ← AI API               │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 3.1 Phase-by-Phase Trace

| Phase | Where | Data State | Duration |
|---|---|---|---|
| **Ingress** | HTTP request body intercepted by proxy | Raw PII in clear text (in transit from browser to proxy, on loopback) | Milliseconds |
| **Detection** | `internal/pii/Engine.Detect()` | PII extracted into `[]Entity` structs. `Entity.Value` contains raw PII. | Duration of detection (sub-millisecond for typical input) |
| **Tokenization** | Tokenizer (this sprint) | Raw PII in `Entity.Value` is read to generate/lookup tokens. The PII value is stored in the mapping if new. | Same call stack as detection |
| **Substitution** | Tokenizer replaces text spans | Text is rewritten: PII spans → `<<TYPE_N>>` strings. Original PII values are no longer in the resulting string. | In-place or new string allocation |
| **Mapping storage** | In-memory map | `token → PII_value` mapping stored in Go map. Raw PII values persist here. | Until process termination or GC |
| **Egress** | HTTP request sent to AI API | Only tokenized text. Zero raw PII. Tokenized text is the request body. | Network flight to AI service |
| **Response Ingress** | HTTP response received from AI API | AI response containing `<<TYPE_N>>` tokens. No raw PII (unless AI hallucinates PII, which is out of scope). | Network flight from AI service |
| **Rehydration** | Tokenizer restores tokens | `<<TYPE_N>>` → raw PII value (from in-memory map). Reconstructed text contains PII. | Sub-millisecond |
| **Egress to Browser** | HTTP response sent to browser | Rehydrated text with restored PII. The browser (user's own machine) sees original PII. The loopback is local. | Network flight to browser on loopback |
| **Destruction** | Process termination | All mappings destroyed. Go GC may have already freed unreferenced entries. Memory pages reclaimed by OS. | At process exit |

### 3.2 Critical Privacy Boundary

The privacy boundary is the **egress point** — the moment the HTTP request leaves the local machine toward the AI service. After tokenization and before egress, the text must contain zero raw PII values. The in-memory mapping ensures this. The DPO review gate must verify that AC #8 ("No PII in output") is rigorously tested.

---

## 4. Risk Assessment

| ID | Risk | Likelihood | Impact | Severity | Mitigation |
|---|---|---|---|---|---|
| **R1** | **Memory dump exposure**: Go process crash dumps, debugger memory inspection, or `os.ReadFile("/proc/self/mem")` (Linux) could reveal PII values in the in-memory mapping. | Low | High | **MEDIUM** | Process runs as the local user; OS-level DAC protects memory from other users. No encryption of in-memory map in this sprint — accepted R-005 in backlog. Vault sprint (QINDU-0008) addresses encryption at rest. Full mitigation requires in-memory encryption (future enhancement). |
| **R2** | **Token metadata leakage**: The AI service learns entity type counts and ordinal positions from `<<TYPE_N>>` tokens. For example, 3 emails, 2 phone numbers, 1 IBAN are distinguishable. | High | Low | **LOW** | Inherent in the design. The type tag is necessary for semantic coherence. Ordinal position carries minimal privacy impact. The alternative (purely opaque tokens like `<<TOKEN_001>>`) would degrade AI response quality. Accepted. |
| **R3** | **Cross-conversation correlation**: If counters or mappings were shared between conversations, an observer could correlate PII usage across sessions. | N/A | High | **NEGLIGIBLE** | Explicitly prevented by design: "No cross-conversation guarantee. New conversation = fresh counters" (behavioral rule #2). Counters reset per conversation. Accepted. |
| **R4** | **Token injection by AI service**: A malicious or compromised AI service could craft responses containing `<<TYPE_N>>` tokens to trigger rehydration of PII into the response body. | Low | Medium | **LOW** | The AI service can only reference tokens it has seen (which were in the user's original, tokenized prompt). It cannot probe for tokens it hasn't received. The user chose to share the tokenized PII; rehydration restores what was already shared. Partial tokens not in the map pass through unchanged (AC #5). The risk is that the AI could restructure the response to place restored PII in surprising or inappropriate contexts, which is a content risk (not a privacy leak to a third party). |
| **R5** | **Race condition in concurrent access**: If the tokenizer's in-memory map is not properly synchronized (AC #6), concurrent tokenization/rehydration could produce incorrect token↔PII mappings, potentially sending the wrong PII value to the browser during rehydration. | Low | Critical | **MEDIUM** | AC #6 explicitly requires "safe for concurrent use." The implementation must use `sync.RWMutex` or equivalent. The `go test -race` requirement (AC #10) validates this. |
| **R6** | **PII in error messages or debug output**: An error condition (e.g., invalid input, internal panic) could include raw PII in the error string. | Medium | High | **HIGH** | The `Entity` struct already uses `json:"-"` on `Value`, `SafeString()`, and a `String()` override (QINDU-0005). The tokenizer must extend this discipline: never include raw PII values, tokenized text, or token↔PII mappings in error messages, log output, or `fmt.Sprintf`. AC #9 explicitly requires "no PII in the error message" for input bounds errors. |
| **R7** | **Test fixture contamination**: Real PII in test fixtures could be committed to the repository, creating a permanent privacy incident. | Low | Critical | **HIGH** | AC #10 explicitly requires "all tests use synthetic PII only." Must be verified during DPO review and QA gates. The QINDU-0005 recognizer suite already established this discipline — all test data uses `@example.com`, synthetic credit cards, test IBANs. The tokenizer must follow the same rule. |
| **R8** | **Go runtime string interning**: Go may share backing arrays for identical strings. If the tokenized output string and the PII value string share memory, the PII could theoretically persist in the tokenized output's memory region. | Very Low | Medium | **LOW** | This would require the token placeholder and the PII value to be substrings of the same allocation, which is unlikely given the `<<TYPE_N>>` format. Even if it occurred, the data is in local process memory. No egress risk. |
| **R9** | **Right-to-left replacement edge case**: If the right-to-left replacement algorithm is incorrectly implemented, byte offsets could shift and token placeholders could overlap with adjacent PII, potentially leaving partial PII in the tokenized output. | Low | Critical | **MEDIUM** | Behavioral rule #3 specifies right-to-left replacement precisely for this reason. Acceptance criteria #8 ("No PII in output") directly validates this. The implementation must be tested with PII adjacent to other PII (e.g., `email: jean.dupont@example.com, phone: +33 6 12 34 56 78`). |
| **R10** | **Mapping unbounded growth**: A long-running conversation with many unique PII values could cause the in-memory map to grow without bound, potentially leading to memory exhaustion or excessive memory pressure. | Medium | Low | **LOW** | The 1 MiB input bound limits the PII count per message, but a conversation could theoretically contain thousands of messages. This is a resource management concern, not a privacy concern per se. The vault sprint (QINDU-0008) will introduce TTL-based eviction. For this sprint, process termination is the natural bound. |

---

## 5. Requirements and Constraints

These requirements MUST be satisfied for the DPO gate to PASS. They are binding constraints on the implementation.

### R1 — Zero PII in Tokenized Output (CRITICAL)

The tokenized text must contain absolutely no raw PII values. Every detected entity must be replaced by its corresponding `<<TYPE_N>>` token. This must hold for all entity types recognized by QINDU-0005 (EMAIL, PHONE, IBAN, CREDIT_CARD, JWT, NAME, SECRET, PRIVATE_KEY).

**Verification**: Automated test that feeds text containing all 8 entity types through `tokenize()`, then scans the output for known PII patterns (email regex, phone regex, IBAN regex, credit card regex, etc.). The test must assert zero matches.

**Rationale**: This is the fundamental privacy guarantee. Failure here means PII egresses in clear text.

### R2 — Token Format Contains Zero Encoded PII (CRITICAL)

The token string `<<TYPE_N>>` must not encode, hash, embed, or derive from the PII value in any way. The token MUST be purely a concatenation of:
- `<<` (literal)
- The uppercase `EntityType` string (e.g., `EMAIL`)
- `_` (literal)
- An integer counter `N` (decimal)
- `>>` (literal)

**Verification**: Code audit confirming the token generation path uses only the entity type and a counter, never the `Entity.Value` field. Test that different PII values of the same type and same ordinal position produce identical token strings.

**Rationale**: A token that encodes PII (e.g., `<<EMAIL_aGFzaA==>>` as base64 of the email) would leak information to the AI service. Behavioral rule #4.

### R3 — Rehydration is Local-Only (CRITICAL)

The rehydration step must resolve tokens exclusively against the local in-memory mapping. No network calls, no external service queries, no filesystem reads. The mapping is the sole source of truth.

**Verification**: Code audit confirming `rehydrate()` only accesses the in-memory map. No HTTP client, no `os.Open`, no external lookup.

**Rationale**: If rehydration depended on an external service, that service would learn the token↔PII mapping, defeating the entire purpose of the proxy.

### R4 — No PII in Logs, Errors, or Debug Output (HIGH)

The tokenizer must never log, print, or include in error messages:
- Raw PII values (from `Entity.Value` or the mapping)
- Tokenized text (input or output)
- Token↔PII mappings (keys or values)
- Any derivative of the above

Acceptable to log: entity counts by type (e.g., `tokenized 3 EMAIL, 1 PHONE, 2 SECRET`), timing, input size, error types (without PII).

**Verification**: Code audit of all `log`, `slog`, `fmt.Print`, `fmt.Sprintf`, `panic`, and error creation sites in the tokenizer package. Grep for `Value`, `entity.Value`, and `%s`/`%v` format strings applied to entity or mapping data.

**Rationale**: Consistent with ADR-008 and the QINDU-0005 discipline. Accidental logging of PII is a permanent data breach.

### R5 — Concurrent Safety (HIGH)

The tokenizer's in-memory map must be safe for concurrent access from multiple goroutines. Tokenization and rehydration may happen concurrently (different requests/responses interleaved).

**Verification**: `go test -race` must pass. Test that spawns multiple goroutines concurrently calling `tokenize()` and `rehydrate()` with overlapping data.

**Rationale**: Race conditions in the mapping could cause tokens to map to wrong PII values, resulting in incorrect rehydration (user sees wrong PII in responses). While this is a correctness issue, it has privacy implications if PII from one conversation bleeds into another's response.

### R6 — Deterministic Re-tokenization (MEDIUM)

Within a single conversation scope, `tokenize(tokenize(text))` must produce the same output as `tokenize(text)`. That is, re-tokenizing already-tokenized text must be idempotent (the tokenizer must not attempt to tokenize its own output).

**Verification**: Test that tokenizing the output of `tokenize()` yields identical output byte-for-byte.

**Rationale**: If the tokenizer naively re-processes tokenized text, `<<EMAIL_1>>` could be detected as a new entity (e.g., the `@` in some context, or `_` as a separator in NAME), creating nested or chained tokens. AC #6.

### R7 — Partial Token Pass-Through (MEDIUM)

During rehydration, token-like strings in the response that don't match any entry in the mapping must be left unchanged. The rehydrator must not:
- Strip them (losing information)
- Replace them with empty strings
- Crash, panic, or return an error

**Verification**: Test `rehydrate()` with a response containing `<<EMAIL_99>>` when the mapping only has `<<EMAIL_1>>`. The output must contain `<<EMAIL_99>>` unchanged.

**Rationale**: AC #5. The AI service could include token-like text (e.g., in code examples, documentation excerpts). Stripping them would corrupt the response.

### R8 — Synthetic Test Data Only (HIGH)

All test fixtures, test inputs, expected outputs, and test assertions must use exclusively synthetic PII:
- Emails: `@example.com`, `@test.invalid`, or other IANA-reserved TLDs
- Phones: numbers from ITU-T E.164 reserved ranges (e.g., `+1 555` for US, `+33 1 99 00` for France) or obviously fake patterns
- IBANs: test IBANs from official financial institution test suites (e.g., `DE89 3704 0044 0532 0130 00`)
- Credit cards: standard test numbers (e.g., Visa `4111 1111 1111 1111`, Mastercard `5555 5555 5555 4444`)
- Names: obviously fictional (e.g., `Jean Dupont`, `Test User`)
- API keys/secrets: recognizably fake prefixes (e.g., `sk-test-00000000000000000000000000`)
- JWTs: test tokens with synthetic payloads
- Private keys: test PEM blocks with "NOT A REAL KEY" markers or generated test keys clearly labeled as such

**Verification**: Grep test files for real PII patterns. Use the same recognizers from QINDU-0005 to scan test files — if they detect PII, the data might be too realistic.

**Rationale**: AC #10. Real PII in the repository is a permanent, public data breach.

### R9 — Input Size Bounds (MEDIUM)

Inputs exceeding 1 MiB must be rejected with a structured error that contains only size metadata (max allowed, received size) — never the input text or any fragment of it.

**Verification**: Test with an input of 1 MiB + 1 byte. Assert the error is returned, the error type is `ErrInputTooLarge` (or equivalent), and the error message contains no PII-like patterns.

**Rationale**: AC #9. This is already implemented at the Engine level (QINDU-0005) — the tokenizer must not bypass this bound.

### R10 — Right-to-Left Replacement Correctness (MEDIUM)

The tokenizer must replace PII spans from rightmost to leftmost to preserve byte offsets of earlier entities. The implementation must be tested with:
- Adjacent PII of different types (e.g., `jean.dupont@example.com+33612345678` — though this specific adjacency is unlikely in practice)
- PII embedded within other PII (if overlap resolution from QINDU-0005 permits it)
- PII at the very beginning and end of the input

**Verification**: Test with multiple PII entities in a single input. Assert that all entities are correctly replaced and that no partial PII remains.

**Rationale**: Behavioral rule #3. An incorrect replacement order could leave PII fragments in the output, violating R1.

### R11 — Package Isolation (MEDIUM)

The tokenizer package must not modify `internal/pii/` (explicitly forbidden in story.md). It must use the Engine and Entity types as a consumer/dependency only. This ensures the detection layer's integrity is preserved and the separation of concerns (detection vs. transformation) is maintained.

**Verification**: `git diff` on `internal/pii/` after implementation must be empty (modulo any bug fixes approved by the orchestrator).

**Rationale**: The tokenizer is a consumer of the detection engine. Modifying the engine to suit the tokenizer would create coupling that complicates future sprints.

### R12 — No Disk Persistence (MEDIUM)

The token↔PII mapping must not be written to disk in any form — no files, no temporary files, no SQLite, no swap file by design. This is explicitly out of scope for this sprint.

**Verification**: Code audit confirming no `os.Create`, `os.WriteFile`, database driver, or `io.Write` to filesystem paths. The only storage is a Go `map[string]string` (or equivalent in-memory data structure).

**Rationale**: Story.md "Design Decisions" table: "Token storage: In-memory, volatile." Persistence arrives in QINDU-0008 with DPAPI encryption.

### R13 — Idempotent Rehydration of Clean Text (LOW)

`rehydrate()` on text containing no tokens must return the text unchanged (byte-for-byte pass-through).

**Verification**: Test `rehydrate("Hello, world!")` → `"Hello, world!"`. Test with empty string, whitespace-only string, text containing `<<` but not a valid token format.

**Rationale**: The rehydrator may be applied to AI responses that don't contain tokens. It must be a no-op in that case.

### R14 — No User Accounts, Tracking, or Identifiers (LOW)

The tokenizer must not introduce any form of user identification, session tracking, analytics, or telemetry. Conversation scope is tracked via a simple counter reset, not via user IDs or session tokens.

**Verification**: Code audit confirming no UUIDs, no cookies, no device fingerprinting, no persistent identifiers.

**Rationale**: Core Qindu non-negotiable rule. Consistent with all prior sprints.

---

## 6. Verdict

### APPROVED_WITH_RECOMMENDATIONS

**Rationale**: The QINDU-0006 sprint is well-designed from a privacy perspective. The tokenization approach — volatile in-memory mapping, opaque `<<TYPE_N>>` format, local-only rehydration, conversation-scoped counters, and no cross-conversation correlation — embodies data protection by design and by default (Art. 25 GDPR). The data minimisation achieved (only tokens egress; raw PII never leaves the machine) is exemplary.

**No blocking privacy defects were found.** The sprint can proceed to implementation.

### Recommendations (non-blocking)

These are privacy enhancements that would strengthen the design but are not required for DPO gate passage:

1. **REC-1 — Mapping size bound**: Consider adding an optional maximum mapping size (e.g., 10,000 entries) to prevent memory exhaustion in extremely long conversations. The vault sprint (QINDU-0008) will add TTL, but this sprint has no eviction mechanism.

2. **REC-2 — Token format validation in rehydrator**: The rehydrator should use a strict regex to identify tokens (matching the exact `<<TYPE_N>>` format with valid entity types) rather than a loose `<<...>>` pattern. This reduces the risk of misinterpreting arbitrary `<<like this>>` text as tokens.

3. **REC-3 — Memory-zeroing on conversation end**: When a conversation ends (future sprint), consider zeroing the freed mapping entries rather than relying on Go GC. This is a defense-in-depth measure against memory dump exposure (R1).

4. **REC-4 — Entity type allowlist for rehydration**: The rehydrator should only accept tokens whose `TYPE` matches a known `EntityType` constant. An AI response containing `<<PASSWORD_1>>` (not a recognized entity type) should be left as-is rather than triggering a map lookup. This prevents accidental rehydration of non-PII token-like strings.

5. **REC-5 — Coverage of secrets in token format**: The ARCHITECTURE.md and story.md mention `SECRET` and `PRIVATE_KEY` as tokenizable types. These carry higher sensitivity than emails or names (they represent credentials). Consider documenting to users that while tokens are opaque, the AI service learns *that* a secret was in the prompt. This is metadata leakage inherent in the design, but users should be aware of it.

---

## 7. Privacy Test Checklist

The following test scenarios must be covered by the implementation's test suite. The QA agent will verify these during the validation gate.

| ID | Test | Verifies |
|---|---|---|
| T1 | Tokenize text with 1 email → output contains `<<EMAIL_1>>`, zero raw email | R1, R2 |
| T2 | Tokenize text with 3 emails → `<<EMAIL_1>>`, `<<EMAIL_2>>`, `<<EMAIL_3>>` | R2 |
| T3 | Same email appears twice → same token both times | R6 |
| T4 | `rehydrate(tokenize(text))` → original text byte-for-byte | R3 |
| T5 | `rehydrate(tokenize(tokenize(text)))` → `rehydrate(tokenize(text))` | R6 |
| T6 | `rehydrate("<<EMAIL_99>>Hello")` → `"<<EMAIL_99>>Hello"` (token not in map) | R7, R13 |
| T7 | `rehydrate("Hello world")` → `"Hello world"` (no tokens) | R13 |
| T8 | Tokenize empty/whitespace input → empty output, no error | — |
| T9 | Tokenize 1 MiB + 1 byte → error, no PII in error message | R4, R9 |
| T10 | Concurrent tokenize + rehydrate → no data race, correct output | R5 |
| T11 | Tokenize all 8 entity types in one input → all replaced, zero raw PII | R1 |
| T12 | Right-to-left: entities at positions [0,5], [5,10], [10,15] → correct replacement | R10 |
| T13 | Tokenize text with `<<EMAIL_1>>` already in it (user typed it literally) → must not be confused with a token (handled by PII detection first, then tokenization) | R6 |
| T14 | Tokenized output scanned by QINDU-0005 recognizers → zero entities detected | R1 |
| T15 | All test data is synthetic (grep for `@example.com`, `555-`, test IBANs, test PANs) | R8 |
| T16 | Token format contains no PII: different PII values of same type get `<<TYPE_1>>`, `<<TYPE_2>>`, not `<<TYPE_base64(value)>>` | R2 |
| T17 | Error paths (empty input, oversized input, etc.) produce no PII in error messages | R4 |
| T18 | No `os.Create`, `os.WriteFile`, or database driver in tokenizer package | R12 |

---

*End of DPO requirements. This document is binding for the QINDU-0006 implementation and review gates.*
*ZERO PII disclosed in this document.*
