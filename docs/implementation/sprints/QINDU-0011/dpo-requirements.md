# DPO Requirements — QINDU-0011

- **Sprint**: QINDU-0011 — Adapter ChatGPT web + Infrastructure Provider-Agnostique
- **DPO Review Date**: 2026-07-05
- **Verdict**: PASS (with mandatory requirements below)

---

## 1. Story Summary

This sprint introduces a `ProviderInterceptor` that delegates text extraction to provider plugins instead of blindly running PII detection on raw SSE data lines. The first plugin targets ChatGPT web. The goal: eliminate false positives (JWT conduit tokens, hex hashes, message markers) by scanning only `content.parts[]` text, ignoring provider metadata. The architecture is provider-agnostic — the interceptor owns byte I/O, SSE framing, and PII engine invocation; plugins own JSON schema knowledge.

---

## 2. Data Processed — PII Categories

The following PII categories transit through the `ProviderInterceptor` → plugin → PII engine data flow (in memory only):

| Category | Source | Path |
|---|---|---|
| **Email addresses** | User prompts in request body | `messages[].content.parts[]` |
| **Email addresses, names, phones, credit cards, addresses** | Assistant responses in SSE stream | JSON Patch append/replace to `*/content/parts/*` |
| **User message text** (general) | `input_message` SSE event | `input_message.content.parts[]` |

PII categories detected: all 9 recognizers from the existing PII engine (email, phone, credit card, IBAN, SSN/fiscal ID, names, addresses, secrets, hex hashes).

**What is NEW versus MonitorInterceptor**:

| Data | MonitorInterceptor | ProviderInterceptor |
|---|---|---|
| Raw SSE data lines | Scanned (source of false positives) | **Not scanned** |
| JWT conduit tokens | Scanned (false positive) | **Excluded by plugin** |
| Message markers / timestamps | Scanned (false positive) | **Excluded by plugin** |
| `content.parts[]` text | Scanned (buried in JSON noise) | **Extracted and scanned in isolation** |
| Non-text JSON Patch paths (`*/status`, `*/metadata`) | Scanned (noise) | **Excluded by plugin** |

---

## 3. Purpose and Necessity

The purpose is to eliminate false positives that make monitor logs untrustworthy. A log flooded with spurious JWT/HEX_HASH/SECRET detections from ChatGPT's internal infrastructure forces users to ignore the log, defeating the purpose of monitoring. The ProviderInterceptor makes each `monitor_scan` entry actionable: every detection represents real PII.

This processing is necessary because the PII engine cannot distinguish provider metadata from user content without provider-specific knowledge. The false-positive rate on raw SSE streams from ChatGPT exceeds 90% (15+ false positives per message), making monitoring non-viable.

---

## 4. Minimization Basis

**Why scanning only `content.parts[]` is the minimum:**

- ChatGPT's SSE stream contains at least 7 event types; only 2 contain user/assistant text (`input_message`, text-targeted JSON Patch ops). The other 5+ types (delta_encoding, resume_conversation_token, message_marker, non-text JSON Patch paths) are provider infrastructure — scanning them produces false positives and serves no privacy purpose.
- The JSON Patch document tree reconstructs only the subset of the message structure needed to resolve `content/parts` paths. Full JSON Patch conformance is NOT implemented — only the subset ChatGPT actually uses. This is minimization by design: do not build or retain structure beyond what text extraction requires.
- Provider plugin state lives for the duration of one SSE stream only. No persistent storage, no cross-stream state, no accumulation.

**Why less would not work:** Removing the plugin layer and falling back to MonitorInterceptor for ChatGPT is the status quo — with 90%+ false positives. The plugin layer is the minimum architectural change needed to solve the false-positive problem.

---

## 5. Rights and Freedoms Risks

### R1 — Missed PII due to incomplete plugin coverage (HIGH)

**Risk**: If the ChatGPT plugin fails to extract text from a new or undocumented content path (e.g., a new field added in a ChatGPT update), real PII passes through unexamined. This is a false-negative risk that does not exist in MonitorInterceptor (which scans everything).

**Mitigation**:
- **DPO-R1.1 (MANDATORY)**: The plugin's text extraction must follow a **conservative default**: when the plugin encounters an SSE event type or JSON Patch path it does not recognize, it must fall back to extracting ALL string values from the event data for PII scanning. The plugin must never silently skip text. Only explicitly recognized non-text paths may be excluded.
- **DPO-R1.2 (MANDATORY)**: The plugin must log a WARNING when it encounters an unrecognized SSE event type (at most once per stream, to avoid log flooding). The log entry must contain the event type name (metadata, no PII) but never the event data content.

### R2 — In-memory document tree accumulation (MEDIUM)

**Risk**: The JSON Patch document tree accumulates the full reconstructed conversation in memory for the duration of the SSE stream. ChatGPT conversations can last minutes to hours. The tree holds user PII in clear text.

**Mitigation**:
- **DPO-R2.1 (MANDATORY)**: The document tree must never be serialized to disk, logged (at any level), or exposed outside the plugin package. All tree fields and methods must be unexported (package-private).
- **DPO-R2.2 (MANDATORY)**: On stream end (`[DONE]`, EOF, or any error), the document tree must be deterministically cleared — set the root reference to `nil` and allow Go's GC to reclaim all nodes.
- **DPO-R2.3 (MANDATORY)**: The tree must NOT be reused across SSE streams. Each new SSE stream (HTTP connection) must start with a fresh tree.

### R3 — Text segment data flow exposure (MEDIUM)

**Risk**: The text content returned by plugin extractors contains actual PII (email addresses, names, etc.). These segments travel from plugin → interceptor → PII engine. Any logging, metrics, or debugging along this path could leak PII.

**Mitigation**:
- **DPO-R3.1 (MANDATORY)**: The SSE helper and ProviderInterceptor must never log extracted text content, text segment byte offsets, or the parsed data JSON at any log level (DEBUG, INFO, WARN, ERROR). The SSE helper may log frame counts, event type names (metadata only), and byte throughput metrics.
- **DPO-R3.2 (MANDATORY)**: The `monitor_scan` log entries emitted by ProviderInterceptor must be **byte-for-byte identical in structure** to MonitorInterceptor's entries. Fields: `direction`, `result`, `bytes_analyzed`, `pii_values_logged: false` (always), and optionally `entity_count` + `entity_summary` (type counts only, never values). No new fields. No interceptor-identifying field.
- **DPO-R3.3 (MANDATORY)**: The `provider` field (provider name string, e.g., `"chatgpt"`) may be logged in `monitor_scan` entries as optional metadata. It is a configuration-derived label, not PII. If added, it must use a fixed, config-controlled string — never derived from request or response data.

### R4 — Plugin interface boundary (LOW)

**Risk**: The plugin interface defines the contract for data crossing between the agnostic layer and provider-specific code. If the contract is unclear about ownership or immutability, data could be mutated or leaked.

**Mitigation**:
- **DPO-R4.1 (MANDATORY)**: The `TextSegment` type must pass text content by value (Go `string`), not by reference to a shared underlying buffer. Byte offsets (`Start`, `End`) must index into the caller's buffer, not the plugin's internal state.
- **DPO-R4.2 (MANDATORY)**: The plugin's SSE event handler must NOT retain references to the parsed data JSON after returning. The caller owns the byte slice and may reuse or discard it.

### R5 — Enforce mode guard (HIGH if violated)

**Risk**: If a ProviderInterceptor is mistakenly created in enforce mode before tokenization is implemented (QINDU-0009), PII passes through un-tokenized despite the user believing enforce mode is active.

**Mitigation**:
- **DPO-R5.1 (MANDATORY)**: The `selectInterceptor` function must refuse to start (fatal error) when the agent `mode` is `enforce` and a provider domain matches a registered plugin. The error message must be clear: `"enforce mode is not yet supported for provider %s (pending QINDU-0009). Set mode to 'monitor' or disable this provider."`
- **DPO-R5.2 (MANDATORY)**: The request body rewriting method in the plugin interface (`RewriteRequestBody` or equivalent) must return the original body unchanged (identity pass-through) in this sprint. If called in any mode, it must not inspect or log the body content.

### R6 — Fallback transparency (LOW)

**Risk**: When a connection falls back to MonitorInterceptor (unknown provider), users may not realize their traffic is being monitored with the less precise raw-scanning approach, potentially missing false positives.

**Mitigation**:
- **DPO-R6.1 (RECOMMENDED)**: Log an INFO message at connection start indicating which interceptor was selected: `interceptor=ProviderInterceptor` with `provider=<name>` or `interceptor=MonitorInterceptor` (fallback). This log entry must contain only configuration-derived strings (host, provider name) and never PII.

---

## 6. Blocking Points

**None.** The architecture is sound from a privacy perspective. The plugin approach is privacy-positive: it reduces the attack surface of automated PII scanning from "everything in the SSE stream" to "only user/assistant text fields." All risks identified above have clear, implementable mitigations.

---

## 7. Required Privacy Tests

These tests verify that privacy constraints are enforced at the implementation level:

| # | Test Name | What It Verifies | DPO Ref |
|---|---|---|---|
| PT-1 | `TestPlugin_UnknownEventType_FallbackScan` | When ChatGPT plugin encounters an unrecognized SSE event type with string values, all strings are scanned for PII (no silent skip) | DPO-R1.1 |
| PT-2 | `TestPlugin_UnknownEventType_WarningLogged` | Unrecognized event type triggers exactly one WARN log entry per stream, containing the event type name but not the data content | DPO-R1.2 |
| PT-3 | `TestDocumentTree_NotSerializedToDisk` | Document tree nodes are never written to files, temp files, or any persistent storage | DPO-R2.1 |
| PT-4 | `TestDocumentTree_ClearedOnStreamEnd` | Tree root is set to nil on DONE/EOF/error; no references remain | DPO-R2.2 |
| PT-5 | `TestDocumentTree_NoCrossStreamLeak` | Two sequential SSE streams get independent trees; data from stream 1 is not visible in stream 2 | DPO-R2.3 |
| PT-6 | `TestSSEHelper_NoTextInLogs` | SSE helper logs contain only metadata (frame count, event type names). Extracted text, parsed JSON data, and byte contents never appear in log output | DPO-R3.1 |
| PT-7 | `TestProviderInterceptor_MonitorScanFormat` | `monitor_scan` entries from ProviderInterceptor match MonitorInterceptor's exact field set. No extra fields, no missing fields. `pii_values_logged` is always `false` | DPO-R3.2 |
| PT-8 | `TestProviderInterceptor_NoPIIInAnyLog` | Comprehensive grep of all log output for the test scenario: no email addresses, phone numbers, credit card numbers, or any PII recognizer pattern appears | DPO-R3.1, R3.2 |
| PT-9 | `TestTextSegment_PassedByValue` | TextSegment content is copied (Go string), not a slice into a shared buffer that could be mutated after return | DPO-R4.1 |
| PT-10 | `TestPlugin_NoBufferRetention` | After SSE event handler returns, the plugin holds no references to the caller's data JSON byte slice | DPO-R4.2 |
| PT-11 | `TestEnforceMode_RefusedForProvider` | Starting proxy with mode=enforce and providers.chatgpt.enabled=true produces a fatal error (not a warning, not a silent fallback to transparent) | DPO-R5.1 |
| PT-12 | `TestRewriteRequestBody_IdentityPassThrough` | The RewriteRequestBody method returns the original body bytes unchanged (byte-level equality) | DPO-R5.2 |
| PT-13 | `TestNonConversationPath_Bypassed` | Request to `/ces/v1/t` with PII in body: zero monitor_scan entries, body forwarded unmodified | AC-5 + minimization |
| PT-14 | `TestChatGPTMetadata_NoFalsePositives` | SSE stream with JWT in `resume_conversation_token`: zero PII detections for that event. Stream with email in `content.parts` append: exactly 1 EMAIL detection | AC-3, AC-4 |
| PT-15 | `TestTestFixtures_NoRealPII` | Static analysis: no test file contains real email addresses, real JWT tokens, real credit card numbers, or HAR-originating conversation fragments | Story: Forbidden |

---

## 8. Verdict

**PASS** — The sprint may proceed provided all DPO-R requirements (R1.1 through R5.2) are implemented and all privacy tests (PT-1 through PT-15) pass.

The ProviderInterceptor is a net privacy improvement over MonitorInterceptor for supported providers: it reduces the scope of automated PII scanning from opaque SSE data lines to known text fields, eliminating systemic false positives that undermine monitoring trustworthiness. The risks identified are structural (in-memory data flow, plugin coverage gaps) and are fully mitigated by the requirements above.

**Note to CISO**: The JSON Patch document tree (PR-T3 through PR-T5) and enforce mode guard (PR-T11) are security-relevant — coordinate on these during your review.
