# CISO Security Requirements — QINDU-0011

- **Author**: Qindu CISO
- **Sprint**: Adapter ChatGPT web + Infrastructure Provider-Agnostique
- **Date**: 2026-07-05
- **Verdict**: PASS (with blocking requirements)

---

## 1. Attack Surface (new or modified)

### 1.1 New surfaces

| # | Surface | Location | Exposure |
|---|---|---|---|
| AS-1 | SSE frame loop (agnostic) | `internal/interceptor/sse_helper.go` | Reads raw bytes from upstream, parses `event:`/`data:` lines, accumulates frames. Accepts arbitrary byte sequences from the upstream AI provider. |
| AS-2 | JSON Patch document tree | `internal/providers/chatgpt/patch_tree.go` | Per-SSE-stream in-memory state machine. Accepts serialized JSON Patch operations from upstream. Grows with each patch operation. Discarded at stream end. |
| AS-3 | Provider plugin interface | `internal/providers/provider.go` | Method dispatch boundary: `MatchPath()`, `ExtractRequestText()`, `HandleSSEEvent()`. Plugin code runs in the proxy process, same memory space. |
| AS-4 | Domain-based interceptor routing | `internal/proxy/proxy.go` (`selectInterceptor`) | New code path in `selectInterceptor` that maps domains to plugins. Extends the existing switch on `agent.mode`. |
| AS-5 | `ProviderInterceptor` | `internal/interceptor/provider_interceptor.go` | New `proxy.Interceptor` implementation. Owns SSE frame loop, plugin lifecycle, PII engine invocation, log emission. |

### 1.2 Unchanged surfaces (confirmed)

- **TLS interception / CA private key** — No code touched. ADR-002, ADR-003 unchanged.
- **Vault encryption (DPAPI)** — Out of scope for this sprint (QINDU-0009).
- **PII engine** (`internal/pii/`) — Consumed as-is. No modifications allowed per story constraints.
- **`MonitorInterceptor`** — Unchanged. Used as fallback.
- **`NoOpInterceptor`** — Unchanged.
- **`Interceptor` interface** — Unchanged (ADR-004).

---

## 2. Protected Assets

| Asset | Classification | Rationale |
|---|---|---|
| PII values in SSE stream text | HIGH — Must never leak to logs, disk, or cross-connection state | The plugin extracts text segments potentially containing emails, phones, IBANs, credit cards |
| Document tree memory | MEDIUM — Must be scoped to one SSE stream, zeroed on discard | Per ADR-008: decrypted PII only in memory. Tree holds extracted text from `content.parts[]` |
| Plugin state isolation | MEDIUM — State from connection A must not leak to connection B | One plugin instance per SSE stream, created via factory. Must be validated |
| SSE frame buffer | MEDIUM — Must not retain PII text of prior frames after frame processing completes | Reset after each frame boundary per existing MonitorInterceptor pattern |
| Domain routing config | MEDIUM — Provider-to-domain mapping determines which plugin sees which traffic | Malicious config could route to wrong plugin |
| `monitor_scan` log entries | MEDIUM — Must be indistinguishable from MonitorInterceptor's output | Same format, same `pii_values_logged: false` guarantee |

---

## 3. Threat Model (STRIDE)

### S-1: Spoofing — Domain routing bypass

**Threat**: An attacker with control over the browser's CONNECT target crafts a hostname like `chatgpt.com.attacker-controlled.tld` or `chatgpt.com%00.malicious` that evades the domain matcher but still routes traffic to a malicious upstream.

**Mitigation**: The `DomainRouter` already normalizes (lowercase, suffix match). ProviderInterceptor's own path matching adds a second layer: the plugin's `MatchPath()` is called with the actual URL path. Even if the domain matches, a non-conversation path (e.g., `/ces/v1/t`) is routed to `NoOpInterceptor`. The plugin must normalize host names defensively — strip port, reject NUL bytes, reject empty host.

### S-2: Tampering — Malformed SSE data lines

**Threat**: A malicious upstream sends deliberately malformed SSE: huge frames, frames with no `data:` line, frames containing only NUL bytes, frames with Unicode Bidirectional override characters, or duplicate `event:`/`data:` lines. This could corrupt the frame parser, confuse the JSON Patch state machine, or inject control characters into extracted text.

**Mitigation**: The SSE frame loop must enforce max frame size, handle `\r\n`, `\n`, and `\r` line endings uniformly, reject non-UTF-8 data lines, and never pass raw binary to the JSON parser without validation.

### S-3: Tampering — Malicious JSON Patch operations

**Threat**: A malicious upstream sends JSON Patch operations with:
- Path traversal: `"/../../etc/passwd"`, `"/../../../"` 
- `null` or non-string paths
- Operations targeting non-existent nodes (`replace` on a path that doesn't exist)
- Type-incompatible operations (`append` to a number, `remove` on the root)
- Gigantic patch arrays with thousands of operations
- Deeply nested `patch` operations (recursive sub-patches)

**Mitigation**: The patch tree must enforce strict path validation, max depth, max node count, and operation type compatibility. Unknown or malformed operations must be skipped (not applied) with a WARN log.

### S-4: Information Disclosure — Cross-connection plugin state leakage

**Threat**: A plugin instance is accidentally reused across two concurrent SSE connections (e.g., stored in a map keyed by something non-unique, or not properly scoped to a single connection lifecycle). PII extracted from connection A's `content.parts[]` bleeds into connection B's document tree.

**Mitigation**: Plugin instances must be created fresh per SSE stream via a factory function. No global/shared mutable state. Verified by test: two concurrent streams to `chatgpt.com` must produce independent `monitor_scan` entries with no cross-contamination of entity counts.

### S-5: Information Disclosure — PII in plugin error paths

**Threat**: Plugin code logs raw JSON data or extracted text containing PII on error paths (e.g., "failed to parse JSON: `{raw data}`").

**Mitigation**: All plugin log output must pass through the same redaction discipline as `MonitorInterceptor`. JSON parse errors must never include the raw input. Only sanitized metadata (operation index, path length, event type) may be logged.

### S-6: Denial of Service — Resource exhaustion on document tree

**Threat**: A malicious upstream (or a bug in ChatGPT's backend) sends an unbounded stream of `append` operations, growing the document tree without bound. Or sends deeply nested JSON Patch paths (`/a/a/a/a/...` repeated 10,000 levels deep). This exhausts Go heap memory, causing OOM kill of the entire proxy process — affecting all concurrent connections.

**Mitigation**: Hard resource bounds on the document tree:
- Max node count: 10,000 per stream
- Max path depth: 32 segments
- Max path segment length: 256 bytes
- Max cumulative text in tree: 1 MiB (aligned with engine max input)
Violations → abort detection for that stream, forward bytes unchanged, log WARN, destroy tree.

### S-7: Denial of Service — SSE frame loop hung on incomplete frame

**Threat**: Upstream sends `data: {"text": "abc` but never sends the closing `\n\n`. The frame buffer accumulates bytes indefinitely, eventually OOM.

**Mitigation**: Per-frame timeout (≤ 30 seconds, same pattern as existing `SSEFrameReader.defaultFrameTimeout`). On timeout: reset buffer, log WARN (`reason: sse_frame_timeout`), forward accumulated bytes, resume reading.

### S-8: Denial of Service — Plugin panic crashes proxy

**Threat**: A bug in `HandleSSEEvent()` or the JSON Patch tree panics (nil dereference, index out of range, type assertion failure). Without recovery, the panic propagates up the call stack and kills the goroutine handling that CONNECT tunnel — closing the connection for the user.

**Mitigation**: Every call from the agnostic layer into the plugin must be wrapped in `recover()`. A plugin panic must: (a) log an ERROR with the panic value (sanitized — no raw data), (b) fall back to raw byte forwarding for the remainder of the stream (MonitorInterceptor-style `extractSSEData` + detect), (c) NOT crash the goroutine.

### S-9: Elevation of Privilege — Plugin closing resources it doesn't own

**Threat**: A plugin calls `Close()` on the upstream response body or the downstream writer, disrupting the proxy's connection lifecycle.

**Mitigation**: The plugin interface must NOT expose `io.Closer` or raw TCP sockets. The agnostic layer owns the I/O lifecycle. Plugins receive parsed data (strings, JSON objects, byte slices) and return transformed data. They never receive raw readers/writers.

---

## 4. Blocking Security Requirements

### CS-11-01 — SSE Frame Size Limit

The agnostic SSE frame loop (`sse_helper.go`) MUST enforce a configurable maximum frame size with a hard default of **256 KiB** (`DefaultMaxProviderSSEFrameSize = 256 * 1024`). If the accumulated frame buffer exceeds this limit, the frame is forwarded in full (all bytes pass through to the caller), detection is skipped with a WARN log (`reason: "sse_frame_oversize"`), and the buffer is reset. This is the same pattern as `MonitorInterceptor`'s `SSEFrameReader` but with an independent, larger default appropriate for JSON Patch frames which can be bulkier than simple text frames.

**ASVS ref**: V5.1.4 (input validation — size limits)

### CS-11-02 — SSE Frame Timeout

The SSE frame loop MUST enforce a per-frame timeout (default **30 seconds**, configurable). If a frame starts accumulating (first byte received) but no `\n\n` or `\r\n\r\n` boundary appears within the timeout, the accumulated partial frame is forwarded as-is, the buffer is reset, and a WARN log is emitted (`reason: "sse_frame_timeout"`). Same pattern as existing `SSEFrameReader`.

**ASVS ref**: V5.1.5 (input validation — timeouts)

### CS-11-03 — JSON Patch Document Tree Resource Bounds

The `patch_tree.go` state machine MUST enforce per-stream hard limits:

| Limit | Value | Violation Action |
|---|---|---|
| Max nodes | 10,000 | Skip detection for stream, log WARN, forward bytes unchanged |
| Max path depth | 32 segments | Skip operation, log WARN, forward data unchanged |
| Max path segment length | 256 bytes | Skip operation, log WARN, forward data unchanged |
| Max cumulative text in tree | 1 MiB | Skip detection for stream, log WARN, forward bytes unchanged |

All limits are applied per SSE stream (per HTTP connection). When any limit is exceeded, the ProviderInterceptor enters a **degraded mode** for the remainder of that stream: all bytes are forwarded unchanged without PII detection, a single WARN log is emitted, and the document tree is destroyed. This is the same graceful-degradation pattern as `MonitorInterceptor`'s oversize-body handling.

**ASVS ref**: V5.1.4 (resource limits), V5.2.1 (safe deserialization)

### CS-11-04 — JSON Patch Path Sanitization

The JSON Patch path parser MUST reject and skip (with WARN log) any operation whose path:

1. Contains `..` (parent directory traversal equivalent in JSON Pointer)
2. Contains an empty path segment (e.g., `/foo//bar`)
3. Starts with `$` or `@` (JSON Pointer extension prefixes; ChatGPT web never uses them)
4. Exceeds 512 bytes total length

Valid path segments are: empty string (root), digits only (array indices), or alphanumeric + `_-` strings (object keys). Anything else is treated as suspicious and skipped.

Rationale: JSON Patch paths follow RFC 6901 (JSON Pointer). The ChatGPT web API only produces paths of the form `/message/content/parts/0` — single-character segments are array indices, others are simple object keys. Path traversal via `..` and extension prefixes are not part of the ChatGPT protocol and represent either a malicious upstream or an upstream behavior change that must be caught.

**ASVS ref**: V5.3.4 (path traversal prevention)

### CS-11-05 — Plugin Panic Recovery

Every call from the agnostic layer into a plugin method (`MatchPath`, `ExtractRequestText`, `HandleSSEEvent`, all factory functions) MUST be wrapped in a `defer recover()` block. On panic:

1. **Log an ERROR** with the panic value (string representation only — no raw request/response data). Include `"plugin":"<name>"`, `"method":"<method_name>"`, `"panic":"<string_value>"`.
2. **Fall back** to raw-byte forwarding using the same `extractSSEData()` function as MonitorInterceptor for the remainder of that stream (for SSE responses) or to `NoOpInterceptor` passthrough (for request bodies).
3. **Do NOT crash** the goroutine. The proxy connection remains open; only the plugin-optimized detection is lost for that stream.
4. **Log exactly one aggregated `monitor_scan`** entry at stream end (same format), with any entities already detected before the panic.

**ASVS ref**: V7.4.1 (error handling — no data leakage), V14.2.1 (safe deserialization)

### CS-11-06 — Plugin Per-Connection Isolation

Plugin instances MUST be created fresh for each SSE stream using a **factory function** (`NewPlugin() Plugin` or `NewPluginSession() PluginSession`). No plugin instance may be shared across concurrent connections. Any mutable state (document tree, accumulated text buffers, event counters) must be scoped to a single plugin instance and discarded when the stream ends (`[DONE]`, EOF, or error).

**Verification test**: Two concurrent SSE streams to `chatgpt.com`, each with distinct PII in their `content.parts[]`, must produce independent `monitor_scan` entries with entity counts matching only their own stream's PII. No cross-contamination.

**ASVS ref**: V4.1.1 (access control — data isolation)

### CS-11-07 — Hostname Normalization for Domain Routing

The `selectInterceptor` function, when matching a CONNECT host to a provider domain, MUST normalize the hostname:

1. **Lowercase** (already done by `DomainRouter.Route()`)
2. **Strip port suffix** — `chatgpt.com:443` → `chatgpt.com` (if not already stripped by `http.Request.Host`)
3. **Reject empty host** — return `NoOpInterceptor`
4. **Reject host containing NUL bytes** or control characters — return `NoOpInterceptor`, log WARN
5. **Use exact match or suffix match** — the existing `DomainRouter` pattern (`.domain`) is sufficient, but MUST be the single source of truth. No secondary/duplicate domain matching logic in ProviderInterceptor.

**ASVS ref**: V5.1.2 (input validation — domain sanitization)

### CS-11-08 — SSE Field Validation (retry, id, event)

The SSE frame loop MAY parse standard SSE fields (`event:`, `id:`, `retry:`). If `retry:` is parsed:
- Reject negative values, NaN, Inf
- Clamp to [0, 300,000] ms (5 minutes max)
- Never pass unvalidated numeric values to `time.After` or `time.NewTicker`

If `event:` or `id:` values exceed 256 bytes: truncate silently (these are metadata, not text to scan). Log a DEBUG entry.

**ASVS ref**: V5.1.1 (input validation — type/format)

### CS-11-09 — Plugin Output Validation

Before the agnostic layer uses any plugin return value (text segments, rewritten data, event classification), it MUST validate:

1. **Text segments** (`[]TextSegment`): nil check, each segment bounds checked (start ≤ end ≤ len(original body)), text content is valid UTF-8, no segment exceeds `maxInputLen`. Invalid segments → skip, log WARN.
2. **Rewritten data** (`[]byte`): nil check, max length ≤ 256 KiB (single data line), valid UTF-8. Invalid → use original data unchanged, log WARN.
3. **Event type strings**: non-nil, max 128 bytes, printable ASCII only (no control characters except space). Invalid → treat as unknown event type (pass through unchanged).

**ASVS ref**: V5.1.1 (input validation of external data)

### CS-11-10 — Log Format Consistency and Zero PII Guarantee

The `ProviderInterceptor` MUST:

1. Emit `monitor_scan` entries using the **identical format** as `MonitorInterceptor` (same field names, same `pii_values_logged: false`, same `direction`/`host`/`method`/`path`/`status_code`/`content_type` fields).
2. Never include extracted text, JSON Patch data, document tree values, or any substring of the upstream response body in ANY log entry (INFO, WARN, ERROR, DEBUG).
3. Log only sanitized metadata on error paths: operation count, path prefix length, frame size, event type string length — never the actual content.
4. Include a `interceptor: "provider"` field in `monitor_scan` entries for operational distinguishability (optional — the story says invisible, but this is useful for debugging and doesn't leak PII).

This aligns with ADR-008 (`pii_values_logged: false`, structured JSON via `slog`).

**ASVS ref**: V7.1.1 (logging without sensitive data), V7.3.1 (log integrity)

---

## 5. Mandatory Security Tests

| Test ID | Requirement | Description |
|---|---|---|
| **SEC-11-T1** | CS-11-01 | SSE frame of 300 KiB → forwarded completely, detection skipped, WARN logged with `reason: sse_frame_oversize` |
| **SEC-11-T2** | CS-11-02 | SSE stream sends partial frame (no closing `\n\n`) and stalls >30s → bytes forwarded, buffer reset, WARN with `reason: sse_frame_timeout` |
| **SEC-11-T3** | CS-11-03 | JSON Patch stream sends 15,000 operations → after 10,000 nodes, detection degrades, WARN logged, all bytes forwarded |
| **SEC-11-T4** | CS-11-03 | JSON Patch path with 64+ segments → operation skipped, WARN logged, frame forwarded |
| **SEC-11-T5** | CS-11-04 | JSON Patch operation with path `/../../etc/passwd` → skipped, WARN logged |
| **SEC-11-T6** | CS-11-04 | JSON Patch operation with path `/$secret/key` → skipped, WARN logged |
| **SEC-11-T7** | CS-11-05 | Plugin `HandleSSEEvent` panics (nil dereference simulation) → ERROR logged, `monitor_scan` still emitted, all bytes forwarded |
| **SEC-11-T8** | CS-11-06 | Two concurrent SSE streams with different PII → independent `monitor_scan` entries, no cross-contaminated entity counts |
| **SEC-11-T9** | CS-11-07 | CONNECT host `chatgpt.com%00.evil` → routed to `NoOpInterceptor`, WARN logged |
| **SEC-11-T10** | CS-11-09 | Plugin returns text segment with `start > end` → segment skipped, WARN logged, detection proceeds with other valid segments |
| **SEC-11-T11** | CS-11-10 | All log output from ProviderInterceptor searched for raw email patterns, phone numbers, SSns — zero matches |
| **SEC-11-T12** | CS-11-03 | Cumulative text in document tree exceeds 1 MiB → detection degrades, WARN logged |

---

## 6. Residual Risks

| Risk | Severity | Rationale | Acceptance |
|---|---|---|---|
| GPT model behavior change alters JSON Patch format silently | MEDIUM | If OpenAI changes the structure of `content.parts[]` or event types, the plugin may miss real PII or produce false negatives. Mitigation: path/event type changes are logged at DEBUG for operations; anomaly detection could be added as a future sprint. | **Accepted** — the proxy operates in monitor mode only for this sprint; worst case is missed PII detection (no data loss, no blocking of valid traffic). |
| Gemini custom protocol not covered by SSE helper | LOW | Gemini requires a `StreamProcessor` abstraction not yet designed. In this sprint, Gemini connections fall back to MonitorInterceptor (raw scanning). The risk is false positives on Gemini metadata — same as current state. | **Accepted** — explicitly out of scope for QINDU-0011. |
| Plugin interface evolution risk | LOW | Adding Claude (QINDU-0012) may expose gaps in the interface that the ChatGPT plugin didn't exercise. The SSE frame loop is shared, but event handling patterns differ. | **Accepted** — the interface is designed with Claude/Gemini HAR analysis confirming coverage. |
| Document tree memory retained after stream error | LOW | If a stream terminates abnormally (upstream TCP RST without EOF), the document tree may not be explicitly destroyed. It will be garbage-collected when the ProviderInterceptor is collected, but PII may linger on the Go heap longer than necessary. | **Accepted** — Go GC reclaims unreferenced memory; PII is never written to disk. Explicit zeroing could be added in a future sprint. |

---

## 7. Verdict

**PASS** — The sprint does not weaken the privacy proxy model or add unjustified attack surface. The provider-agnostic architecture with plugin isolation is sound. The blocking requirements above (CS-11-01 through CS-11-10) are testable, aligned with existing patterns in `MonitorInterceptor`, and do not introduce novel security primitives.

The sprint's use of existing infrastructure (`DomainRouter`, PII engine, `slog` logging, `Interceptor` interface) means:
- TLS interception is untouched (ADR-002, ADR-003)
- The interceptor interface is unchanged (ADR-004)
- Structured logging discipline is preserved (ADR-008)
- PII detection engine is consumed as-is — no modifications

The key risks are **memory safety of the JSON Patch document tree** and **plugin isolation**. Both are addressed by explicit resource bounds (CS-11-03, CS-11-04), panic recovery (CS-11-05), and per-connection scoping (CS-11-06).

**No request rewrite/enforce mode** — this sprint operates in monitor-only mode, which means all traffic is forwarded unchanged. This is the correct risk posture for the first provider plugin. Enforce mode (QINDU-0009) will require additional security review when implemented.
