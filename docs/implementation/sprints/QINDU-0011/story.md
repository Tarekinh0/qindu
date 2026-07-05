# QINDU-0011: Adapter ChatGPT web + Infrastructure Provider-Agnostique

## Metadata

| Field | Value |
|---|---|
| **Sprint ID** | QINDU-0011 |
| **Title** | Adapter ChatGPT web + Infrastructure Provider-Agnostique |
| **Phase** | 4 — Enforce Pipeline |
| **Status** | IN PROGRESS |
| **ADR Ref** | ADR-002 (proxy architecture), ADR-004 (interceptor interface), ADR-008 (structured logging) |
| **Go Version** | 1.26 |

## Dependencies

| ID | Title | Status |
|---|---|---|
| QINDU-0001 | Proxy TLS local sélectif — Fondation | DONE (Interceptor interface, forward.go, selectInterceptor) |
| QINDU-0005 | Moteur PII Go-native — Recognizers | DONE (Engine, 9 recognizers) |

## Gates Required

| Gate | Agent | Stage |
|---|---|---|
| Quality Assurance | QA | Validation |

## Forbidden

- Modification of the existing `MonitorInterceptor` or `NoOpInterceptor` — the new interceptor is additive
- Modification of the `Interceptor` interface (`InterceptRequest` / `InterceptResponse`)
- Modification of `internal/pii/` package (consumed as-is)
- Modification of ADRs
- Hardcoded provider credentials or API keys
- PII values in any log output, error message, or structured log field
- Real PII in test fixtures — use the captured HAR files for structure reference only, synthetic data for tests

---

## Narrative

### Problem

The MonitorInterceptor (QINDU-0007) treats every SSE data line as raw text and runs PII detection blindly. This works but produces false positives: ChatGPT's internal tokens (JWT conduit tokens, hex hashes in metadata, message UUIDs) trigger spurious `JWT`, `SECRET`, and `HEX_HASH` detections. The noise drowns out real PII findings.

Worse, each AI provider structures its conversation data differently:

- **ChatGPT web** uses JSON Patch (RFC 6902) operations to build responses incrementally in a document tree. Text lives at `content.parts[]`. Everything else (conduit tokens, message markers, delta encoding headers) is metadata.
- **Claude web** uses flat SSE with `event:` names. Text lives at `content_block_delta.delta.text` when `delta.type == "text_delta"`. Thinking blocks, tool use, and signatures are separate.
- **Gemini web** uses a custom Google chunked protocol (`)]}'` prefix, size-prefixed arrays). Text lives in deeply nested `[messageId, ["text"]]` arrays with progressive updates.

The proxy must know WHERE text lives to scan only the right fields and ignore the rest. This knowledge is provider-specific and must be isolated behind a clean interface so future providers can be added without touching the proxy pipeline.

### Solution

Introduce a **provider-agnostic `ProviderInterceptor`** that delegates text extraction to small, isolated **provider plugins**. For this sprint, implement the agnostic infrastructure plus the first plugin: **ChatGPT web**.

The split:

- **Agnostic layer** (`internal/interceptor/`): owns the byte I/O loop, SSE frame boundary detection, PII engine invocation, log emission, and content-type dispatch. It never sees provider-specific JSON structure.
- **Provider plugin** (`internal/providers/<name>/`): owns the knowledge of where user/assistant text lives in the provider's JSON. For ChatGPT: which SSE event types contain text, how JSON Patch ops modify the document tree, how to extract `content.parts[]`.

### User story

> As a Qindu user in monitor mode, I type a prompt containing my email into ChatGPT. The monitor log shows exactly 1 EMAIL detection from my actual prompt text — not 15 false positives from ChatGPT's internal JWT tokens, hex hashes, and session IDs. The log is clean. I can trust that every detection entry represents real PII. When I switch to Claude, the same monitor mode correctly identifies PII in Claude's text deltas without false positives on thinking blocks. The experience is consistent across providers.

---

## Functional Description

### Architecture Overview

The sprint introduces two new concepts into the codebase:

1. **Provider Plugin Interface** — a Go interface that defines what every provider plugin must implement. It lives in `internal/providers/provider.go`. The interface covers: path matching (which URL endpoints this provider handles), request body text extraction, and SSE event handling (extract text from data lines, rewrite text back into data lines).

2. **ProviderInterceptor** — a new `proxy.Interceptor` implementation that wraps a provider plugin. It replaces `MonitorInterceptor` for connections that match a known provider domain. For unknown domains or non-conversation endpoints, `MonitorInterceptor` is used as the fallback.

For this sprint, the **only** plugin implemented is ChatGPT web. Claude and Gemini plugins are explicitly out of scope (QINDU-0012, QINDU-0014). However, the plugin interface and `ProviderInterceptor` are designed to accommodate them from day one. The Claude and Gemini HAR files have been analyzed and confirm the interface covers their patterns.

### Provider Plugin Interface

The interface defines the contract between the agnostic interceptor and a provider-specific plugin:

**Path matching**: Given an HTTP method and URL path, return whether this plugin handles the endpoint. For ChatGPT: matches `/backend-anon/f/conversation` and `/backend-api/f/conversation`. Non-conversation endpoints (telemetry, sentinel pings, static assets) are excluded.

**Request body extraction**: Given the raw request body bytes, return a list of text segments (byte start, byte end, text content) that should be scanned for PII. For ChatGPT: locate `messages[].content.parts[]` in the JSON. Return each string value as a segment. The interceptor scans these segments, accumulates any PII findings, and logs them. Request body is NOT modified in this sprint (that's QINDU-0009 enforce mode). The rewritten body path exists in the interface for forward compatibility but returns the original body unchanged.

**SSE event handling**: Given an SSE event type string (from the `event:` line or the JSON `type` field) and the parsed data JSON, return the text to scan and the data to forward downstream. For events that contain no user text, return empty text and the original data unchanged. This is the core of the false-positive elimination: the plugin silently drops JWT tokens, hex hashes, and metadata.

### ChatGPT Plugin — SSE Event Handling

The ChatGPT plugin must parse the heterogeneous SSE stream from the HAR file analysis. The stream contains these event types, classified by the plugin:

**Events containing user/assistant text — extract `content.parts[]`:**

- `input_message` — echo of the user's message. Text at `input_message.content.parts[]`.
- JSON Patch operations of type `append` targeting paths matching `*/content/parts/*` — incremental text appended to a content part in the document tree.

**Events containing NO text — pass through unchanged:**

- `delta_encoding` — format version marker (`"v1"`).
- `resume_conversation_token` — JWT conduit token for session routing.
- `message_marker` — timing/visibility markers (`user_visible_token`, `final_channel_token`).
- JSON Patch operations targeting non-text paths (`*/status`, `*/end_turn`, `*/metadata`, the `add` operation creating the initial message structure).

**Stream termination:** The `[DONE]` marker or EOF signals stream end.

### ChatGPT Plugin — JSON Patch State Machine

ChatGPT web uses RFC 6902 JSON Patch to build responses incrementally. The plugin must maintain a lightweight document tree in memory for the duration of one SSE stream (one HTTP connection):

1. On `input_message`: the plugin initializes the document tree with the echoed user message structure.
2. On `add` operations (`o: "add"`): creates new nodes in the document tree at the given path.
3. On `append` operations (`o: "append"`): appends text to an existing string value at the given path. Only paths matching the text content pattern trigger text extraction.
4. On `replace` operations (`o: "replace"`): replaces a value at the given path. Text paths trigger extraction.
5. On `patch` operations (`o: "patch"`): a batch of sub-operations applied sequentially.
6. On stream end (`[DONE]` or EOF): the document tree is discarded.

The document tree is minimal — only enough structure to resolve paths like `/message/content/parts/0` and know the current value. Full JSON Patch conformance is not required; only the subset actually used by ChatGPT.

### SSE Helper (Agnostic Layer)

Both ChatGPT and Claude web use SSE transport (`text/event-stream`). The agnostic layer provides a reusable SSE frame loop that:

1. Reads raw bytes from the upstream response body
2. Detects frame boundaries (`\n\n` or `\r\n\r\n`)
3. Parses `event:` and `data:` lines from each frame
4. Calls the plugin's SSE event handler with the event type and data JSON
5. Receives the rewritten data and extracted text from the plugin
6. Forwards the rewritten data downstream (assembled back into valid SSE format)
7. Accumulates extracted text across frames for batched PII scanning
8. Emits aggregated `monitor_scan` log entries using the same format as MonitorInterceptor

This SSE helper is used by the ChatGPT plugin and will be reused by the Claude plugin (QINDU-0012). The Gemini plugin will NOT use it — Gemini uses a custom chunked protocol.

### Interceptor Selection

The `selectInterceptor` function in `internal/proxy/proxy.go` is extended:

1. On startup, register all provider plugins with their domain mappings (from config: `providers.chatgpt.domains = ["chatgpt.com"]`).
2. When a CONNECT arrives for a domain:
   - If the domain matches a provider plugin AND the mode is `monitor`: create a `ProviderInterceptor` wired with that plugin.
   - If the domain matches a provider plugin AND the mode is `enforce`: refuse to start (enforce not yet implemented — QINDU-0009).
   - If the domain does NOT match any provider: fall back to `MonitorInterceptor` (existing behavior).
3. `ProviderInterceptor` uses `NoOpInterceptor` for request bodies in non-matching paths (path whitelisting, same logic as MonitorInterceptor).

### Log Format

The `ProviderInterceptor` emits the same `monitor_scan` structured log entries as `MonitorInterceptor`. Format is identical — same fields, same `pii_values_logged: false` guarantee. The caller cannot distinguish which interceptor produced a log entry. This is intentional: the interceptor is an implementation detail.

### Request Body Handling

For this sprint (monitor mode only), request body text extraction follows the same pattern as MonitorInterceptor:

1. Read the full request body
2. Call the plugin to extract text segments
3. Run PII detection on extracted segments only
4. Log results
5. Forward the original request body unchanged

Request body rewriting (for enforce mode) is declared in the plugin interface but returns the original body unchanged in this sprint.

---

## Package Structure

```
internal/
├── providers/                    ← NEW package
│   ├── provider.go               ← Plugin interface + TextSegment type
│   └── chatgpt/
│       ├── plugin.go             ← ChatGPT plugin: path matching, request extraction, SSE handling
│       ├── patch_tree.go         ← Minimal JSON Patch document tree state machine
│       └── plugin_test.go        ← Unit tests with synthetic ChatGPT-format JSON
│
├── interceptor/                  ← EXTENDED
│   ├── provider_interceptor.go   ← NEW: ProviderInterceptor implementation
│   ├── provider_interceptor_test.go ← NEW: Unit tests
│   ├── sse_helper.go            ← NEW: Agnostic SSE frame loop (shared by ChatGPT + Claude)
│   ├── sse_helper_test.go       ← NEW: SSE framing tests
│   ├── monitor.go               ← UNCHANGED
│   ├── sse.go                   ← UNCHANGED (MonitorInterceptor's SSE reader, not reused by ProviderInterceptor)
│   └── ...                       ← Other existing files unchanged
│
├── proxy/
│   ├── interceptor.go           ← Interface (UNCHANGED)
│   ├── forward.go               ← (UNCHANGED)
│   └── proxy.go                 ← MODIFIED: selectInterceptor extended with plugin registry
│
└── policy/
    └── config.go                ← Potentially MODIFIED: provider-to-plugin mapping in config validation
```

### Test Fixtures

The captured HAR files (`chatgpt.com.har`, `claude.ai.har`, `gemini.google.com.har`) are used **only for structure reference** during development. Test fixtures use **synthetic JSON** matching the ChatGPT conversation format with fake PII injected. No real PII, real JWT tokens, or real conversation content appears in test code.

---

## Acceptance Criteria

### Functional — unit-observable

1. **ChatGPT user message — PII detected**: A synthetic ChatGPT request JSON containing an email in `messages[].content.parts[]` triggers a `monitor_scan` log entry showing exactly 1 EMAIL entity. The request is forwarded unmodified.

2. **ChatGPT response — text PII detected**: A synthetic SSE stream mimicking ChatGPT's response format, with an email in a JSON Patch append to `content.parts[0]`, triggers a `monitor_scan` log entry. All SSE bytes pass through to the caller unmodified.

3. **ChatGPT response — metadata ignored**: A synthetic SSE stream containing a JWT in a `resume_conversation_token` event and an email in a `content.parts` append produces exactly 1 EMAIL detection (the JWT is ignored). No false positive for the conduit token.

4. **ChatGPT response — message markers ignored**: A synthetic SSE stream containing `message_marker` events with `user_visible_token` values produces zero PII detections (the marker value is not scanned).

5. **Non-conversation paths bypassed**: A request to `/ces/v1/t` (ChatGPT telemetry endpoint) with a body containing an email is forwarded without scanning. Zero `monitor_scan` log entries.

6. **Fallback to MonitorInterceptor**: A request to `claude.ai` (not yet implemented as a plugin in this sprint) uses MonitorInterceptor. PII is still detected (via raw body scanning), but the format is unoptimized — no false positive elimination for Claude metadata.

7. **ProviderInterceptor + MonitorInterceptor coexist**: The proxy starts successfully with both interceptors. Connections to `chatgpt.com` use ProviderInterceptor. Connections to `claude.ai` use MonitorInterceptor. Both produce correctly formatted `monitor_scan` log entries.

8. **SSE helper correctness**: The agnostic SSE frame loop correctly handles both `\n\n` and `\r\n\r\n` frame boundaries, `event:` and `data:` line parsing, and multiple data lines per frame (joined with newlines).

9. **JSON Patch state machine initialization**: When an `input_message` event arrives with `content.parts: ["hello@example.com"]`, the document tree is initialized and the text is correctly extracted from the parts array.

10. **JSON Patch state machine append**: When an `append` operation targeting `/message/content/parts/0` arrives with text `"Hello! my email is john@doe.com"`, the text is appended to the document tree and correctly extracted for PII scanning.

---

## Out of Scope

- Claude plugin (QINDU-0012)
- Gemini plugin (QINDU-0014)
- Tokenization of PII (QINDU-0009 — enforce mode)
- Rehydration of tokens in responses (QINDU-0009, QINDU-0010)
- Vault integration (already exists in QINDU-0008, but not wired into ProviderInterceptor in this sprint)
- Request body rewriting (enforce mode — interface declared but returns original body unchanged)
- Enforce mode startup (provider domains in enforce mode still refuse to start with fatal error)
- Non-SSE response handling for providers (only SSE streaming responses use the plugin's event handler; non-streaming provider responses use request body extraction only)
- Gemini custom chunked protocol reader (no StreamProcessor interface in this sprint — SSE only)
- Performance optimization, fuzzing, benchmarks

## Design Decisions (from grilling)

| Decision | Choice |
|---|---|
| Agnostic vs provider split | Agnostic layer owns byte I/O, SSE framing, PII engine, logging. Plugin owns JSON schema knowledge (text paths, event type filtering). |
| Plugin isolation | One plugin per provider in `internal/providers/<name>/`. Interface in `provider.go`. |
| SSE reuse | SSE frame loop is agnostic. ChatGPT and Claude plugins both use it. Gemini will not (custom protocol). |
| ChatGPT format | JSON Patch (RFC 6902 subset). Plugin maintains a lightweight document tree per SSE stream. |
| Claude format (analyzed, not implemented) | Flat SSE with `event:` names. Text at `content_block_delta.delta.text` filtered by `delta.type == "text_delta"`. Simple — confirms interface works for both strategies. |
| Gemini format (analyzed, not implemented) | Custom Google chunked protocol (`)]}'` + size-prefixed arrays). Will require a `StreamProcessor` abstraction when implemented. |
| Domain routing | Config maps provider name to domains. `selectInterceptor` constructs the right interceptor per connection based on domain. |
| MonitorInterceptor fallback | Unchanged. Used for providers without a plugin. Produces false positives on metadata — that's acceptable for unoptimized providers. |
| Log format | Identical to MonitorInterceptor's `monitor_scan`. Interceptor used is an implementation detail invisible in logs. |
| Plugin state lifecycle | One plugin session per SSE stream (HTTP connection). Created on first SSE frame, destroyed on `[DONE]` or EOF. |
| Request body handling | Plugin extracts text segments. Interceptor runs PII detection on segments. Body forwarded unmodified (monitor mode). Rewrite method declared but no-op in this sprint. |
