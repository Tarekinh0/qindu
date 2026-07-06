# QINDU-0009: Mode Enforce + Réhydratation (non-streaming + SSE)

## Sprint Overview

This sprint delivers the **enforce pipeline** — the first sprint where PII is actively blocked from leaving the machine. It merges the original QINDU-0009 (non-streaming rehydration) and QINDU-0010 (SSE rehydration with sliding buffer) into a single deliverable, because ChatGPT responses are exclusively SSE and non-streaming-only would never fire for the demo provider.

**The demo milestone.** An operator sends a prompt containing an email address through ChatGPT. The proxy tokenizes `john@example.com` to `<<EMAIL_1>>` before the request reaches OpenAI's servers. The vault persists the mapping. The SSE response stream is rehydrated — `<<EMAIL_1>>` restored to `john@example.com` in the browser.

## Context & Dependencies

| Dependency | Status | What it provides |
|---|---|---|
| QINDU-0005 (PII Engine) | DONE ✅ | 9 recognizers, `engine.Detect()` |
| QINDU-0006 (Tokenizer) | DONE ✅ | `Tokenizer.Tokenize()`, `Tokenizer.Rehydrate()`, `WithPersister()`, `WithProvider()`, `WithConversationID()` |
| QINDU-0007 (Monitor mode) | DONE ✅ | `MonitorInterceptor`, `scanBody()`, `emitMonitorScan()`, SSE framing |
| QINDU-0008 (Vault) | DONE ✅ | `VaultManager`, per-user encrypted storage, `TokenPersister` interface |
| QINDU-0011 (ChatGPT adapter) | DONE ✅ | `ProviderPlugin`, `ChatGPTPlugin`, `text/event-stream` SSE parsing, `patchTree` |

**ADR anchors:** ADR-002 (proxy CONNECT MITM), ADR-004 (Interceptor interface), ADR-008 (slog JSON sans PII).

## Scope & Acceptance Criteria

### AC-1: Enforce mode selectable via config
- `agent.mode: "enforce"` is accepted by config validation.
- `selectInterceptor()` in `proxy.go` constructs the enforce pipeline instead of returning an error.
- If no provider plugins are registered, enforce mode starts with a basic interceptor that tokenizes full request bodies.

### AC-2: Request tokenization via ChatGPT adapter
- The user types a prompt containing an email (e.g., `"My email is john@example.com"`).
- The ChatGPT plugin extracts text segments from `messages[].content.parts[]`.
- The tokenizer replaces PII with `<<TYPE_N>>` tokens.
- The rewritten request body (with tokens, zero PII) is sent upstream to OpenAI.
- Token→value mappings are persisted to the per-user vault.

### AC-3: Vault persistence per conversation
- Each conversation gets a deterministic vault scope: `{Provider: "chatgpt", ConversationID: <hash-of-url-uuid>}`.
- The conversation UUID is derived from the URL path (`/backend-api/f/conversation/<uuid>/`) by extracting and hashing the UUID.
- For connections without a conversation ID in the URL, a per-connection random UUID is used.
- The `VaultManager` is wired per-connection in `handleMITM`: SID resolution → `GetOrCreate()` → per-connection tokenizer with `WithPersister(vault)`.

### AC-4: Non-streaming response rehydration
- For JSON responses (non-SSE), `Rehydrate()` scans the response body for `<<TYPE_N>>` tokens.
- Tokens are replaced with original PII values from the in-memory store (backed by vault).
- Unknown tokens pass through unchanged.
- Response is delivered to the browser with PII restored.

### AC-5: SSE response rehydration with sliding buffer
- SSE frames from ChatGPT are rehydrated per-frame using `Rehydrate()` on the frame `data:` payload.
- A sliding buffer (< 4KB) reassembles tokens split across SSE chunk boundaries (resolves R-004 chunk evasion for responses).
- Frame bytes are modified (tokens → PII) before being written to the browser.
- The SSE session (`chatGPTSession`) remains unchanged — extraction and rehydration are separate passes.
- Latency is not significantly increased relative to monitor mode.

### AC-6: Fail-closed on vault unavailability
- If the vault cannot be opened (SID resolution failure, disk full, key missing), the connection is rejected with 502.
- A structured error is logged with `pii_values_logged: false`.
- No PII leaves the machine un-tokenized.
- Config `fail_mode: "fail_open"` defaults are overridden — enforce mode is always fail-closed.

### AC-7: Monitor log compatibility
- The existing `monitor_scan` log format is preserved.
- When enforce mode acts on PII, optional fields `tokenized_count` (request) and `rehydrated_count` (response) are added.
- When counts are zero, fields are omitted — backward compatible with monitor mode logs.

### AC-8: Config fixes (R-024)
- `PIILogging bool` → `*bool` in `LoggingConfig`.
- `CertCacheEnabled bool` → `*bool` in `TLSConfig`.
- `FailMode string` → `*string` in `AgentConfig`.
- `MergeFileOverride()` correctly distinguishes "not set" from "explicitly set to false/empty."

### AC-9: Round-trip integration test via QEMU VM
- Real prompt sent through Qindu proxy to ChatGPT API.
- Tokenization verified: PII replaced with tokens in outbound request.
- Vault persistence verified: token→value mapping retrievable.
- Rehydration verified: tokens replaced with original PII in SSE response stream.
- Log sanitization verified: zero PII values in any log output.
- See `qemu-test-report.md` for detailed VM test results (API key from `.ssh/openai.key`).

### AC-10: Inherited requirements from QINDU-0008
- Per-connection vault wiring: `VaultManager.GetOrCreate()` called in connection handler.
- SID lookup failure → deny connection (fail-closed).
- Async channel overflow WARN test: verify that when the vault write buffer (1024) is full, a WARN is emitted without data loss, and the proxy continues in memory-only mode.
- DPO PT-1 through PT-12 integration-level verification (currently unit-tested at library level only).

## Architecture Decisions

These decisions were made during the orchestrator's design interview with the human operator:

| # | Decision | Rationale |
|---|---|---|
| **DD-1** | **Integration**: Extend `bodyScanConfig` with tokenizer callbacks (`tokenize`, `rehydrate`) | `scanBody()` already owns the full body processing lifecycle. Adding callbacks keeps all processing in one auditable function. |
| **DD-2** | **Request rewriting**: Interceptor-level `replaceSegments(body, segments) []byte` helper | Generic byte replacement, handles token/PII length differences. Plugins only do extraction — no rewriting code. |
| **DD-3** | **Response rehydration (non-streaming)**: `Rehydrate()` on full body after extraction | Uses `extractAllStringValues` for text extraction. ChatGPT plugin optionally implements `ResponseTextExtractor` for surgical extraction. Blind replacement is safe because `<<TYPE_N>>` contains no JSON-breaking characters. |
| **DD-4** | **SSE rehydration**: Blind `Rehydrate()` on frame `data:` bytes | JSON-safe: no PII type Qindu handles contains `"`, `\`, or control characters. Zero changes to `ProviderPluginSession` interface. Sliding buffer handles tokens split across chunk boundaries. |
| **DD-5** | **Conversation UUID**: Hash from URL path | Deterministic across connections. Extract conversation UUID from `/conversation/<uuid>/`, hash it for vault scope. Fallback to per-connection random UUID when no conversation ID in URL. |
| **DD-6** | **Vault wiring**: `handleMITM` creates per-connection tokenizer | SID resolution → `VaultManager.GetOrCreate()` → `tokenize.New(engine, WithPersister(vault), WithConversationID(hash))` → injected into request context. Interceptor reads from context. |
| **DD-7** | **Interceptor type**: New `EnforceInterceptor` struct | Separate from `ProviderInterceptor` to avoid runtime mode branches. Reuses shared functions (`classifyContentType`, `scanBody`) with different callbacks. |
| **DD-8** | **Config fix (R-024)**: `*bool` for bool fields, `*string` for FailMode | `yaml.v3` zero-value ambiguity. Fixes all three in one pass. |
| **DD-9** | **Fail mode**: Enforce is always fail-closed | If vault is unavailable, reject connection. `fail_open` would silently leak PII and defeat the purpose of enforce mode. |
| **DD-10** | **Log format**: `monitor_scan` with optional `tokenized_count`/`rehydrated_count` | Unified schema for monitor and enforce. Backward compatible. |
| **DD-11** | **Response extraction plugin**: Optional `ResponseTextExtractor` interface | Plugin can implement `ExtractResponseText(body) []TextSegment` for surgical extraction. Fallback: `extractAllStringValues`. ChatGPT implements it for proper response structure awareness. |

## Technical Design

### New types and methods

**`ResponseTextExtractor` interface** (in `internal/providers/provider.go`):
```go
// ResponseTextExtractor is an optional interface for provider plugins
// that support surgical text extraction from response bodies.
// If a plugin does not implement this, the interceptor falls back to
// extractAllStringValues (conservative but safe).
type ResponseTextExtractor interface {
    ExtractResponseText(body []byte) []TextSegment
}
```

**`EnforceInterceptor` struct** (in `internal/interceptor/`):
- Implements `proxy.Interceptor`.
- Fields: `engine *pii.Engine`, `plugin providers.ProviderPlugin`, `logger *slog.Logger`, `piiLogging bool`, `tokenizeSegments func([]TextSegment) []TextSegment`.
- `InterceptRequest`: extracts text, tokenizes segments, rewrites body via `replaceSegments`, logs with `tokenized_count`.
- `InterceptResponse`: for SSE → wraps body in rehydrating SSE frame reader; for JSON → extracts text, runs `Rehydrate()` on body, logs with `rehydrated_count`.

**`replaceSegments` function** (in `internal/interceptor/`):
- Signature: `func replaceSegments(body []byte, segments []TextSegment) []byte`
- Replaces each segment's original text with its (now tokenized) text.
- Processes segments right-to-left to handle length changes without invalidating offsets.
- Segments must be non-overlapping and sorted by Start ascending (engine guarantees this).

**Modified `bodyScanConfig`** (in `internal/interceptor/monitor.go`):
- New optional field: `tokenize func([]TextSegment) []TextSegment` — called after detection, before rewrite.
- New optional field: `rehydrate func([]byte) []byte` — called on body bytes for response path.
- When nil, existing monitor behavior is unchanged.

### Pipeline flows

**Request (enforce)**:
```
handleMITM:
  → resolve SID from TCP conn
  → vault = vaultManager.GetOrCreate(user, token)
  → convID = hashFromURL(req.URL.Path) || uuid.New()
  → tokenizer = tokenize.New(engine, WithPersister(vault), WithProvider("chatgpt"), WithConversationID(convID))
  → inject tokenizer into request.Context

EnforceInterceptor.InterceptRequest:
  → scanBody(body, bodyScanConfig{
      extractor: plugin.ExtractText,
      tokenize:  func(segs) { for each seg: seg.Text = tokenizer.Tokenize(seg.Text); return segs },
      rewriter:  func(body, segs) { return replaceSegments(body, segs) },
    })
    → scanBody emits monitor_scan with tokenized_count=N
    → returns body with PII replaced by <<TYPE_N>>
```

**Response non-streaming (enforce)**:
```
EnforceInterceptor.InterceptResponse:
  → scanBody(body, bodyScanConfig{
      extractor: plugin.ExtractText (or extractAllStringValues fallback),
      rehydrate: func(body) []byte { return []byte(tokenizer.Rehydrate(string(body))) },
      rewriter:  nil,
    })
    → scanBody emits monitor_scan with rehydrated_count=N
    → returns body with <<TYPE_N>> restored to PII
```

**Response SSE (enforce)**:
```
EnforceInterceptor.InterceptResponse:
  → Create enforceSSEReader wrapping resp.Body
  → For each SSE frame:
      1. Parse frame (event: type, data: payload) — existing SSE parsing
      2. session.HandleSSEEvent(eventType, data) → textToScan (for logging)
      3. data = tokenizer.Rehydrate(data)  ← blind replacement on data: payload
      4. engine.Detect(textToScan) → entities (for logging)
      5. Accumulate frame stats
      6. Write rehydrated frame bytes to browser
  → On stream end: emit aggregated monitor_scan with rehydrated_count
  → Sliding buffer (<4KB) reassembles tokens split across chunk boundaries
```

### Vault wiring in handleMITM

The `handleMITM` function in `internal/proxy/mitm.go` gains:
1. SID resolution from the TCP connection (on Windows: PID→SID via `session` package; on Unix: fallback to current user).
2. `vaultManager.GetOrCreate(resolvedUser, impersonationToken)` to get a per-user vault.
3. Conversation UUID derivation from request URL path.
4. Per-connection `Tokenizer` creation with vault persister.
5. Tokenizer injection into `http.Request.Context()`.

The `forwardRequestAndResponse` loop is unchanged. The interceptor picks up the tokenizer from context.

### Config changes (R-024)

In `internal/policy/config.go`:
- `LoggingConfig.PIILogging`: `bool` → `*bool`
- `TLSConfig.CertCacheEnabled`: `bool` → `*bool`
- `AgentConfig.FailMode`: `string` → `*string`
- `MergeFileOverride()`: check `!= nil` instead of zero-value checks for these fields.
- `Validate()` and all code reading these fields: dereference with nil-safe defaults.

The default for `FailMode` in enforce mode is `"fail_closed"`, overridden by config if explicitly set.
For monitor/transparent mode, `FailMode` defaults to `"fail_open"` (unchanged behavior).

### ChatGPT plugin changes

- Implements optional `ResponseTextExtractor` interface.
- `ExtractResponseText(body)`: parses response JSON, extracts text from `message.content.parts[]` (assistant reply structure).
- Returns nil/empty for metadata-only responses (prepare, sentinel, etc.).
- Uses the HAR file at `chatgpt.com.har` as ground truth for response formats.

### Sliding buffer for SSE chunked tokens

From QINDU-0010 original scope:
- When a token like `<<EMA` arrives in one chunk and `IL_1>>` in the next, the buffer reassembles.
- Buffer size: 4KB maximum (covers largest possible token `<<PRIVATE_KEY_999>>` ≈ 30 bytes with ample margin).
- Buffer logic: if frame data ends with a partial token pattern (matches `<<[A-Z_]*` prefix), hold remainder; prepend to next chunk.
- `tokenRegex` is used for both matching and detecting partial prefixes.

## Inherited Risks

| Risk | ID | Mitigation in this sprint |
|---|---|---|
| Chunking evasion (PII fragments) | R-004 | Resolved for responses via SSE sliding buffer. Request chunk evasion still accepted for V1. |
| Core dump PII exposure | R-005 | Accepted — Go runtime limitation. |
| Async channel overflow → silent loss | R-013 | Add integration test: verify WARN is emitted when buffer is full. |
| valueToToken PII keys on Go heap | R-017 | Accepted — documented trade-off. |
| IBAN/IP_ADDRESS not detected | R-023 | Accepted — gap in PII engine, not this sprint. |
| Adapter before enforce order | R-009 | Resolved — QINDU-0011 delivered before this sprint. |
| Config bool fields silently ignored | R-024 | FIXED in this sprint (*bool pointers). |
| Per-user vault.db not cleaned on uninstall | R-031 | Accepted — MSI limitation, documented. |
| SeImpersonatePrivilege GPO revocation | R-033 | Add WARNING at startup if privilege is absent (inherited requirement). |

## Inherited Tests from QINDU-0008

These 12 DPO privacy tests were unit-tested at library level. They must be verified at integration level:

| Test | What to verify |
|---|---|
| PT-1 | vault.db unreadable without vault.key |
| PT-2 | vault.key is 0600 (Unix) or ACL-restricted (Windows) |
| PT-3 | Startup sweep purges expired conversations |
| PT-4 | Background sweeper runs on schedule |
| PT-5 | Access-time check purges expired conversation |
| PT-6 | No PII in bbolt keys |
| PT-7 | Log messages with `pii_values_logged: false` contain zero PII |
| PT-8 | Paths in log messages are redacted |
| PT-9 | SID lookup failure closes connection (fail-closed) |
| PT-10 | Per-user vault isolation |
| PT-11 | Async channel backpressure doesn't silently drop PII |
| PT-12 | Graceful shutdown drains all pending writes |

## Testing Strategy

### Unit tests (in `internal/interceptor/`)
- `replaceSegments` with various token/PII length combinations.
- `EnforceInterceptor` request path with mock tokenizer.
- `EnforceInterceptor` response path (non-streaming) with mock rehydrator.
- SSE rehydration with mock tokenizer and token-containing frames.
- Sliding buffer: tokens split across 2, 3, and edge-of-buffer chunks.
- Conversation UUID derivation from URL paths.

### Integration tests
- Full enforce pipeline with testcontainers-go (mock AI server).
- Vault persistence: verify token→value survives process restart.
- Fail-closed: mock vault failure, verify 502 and zero PII leakage.
- Async channel overflow: generate enough concurrent writes to fill the 1024 buffer, verify WARN.

### QEMU VM API integration test
- Real HTTP prompt to ChatGPT API through Qindu proxy.
- Verify tokenization (inspect outbound request body via proxy debug log).
- Verify vault persistence (read vault.db after test).
- Verify SSE rehydration (inspect browser-side response).
- Verify zero PII in any log file.

### Regression tests
- Monitor mode: all existing `monitor_scan` tests must pass unchanged.
- Transparent mode: all existing NoOpInterceptor tests must pass unchanged.
- Config validation: `*bool`/`*string` changes must not break existing YAML parsing.
- `ProviderPlugin` interface: no breaking changes to existing plugins.

## Files Likely to Change

| File | Change |
|---|---|
| `internal/interceptor/monitor.go` | Add `tokenize`, `rehydrate` fields to `bodyScanConfig`; call them in `scanBody` |
| `internal/interceptor/enforce.go` | **New file**: `EnforceInterceptor` implementation |
| `internal/interceptor/enforce_sse.go` | **New file**: SSE reader with rehydration + sliding buffer |
| `internal/interceptor/segments.go` | **New file**: `replaceSegments()` helper |
| `internal/proxy/proxy.go` | Update `selectInterceptor()` for enforce mode; remove "not yet implemented" error |
| `internal/proxy/mitm.go` | Add SID resolution + vaultManager + per-connection tokenizer creation |
| `internal/policy/config.go` | Fix `*bool`/`*string` fields (R-024); validate enforce mode |
| `internal/providers/provider.go` | Add optional `ResponseTextExtractor` interface |
| `internal/providers/chatgpt/plugin.go` | Implement `ResponseTextExtractor`; no changes to `HandleSSEEvent` |
| `cmd/agent/proxy.go` | Create `VaultManager` at startup; pass to `NewProxy()` |

## Gates Required

| Gate | Agent | Deliverable |
|---|---|---|
| Design — DPO | qindu-dpo | `dpo-requirements.md` |
| Design — CISO | qindu-ciso | `ciso-requirements.md` |
| Implementation | qindu-devsecops | Code, tests, `dev-notes.md` |
| Peer Review | qindu-peer-reviewer | `peer-review.md` |
| Security Review | qindu-ciso | `ciso-review.md` |
| Privacy Review | qindu-dpo | `dpo-review.md` |
| Quality Review | qindu-qa | `qa-review.md` |
| Release Review | qindu-release | `release-review.md` |
| VM & API Test | qindu-qemu-tester | `qemu-test-report.md` |

## Forbidden

- PII in logs, test fixtures, or comments.
- Modifications to `docs/decisions/` ADRs.
- Breaking changes to `ProviderPlugin` or `ProviderPluginSession` interfaces.
- Hardcoded credentials or API keys.
- Buffering complete SSE response before rehydration.
- Telemetry, analytics, tracking, or network calls to non-AI destinations.
