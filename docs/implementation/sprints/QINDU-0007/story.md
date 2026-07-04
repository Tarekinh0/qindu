# QINDU-0007: Mode Monitor (détection sans modification)

## Metadata

| Field | Value |
|---|---|
| **Sprint ID** | QINDU-0007 |
| **Title** | Mode Monitor (détection sans modification) |
| **Phase** | 2 — Moteur PII |
| **Status** | READY |
| **ADR Ref** | ADR-004 (interceptor interface), ADR-008 (structured logging) |
| **Go Version** | 1.26 |

## Dependencies

| ID | Title | Status |
|---|---|---|
| QINDU-0001 | Proxy TLS local sélectif — Fondation | DONE (NoOpInterceptor, forward.go pipeline) |
| QINDU-0005 | Moteur PII Go-native — Recognizers | DONE (Engine, 9 recognizers, Entity.SafeString()) |

## Gates Required

| Gate | Agent | Stage |
|---|---|---|
| Privacy by Design | DPO | Design + Review |
| Security Review | CISO | Design + Review |
| Quality Assurance | QA | Validation |

## Forbidden

- Modification of HTTP request or response bodies in monitor mode — traffic passes through unmodified
- PII values in any log output, error message, or structured log field
- PII detection results stored to disk or transmitted outside the process
- Real PII in test fixtures — synthetic data only
- Modification of the `Interceptor` interface or `NoOpInterceptor`
- Modification of the `internal/pii/` package (consumed as-is)
- Modification of ADRs

---

## Narrative

### Problem

Qindu currently proxies all AI traffic transparently via `NoOpInterceptor`. The PII detection engine exists (QINDU-0005, 9 recognizers, 253 tests) but is completely disconnected from the proxy pipeline. Users have no visibility into what PII leaves their machine when they interact with AI services. Before we can tokenize or block PII, we need the first operational integration: **detect and report PII in live traffic, without modifying a single byte.**

### Solution

Introduce a new proxy mode — **Monitor** — that runs the PII detection engine on HTTP request and response bodies passing through the proxy, logs detected entities in structured JSON format (zero PII values in logs), and forwards all traffic unmodified. This is the first real use of the `Interceptor` interface since QINDU-0001.

### User story

> As a Qindu user, I type a prompt containing my email address into ChatGPT. Qindu's monitor mode logs that an EMAIL entity was detected in my outgoing request, without altering what gets sent to OpenAI. I can see in the logs: "3 PII entities detected — 1 EMAIL, 1 PHONE, 1 IBAN — at positions 45-60, 120-138, 200-225". No PII values appear in the logs. My prompt reaches ChatGPT exactly as I typed it. If OpenAI's response happens to mention an email address, Qindu logs that too.

---

## Functional Description

### Proxy modes

The existing config field `agent.mode` is wired into the proxy's interceptor selection:

| Mode | Behavior |
|---|---|
| `transparent` | `NoOpInterceptor` — zero detection, zero inspection, passes all traffic through unchanged. Equivalent to current behavior. |
| `monitor` | **This sprint** — detects PII in request and response bodies, logs structured results, passes all traffic through unmodified. |
| `enforce` | Future (QINDU-0009) — tokenizes PII in requests, rehydrates in responses. In this sprint, if `enforce` is configured, the proxy REFUSES to start with a fatal error. No silent fallback. |

The config `agent.mode` field must be validated to accept only these three values.

### MonitorInterceptor behavior

The MonitorInterceptor implements the existing `Interceptor` interface. In monitor mode:

**Request processing** (`InterceptRequest`):
1. Read the full request body
2. Run the PII detection engine on the body text
3. If entities are found: emit a structured log entry with entity metadata (zero PII values)
4. Return the original request and a new body reader containing the exact same bytes

**Response processing** (`InterceptResponse`):
1. Inspect the response `Content-Type` header
2. If the content type is not analyzable (see Content-Type rules below): return the response unchanged
3. For streaming SSE responses (`text/event-stream`): process frame-by-frame (see SSE handling below)
4. For non-streaming text responses: read the full body, run detection, log results, return a new body reader with the exact same bytes
5. If entities are found: emit a structured log entry (per response, or per SSE frame)

**Zero-PII guarantee**: No log entry, error message, or structured field ever contains a PII value. The `Entity.SafeString()` method from `internal/pii/` is the only source of entity representation in logs. Every log entry includes `"pii_values_logged": false`.

### Content-Type rules

The interceptor analyzes only text-based content. The decision tree:

| Content-Type | Action |
|---|---|
| `application/json` | Analyze fully |
| `text/*` (except `text/event-stream`) | Analyze fully |
| `text/event-stream` | Analyze frame-by-frame (see SSE handling) |
| `multipart/form-data` | Skip (binary mixing) — log DEBUG skip reason |
| `image/*`, `audio/*`, `video/*` | Skip — log DEBUG skip reason |
| `application/octet-stream` | Skip — log DEBUG skip reason |
| Missing Content-Type header | Skip — defensive default |
| Body exceeds 1 MiB (engine limit) | Skip detection + WARN log. Body is still forwarded. |

Skipped bodies are forwarded unmodified with no latency impact.

### SSE (Server-Sent Events) handling

AI services (ChatGPT, Claude) return responses as SSE streams. The monitor interceptor must handle these:

1. The response body is wrapped in an SSE frame reader
2. Each complete SSE frame (text between `\n\n` delimiters, parsed for `data:` lines) is accumulated into a frame buffer
3. PII detection runs on the frame's text content once the frame is complete
4. Detection results are logged per-frame, per response (not per individual `data:` line)
5. Every byte of the original response passes through to the browser unmodified and unbuffered — detection runs on a copy of the frame data
6. If a single SSE frame exceeds the engine's input size limit: skip detection for that frame, log WARN, continue forwarding

### Log format

Detection logs are structured JSON per ADR-008. A single log entry per intercepted message (request, response, or SSE frame). Required fields:

- Standard slog fields: `time`, `level`, `msg`, `host`, `direction` (`"request"` or `"response"`)
- HTTP metadata: `method`, `path` (for requests); `status_code`, `content_type` (for responses)
- Detection summary: `entity_count` (integer), `entity_summary` (map of entity type → count, e.g. `{"EMAIL": 2, "PHONE": 1}`)
- Entity detail array: `entities` — list of objects with fields: `type`, `source`, `confidence`, `pos` (string `"start-end"`)
- Compliance marker: `"pii_values_logged": false`
- Processing metadata: `bytes_analyzed` (integer)
- SSE marker: `sse_frame` (boolean, true for per-frame detection in SSE responses)

When **no PII is detected**: emit nothing. Silence means clean. Logging "no PII found" for every request would create noise.

When **no entities are detected but the body was analyzed**: no log entry. Zero PII = zero log.

### Engine integration

The PII detection engine is created once at proxy startup with all 9 recognizers (EMAIL, PHONE, IBAN, CREDIT_CARD, JWT, NAME, SECRET, PRIVATE_KEY) and a 1 MiB input size limit. The same engine instance is shared across all connections and reused by the interceptor on every message.

### Config validation

The `agent.mode` field in `policy.Config.Validate()` must accept `"transparent"`, `"monitor"`, and `"enforce"`. Invalid values produce a validation error. The default mode in `DefaultConfig()` remains `"enforce"` (forward compatibility for QINDU-0009).

---

## Acceptance Criteria

### Functional — unit-observable

1. **Monitor mode PII detection — request**: A JSON request body containing a synthetic email triggers a structured log entry with `entity_count >= 1`, entity type `EMAIL`, `"pii_values_logged": false`. The request body forwarded to the upstream is byte-identical to the original.

2. **Monitor mode PII detection — response**: A JSON response body containing a synthetic phone number triggers a structured log entry. The response body forwarded to the browser is byte-identical to the original.

3. **Transparent mode — no detection**: In `transparent` mode, synthetic PII in request/response bodies produces zero log entries. Behavior identical to current NoOpInterceptor.

4. **Binary skip**: A response with `Content-Type: image/png` is forwarded unmodified with no detection attempts and no log entries.

5. **SSE frame detection**: A streaming `text/event-stream` response containing synthetic emails in SSE `data:` frames produces per-frame detection log entries. All original SSE bytes arrive at the browser unchanged.

6. **Oversize body skip**: A request body > 1 MiB is forwarded unmodified. A WARN log entry is emitted indicating detection was skipped (no PII values in the warning). The engine's size limit is respected.

7. **Zero-PII guarantee**: No structured log field, `msg` string, error message, or WARN log ever contains a PII value. Every detection log entry includes `"pii_values_logged": false`.

8. **No-PII silence**: When a request or response body contains zero PII entities, no log entry is emitted.

9. **Multiple entity types**: A body containing an email, a phone number, and an IBAN produces one log entry with `entity_count: 3`, `entity_summary: {"EMAIL": 1, "PHONE": 1, "IBAN": 1}`, and three entries in the `entities` array.

10. **Config validation**: `agent.mode` accepts `"transparent"`, `"monitor"`, `"enforce"`. Invalid values are rejected with a clear error message.

11. **Enforce refusal**: When config is `agent.mode: enforce`, the proxy REFUSES to start with a clear fatal error message. No silent fallback to monitor mode. The process exits with a non-zero code. This ensures users are never misled into thinking PII is being tokenized when it is not.

### QEMU VM scenarios (run by qemu-tester)

12. **ChatGPT prompt with PII**: On a Windows VM with Qindu installed (monitor mode), navigate to ChatGPT, type a prompt containing a synthetic email address and phone number. Verify the Qindu log file contains a detection log entry with `entity_count >= 2`, entity types `EMAIL` and `PHONE`, and `pii_values_logged: false`. Verify the prompt reaches ChatGPT and the AI responds normally.

13. **Claude conversation with PII**: Same scenario against Claude — prompt with synthetic IBAN and credit card number. Verify detection log entry with both entity types. Verify normal AI response.

14. **PII in AI response**: Ask ChatGPT to repeat back a synthetic phone number. Verify the response body is analyzed and a detection log entry appears for the AI's response as well as the request.

15. **No modification guarantee**: In a ChatGPT conversation, confirm that prompts containing PII produce coherent, correct AI responses — proving the request was not altered by the interceptor.

16. **Mode toggle via config**: Change `config.yaml` from `mode: monitor` to `mode: transparent`, restart the service. Send a ChatGPT prompt with synthetic PII. Verify zero detection log entries appear. Change back to `monitor`, restart, verify entries return.

---

## Package Structure

```
internal/
├── interceptor/           ← NEW package
│   ├── monitor.go         ← MonitorInterceptor implementation
│   └── monitor_test.go    ← Unit tests
├── proxy/
│   ├── interceptor.go     ← Interface (UNCHANGED, but may add doc comments)
│   ├── forward.go         ← (UNCHANGED)
│   └── proxy.go           ← MODIFIED: interceptor selection based on config mode
├── policy/
│   └── config.go          ← MODIFIED: validate agent.mode field
└── pii/
    └── (UNCHANGED — consumed as-is)
```

## Out of Scope

- Tokenization of PII (QINDU-0006 exists, but not wired in — that's QINDU-0009)
- Modification of any HTTP body content
- Vault integration (QINDU-0008)
- SSE rehydration (QINDU-0010)
- Provider-specific parsers (QINDU-0011, QINDU-0012)
- Config UI / tray icon integration (QINDU-0016)
- Endpoint rewriting (QINDU-0017)
- Performance optimization or latency measurement
- Fuzzing or benchmarks (deferred to dedicated sprint per R-007)
- Per-provider entity filtering or allow/deny lists

## Design Decisions (from grilling)

| Decision | Choice |
|---|---|
| Package placement | New `internal/interceptor/` package — interceptor implementations separate from proxy orchestration |
| Config wiring | `NewProxy` internally switches interceptor based on `agent.mode` |
| Mode mapping | `transparent`→NoOp, `monitor`→Monitor, `enforce`→FATAL (refuses start) |
| Content types | Analyze `application/json` + `text/*`; skip binary, multipart, missing Content-Type |
| SSE handling | Frame-by-frame detection; no full-stream buffering; pass-through unmodified |
| Oversize bodies | Skip detection + WARN; forward anyway |
| Body consumption | Full body read for detection; return fresh reader with same bytes; skip detection = return original body |
| Engine lifecycle | Created once at proxy startup, injected into MonitorInterceptor constructor |
| Testing | Unit tests for interceptor logic; integration tests for proxy pipeline; QEMU VM for real-world scenarios |
| Zero-PII logs | `Entity.SafeString()` only; `"pii_values_logged": false` in every detection log entry |
| Silence on clean | No log entry when zero PII detected |
