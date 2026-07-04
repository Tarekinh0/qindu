# CISO Security Requirements — QINDU-0007: Mode Monitor

**Author**: Qindu CISO (Chief Information Security Officer)
**Review stage**: Design Mode
**Sprint**: QINDU-0007 — Mode Monitor (détection sans modification)
**Date**: 2026-07-04

---

## 0. Executive Summary

QINDU-0007 introduces the first operational integration of the PII detection engine into the proxy pipeline. A `MonitorInterceptor` reads HTTP request/response bodies, runs the PII engine on them, emits structured JSON detection logs with entity metadata (NEVER PII values), and forwards all traffic unmodified.

From a threat-modeling perspective, the primary risks are:

1. **Memory exhaustion** via unbounded body/frame buffering before the engine size check (DoS)
2. **Log injection** via attacker-controlled HTTP metadata fields in structured log output
3. **Config validation bypass** leading to undefined interceptor behavior
4. **Accidental PII leakage** through log fields or error paths (mitigated by `Entity.SafeString()` and `json:"-"`, but requires verification)

The design is fundamentally sound — detection without modification is the correct first step. The requirements below close the identified gaps.

---

## 1. Attack Surface Analysis

### 1.1 New Attack Surface

| Surface | Description | Risk | Rationale |
|---------|-------------|------|-----------|
| **AS-1: Body buffering** | MonitorInterceptor reads full request/response bodies into memory before passing to engine | **HIGH** | An attacker sending a 100 MiB body exhausts memory even though detection is skipped — the buffer allocation happens *before* the engine size check. 100 concurrent connections × 1 MiB = 100 MiB; without Content-Length pre-check, a single connection could consume gigabytes. |
| **AS-2: SSE frame accumulation** | Per-frame buffer for `text/event-stream` responses accumulates bytes until `\n\n` delimiter | **MEDIUM** | A malicious upstream (or MITM upstream of Qindu) could send frames that never close, causing unbounded buffer growth. Individual frames may be large (AI responses with code blocks). Without a frame size cap, single frames could exhaust memory. |
| **AS-3: Structured log output** | Detection logs written to `os.Stderr` (JSON via slog) include attacker-influenced fields: `path`, `host` | **MEDIUM** | Log injection via HTTP path (newlines, control chars, JSON-like strings in path segments). slog properly escapes values, but user-controlled keys warrant defense-in-depth. |
| **AS-4: Interceptor injection** | `NewProxy` now accepts and stores a config-based interceptor selection | **LOW** | If config validation is bypassed, a nil interceptor or unexpected behavior could result. The interface contract is well-defined; the risk is a nil pointer dereference, not a security escalation. |
| **AS-5: Detection log volume** | Each PII detection event produces one JSON log line to stderr | **LOW** | A user flooding the proxy with PII-containing requests could generate high log volume. stderr on Windows goes to the service manager event buffer, which has default size limits. Not a practical DoS at user-behavior scale. |

### 1.2 Modified Attack Surface

| Surface | Description | Risk | Rationale |
|---------|-------------|------|-----------|
| **AS-6: Config mode validation** | `agent.mode` field validated in `Config.Validate()` — must accept only `transparent`, `monitor`, `enforce` | **LOW** | Well-bounded change with clear validation rule. Failure mode: invalid mode causes startup rejection (safe). |
| **AS-7: Interceptor selection in NewProxy** | Proxy constructor reads `cfg.Agent.Mode` to select NoOpInterceptor or MonitorInterceptor | **LOW** | Local code change within the same package. Default should remain safe if mode is somehow invalid. |

---

## 2. Threat Model (STRIDE-LM)

### 2.1 Spoofing

| Threat | Impact | Likelihood | Mitigation |
|--------|--------|------------|------------|
| **T-S1: Crafted input to trigger false positive detection** | LOW: User sees false detection, no operational impact | High | Engine confidence scores (0.55–1.0) communicate uncertainty. Acceptable — this is detection, not enforcement. |
| **T-S2: Encoded PII to bypass detection** (base64, rot13, URL-encoding) | MEDIUM: PII exfiltrates without detection | High | Engine does not decode — known limitation, not a code defect. Tracked for future recognizer enhancement. Not in scope for QINDU-0007. |
| **T-S3: Log injection via HTTP path to corrupt structured JSON logs** | MEDIUM: Malformed log entries could break log parsers or inject false entries | Low | slog JSON handler escapes values; user data goes into key-value pairs, not the message string. Path is logged as `"path": "/v1/chat/completions"` — Go's `net/http` sanitizes request URIs, rejecting raw newlines. See **SR-3** for defense-in-depth. |

### 2.2 Tampering

| Threat | Impact | Likelihood | Mitigation |
|--------|--------|------------|------------|
| **T-T1: Bypass detection via binary Content-Type** | LOW: By design — binary content is skipped | High | Content-Type routing is intentional. Binary bodies (images, audio) are not text — analyzing them would be meaningless. See **SR-8** for Content-Type vs Content-Length mismatch edge case. |
| **T-T2: Bypass detection via oversized body** | LOW: By design — bodies > 1 MiB are skipped | Medium | Engine rejects > 1 MiB with `ErrInputTooLarge`. The body is still forwarded. See **SR-1** for the pre-buffering concern. |
| **T-T3: Manipulate detection log output by controlling HTTP path** | LOW: slog escapes values; structured fields are key-value, not raw message injection | Very Low | Defense-in-depth: path sanitization (DPO-R4), length truncation (SR-3). |

### 2.3 Repudiation

| Threat | Impact | Likelihood | Mitigation |
|--------|--------|------------|------------|
| **T-R1: User denies sending PII, claims false positive** | LOW: Detection logs show entity type + position, but not the PII value. No cryptographic proof of detection. | Medium | This is a privacy-preserving design choice — storing the original body text for non-repudiation would violate zero-persistence principles. Logs are diagnostic, not forensic. Acceptable. |

### 2.4 Information Disclosure

| Threat | Impact | Likelihood | Mitigation |
|--------|--------|------------|------------|
| **T-I1: PII value leaked in log output** | **CRITICAL**: GDPR art. 5(1)(f), data breach | Low (with controls) | `Entity.Value` is tagged `json:"-"`. `String()` → `SafeString()`. Every detection log entry includes `"pii_values_logged": false`. DPO-R1 compliance MUST be verified by test (see AC-7, **SR-4**). |
| **T-I2: PII in memory via process dump** | **HIGH**: A local admin/root could dump the Qindu process and extract PII from body buffers | Medium | Mitigation: buffers are transient (per-request, GC'd after forwarding). A local admin can already read browser memory, keylog, or screen-capture. Qindu does not worsen the local threat model. See **SR-2** for buffer lifecycle verification. |
| **T-I3: Detection metadata reveals PII sharing patterns** (entity types, counts, provider, timestamp) | MEDIUM: Logs reveal *what kind* of PII was shared with which AI provider | High | Mitigation: `pii_logging: false` suppresses all detection logs (DPO-R3, **SR-6**). Logs are local-only, no telemetry (DPO-R11). |
| **T-I4: Timing side-channel reveals PII count** | LOW: Detection time correlates with entity count | Very Low | Engine processing time is negligible (~microseconds per entity). Not practically observable for local process. |

### 2.5 Denial of Service

| Threat | Impact | Likelihood | Mitigation |
|--------|--------|------------|------------|
| **T-D1: Oversized request/response body exhausts memory** | **HIGH**: A single 100 MiB body is fully buffered before the engine size check rejects it. | Medium | **BLOCKING**. The body is read into memory by the interceptor before `Engine.Detect()` is called. The engine rightly rejects > 1 MiB, but the damage is done. MUST check `Content-Length` before reading. See **SR-1**. |
| **T-D2: SSE frame never closes, buffer grows unbounded** | **HIGH**: A malicious upstream sends data without `\n\n` delimiter, causing unbounded buffer growth | Low | **BLOCKING**. MUST cap per-frame buffer to engine limit (1 MiB). If frame exceeds limit, skip detection, forward bytes, reset buffer. See **SR-7**. |
| **T-D3: Many concurrent PII-rich requests** | MEDIUM: 100 concurrent requests × 1 MiB body buffers = 100 MiB memory | Low | Go's goroutine scheduler handles concurrency. Memory is released per-request. Not a unique threat — true of any HTTP proxy. 1 MiB cap per body provides a hard bound (if **SR-1** is implemented). |
| **T-D4: Malformed HTTP bodies causing engine panic** | MEDIUM: A crafted body could trigger a regex panic in a recognizer | Very Low | Engine recognizers use Go's `regexp` which is linear-time and safe against ReDoS. 253 existing engine tests cover edge cases. The `Detect()` method does not panic on any known input. See **SR-16**. |

### 2.6 Elevation of Privilege

| Threat | Impact | Likelihood | Mitigation |
|--------|--------|------------|------------|
| **T-E1: Interceptor accesses HTTP headers beyond Content-Type** | LOW: Headers are available in the `*http.Request` and `*http.Response` objects passed to interceptor methods | N/A | The interceptor has access to full request/response objects by design (ADR-004). Headers are never scanned for PII (per story), never logged (except `content_type` per DPO sec 2.4). No privilege escalation — interceptor runs in-process with same privileges. |
| **T-E2: Interceptor could modify request/response despite monitor mode promise** | LOW: The interceptor returns a new `io.ReadCloser` which *could* contain different bytes | N/A | The story explicitly forbids modification. Test verification: AC-1 and AC-2 require byte-identical forwarding. **SR-9** requires tests to verify byte-for-byte equality. |

---

## 3. SSE-Specific Threats

### 3.1 Frame Boundary Manipulation

**Description**: SSE protocol uses `\n\n` as the frame delimiter (lines starting with `data:` within a frame). A malicious upstream could exploit the parser by:

- Sending continuous data without `\n\n` → frame buffer grows unbounded
- Sending `\n\n` within a `data:` field value → legitimate per spec, but splits the logical frame unexpectedly
- Sending lines with `data:` prefix and extremely long values → large per-frame buffers

**CISO assessment**: The SSE frame reader MUST enforce a **maximum frame size** equal to the engine's input limit (1 MiB). If a frame exceeds this limit before encountering `\n\n`:
- Skip detection for this frame
- Log a WARN with `bytes_received` and `bytes_limit` (no frame content, no PII)
- Forward all accumulated bytes as-is
- Reset the frame buffer

See **SR-7**.

### 3.2 Partial Frame Buffering Memory Risks

**Description**: Each SSE frame is accumulated in memory until `\n\n` is found. For a 500 KB frame, PII exists in memory for the duration of frame accumulation. For slow connections, this could be seconds to minutes.

**CISO assessment**: Acceptable. The alternative (no SSE inspection) would miss PII in AI responses. Mitigations:
- Frame buffers are per-frame only — each frame buffer is independent and released after processing (DPO-R6)
- 1 MiB maximum per frame (SR-7)
- Memory is transient and garbage-collected (SR-2)

### 3.3 Detection Copy vs. Forwarding Copy

**Description**: The story specifies: "detection runs on a copy of the frame data" — detection must not interfere with forwarding. This requires the SSE frame reader to tee the data: one path for detection (accumulated, analyzed, discarded), another for forwarding (streamed immediately to the browser, unmodified).

**CISO assessment**: The implementation MUST ensure that:
- Forwarding bytes are written to the browser immediately — not buffered waiting for detection to complete
- The detection copy and forwarding copy are truly independent byte slices (not a shared underlying array that could be corrupted)
- If detection fails (error, panic), forwarding continues unaffected

See **SR-10**.

---

## 4. Log Security

### 4.1 Structured Log Injection

**Description**: Detection log entries written via `slog.Info()` include these user-influenced fields:

| Field | Source | Attacker Control | Risk |
|-------|--------|-----------------|------|
| `path` | `req.URL.Path` (or sanitized per DPO-R4) | Partial — path segments limited by Go's HTTP parser | **LOW**: Go's `net/http` rejects raw `\r\n` in request URIs. URL encoding prevents log line injection. Path length is bounded by Go's default `MaxHeaderBytes`. |
| `host` | TLS SNI / `req.Host` | Partial — but domain router only allows AI provider domains | **LOW**: Only routed domains appear in the proxy pipeline. |
| `method` | HTTP method | Constrained set (GET, POST, etc.) | **NEGLIGIBLE** |
| `entities[]` | Engine output | Indirect — engine detection triggered by body content | **LOW**: Entity metadata is engine-generated (type, source, confidence, pos). No user-controlled strings. |

**slog JSON handler**: Go's `slog.JSONHandler` properly escapes all values. Even if a path contained a double-quote or backslash, it would be escaped. Log injection via key-value pairs is not a practical threat with `slog`.

See **SR-3** for defense-in-depth: path length truncation to prevent log bloat.

### 4.2 Log Tampering

**Description**: Detection logs go to `os.Stderr`, captured by the Windows Service Manager. Could a non-admin user clear or modify detection logs?

**CISO assessment**: On Windows, the Event Log requires `SeSecurityPrivilege` (Administrator) to clear. For stderr captured to a file by the service wrapper, file permissions are configurable. Qindu does not implement its own log storage — this is the OS/service manager's responsibility. LOW risk.

### 4.3 Log Volume DoS

**Description**: Each PII detection produces one log entry. High-frequency PII traffic could generate large log volumes.

**CISO assessment**: Not a practical threat at user scale. A single user interacting with ChatGPT produces 1 request every few seconds. Log entries are ~200–500 bytes each. Even 10,000 detections/day = ~5 MB. stderr is not persisted to disk by Qindu — it's streamed to the service manager. LOW risk.

---

## 5. Config Security

### 5.1 Mode Validation ByPass

**Description**: The `Config.Validate()` method must check `agent.mode` against the allowed set: `"transparent"`, `"monitor"`, `"enforce"`. If validation is missing or incomplete, an invalid mode could propagate to `NewProxy`, causing undefined behavior.

**CISO assessment**: **BLOCKING if missing.** The `Validate()` method currently does NOT validate `agent.mode`. It MUST be added. Invalid modes MUST cause `Validate()` to return an error with a clear message listing valid values.

See **SR-11**.

### 5.2 Enforce → Monitor Fallback

**Description**: When `agent.mode: enforce`, the proxy falls back to monitor mode with a WARN log. This is a graceful degradation for forward compatibility (QINDU-0009).

**CISO assessment**: The WARN log must clearly communicate that PII is **not being tokenized** and **still reaches AI providers** (DPO-R5). No crash, no error exit. This is a transparency requirement, not a security control. LOW risk.

### 5.3 Default Mode

**Description**: `DefaultConfig()` sets `Mode: "enforce"`. This means users with default config will start in monitor mode (enforce fallback).

**CISO assessment**: Acceptable. The INFO log at startup (DPO-R5) will inform the user of the actual mode. The default must remain safe — and it does (monitor fallback is safe — detection only, no modification).

---

## 6. Memory Safety

### 6.1 Body Buffering: The Content-Length Gap

**Description**: The interceptor reads the full body via `io.ReadAll(req.Body)` before passing the bytes to `Engine.Detect()`. `Engine.Detect()` checks `len(text) > e.maxInputLen` and returns `ErrInputTooLarge`. But by that point, the body is already fully in memory.

Consider an attacker sending `Content-Length: 1073741824` (1 GiB): the interceptor reads 1 GiB into memory, the engine rejects it, the interceptor returns a new reader with the 1 GiB buffer, and the body is forwarded. Memory is released after the request, but during processing, 1 GiB is consumed.

**CISO assessment**: **BLOCKING.** The interceptor MUST check `Content-Length` before reading the body:

1. If `req.ContentLength > engineLimit` (or `ContentLength` is `-1` for chunked/unknown), the body MAY exceed the limit.
2. For known `Content-Length > engineLimit`: **skip the body read entirely**. Return the original `req.Body` unread. Log a WARN with `content_length` and `bytes_limit` (no body content). Forward the request with the original body reader.
3. For `Content-Length <= engineLimit`: read the full body, run detection, return a new reader.
4. For chunked transfer encoding (`Content-Length == -1`): use a `io.LimitReader` to cap the read at `engineLimit + 1` bytes. If the limit is reached before EOF, skip detection and use `io.MultiReader` to combine the bytes already read with the remainder of the original body for forwarding. Log WARN.

See **SR-1**.

### 6.2 Buffer Lifecycle Verification

**Description**: After detection completes and forwarding starts, the body buffer must be eligible for garbage collection. The interceptor must not retain references.

**CISO assessment**: In Go, a `[]byte` created during `io.ReadAll()` is eligible for GC when no references remain. The interceptor reads the body, passes the bytes to `Engine.Detect()`, then returns `io.NopCloser(bytes.NewReader(bodyBytes))`. The `bodyBytes` slice is captured by `bytes.Reader` and released when the reader is consumed and destroyed. This is standard Go memory management — no explicit free needed. Acceptable.

See **SR-2** for test verification.

### 6.3 SSE Frame Buffer Caps

**Description**: As described in Section 3.1, the SSE frame accumulator must have a hard maximum size.

**CISO assessment**: **BLOCKING.** See **SR-7**.

---

## 7. Concurrency

### 7.1 Engine Concurrent Safety

**Description**: `Engine.Detect()` acquires `RLock`, copies the recognizer slice, releases `RUnlock`, then runs detection sequentially. Multiple goroutines can hold `RLock` concurrently, each getting their own copy of the recognizer list.

**CISO assessment**: The recognizer list copy under `RLock` ensures that even if someone calls a hypothetical `AddRecognizer()` (under `Lock`), the current `Detect()` runs with a stable snapshot. Recognizers are stateless (immutable regex patterns, stop-word maps). Concurrent calls to `Detect()` are safe. **VERIFIED: engine is concurrent-safe.**

### 7.2 Interceptor Body Reader Replacement

**Description**: In `forward.go`, the pattern is:

```go
modifiedReq, reqBody, err = interceptor.InterceptRequest(req)
modifiedReq.Body = reqBody
modifiedReq.Write(upWriter)
```

The interceptor reads the body, returns a new reader. The caller replaces the body and writes. All in a single goroutine per request. No concurrent access to the request object.

**CISO assessment**: No race condition. The `InterceptRequest` and `InterceptResponse` methods are called sequentially within `forwardRequestAndResponse`. The returned body reader is used immediately. Thread-safe by design.

### 7.3 SSE Detection and Forwarding Goroutines

**Description**: The SSE frame reader needs to forward bytes to the browser while simultaneously accumulating a copy for detection. If the detection goroutine writes to shared state, a race condition could occur.

**CISO assessment**: The implementation MUST use separate byte slices for the forwarding path and the detection path. If `io.TeeReader` is used, the underlying buffer (byte slice passed to `TeeReader.Write`) must not be reused until detection is complete. Recommended pattern:

```go
// Per-frame: copy bytes into a fresh buffer for detection
var frameBuf bytes.Buffer
teeReader := io.TeeReader(upstreamReader, &frameBuf)
io.Copy(browserWriter, teeReader) // forward to browser
engine.Detect(frameBuf.String())  // detect on copy (after forward completes)
```

See **SR-10**.

---

## 8. Requirements for DevSecOps

### BLOCKING Requirements (violation = sprint BLOCKED)

#### SR-1: Pre-check Content-Length before body buffering (BLOCKING)

**Requirement**: The MonitorInterceptor MUST check the request/response Content-Length before reading the body. If Content-Length is known and exceeds `Engine.MaxInputLen()`, skip the body read entirely. Return the original body reader unread. Log a WARN with `content_length` and `bytes_limit`.

For responses with chunked transfer encoding (Content-Length = -1), use `io.LimitReader` capped at `engineLimit + 1` to avoid unbounded reads.

**Rationale**: Without this check, a single oversized body can exhaust process memory. The `Engine.Detect()` size check happens after buffering — too late. This is the single highest-impact DoS vector in this sprint. Maps to STRIDE **T-D1**.

**Verification**: Unit test sending body > 1 MiB — verify interceptor does NOT read body, returns original reader, logs WARN.

---

#### SR-2: Verify buffer release after forwarding (BLOCKING)

**Requirement**: After the interceptor reads a body, runs detection, and returns a new `io.ReadCloser`, the body bytes must be released (eligible for GC) once the caller (forward.go) has consumed the returned reader and closed it. The interceptor MUST NOT retain any reference to the body bytes after returning.

**Rationale**: PII-containing buffers must be truly transient. Retaining references extends the window for memory-scraping attacks. Maps to STRIDE **T-I2**, DPO-R1.

**Verification**: Code review — verify `io.NopCloser(bytes.NewReader(bodyBytes))` is the only reference path. No global caches, no closure captures, no retained slices. The body bytes are owned solely by the returned reader.

---

#### SR-3: Truncate logged path to 512 bytes (BLOCKING)

**Requirement**: The `path` field in detection log entries MUST be truncated to 512 bytes (or the engine's input limit, whichever is smaller). This is defense-in-depth beyond DPO-R4 (which strips query params). The truncated path MUST be logged as-is without query string (use `req.URL.Path`).

**Rationale**: Go's `net/http` does not enforce a strict URI length limit beyond `DefaultMaxHeaderBytes` (1 MiB). A very long path (e.g., 64 KB of path segments) would bloat log entries. 512 bytes is sufficient for any legitimate AI API endpoint path. Maps to STRIDE **T-S3**, **T-D4**.

**Verification**: Unit test with a 10 KB URL path — verify logged `path` is truncated to 512 chars.

---

#### SR-4: Zero-PII-in-logs verification test (BLOCKING)

**Requirement**: Every code path that produces a detection log entry MUST be covered by a test that asserts:
- `pii_values_logged` key equals `false`
- No field value contains a substring of the synthetic PII used in the test body
- The `Entity.Value` field (tagged `json:"-"`) is not present in the log output

Use `slog.NewJSONHandler` with a `bytes.Buffer` as writer in tests, then `json.Unmarshal` the log output and assert field absence.

**Rationale**: DPO-R1 is the fundamental privacy guarantee. A single accidental PII leak in a log field is a data breach. Maps to STRIDE **T-I1**.

**Verification**: Test harness that intercepts structured log output and asserts zero PII values for all 9 entity types, including edge cases (empty body, binary body, oversized body, SSE frames).

---

#### SR-5: Sanitize Content-Type before logging (BLOCKING)

**Requirement**: The `content_type` field in detection logs MUST be sanitized. It should be extracted from the response header, lowercased, and trimmed. If the Content-Type header contains parameters (e.g., `text/plain; charset=utf-8`), only the media type portion (`text/plain`) should be logged.

**Rationale**: Content-Type is metadata, not PII. However, defense-in-depth: if a future code path accidentally includes a PII-containing header value under the Content-Type key, only the media type is logged. Also ensures consistent log format.

**Verification**: Unit test with `Content-Type: application/json; charset=utf-8` — verify logged `content_type` is `application/json`.

---

#### SR-6: Wire `pii_logging` config flag (BLOCKING — DPO-R3)

**Requirement**: The MonitorInterceptor MUST accept a `piiLogging bool` parameter (from `config.Logging.PIILogging`) and use it to gate ALL detection log output. When `false`:
- The engine still runs detection (for future enforcement tracking, and to avoid changing behavior semantics)
- Zero detection log entries are emitted
- Skip-reason logs (DEBUG: binary skip, oversized skip, missing Content-Type skip) are still emitted — these are operational logs, not detection logs
- The startup transparency message (DPO-R5) is still emitted

**Rationale**: `pii_logging` has been an unwired config field since QINDU-0001. This sprint produces the first actual PII detection logs — the flag must work now. Users who want silent monitoring (detection without log output) must have this option. Maps to DPO-R3 (BLOCKING), GDPR Art. 25(2) data protection by default.

**Verification**: Unit test with `piiLogging=false` — PII in body → verify zero log entries. Unit test with `piiLogging=true` → verify log entry present.

---

#### SR-7: SSE frame size cap (BLOCKING)

**Requirement**: The SSE frame reader MUST enforce a maximum frame size equal to the engine's input limit (1 MiB). If a frame exceeds this limit before encountering `\n\n`:
- Emit a WARN log with `bytes_received` and `bytes_limit` (NEVER frame content)
- Forward all accumulated bytes to the browser (do NOT drop data)
- Skip detection for this frame
- Reset the frame buffer

Additionally, a **per-frame accumulation timeout** of 30 seconds MUST be enforced. If a frame has not completed within 30 seconds of the first byte, treat it as oversized and follow the same skip-forward-reset path.

**Rationale**: Maps to STRIDE **T-D2** (unbounded buffer growth). Without a frame size cap, a malicious upstream (or a misconfigured AI provider) could exhaust memory. The timeout defends against slow-loris-style attacks on SSE frames (malicious upstream sends 1 byte per second forever). 30 seconds is generous for legitimate AI response frames.

**Verification**: Unit test with SSE frame > 1 MiB — verify WARN log, frame forwarded, buffer reset. Test with frame that never closes — verify timeout triggers skip.

---

#### SR-8: Content-Type vs Content-Length mismatch (BLOCKING)

**Requirement**: When a response declares `Content-Type: image/png` but `Content-Length: 50`, the interceptor skips detection (binary skip). But when the Content-Type is `text/plain` and Content-Length exceeds the engine limit, the SR-1 pre-check must trigger. The Content-Type routing and size pre-check MUST be independent: Content-Type gate comes first, but the size gate is still enforced for text types.

**Rationale**: Defense-in-depth. A Content-Type header could be spoofed by the upstream. If the upstream sends `Content-Type: text/plain` with a 100 MiB body, both the Content-Type gate (passes — it's text) and the size gate (triggers — exceeds limit) are evaluated. The size gate is the safety net.

**Verification**: Unit test with `Content-Type: text/plain`, `Content-Length: 2_000_000` → verify WARN log, detection skipped, body forwarded unread.

---

#### SR-9: Byte-identical forwarding verification (BLOCKING)

**Requirement**: For every request and response body (including SSE frames), the bytes written to the upstream/browser MUST be byte-identical to the original bytes. Tests MUST use `bytes.Equal(originalBody, forwardedBody)` assertion.

**Rationale**: Monitor mode's defining contract is zero modification. Any byte difference is a data integrity violation. Maps to STRIDE **T-E2**, AC-1, AC-2, AC-5.

**Verification**: Unit tests for request, response, SSE. For SSE: capture the full stream at the browser side, compare to original upstream bytes.

---

#### SR-10: SSE detection must not block forwarding (BLOCKING)

**Requirement**: SSE response bytes MUST be forwarded to the browser without waiting for detection to complete on each frame. If possible, detection should run on a copy while forwarding proceeds independently. If detection and forwarding share a single goroutine (simpler implementation), the detection execution time per frame MUST be negligible (< 1ms for typical frames) so that latency impact is imperceptible.

At minimum: detection on a frame copy, with forwarding proceeding immediately after the copy is made (not after detection completes).

**Rationale**: Maps to STRIDE **T-D2** (partial), Section 3.3. If detection blocks forwarding, SSE streaming latency becomes visible to the user — a functional regression. The story specifies: "detection runs on a copy of the frame data." The copy must not stall forwarding.

**Verification**: Integration test with an SSE stream of 100 frames — verify total forwarding time with detection enabled is within 5% of forwarding time with NoOpInterceptor.

---

#### SR-11: Validate `agent.mode` in Config.Validate() (BLOCKING)

**Requirement**: Add `agent.mode` validation to `Config.Validate()`. Accepted values: `"transparent"`, `"monitor"`, `"enforce"`. Invalid values must produce an error message listing valid modes. Empty string must be rejected.

**Additionally**: `NewProxy()` MUST apply a defensive default if mode is somehow invalid at the proxy level (defense-in-depth). If mode is not one of the three recognized values, log an ERROR and fall back to `NoOpInterceptor` (transparent mode — safe default that doesn't introduce new behavior).

**Rationale**: Maps to STRIDE **T-E1** (config bypass). Without validation, an invalid mode could produce undefined behavior or a nil interceptor dereference. The two-layer check (Validate + NewProxy default) follows defense-in-depth.

**Verification**: Unit tests for `Validate()` with valid and invalid modes. Unit test for `NewProxy` with invalid mode → NoOpInterceptor selected, ERROR logged.

---

#### SR-12: Defensive NewProxy interceptor selection (BLOCKING)

**Requirement**: The `NewProxy` constructor MUST defensively handle all mode values:

| Mode | Interceptor | Log |
|------|------------|-----|
| `"transparent"` | `NoOpInterceptor` | None (normal behavior) |
| `"monitor"` | `MonitorInterceptor` | INFO: "Monitor mode active: PII detection enabled..." (DPO-R5) |
| `"enforce"` | `MonitorInterceptor` | WARN: "Enforce mode not yet available..." (DPO-R5) |
| Any other value | `NoOpInterceptor` | ERROR: "Unknown agent.mode '%s': falling back to transparent (NoOpInterceptor)" |

**Rationale**: Defense-in-depth beyond config validation. If a code path bypasses `Validate()`, the proxy still starts safely. Maps to STRIDE **T-E1**.

**Verification**: Unit test for each mode value → correct interceptor selected. Unit test for invalid mode → NoOpInterceptor with ERROR log.

---

### NON-BLOCKING Requirements

#### SR-13: Log `host` field from TLS SNI, not request Host header

**Requirement**: The `host` field in detection logs SHOULD use the TLS SNI server name (available in the TLS connection state) rather than `req.Host`. The SNI is set by Qindu during upstream connection and is guaranteed to be a known AI provider domain (validated by `DomainRouter`). The `req.Host` header could be manipulated by the browser.

**Rationale**: Defense-in-depth for log metadata. SNI is more trustworthy than request Host header. This prevents a compromised browser extension from injecting arbitrary hostnames into detection logs. Maps to STRIDE **T-S3**.

---

#### SR-14: Add engine MaxInputLen() accessor

**Requirement**: The `Engine` type in `internal/pii/` SHOULD expose a `MaxInputLen() int` method so the MonitorInterceptor can check the size limit without hardcoding the constant.

**Rationale**: Avoids coupling the interceptor to the engine's internal constant. If the engine limit changes in the future, the interceptor automatically adapts. The story says "do not modify internal/pii/" — but adding a read-only accessor is a backwards-compatible addition, not a modification. If this is considered out of scope, the interceptor may hardcode/use the constant from `pii.DefaultMaxInputBytes`.

---

#### SR-15: Log entry msg field consistency

**Requirement**: All detection log entries SHOULD use a consistent `msg` value: `"pii_detected"`. Skip-reason WARN logs SHOULD use `"pii_detection_skipped"` with a `reason` field (`"oversize"`, `"binary"`, `"missing_content_type"`, `"sse_frame_oversize"`).

**Rationale**: Consistent message values enable log filtering and alerting. Maps to ADR-008.

---

#### SR-16: Engine panic recovery wrapper

**Requirement**: The MonitorInterceptor SHOULD wrap `Engine.Detect()` calls in a deferred `recover()` to prevent a panic in the detection engine from crashing the proxy. If a panic is caught, log an ERROR with the panic value (string only, never body content), skip detection, and forward traffic. The proxy MUST continue serving.

**Rationale**: The PII engine has 253 tests and uses Go's safe `regexp` (no backtracking, no ReDoS), but regex is complex. A panic in the engine should never crash the proxy. Maps to STRIDE **T-D4**. Defense-in-depth.

**Verification**: This is hard to unit-test (Go doesn't expose a way to force a regex panic). Code review verification is sufficient for this requirement.

---

#### SR-17: Tests for interceptor error paths

**Requirement**: Tests SHOULD cover error paths:
- Engine returns `ErrInputTooLarge` → interceptor handles gracefully
- Request body is nil (should never happen in practice, but `http.Request.Body` is `io.ReadCloser`, not `nil`-safe) → interceptor must not panic
- Response body is nil → interceptor must not panic
- Engine returns error (non-`ErrInputTooLarge`) → interceptor must not crash

**Rationale**: Robustness. Error paths that crash the proxy are DoS vectors. Maps to STRIDE **T-D4**.

**Verification**: Unit tests with mocked/nil bodies. Verify no panic, traffic forwarded.

---

#### SR-18: No detection log when Content-Type is missing (MPD requirement)

**Requirement**: When both `pii_logging: true` AND the response has no `Content-Type` header, the interceptor skips detection and logs a DEBUG-level skip reason. A DEBUG-level skip reason is NOT a detection log entry — this does not violate DPO-R3. This is consistent with DPO-R9 (defensive defaults).

**Rationale**: Without Content-Type, the content nature is unknown. Assuming text is unsafe — binary content could trigger false positives in regex recognizers. Maps to DPO-R9.

---

## 9. Integration Points

### 9.1 How MonitorInterceptor Integrates with forward.go

The `forwardRequestAndResponse` function in `forward.go` calls:
```go
modifiedReq, reqBody, err = interceptor.InterceptRequest(req)
if reqBody != nil {
    modifiedReq.Body = reqBody
}
modifiedReq.Write(upWriter)
```

For the **MonitorInterceptor**:

**InterceptRequest**:
1. Check `req.ContentLength` > engine limit → if so, return `(req, req.Body, nil)` with WARN log
2. Read body: `bodyBytes, err := io.ReadAll(req.Body)`
3. Close original body: `req.Body.Close()`
4. Run detection: `entities, err := engine.Detect(string(bodyBytes))`
5. If entities found AND `pii_logging`: emit structured log entry
6. Return `(req, io.NopCloser(bytes.NewReader(bodyBytes)), nil)`

**InterceptResponse**:
1. Check Content-Type → binary/multipart/missing → return `(resp, resp.Body, nil)` with DEBUG skip
2. If `text/event-stream`: enter SSE frame reader path
3. Check `resp.ContentLength` > engine limit → return original with WARN
4. If Content-Length unknown (chunked): use `io.LimitReader`
5. Read body, detect, log, return new reader

**No modifications to forward.go** — the existing body replacement pattern (`modifiedReq.Body = reqBody`) works with the returned reader. No changes to the interceptor interface or NoOpInterceptor. The implementation is a drop-in.

### 9.2 Changes to proxy.go

`NewProxy` currently hardcodes `&NoOpInterceptor{}`:

```go
interceptor: &NoOpInterceptor{},
```

Must be changed to select based on `cfg.Agent.Mode`:

```go
interceptor: selectInterceptor(cfg, engine, logger),
```

Where `selectInterceptor` implements the SR-12 decision table. The `MonitorInterceptor` constructor requires:
- `engine *pii.Engine` (created once at startup with all 9 recognizers)
- `piiLogging bool` (from `cfg.Logging.PIILogging`)
- `logger *slog.Logger` (for structured log output)

### 9.3 Engine Construction

The engine must be created in `NewProxy` (or in `main.go` and passed to `NewProxy`). Required recognizer registration order (per `engine.go` line 36-38, DPO-R7):
1. EMAIL (before NAME — dependency)
2. PHONE
3. IBAN
4. CREDIT_CARD
5. JWT
6. NAME (after EMAIL)
7. SECRET
8. PRIVATE_KEY

The number of recognizers is 8 (not 9 — NAME is one recognizer, not two). Wait, re-reading the story: "9 recognizers (EMAIL, PHONE, IBAN, CREDIT_CARD, JWT, NAME, SECRET, PRIVATE_KEY)" — that's 8 types. The recognizers may be more than 8 if some types use multiple recognizers (e.g., CREDIT_CARD uses prefix regex + Luhn). The exact list should match what QINDU-0005 provides. The story says "9 recognizers" — DevSecOps must verify the count with the engine package.

### 9.4 What MUST NOT Change

Per story's Forbidden section:
- `Interceptor` interface — unchanged
- `NoOpInterceptor` — unchanged
- `internal/pii/` package — consumed as-is (but see SR-14 for optional `MaxInputLen()` accessor)
- `forward.go` — the body replacement pattern is already compatible
- ADRs — unchanged

---

## 10. Residual Risks

| Risk | Post-Mitigation Level | Rationale |
|------|----------------------|-----------|
| PII still reaches AI providers in clear text | **HIGH** | Inherent to monitor mode. Mitigated by transparency logs (DPO-R5) and user education. Resolution: QINDU-0009 (enforcement mode). |
| Process memory dump reveals PII | **MEDIUM** | Requires local admin/root — same privilege model as reading browser memory. Buffers are transient. Qindu does not worsen the local threat model. |
| Encoded PII bypasses detection | **MEDIUM** | Engine does not decode (base64, URL-encoding). Users who intentionally encode PII will bypass detection. Tracked for future recognizer enhancement. |
| Detection metadata reveals sharing patterns | **LOW** | Mitigated by `pii_logging: false` (user control). Logs are local-only. |
| NAME inference produces incorrect personal data | **LOW** | Confidence scores communicate uncertainty. Inferred names never logged (only type+source+confidence). GDPR Art. 5(1)(d) accuracy concern is managed. |
| Large chunked body memory consumption | **LOW** | Addressed by SR-1 with `io.LimitReader` cap. Forwarding uses the original reader; detection uses a capped copy. |
| SSE frame timeout false positive | **LOW** | The 30-second frame timeout (SR-7) may trigger on legitimate slow AI responses (e.g., Claude generating a long code block line-by-line). Mitigation: WARN log only, forwarding continues. User experience is unaffected. |

---

## 11. Verdict

### APPROVED_WITH_REQUIREMENTS

The QINDU-0007 Monitor Mode story is **security-conscious by design**. The detection-without-modification architecture is the correct first step — it validates the pipeline without risking data integrity. The `Entity` struct's `json:"-"` tag and `SafeString()` method provide strong PII-in-log protection at the type level.

The blocking requirements identified in this review close critical gaps:

1. **SR-1** (Content-Length pre-check): The most impactful finding. Without it, a 1 GiB body is fully buffered before detection is skipped. This MUST be implemented before the sprint ships.

2. **SR-7** (SSE frame size cap): Unbounded frame buffer is a memory exhaustion vector. MUST be capped at the engine limit with a timeout.

3. **SR-6** (Wire `pii_logging`): The flag has been unwired since QINDU-0001. This sprint produces actual PII detection logs — the user MUST have control over log output via this flag.

4. **SR-11** (Config mode validation): Currently missing from `Validate()`. MUST be added to prevent undefined behavior from invalid mode values.

5. **SR-12** (Defensive NewProxy default): Defense-in-depth so that even a config validation bypass results in safe (transparent) behavior, not a crash.

All other requirements (SR-2 through SR-5, SR-8 through SR-10, SR-13 through SR-18) are important but can be verified during Review Mode without blocking the sprint.

The sprint does NOT weaken any ADR. It respects:
- **ADR-004**: Implements the `Interceptor` interface without modification
- **ADR-008**: Uses `slog` JSON structured logging with `pii_values_logged: false` compliance marker
- **ADR-003** (loopback binding): Unchanged — proxy still binds to `127.0.0.1` only
- **ADR-002** (local CA): Unchanged — TLS interception logic is untouched

No grounds for BLOCKED. All blocking concerns are captured as mandatory requirements above. The implementation must satisfy SR-1, SR-6, SR-7, SR-11, and SR-12 before the sprint can pass CISO Review in Review Mode.

---

## Appendix A: Requirements Summary

| ID | Requirement | Priority | Blocks Sprint? | Maps To |
|----|------------|----------|---------------|---------|
| **SR-1** | Content-Length pre-check before body buffering | MANDATORY | **YES** | T-D1, AS-1 |
| **SR-2** | Verify buffer release after forwarding | MANDATORY | **YES** | T-I2, DPO-R1 |
| **SR-3** | Truncate logged path to 512 bytes | MANDATORY | **YES** | T-S3, DPO-R4 |
| **SR-4** | Zero-PII-in-logs verification test | MANDATORY | **YES** | T-I1, DPO-R1 |
| **SR-5** | Sanitize Content-Type before logging | MANDATORY | **YES** | T-S3 |
| **SR-6** | Wire `pii_logging` config flag | MANDATORY | **YES** | DPO-R3 |
| **SR-7** | SSE frame size cap (1 MiB + 30s timeout) | MANDATORY | **YES** | T-D2, AS-2 |
| **SR-8** | Content-Type vs Content-Length mismatch handling | MANDATORY | **YES** | T-E1, AS-1 |
| **SR-9** | Byte-identical forwarding verification | MANDATORY | **YES** | T-E2, AC-1/2/5 |
| **SR-10** | SSE detection must not block forwarding | MANDATORY | **YES** | Section 3.3 |
| **SR-11** | Validate `agent.mode` in Config.Validate() | MANDATORY | **YES** | T-E1, AS-6 |
| **SR-12** | Defensive NewProxy interceptor selection | MANDATORY | **YES** | T-E1, AS-6 |
| **SR-13** | Log `host` from TLS SNI | SHOULD | No | T-S3 |
| **SR-14** | Engine MaxInputLen() accessor | SHOULD | No | — |
| **SR-15** | Consistent log `msg` field values | SHOULD | No | ADR-008 |
| **SR-16** | Engine panic recovery wrapper | SHOULD | No | T-D4 |
| **SR-17** | Tests for interceptor error paths | SHOULD | No | T-D4 |
| **SR-18** | Skip detection when Content-Type missing | MANDATORY | No | DPO-R9 |

## Appendix B: Interceptor Method Contracts

### InterceptRequest contract (MonitorInterceptor)

```
Input:  req *http.Request (from browser, TLS-decrypted)
Output:
  - Same *http.Request (may be the same pointer)
  - io.ReadCloser body reader containing EXACT same bytes as original
  - nil error (forwarding proceeds) OR non-nil error (forwarding aborted)

Behavior:
  - If Content-Length known AND > engine limit: return (req, req.Body, nil), WARN log
  - If Content-Length unknown: read via LimitReader(engineLimit+1)
    - If LimitReader exhausted: skip detection, return (req, originalReaderViaMultiReader, nil), WARN log
    - If full body read: detect, log if entities found + pii_logging, return (req, bytes.NewReader(body), nil)
  - If reading body fails: return (req, nil, err) — proxy aborts
  - Original req.Body is closed after reading
```

### InterceptResponse contract (MonitorInterceptor)

```
Input:  resp *http.Response (from upstream, TLS-decrypted)
Output:
  - Same *http.Response (may be the same pointer)
  - io.ReadCloser body reader containing EXACT same bytes as original
  - nil error (forwarding proceeds) OR non-nil error (forwarding aborted)

Behavior:
  - Check Content-Type header:
    - Missing → return (resp, resp.Body, nil), DEBUG log
    - image/*, audio/*, video/*, application/octet-stream, multipart/form-data → return (resp, resp.Body, nil), DEBUG log
    - text/event-stream → enter SSE frame reader path
    - application/json, text/* → proceed to body reading
  - If text/event-stream: wrap body in SSEFrameReader, return (resp, frameReader, nil)
    - SSEFrameReader handles per-frame detection internally
  - If non-streaming text: same size-check and read logic as InterceptRequest
    - Check Content-Length, use LimitReader if unknown
    - Read body, detect, log, return bytes.NewReader(body)
  - Original resp.Body is NOT closed if returned unchanged
  - Original resp.Body IS closed after reading if detected
```

### SSEFrameReader contract

```
Behavior:
  - Read bytes from upstream response body
  - Forward every byte immediately to the caller (browser) via Read()
  - Accumulate a copy of bytes until \n\n delimiter
  - When frame is complete:
    - Run Engine.Detect(frameCopy)
    - If entities found AND pii_logging: emit structured log entry with sse_frame: true
    - Reset frame buffer
  - If frame exceeds engine limit: WARN, skip detection, reset buffer, continue
  - If frame does not complete within 30s: WARN, skip detection, reset buffer, continue
  - When upstream body is exhausted (EOF): flush any remaining partial frame bytes (no detection on partial frames)
```

(End of file - total 507 lines)
