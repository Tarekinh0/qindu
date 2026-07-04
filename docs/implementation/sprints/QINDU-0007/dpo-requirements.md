# DPO Requirements — QINDU-0007: Mode Monitor

**Author**: Qindu DPO (Data Protection Officer)
**Review stage**: Design Mode
**Sprint**: QINDU-0007 — Mode Monitor (détection sans modification)
**Date**: 2026-07-04

---

## 1. Story Summary

QINDU-0007 introduces **Monitor Mode** — the first operational integration of the PII detection engine
(QINDU-0005, 9 recognizers, 253 tests) into the proxy pipeline. The `MonitorInterceptor` implements the
existing `Interceptor` interface (ADR-004). It inspects HTTP request and response bodies for PII, emits
structured JSON detection logs (ADR-008), and forwards all traffic **unmodified**. Zero bytes are changed.
The detection engine and logs never expose PII values — only `Entity.SafeString()` representations and
byte offsets.

The proxy mode is selected via `agent.mode` in config (`transparent` / `monitor` / `enforce`-which-falls-back).
A new `internal/interceptor/` package hosts the `MonitorInterceptor`. The proxy wire-up in `NewProxy`
selects the appropriate interceptor based on config mode.

---

## 2. Data Processed — PII Categories

### 2.1 Directly observed PII (in body text)

The PII detection engine scans HTTP request/response bodies and identifies 9 entity types:

| Entity Type | GDPR Classification | Recognizer | Source |
|---|---|---|---|
| `EMAIL` | Personal data (Art. 4(1)) — directly identifies a natural person | Regex | `SourceRegex` |
| `PHONE` | Personal data — directly identifies | Regex | `SourceRegex` |
| `IBAN` | Personal data — bank account identifier | Regex + Mod97 validation | `SourceRegex`, `SourceMod97` |
| `CREDIT_CARD` | Personal data — financial instrument linked to person | Regex + Luhn validation | `SourceRegex`, `SourceLuhn` |
| `NAME` | Personal data — directly identifies | Inferred from email local-part | `SourceEmailInference` |
| `JWT` | Can contain personal data (claims: email, name, sub) | Structural (header.payload.signature) | `SourceStructural` |
| `SECRET` | Can contain credentials tied to a person (API keys, tokens) | Prefix + Entropy | `SourcePrefix`, `SourceEntropy` |
| `PRIVATE_KEY` | Can identify/authenticate a person (SSH, GPG, TLS keys) | PEM armor detection | `SourcePEMArmor` |

### 2.2 Inferred / derived PII

- **NAME from email**: The `NameFromEmailRecognizer` extracts the local-part of detected EMAIL entities
  and infers a human name (e.g., `john.doe@example.com` → `John Doe`). The inferred name is stored in
  `Entity.Value` (tagged `json:"-"` — never serialized). This is **derived personal data** under GDPR —
  even if the inference is wrong, the processing of email local-parts to produce candidate names is
  personal data processing.

### 2.3 HTTP metadata processed

| Field | GDPR Status | Risk |
|---|---|---|
| `method` | Not personal data | Safe |
| `path` | **Can contain personal data** (query parameters, path segments with identifiers) | **Requires sanitization** |
| `status_code` | Not personal data | Safe |
| `content_type` | Not personal data | Safe |
| `host` (domain) | Can reveal which AI service is used — metadata, not directly PII | Low risk |
| `bytes_analyzed` | Reveals body size — low-information metadata | Low risk |

### 2.4 Data NOT processed

- Request/response **headers** (except `Content-Type` for content-type routing) — not scanned for PII
- Request/response **headers** are not logged (except `content_type` in detection logs)
- Binary bodies (images, audio, video, octet-stream) — skipped entirely
- Multipart bodies — skipped entirely
- Bodies missing `Content-Type` — skipped (defensive default)
- Bodies > 1 MiB — skipped with WARN log
- User IP addresses, cookies, session tokens — never accessed by the monitor interceptor

---

## 3. Purpose — Why This Processing Is Necessary

Monitor mode serves **three lawful purposes** under GDPR:

1. **Transparency and self-awareness** (Art. 5(1)(a)): Users gain visibility into what personal data
   leaves their machine when interacting with AI services. This empowers them to make informed decisions
   about what they share. Without detection, users are blind to PII exfiltration.

2. **Data protection by design** (Art. 25): Monitor mode is the prerequisite for future enforcement
   modes (QINDU-0009 tokenization, QINDU-0010 rehydration). The detection pipeline must be validated
   in pass-through mode before any byte modification is attempted. This follows the principle of
   progressive assurance.

3. **Legitimate interest of the data subject** (Art. 6(1)(f)): The user (data subject) has a legitimate
   interest in knowing what personal data they are sharing. Qindu operates exclusively on the user's
   machine — there is no third-party data controller. The user is both the data subject and the
   controller of their own data within the Qindu context.

---

## 4. Minimization Basis — Why Less Would Not Work

### 4.1 Why all 9 recognizers are necessary

- **EMAIL, PHONE, IBAN, CREDIT_CARD**: Core PII categories. Removing any would blind the user to
  that class of data leaving their machine. A user who accidentally pastes an IBAN into a prompt
  deserves to know about it.
- **JWT**: Auth tokens often contain personal claims (email, name, user ID). Detecting JWT transmission
  is critical — a user who accidentally copies a JWT into a prompt is exfiltrating not just a token
  but all claims it carries.
- **NAME**: Removable in theory since it's inferred, not detected. But NAME detection has significant
  privacy utility — we can show users that their email address format reveals their real name,
  educating them about the privacy implication of using `firstname.lastname@` emails with AI providers.
- **SECRET, PRIVATE_KEY**: These are security-critical. While not strictly "personal data" under GDPR
  (they're credentials), accidental exfiltration of a private key or API secret is a security incident
  that directly impacts the data subject's rights. Detection serves the broader data protection mandate.

### 4.2 Why body inspection is necessary

AI prompts are the primary vector for accidental PII sharing. Inspecting only URLs or headers would
miss the vast majority of PII exposure. Body inspection with content-type filtering (text only) is
the minimum necessary scope.

### 4.3 Why structured logging is necessary

Without structured detection logs, the user gets no feedback from monitor mode — the feature would be
a no-op from the user's perspective. Structured logs allow the user (and future Qindu UIs) to
understand what was detected. The alternative (no logs) would defeat the transparency purpose.

### 4.4 What is minimized

- PII **values** are never logged — only type, source, confidence, and byte position
- Detection runs only on text-based content types — binary content is skipped
- When no PII is detected: **zero log output** (silence under normality)
- Entity-level detail (`entities` array with positions) is provided in detection logs, but position
  data alone cannot reconstruct the original PII value without the source body text
- The body text inspected by the engine exists only in memory and is never persisted

---

## 5. Rights and Freedoms Risks

### 5.1 Risk: PII still reaches the AI provider (HIGH)

**Description**: In monitor mode, PII is detected but **not blocked, tokenized, or modified**.
The user's email, phone number, credit card, etc. still reaches the AI provider (OpenAI, Anthropic,
Google, etc.) in clear text.

**DPO assessment**: This is the **defining characteristic** of monitor mode — detection without
enforcement. The risk is inherent to the feature and is acceptable **only if**:

- The user is **explicitly informed** that monitor mode does not block PII (transparency requirement)
- The user can **toggle** to a future enforcement mode when it becomes available (QINDU-0009)
- The detection logs serve as an **audit trail** of what was shared, enabling users to make informed
  decisions about their future behavior
- Qindu never claims or implies that monitor mode "protects" PII — it "detects and reports" PII

**This is the single most important transparency requirement for this sprint.**

### 5.2 Risk: Detection logs reveal metadata about PII sharing (MEDIUM)

**Description**: Detection logs contain entity types, counts, and byte positions. While no PII values
are included, the logs reveal **what kind of personal data** was sent, to **which provider**
(inferred from the `host` field), at **what time**. This metadata is itself information about
personal data processing.

**DPO assessment**: Acceptable because:
- Logs are stored **locally** on the user's machine
- No telemetry, analytics, or cloud upload of detection logs
- The `pii_logging` config flag provides user control over log verbosity
- Byte positions without the original body text cannot reconstruct PII values

**Mitigation**: The `pii_logging` config flag MUST be wired to suppress detection logs when set to `false`.
See Requirement **DPO-R3**.

### 5.3 Risk: URL path may contain PII in query parameters (MEDIUM)

**Description**: The detection log format includes `path` (the URL path of the request). Some AI provider
endpoints may include PII in query parameters (e.g., `?user_id=...`, `?email=...`). Logging raw paths
could inadvertently expose personal data.

**DPO assessment**: Require sanitization of the `path` field before logging. Query parameters should be
stripped. Path segments should be logged as-is (paths for AI API endpoints do not typically contain
PII in segment form, but query strings are a well-known PII vector).

**Mitigation**: See Requirement **DPO-R4**.

### 5.4 Risk: SSE frame buffering creates temporary PII copies (LOW)

**Description**: For SSE responses (`text/event-stream`), each complete frame is accumulated in a buffer
before PII detection runs. This buffer temporarily holds the frame text in memory. If the AI response
contains PII (e.g., the AI mentions a phone number from the prompt), that PII exists temporarily in
the frame buffer.

**DPO assessment**: Acceptable because:
- Buffering is per-frame, not per-stream — typical SSE frames are small (tens to hundreds of bytes)
- Buffers are transient and in memory only — garbage-collected after frame processing
- No accumulation across frames — each frame buffer is independent and short-lived
- This is unavoidable for any content inspection — the alternative (no SSE inspection) would miss
  PII in AI responses, which carry valuable transparency (the AI repeating a user's PII back to them
  is a critical detection scenario)

### 5.5 Risk: NAME inference produces incorrect personal data (LOW)

**Description**: The `NameFromEmailRecognizer` infers human names from email local-parts. Inference
can be wrong (e.g., `red.car@example.com` might be flagged as NAME `"Red Car"`). Under GDPR,
processing inaccurate personal data is a concern (Art. 5(1)(d) — accuracy principle).

**DPO assessment**: Acceptable because:
- Inferred NAME values are marked with `confidence` scores (0.55 for borderline, 0.70 for standard)
- Inferred NAME values are NEVER logged (stored in `Entity.Value`, tagged `json:"-"`)
- The detection log entry shows `type: "NAME"` and `source: "email_inference"` — the user can
  assess whether the inference is plausible
- The stop-word list prevents role accounts (`support@`, `noreply@`, etc.) from producing false names
- No automated decision is made based on NAME inference — detection is purely informational

### 5.6 Risk: Model collapse / training data contamination (MEDIUM, external)

**Description**: When a user sends PII to an AI provider and the provider uses that data for model
training (depending on the provider's data usage policy), the PII could become embedded in the AI
model's weights. This is a risk that exists **regardless of Qindu** — Qindu does not create this
risk, but monitor mode does not mitigate it either.

**DPO assessment**: This is a user education issue, not a Qindu design flaw. Qindu's enforcement
modes (QINDU-0009) will address this by tokenizing PII before it reaches the provider. For this
sprint, the transparency requirement (user informed that monitor mode does not block PII) is the
appropriate mitigation.

---

## 6. Blocking Points

**No blocking points identified.** The story design is privacy-conscious and well-aligned with
GDPR principles for a detection-only mode. The following items are **requirements**, not blockers:

- `pii_logging` flag must be wired (DPO-R3)
- Path sanitization in detection logs (DPO-R4)
- User transparency about monitor mode limitations (DPO-R5)
- Test fixtures must use synthetic PII only (DPO-R8) — already stated in story's "Forbidden" section

---

## 7. Requirements for DevSecOps

### DPO-R1 — Zero-PII in logs (MANDATORY, BLOCKING IF VIOLATED)

**Requirement**: No log entry, error message, structured field, `msg` string, `fmt.Sprintf` output,
`panic` message, or any other output channel may ever contain a raw PII value. This includes:

- `Entity.Value` — tagged `json:"-"`, never serialized. `String()` → `SafeString()`. No code path
  may call `entity.Value` outside the detection engine.
- Body text passed to the detection engine — must never be logged, even in DEBUG mode, even
  truncated. If logging is needed for debugging body content, use length/checksum only.
- Error messages from the engine (`ErrInputTooLarge`) — already safe (contains only sizes).
- Any custom error wrapping that includes PII-adjacent context.

**Verification**: Every acceptance criteria (AC-1 through AC-9) already addresses this. The `"pii_values_logged": false`
compliance marker in every detection log entry provides runtime attestation.

**Implementation note**: If DevSecOps needs to log body content for debugging during development,
use a compile-time build tag (`//go:build debug`) that is **never present in release builds**.

### DPO-R2 — Entity metadata format (MANDATORY)

**Requirement**: The detection log entry MUST contain:
- `entity_count` (integer, total entities detected)
- `entity_summary` (map of entity type → count)
- `entities[]` array with per-entity objects containing: `type`, `source`, `confidence`, `pos` (as `"start-end"` string)
- `pii_values_logged` set to `false`
- `bytes_analyzed` (integer)
- Per ADR-008: `time`, `level`, `msg`, `host`, `direction` (`"request"` or `"response"`)
- HTTP metadata: `method`, `path` (sanitized per DPO-R4), `status_code`, `content_type`

**Forbidden in detection log entries**:
- `Entity.Value` (any form, even truncated/masked/redacted — use entity type + position only)
- Raw body bytes or body checksums that could enable hash-lookup attacks
- User identifiers, cookies, session tokens, IP addresses

### DPO-R3 — Respect `pii_logging` config flag (MANDATORY)

**Background**: The `logging.pii_logging` field has existed in `Config` since QINDU-0001 and has been flagged
as unwired in multiple DPO reviews (DPO-F3 in QINDU-0001, DPO-F1 in QINDU-0002). It defaults to `false` in
`DefaultConfig()` and `configs/default.yaml`.

**Requirement**: The `MonitorInterceptor` MUST respect the `pii_logging` config flag. Behavior:

| `pii_logging` | Behavior |
|---|---|
| `true` | Full detection log entries emitted (entity metadata, positions, summary) |
| `false` | Detection log entries MUST be suppressed. PII detection still occurs (the engine runs), but zero log entries are produced. Effectively: silent monitoring. |

**Rationale**: The user must have control over whether detection metadata is logged. `pii_logging: false` is
the safe default — users who want visibility opt in. This aligns with data protection by default (Art. 25(2)).

**Implementation note**: The `MonitorInterceptor` constructor should accept the `pii_logging` flag (or the full
`Config` or `LoggingConfig`) and use it to gate `slog.Info()` calls for detection. The story's AC-8 (silence
when no PII) should naturally extend to "complete silence when `pii_logging: false`."

### DPO-R4 — URL path sanitization (MANDATORY)

**Requirement**: The `path` field logged in detection entries MUST be sanitized to remove query parameters.
The path should include only the URL path portion (up to but not including `?`). For example:
- `https://api.openai.com/v1/chat/completions?model=gpt-4` → log `path: "/v1/chat/completions"`
- `https://api.anthropic.com/v1/messages` → log `path: "/v1/messages"`

**Rationale**: Query parameters on AI API endpoints can contain user identifiers, API keys, or other
personal data. Stripping query strings is a defense-in-depth measure. The scheme and host are not
logged in the `path` field (they're in the `host` field).

**Implementation**: Use `req.URL.Path` (Go's `net/url` already strips query and fragment) instead of
`req.URL.String()` or `req.RequestURI`.

### DPO-R5 — User transparency about monitor mode limitations (MANDATORY)

**Requirement**: The implementation MUST provide clear transparency to the user that monitor mode
detects but does NOT block PII. This should be implemented as:

1. **At startup**: When `agent.mode` is `monitor`, emit an INFO log message stating clearly:
   ```
   "Monitor mode active: PII detection enabled, traffic passed through unmodified. PII still reaches AI providers. Use enforce mode (QINDU-0009) to tokenize PII."
   ```
   This log message MUST not contain any PII values.

2. **In the WARN for enforce fallback**: When `agent.mode: enforce` falls back to monitor, the WARN
   log should state:
   ```
   "Enforce mode not yet available (QINDU-0009 pending). Falling back to monitor mode. PII is detected but NOT tokenized — PII still reaches AI providers."
   ```

**Rationale**: The user must understand that their PII still reaches AI providers. Without this
transparency, users might mistakenly believe Qindu is blocking their PII, leading to a false sense
of security (cf. Section 5.1).

### DPO-R6 — SSE frame handling: transient buffers only (MANDATORY)

**Requirement**: The SSE frame reader MUST ensure:

1. Frame buffers are allocated per-frame and **independently** — no accumulation across the full
   stream. After a frame is processed (detection + forwarding), its buffer must be released.
2. Frame buffers exist only in **process memory** — never written to disk, never persisted.
3. If a single SSE frame exceeds the engine's input size limit (1 MiB), skip detection for that
   frame with a WARN log. The WARN log must not include the frame content or any PII.
4. The detection copy of frame data is separate from the forwarding copy — detection must not
   interfere with or delay forwarding.

**Rationale**: SSE frames from AI providers can contain content that the AI echoes back from the
user's prompt, potentially including PII. Buffers must be truly transient.

### DPO-R7 — Engine lifecycle: one instance, shared across connections (MANDATORY)

**Requirement**: The detection engine must be created **once** at proxy startup with all 9 recognizers,
then injected into the `MonitorInterceptor` constructor. It must be safe for concurrent use across
all connections (the engine already provides `sync.RWMutex` — verify this is sufficient).

**Forbidden**: Creating a new engine per request or per connection — wasteful and could mask threading
issues. The engine is stateless (all state is in the input text and recognizers, both immutable after
construction).

**Registration order**: The story does not specify recognizer registration order. The EMAIL recognizer
MUST be registered before the NAME recognizer (per `engine.go` line 36-37: "the NAME recognizer
depends on EMAIL results"). This ordering requirement is documented in the engine package. The
`MonitorInterceptor` must follow it.

### DPO-R8 — Test fixtures: synthetic data only (MANDATORY, BLOCKING IF VIOLATED)

**Requirement**: Test fixtures in `internal/interceptor/monitor_test.go` and any integration tests
MUST use exclusively **synthetic PII**. Synthetic means:

- Emails: `test.user@example.com`, `alice@test.org` (use `example.com`, `test.org`, or similar
  IANA-reserved domains)
- Phones: `+1-555-0100` through `+1-555-0199` (reserved for fiction per NANP)
- IBAN: Synthetic IBANs that pass mod97 but are clearly test values (e.g., `GB29NWBK60161331926819`
  is a well-known test IBAN, but prefer generating your own with clearly synthetic components)
- Credit cards: Use well-known test card numbers (e.g., `4111111111111111` for Visa test,
  `5500000000000004` for Mastercard test)
- Names: `Jane Doe`, `John Smith`, `Alice Test` — common synthetic names
- JWTs: Self-generated tokens with no real claims
- Private keys: Generated test keys, clearly labeled as test material

**Forbidden**: Real email addresses (even of consenting team members), real phone numbers, real IBANs
from any bank account, real credit card numbers, real names of identifiable persons, real JWTs from
any service, real private keys.

**Rationale**: Even in test code, real PII is a data breach waiting to happen. Git history is forever.
Test fixtures are checked into the repository. This has been a requirement since QINDU-0005 and must
be upheld.

### DPO-R9 — Content-Type decision tree: defensive defaults (MANDATORY)

**Requirement**: The content-type routing logic MUST:

1. When `Content-Type` header is **missing**: skip detection (defensive default). Do NOT assume text.
   Log a DEBUG skip reason.
2. When `Content-Type` is `text/event-stream`: use per-frame SSE detection. Do NOT attempt full-body
   detection on the stream.
3. When `Content-Type` is `multipart/form-data`: skip detection. The body mixes binary and text parts;
   the engine cannot safely parse it. Log a DEBUG skip reason.
4. When body size exceeds the engine's input limit (1 MiB): skip detection with a WARN log that
   includes `bytes_received` and `bytes_limit`, but **never** any body content. The body is still
   forwarded unmodified.

**Forbidden**: Any "best guess" heuristics about content type. If the Content-Type is unknown,
unrecognized, or missing: skip detection.

### DPO-R10 — Log destination and retention (RECOMMENDED)

**Requirement**: Detection logs are written to the configured log destination (currently `os.Stderr`
per `logging/logger.go`). In a Windows service context, stderr should be captured by the service
manager.

**Recommendation** (not blocking for this sprint, but should be tracked for QINDU-0016 / system tray):
- Implement log file rotation with configurable retention (e.g., 7 days default, max 30 days)
- Detection logs should NOT be stored permanently — they are diagnostic metadata, not audit records
- When QINDU-0008 (vault) is implemented, the vault will provide encrypted, persistent storage for
  PII token mappings — detection logs serve a different purpose and should have shorter retention

The absence of a formal retention policy does not block this sprint (detection logs contain metadata,
not PII values), but it should be tracked as a product requirement.

### DPO-R11 — No egress of PII or detection metadata (MANDATORY, IDEMPOTENT WITH ADRS)

**Requirement**: Confirm that no code path transmits:

- Raw PII values to any external service
- Detection log entries to any remote log aggregator (no Loki, no ELK, no cloud logging)
- Entity metadata to any analytics service
- User identifiers, machine identifiers, installation IDs

This is already enforced by Qindu's architecture (local proxy, zero telemetry) but must be verified
for the new `internal/interceptor/` package. The `Forbidden` section of the story already prohibits
"PII detection results stored to disk or transmitted outside the process."

### DPO-R12 — `pii_logging` override boolean: pointer-based fix (RECOMMENDED)

**Background**: The `PIILogging` bool field in `Config` suffers from the yaml.v3 zero-value problem
documented in QINDU-0002 (Peer PR-104, DPO-F1). When merging config overrides, absent boolean fields
are indistinguishable from explicitly `false`.

**Recommendation** (tracked from QINDU-0001 and QINDU-0002, not resolved yet): Change `PIILogging bool`
to `PIILogging *bool` to support three states: `nil` (not set), `true` (explicitly enabled), `false`
(explicitly disabled). This ensures config overrides work correctly.

**Impact**: Without this fix, a user who sets `pii_logging: true` in their override file will not
get the expected behavior if the base config has `pii_logging: false` (both are skipped in merge).
This is a **latent defect** — does not block QINDU-0007 because `pii_logging: false` is the default
in `DefaultConfig()` and the override skip preserves it. However, it must be resolved before
QINDU-0009 when enforcement and vault logging increase the importance of this flag.

---

## 8. Entity Type GDPR Implications

### EMAIL (Personal data — Art. 4(1))

Email is the quintessential personal identifier under GDPR. Detection is straightforward regex.
**No special GDPR concern beyond the standard zero-PII-in-logs requirement.**

### PHONE (Personal data — Art. 4(1))

Phone numbers directly identify individuals. Detection is regex-based with format validation.
**No special concern beyond standard requirements.**

### IBAN (Personal data — financial)

IBANs are bank account identifiers — sensitive financial personal data. Detection includes mod97
checksum validation for accuracy. **The user should be aware that sharing IBANs with AI providers
is particularly sensitive** — this is part of the user education that goes beyond the code and into
documentation/UI.

### CREDIT_CARD (Personal data — financial, sensitive)

Credit card numbers are among the most sensitive personal data categories. Detection includes Luhn
validation. **Same sensitivity concern as IBAN** — credit card numbers should never be shared with
AI providers. The detection log for CREDIT_CARD should be treated as a critical alert.

**DPO note**: For QINDU-0009 (enforcement), CREDIT_CARD and IBAN should have the most aggressive
tokenization policy. For QINDU-0007 (monitor only), detection is informational.

### NAME (Personal data — directly identifying, but inferred)

NAME entities are **inferred**, not directly matched. This creates unique GDPR considerations:

1. **Accuracy (Art. 5(1)(d))**: Inferred names may be wrong. The `confidence` field (0.55–0.70)
   communicates uncertainty. Detection logs show `source: "email_inference"` to distinguish from
   directly observed names.

2. **Derived data**: The NAME `Entity.Value` is derived from the EMAIL local-part. It is NOT the
   original text — it's a transformation (e.g., `john.doe` → `John Doe`). This derived value is
   tagged `json:"-"` (never serialized). The detection log never contains the inferred name, only
   the entity type, source, confidence, and position.

3. **Stop-word filtering**: Role accounts (`support@`, `noreply@`, `info@`, etc.) are excluded.
   27 stop words are defined in `name_email.go`. This is important for minimization — false NAME
   detections on role accounts would be noise that dilutes the utility of detection logs.

4. **Future consideration**: When QINDU-0009 introduces tokenization, the NAME entity should be
   handled with caution. Rehydrating an inferred name that the AI provider never saw is semantically
   different from redacting an email address. The inferred name exists only within Qindu's engine,
   not in the original prompt. Tokenization of NAME should be configurable.

### JWT (Can contain personal data)

JWTs are structured tokens that can contain personal data in their claims (email, name, sub, etc.).
Detection is structural (header.payload.signature pattern), not content-based. **Qindu does not
decode or inspect JWT claims** — it only detects the structural presence of a JWT.

**GDPR implication**: A JWT detected in a prompt represents potential PII exfiltration (all embedded
claims) even though Qindu cannot see what those claims are. Detection logs for JWT should be treated
as high-severity alerts during user education.

### SECRET (Security credentials — not strictly PII, but protection-critical)

Secrets (API keys, tokens, passwords in code) are detected via prefix matching and entropy analysis.
Under GDPR, secrets are not per se "personal data" unless they are linked to an identifiable person.
However:

- API keys for services like OpenAI are linked to the user's account (which IS personal data)
- Token exfiltration can lead to account compromise and subsequent personal data breaches
- Detection serves the data protection mandate even if the credential itself is not PII

**DPO note**: SECRET detection is a security feature that serves data protection. From a GDPR
perspective, it's a data-protection-by-design measure (Art. 25).

### PRIVATE_KEY (Authentication material — similar to SECRET)

Same analysis as SECRET. Private keys (SSH, GPG, TLS) are authentication material. Detection via
PEM armor patterns. **Serves data protection mandate. Not strictly PII under GDPR but adjacent.**

---

## 9. Data Flow Diagram (textual)

```
User Browser
     |
     | (TLS - MITM by Qindu)
     v
 MonitorInterceptor.InterceptRequest()
     |
     ├─ read body → bytes in memory (TRANSIENT, < 1 MiB)
     ├─ Engine.Detect(body) → []Entity with Value fields
     ├─ if entities found AND pii_logging=true:
     │    └─ slog.Info("pii_detected", entity metadata, pii_values_logged=false)
     ├─ body bytes → os.Stderr (JSON log entry, NO PII VALUES)
     └─ return original body reader with exact same bytes
     |
     v
 AI Provider (OpenAI / Anthropic / etc.)
     |  ← PII IN CLEAR TEXT (monitor mode does not modify)
     |
     v
 MonitorInterceptor.InterceptResponse()
     |
     ├─ check Content-Type
     ├─ if text/event-stream:
     │    ├─ accumulate frame (TRANSIENT memory buffer)
     │    ├─ Engine.Detect(frame_text)
     │    ├─ if entities found AND pii_logging=true: log per-frame
     │    └─ forward frame bytes unchanged
     ├─ if application/json or text/*:
     │    ├─ read body → bytes in memory
     │    ├─ Engine.Detect(body)
     │    ├─ if entities found AND pii_logging=true: log per-response
     │    └─ return new body reader with exact same bytes
     ├─ if binary/multipart: skip, forward unchanged
     └─ body bytes → os.Stderr (JSON log entry, NO PII VALUES)
     |
     v
 User Browser ← response bytes (UNMODIFIED)
```

All PII processing paths are:
- **In memory** (no filesystem, no persistent storage)
- **Transient** (garbage-collected after request/response completes)
- **Zero-copy for forwarding** (the original bytes pass through unmodified)
- **Logged without PII values** (only type, source, confidence, position metadata)

---

## 10. Summary of Requirements

| ID | Requirement | Priority | Blocks Sprint? |
|---|---|---|---|
| **DPO-R1** | Zero-PII in any log output, error message, or structured field | MANDATORY | **BLOCKING** |
| **DPO-R2** | Detection log format (entity metadata, compliance marker) | MANDATORY | No (format defined in story) |
| **DPO-R3** | Respect `pii_logging` config flag — suppress detection logs when `false` | MANDATORY | **YES — BLOCKING if unwired** |
| **DPO-R4** | URL path sanitization — strip query parameters from `path` in logs | MANDATORY | **BLOCKING** |
| **DPO-R5** | User transparency log messages at startup | MANDATORY | No (informational) |
| **DPO-R6** | SSE frame buffers transient only, per-frame, no accumulation | MANDATORY | No (design constraint) |
| **DPO-R7** | Single engine instance, concurrent-safe, EMAIL-before-NAME ordering | MANDATORY | No (design constraint) |
| **DPO-R8** | Test fixtures: synthetic PII only | MANDATORY | **BLOCKING** |
| **DPO-R9** | Content-Type decision tree with defensive defaults | MANDATORY | No (design constraint) |
| **DPO-R10** | Log retention policy (recommendation) | RECOMMENDED | No |
| **DPO-R11** | No egress of PII or detection metadata | MANDATORY | No (idempotent with ADRs) |
| **DPO-R12** | Pointer-based fix for `PIILogging` config override | RECOMMENDED | No (tracked from QINDU-0002) |

---

## 11. Verdict

### APPROVED_WITH_REQUIREMENTS

The QINDU-0007 Monitor Mode story is **privacy-conscious by design**. The architecture follows
data protection principles:

- **Data minimization**: Only text bodies are analyzed; binary content is skipped. Zero PII in logs.
  Silence when no PII detected. Entity metadata in logs is the minimum needed for user visibility.

- **Purpose limitation**: Detection serves the specific purpose of transparency — showing the user
  what PII leaves their machine. No secondary use of detection data.

- **Storage limitation**: Detection data is transient (in-memory) and logs are local only. No
  persistence of PII values. No cloud transmission of detection metadata.

- **Accuracy**: Entity confidence scores communicate detection reliability. NAME inference is
  flagged with `email_inference` source.

- **Integrity and confidentiality**: TLS throughout. No modification of traffic. No external
  transmission of logs.

- **Accountability**: Compliance marker (`pii_values_logged: false`) in every detection log entry.
  Structured JSON for auditability.

### Critical Requirements (must be verified in Review Mode)

1. **DPO-R3**: The `pii_logging` config flag MUST be wired to runtime behavior. This flag has been
   unwired since QINDU-0001. QINDU-0007 is the first sprint that produces PII detection logs — the
   flag must work before this sprint ships.

2. **DPO-R4**: URL `path` in detection logs MUST be sanitized (query parameters stripped).

3. **DPO-R8**: All test fixtures MUST use synthetic PII only. Real PII in test code is a blocking
   privacy violation.

4. **DPO-R1**: Zero-PII-in-logs guarantee must hold for every code path, including error paths,
   debug logging, and any SSE frame processing edge cases.

### Verdict justification

The story design correctly separates detection from enforcement. Monitor mode is a necessary
stepping stone to full PII protection (QINDU-0009 tokenization / QINDU-0010 rehydration). The
privacy risks of this mode (PII still reaches AI providers) are inherent to the feature and are
adequately mitigated by transparency requirements (DPO-R5). The most significant requirement is
DPO-R3 (wiring `pii_logging`) — without it, users have no control over detection log output,
undermining the data-protection-by-default principle.

**No grounds for BLOCKED.** All blocking concerns are captured as mandatory requirements above.
