# DPO Requirements – QINDU-0001: Proxy TLS local sélectif - Fondation

**Author**: qindu-dpo (Data Protection Officer)
**Date**: 2026-06-12
**Sprint**: QINDU-0001
**Phase**: 1 - Fondation Proxy

---

## 1. Privacy Impact Assessment (PIA) Summary

### Nature of processing

QINDU-0001 implements the skeleton of a local TLS proxy that sits between the user's browser and web-based AI services. The proxy:
- Performs MITM (TLS decryption) on AI domains (`chatgpt.com`, `claude.ai`) and forwards traffic through a NoOp interceptor (no inspection or modification)
- Tunnel-blinds (no decryption) all non-AI traffic — a privacy-preserving "least decrypt" design
- Serves a PAC file dynamically for browser routing and a minimal `/health` endpoint
- Generates and persists a CA root key (ECDSA P-256) encrypted via DPAPI on disk
- Logs structured JSON with connection metrics (host, status, duration, byte counts) but **no headers, no bodies, no PII**
- Runs entirely on `127.0.0.1:8787` — no external network exposure
- Performs graceful shutdown with a 30s timeout

### Data processed

| Category | Collected | Stored | Transmitted externally | Notes |
|---|---|---|---|---|
| CA private key | Generated locally | Disk (DPAPI-encrypted) | No | Machine-bound, ACL-restricted |
| Leaf certificates | Generated in-memory | Memory only (cache) | No | Regenerated on restart |
| Destination hostnames (AI domains) | Processed for routing & logging | Logged to local stdout/stderr (JSON) | No | `chatgpt.com`, `claude.ai` — behavioral metadata |
| Client IP | Implicit (localhost) | Not logged | No | Proxy binds `127.0.0.1` exclusively |
| HTTP request/response bodies | Passed through NoOp | Not logged, not stored | Forwarded to AI service (MITM) | No inspection in this sprint |
| HTTP headers | Passed through | Not logged | Forwarded to AI service (MITM) | No inspection in this sprint |
| PAC file | Generated from config | Not stored | Served to browser via localhost | No tracking identifiers |
| Health status | Generated on request | Not stored | Served to browser via localhost | Version + uptime only |

**Crucially, zero PII is detected, tokenized, stored, logged, or transmitted in this sprint.**

### Purpose and necessity

The proxy infrastructure established in QINDU-0001 is a **prerequisite** for the privacy-enhancing PII tokenization and rehydration features planned for QINDU-0005 through QINDU-0010. Without TLS interception capability, the proxy cannot inspect AI-bound traffic for PII and therefore cannot tokenize it before egress. The NoOp interceptor is a placeholder for the future PIIInterceptor.

The "least decrypt" architecture (MITM on AI domains only, blind tunnel for everything else) is the correct privacy-by-design approach — it minimizes the scope of decryption to what is strictly necessary.

### Legal basis

Qindu runs **entirely on the user's own machine**. There are **no Qindu servers, no cloud backend, no telemetry, no user accounts, and no data collection whatsoever**. The software does not transmit any data to Qindu as an organization.

- **GDPR applicability**: Qindu (the software provider) is **not** a data controller or processor — it receives zero user data. The user, by installing and configuring Qindu on their own machine, processes their own personal data for their own purposes. This falls within the **household exemption** (GDPR Article 2(2)(c)) — processing by a natural person in the course of a purely personal or household activity.
- **Nevertheless**, Qindu must adhere to **privacy by design and by default** (GDPR Article 25) as a matter of ethical engineering and to ensure the software can be adopted in enterprise contexts where the employer (not the employee) would be the data controller.
- **ePrivacy Directive**: Qindu intercepts TLS traffic that may contain the content of communications. The user's informed consent is obtained through the voluntary installation and browser configuration process. The interception is limited in scope (AI domains only) and purpose (PII protection).

---

## 2. Requirements

The following requirements **MUST** be satisfied by the implementation. These are binding conditions for the DPO gate.

### R1 – No PII in Logs (Critical)

The implementation must log **only** the following connection-level metadata:
- Timestamp
- Destination hostname (AI domain)
- HTTP status code
- Duration in milliseconds
- Bytes in / bytes out

The implementation must **never** log:
- HTTP request or response bodies (even partially)
- HTTP headers (including `Authorization`, `Cookie`, `User-Agent`, `X-Forwarded-For`, or custom headers)
- Client IP addresses (irrelevant since bind is `127.0.0.1`, but must be verified)
- CA key material, certificate contents, or TLS session keys
- Any content that passes through the Interceptor pipeline

**Verification**: Review-mode grep for `slog.Info`, `slog.Debug`, `slog.Warn`, `slog.Error` to confirm no body/header/credential logging. If `json.Marshal` or `fmt.Sprintf` is used on `*http.Request` or `*http.Response`, that's a violation.

### R2 – No Persistent Storage of Intercepted Traffic (Critical)

All intercepted traffic (request bodies, response bodies, TLS session data) must exist **only in memory** during active connections and must be discarded immediately after forwarding. Specifically:
- No buffering of complete request or response bodies to disk
- No caching of request/response content in the Interceptor pipeline
- The `io.CopyBuffer` (32KB buffer) must be stack-allocated or short-lived heap memory, not accumulated across the lifetime of a connection

**Verification**: Review `forward.go`, `interceptor.go`, and `mitm.go` for any `os.Create`, `ioutil.WriteFile`, or `io.ReadAll` on intercepted content without immediate disposal.

### R3 – CA Key Protection (Critical)

The CA private key must be:
- Generated using ECDSA P-256 (compliant with ENISA and BSI cryptographic recommendations)
- Stored on disk **only** in DPAPI-encrypted form (`%PROGRAMDATA%\Qindu\ca.key`)
- Protected by ACL restricting access to `SYSTEM` and `Administrators` (Windows)
- **Never** logged, serialized to plaintext, or included in error messages
- On Linux/CI: **memory-only**, no disk persistence — this is acceptable given the CI context

**Verification**: Review `ca.go` for key generation, encryption, and storage. Confirm no `fmt.Printf("%x", key)` or equivalent. Confirm the plaintext key is zeroed or goes out of scope before disk write.

### R4 – Bind Restriction to Loopback (Critical)

The HTTP server must bind **exclusively** to `127.0.0.1` (and optionally `::1` for IPv6 loopback). It must **never** bind to `0.0.0.0`, any routable interface, or a configurable address that could accept non-localhost connections. The `listen_addr` config field must be validated or hardcoded to loopback only.

**Verification**: Review `proxy.go` `ListenAndServe` call. Confirm `listen_addr` is always loopback.

### R5 – No Telemetry, Analytics, or Tracking (High)

The software must not:
- Initiate any outbound network connections except to the user's intended AI service destinations (via the proxy pipeline)
- Transmit any data about the user, the machine, or usage patterns to Qindu or any third party
- Include persistent user identifiers, device fingerprints, or installation IDs
- Use cookies, ETags, or any tracking mechanism on the `/proxy.pac` or `/health` endpoints
- Implement any form of phoning-home, update checking, or crash reporting that transmits data externally

**Verification**: Review all outbound network calls in the codebase. Review `/proxy.pac` and `/health` handlers for `Set-Cookie` or tracking headers.

### R6 – No User Accounts or Persistent Identifiers (High)

The proxy must operate without any concept of user identity. There must be:
- No user registration, authentication, or login mechanism
- No user-specific configuration stored separately
- No unique installation identifiers (no UUID, no machine hash, no hardware ID)
- No differentiation between users on the same machine

**Verification**: Review entire codebase for user management, auth, or UUID generation. Grep for `uuid`, `machineid`, `device`, `user_id`, `account`.

### R7 – Test Fixtures Must Contain No Real PII (High)

All test data (Go test files, test fixtures, YAML configs in test directories, Docker container test data) must use **synthetic, obviously fake data**:
- Email: `test@example.com`, `user@test.local` (but beware — `example.com` is RFC 2606 reserved, fine)
- Names: `Jane Doe`, `John Smith` — acceptable as synthetic placeholders
- Credit card: Use test PANs from payment processor documentation (e.g., `4111111111111111` is a standard Visa test number, acceptable)
- Phone: `+1-555-0100` through `+1-555-0199` (reserved for fiction per NANP)
- IBAN: Use test IBANs from SWIFT documentation only

**No real person's actual PII may appear anywhere in the repository.**

**Verification**: Grep the entire `tests/` directory and test fixtures for patterns resembling real PII.

### R8 – Graceful Shutdown Must Not Leak Data (Medium)

The 30-second graceful shutdown (`http.Server.Shutdown(ctx)`) must:
- Drain in-flight connections completely before terminating
- Not truncate responses mid-stream in a way that exposes partial decrypted data
- Not leave plaintext data in memory buffers longer than necessary

**Verification**: Review `graceful.go`. Integration tests must verify graceful shutdown behavior.

### R9 – PAC File Must Not Leak Configuration Details (Low)

The dynamically-generated PAC file served at `/proxy.pac` must:
- Only expose AI domain patterns necessary for browser routing
- Not include configuration secrets, CA information, or internal proxy details
- Not include any user-identifying information

**Verification**: Review `pac.go` for the PAC template. Inspect a sample PAC output.

---

## 3. Recommendations

The following are non-binding suggestions that would strengthen privacy posture:

### REC1 – Log Redaction Middleware

Consider adding a lightweight log redaction middleware (as foreseen in ADR-008: `internal/logging/redaction.go`) that scans log messages before emission and strips any accidental PII-like patterns (emails, credit card numbers). Even though QINDU-0001 has no PII processing, implementing this now would catch developer errors in future sprints. This aligns with the "safety rails" philosophy of ADR-008.

### REC2 – Domain Logging Granularity

The `host` field in logs currently records the destination domain (e.g., `chatgpt.com`). While this is necessary for debugging, it does reveal which AI services a user visits. Consider:
- An option to log only whether the connection was MITM or Tunnel (i.e., `tls_mode: mitm | tunnel`) without the specific hostname for production deployments
- Retaining the hostname only at `DEBUG` level, not `INFO`

This is low priority for QINDU-0001 since logs are local-only, but should be addressed before production release.

### REC3 – Transparency Notice (Future)

When Qindu reaches production readiness (QINDU-0002+), the installer should present a clear, plain-language transparency notice explaining:
- "Qindu intercepts and decrypts TLS traffic to AI services on this machine to detect and protect your personal data"
- "No data is sent to Qindu — all processing happens on this device"
- "Qindu installs a local Certificate Authority to perform this inspection"
- "You can uninstall Qindu at any time, which will remove the CA certificate"

This is not required for QINDU-0001 (no installer), but must be planned for QINDU-0002.

### REC4 – CA Key Rotation Mechanism

The CA has a 10-year validity with no rotation mechanism (ADR-003 acknowledges this). Consider designing a rotation protocol now — even if not implemented — to avoid architectural lock-in. A compromised CA key would allow an attacker on the same machine (who has admin access) to decrypt AI traffic.

### REC5 – In-Memory Certificate Cache Purging

The leaf certificate cache (`map[string]*tls.Certificate`) lives indefinitely in memory. Consider if there's a scenario where cached certificates for domains that are no longer configured as AI providers should be purged. Not critical — memory footprint is negligible.

---

## 4. Risk Assessment

| ID | Risk | Likelihood | Impact | Mitigation | Residual |
|---|---|---|---|---|---|
| RK1 | CA private key extracted from disk by malware with admin privileges | Low | High — enables decryption of all past and future AI traffic from this machine | DPAPI encryption + ACL (SYSTEM/Admin only) + local-only scope | Medium — if admin is compromised, the machine is fully compromised anyway |
| RK2 | Developer accidentally logs request/response bodies or headers | Medium | Medium — PII exposure in local log files | ADR-008 prohibitions, code review, DPO review gate | Low — review-mode grep verification will catch this |
| RK3 | Proxy mistakenly binds to a non-loopback interface, allowing remote connections | Low | High — external attacker could use the proxy | Config validation, hardcoded loopback bind | Low — caught by review and testing |
| RK4 | Graceful shutdown truncates data mid-stream, leaving partial decrypted content visible | Low | Low — cosmetic, no persistent exposure | 30-second drain timeout, connection-level tracking | Very Low |
| RK5 | DNS rebinding attack via PAC file to route non-AI traffic through proxy | Very Low | Medium — unintended domain interception | PAC dynamically generated from config, browser PAC enforcement | Low — attacker would need to compromise the config YAML |
| RK6 | The proxy infrastructure (MITM capability) could be misused by third-party software on the same machine that routes through port 8787 | Low | Medium — unintended traffic interception | Bind to 127.0.0.1 only, firewall rule (future QINDU-0002) | Low |
| RK7 | AI service domain hostnames in logs reveal user's behavioral patterns | Medium | Low — logs are local only, but could be exfiltrated by malware | Logs are local; see REC2 for production enhancement | Low |

---

## 5. Verdict

### Verdict: **PROCEED_WITH_CAVEATS**

This sprint establishes a privacy-respecting, local-only proxy foundation that embodies **privacy by design** principles from the start. The architecture correctly minimizes the scope of TLS interception (AI domains only), binds exclusively to localhost, avoids all PII in logging, protects the CA key with OS-level encryption, and contains zero telemetry, tracking, or user identifiers.

**Rationale for not BLOCKING**: The sprint explicitly excludes PII detection, tokenization, vault, and rehydration — those features will undergo their own DPO reviews (QINDU-0005, QINDU-0007, QINDU-0008, QINDU-0009). The infrastructure built here is a necessary prerequisite for those privacy-enhancing features. Blocking at this stage would prevent the eventual delivery of the privacy protections Qindu is designed to provide.

**Caveats that must be addressed in subsequent sprints or during DPO review:**

1. **C1 (QINDU-0002)**: The Windows installer must present a transparency notice explaining TLS interception to the user.
2. **C2 (QINDU-0005)**: When the `PIIInterceptor` replaces the `NoOpInterceptor`, a full DPO review of the data pipeline must verify that PII is never logged, stored unencrypted, or leaked through error paths.
3. **C3 (QINDU-0008)**: The vault implementation must respect TTL and retention policies. No infinite retention without explicit user opt-in.
4. **C4 (Review gate for QINDU-0001)**: The DPO review of the implementation must verify R1 (no PII in logs) by auditing actual log output from integration tests.
5. **C5 (Ongoing)**: The CA key on disk, while DPAPI-protected, remains a sensitive asset. Any future feature that expands the scope of TLS interception (additional providers, config reload) must be re-assessed for impact on the CA key's attack surface.

**The DPO gate for QINDU-0001 design phase is PASSED, contingent on verification of requirements R1–R9 during the review phase.**
