# CISO Requirements – QINDU-0001: Proxy TLS local sélectif - Fondation

**Author**: qindu-ciso (Chief Information Security Officer)
**Date**: 2026-06-12
**Sprint**: QINDU-0001
**Phase**: 1 - Fondation Proxy

---

## 1. Attack Surface (New & Modified)

| Attack Surface | Type | Description |
|---|---|---|
| CA Root Key (disk) | **New** | ECDSA P-256 private key stored at `%PROGRAMDATA%\Qindu\ca.key`, encrypted via DPAPI. If compromised, attacker can decrypt all AI-bound TLS traffic on the machine. |
| CA Root Key (generation) | **New** | Key generation at startup using `crypto/ecdsa` + `crypto/rand`. Entropy source quality directly determines key strength. |
| Leaf Certificate Cache | **New** | In-memory `map[string]*tls.Certificate` with `sync.RWMutex`. Never persisted to disk. Must not be accessible cross-connection. |
| MITM TLS Interception | **New** | Decryption of AI domain traffic between browser and upstream. Decrypted data exists ephemerally in memory during forwarding. |
| Blind Tunnel (`io.Copy`) | **New** | Raw TCP relay for non-AI domains. No decryption — surface is network-level only. |
| CONNECT Handler (Hijacker) | **New** | `http.Hijacker` interface for raw TCP takeover. Must not allow non-CONNECT methods on the proxy endpoint. |
| Upstream TLS Connections | **New** | Outbound TLS to AI services. Validated via `x509.SystemCertPool`. Must not use `InsecureSkipVerify` in default configuration. |
| `/proxy.pac` Endpoint | **New** | Serves PAC to browser. Must not leak CA info, config secrets, or user identifiers. |
| `/health` Endpoint | **New** | Unauthenticated health check. Must return minimal info (status, version, uptime). |
| HTTP Server Bind | **New** | `127.0.0.1:8787` only. Must never bind to `0.0.0.0` or a routable interface. |
| Windows Service | **New** | Runs as `SYSTEM` or configured service account. Must respect Windows service security boundaries. |
| Configuration YAML | **New** | Static config at startup. Contains domain list and TLS parameters. Must not contain secrets unencrypted. |

---

## 2. Protected Assets

| Asset | Sensitivity | Storage | Lifespan |
|---|---|---|---|
| CA Root Private Key (ECDSA P-256) | **Critical** — allows full MITM | Disk (DPAPI-encrypted), memory during generation | 10 years (configurable) |
| CA Root Certificate (public) | **Medium** | Disk (plaintext acceptable, not a secret) | 10 years |
| Leaf Certificate Private Keys | **High** — per-domain decryption | Memory only (cert cache) | Process lifetime |
| Decrypted AI Traffic (request/response bodies) | **Critical** — may contain user PII in future sprints | Memory only (streaming buffers) | Duration of single request |
| Connection Metadata (host, duration, byte counts) | **Low** — behavioral data | Log output (stdout/stderr, JSON) | Log rotation window |
| Configuration (AI domain list) | **Low** — public knowledge | Disk (YAML), memory | Process lifetime |
| PAC File Content | **Low** — routing rules only | Memory (generated per request) | Per-request |

---

## 3. Threat Model (STRIDE — Condensed)

### 3.1 Spoofing

| Threat | Severity | Mitigation |
|---|---|---|
| Attacker generates fraudulent cert for AI domain using compromised CA key | **Critical** | CA key encrypted via DPAPI, ACL-restricted to SYSTEM/Admin, never logged, memory-only on Linux/CI |
| Attacker tricks proxy into connecting to malicious upstream by spoofing DNS | **High** | Upstream TLS validated via `x509.SystemCertPool`. Hostname verified per Go `crypto/tls` defaults. No `InsecureSkipVerify`. |
| Attacker impersonates `/proxy.pac` endpoint to redirect traffic | **Low** | Endpoint only accessible via `127.0.0.1`. Browser PAC is local-only. |

### 3.2 Tampering

| Threat | Severity | Mitigation |
|---|---|---|
| Attacker modifies `configs/default.yaml` to add malicious AI domains | **Medium** | File protected by Windows filesystem ACL. Config is static (no hot-reload, no remote fetch). |
| Attacker modifies leaf cert cache in-memory (race condition) | **Low** | `sync.RWMutex` protects all cache access. Concurrent reads, exclusive writes. |
| Attacker tampers with CA cert stored on disk | **Medium** | CA cert public — tampering would cause browser trust errors (fail-closed). |

### 3.3 Repudiation

| Threat | Severity | Mitigation |
|---|---|---|
| User cannot audit proxy activity because logs lack detail | **Low** | Structured JSON logs include: timestamp, host, status, duration_ms, bytes_in, bytes_out per connection. Sufficient for forensic reconstruction. |
| Logs are tampered with post-hoc | **Low** | Local-only logs. File integrity managed by OS. Not a primary concern for local agent. |

### 3.4 Information Disclosure

| Threat | Severity | Mitigation |
|---|---|---|
| CA private key logged in plaintext | **Critical** | Prohibited. Must never appear in `slog` calls, `fmt.Printf`, error messages, or stack traces. Code review gate. |
| Decrypted AI traffic logged or persisted | **Critical** | Prohibited. Logs contain zero request/response bodies. No `io.ReadAll` buffering to disk. `io.CopyBuffer` with 32KB transient buffer. |
| HTTP headers logged (Authorization, Cookie, etc.) | **High** | Prohibited. Only connection-level metadata logged (host, status, duration, byte counts). |
| PAC file leaks CA certificate or config secrets | **Medium** | PAC template must only expose AI domain patterns for browser routing. No CA info, no internal details. |
| `/health` endpoint leaks internal state | **Low** | Must return only `status`, `version`, `uptime`. No connection counts, no config dump, no key fingerprints. |
| Proxy binds to `0.0.0.0` exposing interception to network | **Critical** | Must bind exclusively to `127.0.0.1`. Config validation must reject routable addresses. |
| Connection data leaked via timing side channel | **Very Low** | Not a concern for local-only proxy. Future: constant-time tokenization QINDU-0005+. |
| AI domain hostnames in logs reveal user behavior | **Low** | Logs are local-only. See DPO REC2 for production enhancement (log `tls_mode` only). |

### 3.5 Denial of Service

| Threat | Severity | Mitigation |
|---|---|---|
| Memory exhaustion via unbounded concurrent CONNECT requests | **Medium** | Go HTTP server handles concurrent connections. No explicit limit in V1 — acceptable for single-user local proxy. Mitigate in QINDU-0004 if needed. |
| Certificate cache memory exhaustion (many distinct AI subdomains) | **Low** | Cache bounded by number of configured AI domains × subdomains. AI domain list is static and small. |
| Graceful shutdown timeout (30s) insufficient for slow connections | **Low** | 30-second drain timeout. Connections exceeding this are dropped — no data leakage, just client-side error. |
| `/health` endpoint DoS (trivial CPU load) | **Very Low** | Minimal response generation. Not a meaningful attack vector on localhost. |

### 3.6 Elevation of Privilege

| Threat | Severity | Mitigation |
|---|---|---|
| Non-admin user reads CA private key | **Critical** | `%PROGRAMDATA%\Qindu\ca.key` ACL set to `SYSTEM` + `Administrators` only (Windows). |
| Non-admin user connects to proxy on `127.0.0.1:8787` | **Low** | Any local user can connect to localhost — by design. Proxy is per-machine, not per-user in V1. |
| Proxy running as SYSTEM could be abused for lateral movement | **Low** | Proxy only makes outbound connections to AI domains specified in config. No arbitrary forwarding. |
| Malware leverages proxy's MITM capability to intercept traffic for non-AI domains | **Medium** | DomainRouter enforces AI-only MITM. Other domains are tunneled blind. Domain list is static. |

---

## 4. Blocking Security Requirements

The following requirements **MUST** be satisfied by the implementation. These are binding conditions for the CISO gate.

### SR1 – CA Key Encrypted at Rest (Critical) — OWASP ASVS V6.2.1, V6.4.1

The CA private key (ECDSA P-256) must:
- Be generated using `crypto/rand` (cryptographically secure PRNG)
- Be encrypted via DPAPI (`CryptProtectData` on Windows) before **any** disk write
- Be stored at `%PROGRAMDATA%\Qindu\ca.key` with the encrypted blob
- Have filesystem ACL set to `SYSTEM` (Full Control) and `Administrators` (Full Control) only
- **Never** be stored as plaintext on disk, even temporarily (no temp files, no swap spillage of plaintext key)
- On Linux/CI: maintain memory-only CA key (DPAPI not available) — this is acceptable for test environments

**Verification**: Review `ca.go` for key generation path. Confirm:
- `crypto/ecdsa.GenerateKey(elliptic.P256(), crypto/rand.Reader)` — not `math/rand`
- Plaintext key is zeroed or goes out of scope before any persistent write
- DPAPI encrypt happens before `os.WriteFile` / `ioutil.WriteFile` to the key path
- ACL is set after file creation (Windows)
- No `%x`, `%s`, `%v` formatting of key bytes in any log or error message

### SR2 – Leaf Certificates Ephemeral Only (High) — OWASP ASVS V6.2.4

Leaf certificates must:
- Be generated on-demand (lazy) at first CONNECT to a domain
- Use ECDSA P-256 (`crypto/ecdsa`)
- Include SAN: `DNS:<domain>` + `DNS:*.<domain>` (wildcard)
- Have a short validity (≤24 hours — recommended, match CA validity window conservatively)
- Be stored **only** in the in-memory certificate cache (`map[string]*tls.Certificate`)
- **Never** be persisted to disk. No certificate files, no PEM exports, no key material on disk.
- Be regenerated on proxy restart (fresh certs, fresh keys)
- Serial numbers must be generated with `crypto/rand` (RFC 5280 compliance) — not sequential or predictable

**Verification**: Review `cert.go` and `cert_cache.go`. Confirm:
- No `pem.Encode` + `os.WriteFile` for leaf certs or their private keys
- Cache is in-memory Go struct, protected by `sync.RWMutex`
- Cache write path holds write lock, read path holds read lock
- Serial number uses `crypto/rand` with sufficient entropy (≥64 bits recommended)

### SR3 – Upstream TLS Validation Must Not Be Disabled by Default (Critical) — OWASP ASVS V9.1.1, V9.1.3

Upstream TLS connections to AI services must:
- Use `x509.SystemCertPool` (Windows trust store) for certificate validation
- Verify hostname matches certificate SAN/CN (Go `crypto/tls` default behavior)
- **NOT** set `InsecureSkipVerify: true` in the default configuration
- The `tls.upstream_validation: "insecure"` config option must exist only for debugging/enterprise workarounds and must be accompanied by a prominent warning log
- Return **502 Bad Gateway** on upstream TLS verification failure (not crash, not silent fallthrough)

**Verification**: Review `mitm.go` or equivalent upstream connection code. Confirm:
- `tls.Config{InsecureSkipVerify: false}` or unset (Go default is `false`)
- `RootCAs` set to `x509.SystemCertPool()` (or `nil` which implies system pool on most platforms)
- 502 status returned on TLS handshake failure with upstream
- Review `config.go` for `tls.upstream_validation` handling — `insecure` must be an explicit opt-in

### SR4 – Proxy Binds to Loopback Exclusively (Critical) — OWASP ASVS V4.1.1

The HTTP server must:
- Bind **exclusively** to `127.0.0.1` (and optionally `::1` for IPv6 loopback)
- **Never** bind to `0.0.0.0`, empty string (which Go treats as `0.0.0.0`), or any routable IP
- Validate or hardcode the listen address — if reading from `configs/default.yaml`, the implementation must verify the address is a loopback address (`127.0.0.0/8` or `::1`)
- Reject any config that specifies a non-loopback `listen_addr` at startup with a fatal error

**Verification**: Review `proxy.go` for `net.Listen` or `http.ListenAndServe` call. Confirm:
- Address is `127.0.0.1:8787` or `localhost:8787`
- If config-driven, a loopback validation function exists: `net.IP.IsLoopback()` or equivalent
- No `0.0.0.0`, no `""`, no variable that could resolve to a non-loopback address

### SR5 – Zero PII in Logs (Critical) — OWASP ASVS V7.1.1, V7.1.2

Log output must contain **only** connection-level metadata:
- `timestamp` (ISO 8601), `host` (destination domain), `status` (HTTP status code), `duration_ms`, `bytes_in`, `bytes_out`
- The following must **never** appear in any log:
  - HTTP request bodies (full or partial)
  - HTTP response bodies (full or partial)
  - HTTP headers of any kind (including `Authorization`, `Cookie`, `User-Agent`, `X-*`)
  - Client IP addresses
  - CA key material, certificate contents, or TLS session keys
  - Any data passing through the Interceptor pipeline

**Verification**: Review-mode grep for all `slog.Info`, `slog.Debug`, `slog.Warn`, `slog.Error`, `fmt.Printf`, `fmt.Fprintf`, `log.Printf` calls. Confirm no `req.Body`, `res.Body`, `req.Header`, `res.Header`, `keyBytes`, `certPEM` passed to log functions.

### SR6 – Config-Directed MITM Scope Enforcement (High)

The DomainRouter must:
- Route only domains matching the configured AI provider domain list to MITM processing
- Route **all other** domains (including unknown domains, corporate domains, personal email, banking) to blind tunnel (`io.Copy` without TLS decryption)
- Be case-insensitive in matching but preserve original casing for SNI
- Never allow a CONNECT request to override the routing decision (no `X-Qindu-MITM: true` header or equivalent)
- The AI domain list is the **only** source of truth for MITM routing

**Verification**: Review `domain_router.go`. Confirm:
- Domain matching against `providers.*.domains` from config
- Default route is `Tunnel` (not `MITM`)
- No request-controlled routing overrides
- Test: connection to `example.com` → Tunnel (verified by no cert generation for that domain)

### SR7 – NoOp Interceptor Must Be Strictly Transparent (High)

The `NoOpInterceptor` implementation must:
- Pass request/response bodies through unmodified (bitwise identical)
- Not buffer, inspect, log, or store any data
- Not introduce latency beyond the minimum for `io.Copy` operations
- Return the original `io.ReadCloser` or a verified no-op wrapper
- Be the **only** active interceptor in this sprint — no PII detection logic may be present

**Verification**: Review `interceptor.go`. Confirm:
- `InterceptRequest` returns the input `io.ReadCloser` unchanged or a trivially wrapping reader
- `InterceptResponse` returns the input `io.ReadCloser` unchanged or a trivially wrapping reader
- No regex patterns, no `strings.Contains` for PII patterns, no data inspection whatsoever
- Integration test verifies bitwise identical output for a known payload

### SR8 – Concurrency Safety (High) — OWASP ASVS V1.14.1

All shared mutable state must be protected:
- Certificate cache: `sync.RWMutex` — read lock for cache lookups, write lock for cache insertions
- Configuration: read-only after startup (no hot-reload, no mutation)
- Log writer: `slog` is goroutine-safe by design (Go standard library guarantee)
- Connection tracking (for graceful shutdown): must be goroutine-safe if using a counter or map

**Verification**: Review `cert_cache.go`. Confirm:
- `RLock()`/`RUnlock()` on cache reads
- `Lock()`/`Unlock()` on cache writes
- No naked map access outside lock-protected regions
- `go test -race` must pass on CI

### SR9 – Graceful Shutdown Integrity (Medium)

The 30-second graceful shutdown (`http.Server.Shutdown(ctx)`) must:
- Stop accepting new connections immediately upon shutdown signal
- Drain existing connections completely (within the 30-second window)
- Not truncate mid-response in a way that exposes partial decrypted data to the client
- Log the number of connections being drained and whether the deadline was exceeded
- Return a non-zero exit code if connections were forcefully terminated after timeout

**Verification**: Review `graceful.go`. Confirm:
- `http.Server.Shutdown(ctx)` with `context.WithTimeout(context.Background(), 30*time.Second)`
- Signal handling for `SIGINT`, `SIGTERM` (and Windows service stop events)
- Integration test: start proxy, establish slow connection, send shutdown signal, verify clean drain

### SR10 – PAC File Security (Medium)

The PAC file served at `/proxy.pac` must:
- Only contain AI domain patterns from the configuration
- Not include the CA certificate, CA key, proxy version (except as needed), or internal state
- Not include any user-identifying information
- Be served with `Content-Type: application/x-ns-proxy-autoconfig` (or `application/x-javascript-config`)
- Not include `Set-Cookie` headers or any tracking mechanism
- Be generated fresh on each request (no caching that could leak between users — though V1 is single-user)

**Verification**: Review `pac.go`. Confirm:
- Template only injects `domains` array
- No config secrets embedded
- Integration test validates PAC output is valid JavaScript and contains correct domains

---

## 5. Mandatory Security Tests

| Test ID | Test | Type | Rationale |
|---|---|---|---|
| SEC-T1 | Verify CA key is never logged — grep test output and code paths for key material patterns | Unit + Review | Ensures SR1 compliance |
| SEC-T2 | Verify DPAPI encryption is called before `WriteFile` for CA key (Windows) / CA key is memory-only (Linux/CI) | Unit | Ensures SR1 compliance |
| SEC-T3 | Verify leaf certificates are not persisted to disk — no PEM files for leaf certs in `%PROGRAMDATA%` or `/tmp` | Integration | Ensures SR2 compliance |
| SEC-T4 | Verify upstream TLS validation fails closed — connect to upstream with expired/self-signed cert, expect 502 | Integration | Ensures SR3 compliance |
| SEC-T5 | Verify `InsecureSkipVerify: true` is NOT set in default TLS config — inspection of `tls.Config` struct | Unit | Ensures SR3 compliance |
| SEC-T6 | Verify proxy rejects non-loopback bind address — attempt to start with `listen_addr: 0.0.0.0`, expect fatal error | Unit | Ensures SR4 compliance |
| SEC-T7 | Verify logs contain no request/response bodies or headers — capture log output, grep for PII-like patterns | Integration | Ensures SR5 + DPO-R1 compliance |
| SEC-T8 | Verify DomainRouter sends non-AI domain to blind tunnel — connect to `example.com`, verify no cert generated | Integration | Ensures SR6 compliance |
| SEC-T9 | Verify NoOp proxy passes data unmodified — send known payload, verify bitwise identical response | Integration | Ensures SR7 compliance |
| SEC-T10 | Verify `go test -race` passes — no data race on certificate cache or connection tracking | CI | Ensures SR8 compliance |
| SEC-T11 | Verify graceful shutdown drains connections — slow response + shutdown signal, verify response completes | Integration | Ensures SR9 compliance |
| SEC-T12 | Verify PAC file contains only domain patterns — inspect `/proxy.pac` response for secrets, keys, identifiers | Integration | Ensures SR10 compliance |

---

## 6. Residual Risks

| Risk | Severity | Acceptance Rationale |
|---|---|---|
| **CA key on disk is a single point of failure** — if compromised, all AI TLS traffic (past and future) from this machine can be decrypted | **Medium** | DPAPI encryption + ACL + localhost-only scope significantly mitigates. Risk accepted because the machine itself is the trust boundary: if an attacker has admin on the machine, they can install their own CA, keylogger, or screen recorder anyway. Future: CA key rotation (ADR-003 acknowledges this gap). |
| **Leaf cert cache lives in process memory indefinitely** — memory dumping by admin/malware could extract leaf keys | **Low** | Leaf keys are ephemeral per-domain. If attacker has memory dump capability, they already have admin and can extract the CA key directly. Leaf key extraction is strictly less damaging. |
| **No connection limit** — a malicious local process could exhaust file descriptors or memory by opening many CONNECT requests | **Low** | Localhost-only proxy on single-user machine. Resource exhaustion is self-inflicted. Can be mitigated with connection limits in future sprints if needed. |
| **AI domain hostnames in logs** — behavioral metadata about which AI services are visited | **Low** | Logs are local-only. DPO REC2 suggests optional reduction to `tls_mode` only for production. Acceptable for V1 foundation. |
| **DPAPI mock on Linux/CI** — CA key is memory-only, not encrypted at rest in CI | **Very Low** | CI environments are ephemeral, no real user data, no production CA keys. Mock DPAPI is acceptable for testing. |
| **No certificate revocation mechanism** — browser would need to manually untrust the Qindu CA if compromised | **Low** | Qindu CA is machine-local. Uninstall process (QINDU-0003) handles removal. No CRL/OCSP needed for a local, single-machine CA. |
| **Single-CA design** — one CA key serves all intercepted domains | **Medium** | ADR-003 explicitly chose single-CA for simplicity. Per-provider isolation would require multiple CAs (complexity not justified for local-only threat model). If the CA key is compromised, the machine is already fully compromised. |
| **`tls.upstream_validation: "insecure"` config option** — could be misused to disable upstream validation | **Medium** | Necessary for enterprise environments with custom proxy setups (ADR-010). Mitigated by prominent warning log and documentation that `insecure` is for debugging/enterprise workarounds only. Not the default. |

---

## 7. Recommendations

The following are non-binding security enhancements for consideration:

### REC-SEC1 – TLS Version Constraints
Ensure the proxy's TLS configurations (both browser-facing and upstream-facing) constrain minimum TLS version to 1.2 and explicitly disable known-weak cipher suites. Go's `crypto/tls` default is already TLS 1.2 minimum — verify this is not lowered.

### REC-SEC2 – Certificate Cache TTL
Consider a TTL or max-age for leaf certificates in the cache, even though the current design regenerates on restart. If configuration hot-reload is added in future (currently excluded), cached certs for removed domains should be purged.

### REC-SEC3 – Structured Error Responses
When returning 502 Bad Gateway (upstream unreachable, TLS validation failure), ensure the error response body is a minimal JSON object (`{"error":"bad_gateway","detail":"upstream tls validation failed"}`) rather than exposing Go stack traces or internal connection details.

### REC-SEC4 – Internal-Only PAC
Consider adding `// This PAC file is generated by Qindu for local use only` as a comment at the top, and verifying the Content-Type is correct to avoid browser misinterpretation.

### REC-SEC5 – CA Key Integrity Verification
After writing the DPAPI-encrypted CA key to disk, verify the file can be decrypted and the key is valid before proceeding. This catches DPAPI failures, disk write errors, or corruption early.

### REC-SEC6 – Signal Handling Robustness
On Windows, ensure the service stop handler properly triggers `http.Server.Shutdown()`. On non-Windows (console mode), ensure `SIGINT` (Ctrl+C) and `SIGTERM` are both handled. The 30-second timeout should be logged if exceeded.

---

## 8. ADR Compliance Matrix

| ADR | Requirement | Status |
|---|---|---|
| ADR-001 | Go module structure — `internal/proxy`, `internal/tls`, `internal/policy`, `internal/logging`, `internal/service` | ✅ Aligned |
| ADR-002 | CONNECT + MITM architecture with Hijacker | ✅ Aligned |
| ADR-003 | Single CA ECDSA P-256, lazy leaf certs, SAN wildcard, in-memory cache, no disk persistence for leaf certs | ✅ Aligned (SR1, SR2 enforce) |
| ADR-004 | Interceptor interface — NoOp implementation, extensible pipeline | ✅ Aligned (SR7 enforces) |
| ADR-005 | Static config YAML, dynamic PAC | ✅ Aligned (SR10 enforces) |
| ADR-006 | Single binary, Windows service auto-detection | ✅ Aligned |
| ADR-007 | testcontainers-go, cross-compilation, CI on ubuntu-latest | ✅ Aligned (SEC-T1–T12 cover) |
| ADR-008 | slog JSON, zero PII in logs | ✅ Aligned (SR5 enforces) |
| ADR-009 | Goroutine concurrency model | ✅ Aligned (SR8 enforces) |
| ADR-010 | Upstream validation via SystemCertPool, no InsecureSkipVerify by default | ✅ Aligned (SR3 enforces) |

---

## 9. Risk Assessment

| Risk Level | Count | Key Items |
|---|---|---|
| **Critical** | 3 | SR1 (CA key encryption), SR3 (upstream TLS validation), SR4 (loopback bind), SR5 (no PII in logs) |
| **High** | 4 | SR2 (leaf certs ephemeral), SR6 (MITM scope enforcement), SR7 (NoOp transparency), SR8 (concurrency safety) |
| **Medium** | 2 | SR9 (graceful shutdown integrity), SR10 (PAC file security) |
| **Low** | 0 | — |

---

## 10. Verdict

### Verdict: **PROCEED_WITH_CAVEATS**

**Rationale**: The QINDU-0001 sprint establishes a security-respecting proxy foundation with appropriate cryptographic primitives, correct TLS boundaries, and a "least-privilege" MITM architecture. The core security design — DPAPI-encrypted CA key, loopback-only binding, upstream TLS validation via system trust store, blind tunneling of non-AI traffic, and zero-PII logging — is sound and aligns with all applicable ADRs.

**No BLOCKING issues** exist at the design level. All critical security surfaces (CA key, MITM scope, upstream validation, bind restriction, logging) are addressed by the 10 security requirements (SR1–SR10), which are verifiable in the review phase.

**Caveats that must be verified during review (CISO review gate, QINDU-0001 review phase):**

| Caveat | Requirement | Review Action |
|---|---|---|
| C1 — CA key encryption path | SR1 | Verify DPAPI encrypt occurs before disk write. Verify no plaintext key on disk, even temporarily. |
| C2 — No InsecureSkipVerify in default config | SR3 | Verify `tls.Config.InsecureSkipVerify` is `false` (or unset) in default upstream TLS config. |
| C3 — Loopback enforcement in code | SR4 | Verify `127.0.0.1` is hardcoded or validated against `net.IP.IsLoopback()`. |
| C4 — Log hygiene | SR5 | Grep all log calls for `req.Body`, `res.Body`, `req.Header`, `res.Header`, `keyBytes`, `certPEM`. |
| C5 — Race detector clean | SR8 | Verify `go test -race ./...` passes on CI. |
| C6 — Cross-compilation security | All | Verify `GOOS=windows` build does not silently compile out DPAPI or ACL logic. |

**Path to BLOCKED**: Any of the following findings during review would change the verdict to BLOCKED:
- CA private key stored as plaintext on disk (even temporarily)
- `InsecureSkipVerify: true` set in default (non-debug) configuration
- Proxy binds to `0.0.0.0` or any non-loopback address
- Request/response bodies or headers appearing in log output
- Leaf certificates persisted to disk
- Non-`crypto/rand` entropy used for key generation

---

## Appendix A: OWASP ASVS Mappings

| Qindu SR | OWASP ASVS v4.0 | Mapping |
|---|---|---|
| SR1 | V6.2.1, V6.4.1 | Verify that cryptographic keys are stored securely (encrypted at rest). |
| SR2 | V6.2.4 | Verify that random numbers are generated using an approved cryptographic random number generator. |
| SR3 | V9.1.1, V9.1.3 | Verify that TLS is used for all connectivity, and that certificates are properly validated. |
| SR4 | V4.1.1 | Verify that the application enforces access control rules on a trusted service layer. |
| SR5 | V7.1.1, V7.1.2 | Verify that the application does not log credentials or payment details. |
| SR8 | V1.14.1 | Verify the application is not susceptible to race conditions. |

## Appendix B: Non-Security Items Correctly Excluded

The following are correctly **excluded** from this sprint and should not be flagged as security gaps:
- ❌ PII detection / tokenization / rehydration (QINDU-0005 through QINDU-0009)
- ❌ Vault encryption beyond DPAPI for CA key (QINDU-0008)
- ❌ Installer / MSI / browser policy (QINDU-0002)
- ❌ Admin endpoint authentication (QINDU-0002+)
- ❌ Fail-closed error page (QINDU-0005+)
- ❌ Certificate revocation (not applicable to local single-machine CA per ADR-003)
- ❌ Connection rate limiting (acceptable for local-only V1)
- ❌ Tray icon / UI security (QINDU-0002+)
- ❌ Hot-reload configuration (deliberately excluded for security — static config reduces attack surface)

---

**End of CISO Requirements — QINDU-0001 Design Phase**
