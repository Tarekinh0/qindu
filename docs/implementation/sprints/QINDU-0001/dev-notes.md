# Dev Notes – QINDU-0001: Proxy TLS local sélectif - Fondation

**Sprint**: QINDU-0001
**Author**: qindu-devsecops
**Date**: 2026-06-12

## 1. Files Modified/Created

### New files (28 source + test files)

| File | Purpose |
|---|---|
| `go.mod`, `go.sum` | Go module initialization |
| `configs/default.yaml` | Default YAML configuration |
| `cmd/agent/main.go` | Single-binary entry point (console + Windows service auto-detection) |
| `internal/policy/config.go` | YAML config loading, validation (loopback, port, upstream TLS, CA algo) |
| `internal/policy/config_test.go` | Config parsing, validation, default config tests |
| `internal/policy/pac.go` | Dynamic PAC JavaScript generation from YAML providers |
| `internal/policy/pac_test.go` | PAC content, domain inclusion, no secrets tests |
| `internal/policy/domain_router.go` | DomainRouter: MITM vs Tunnel routing, case-insensitive, injection prevention |
| `internal/policy/domain_router_test.go` | Routing logic, default tunnel, injection attacks tests |
| `internal/tls/ca.go` | ECDSA P-256 CA generation using crypto/rand |
| `internal/tls/ca_windows.go` | Windows DPAPI-encrypted CA storage (CryptProtectData/CryptUnprotectData) |
| `internal/tls/ca_other.go` | Non-Windows memory-only CA storage stub |
| `internal/tls/ca_helper.go` | CreateOrLoadCA orchestration, parseCAFromPEM |
| `internal/tls/ca_test.go` | CA generation, key strength, serial uniqueness, PEM round-trip tests |
| `internal/tls/cert.go` | Leaf cert generation: ECDSA P-256, SAN wildcard, 24h validity, crypto/rand serials |
| `internal/tls/cert_test.go` | SAN validation, CA signing, wildcard verification, ServerAuth EKU tests |
| `internal/tls/cert_cache.go` | Thread-safe in-memory cert cache with sync.RWMutex |
| `internal/tls/cert_cache_test.go` | Concurrent read/write, double-check locking, race safety tests |
| `internal/logging/logger.go` | slog JSON structured logger, ConnectionLogEntry (PII-free) |
| `internal/logging/logger_test.go` | Log format validation, forbidden PII pattern checks |
| `internal/proxy/proxy.go` | HTTP server dispatch (CONNECT vs GET), PAC/health endpoints, test hooks |
| `internal/proxy/connect.go` | CONNECT handler with Hijacker, blind tunnel routing |
| `internal/proxy/mitm.go` | Double TLS handshake (browser + upstream), 502 error handling |
| `internal/proxy/forward.go` | HTTP request/response forwarding via Request.Write/Response.Write, byte counting |
| `internal/proxy/interceptor.go` | Interceptor interface + NoOpInterceptor (strictly transparent) |
| `internal/proxy/graceful.go` | SIGINT/SIGTERM signal handling, 30s graceful shutdown |
| `internal/proxy/proxy_integration_test.go` | 17 integration tests (E2E MITM, blind tunnel, PAC, health, 502, graceful shutdown, TLS validation, security tests) |
| `internal/service/windows_service.go` | Windows service handler (golang.org/x/sys/windows/svc) |
| `internal/service/service_other.go` | Non-Windows service stub |
| `internal/service/health.go` | /health JSON endpoint handler |
| `.github/workflows/ci.yml` | GitHub Actions CI: test on Go 1.26, vet, race, Windows cross-compile |

## 2. Implementation Checklist (against story.md)

| Story item | Status | Notes |
|---|---|---|
| 1. Go module initialized | ✅ | `github.com/Tarekinh0/qindu`, Go 1.26 |
| 2. HTTP server on 127.0.0.1:8787 | ✅ | CONNECT dispatch + GET endpoints |
| 3. DomainRouter (MITM/Tunnel) | ✅ | Case-insensitive, subdomain matching, injection-proof |
| 4. Blind tunnel (io.Copy) | ✅ | Non-AI domains, no decryption |
| 5. MITM TLS (CA + leaf certs) | ✅ | ECDSA P-256, lazy generation, SAN wildcard, in-memory cache |
| 6. Interceptor interface + NoOp | ✅ | Transparent forwarding, extensible pipeline |
| 7. Streaming pipeline (io.CopyBuffer 32KB) | ✅ | Request.Write/Response.Write handle body serialization |
| 8. Dynamic PAC generation | ✅ | From YAML providers config |
| 9. Structured logging (slog JSON) | ✅ | host, status, duration_ms, bytes_in, bytes_out, mode. ZERO PII |
| 10. YAML config (no hot-reload) | ✅ | Static, validated at startup |
| 11. Windows service (single binary) | ✅ | Auto-detection via svc.IsAnInteractiveSession |
| 12. Graceful shutdown (30s) | ✅ | SIGINT/SIGTERM handling |
| 13. Unit tests | ✅ | 54 unit tests across policy, tls, logging |
| 14. Integration tests (testcontainers-go) | ✅ | 17 integration tests (in-process Go TLS servers) |
| 15. CI GitHub Actions | ✅ | Matrix Go 1.26, vet, race, Windows cross-compile |

## 3. Test Coverage Summary

### Unit Tests: 54 tests, all passing
- **internal/policy**: 21 tests (config parsing/validation, domain routing, PAC generation)
- **internal/tls**: 26 tests (CA generation, leaf cert, cert cache concurrency)
- **internal/logging**: 7 tests (logger initialization, log fields, PII absence)

### Integration Tests: 17 tests, all passing
- TestIntegration_CONNECT_MITM_E2E — E2E MITM with TLS handshake and HTTP forwarding
- TestIntegration_CONNECT_BlindTunnel — Non-AI domain tunnel routing
- TestIntegration_PAC_Endpoint — Valid PAC JavaScript with correct Content-Type
- TestIntegration_Health_Endpoint — Correct JSON with status/version/uptime
- TestIntegration_502_BadGateway — 502 when upstream unreachable
- TestIntegration_GracefulShutdown — Connections drain within 30s during shutdown
- TestIntegration_UpstreamTLSValidationRejectsSelfSigned — Self-signed cert → 502
- TestIntegration_InsecureSkipVerifyNotDefault — Default config has no InsecureSkipVerify
- TestIntegration_NoPIIInLogs — ConnectionLogEntry has no body/header fields
- TestIntegration_HealthEndpointNoSensitiveInfo — Health reveals no secrets
- TestIntegration_PACContainsOnlyDomains — PAC contains no secrets
- TestIntegration_ProxyBindsLoopbackOnly — 0.0.0.0 rejected at config validation
- TestIntegration_LeafCertsNotPersisted — Leaf certs in memory only, not on disk
- TestIntegration_CertCacheConcurrency — Concurrent access without races
- TestIntegration_DomainRouterPreventsInjection — Injection attacks routed to Tunnel
- TestIntegration_NoOpInterceptorTransparency — Data passes unmodified
- TestIntegration_ConfigRejectsNonLoopback — Non-loopback bind rejected

### Race Detector: All tests pass with `-race`

## 4. Security Requirement Mapping (CISO SR1-SR10)

| SR | Requirement | Implemented | Verified By |
|---|---|---|---|
| SR1 | CA key encrypted at rest | ✅ DPAPI on Windows, memory-only on other | ca_windows.go, ca_other.go |
| SR2 | Leaf certs ephemeral (memory only) | ✅ In-memory cache, 24h validity, no disk write | cert_cache.go, TestIntegration_LeafCertsNotPersisted |
| SR3 | Upstream TLS validation (no InsecureSkipVerify default) | ✅ SystemCertPool, 502 on failure | mitm.go, TestIntegration_UpstreamTLSValidationRejectsSelfSigned |
| SR4 | Bind loopback only | ✅ Config validation rejects non-loopback | config.go:Validate(), TestIntegration_ProxyBindsLoopbackOnly |
| SR5 | Zero PII in logs | ✅ ConnectionLogEntry has metadata only | logger.go, TestIntegration_NoPIIInLogs |
| SR6 | Config-directed MITM scope enforcement | ✅ DomainRouter, default Tunnel | domain_router.go, TestIntegration_DomainRouterPreventsInjection |
| SR7 | NoOp transparent | ✅ Returns unmodified readers | interceptor.go, TestIntegration_NoOpInterceptorTransparency |
| SR8 | Concurrency safety | ✅ sync.RWMutex on cache, race-free | cert_cache.go, TestIntegration_CertCacheConcurrency |
| SR9 | Graceful shutdown integrity | ✅ 30s timeout, connection draining | graceful.go, TestIntegration_GracefulShutdown |
| SR10 | PAC file security | ✅ Only domain patterns, no secrets | pac.go, TestIntegration_PACContainsOnlyDomains |

## 5. Dependencies Added

### Production
- `gopkg.in/yaml.v3` v3.0.1 — YAML config parsing
- `golang.org/x/sys` v0.46.0 — Windows service (svc) and DPAPI

### Test-only
- `github.com/testcontainers/testcontainers-go` v0.42.0 — Docker-based integration tests (framework available; current tests use in-process Go TLS servers for speed)

## 6. Technical Choices and Rationale

### Forwarding: Request.Write / Response.Write instead of manual body copy
**Rationale**: `http.Request.Write` and `http.Response.Write` handle body serialization and body closing automatically. Attempting a separate `io.CopyBuffer` for the body after `Request.Write` fails because `Write` already consumes and closes the body. The interceptor pipeline ensures the correct body is set on the modified request/response before calling Write.

### Counting writer for byte metrics (PR-003 fix)
**Rationale**: Using `Content-Length` for byte counting silently undercounts chunked/streaming responses (where `Content-Length` is -1). A `countingWriter` wrapper intercepts `Write` calls and atomically counts actual bytes transferred, ensuring accurate metrics regardless of transfer encoding.

### TLS test dialer configuration via direct field access (PR-002 fix)
**Rationale**: Public setters (`SetUpstreamCertPool`, `SetDialTLS`) exposed a mutation surface that could disable upstream TLS validation from outside the test package. Since integration tests live in `package proxy`, they use direct field access (`p.rootCAs`, `p.dialTLS`) for test configuration. No public mutation API.

### Health handler delegation to service package (PR-007 fix)
**Rationale**: The proxy's inline JSON string concatenation for `/health` was fragile and duplicated the `service.HealthHandler`. The proxy now delegates to `service.HealthHandler(p.startTime, p.version)`, which uses proper `encoding/json`. The version string is passed via `NewProxy` constructor.

### 1-byte buffered reader for CONNECT response in tests
**Rationale**: `http.ReadResponse` uses a `bufio.Reader` which may buffer TLS handshake bytes that follow the "200 Connection Established" response. Using `bufio.NewReaderSize(conn, 1)` prevents this buffering, allowing the subsequent `tls.Client()` handshake to work correctly.

### CA on non-Windows: memory-only
**Rationale**: DPAPI is a Windows-only API. On Linux/CI, the CA key exists only in memory during the process lifetime. A new CA is generated on each restart. This is acceptable for development and CI — production deployments target Windows where DPAPI encryption is active.

### Windows service graceful shutdown (PR-001 fix)
**Rationale**: The service handler now receives `*http.Server` directly and calls `server.Shutdown(ctx)` with a 30-second timeout when receiving Stop/Shutdown control commands. This ensures proper connection draining per CISO SR9 and DPO R8.

### Port preservation from CONNECT host:port (FIX-ORCH-2)
**Rationale**: The CONNECT handler now preserves the port from the request (e.g., `chatgpt.com:8443`). If no port is specified, defaults to 443. The port is passed through to `handleMITM` and `handleTunnel` for correct upstream dialing.

## 7. Platform-Specific Notes

### Windows
- CA key encrypted via DPAPI (CryptProtectData) before disk write to `%PROGRAMDATA%\Qindu\ca.key`
- CA certificate stored as plaintext `ca.crt` (public key, not secret)
- Windows service auto-detection: `svc.IsAnInteractiveSession()` distinguishes service vs console
- Cross-compilation from Linux: `GOOS=windows GOARCH=amd64 go build` succeeds

### Linux / macOS / CI
- CA key memory-only (no disk persistence)
- No Windows service support (graceful fallback to console mode)
- All integration tests use in-process TLS servers (no Docker requirement for tests)

### Cross-compilation
- `ca_windows.go` uses `//go:build windows` tag
- `ca_other.go` uses `//go:build !windows` tag
- `service_other.go` uses `//go:build !windows` tag
- Both `GOOS=windows GOARCH=amd64` and `GOOS=windows GOARCH=arm64` compile successfully

## 8. Known Limitations and Remaining Gaps

### Not implemented (excluded from sprint — future work)
- ❌ PII detection / recognizers (QINDU-0005+)
- ❌ Tokenisation / rehydratation (QINDU-0007+)
- ❌ Vault local (QINDU-0008)
- ❌ Mode monitor / enforce toggle (config field present but ignored)
- ❌ Installer Windows / MSI (QINDU-0002)
- ❌ Browser configuration automation (QINDU-0002)
- ❌ Provider adapters (chatgpt, claude)
- ❌ Fail-closed error page
- ❌ Hot-reload configuration

### Known gaps
1. **Windows ACL on CA key**: The `ca_windows.go` `setKeyACL()` function is a stub — file permissions rely on `0600` mode. Full `SetNamedSecurityInfo` ACL implementation requires more complex Windows API calls (deferred to QINDU-0002 installer sprint).
2. **HTTP/2 browser-to-proxy**: The proxy reads HTTP/1.1 requests from the browser after TLS handshake. HTTP/2 from browser to proxy is not supported in this sprint (browser does H2 negotiation via CONNECT tunnel, which is standard HTTP/1.1).
3. **PAC caching headers**: PAC response includes `Cache-Control: no-cache`. Recommended for dynamic PAC. May cause extra requests from browser.
4. **No connection rate limiting**: Single-user localhost proxy — not a meaningful attack vector in V1.
5. **Config `mode`/`fail_mode` silently ignored**: Parsed but have no effect in QINDU-0001 (per sprint scope). Startup log could warn operators.
6. **Tunnel dialer uses hardcoded timeout**: `net.DialTimeout` with 10s timeout, no context propagation for graceful shutdown cancellation.

### Deviations from story/ADRs
- **Integration test approach**: The story mentions `testcontainers-go` with `nginx:alpine` Docker containers. Current integration tests use in-process Go TLS servers instead. This is faster, more reliable in CI, and avoids Docker dependency for test runs. `testcontainers-go` is included as a dependency for future Docker-based tests.
- **Test proxy logger**: The test harness now uses a debug-level text logger (captured to buffer) instead of `io.Discard`. This provides diagnostic output on test failure without slowing tests.

## 9. How to Test

### Quick test
```bash
go test -race ./...
```

### Run with coverage
```bash
go test -race -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

### Build for Windows
```bash
GOOS=windows GOARCH=amd64 go build ./cmd/agent/
```

### Run the proxy (console mode)
```bash
go run ./cmd/agent/ -config configs/default.yaml
```

### Manual smoke test
```bash
# Start proxy in one terminal
go run ./cmd/agent/ -config configs/default.yaml

# In another terminal:
# Health check
curl http://127.0.0.1:8787/health
# PAC file
curl http://127.0.0.1:8787/proxy.pac
# CONNECT tunnel (non-AI domain)
curl -x http://127.0.0.1:8787 https://example.com/ -v
```

## 10. CI/CD

GitHub Actions workflow (`.github/workflows/ci.yml`):
- **Triggers**: push + pull_request on `main`
- **Matrix**: Go 1.26
- **Steps**:
  1. Checkout
  2. Setup Go
  3. Cache modules
  4. `go mod verify`
  5. `go vet ./...`
  6. `go test -race -count=1 -timeout 120s ./...`
  7. Cross-compile `GOOS=windows GOARCH=amd64`
  8. Cross-compile `GOOS=windows GOARCH=arm64`
  9. Code formatting check (`go fmt` + git diff)
- **Docker**: Not required for current tests (integration tests use in-process TLS servers)

## 11. Peer Review Fixes Changelog

After peer review (qindu-peer-reviewer, 2026-06-12), the following fixes were applied:

| ID | Severity | Issue | Resolution |
|---|---|---|---|
| **PR-001** | CRITICAL | Windows service graceful shutdown non-functional — `server.Shutdown()` never called on Stop/Shutdown | Rewrote `serviceHandler.Execute()` to receive `*http.Server`, call `h.server.Shutdown(ctx)` with 30s timeout on Stop/Shutdown, drain connections, then wait for `ListenAndServe` to return |
| **PR-002** | HIGH | Public test hooks `SetUpstreamCertPool` / `SetDialTLS` expose mutation surface | Removed both public methods. Tests (same package) use direct field access: `h.proxy.rootCAs = ...` and `h.proxy.dialTLS = ...` |
| **PR-003** | HIGH | Byte counting silently zero for chunked/streaming (Content-Length == -1) | Added `countingWriter` wrapper that atomically counts actual bytes written to the connection, regardless of Content-Length. Applied to both request and response paths |
| **PR-004** | HIGH | 7 `var _ =` import hacks masking unused imports | Removed all 7 occurrences. Removed unused imports: `log/slog` (connect.go), `crypto` (ca.go), `os` (windows_service.go), `encoding/binary` (ca_windows.go), `golang.org/x/sys/windows` (ca_windows.go). Removed dead `var _=` lines from test file and service_other.go |
| **PR-005** | HIGH | `CA.TLSCertificate()` dead code with misleading name | Removed the method entirely (0 callers) |
| **PR-006** | HIGH | `tunnelCopy()` dead code never called | Removed the function. Blind tunnel copy is implemented inline in `handleTunnel` |
| **PR-007** | HIGH | Health handler duplicated with inconsistent JSON construction | Proxy's `handleHealth` now delegates to `service.HealthHandler()`. Version string passed via `NewProxy` constructor parameter. Single source of truth for health endpoint |

Additional orchestrator findings fixed:

| ID | Issue | Resolution |
|---|---|---|
| **FIX-ORCH-1** | `configs/default.yaml` missing | Created with default configuration matching story.md |
| **FIX-ORCH-2** | Port hardcoded to 443; CONNECT port discarded | `handleCONNECT` preserves the port from `host:port`. Defaults to 443 if not specified. Passes port to `handleMITM` and `handleTunnel` |
| **FIX-ORCH-3** | Cert cache unbounded growth | Added `maxSize` field (default 1000). `evictIfNeededLocked()` removes a random entry when at capacity. Added `NewCertCacheWithSize()` for custom limits |

### Verification

After all fixes:
- ✅ `go build ./...` — passes
- ✅ `go vet ./...` — passes
- ✅ `go test -race -count=1 ./...` — all 71+ tests pass
- ✅ `GOOS=windows GOARCH=amd64 go build ./cmd/agent/` — cross-compiles cleanly
- ✅ `go fmt ./...` — clean
- ✅ `go mod tidy` — clean

## 12. Re-Review Fixes Changelog

After second peer review (qindu-peer-reviewer, 2026-06-12), the following additional fixes were applied:

| ID | Severity | Issue | Resolution |
|---|---|---|---|
| **PR-NEW-001** | MEDIUM | Tunnel `bytes_in` race condition — the client→upstream goroutine's `bytesIn.Add(n)` may execute after the connection log entry is written, resulting in `bytes_in: 0` | Added `sync.WaitGroup` to `handleTunnel`. Both copy directions now complete before logging. Also added `CloseWrite()` on TCP connections to properly signal the peer to stop reading |
| **PR-NEW-002** | MEDIUM | DPAPI missing `CRYPTPROTECT_LOCAL_MACHINE` flag — encryption bound to user context instead of machine, preventing service (SYSTEM) from decrypting keys generated in console mode (admin user) | Added named constants `cryptProtectUIFForbidden` (0x1) and `cryptProtectLocalMachine` (0x4). Both `dpapiEncrypt` and `dpapiDecrypt` now use `flags := uint32(cryptProtectUIFForbidden \| cryptProtectLocalMachine)` |
