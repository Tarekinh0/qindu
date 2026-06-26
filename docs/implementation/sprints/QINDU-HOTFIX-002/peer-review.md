# Peer Review: QINDU-HOTFIX-002 — Fix golangci-lint v2.7.2 Failures

**Reviewer**: qindu-peer-reviewer  
**Date**: 2026-06-19  
**Sprint**: QINDU-HOTFIX-002  
**Verdict**: **FIX_AND_RESUBMIT** — 47 lint issues must be resolved; no critical security bugs found.

---

## 1. Executive Summary

This is a hotfix sprint targeting **47 golangci-lint v2.7.2 findings** across 6 categories (errcheck, govet, ineffassign, misspell, staticcheck, unused). The underlying code is fundamentally sound — well-structured, Go-idiomatic, security-conscious, and properly tested. However, the lint failures are genuine and must be fixed before CI can pass.

**Overall architecture rating**: Strong. The codebase follows ADR-001 through ADR-010 faithfully. Domain boundaries are clear (proxy, tls, policy, logging, service). No PII leakage, no security regressions needed.

**Risk assessment**: LOW. None of the 47 issues represent a security vulnerability, data-loss risk, or production panic. All are code-quality hygiene issues: unchecked error returns, variable shadowing, suboptimal struct layout, dead code/assignments, and deprecated API usage. The fixes are mechanical and low-risk.

---

## 2. Scorecard

| Framework | Score | Justification |
|-----------|-------|---------------|
| **Clean Code** | 3/5 | Good naming, small functions, DRY. But 26 unchecked error returns violate "errors are values." Dead `upstreamServer` field and ineffectual assignment indicate sloppiness. |
| **Pragmatic Programmer** | 4/5 | Good orthogonality (proxy/tls/policy decoupled). Design by contract visible (Validate on load, nil guards). No test hooks in production. |
| **SOLID** | 4/5 | SRP: good per-package. OCP: `Interceptor` interface enables extension. ISP: `Interceptor` has only 2 methods. `CAStore` interface is clean. DIP: proxy depends on `Interceptor` interface, not concrete. |
| **Go Proverbs** | 2/5 | **Major gap**: 26 unchecked errors violate "Errors are values" and "Don't just check errors — handle them gracefully." Shadowing issues violate clarity. `defer` in loops absent (good). |
| **Effective Go** | 3/5 | Idiomatic naming, proper `%w` wrapping, `defer` usage correct. But fieldalignment issues, deprecated API usage (`RevokedCertificates`), and the `cancelled` misspelling dock points. |
| **DDD** | 4/5 | Ubiquitous language aligns with domain (proxy, MITM, CA, leaf cert, PAC). Bounded contexts well-separated. Value objects present (ConnectionLogEntry). |
| **Code Complete** | 4/5 | Defensive programming visible (nil guards in `GenerateLeafCert`, path traversal rejection). No global mutable state. Config validation at boundaries. Missing: Write/Close errors not verified at I/O boundaries. |

---

## 3. Critical Findings 🔴

### PR-001 — Unchecked `fs.Parse` error in ca-init path
- **File**: `cmd/agent/main.go:59`
- **Severity**: **HIGH**
- **Problem**: `fs.Parse(args)` returns an error that is silently discarded. While `flag.ExitOnError` causes `os.Exit(2)` on parse failure, this is not guaranteed for all error modes. If the flag package internals change, or if `flag.ExitOnError` behavior is removed, this becomes a silent data corruption path where the CLI silently continues with zero-value flags.
- **Fix**: Capture and handle the return value explicitly:
  ```go
  if err := fs.Parse(args); err != nil {
      fmt.Fprintf(os.Stderr, "error: parsing ca-init flags: %v\n", err)
      return 1
  }
  ```

### PR-002 — `bufrw.WriteString` / `bufrw.Flush` errors ignored after CONNECT hijack
- **File**: `internal/proxy/connect.go:64-65`
- **Severity**: **HIGH**
- **Problem**: After hijacking the connection, the proxy writes `HTTP/1.1 200 Connection Established\r\n\r\n` to the client. If `bufrw.WriteString` or `bufrw.Flush` fail (broken pipe, client disconnected mid-hijack), the error is silently swallowed. The proxy then proceeds to call `handleMITM` or `handleTunnel` on a connection whose write side is dead — wasting a goroutine, TLS handshake CPU, and potentially a certificate generation. This is a resource-leak vector under high connection churn.
- **Fix**:
  ```go
  if _, err := bufrw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
      p.logger.Debug("client disconnected before CONNECT response", "host", hostOnly, "error", err)
      return
  }
  if err := bufrw.Flush(); err != nil {
      p.logger.Debug("flush failed after CONNECT response", "host", hostOnly, "error", err)
      return
  }
  ```

### PR-003 — `conn.Write` error ignored in `sendBadGateway`
- **File**: `internal/proxy/mitm.go:170`
- **Severity**: **MEDIUM**
- **Problem**: `sendBadGateway` writes a 502 error JSON to the connection. If the write fails (the connection is already dead, which is the typical case here), the error is silently ignored. While this is usually benign (connection is already toast), it hinders debugging and violates the "don't ignore errors" principle.
- **Fix**:
  ```go
  func (p *Proxy) sendBadGateway(conn io.Writer) {
      msg := "HTTP/1.1 502 Bad Gateway\r\n...\n"
      if _, err := conn.Write([]byte(msg)); err != nil {
          p.logger.Debug("sendBadGateway write failed", "error", err)
      }
  }
  ```

### PR-004 — `w.Write` error ignored in PAC handler
- **File**: `internal/proxy/proxy.go:88`
- **Severity**: **MEDIUM**
- **Problem**: `w.Write([]byte(pacContent))` returns `(int, error)`. A partial write or write failure means the browser receives a truncated PAC file, causing silent proxy misconfiguration. The HTTP status is already 200 at this point via the prior `w.WriteHeader(http.StatusOK)` call (line 87), so the browser sees HTTP 200 + corrupted body.
- **Fix**: Either check the error or restructure to use `io.WriteString` and log failures:
  ```go
  if _, err := w.Write([]byte(pacContent)); err != nil {
      p.logger.Error("failed to write PAC response", "error", err)
  }
  ```

### PR-005 — `json.NewEncoder(w).Encode(resp)` error ignored in health handler
- **File**: `internal/service/health.go:32`
- **Severity**: **MEDIUM**
- **Problem**: Same pattern as PR-004. `Encode` returns an error that is silently discarded. A client could receive a partial JSON body with HTTP 200 status, breaking health-check monitoring tools.
- **Fix**:
  ```go
  if err := json.NewEncoder(w).Encode(resp); err != nil {
      slog.Error("health response encode failed", "error", err)
  }
  ```

### PR-006 — `fmt.Fprintf` error ignored on default action
- **File**: `internal/proxy/connect.go:92`
- **Severity**: **LOW**
- **Problem**: In the `default` case of the CONNECT switch, `fmt.Fprintf(clientConn, "HTTP/1.1 500 Internal Server Error\r\n\r\n")` error is ignored. This is a defense-in-depth handler for an impossible state (unknown routing action), but if triggered, the client gets no response if the write fails.
- **Fix**: Assign to `_` with comment, or use the same pattern as PR-003.

---

## 4. Design Flaws & Anti-Patterns 🟡

### PR-100 — Variable shadowing: `err` re-declared in same function scope
- **Category**: Readability / Maintainability
- **Files**: `cmd/agent/main.go`, `internal/proxy/forward.go`, `internal/proxy/mitm.go`, `internal/tls/cert_test.go`, `cmd/agent/ca_init_test.go`, `internal/proxy/proxy_integration_test.go`
- **Problem**: Multiple functions use `:=` to re-declare `err` when other new variables are introduced on the left-hand side (e.g., `modifiedReq, reqBody, err := interceptor.InterceptRequest(req)`). This creates a new `err` binding that shadows the outer `err`, making code flow harder to trace and potentially masking bugs where the wrong `err` is checked.
- **Fix**: Declare `err` once at function top with `var err error`, then use `=` instead of `:=` in subsequent assignments. Example in `forward.go`:
  ```go
  var err error
  req, err := http.ReadRequest(browserReader)
  ...
  var modifiedReq *http.Request
  var reqBody io.ReadCloser
  modifiedReq, reqBody, err = interceptor.InterceptRequest(req)
  ```

### PR-101 — Suboptimal struct field alignment
- **Category**: Memory efficiency
- **Files**: `internal/logging/logger.go:12-19` (ConnectionLogEntry), `internal/policy/config.go:13-17` (Config), `internal/proxy/proxy.go:20-33` (Proxy), `internal/proxy/proxy_integration_test.go:30-42` (testHarness), `internal/tls/cert_cache.go:18-22` (CertCache)
- **Problem**: The Go compiler pads struct fields to align them on word boundaries. Poor field ordering wastes memory — e.g., `Config` has `int` fields (8 bytes) interspersed with `string` fields (16 bytes) and `map` fields (8 bytes), causing unnecessary padding.
- **Fix**: Use `golang.org/x/tools/go/analysis/passes/fieldalignment` or reorder fields from largest to smallest alignment (pointers/interfaces/maps/slices/strings → int64/uint64 → int32/float32 → etc.). For `CertCache`:
  ```go
  type CertCache struct {
      cache   map[string]*tls.Certificate  // 8 bytes
      mu      sync.RWMutex                 // 24 bytes
      maxSize int                          // 8 bytes (was after mu, now after cache)
  }
  ```

### PR-102 — Deprecated `crl.RevokedCertificates` usage
- **Category**: Deprecation
- **File**: `internal/tls/cert_test.go:284`
- **Problem**: `crl.RevokedCertificates` has been deprecated since Go 1.21 in favor of `crl.RevokedCertificateEntries`. Using deprecated APIs risks breakage when they are removed in future Go versions.
- **Fix**:
  ```go
  if len(crl.RevokedCertificateEntries) != 0 {
      t.Errorf("CRL should have 0 revoked certs, got %d", len(crl.RevokedCertificateEntries))
  }
  ```

### PR-103 — Unused `upstreamServer` field in test harness
- **Category**: Dead code
- **File**: `internal/proxy/proxy_integration_test.go:35`
- **Problem**: The `upstreamServer *http.Server` field in `testHarness` is never read. It's assigned at construction but only the address, cert pool, and shutdown function are used. Dead fields confuse readers and bloat the struct.
- **Fix**: Remove the field from the struct and the raw assignment. The `shutdownUpstream` closure already captures the server reference.

### PR-104 — Ineffectual assignment to `port` in test helper
- **Category**: Dead code
- **File**: `internal/proxy/proxy_integration_test.go:140`
- **Problem**: In `proxyURL()`, `port` is assigned at line 137, then reassigned at line 140 without the first value ever being used. This is dead code that the `ineffassign` linter correctly flags.
- **Fix**: Remove lines 137-141 (the `if port == ""` block). The logic at lines 142-146 handles the addr extraction correctly. Or restructure to eliminate the dead path.

### PR-105 — Misspelling: `cancelled` → `canceled`
- **Category**: Typo
- **File**: `cmd/agent/main.go:207`
- **Problem**: Error message uses British spelling `cancelled`. The `misspell` linter with `locale: US` requires American English `canceled`. Minor, but CI blocks on it.
- **Fix**: Change `"aborted by user — CA generation cancelled"` to `"aborted by user — CA generation canceled"`.

### PR-106 — Unchecked `GetOrCreate` errors in cache tests
- **Category**: Test quality
- **File**: `internal/tls/cert_cache_test.go:162-166`, etc.
- **Problem**: Test code calls `cache.GetOrCreate("a.com", ca)` and discards both the certificate and the error. If `GetOrCreate` fails (e.g., CA is nil or cert generation fails), the test silently passes with an empty cache, producing false positives.
- **Fix**: Check the error in each call:
  ```go
  if _, err := cache.GetOrCreate("a.com", ca); err != nil {
      t.Fatalf("GetOrCreate(a.com): %v", err)
  }
  ```

### PR-107 — Unchecked `json.Unmarshal` in integration test
- **File**: `internal/proxy/proxy_integration_test.go:490`
- **Problem**: `json.Unmarshal(data, &fields)` error is ignored. If the marshaled output is corrupt (should never happen with valid struct, but still invalid JSON could be produced), the test might pass when it shouldn't because `fields` would be empty.
- **Fix**: Add error check.

### PR-108 — `os.MkdirAll` and `os.WriteFile` errors unchecked in tests
- **File**: `cmd/agent/ca_init_test.go:105-108, 355, 367`
- **Problem**: Test setup calls `os.MkdirAll`, `os.WriteFile`, and `os.RemoveAll` without checking errors. If any of these fail (permissions, disk full), the test may silently produce a false pass or obscure failure.
- **Fix**: Check all errors in test setup; call `t.Fatalf` on failure. For `defer os.RemoveAll`, wrap in an anonymous function that checks (or uses `t.TempDir()` which auto-cleans).

### PR-109 — Double-close of `clientConn` between handleCONNECT and handleMITM
- **Category**: Code clarity
- **File**: `internal/proxy/connect.go:61` + `internal/proxy/mitm.go:28`
- **Problem**: `handleCONNECT` defers `clientConn.Close()` at line 61, then passes `clientConn` to `handleMITM`, which also defers `clientConn.Close()` at line 28. While `net.Conn.Close()` is safe to call multiple times, the double-close is confusing and suggests the ownership semantics are unclear. If `handleMITM` is taking ownership, `handleCONNECT` should not defer the close.
- **Fix**: In `handleCONNECT`, remove `defer clientConn.Close()` when routing to MITM (since `handleMITM` manages the lifecycle). Keep the defer for the Tunnel and default paths.

---

## 5. Excellence 🟢

### Scattered excellence — patterns to preserve

**1. `cert_cache.go` — GetOrCreate double-check locking pattern (lines 73-105)**
The classic double-check after upgrading from read lock to write lock, with inline TTL check to avoid deadlock. This is textbook correct concurrent code:
```go
c.mu.RLock()
if cert, ok := c.Get(host); ok { return cert, nil }  // fast path
c.mu.RUnlock()
c.mu.Lock()
// double-check with inlined TTL (can't call Get() — would deadlock on RLock)
if cert, ok := c.cache[host]; ok {
    if cert.Leaf != nil && time.Now().After(cert.Leaf.NotAfter) {
        delete(c.cache, host)
    } else {
        return cert, nil
    }
}
```
If every concurrent structure in this codebase follows this pattern, we're in excellent shape.

**2. `cert.go` — Hostname validation with multi-layer defense (lines 107-133)**
`isValidHostname` checks length, IP rejection, character set, label-level hyphens, and label length bounds. This is defensive programming at its best — each validation layer catches a different class of invalid input before it reaches `x509.CreateCertificate`.

**3. `ca_windows.go` — DPAPI with `unsafe.Slice` for zero-copy (line 132)**
```go
encrypted := make([]byte, outBlob.cbData)
copy(encrypted, unsafe.Slice(outBlob.pbData, outBlob.cbData))
```
Proper use of `unsafe.Slice` to avoid CGo or manual pointer arithmetic. `LocalFree` is deferred correctly to prevent memory leaks even on error paths.

**4. `config.go` — MergeFileOverride field-by-field merge (lines 157-224)**
The override mechanism correctly applies a field-by-field merge instead of unmarshaling directly into the receiver (which would replace nested maps wholesale). The `CertCacheEnabled` / `PIILogging` bool zero-value comment (lines 193-217) shows awareness of the yaml.v3 deserialization ambiguity.

**5. `graceful.go` and `windows_service.go` — Proper graceful shutdown with drain**
Both console mode (`WaitForShutdown`) and Windows service mode (`Execute`) use `http.Server.Shutdown(ctx)` with `context.WithTimeout`, correctly draining connections rather than canceling them abruptly. The service handler uses `errCh` to synchronize with the goroutine — no goroutine leaks.

**6. Comprehensive security tests in `proxy_integration_test.go`**
The test suite validates: loopback-only binding, leaf certs not persisted, NoOp transparency, PAC/health endpoint no-secrets, upstream TLS rejection of self-signed, config rejection of `InsecureSkipVerify` by default, and domain injection prevention. This is production-grade security test coverage.

**7. `ADR` conformance across the board**
Every architectural decision from ADR-001 through ADR-010 is respected:
- Single-binary Windows service (ADR-006) ✅
- Memory-only leaf certs, no disk persistence (ADR-003) ✅
- Interceptor interface with streaming bodies (ADR-004) ✅
- Structured JSON logging without PII (ADR-008) ✅
- Testcontainers-free integration tests with synthetic TLS (ADR-007) ✅
- TLS upstream validation configurable (ADR-010) ✅
- CONNECT + MITM architecture (ADR-002) ✅
- Dynamic PAC generation (ADR-005) ✅

---

## 6. Lint Issue Inventory (Reference)

Complete catalog of all 47 findings with file locations for DevSecOps to fix:

### 6.1 errcheck (26 issues)

| # | File | Line(s) | Expression |
|---|------|---------|------------|
| E1 | `cmd/agent/main.go` | 59 | `fs.Parse(args)` |
| E2 | `cmd/agent/ca_init_test.go` | 105 | `os.MkdirAll(configDir, 0755)` |
| E3 | `cmd/agent/ca_init_test.go` | 107 | `os.WriteFile(configFile, ...)` |
| E4 | `cmd/agent/ca_init_test.go` | 108 | `os.RemoveAll("/tmp/testpf")` (defer) |
| E5 | `internal/logging/logger_test.go` | 163 | `json.Unmarshal([]byte(output), &logEntry)` |
| E6 | `internal/proxy/connect.go` | 61 | `clientConn.Close()` (defer) |
| E7 | `internal/proxy/connect.go` | 64 | `bufrw.WriteString(...)` |
| E8 | `internal/proxy/connect.go` | 65 | `bufrw.Flush()` |
| E9 | `internal/proxy/connect.go` | 92 | `fmt.Fprintf(clientConn, ...)` |
| E10 | `internal/proxy/connect.go` | 119 | `upstreamConn.Close()` (defer) |
| E11 | `internal/proxy/connect.go` | 132 | `tcpConn.CloseWrite()` |
| E12 | `internal/proxy/connect.go` | 140 | `tcpConn.CloseWrite()` |
| E13 | `internal/proxy/mitm.go` | 28 | `clientConn.Close()` (defer) |
| E14 | `internal/proxy/mitm.go` | 73 | `browserConn.Close()` (defer) |
| E15 | `internal/proxy/mitm.go` | 118 | `upstreamConn.Close()` (defer) |
| E16 | `internal/proxy/mitm.go` | 170 | `conn.Write([]byte(msg))` |
| E17 | `internal/proxy/proxy.go` | 88 | `w.Write([]byte(pacContent))` |
| E18 | `internal/service/health.go` | 32 | `json.NewEncoder(w).Encode(resp)` |
| E19-26 | `internal/proxy/proxy_integration_test.go` | various | `Serve`, `Shutdown`, `Encode`, `Write`, `Body.Close`, `Unmarshal`, `Close` |
| E27-30 | `internal/tls/cert_cache_test.go` | 162-183 | `GetOrCreate` calls |

### 6.2 govet — shadow (12 issues)

| # | File | Description |
|---|------|-------------|
| V1-V3 | `cmd/agent/main.go` | `err` shadow in `runCAInit`, `resolveConfigPath` |
| V4-V5 | `cmd/agent/ca_init_test.go` | `err` shadow in test functions |
| V6-V7 | `internal/proxy/forward.go` | `err` shadow in `forwardRequestAndResponse` (lines 64, 66, 80 etc.) |
| V8-V9 | `internal/proxy/mitm.go` | `err` shadow with `upstreamConn, err =` |
| V10-V11 | `internal/proxy/proxy_integration_test.go` | `err` shadow in test helpers |
| V12 | `internal/tls/cert_test.go` | `err` shadow |

### 6.3 govet — fieldalignment (5 issues)

| # | File | Struct |
|---|------|--------|
| F1 | `internal/logging/logger.go` | `ConnectionLogEntry` |
| F2 | `internal/policy/config.go` | `Config`, `AgentConfig`, `TLSConfig` |
| F3 | `internal/proxy/proxy.go` | `Proxy` |
| F4 | `internal/proxy/proxy_integration_test.go` | `testHarness` |
| F5 | `internal/tls/cert_cache.go` | `CertCache` |

### 6.4 ineffassign (1 issue)

| # | File | Line | Expression |
|---|------|------|------------|
| I1 | `internal/proxy/proxy_integration_test.go` | 140 | `port` reassigned without using first value |

### 6.5 misspell (1 issue)

| # | File | Line | Word |
|---|------|------|------|
| M1 | `cmd/agent/main.go` | 207 | `cancelled` → `canceled` |

### 6.6 staticcheck (2 issues)

| # | File | Line | Issue |
|---|------|------|-------|
| S1 | `internal/tls/cert_test.go` | 284 | `crl.RevokedCertificates` deprecated; use `RevokedCertificateEntries` |
| S2 | `internal/tls/ca_helper.go` | 82 | QF1008: could remove embedded field `PublicKey` from selector |

### 6.7 unused (1 issue)

| # | File | Line | Symbol |
|---|------|------|--------|
| U1 | `internal/proxy/proxy_integration_test.go` | 35 | `upstreamServer` field unused |

---

## 7. Security Audit (Qindu-Specific Checks)

| Check | Status | Notes |
|-------|--------|-------|
| No PII in logs, errors, test fixtures | ✅ PASS | Synthetic domains only; `ConnectionLogEntry` has no body/header fields. |
| No `InsecureSkipVerify` in production path | ✅ PASS | Only in test dial override with comment; prod path guarded by `UpstreamInsecure()` config flag defaulting to `"system"`. |
| Loopback-only bind enforced | ✅ PASS | `config.go:98-99` rejects non-loopback; `default.yaml` uses `127.0.0.1`. |
| DPAPI before disk write | ✅ PASS | `ca_windows.go` encrypts key via `CryptProtectData` before `os.WriteFile`. |
| Interceptor streaming-only | ✅ PASS | Interface uses `io.ReadCloser`; `NoOpInterceptor` returns body directly — no buffering. |
| Certificate cache bounded | ✅ PASS | `defaultMaxCacheSize = 1000`; random eviction when full. |
| No hardcoded secrets | ✅ PASS | All credentials are config-driven; no embedded keys. |
| Graceful shutdown drains connections | ✅ PASS | `server.Shutdown(ctx)` with 30s timeout; `errCh` goroutine synchronization. |
| Config validation at startup | ✅ PASS | `Validate()` called in `LoadConfig` and `ParseConfig`. |
| No telemetry/analytics/tracking | ✅ PASS | Zero external network calls outside proxy data path. |

---

## 8. Test Adequacy

| Area | Coverage | Notes |
|------|----------|-------|
| CA generation (ECDSA, Name Constraints, serial uniqueness) | ✅ Good | `ca_test.go`, `ca_init_test.go` cover generation, PEM roundtrip, key mismatch detection. |
| Leaf certificate generation (SAN, wildcard, CRL DP, revocation extensions) | ✅ Good | `cert_test.go` covers SAN, validity, signing, NotCA, ServerAuth, revocation extensions. |
| Certificate cache (Get/Put/GetOrCreate, concurrency) | ✅ Good | `cert_cache_test.go` covers basic get/set, concurrent read/write (race-enabled), same-key concurrency. |
| Domain router (MITM/Tunnel, case-insensitive, injection prevention) | ✅ Good | `domain_router_test.go` covers exact match, subdomain, case, attacks, empty list. |
| PAC generation (domains, structure, no secrets) | ✅ Good | `pac_test.go` covers content, empty domains, single domain, forbidden content. |
| Config (parse, validate, merge override) | ✅ Good | `config_test.go` covers valid YAML, invalid YAML, loopback rejection, upstream validation, port range, CA algorithm, override merge preservation. |
| Logging (connection entry, no PII, timestamp/duration helpers) | ✅ Good | `logger_test.go` covers JSON/text, levels, field names, PII absence. |
| Integration (CONNECT MITM, blind tunnel, PAC endpoint, health, 502, graceful shutdown, upstream TLS validation, NoOp transparency, cert cache concurrency) | ✅ Good | `proxy_integration_test.go` — 15 tests covering E2E flows. |
| **Gap**: Integration test with real TLS handshake (non-InsecureSkipVerify) | ⚠️ Minor | Current MITM E2E test overrides dial to skip verify. A separate test validating real upstream TLS against a trusted pool exists (`TestIntegration_UpstreamTLSValidationRejectsSelfSigned`) but only tests the rejection path. |
| **Gap**: `handleCONNECT` with missing Host header | ⚠️ Minor | Code handles it (line 20-23) but no test exercises this path. |

---

## 9. Verdict

**FIX_AND_RESUBMIT**

The codebase is architecturally sound, security-hardened, and well-tested. The 47 lint issues are genuine but **none are security-critical**. They represent a maintenance burden that must be cleared for CI to pass, and fixing them will improve code robustness (especially the unchecked error returns in I/O paths).

### Fix Priority Order

1. **Immediate (blocks CI)**: All 47 lint issues per §6 inventory. Most are mechanical 1-line changes.
2. **Design (post-CI)**: PR-109 (double-close cleanup), PR-104 (dead port assignment).
3. **Enhancement (future sprint)**: Add test for `handleCONNECT` with empty Host header; add E2E test with real (non-skip-verify) TLS handshake.

### Estimated Fix Effort

~30 minutes for a developer familiar with the codebase. All changes are localized and mechanical. No architectural changes required.

---

*End of peer review. qindu-peer-reviewer signing off.*
