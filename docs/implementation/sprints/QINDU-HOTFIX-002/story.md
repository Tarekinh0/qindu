# QINDU-HOTFIX-002: Fix golangci-lint failures blocking CI

## Status
DRAFT

## Context
The CI pipeline (QINDU-0004) is failing because golangci-lint v2.7.2 reports 47 code quality issues across the codebase. The `.golangci.yml` config was fixed (removed invalid `exclusions` key), unblocking the linter, which now reveals pre-existing code issues that were previously masked.

All other CI jobs pass: Code Formatting, Test & Build, Validate WiX Sources.

## Scope
Fix all golangci-lint findings so CI turns green again. No new features.

## Lint Issues Summary (47 total)

### errcheck (26 issues) — Unchecked error returns
- `cmd/agent/ca_init_test.go`: `os.MkdirAll`, `os.WriteFile`, `os.RemoveAll` (3)
- `cmd/agent/main.go:59`: `fs.Parse` (1)
- `internal/logging/logger_test.go:163`: `json.Unmarshal` (1)
- `internal/proxy/connect.go`: `clientConn.Close`, `bufrw.WriteString`, `bufrw.Flush`, `fmt.Fprintf`, `upstreamConn.Close`, `tcpConn.CloseWrite` (6)
- `internal/proxy/mitm.go`: `clientConn.Close`, `browserConn.Close`, `upstreamConn.Close`, `conn.Write` (4)
- `internal/proxy/proxy.go:88`: `w.Write` (1)
- `internal/proxy/proxy_integration_test.go`: `Serve`, `Shutdown`, `Encode`, `Write`, `Body.Close`, `Unmarshal`, various `Close` calls (17)
- `internal/service/health.go:32`: `Encode` (1)
- `internal/tls/cert_cache_test.go`: `GetOrCreate` (4)

### govet (17 issues)
- **shadow** (12): Variable `err` shadows earlier declaration in `main.go`, `ca_init_test.go`, `forward.go`, `mitm.go`, `proxy_integration_test.go`, `cert_test.go`
- **fieldalignment** (5): Suboptimal struct layout in `logging/logger.go`, `policy/config.go`, `proxy/proxy.go`, `proxy/proxy_integration_test.go`, `tls/cert_cache.go`

### ineffassign (1 issue)
- `internal/proxy/proxy_integration_test.go:140`: Ineffectual assignment to `port`

### misspell (1 issue)
- `cmd/agent/main.go:207`: `cancelled` should be `canceled`

### staticcheck (2 issues)
- `internal/tls/cert_test.go:284-285`: `crl.RevokedCertificates` deprecated since Go 1.21, use `RevokedCertificateEntries`
- `internal/tls/ca_helper.go:82`: QF1008: could remove embedded field `PublicKey` from selector

### unused (1 issue)
- `internal/proxy/proxy_integration_test.go:35`: `upstreamServer` field unused

## Affected Domains
[proxy, tls, logging, policy, service, agent, ci]

## Dependencies
None (hotfix on completed sprints)

## Gates Required
Peer Reviewer → DevSecOps → Peer Reviewer (re-check) → Closure

## Forbidden
- No new features
- No PII in logs or test fixtures
- No modification to ADRs
- No weakening of security or privacy guarantees

## Acceptance Criteria
- `golangci-lint run ./...` passes with zero findings
- All existing tests still pass
- CI pipeline fully green
