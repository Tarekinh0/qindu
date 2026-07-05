# Dev Notes — QINDU-0008 Fix Cycle (Peer Review)

**Fix cycle**: Post-peer-review blank-slate remediation  
**Date**: 2026-07-04

## Modified Files

| File | Changes |
|------|---------|
| `internal/tls/cert.go` | Removed `slog.Default().Warn()` bypass (PR-001); added nil guard and empty `PROGRAMDATA` handling to `resolveCRLDP` (PR-002); removed `"log/slog"` import |
| `internal/tls/cert_test.go` | Updated `TestGenerateLeafCert_CRLDP_Fallback` to handle CI/Unix where `PROGRAMDATA` is unset — skips CDP assertions instead of failing |
| `internal/vault/manager.go` | Fixed thundering-herd race in `GetOrCreate` waiter retry path — waiter now registers itself as new creator before retrying creation (PR-003) |
| `internal/vault/manager_test.go` | Replaced custom `containsStr` with `strings.Contains` (PR-101); removed `containsStr` function; added `"strings"` import |
| `internal/crypto/crypto.go` | Fixed stale doc comment on `zeroBytes` — was copy-pasted from `writeKeyFile` (PR-004) |
| `cmd/agent/proxy.go` | Removed dead `VaultManager` creation and `createVaultManager` function — deferred to QINDU-0009 (PR-005); removed `"internal/vault"` import |
| `.gitignore` | Added `/agent-windows.exe` entry (PR-006) |
| `agent-windows.exe` (root) | Deleted binary artifact (PR-006) |

## Technical Choices and Rationale

### PR-001: `slog.Default()` bypass removed
Chose **Option A** from the peer review: removed the `slog.Default().Warn()` call entirely. The fallback from `PROGRAMDATA` is deterministic and correct — there is no need for a warning on every leaf cert generation cycle. This eliminates both the architectural separation violation (`internal/tls` depending on global logging state) and the production invisibility issue (stderr discarded by Windows SCM).

### PR-002: Nil guard + empty PROGRAMDATA
Added `ca == nil` guard at the top of `resolveCRLDP`, returning nil. Also added a check for empty `os.Getenv("PROGRAMDATA")` — when unset (CI/Unix/cross-platform), returns nil rather than constructing a broken `file:///Qindu/ca.crl` URL. The `nil` return flows through `GenerateLeafCert` to produce a certificate with no CDP URLs, which is safe (no CRL verification) and better than a dangling `file://` URL that would fail silently.

### PR-003: Waiter retry registration
The waiter path in `GetOrCreate` now registers itself as the new creator (`vm.creating[path] = make(chan struct{})`) before dropping the lock after a failed creation. This prevents the thundering herd where all waiters wake up simultaneously and attempt `createUserVault` (which triggers concurrent `bolt.Open` calls — most fail with timeout errors). With this fix, only the first waiter registers as creator; others see the new entry in `vm.creating` and become waiters on the new channel (cascaded deduplication). The double-check at the end of the slow path (lines 133-138) already handles the edge case where a waiter created a vault before the original creator registered it.

### PR-005: VaultManager deferred
Removed `createVaultManager` and its caller site from `runProxy`. The `VaultManager` was constructed with a background eviction goroutine and context but had no consumer (no wiring into the proxy). The subsystem is tested in isolation via `manager_test.go` and `vault_test.go`. Wiring happens in QINDU-0009 where the persister is connected to the proxy.

### PR-101: `containsStr` → `strings.Contains`
Replaced the custom 9-line `containsStr` function with `strings.Contains` from the standard library. The only behavioral difference (`containsStr("", "")` returns true vs. `strings.Contains` returning false) is irrelevant because all test call sites guard against empty substrings (`tc.contains != ""`).

## How to Test

```bash
# Build, vet, and test with race detector
go build ./... && go vet ./... && go test -count=1 -race ./...

# Specifically verify the thundering-herd fix
go test -race -run TestVaultManager_GetOrCreate_ConcurrentDeduplication ./internal/vault/

# Verify CRL DP fallback works when CRLPath is empty
go test -race -run TestGenerateLeafCert_CRLDP_Fallback ./internal/tls/

# Verify the proxy binary builds without vault manager
go build ./cmd/agent/
```

## Gaps and Remaining Risks

- **CRLPath on CA struct (PR-102)**: Not addressed — the review's recommendation to pass CDP as a parameter to `GenerateLeafCert` is a design change that touches the cert cache and several call sites. It should be a dedicated refactoring story.
- **slog.Default() fallback in vault (PR-103)**: Not addressed — the review acknowledged this as safe and recommended leaving it as-is with a comment. This is a defensive nil-guard, not a logging bypass.
- **TOKEN_IMPERSONATE comment (PR-105)**: Not addressed — expanding the comment is a documentation-only change that doesn't affect behavior. Can be picked up in a future maintenance sprint.
