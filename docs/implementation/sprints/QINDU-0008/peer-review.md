# Peer Review — QINDU-0008: Vault local chiffré

**Reviewer**: qindu-peer-reviewer (blank-slate, fresh session)  
**Date**: 2026-07-04 (round 2 — fresh review after fix cycle)  
**Scope**: All uncommitted changes + all untracked files in the working tree  
**Frameworks applied**: Clean Code, Pragmatic Programmer, SOLID, Go Proverbs, Effective Go, DDD, Code Complete

---

## Section 1: Scorecard

| Framework | Score | Justification |
|-----------|-------|---------------|
| **Clean Code** | 4/5 | Functions are small and single-responsibility. No dead code, no `var _ =` hacks, no comments-as-band-aids. Minor: stale comment in `crypto.go:168` references non-existent `setPlatformACL` hook. |
| **Pragmatic Programmer** | 4/5 | Platform build-tag separation (`crypto_unix.go`/`crypto_windows.go`) is orthogonal and reversible. Vault `GetOrCreate` deduplication via channel signaling is a well-chosen design pattern. Minor: `getCADir()` fallback to `/tmp` is a latent issue for multi-user Unix systems. |
| **SOLID** | 4/5 | `VaultManager` has clear SRP (create, evict, shutdown). Small interfaces throughout. Minor: `CRLPath` on `CA` mixes crypto and deployment concerns (acknowledged design tradeoff). |
| **Go Proverbs** | 5/5 | Errors are wrapped with `%w`, concurrency via channels and sync primitives is idiomatic. No panics outside test code. No `init()` abuse. Platform differences handled via build tags, not runtime checks. |
| **Effective Go** | 4/5 | Idiomatic naming, consistent `%w` error wrapping, proper `defer` usage. `gofmt` compliant. Minor: `slog.Default()` fallback in `manager.go:50` and `vault.go:77` is a defensive pattern — safe but inconsistent with the rest of the codebase. |
| **DDD** | 4/5 | Package boundaries (`vault`, `crypto`, `session`, `tls`) align with bounded contexts. Ubiquitous language in code. Minor: `CRLPath` on `CA` bleeds infrastructure concern into crypto domain object. |
| **Code Complete** | 4/5 | Defensive nil checks at all boundaries (`resolveCRLDP`, `GenerateLeafCert`, `CreateCRL`, `vault.New`). `PROGRAMDATA` empty check in fallback path. Minor: stale comment in `crypto.go:168`. |

---

## Section 2: Critical Findings 🔴

**NONE.** All five critical/high findings from the previous review (PR-001 through PR-006) have been resolved:

| Previous ID | Issue | Resolution |
|-------------|-------|------------|
| PR-001 | `slog.Default()` bypass in `cert.go` | `resolveCRLDP` no longer calls any logger — the fallback path is silent |
| PR-002 | `resolveCRLDP` nil receiver panic | Nil guard added at line 115; empty `PROGRAMDATA` returns `nil` CDP |
| PR-003 | `GetOrCreate` waiter-retry race | Waiter now registers as creator before retrying (lines 105-107) |
| PR-004 | Stale doc comment on `zeroBytes` | Comment updated to describe `zeroBytes` correctly |
| PR-005 | Dead `vaultManager` in proxy | Vault manager removed entirely from `proxy.go` — vault code lives in library only, pending QINDU-0009 wiring |
| PR-006 | Binary artifact `agent-windows.exe` | File deleted; `.gitignore` entry confirmed |

All packages build and pass `-race` with zero failures. `go vet` reports zero warnings.

---

## Section 3: Design Flaws 🟡

### PR-101: Stale comment in `crypto.go` references non-existent function

- **ID**: PR-101
- **Category**: Maintainability
- **File**: `internal/crypto/crypto.go:168`
- **Problem**: The comment `// Platform-specific ACL logic is applied via the setPlatformACL hook.` references a function `setPlatformACL` that does not exist anywhere in the codebase. The actual platform-specific logic (`validateKeyFilePermissions`) is handled via build-tagged files, not an ACL hook. This stale comment misleads future maintainers about the security architecture.
- **Fix**: Remove or update the comment:

  ```go
  // writeKeyFile writes the 32-byte key to disk with mode 0600.
  // Platform-specific permission validation is handled by validateKeyFilePermissions
  // (crypto_unix.go or crypto_windows.go), called by loadOrCreateKey on subsequent
  // reads. Windows relies on directory ACLs, not POSIX modes, so validation is a no-op.
  func writeKeyFile(path string, key []byte) error {
  ```

---

### PR-102: `CRLPath` on `CA` struct mixes crypto and deployment concerns

- **ID**: PR-102
- **Category**: Coupling / DDD
- **File**: `internal/tls/ca.go:22`
- **Problem**: The `CA` struct (a domain object representing a cryptographic certificate authority) now carries a `CRLPath string` — a filesystem deployment path. This forces every consumer of `CA` to think about deployment layout, even tests. The test `TestGenerateLeafCert_RevocationExtensions` works around this by setting `ca.CRLPath = filepath.Join(tmpDir, CRLFilename)`.
- **Status**: Acknowledged design tradeoff. The alternative (passing CDP as a parameter to `GenerateLeafCert`) would require signature changes across the cert cache and MITM handler — high-touch for marginal benefit. This is acceptable for V1.

---

### PR-103: `slog.Default()` fallback inconsistency

- **ID**: PR-103
- **Category**: Defensive Programming / Consistency
- **File**: `internal/vault/manager.go:49-51`, `internal/vault/vault.go:76-78`
- **Problem**: Both `NewVaultManager` and `vault.New` accept `*slog.Logger` but silently fall back to `slog.Default()` when `nil` is passed. This is inconsistent with other code (e.g., `proxy.NewProxy` does not guard against nil logger). While safe (no data loss), a nil logger typically indicates a programming bug, and Go convention is to panic on nil required parameters.
- **Status**: Leave as-is. The nil guard is useful for testing convenience and doesn't cause correctness issues. Add a comment noting that `nil` logger uses `slog.Default()`.

---

### PR-104: `getCADir()` fallback to `/tmp` on Unix

- **ID**: PR-104
- **Category**: Security / Multi-user
- **File**: `cmd/agent/main.go:341-345`
- **Problem**: When both `PROGRAMDATA` and `UserHomeDir` are unavailable, `getCADir()` falls back to `filepath.Join(os.TempDir(), "qindu-ca")`. On multi-user Unix systems, `/tmp/qindu-ca` would be shared between all users, exposing the CA private key to other users. This is a theoretical concern — V1 targets Windows, and `os.UserHomeDir()` only fails in pathological cases (container without HOME, UID without passwd entry).
- **Fix for future sprints**: When porting to Linux, either reject startup with a clear error if no home directory is available, or use a per-user temp directory (`os.MkdirTemp`).

---

## Section 4: Excellence 🟢

### 🟢 `resolveCRLDP` — clean, defensive, handles all edge cases

**File**: `internal/tls/cert.go:109-131`

This function is a model of defensive programming:
- **Nil guard** (line 115): returns `nil` if `ca` is nil
- **Explicit CRLPath** (lines 118-119): uses the caller-provided path when set
- **Backward compatibility** (lines 125-128): falls back to `%PROGRAMDATA%` for old CAs
- **Empty env guard** (lines 126-127): returns `nil` when `PROGRAMDATA` is unset (CI/Unix) — no broken `file:///` URLs
- **No logging dependencies**: removed the previous `slog.Default()` call; the fallback is silent

The function has exactly one responsibility: resolve a CRL DP URL from a CA. It handles nil input, empty paths, missing environment variables, and backward compatibility — all in 22 lines.

### 🟢 Platform build-tag separation for crypto

**Files**: `internal/crypto/crypto_unix.go`, `internal/crypto/crypto_windows.go`, `internal/crypto/crypto_unix_test.go`

The extraction of `validateKeyFilePermissions` and `checkFileMode` into build-tagged files is idiomatic Go. Key design decisions:
- Unix: strict 0600 enforcement — hard rejection for wide permissions
- Windows: no-op — relies on directory ACLs, not POSIX modes (which Go's `os.Chmod` doesn't properly support on Windows)
- Test file gated with `//go:build !windows` — the three cross-platform test failures from the QEMU report (§8) are eliminated at the source

This is the correct approach: platform differences are resolved at compile time, not at runtime via `runtime.GOOS` checks.

### 🟢 `TestCreateUserVault_ReopenExisting` — genuine integration test for data survivorship

**File**: `internal/vault/manager_test.go:313-346`

This test creates a vault, writes data, calls `v1.Close()`, then reopens via `createUserVault` again and verifies the data survives. It uses real disk I/O (bbolt flush + close + reopen) rather than mocking. This directly validates AC-1 (cross-session persistence) and exercises the exact scenario that matters for production: the proxy restarts, and previously-persisted tokens must be retrievable.

### 🟢 `TestGenerateLeafCert_CRLDP_Fallback` — tests the untestable

**File**: `internal/tls/cert_test.go:264-308`

This test explicitly exercises the `PROGRAMDATA` fallback path. When `PROGRAMDATA` is not set (CI/Linux), it gracefully skips CDP assertion with `t.Log(...)`. When set (Windows), it verifies the CRL filename appears in the CDP URL. This is well-designed testing that doesn't break in different environments.

---

## Section 5: Verdict

### ✅ **MERGE_READY**

**Rationale**:

1. **Zero critical bugs**: No panics, no data races, no security holes, no AC violations
2. **All tests pass with `-race`**: Every package (`crypto`, `vault`, `tls`, `session`, `policy`) builds and tests cleanly
3. **`go vet` clean**: Zero warnings
4. **All five previous critical/high findings are resolved**: each has been addressed with correct, idiomatic fixes
5. **Cross-platform test failures eliminated**: build-tag separation removes the three POSIX-mode tests from Windows builds
6. **Vault code is library-only**: `VaultManager` is not wired to the proxy binary — this is correct for the current sprint scope (enforce-mode wiring is QINDU-0009). The vault code is thoroughly unit-tested in isolation and ready for wiring.

**Non-blocking items for QINDU-0009**:
- Wire `VaultManager` into the proxy at connection time (DD-15 step 6)
- Consider extracting `CRLPath` from `CA` struct when adding new callers
- Update stale `setPlatformACL` comment in `crypto.go:168`

---

## Appendix: Qindu-Specific Security Checklist

| # | Check | Status |
|---|-------|--------|
| 1 | No PII in logs, errors, or test fixtures | ✅ PASS |
| 2 | No `InsecureSkipVerify` in production code paths | ✅ PASS — only in `mitm.go:82`, gated by explicit config `upstream_validation: "insecure"`, logged at WARN |
| 3 | Loopback-only bind | ✅ PASS — `config.go:125`: `ip.IsLoopback()` check rejects non-loopback |
| 4 | DPAPI before disk write | ✅ N/A — vault key uses AES file, not DPAPI; CA DPAPI untouched |
| 5 | Interceptor interface safety | ✅ N/A — no interceptor changes in this diff |
| 6 | Certificate cache has bounds | ✅ PASS — `CertCache` has `maxSize` (default 1000) with eviction |
| 7 | No hardcoded secrets, credentials, or keys | ✅ PASS — keys generated via `crypto/rand`, never hardcoded |
| 8 | Graceful shutdown drains connections | ✅ PASS — `proxy.WaitForShutdown` with 30s timeout |
| 9 | Config validation happens at startup | ✅ PASS — `LoadConfig` → `Validate()` called before proxy starts |
| 10 | No telemetry, analytics, tracking, or phone-home code | ✅ PASS |

## Appendix B: Resolution of QEMU Test Report Findings

| QEMU Finding | Status | Resolution |
|-------------|--------|------------|
| F1 (uninstaller leaves `ProgramData`) | Not in scope | MSI/WiX issue — addressed in installer build system, not Go code |
| F2 (uninstaller leaves vault files) | Not in scope | MSI/WiX issue — installer cleanup |
| F3 (vault path in service profile) | Resolved | `initVault()` removed from `proxy.go` — vault is library-only until QINDU-0009 |
| F4-F6 (cross-platform test failures) | Resolved | Platform build-tag separation — POSIX-mode tests gated to Unix only |

*End of peer review for QINDU-0008.*
