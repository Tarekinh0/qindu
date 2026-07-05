# Dev Notes — QINDU-0008 Fix Cycle 8

**Date**: 2026-07-04
**Author**: qindu-devsecops

---

## Overview

Three changes implemented in this fix cycle:

1. **WIX-005**: Fix hardcoded CRL Distribution Point path (prevents MITM TLS failures on non-C: Windows drives)
2. **Platform-specific crypto permission validation**: Split `validateKeyFilePermissions`/`checkFileMode` into build-tagged files (fixes false-positive test failures on Windows)
3. **Lazy per-user vault architecture**: Remove bootstrap `initVault()`, create `VaultManager` with idle eviction, platform-specific `createUserVault` with token impersonation on Windows

---

## Modified Files

### Change 1: WIX-005

| File | Change |
|------|--------|
| `internal/tls/ca.go` | Added `CRLPath string` field to `CA` struct |
| `internal/tls/ca_helper.go` | `CreateOrLoadCA` now accepts `crlPath string` parameter; sets `ca.CRLPath` on both new and loaded CAs |
| `internal/tls/cert.go` | Replaced hardcoded `file:///C:/ProgramData/Qindu/ca.crl` with `resolveCRLDP(ca)`. Added fallback using `%PROGRAMDATA%` with WARNING log for backward compatibility |
| `cmd/agent/proxy.go` | `initCA()` passes `filepath.Join(caDir, CRLFilename)` to `CreateOrLoadCA` |
| `cmd/agent/main.go` | `runCAInit()` sets `ca.CRLPath` after `GenerateCA()` returns |
| `internal/tls/cert_test.go` | Fixed two CRL DP tests: `TestGenerateLeafCert_RevocationExtensions` uses `ca.CRLPath` from temp dir; added `TestGenerateLeafCert_CRLDP_Fallback` for backward compat path. Added `strings` import |

### Change 2: Crypto Platform Split

| File | Change |
|------|--------|
| `internal/crypto/crypto.go` | Removed `validateKeyFilePermissions()` and `checkFileMode()` functions. Removed unused imports (`io/fs`, `runtime`). `loadOrCreateKey()` still calls `validateKeyFilePermissions()` — Go build tags select the right platform file |
| `internal/crypto/crypto_unix.go` | **NEW** — `//go:build !windows`. `validateKeyFilePermissions()` enforces exactly 0600 (hard rejection). `checkFileMode()` returns true/false based on actual mode bits |
| `internal/crypto/crypto_windows.go` | **NEW** — `//go:build windows`. `validateKeyFilePermissions()` returns nil (ACLs handle security). `checkFileMode()` always returns true (Windows mode bits unreliable) |
| `internal/crypto/crypto_test.go` | Removed `TestKeyFileCreatedWith0600` and `TestKeyFileRejectsWidePermissions` (moved to Unix-only file) |
| `internal/crypto/crypto_unix_test.go` | **NEW** — `//go:build !windows`. Contains the two permission tests that only make sense on Unix |

### Change 3: Lazy Per-User Vault

| File | Change |
|------|--------|
| `internal/session/lookup_windows.go` | Changed `OpenProcessToken` flags from `TOKEN_QUERY` to `TOKEN_QUERY|0x0004` (TOKEN_IMPERSONATE). Token is still closed in `resolvePathFromPID` |
| `internal/vault/create_windows.go` | **NEW** — `//go:build windows`. `createUserVault()` with impersonation: calls `ImpersonateLoggedOnUser` via raw `syscall.SyscallN` (not exported by `golang.org/x/sys/windows` v0.46.0), `defer RevertToSelf()`. All filesystem ops inside impersonation block |
| `internal/vault/create_unix.go` | **NEW** — `//go:build !windows`. `createUserVault()` — same logic without impersonation. Token param is `uintptr`, ignored |
| `internal/vault/manager.go` | **NEW** — `VaultManager` with `GetOrCreate()` (lazy vault creation with per-path serialization), `Shutdown()` (closes all vaults), idle eviction (30min default, 10min check interval). Handles nil logger. Contains standalone `redactHomePath()` |
| `internal/vault/manager_test.go` | **NEW** — Tests: GetOrCreate basic, cache hit, multi-user, concurrent dedup (10 goroutines), Shutdown, idle eviction, invalid path error, default/custom idle timeout, redactHomePath, createUserVault success/reopen |
| `cmd/agent/proxy.go` | Deleted `initVault()` function (170 lines). Added `createVaultManager()` (20 lines) which creates `VaultManager` (no vault at startup). Removed `vaultInst` references from shutdown error handling. Cleaned up imports (removed `bolt`, `crypto`, `session`, `context`, `strings`, `time`). Added `path/filepath` import for CRL path |

---

## Technical Choices and Rationale

### CRL Path (WIX-005)
- **On-disk format**: `file:///` + `filepath.ToSlash(crlPath)` — converts Windows backslashes to URL-standard forward slashes
- **Fallback**: Uses `%PROGRAMDATA%` + `\Qindu\ca.crl` with `slog.Default().Warn()`. Only triggers for old CAs created before this fix. The warning guides users to regenerate with `ca-init`
- **Default logger**: The fallback path uses `slog.Default()` instead of requiring a logger parameter. Acceptable trade-off — this is an edge case that triggers once per old-CA lifetime

### Crypto Platform Split
- **Build tags clean**: No `runtime.GOOS` checks in production code. Go compiler selects the right file at build time
- **Windows ACL philosophy**: `validateKeyFilePermissions` returns nil on Windows because `%LOCALAPPDATA%` already has restrictive ACLs. The previous `runtime.GOOS == "windows"` check in `crypto.go` was equivalent but now cleaner
- **Test isolation**: Permission tests moved to `_unix_test.go` with `//go:build !windows`. Windows CI won't see false-positives for 0666 vs 0600

### VaultManager
- **Per-path creation serialization**: `creating map[string]chan struct{}` — only one goroutine opens bbolt per path. Others wait on the channel and receive the cached result. This prevents bbolt file-locking timeouts under concurrent access
- **Idle eviction**: 30min default, 10min check interval. Chosen based on typical ChatGPT session duration + idle browsing
- **No bootstrap vault**: `createVaultManager()` returns a `VaultManager` with zero vaults. Per-connection `GetOrCreate()` wiring deferred to QINDU-0009
- **`uintptr` token param**: `GetOrCreate` uses `uintptr` for platform-agnostic token passing. On Windows, it's cast to `windows.Token` inside `create_windows.go`. On Unix, it's ignored

### Windows Impersonation
- **Raw syscall**: `golang.org/x/sys/windows` v0.46.0 does not export `ImpersonateLoggedOnUser` (it exports `ImpersonateSelf` and `RevertToSelf`). We define the `advapi32.dll` proc directly using `syscall.NewLazyDLL` + `syscall.SyscallN` — same pattern used in `lookup_windows.go`
- **`defer RevertToSelf()`**: At function top in the `if token != 0` block. Ensures impersonation never leaks past filesystem operations even on panic

---

## How to Test

### Quick verification
```bash
go build ./...
go vet ./...
go test -count=1 ./...
```

### Windows cross-compilation
```bash
GOOS=windows GOARCH=amd64 go build ./...
GOOS=windows GOARCH=amd64 go vet ./...
```

### VaultManager-specific tests
```bash
go test -v -run "VaultManager" ./internal/vault/
```

### CRL path test
```bash
go test -v -run "TestGenerateLeafCert_Revocation|TestGenerateLeafCert_CRLDP" ./internal/tls/
```

### Crypto permission tests (Unix only)
```bash
go test -v -run "TestKeyFileCreatedWith0600|TestKeyFileRejectsWidePermissions" ./internal/crypto/
# These are now build-tagged and only run on non-Windows
```

---

## Gaps and Remaining Risks

### QINDU-0009 scope
- **Per-connection vault wiring**: `VaultManager.GetOrCreate()` is built but not called from the proxy connection handler. The proxy handler (`handleCONNECT`) needs to call `LookupVaultPathForPort()` → `vm.GetOrCreate()` → pass vault to tokenizer. This is QINDU-0009 work
- **Token lifecycle**: Currently `resolvePathFromPID` closes the token before returning. For QINDU-0009, the token must stay open until vault creation is complete. Need to add a `LookupTokenForPort` helper that returns the token without closing it

### Known limitations
- **Eviction timing granularity**: Eviction loop runs every 10 minutes. Vaults idle for up to 40 minutes (30min timeout + 10min check interval) before cleanup
- **No vault key rotation**: Each user's `vault.key` is created once and persists
- **Uninstall cleanup**: Vault files in per-user profiles are not cleaned by uninstall. This is a separate UX concern (QINDU-0016)
- **LSP warning**: The LSP reports `undefined: windows.ImpersonateLoggedOnUser` on `[windows]` target. This is a false positive — the Windows build compiles correctly using the raw syscall approach

### Test coverage
- VaultManager tests run on all platforms (use `createUserVault` with `uintptr(0)` on Unix)
- Windows impersonation-specific code path cannot be unit-tested on Linux — requires Windows VM integration test (QINDU-qemu-tester)
- CRL DP fallback test: covers the code path but cannot verify actual `%PROGRAMDATA%` resolution on Linux

---

## Files Not Modified
- `docs/implementation/sprints/QINDU-0008/dev-notes.md` — unchanged (this is a new file)
- `internal/proxy/proxy.go` — unchanged (per-connection vault wiring is QINDU-0009)
- `internal/tokenize/` — unchanged
- `configs/default.yaml` — unchanged
- `go.mod`, `go.sum` — no dependency changes needed
