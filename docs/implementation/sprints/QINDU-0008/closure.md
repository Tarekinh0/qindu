# Sprint Closure — QINDU-0008: Vault local chiffré

**Date**: 2026-07-05
**Arbiter**: qindu-orchestrator

## Final Verdict: PASS

## Review Chain

| Gate | Reviewer | Verdict |
|------|----------|---------|
| Peer Review (round 1) | qindu-peer-reviewer | FIX_AND_RESUBMIT (PR-001 through PR-005) |
| DevSecOps (fix cycle) | qindu-devsecops | All 5 blocking bugs fixed |
| Peer Review (round 2) | qindu-peer-reviewer | MERGE_READY |
| QEMU Test | qindu-qemu-tester | PASS |
| Security Review | qindu-ciso | PASS |
| Privacy Review | qindu-dpo | PASS |
| Quality Review | qindu-qa | PASS |
| Release Review | qindu-release | PASS |

## Changes Delivered

1. **WIX-005**: CRL Distribution Point path no longer hardcoded — uses `ca.CRLPath` with `%PROGRAMDATA%` fallback
2. **Crypto platform split**: `crypto_unix.go` (0600 enforcement) and `crypto_windows.go` (no-op) via build tags — DD-7 reversed
3. **Lazy vault architecture**: `initVault()` removed, `VaultManager` with per-path creation serialization and idle eviction, platform-specific `createUserVault` (token impersonation on Windows)
4. **Phantom vault eliminated**: No vault created at startup — QEMU confirms `C:\Windows\ServiceProfiles\LocalService\AppData\Local\Qindu\` is gone

## Deferred to QINDU-0009

- Per-connection `VaultManager.GetOrCreate()` wiring in proxy handler
- Token lifecycle for vault creation (token must outlive `resolvePathFromPID`)

## Non-Blocking Items for Future Sprints

- Key shredding on erasure (CISO F-002)
- `/tmp` CA fallback removal for Unix (DPO)
- Authenticode signing, SBOM, SLSA provenance (Release)
- Stale comment cleanup at `crypto.go:168` (QA)
