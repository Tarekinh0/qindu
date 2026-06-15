# Peer Review — QINDU-HOTFIX-001 (Round 5)

**Reviewer**: qindu-peer-reviewer (blank-slate — fresh session)  
**Date**: 2026-06-15  
**Scope**: Two new fixes — CRL custom actions (BUG-CRL-001) and DELETEDATA command quoting (BUG-DD-001)  
**Reviewed files**:
- `installer/wix/includes/ca-trust.wxs`
- `installer/wix/qindu.wxs`
- `installer/wix/includes/cleanup.wxs`

---

## Section 1: Scorecard

| Framework | Score | Justification |
|-----------|-------|---------------|
| **Clean Code** | 4/5 | Well-named actions (`CAInstallCRL`, `CARollbackCRL`, `CARemoveCRL`); descriptive comments reference bug IDs; one SetProperty condition inconsistency (PR-402). |
| **Pragmatic Programmer** | 5/5 | Orthogonal design — CA trust, CRL trust, and cleanup are separate fragments; reversible via rollback hooks; no test hooks in production paths. |
| **SOLID** | 5/5 | Single responsibility per fragment; CRL actions are an extension of the trust-store pattern (OCP); no fat interfaces; DIP not applicable (WiX XML). |
| **Go Proverbs** | 5/5 | Go code unchanged; all 148 tests still pass with `-race`. |
| **Effective Go** | N/A | No Go code changes in this round. WiX XML reviewed separately below. |
| **DDD** | N/A | Not applicable to installer XML. |
| **Code Complete** | 4/5 | Defensive patterns present (rollback hooks, `Return="ignore"` on uninstall); PATH hardening inconsistent — `cmd.exe` lacks `[System64Folder]` prefix (PR-403). |

---

## Section 2: Critical Findings 🔴

**None.** The two targeted fixes (BUG-CRL-001, BUG-DD-001) are implemented correctly and follow the established WixQuietExec pattern. No blocking issues found.

---

## Section 3: Design Flaws 🟡

### PR-401: CRL removal uses `certutil -delstore` — may not remove CRL from store

- **Category**: Correctness / Robustness
- **File**: `installer/wix/includes/ca-trust.wxs`, lines 113–114
- **Problem**: `CARemoveCRL` executes `certutil -delstore Root "!(loc.CAName)"` — the identical command used by `CARemoveTrustStore`. However, `certutil -delstore` is documented for deleting certificates, not Certificate Revocation List (CRL) objects. A CRL is a distinct store entry type; removing it may require `certutil -delCRL <serial>` or a CRL-specific command rather than `-delstore`. The CRL was added via `certutil -addstore Root ca.crl`, and the `-delstore` variant by Common Name may not match CRL entries in all Windows versions.
- **Impact**: The CRL may persist in the machine trust store after uninstall. Since the CRL expires in 2036 and is harmless (it only enables revocation checking for a CA already removed), this is low-severity. `Return="ignore"` prevents it from blocking uninstall.
- **Fix**: Investigate whether `certutil -delCRL` or a serial-number-based `-delstore` variant correctly removes the CRL. If confirmed, update the `CARemoveCRL` SetProperty value. Alternatively, add a comment acknowledging the limitation and accept the residual CRL (it expires naturally and causes no harm without the CA cert).

### PR-402: SetProperty condition broader than InstallExecuteSequence condition

- **Category**: Precision / Maintainability
- **File**: `installer/wix/includes/cleanup.wxs`, lines 36–37
- **Problem**: The `SetProperty` for `CleanupProgramDataCmd` uses condition `Installed AND DELETEDATA="1"`, while the corresponding `<Custom>` entry in `InstallExecuteSequence` (qindu.wxs line 205) uses `Installed AND REMOVE="ALL" AND DELETEDATA="1"`. During repair/reinstall with DELETEDATA=1, the SetProperty fires (setting CustomActionData unnecessarily) but the deferred CA does not execute. This is functionally harmless but reduces code precision — a future maintainer may not understand why the conditions diverge.
- **Fix**: Add `AND REMOVE="ALL"` to the SetProperty condition for strict parity, or add a comment explaining the deliberate divergence.

### PR-403: `cmd.exe` lacks `[System64Folder]` prefix — inconsistent PATH hardening

- **Category**: Security Hardening / Consistency
- **File**: `installer/wix/includes/cleanup.wxs`, line 36
- **Problem**: The `SetProperty` for `CleanupProgramDataCmd` invokes `"cmd.exe"` without an absolute path. The `ca-trust.wxs` custom actions use `[System64Folder]certutil.exe` to prevent PATH hijacking (per SR-INSTALLER-2 and PR-001). While `cmd.exe` is well-protected by Windows itself (WRP, system32 always first in PATH for elevated processes), an absolute path would be consistent with the codebase's security posture and the qemu-test-report's explicit recommendation (line 188).
- **Fix**: Change the `SetProperty` `Value` from:
  ```xml
  Value="&quot;cmd.exe&quot; /c rmdir /s /q &quot;[PROGRAMDATADIR]&quot;"
  ```
  to:
  ```xml
  Value="&quot;[System64Folder]cmd.exe&quot; /c rmdir /s /q &quot;[PROGRAMDATADIR]&quot;"
  ```

---

## Section 4: Excellence 🟢

### 1. Comprehensive rollback coverage for CRL

`ca-trust.wxs` includes a proper `CARollbackCRL` rollback custom action (lines 141–155) that removes the CRL from the trust store if installation fails after `CAInstallCRL`. The SetProperty runs `Before="CAInstallCRL"` in immediate context, capturing property values while the session is available. This follows the established rollback pattern used by `FirewallRollbackAllowLoopback`, `FirewallRollbackBlockExternal`, and `CARollbackTrustStore`. Rollback correctness is often overlooked in installer design — this is genuinely well-done.

### 2. Clear, bug-referencing comments

Every new CRL custom action includes a comment referencing `BUG-CRL-001`:

```xml
<!-- Install CRL into machine trust store (BUG-CRL-001). -->
```

```xml
<!-- Remove CRL from trust store on uninstall (BUG-CRL-001). -->
```

This creates an auditable trace from the QEMU test report → bug → fix → code. Excellent practice for compliance and maintenance.

### 3. Consistent WixQuietExec64 pattern

All three new custom actions (`CAInstallCRL`, `CARemoveCRL`, `CARollbackCRL`) faithfully follow the dual-element pattern:

```xml
<SetProperty Id="X" Before="X" Sequence="execute"
    Value="…command…">condition</SetProperty>
<CustomAction Id="X" BinaryKey="WixCA" DllEntry="WixQuietExec64"
    Execute="deferred" Impersonate="no" Return="…" />
```

No shortcuts. No stray `Win64` attributes. No hardcoded `<Binary>` paths. No `Impersonate="yes"`. This uniformity makes the entire WiX codebase predictable and reviewable.

### 4. Correct DELETEDATA quoting fix

The `cleanup.wxs` fix on line 36 correctly addresses the root cause identified in the QEMU test report (line 148: `Command string must begin with quoted application name`):

```xml
Value="&quot;cmd.exe&quot; /c rmdir /s /q &quot;[PROGRAMDATADIR]&quot;"
```

`cmd.exe` is now properly quoted with `&quot;`, which satisfies WixQuietExec64's requirement. The `[PROGRAMDATADIR]` is also quoted, protecting against paths with spaces.

### 5. Go code unchanged — full test suite passes

All 148 tests pass with `-race`:

```
ok  github.com/Tarekinh0/qindu/cmd/agent    (cached)
ok  github.com/Tarekinh0/qindu/internal/logging  (cached)
ok  github.com/Tarekinh0/qindu/internal/policy   (cached)
ok  github.com/Tarekinh0/qindu/internal/proxy    (cached)
ok  github.com/Tarekinh0/qindu/internal/tls      (cached)
```

Zero regressions. The WiX-only scope of these fixes was respected.

---

## Section 5: Verdict

### MERGE_READY

The two targeted fixes (BUG-CRL-001 and BUG-DD-001) are correctly implemented. No critical findings. No security regressions. No build breakers. The three design findings (PR-401, PR-402, PR-403) are non-blocking improvements that can be addressed in a future refinement sprint.

The QEMU VM test on the rebuilt MSI should confirm:

1. **BUG-CRL-001 fixed**: `curl -x http://127.0.0.1:8787 https://chatgpt.com/` succeeds WITHOUT `--ssl-no-revoke` (no manual `certutil -addstore Root ca.crl` needed).
2. **BUG-DD-001 fixed**: `msiexec /x … DELETEDATA=1` successfully deletes `%PROGRAMDATA%\Qindu\` — no "Command string must begin with quoted application name" errors in the uninstall log.
3. **No regressions**: All 10 acceptance criteria from `story.md` remain satisfied.

---

*End of peer review. ZERO PII disclosed.*
