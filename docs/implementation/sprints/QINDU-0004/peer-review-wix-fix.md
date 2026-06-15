# Peer Review — WiX Installer Source Fix

**Reviewer**: qindu-peer-reviewer
**Date**: 2026-06-15
**Subject**: Uncommitted WiX installer source fixes (root element, namespace, structural, and CI changes)
**Sprint**: QINDU-0004 (follow-up fix cycle)

---

## 1. Scorecard

| Framework | Score | Justification |
|-----------|-------|---------------|
| **Clean Code** | 4/5 | Diffractal changes are minimal and focused. Build comment slightly outdated (see PR-100). |
| **Pragmatic Programmer** | 4/5 | Fixes are orthogonal — root element change in 8 files, namespace fix in 1, structural fix in 1, CI fix in 1. No cross-cutting coupling. |
| **SOLID** | N/A | XML schema fix — SOLID principles don't meaningfully apply to WiX source. |
| **Go Proverbs** | N/A | No Go code changed. |
| **Effective Go** | N/A | No Go code changed. `go vet` / `go fmt` confirmed clean by DevSecOps. |
| **DDD** | N/A | No bounded context changes. Include files are already domain-aligned (ca-trust, firewall, dialogs, etc.). |
| **Code Complete** | 4/5 | Good defensive practices — isolated changes, no magic strings, validation via grep/xmllint documented. One command missing a required flag (PR-001). |

---

## 2. Critical Findings 🔴

### PR-001 — `light` command missing `-ext WixUtilExtension`

- **File**: `.github/workflows/ci.yml`, line 211
- **Severity**: **CRITICAL**
- **Problem**:

  The `candle` (compile) step on line 210 correctly passes both extensions:
  ```
  candle qindu.wxs -dProductVersion=%VERSION% -ext WixUtilExtension -ext WixUIExtension
  ```

  However, the `light` (link) step on line 211 only passes `-ext WixUIExtension`:
  ```
  light qindu.wixobj -out Qindu-Installer-x64.msi -cultures:en-us -loc locale/en-us.wxl -ext WixUIExtension
  ```

  In WiX v3, `light` requires **every** extension used at compile time to also be specified at link time. The extension DLL provides:
  1. Table schema definitions (for `WixUtilRemoveFolderEx`)
  2. Custom action binary (`WixUtilCA.dll`) to embed in the MSI Binary table
  3. Custom action row generation and scheduling logic

  Without `-ext WixUtilExtension`, `light` will fail with a link-time error such as:
  ```
  light.exe : error LGHT0094: Unresolved reference to symbol ...
  ```
  or
  ```
  light.exe : error LGHT0103: The database contains an unknown table 'WixUtilRemoveFolderEx'.
  ```

- **Fix**: Add `-ext WixUtilExtension` to the `light` command. The corrected line should be:

  ```
  light qindu.wixobj -out Qindu-Installer-x64.msi -cultures:en-us -loc locale/en-us.wxl -ext WixUtilExtension -ext WixUIExtension
  ```

  **Order note**: The order of `-ext` flags to `light` does not matter. However, for consistency with the `candle` command on line 210, keep `WixUtilExtension` before `WixUIExtension`.

---

## 3. Design / Quality Issues 🟡

### PR-100 — Build comment in `qindu.wxs` doesn't list `light` extension flags

- **Category**: Documentation / Maintainability
- **File**: `installer/wix/qindu.wxs`, line 9
- **Problem**:

  The build comment (lines 7–9) documents the build incantation:
  ```
  candle qindu.wxs -dProductVersion=0.1.0 -ext WixUtilExtension -ext WixUIExtension
  light qindu.wixobj -out Qindu-Installer-x64.msi -cultures:en-us -loc locale/en-us.wxl
  ```

  The `light` line is missing **both** `-ext WixUIExtension` and `-ext WixUtilExtension`. The CI workflow (line 211) already has `-ext WixUIExtension` on `light` but not `-ext WixUtilExtension` (see PR-001). The build comment serves as the canonical reference for anyone building locally — it should be accurate.

- **Fix**: Update line 9 to:
  ```
  light qindu.wixobj -out Qindu-Installer-x64.msi -cultures:en-us -loc locale/en-us.wxl -ext WixUtilExtension -ext WixUIExtension
  ```

### PR-101 — Trailing blank lines after `</Feature>` removal

- **Category**: Minor / Style
- **File**: `installer/wix/qindu.wxs`, lines 90–91
- **Problem**:

  After removing the duplicate `<UI Id="QinduUI">` block (previously at lines 91–96), two blank lines remain between `</Feature>` and the `<Property>` comments. While not a build error, this is vestigial whitespace that creates a visual gap suggesting something was removed. Eliminating one blank line would tighten the structure.

- **Fix**: Delete one of the two blank lines (line 91), leaving a single blank line between `</Feature>` and the `<!-- UNSAFE_CA ... -->` comment block.

---

## 4. Verification of Changes 🟢

The following structural checks pass for all modified files:

### 4.1 Root element correctness

| File | Root element | Correct? |
|------|-------------|----------|
| `qindu.wxs` (main) | `<Wix>` | ✅ Correct — main `.wxs` files use `<Wix>` |
| `includes/ca-trust.wxs` | `<Include>` | ✅ Correct — include files use `<Include>` |
| `includes/cleanup.wxs` | `<Include>` | ✅ Correct |
| `includes/dialogs.wxs` | `<Include>` | ✅ Correct |
| `includes/files.wxs` | `<Include>` | ✅ Correct |
| `includes/firewall.wxs` | `<Include>` | ✅ Correct |
| `includes/registry-chrome.wxs` | `<Include>` | ✅ Correct |
| `includes/registry-edge.wxs` | `<Include>` | ✅ Correct |
| `includes/service.wxs` | `<Include>` | ✅ Correct |

### 4.2 Namespace declarations

- `xmlns="http://schemas.microsoft.com/wix/2006/wi"` — present on all `<Wix>` and `<Include>` roots. Correct WiX v3 namespace URI.
- `xmlns:util="http://schemas.microsoft.com/wix/UtilExtension"` — present only on `cleanup.wxs` `<Include>`. Correct scoping — only `cleanup.wxs` uses `util:`-prefixed elements.

### 4.3 `util:RemoveFolderEx` — namespace prefix applied

All four occurrences in `cleanup.wxs` correctly use the `util:` prefix:
- Line 29: `<util:RemoveFolderEx Id="CleanupProgramDataDirEx" ...>`
- Line 31: `</util:RemoveFolderEx>`
- Line 41: `<util:RemoveFolderEx Id="CleanupInstallDirEx" ... />`

### 4.4 `Dialog` nesting under `<UI>`

All three `Dialog` elements (`QinduNoticeDlg`, `QinduOptionsDlg`, `QinduUninstallDlg`) are direct children of `<UI Id="QinduUI">` in `dialogs.wxs` (lines 44, 67, 93). This matches the WiX v3 XSD content model: `UI` permits `Dialog` as a child; `Fragment` does not.

### 4.5 Duplicate `<UI Id="QinduUI">` eliminated

`grep -rn "UI.*QinduUI" installer/wix/ .github/workflows/` returns exactly one match: `dialogs.wxs:28`. The duplicate in `qindu.wxs` (previously lines 91–96) has been fully removed. No link-time duplicate symbol error will occur.

### 4.6 CI `candle` command updated

Line 210 of `ci.yml` now reads:
```
candle qindu.wxs -dProductVersion=%VERSION% -ext WixUtilExtension -ext WixUIExtension
```
This matches the documented build command in `qindu.wxs` line 8. Both extensions are present.

---

## 5. Excellence 🟢

### File: `cleanup.wxs` — clean namespace and prefix application

The fix to `cleanup.wxs` is well-executed:
- The `xmlns:util` declaration is on the `<Include>` root (line 2), exactly where a reader expects to find all namespace declarations.
- The `util:` prefix is applied consistently to both the parenthetical element (lines 29–31) and the self-closing element (line 41).
- Comments correctly document that `RemoveFolderEx` is an API-level call, eliminating command-injection risk (unlike the previous `cmd.exe /c rmdir` approach).

### Specific, surgical changes

The diff touches exactly what it needs to and nothing else. All 10 modified files receive minimal, targeted changes:
- 8 include files: root element swap only (+ namespace declaration on 1 file)
- `qindu.wxs`: removed duplicate UI block + updated build comment
- `ci.yml`: added `-ext WixUtilExtension` to candle

No refactoring creep, no unrelated reformatting. This is disciplined diff hygiene.

---

## 6. Verdict

**FIX_AND_RESUBMIT**

### Rationale

PR-001 is a build-breaking defect: the `light` (MSI linker) step in CI is missing `-ext WixUtilExtension`, which is required to resolve `util:RemoveFolderEx` table entries and embed the `WixUtilCA.dll` custom action binary. Without this flag, the MSI build will fail at link time with an unresolved symbol or unknown table error.

### Required fix

One line change in `.github/workflows/ci.yml` (line 211):

```diff
-          light qindu.wixobj -out Qindu-Installer-x64.msi -cultures:en-us -loc locale/en-us.wxl -ext WixUIExtension
+          light qindu.wixobj -out Qindu-Installer-x64.msi -cultures:en-us -loc locale/en-us.wxl -ext WixUtilExtension -ext WixUIExtension
```

### Recommended (non-blocking)

Update the `light` build comment in `qindu.wxs` line 9 to include both extension flags (PR-100), and clean up the trailing blank line after `</Feature>` (PR-101).

---

*End of review.*
