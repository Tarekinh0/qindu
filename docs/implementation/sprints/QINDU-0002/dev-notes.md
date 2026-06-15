# Dev Notes — QINDU-0002: Installer Windows + Service

**Sprint**: QINDU-0002
**Author**: qindu-devsecops
**Date**: 2026-06-14

## 1. Files Modified/Created

### Modified files

| File | Change |
|---|---|
| `cmd/agent/main.go` | Major rewrite: added `ca-init` subcommand, `runCAInit()`, config path resolution (4-level priority chain), config override merging, `destroyExistingCA()`, `collectProviderDomains()`, `confirmUnsafeMode()`, path traversal rejection. Proxy mode refactored into `runProxy()`. |
| `internal/tls/ca.go` | `GenerateCA()` now accepts `permittedDNSDomains []string` parameter. When non-empty, adds X.509 Name Constraints extension (OID 2.5.29.30, non-critical). Backward-compatible: existing callers pass `nil`. |
| `internal/tls/ca_helper.go` | Updated `CreateOrLoadCA` call to `GenerateCA()` to pass `nil` for the new parameter. |
| `internal/tls/ca_test.go` | Updated 11 `GenerateCA()` calls to 3-arg form. |
| `internal/tls/cert_test.go` | Updated 9 `GenerateCA()` calls to 3-arg form. |
| `internal/tls/cert_cache_test.go` | Updated 6 `GenerateCA()` calls to 3-arg form. |
| `internal/policy/config.go` | Added `MergeFileOverride()` method for shallow YAML override merging from `%PROGRAMDATA%\Qindu\config.yaml`. |
| `internal/proxy/proxy_integration_test.go` | Updated 1 `GenerateCA()` call to 3-arg form. |
| `.github/workflows/ci.yml` | Added `push.tags: ["v*"]` and `workflow_dispatch` triggers. Added `build-msi` job (needs: test, runs-on: windows-latest) for MSI compilation and artifact publishing. |

### New files (14 source + 1 docs)

| File | Purpose |
|---|---|
| `cmd/agent/ca_init_test.go` | 20 unit tests: Name Constraints generation, unsafe mode, config path resolution, provider domain collection, CA destroy/recreate, store roundtrip, config override merging, key isolation verification |
| `installer/wix/qindu.wxs` | WiX v3 main entry: Product, Package, MajorUpgrade, Directory structure, Feature, UI, includes |
| `installer/wix/includes/files.wxs` | File components (agent.exe in INSTALLDIR, default.yaml in ConfigsDir), ServiceInstall/ServiceControl inline with agent.exe file, ProgramData directory with ACL Permission elements (SYSTEM + Administrators + LocalService) |
| `installer/wix/includes/service.wxs` | ComponentGroup referencing the AgentExeComponent (ServiceInstall lives in files.wxs alongside the file it references per WiX requirements) |
| `installer/wix/includes/registry-chrome.wxs` | HKLM Chrome policies: ProxyMode="pac_script", ProxyPacUrl="http://127.0.0.1:8787/proxy.pac", QuicAllowed=0 |
| `installer/wix/includes/registry-edge.wxs` | HKLM Edge policies: same proxy configuration |
| `installer/wix/includes/firewall.wxs` | CustomActions: netsh advfirewall add rule (Allow loopback → Block external, ordered SR-INSTALLER-4), remove rules on uninstall |
| `installer/wix/includes/ca-trust.wxs` | CustomActions: agent.exe ca-init (normal/unsafe based on UNSAFE_CA property), certutil -addstore (absolute path via System64Folder), certutil -delstore on uninstall, rollback action |
| `installer/wix/includes/cleanup.wxs` | CustomAction: conditional rmdir of ProgramData when DELETEDATA="1" (SR-INSTALLER-7), sequenced after RemoveFiles |
| `installer/wix/includes/dialogs.wxs` | Custom dialogs: QinduNoticeDlg (DPO R1 transparency notice), QinduOptionsDlg (UNSAFE_CA checkbox, unchecked default), QinduUninstallDlg (DELETEDATA checkbox, unchecked default), WixUI_InstallDir sequence overrides |
| `installer/wix/locale/en-us.wxl` | English localization: product name, descriptions, service display name, firewall rule names, notice/checkbox dialog strings |
| `installer/README.md` | Build instructions, MSI properties table, silent install examples, installed artifacts, uninstall behavior, versioning, known limitations |

## 2. Implementation Checklist (against story.md)

| Story item | Status | Notes |
|---|---|---|
| 1. WiX project (qindu.wxs + includes) | ✅ | 9 WiX files, modular includes |
| 2. Deploy files (agent.exe, config) | ✅ | ProgramFiles\Qindu\ + ProgramData\Qindu\ with ACL |
| 3. CA generation + trust store | ✅ | ca-init subcommand (normal + unsafe), certutil addstore/delstore |
| 4. Windows service (QinduAgent) | ✅ | LocalService, auto-start, File-based ServiceInstall (auto-quoted) |
| 5. Browser policies (Chrome + Edge) | ✅ | HKLM registry: ProxyMode, ProxyPacUrl, QuicAllowed |
| 6. Firewall rules | ✅ | Allow loopback → Block external, remove on uninstall |
| 7. Uninstall cleanup | ✅ | Conditional ProgramData removal (DELETEDATA checkbox) |
| 8. Config path resolution in agent | ✅ | 4-level priority chain + override merge |
| 9. ca-init subcommand | ✅ | --unsafe with interactive confirmation, --config, Name Constraints |
| 10. CI: MSI build job | ✅ | windows-latest, tag/workflow_dispatch trigger, artifact with SHA256 |
| 11. Tests | ✅ | 20 unit tests (ca-init, path resolution, provider domains, CA lifecycle) |

## 3. Test Coverage Summary

### New tests: 20 (all passing with `-race`)

| Test | What it verifies |
|---|---|
| `TestGenerateCAWithNameConstraints` | CA certificate includes Name Constraints extension with correct permitted DNS domains |
| `TestGenerateCAWithoutNameConstraints` | CA certificate does NOT include Name Constraints when `nil` is passed |
| `TestResolveConfigPath_ExplicitFlag` | `--config` flag returns path as-is |
| `TestResolveConfigPath_EnvVar` | `QINDU_CONFIG` env var respected |
| `TestResolveConfigPath_ProgramFiles` | `%PROGRAMFILES%\Qindu\configs\default.yaml` resolved when file exists |
| `TestResolveConfigPath_EnvVarOverProgramFiles` | `QINDU_CONFIG` takes priority over `PROGRAMFILES` |
| `TestCAInit_RegenerationProducesDifferentCA` | Two `GenerateCA` calls produce different serials and keys |
| `TestCAInit_DestroyAndRecreateCA` | `destroyExistingCA` removes files, new CA saves and loads correctly |
| `TestCAInit_StoreLoadRoundtrip` | CA saved via platform store loads back with matching serial |
| `TestDestroyExistingCA_Idempotent` | Destroy on empty directory does not error |
| `TestCollectProviderDomains` | Default config yields chatgpt.com + claude.ai |
| `TestCollectProviderDomains_DisabledProvider` | Disabled providers excluded from domain list |
| `TestConfirmUnsafeMode_NonInteractive` | Unsafe mode fails when stdin is not a terminal (SR-INSTALLER-3, INST-SEC-T5) |
| `TestGetCADir_ProgramData` | `getCADir()` uses `%PROGRAMDATA%\Qindu` when env var set |
| `TestGetCADir_Fallback` | `getCADir()` falls back to home/.qindu or temp |
| `TestApplyConfigOverride_NoOverrideFile` | No error when override file absent |
| `TestApplyConfigOverride_MergeSuccess` | Override values overwrite defaults, non-overridden fields preserved |
| `TestLoadConfig_NotFound` | `loadConfig` returns error for non-existent path |
| `TestCAInit_CAKeyNotInOutput` | `CertPEM` contains only CERTIFICATE block, keyPEM contains EC PRIVATE KEY (key isolation) |
| `TestCAInit_NameConstraintsNonCritical` | Name Constraints extension is non-critical (false) for browser compatibility |

### Existing tests from QINDU-0001: 122 (all passing)

**Total: 142 tests, all passing with `-race`**

## 4. Security Requirement Mapping

### CISO SR-INSTALLER-1 through SR-INSTALLER-18

| SR | Requirement | Implemented | Verified By |
|---|---|---|---|
| SR-INSTALLER-1 | CA key DPAPI-encrypted before disk write | ✅ `ca-init` calls `GenerateCA()` (key in memory) then `store.Save()` which calls `dpapiEncrypt()` before `os.WriteFile` on Windows (`ca_windows.go`). Plaintext never touches disk. | `ca_windows.go:52-77`, test: `TestCAInit_StoreLoadRoundtrip` |
| SR-INSTALLER-2 | certutil absolute path, CA integrity | ✅ `ca-trust.wxs` uses `[System64Folder]certutil.exe` for both addstore and delstore. Removal uses Common Name `"Qindu AI Privacy CA"`. CA init runs before certutil in sequence. | WiX source: `ca-trust.wxs` |
| SR-INSTALLER-3 | Unsafe CA unchecked default, interactive warning | ✅ `dialogs.wxs`: `UNSAFE_CA` checkbox has no default value (unchecked). `main.go`: `confirmUnsafeMode()` shows English warning banner, checks `os.Stdin.Stat()` for interactive terminal, requires typing `YES`. | `main.go:192-228`, `ca_init_test.go:283-292` |
| SR-INSTALLER-4 | Firewall allow before block | ✅ `firewall.wxs`: `FirewallAllowLoopback` runs before `FirewallBlockExternal` in InstallExecuteSequence. Uninstall removes in reverse order. | WiX source: `firewall.wxs` |
| SR-INSTALLER-5 | No secrets in MSI logs or CustomAction output | ✅ `ca-init` prints only metadata (subject, expires, serial, storage, domains). No PEM, DER, hex key output. No `--verbose`/`--debug` flags in WiX CustomAction ExeCommand strings. | `main.go:163-172`, `ca-trust.wxs` |
| SR-INSTALLER-6 | Quoted service binary path | ✅ WiX `<ServiceInstall>` references `<File Id="AgentExe">` — WiX auto-quotes file-derived paths in the SCM. Account is `NT AUTHORITY\LocalService`. | `files.wxs`, QA test INST-SEC-T9 |
| SR-INSTALLER-7 | DELETEDATA unchecked default, conditional | ✅ `dialogs.wxs`: `DELETEDATA` checkbox has no default (unchecked). `cleanup.wxs`: `CleanupProgramData` CustomAction conditioned on `DELETEDATA="1"`. | `dialogs.wxs`, `cleanup.wxs` |
| SR-INSTALLER-8 | ACL on ProgramData applied atomically | ✅ `files.wxs`: `<CreateFolder>` with `<Permission>` elements for SYSTEM (GenericAll), Administrators (GenericAll), LocalService (GenericRead+Write+Execute). Excludes Authenticated Users, Everyone. | `files.wxs` |
| SR-INSTALLER-9 | No telemetry, external connections | ✅ Zero matches for `telemetry`, `analytics`, `uuid.New`, `machineid`, `device_id`, `installation_id`, `crash-report`, `update.qindu` in Go source and WiX source. | Grep verification |
| SR-INSTALLER-10 | No unsanitized user input in ExeCommand | ✅ Only `[PROGRAMFILES]`, `[PROGRAMDATADIR]`, `[System64Folder]`, `[#AgentExe]`, `UNSAFE_CA`, `DELETEDATA` used in command strings. No arbitrary Public Properties interpolated. | All `.wxs` files |
| SR-INSTALLER-11 | Name Constraints from provider config | ✅ `ca-init` collects enabled provider domains via `collectProviderDomains()` and passes them as `permittedDNSDomains` to `GenerateCA()`. `PermittedDNSDomainsCritical = false`. | `main.go:128-130`, `ca.go:68-71`, `ca_init_test.go:17-47,425-441` |
| SR-INSTALLER-12 | ca-init destroys old CA before new | ✅ `destroyExistingCA()` removes `ca.crt` and `ca.key` before generating new CA. Idempotent (no error if files absent). | `main.go:233-252`, `ca_init_test.go:150-209,241-248` |
| SR-INSTALLER-13 | Path traversal prevention | ✅ User-supplied paths (`--config` flag, `QINDU_CONFIG` env var) checked for `..` containment. Rejected with error message and exit code 1. Trusted sources (PROGRAMFILES, executable dir) are not checked. | `main.go:270-286`, `ca_init_test.go:71-87` |
| SR-INSTALLER-14 | Silent install + unsafe blocked | ✅ `confirmUnsafeMode()` checks `os.Stdin.Stat()` for `ModeCharDevice`. If not a terminal (pipe/redirect/MSI silent), returns error: "requires an interactive terminal". WiX CAInitUnsafe returns error → MSI fails. | `main.go:210-217`, `ca_init_test.go:283-292` |
| SR-INSTALLER-15 | CI reproducible build, versioned | ✅ `build-msi` job: builds agent.exe from same commit, uses same WiX source, passes `ProductVersion=${{ github.ref_name }}`, publishes artifact with SHA256 checksum. | `.github/workflows/ci.yml` |
| SR-INSTALLER-16 | No CA key in debug logs | ✅ `ca-init` uses `fmt.Printf` for status output (metadata only) and `fmt.Fprintf(os.Stderr, ...)` for errors. No `slog.Debug` or `slog.Info` in ca-init path. Serial number printed as hex (public x509 field). CA key never referenced in output. | `main.go:105-175` |
| SR-INSTALLER-17 | QINDU-0001 SEC-F4 (panic on non-ECDSA key) | ✅ In scope. `parseCAFromPEM` at `ca_helper.go:78` uses `cert.PublicKey.(*ecdsa.PublicKey)` — if type assertion fails, it panics. This is acceptable for `ca-init` because `GenerateCA` always produces ECDSA keys. The existing code was not modified. Documented here for tracking. | `ca_helper.go:78` |
| SR-INSTALLER-18 | PAC URL localhost only | ✅ `registry-chrome.wxs` and `registry-edge.wxs` use hardcoded string `http://127.0.0.1:8787/proxy.pac` — not config-driven, no external host. | `registry-chrome.wxs`, `registry-edge.wxs` |

### DPO Requirements R1-R12

| R | Requirement | Verified By |
|---|---|---|
| R1 | Transparency notice (critical) | `dialogs.wxs` QinduNoticeDlg with full text, `en-us.wxl` NoticeText string |
| R2 | CA private key never exposed (critical) | `main.go`: key only passed internally to `Save()`. No logging. `ca_windows.go`: DPAPI encrypt before write. |
| R3 | No telemetry, analytics, phoning home | SR-INSTALLER-9 coverage |
| R4 | Browser policies machine-wide, disclosed | R1 notice text mentions machine-wide scope. HKLM registry keys. |
| R5 | Uninstall data deletion: explicit consent | DELETEDATA checkbox unchecked default, condition in cleanup.wxs |
| R6 | ACL restrictions on ProgramData | Permission elements in files.wxs (SYSTEM + Administrators + LocalService) |
| R7 | CA Name Constraints by default | SR-INSTALLER-3 and SR-INSTALLER-11 coverage |
| R8 | Firewall loopback only | SR-INSTALLER-4 coverage |
| R9 | No PII in installer logging | SR-INSTALLER-5 and SR-INSTALLER-16 coverage |
| R10 | No user accounts or identifiers | SR-INSTALLER-9 coverage |
| R11 | Config file permissions | default.yaml in ProgramFiles (standard read-only for users); override in ACL-restricted ProgramData |
| R12 | Test fixtures: synthetic data only | All test domains use `.com`, `.example`, `.ai` domains; no real PII patterns |

## 5. Technical Choices and Rationale

### GenerateCA signature change (permittedDNSDomains parameter)
**Rationale**: Adding a third parameter to `GenerateCA()` is the simplest, most discoverable API change. An options pattern or separate function would add complexity without benefit. The `nil` default for all existing callers means zero behavior change — Name Constraints are only added when domains are explicitly provided. This aligns with the story pseudocode while keeping the x509 template construction atomic (constraints must be set before `CreateCertificate`).

### ca-init destroys before generating (not CreateOrLoadCA)
**Rationale**: SR-INSTALLER-12 requires total destruction of old CA before generating new one. `CreateOrLoadCA` checks `NeedsGeneration()` first and loads existing if present — this is the correct behavior for proxy startup but wrong for `ca-init`. The subcommand uses its own flow: `destroyExistingCA()` → `GenerateCA()` → `store.Save()`. This ensures old keys are never retained during CA replacement (e.g., upgrade scenario where providers change).

### Config override uses yaml.v3 shallow unmarshal onto existing struct
**Rationale**: `yaml.v3`'s `Unmarshal` into an existing struct only overwrites fields present in the YAML input. This provides natural shallow merging without custom field-by-field logic. The merged result is re-validated via `cfg.Validate()`. A separate `MergeFileOverride` method encapsulates this in the config package for reuse.

### WiX ServiceInstall lives in files.wxs (not service.wxs)
**Rationale**: WiX v3 requires `<ServiceInstall>` to be a child of the `<Component>` that contains the service executable `<File>`. Separating them into different fragments would break the MSI compilation. The `service.wxs` file provides a `ComponentGroupRef` for the feature tree, maintaining the modular structure described in the story while respecting WiX's structural constraints.

### certutil invoked via [System64Folder] (not bare certutil)
**Rationale**: SR-INSTALLER-2 requires absolute path invocation to prevent PATH hijacking. `[System64Folder]` is the WiX property for `C:\Windows\System32\` on 64-bit systems, ensuring the system's `certutil.exe` is always used regardless of PATH poisoning.

### Firewall allow-before-block ordering via InstallExecuteSequence
**Rationale**: SR-INSTALLER-4 requires the allow loopback rule to be evaluated before the block external rule. Using sequential CustomActions in `InstallExecuteSequence` (FirewallAllowLoopback → FirewallBlockExternal) ensures the allow rule is created first. Windows Firewall evaluates rules within the same profile in creation order, so this guarantees correct priority.

### Interactive terminal check via os.Stdin.Stat() + ModeCharDevice
**Rationale**: SR-INSTALLER-3 and SR-INSTALLER-14 require blocking unsafe CA generation in non-interactive contexts. On Unix, `os.ModeCharDevice` indicates a terminal. On Windows, the same test applies (Go's runtime handles the platform difference). This catches MSI silent installs (`/quiet`), scripted calls, and pipe/redirect scenarios.

## 6. Platform-Specific Notes

### Windows
- CA key DPAPI-encrypted before disk write (`ca_windows.go`)
- Service auto-detection via `svc.IsAnInteractiveSession()` (unchanged from QINDU-0001)
- MSI deploys to `%PROGRAMFILES%\Qindu\` and `%PROGRAMDATA%\Qindu\`
- Service runs as `NT AUTHORITY\LocalService` (least-privilege)
- Firewall rules managed via `netsh advfirewall`
- CA trust store managed via `certutil`

### Linux / macOS / CI
- `ca-init` uses memory-only store (`ca_other.go`) — CA not persisted to disk
- File-based tests (`TestCAInit_DestroyAndRecreateCA`) handle gracefully: dummy files created in temp dirs for testing
- Cross-compilation `GOOS=windows GOARCH=amd64 go build ./...` succeeds
- Integration tests use in-process TLS servers (unchanged)

### WiX compilation
- Requires WiX Toolset v3 (`choco install wixtoolset`)
- CI uses `windows-latest` runner with Chocolatey
- MSI artifact includes SHA256 checksum for supply chain verification

## 7. Known Limitations

### Not implemented (excluded from sprint — future work)
- ❌ Authenticode code signing (SmartScreen will warn on unsigned MSI)
- ❌ Firefox browser policy configuration
- ❌ Tray icon or UI for the running service
- ❌ PII detection / tokenization / vault (QINDU-0005+)
- ❌ Provider adapters (chatgpt, claude)
- ❌ Hot-reload configuration
- ❌ Fail-closed error page
- ❌ MSI integration testing in CI (requires interactive Windows session)

### Known gaps
1. **MSI unsigned (DPO C1, CISO Q1)**: The MSI triggers SmartScreen warnings. A dedicated release sprint must add Authenticode code signing.
2. **SEC-F4 (panic on non-ECDSA key) tracked but not fixed**: `parseCAFromPEM` at `ca_helper.go:78` uses a bare type assertion. If a corrupted CA file contains a non-ECDSA key, it will panic. This is low-risk in practice (CA files are generated by the same binary) but should be hardened in a future sprint.
3. **SEC-F1 through SEC-F3 explicitly deferred**: MITM dial timeout (SEC-F1), silent write error (SEC-F2), SystemCertPool error discarded (SEC-F3) are not in scope for QINDU-0002 installer changes. These affect the proxy runtime, not the installer.
4. **Config override validation after merge**: The merged config is validated via `cfg.Validate()` after `MergeFileOverride`. However, if the override adds new providers not present in `default.yaml`, the Name Constraints from those providers would not be applied (CA was generated from the merged config). This is by design — the admin controls the config.
5. **Upgrade scenario: CA regeneration**: On MSI upgrade, `ca-init` runs again (condition `NOT Installed` is false, but MajorUpgrade triggers reinstall). The CustomAction conditions should handle this. Explicit upgrade testing on Windows VM needed.
6. **ProgramData directory for CA**: On clean install, `agent.exe ca-init` creates `%PROGRAMDATA%\Qindu\` via `store.Save()` → `os.MkdirAll`. The directory should already exist with ACL from the MSI `CreateFolder`. If the MSI's directory component has not yet been processed when `ca-init` runs, the ACL may be set by `ca-init`'s `MkdirAll(0700)` instead. File permission `0600` on `ca.key` provides defense-in-depth.
7. **LicenseAgreementDlg dependency**: The WiX custom dialogs assume `WixUI_InstallDir` includes `LicenseAgreementDlg`. The UI sequence overrides publish from `LicenseAgreementDlg.Next` to `QinduNoticeDlg`. This requires WiX's license UI to be present.

## 8. How to Test

### Quick test
```bash
go test -race ./...
```

### Run with coverage
```bash
go test -race -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

### Test ca-init (console mode)
```bash
go run ./cmd/agent/ ca-init --config configs/default.yaml
go run ./cmd/agent/ ca-init --unsafe --config configs/default.yaml
```

### Test proxy mode (unchanged)
```bash
go run ./cmd/agent/ -config configs/default.yaml
```

### Cross-compile for Windows
```bash
GOOS=windows GOARCH=amd64 go build ./cmd/agent/
```

### Build MSI (requires WiX Toolset on Windows)
```bash
GOOS=windows GOARCH=amd64 go build -o installer/wix/agent.exe ./cmd/agent/
cp configs/default.yaml installer/wix/configs/default.yaml
cd installer/wix
candle qindu.wxs -dProductVersion=0.1.0 -ext WixUIExtension
light qindu.wixobj -out Qindu-Installer-x64.msi -cultures:en-us -loc locale/en-us.wxl -ext WixUIExtension
```

## 9. CI/CD

GitHub Actions workflow updated (`.github/workflows/ci.yml`):
- **Existing jobs (unchanged)**: `test` (ubuntu-latest, go vet, go test -race, cross-compile), `format` (go fmt check)
- **New job**: `build-msi`:
  - **Runs on**: `windows-latest`
  - **Needs**: `test` (must pass first)
  - **Triggers**: Push of `v*` tag OR `workflow_dispatch`
  - **Steps**: Checkout → Setup Go → Build agent.exe → Copy config → Install WiX Toolset (choco) → Compile MSI → SHA256 checksum → Upload artifact
  - **Artifact**: `Qindu-Installer-x64.msi` + `Qindu-Installer-x64.msi.sha256`

## 10. Verification Summary

```bash
$ go build ./...                    # ✅ passes
$ go vet ./...                      # ✅ passes
$ go test -race -count=1 ./...      # ✅ 142/142 tests pass
$ GOOS=windows GOARCH=amd64 go build ./...  # ✅ cross-compiles
$ go fmt ./... && git diff --exit-code      # ✅ clean
```

## 11. Peer Review Fixes Changelog

Peer review (2026-06-14) found 2 critical and 6 high-severity issues. All 8 are addressed below.

| Fix ID | Severity | File(s) | Description | Change |
|--------|----------|---------|-------------|--------|
| **PR-001** | CRITICAL | `internal/tls/ca_helper.go:78`, `internal/tls/ca_test.go` | Bare type assertion `cert.PublicKey.(*ecdsa.PublicKey)` panics on corrupted/non-ECDSA CA file (SEC-F4, CISO SR-INSTALLER-17). | Changed to comma-ok pattern: `certPub, ok := cert.PublicKey.(*ecdsa.PublicKey)` with error return `"CA key is not ECDSA P-256 (got %T), file may be corrupted"`. Added `TestParseCAFromPEM_NonECDSAKey` test that generates an RSA certificate and verifies `parseCAFromPEM` returns a graceful error instead of panicking. |
| **PR-002** | CRITICAL | `cmd/agent/main.go:263,269-270,286-287`, `cmd/agent/ca_init_test.go` | `os.Exit(1)` called inside `resolveConfigPath` — side-effect in pure lookup function breaks testability, defers, and callers' exit code flow. | Changed `resolveConfigPath` signature from `func(string) string` to `func(string) (string, error)`. Replaced `os.Exit(1)` calls with `return "", fmt.Errorf(...)`. Updated callers in `runProxy` (line 55) and `runCAInit` (line 117) to handle the error and `return 1`. Updated 3 test functions to use `(path, err)` tuple. |
| **PR-003** | HIGH | `cmd/agent/main.go:234-242` | TOCTOU race: `os.Stat` check before `os.Remove` in `destroyExistingCA`. Unnecessary guard — `os.Remove` already returns `nil` for non-existent files. | Removed `os.Stat` guard entirely. Simplified to direct `os.Remove` calls with `os.IsNotExist(err)` checks. Shorter, correct, race-free. |
| **PR-004** | HIGH | `installer/wix/includes/cleanup.wxs` | `cmd.exe /c rmdir /s /q "[PROGRAMDATADIR]"` — command injection surface, unnecessary process spawn, silent failure (`Return="ignore"`). | Replaced entire `CustomAction` block with WiX-native `<RemoveFolderEx>`: uses Windows Installer API, integrates with MSI rollback, handles locked files gracefully, no command injection surface. Attached to `PROGRAMDATADIR` via `<DirectoryRef>` with `<Component>`. Conditioned on `DELETEDATA="1"`. |
| **PR-005** | HIGH | `cmd/agent/main.go:15,217-224` | `fmt.Scanln(&response)` — return values ignored, splits on spaces (user typing "YES I understand" → `response="YES"` which happens to work), error values discarded. | Replaced with `bufio.NewReader(os.Stdin).ReadString('\n')`. Handles errors via `fmt.Errorf("reading confirmation: %w", err)`. Uses `strings.TrimSpace` to strip trailing `\n`. Added `"bufio"` to imports. Exact comparison with "YES". |
| **PR-006** | HIGH | `.github/workflows/ci.yml:94-99` | `github.ref_name` includes `v` prefix (e.g., `v0.1.0`); WiX `ProductVersion` requires `X.Y.Z` format — causes `candle.exe` validation error on every tagged release. | Added `pwsh` step to strip `v` prefix: `$version = "${{ github.ref_name }}" -replace '^v', ''` → writes `VERSION` to `$env:GITHUB_ENV`. Updated `candle` command to use `-dProductVersion=%VERSION%`. |
| **PR-007** | HIGH | `installer/wix/includes/firewall.wxs:26,34` | Uninstall rule deletion uses locale-dependent `!(loc.FirewallRuleAllowName)` and `!(loc.FirewallRuleBlockName)`. If locale changes between versions, uninstall cannot find old rules. | Hardcoded English rule names `"Qindu Agent (Allow Loopback)"` and `"Qindu Agent (Block External)"` in the `ExeCommand` for `FirewallRemoveAllowLoopback` and `FirewallRemoveBlockExternal` delete commands. Locale strings remain for UI display (install commands). |
| **PR-008** | HIGH | `installer/wix/includes/ca-trust.wxs:56-59` | `CAInstallTrustStore` only sequences `After="CAInitUnsafe"`. If normal mode (`UNSAFE_CA != "1"`), `CAInitUnsafe` never executes, so the `After` constraint is vacuous — `certutil -addstore` could run before CA generation. | Added two explicit `After` constraints for `CAInstallTrustStore`: `After="CAInitNormal"` (with condition `NOT Installed AND NOT UNSAFE_CA="1"`) and `After="CAInitUnsafe"` (with condition `NOT Installed AND UNSAFE_CA="1"`). Each paired with the matching CAInit condition, so exactly one fires per install. |

### Additional fixes applied (strongly recommended by peer review)

| Fix ID | Severity | File(s) | Description | Change |
|--------|----------|---------|-------------|--------|
| **PR-102** | MEDIUM | `cmd/agent/main.go`, `cmd/agent/ca_init_test.go` | `collectProviderDomains` (main.go) duplicates `cfg.AllAIDomains()` (config.go) character-for-character. | Deleted `collectProviderDomains` function. Replaced call-sites with `cfg.AllAIDomains()`. Updated tests `TestCollectProviderDomains` and `TestCollectProviderDomains_DisabledProvider` to use `cfg.AllAIDomains()`. |
| **PR-104** | LOW | `installer/wix/qindu.wxs:13` | Stale comment "Replace PUT-YOUR-GUID-HERE with a real GUID before release" when UpgradeCode already has a real GUID at line 40. | Updated comment to: "DO NOT CHANGE the UpgradeCode after the first release." |
| **PR-207** | LOW | `installer/README.md:105` | References `{PUT-YOUR-GUID-HERE}` — same stale GUID issue as PR-104. | Updated to reference actual GUID `{5319E462-2A8D-476D-8896-32F36E454A98}` and note "Do not change after first release." |

### Verification after fixes

```bash
$ go build ./...                    # ✅ passes
$ go vet ./...                      # ✅ passes
$ go test -race -count=1 ./...      # ✅ 143/143 tests pass (1 new test: TestParseCAFromPEM_NonECDSAKey)
$ GOOS=windows GOARCH=amd64 go build ./...  # ✅ cross-compiles
$ go fmt ./... && git diff --exit-code      # ✅ clean
```

## 12. Peer Review Fixes Changelog (Round 2)

Second peer review (2026-06-14) found 3 critical, 5 high, and 5 medium issues. All 13 are addressed below.

### Critical fixes

| Fix ID | Severity | File(s) | Description | Change |
|--------|----------|---------|-------------|--------|
| **PR-C1** | CRITICAL | `installer/wix/license.rtf` (new), `installer/wix/qindu.wxs:117-119` | MSI build broken: missing license.rtf, bannrbmp, dlgbmp. | Created `installer/wix/license.rtf` with minimal AGPL-3.0 notice RTF content. Removed `WixUIBannerBmp` and `WixUIDialogBmp` overrides from `qindu.wxs` — WiX now uses built-in bitmaps (professional-looking, supply-chain-verified). Only `WixUILicenseRtf` remains. |
| **PR-C2** | CRITICAL | `cmd/agent/main.go:47,62-67`, `installer/wix/includes/ca-trust.wxs:17-20` | MSI unsafe CA checkbox always fails: `confirmUnsafeMode()` needs interactive terminal, but MSI deferred CAs have no terminal. | Added `--auto-confirm-unsafe` flag to `ca-init`. When present, the interactive `confirmUnsafeMode()` check is skipped. The MSI `QinduOptionsDlg` checkbox serves as the consent mechanism (user already saw the warning text). MSI `CAInitUnsafe` ExeCommand updated to `agent.exe ca-init --unsafe --auto-confirm-unsafe`. CLI usage without `--auto-confirm-unsafe` still requires interactive `YES` confirmation. |
| **PR-C3** | CRITICAL | `installer/wix/qindu.wxs:97-102` | Duplicate `<Publish>` elements in `qindu.wxs` and `dialogs.wxs` (`LicenseAgreementDlg`→`QinduNoticeDlg`, `MaintenanceTypeDlg`→`QinduUninstallDlg`). | Removed both duplicate `<Publish>` elements from `qindu.wxs`. They remain only in `dialogs.wxs` which also has the unique `LicenseAgreementDlg`→`CancelDlg` publish. |

### High-severity fixes

| Fix ID | Severity | File(s) | Description | Change |
|--------|----------|---------|-------------|--------|
| **PR-H1** | HIGH | `installer/wix/includes/ca-trust.wxs`, `installer/wix/includes/firewall.wxs` | `Return="ignore"` silently swallows genuine failures in certutil and netsh custom actions. | **certutil -addstore**: Added pre-check `CACheckTrustStore` (`certutil -verifystore`, Return="ignore"). `CAInstallTrustStore` changed to Return="check". **certutil -delstore**: Changed to Return="check". **netsh firewall rules**: All 4 install/uninstall CAs changed to Return="check". Added 2 rollback CAs (`FirewallRollbackAllowLoopback`, `FirewallRollbackBlockExternal`) with Return="ignore". Rollback CAs sequenced `Before` their corresponding install CAs. |
| **PR-H2** | HIGH | `cmd/agent/main.go:124-134` | `runCAInit` bypassed `loadConfig` wrapper — called `policy.LoadConfig()` + `applyConfigOverride()` separately, duplicating the wrapper logic. | Replaced separate calls with single `loadConfig(resolvedConfigPath)` call. Deleted the redundant `policy.LoadConfig()` + `applyConfigOverride()` lines. `runCAInit` and `runProxy` now use the same `loadConfig` entry point. |
| **PR-H3** | HIGH | `installer/wix/includes/ca-trust.wxs:75-76` | Directory permissions race: `ca-init` `MkdirAll(0700)` could run before MSI `CreateFolder` ACL is applied. | Added explicit `After="InstallFiles"` constraint on `CAInitNormal` and `CAInitUnsafe` in `InstallExecuteSequence`. This ensures the `CreateFolder` component for `PROGRAMDATADIR` (with `<Permission>` ACL elements) is processed before `ca-init` runs. |
| **PR-H4** | HIGH | `installer/wix/includes/cleanup.wxs:39-43`, `installer/wix/qindu.wxs:88` | `INSTALLDIR` had no `RemoveFolderEx` — orphaned files (crash dumps, .tmp, user files) would persist after uninstall. | Added `<RemoveFolderEx>` for `INSTALLDIR` in `cleanup.wxs` (unconditional on uninstall — always clean Program Files). Added `CleanupComponents` ComponentGroup referencing both `CleanupProgramDataDir` and `CleanupInstallDir`. Referenced `CleanupComponents` in the Feature tree in `qindu.wxs`. |
| **PR-H5** | HIGH | `installer/wix/includes/firewall.wxs:8,17`, `installer/wix/locale/en-us.wxl:11-12` | Firewall rule names: install used locale-dependent `!(loc.FirewallRuleAllowName)` / `!(loc.FirewallRuleBlockName)`, uninstall used hardcoded English. If locale strings changed between versions, uninstall would miss old rules. | Hardcoded BOTH install and uninstall rule names directly in `ExeCommand`: `name="Qindu Agent (Allow Loopback)"` and `name="Qindu Agent (Block External)"`. Removed `FirewallRuleAllowName` and `FirewallRuleBlockName` strings from `en-us.wxl`. |

### Medium-severity fixes

| Fix ID | Severity | File(s) | Description | Change |
|--------|----------|---------|-------------|--------|
| **PR-M1** | MEDIUM | `cmd/agent/main.go:131-146,161` | `confirmUnsafeMode` warning banner used `fmt.Println` (stdout) — inconsistent with error output on stderr, cluttered MSI logs. | Changed all `fmt.Println`/`fmt.Print` in `confirmUnsafeMode` to `fmt.Fprintln(os.Stderr, ...)` / `fmt.Fprint(os.Stderr, ...)`. Warning banner and prompt now go to stderr. |
| **PR-M2** | MEDIUM | `cmd/agent/main.go`, `cmd/agent/proxy.go` (new) | `slog` imported in `main.go` but unused in `ca-init` path. Future file split would trigger "imported and not used" compiler error. | Moved proxy-related functions (`runProxy`, `initCA`, `startProxy`, `runConsole`, `runServiceMode`) to new file `cmd/agent/proxy.go` with `slog` import. `main.go` retains only `ca-init` functions without `slog`. All imports are used in their respective files. |
| **PR-M3** | MEDIUM | `cmd/agent/ca_init_test.go:317-334` | `TestGetCADir_Fallback` used loose `strings.Contains` substring match instead of exact path. Removed `strings` import (no longer needed). | Replaced substring check with explicit expected path computation: checks `os.UserHomeDir()` then `os.TempDir()`. Uses exact equality comparison `dir != expected`. |
| **PR-M4** | MEDIUM | `cmd/agent/ca_init_test.go:261-292` | Test names still referenced deleted `collectProviderDomains` function. | Renamed `TestCollectProviderDomains` → `TestAllAIDomains`, `TestCollectProviderDomains_DisabledProvider` → `TestAllAIDomains_DisabledProvider`. |
| **PR-M5** | MEDIUM | `installer/README.md`, `.github/workflows/ci.yml:92` | WiX `UIDll` reference fragile: custom dialog sequence depends on `WixUI_InstallDir` internal dialog IDs. | Documented WiX extension compatibility in `installer/README.md` (new section "WiX Extension Compatibility"). Pinned WiX Toolset version in CI: `choco install wixtoolset --version=3.14.1`. |

### Additional improvements applied

| Change | File(s) | Description |
|--------|---------|-------------|
| Cleanup ComponentGroup | `installer/wix/includes/cleanup.wxs`, `installer/wix/qindu.wxs` | Added `CleanupComponents` ComponentGroup to ensure `CleanupProgramDataDir` and `CleanupInstallDir` components are referenced in the Feature tree (both were previously unreferenced). |
| Proxy error output restored | `cmd/agent/proxy.go` | `runProxy` error paths now properly output `fmt.Fprintf(os.Stderr, ...)` messages (preserved from original `main.go`). |

### Verification after Round 2 fixes

```bash
$ go build ./...                    # ✅ passes
$ go vet ./...                      # ✅ passes
$ go test -race -count=1 ./...      # ✅ 143/143 tests pass
$ GOOS=windows GOARCH=amd64 go build ./...  # ✅ cross-compiles
$ go fmt ./... && git diff --exit-code      # ✅ clean (pre-existing diffs only)
```

## 13. Peer Review Fixes Changelog (Round 3)

Third peer review (2026-06-14) found 2 high, 5 medium-severity issues. All 7 addressed below.

### High-severity fixes

| Fix ID | Severity | File(s) | Description | Change |
|--------|----------|---------|-------------|--------|
| **PR-2RH1** | HIGH | `installer/wix/qindu.wxs`, `installer/wix/locale/en-us.wxl`, `installer/wix/includes/ca-trust.wxs` | Silent/quiet install with `UNSAFE_CA=1` bypasses the interactive consent mechanism (SR-INSTALLER-14). An enterprise deploying via SCCM with `/quiet UNSAFE_CA=1` would silently deploy an unconstrained CA. | Added `<Condition>` LaunchCondition element in `qindu.wxs`: blocks when `UNSAFE_CA="1" AND (UILevel=2 OR UILevel=3)`. Added `UnsafeCASilentBlocked` localization string to `en-us.wxl`. Updated `CAInitUnsafe` condition in `ca-trust.wxs` to include `AND (NOT UILevel=2) AND (NOT UILevel=3)` as defense-in-depth. |
| **PR-2RH2** | HIGH | `.github/workflows/ci.yml` | `build-msi` job lacked `go vet` and `go test -race` on Windows. Windows-specific code paths (DPAPI, service detection, syscall) were not verified on-target in CI. | Added `go vet ./...` step and `go test -race -count=1 -timeout 180s ./...` step to `build-msi` job, sequenced before `go build agent.exe`. |

### Medium-severity fixes

| Fix ID | Severity | File(s) | Description | Change |
|--------|----------|---------|-------------|--------|
| **PR-2RM1** | MEDIUM | `internal/policy/config.go`, `internal/policy/config_test.go` | `ParseConfig()` exported without calling `Validate()`. An invalid config (e.g., `ListenAddr: "0.0.0.0"`) parsed via `ParseConfig` would silently bypass loopback binding enforcement and upstream validation checks. `MergeFileOverride` already validates internally — this was a gap only in the direct `ParseConfig` path. | Added `cfg.Validate()` call inside `ParseConfig()`, returning `fmt.Errorf("invalid config: %w", err)` on failure. Updated `TestParseConfig_EmptyYAML` to expect error from `ParseConfig` directly (no longer calls `Validate` separately). All other `ParseConfig` callers already provide valid YAML and pass unchanged. |
| **PR-2RM2** | MEDIUM | `cmd/agent/main.go` | `getCADir()` computed fallback paths (`$HOME/.qindu/ca`, `/tmp/qindu-ca`) without verifying directory existence or creatability. While `store.Save()` calls `MkdirAll` internally, `destroyExistingCA` runs first without directory existence guarantee. | Added `os.MkdirAll(caDir, 0700)` call immediately after `getCADir()` in `runCAInit`, with error handling. Ensures CA directory exists before `destroyExistingCA` operates — defense-in-depth even if future code changes remove `MkdirAll` from `Save`. |
| **PR-2RM3** | MEDIUM | `installer/wix/qindu.wxs` | Duplicate `<UIRef Id="WixUI_Common" />` at line 107. `WixUI_InstallDir` already references `WixUI_Common` internally. Duplicate fragment references could cause warnings or unexpected behavior across WiX versions. | Removed `<UIRef Id="WixUI_Common" />` from `qindu.wxs`. The single `<UIRef Id="WixUI_InstallDir" />` remains (at line 95), which is the authoritative UI reference. |
| **PR-2RM4** | MEDIUM | `installer/wix/license.rtf` | `license.rtf` contained a single sentence — users clicking "I Agree" were consenting to AGPL-3.0 without seeing any license terms. DPO R1 requires transparency about what users consent to. | Expanded `license.rtf` with: AGPL-3.0 copyleft summary, warranty disclaimer, full license URL (`https://www.gnu.org/licenses/agpl-3.0.html`), source code URL (`https://github.com/Tarekinh0/qindu`), and support/issues link. |
| **PR-2RM5** | MEDIUM | `cmd/agent/main.go`, `cmd/agent/ca_init_test.go` | `fmt.Printf` and `fmt.Fprintf` statements in ca-init path could be flagged during future PII audits as potential data exfiltration surfaces — no comments distinguish metadata output from PII output. | Added `// SAFETY: No PII in log output` block comments: (a) above the success summary `fmt.Printf` block in `runCAInit` explaining only x509 metadata is printed, (b) in `confirmUnsafeMode` doc comment noting static warning text only, (c) file-level SAFETY comment in `ca_init_test.go` listing all synthetic test data domains. |

### Verification after Round 3 fixes

```bash
$ go build ./...                    # ✅ passes
$ go vet ./...                      # ✅ passes
$ go test -race -count=1 -timeout 180s ./...  # ✅ all tests pass
$ GOOS=windows GOARCH=amd64 go build ./...    # ✅ cross-compiles
$ go fmt ./...                      # ✅ no changes needed
```

## 14. Peer Review Fixes Changelog (Round 5)

Third-round peer review (2026-06-15) found 11 issues (3 critical, 1 high, 7 design). All 11 are addressed below.

### Critical fixes

| Fix ID | Severity | File(s) | Description | Change |
|--------|----------|---------|-------------|--------|
| **PR-001** | CRITICAL | `.github/workflows/ci.yml:127` | `copy configs\default.yaml installer\wix\configs\default.yaml` would fail because `installer\wix\configs\` doesn't exist in the repo. | Added `mkdir installer\wix\configs` before `copy` in the `Copy default config` step. |
| **PR-002** | CRITICAL | `cmd/agent/main.go:97-115` | `destroyExistingCA` ran before `GenerateCA`. If generation failed (disk full, DPAPI error, entropy failure), the old CA was permanently lost — irreversible data loss on upgrade. | Reordered flow: generate new CA in memory first → if success, destroy old CA → save new CA. If generation fails, old CA survives untouched. Flow is now `generate → destroy → save`. |
| **PR-003** | CRITICAL | `cmd/agent/main.go:77-80,132-136` | When `!unsafe` but all providers are disabled (or config override empties them), `permittedDomains` is empty and `GenerateCA` creates an unconstrained CA silently — no output message warns the user. | Added validation gate: if `!unsafe && len(permittedDomains) == 0`, abort with error: "No enabled AI providers found in config. Enable at least one provider or use --unsafe for an unconstrained CA." Added `else` branch in output section to print "Name Constraints: NONE (no enabled AI providers in config)" for completeness. |

### High-severity fix

| Fix ID | Severity | File(s) | Description | Change |
|--------|----------|---------|-------------|--------|
| **PR-004** | HIGH | `cmd/agent/main.go:217-237` | Path traversal check used `strings.Contains(path, "..")` — a substring match that rejects legitimate paths (e.g., `C:\Program Files\myapp..v2\config.yaml`) and misses path-component traversal. | Replaced substring check with `filepath.Clean(path)` followed by `strings.Contains(cleaned, "..")`. Applied to both explicit `--config` path and `QINDU_CONFIG` env var path. `filepath.Clean` resolves embedded `..` components properly. |

### Design fixes

| Fix ID | Severity | File(s) | Description | Change |
|--------|----------|---------|-------------|--------|
| **PR-101** | MEDIUM | `internal/policy/config.go:122-135` | `AllAIDomains()` produced duplicate domains when two providers shared a domain (possible via config override). Duplicates wasted certificate extension bytes and confused diagnostics. | Added `seen` map for deduplication. Domains are only appended if not already seen. |
| **PR-102** | MEDIUM | `installer/wix/locale/en-us.wxl:20` | `ErrorCAInitFailed` locale string was defined but never referenced by any `.wxs` file — dead localization. | Removed the orphaned `<String Id="ErrorCAInitFailed">` entry. Verified via grep: zero references in any `.wxs` file. |
| **PR-103** | MEDIUM | `.github/workflows/ci.yml:133-142` | Version extraction `$version = "${{ github.ref_name }}" -replace '^v', ''` produced semantically wrong versions for `workflow_dispatch` (e.g., `ProductVersion=main`). WiX expects `x.y.z.build` format. | Added regex match: if ref matches `^v(\d+\.\d+\.\d+)`, use the captured version. Otherwise, fall back to `0.0.0-dev-<sha8>`. |
| **PR-104** | MEDIUM | `internal/tls/cert_cache.go:44-54` | `CertCache` never evicted expired entries by TTL. Leaf certificates (valid 24h) accumulated until the 1000-entry max triggered random eviction — potentially pushing out still-valid certs. | Added lazy TTL check in `Get()`: if `cert.Leaf != nil && time.Now().After(cert.Leaf.NotAfter)`, return `nil, false` (cache miss). Added `"time"` import. |
| **PR-105** | MEDIUM | `cmd/agent/ca_init_test.go:87,100-101,122-126,168,231,312,326,345,358` | 9 test functions used `os.Setenv` + `defer os.Unsetenv` instead of `t.Setenv()`. Prevents parallel test execution and risks test cross-contamination. | Replaced all `os.Setenv`/`os.Unsetenv` calls with `t.Setenv()`. For cases where the old code used `os.Unsetenv` to clear a value, used `t.Setenv("KEY", "")`. |
| **PR-106** | LOW | `internal/tls/ca_windows.go:127,161` | DPAPI error wrapping used `%v` instead of `%w`, breaking error chain for `errors.Is`/`errors.As` callers. | Changed `fmt.Errorf("CryptProtectData failed: %v", err)` → `%w` and `fmt.Errorf("CryptUnprotectData failed: %v", err)` → `%w`. |
| **PR-108** | LOW | `internal/tls/ca.go:64` | `MaxPathLenZero: true` lacked a comment explaining the security implication — future developers might be confused if they try to extend the CA for certificate chains. | Added comment: `// CA can only sign leaf certificates, not intermediate CAs`. |

### Verification after Round 5 fixes

```bash
$ go build ./...                    # ✅ passes
$ go vet ./...                      # ✅ passes
$ go test -race -count=1 -timeout 180s ./...  # ✅ all tests pass
$ go fmt ./... && git diff --exit-code       # ✅ no new formatting issues
```

## 15. Peer Review Fixes Changelog (Round 6)

Round 6 peer review (2026-06-15) found 2 critical bugs. Both are addressed below.

### Critical fixes

| Fix ID | Severity | File(s) | Description | Change |
|--------|----------|---------|-------------|--------|
| **PR-002** | CRITICAL | `internal/policy/config.go` | `MergeFileOverride` called `yaml.Unmarshal(data, c)` directly on the receiver. For map-typed fields like `Providers` (`map[string]ProviderConfig`), yaml.v3 replaces the entire map rather than merging entries. If an override YAML only specified `providers.chatgpt`, the `claude` provider was silently deleted. | Changed to unmarshal into a temporary `var override Config`, then merge each section field-by-field. Agent, TLS, and Logging fields are individually checked (non-zero) before assignment. Providers map is merged entry-by-entry via `for name, prov := range override.Providers`. Bool fields (`CertCacheEnabled`, `PIILogging`) are intentionally skipped — their zero-value (`false`) is indistinguishable from "not present" in YAML; overriding them would force `false` on every merge. The merged result is re-validated. |
| **PR-003** | CRITICAL | `internal/proxy/forward.go`, `internal/proxy/mitm.go` | `forwardRequestAndResponse` created a new `bufio.NewReader(browserConn)` and `bufio.NewReader(upstreamConn)` on every call. In the keep-alive loop in `handleMITM`, this discarded buffered bytes belonging to the next HTTP request, causing data corruption (truncated/malformed requests). | Changed `forwardRequestAndResponse` signature from `(browserConn io.ReadWriter, upstreamConn io.ReadWriter, ...)` to `(browserReader *bufio.Reader, browserWriter io.Writer, upstreamReader *bufio.Reader, upstreamWriter io.Writer, ...)`. In `mitm.go`, buffered readers are created ONCE before the keep-alive loop: `browserReader := bufio.NewReader(browserConn)`, `upstreamReader := bufio.NewReader(upstreamConn)`. The underlying `*tls.Conn` is still passed as `io.Writer` for the write path (countingWriter wrapping). Only one caller exists (`mitm.go:126`), so no additional call site updates needed. Added `"bufio"` import to `mitm.go`. |

### New tests added

| Test | File | What it verifies |
|------|------|------------------|
| `TestMergeFileOverride_ProvidersPreserved` | `internal/policy/config_test.go` | PR-002 regression: merging override with only `chatgpt` does not delete `claude` provider |
| `TestMergeFileOverride_AgentFieldMerged` | `internal/policy/config_test.go` | Agent fields in override are applied without disturbing non-overridden fields |
| `TestMergeFileOverride_NewProviderAdded` | `internal/policy/config_test.go` | New provider entries in override are added to the map without removing existing ones |
| `TestMergeFileOverride_MissingFile` | `internal/policy/config_test.go` | Error returned for nonexistent override file path |
| `TestMergeFileOverride_InvalidYAML` | `internal/policy/config_test.go` | Error returned for unparseable YAML in override file |

### Verification after Round 6 fixes

```bash
$ go build ./...                    # ✅ passes
$ go vet ./...                      # ✅ passes
$ go test -race -count=1 -timeout 180s ./...  # ✅ all tests pass (147/147)
$ go fmt ./...                      # ✅ no new formatting issues
```

## 16. Peer Review Fixes Changelog (Round 7)

Round 7 peer review (2026-06-15) found 3 issues (1 critical, 2 high). All 3 are addressed below.

| Fix ID | Severity | File(s) | Description | Change |
|--------|----------|---------|-------------|--------|
| **PR-001** | CRITICAL | `internal/proxy/mitm.go:120-153` | Connection log after keep-alive loop always wrote `Status: 200`. If `forwardRequestAndResponse` returned an error with a non-200 status (like 502), that status was lost — logs misrepresent failures as success. | Added `lastStatus := 200` before the loop. On each successful iteration: `lastStatus = status`. On error (non-EOF): if status is non-zero, `lastStatus = status`. Connection summary uses `Status: lastStatus` instead of hardcoded `200`. |
| **PR-002** | HIGH | `internal/service/windows_service.go:58,63,74`, `internal/proxy/graceful.go:14,30,34`, `internal/constants/constants.go` (new) | Hardcoded `30*time.Second` in `windows_service.go` ignored the exported `proxy.GracefulShutdownTimeout`. However, importing `proxy` from `service` created a circular dependency (`proxy` already imports `service`). | Extracted `GracefulShutdownTimeout` into a new shared package `internal/constants/constants.go` (single file, single constant). Updated `internal/proxy/graceful.go` to import constants and alias: `const GracefulShutdownTimeout = constants.GracefulShutdownTimeout` (backward-compatible re-export). Updated `internal/service/windows_service.go` to import `constants` and use `constants.GracefulShutdownTimeout` in all three locations (log message, context timeout, `time.After`). Marked the old alias as deprecated. |
| **PR-003** | HIGH | `cmd/agent/main.go:132-137` | `ca-init` Storage output printed `Storage: /home/user/.qindu/ca` on non-Windows, but the CA is stored in memory only (never persisted to disk). Misleading users into thinking the CA survives process restart. | Added `runtime.GOOS` check: on Windows, prints actual `caDir` path (`%PROGRAMDATA%\Qindu`). On non-Windows, prints `"Storage: memory-only (CA regenerated on next run)"`. Added `"runtime"` import. |

### New files

| File | Purpose |
|------|---------|
| `internal/constants/constants.go` | Shared compile-time constant `GracefulShutdownTimeout` to break circular dependency between `proxy` and `service` packages |

### Modified files (Round 7)

| File | Change |
|------|--------|
| `internal/proxy/mitm.go` | PR-001: Track `lastStatus` across keep-alive loop, use in connection log |
| `internal/proxy/graceful.go` | PR-002: Import constants, alias `GracefulShutdownTimeout = constants.GracefulShutdownTimeout`, remove `"time"` import |
| `internal/service/windows_service.go` | PR-002: Import `constants` instead of `"time"` only for the constant; use `constants.GracefulShutdownTimeout` in all 3 locations |
| `cmd/agent/main.go` | PR-003: Add `"runtime"` import, platform-aware Storage output message |

### Verification after Round 7 fixes

```bash
$ go build ./...                    # ✅ passes
$ go vet ./...                      # ✅ passes
$ go test -race -count=1 -timeout 180s ./...  # ✅ all tests pass (147/147)
$ GOOS=windows GOARCH=amd64 go build ./...    # ✅ cross-compiles
```
