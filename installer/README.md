# Qindu Windows Installer (WiX MSI)

This directory contains the WiX Toolset v3 project that builds the Qindu AI Privacy Proxy Windows installer (`Qindu-Installer-x64.msi`).

## Prerequisites

- **WiX Toolset v3**: Install via `choco install wixtoolset -y` (Windows) or download from [wixtoolset.org](https://wixtoolset.org/)
- **Go 1.26+**: For cross-compiling `agent.exe` for Windows
- **Windows SDK**: Required by WiX (included with WiX Toolset installation)

## Build Instructions

### 1. Build agent.exe for Windows

```bash
# From the repository root
GOOS=windows GOARCH=amd64 go build -o agent.exe ./cmd/agent/
```

### 2. Build the MSI

```bash
# Copy agent.exe and default config to the WiX build directory
cp agent.exe installer/wix/
cp configs/default.yaml installer/wix/configs/

# Build MSI (replace VERSION with actual version, e.g., 0.1.0)
cd installer/wix
candle qindu.wxs -dProductVersion=0.1.0 -ext WixUIExtension
light qindu.wixobj -out Qindu-Installer-x64.msi -cultures:en-us -loc locale/en-us.wxl -ext WixUIExtension
```

### 3. Verify the MSI

```bash
# Check MSI properties
msiexec /a Qindu-Installer-x64.msi /lv verify.log

# Or use Orca/MSI viewer to inspect tables
```

## CI Build

The GitHub Actions workflow (`.github/workflows/ci.yml`) includes a `build-msi` job that:
1. Builds `agent.exe` from the current source
2. Installs WiX Toolset via Chocolatey
3. Compiles the WiX project
4. Uploads `Qindu-Installer-x64.msi` as an artifact

The job is triggered on:
- Push of a `v*` tag (e.g., `v0.1.0`)
- Manual `workflow_dispatch`

## MSI Properties

| Property | Description | Default |
|---|---|---|
| `UNSAFE_CA` | Set to `"1"` to generate CA without Name Constraints | unset (safe mode) |
| `DELETEDATA` | Set to `"1"` to delete all Qindu data on uninstall | unset (preserve data) |
| `WIXUI_INSTALLDIR` | Installation directory | `%PROGRAMFILES%\Qindu\` |

## Silent Installation

```bash
# Normal install (CA with Name Constraints)
msiexec /i Qindu-Installer-x64.msi /quiet /norestart

# Unsafe install (CA without Name Constraints) — BLOCKED in silent mode!
# The interactive confirmation cannot be obtained in silent mode.
msiexec /i Qindu-Installer-x64.msi /quiet UNSAFE_CA=1  # Will FAIL

# Uninstall with data deletion
msiexec /x Qindu-Installer-x64.msi /quiet DELETEDATA=1

# Uninstall preserving data
msiexec /x Qindu-Installer-x64.msi /quiet
```

## What the MSI Installs

| Location | Contents | ACL |
|---|---|---|
| `%PROGRAMFILES%\Qindu\agent.exe` | Qindu agent binary | Standard Program Files (read-only for users) |
| `%PROGRAMFILES%\Qindu\configs\default.yaml` | Default YAML config | Standard Program Files |
| `%PROGRAMDATA%\Qindu\ca.key` | DPAPI-encrypted CA private key | SYSTEM + Admins + LocalService |
| `%PROGRAMDATA%\Qindu\ca.crt` | CA certificate (public) | SYSTEM + Admins + LocalService |
| `HKLM\Software\Policies\Google\Chrome\` | Chrome proxy policies | HKLM (admin-write) |
| `HKLM\Software\Policies\Microsoft\Edge\` | Edge proxy policies | HKLM (admin-write) |
| Windows Firewall | Allow loopback + Block external (port 8787) | System |
| Windows Trust Store | "Qindu AI Privacy CA" root CA | Machine store |
| Windows Service | QinduAgent (LocalService, auto-start) | System |

## Uninstall

The MSI provides a complete uninstall:
- Stops and removes the QinduAgent service
- Removes CA from Windows trust store
- Removes Chrome/Edge registry policies
- Removes firewall rules
- Removes program files
- Optionally removes `%PROGRAMDATA%\Qindu\` (if user opts in via checkbox)

## Versioning

- `UpgradeCode`: Fixed GUID `{5319E462-2A8D-476D-8896-32F36E454A98}` (see `qindu.wxs`). Do not change after first release.
- `ProductCode` and `PackageCode`: Auto-generated (`*`) on each build
- `ProductVersion`: Passed via `-dProductVersion=X.Y.Z` at build time

## WiX Extension Compatibility

The custom dialog sequence (`QinduNoticeDlg`, `QinduOptionsDlg`, `QinduUninstallDlg`) overrides the built-in `WixUI_InstallDir` dialog transitions. This depends on internal dialog IDs (`LicenseAgreementDlg`, `MaintenanceTypeDlg`, `VerifyReadyDlg`, etc.) from the `WixUIExtension`. To prevent silent breakage from WiX updates:

- **Pin WiX version**: The CI build pins WiX Toolset to v3.14.1 (`choco install wixtoolset --version=3.14.1`).
- **WixUI_InstallDir requirement**: The installer requires `WixUI_InstallDir` which includes `LicenseAgreementDlg`. The custom publish events in `dialogs.wxs` override `LicenseAgreementDlg.Next` → `QinduNoticeDlg` and `MaintenanceTypeDlg.RemoveButton` → `QinduUninstallDlg`.

## Known Limitations

- No Authenticode code signing in this sprint (SmartScreen will warn)
- No automatic browser detection — Chrome/Edge policies are written unconditionally
- Firefox is not automatically configured
- Silent install with `UNSAFE_CA=1` will fail (by design — requires interactive consent)
- Uninstall: `certutil -delstore` uses `Return="check"`. If the CA certificate was manually removed from the trust store before uninstall, uninstall may show an error. This is intentional — the user should be aware the trust store state does not match.
