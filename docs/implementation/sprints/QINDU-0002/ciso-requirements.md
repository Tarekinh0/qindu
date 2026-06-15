# CISO Requirements — QINDU-0002: Installer Windows + Service

**Agent**: qindu-ciso
**Date**: 2026-06-14
**Sprint**: QINDU-0002
**Phase**: 2 - Installation & Packaging
**Verdict**: PROCEED_WITH_CAVEATS

---

## Threat Model Additions

QINDU-0002 introduces the Windows MSI installer, which deploys the Qindu agent as a Windows service, installs the CA into the machine trust store, configures browser policies, sets firewall rules, and manages uninstall cleanup. The following threats are **new or significantly modified** compared to the QINDU-0001 proxy-only threat model.

### T1 — MSI Tampering / Supply Chain Injection
| Attribute | Detail |
|---|---|
| **STRIDE** | Tampering, Spoofing |
| **Severity** | **High** |
| **Description** | The MSI file is an unsigned binary (Authenticode excluded per story line 87). An attacker who intercepts the download or compromises the CI runner's WiX toolchain could inject malicious CustomActions, registry writes, or replace `agent.exe` with a trojanized binary. A compromised installer gains SYSTEM-equivalent write access during installation. |
| **Attack vector** | Man-in-the-middle on MSI download; CI runner compromise; WiX Toolset choco package supply chain; malicious tag push triggering CI build. |
| **Mitigation** | CI build pinned to specific runner versions; WiX Toolset installed from verified `choco` feed; MSI artifact checksum published alongside release; `agent.exe` compiled from audited source (not downloaded binary); reproducibility: CI builds MSI from source on every tag push. |
| **Residual** | No Authenticode signing until a dedicated release sprint. Users click through SmartScreen warnings. Accepted per story exclusion line 87. |

### T2 — Service Privilege Escalation via LocalService
| Attribute | Detail |
|---|---|
| **STRIDE** | Elevation of Privilege |
| **Severity** | **Medium** |
| **Description** | The `QinduAgent` service runs as `NT AUTHORITY\LocalService`. If an attacker compromises the service process (e.g., via a vulnerability in the proxy's HTTP handling, TLS parsing, or config loading), they gain `LocalService` privileges — which include network access to localhost services and the ability to read files accessible to LocalService. The CA key directory ACL grants LocalService read access (necessary for proxy startup), so a compromised `agent.exe` could exfiltrate the DPAPI-encrypted CA key (though decryption requires DPAPI context matching). |
| **Attack vector** | Memory corruption in `agent.exe`; malicious PAC file injection; crafted CONNECT request triggering panic/hang; registry write escalation via service restart. |
| **Mitigation** | `LocalService` is the least-privileged viable account (cannot use `SYSTEM` — that would allow CA key theft without DPAPI). Service is constrained to loopback networking. No outbound connections except to AI upstream domains. No file writes outside `%PROGRAMDATA%\Qindu\` (ACL-restricted). `go test -race` + `go vet` at build time. `Buildmode=pie` (position-independent executable) for ASLR. |
| **Residual** | If `agent.exe` is compromised, attacker gets LocalService. They can read CA key (DPAPI-encrypted) and vault (DPAPI-encrypted in future sprints). Decryption requires the same machine context. Accepted — the machine is the trust boundary. |

### T3 — CA Trust Store Poisoning / Improper Installation
| Attribute | Detail |
|---|---|
| **STRIDE** | Tampering, Spoofing |
| **Severity** | **Critical** |
| **Description** | `certutil -addstore Root "%PROGRAMDATA%\Qindu\ca.crt"` installs the Qindu CA into the machine trust store. If the CA certificate is tampered between generation and `certutil` execution (e.g., a race condition where another process replaces `ca.crt` before `certutil` reads it), the trust store could contain a malicious CA — allowing an attacker to MITM **all** TLS traffic on the machine, not just AI domains. Additionally, if `ca-init` fails mid-generation and leaves a partial CA cert, `certutil` might install a corrupted entry. |
| **Attack vector** | TOCTOU: attacker replaces `ca.crt` between `agent.exe ca-init` completion and `certutil` execution; CustomAction ordering error causes `certutil` to read stale/wrong file; file permissions allow non-admin write to `%PROGRAMDATA%\Qindu\` before ACL is applied. |
| **Mitigation** | `ca-init` must write `ca.crt` with ACL-restricted file permissions (0600 minimum) before returning. `certutil` must execute as the immediate next CustomAction in the WiX sequence (no intervening file-system-modifying actions). Uninstall must remove the CA with `certutil -delstore Root "Qindu AI Privacy CA"` — name-exact match, not filename. ACL on `%PROGRAMDATA%\Qindu\` must be set before `ca.crt` is written (or atomically with directory creation). |
| **Residual** | If a local admin attacker has write access to `%PROGRAMDATA%\Qindu\`, they can replace `ca.crt` at any point after installation. Admin-level attackers can also install arbitrary CAs directly via `certutil`. This is outside the threat model — admin on the machine owns the machine. |

### T4 — Firewall Rule Ordering / Self-Lockout
| Attribute | Detail |
|---|---|
| **STRIDE** | Denial of Service |
| **Severity** | **Medium** |
| **Description** | The installer creates two `netsh advfirewall` rules: one to allow loopback on port 8787, and one to block external connections on port 8787. Windows firewall evaluates rules in priority order. If the block rule has higher priority (evaluated first) than the allow rule, loopback connections will be **blocked** — the proxy becomes unreachable. This is a self-inflicted DoS. Additionally, the `netsh` command could fail silently (e.g., if Windows Firewall service is stopped) without the MSI detecting the failure. |
| **Attack vector** | Misconfiguration during development; Windows Firewall API behavior change in future OS versions; `netsh` command syntax error in WiX CustomAction. |
| **Mitigation** | The allow rule must have a higher priority (lower profile number or inserted before the block rule). WiX CustomAction must use explicit rule naming and verify the rules exist after creation (e.g., `netsh advfirewall firewall show rule name="Qindu Agent (Allow Loopback)"` — though MSI has limited feedback). Uninstall must remove both rules in reverse order. QA test TS9 verifies loopback access works post-install. |
| **Residual** | If Windows Firewall is disabled, rules have no effect — the proxy is exposed on port 8787 to the local machine only (binding is 127.0.0.1). This is acceptable because binding enforcement (QINDU-0001 SR4) is the primary protection, firewall is defense-in-depth. |

### T5 — Uninstall Race Conditions / Incomplete Cleanup
| Attribute | Detail |
|---|---|
| **STRIDE** | Tampering, Information Disclosure |
| **Severity** | **Medium** |
| **Description** | During uninstall, the MSI must stop the service → remove CA from trust store → delete registry keys → delete firewall rules → delete files → optionally delete `%PROGRAMDATA%\Qindu\`. If the service is slow to stop (30-second drain timeout), file deletion may fail because files are locked. If `certutil -delstore` fails silently (e.g., CA already removed, wrong CA name), the trust store retains the CA — enabling future MITM even after Qindu is uninstalled. If the firewall rules are not removed, port 8787 remains firewalled permanently. If the `DELETEDATA` checkbox logic is inverted or defaults to checked, user data is deleted without consent. |
| **Attack vector** | Service hang prevents file cleanup; MSI rollback logic leaves partial artifacts; `certutil` exit code not checked; uninstall order dependency failure. |
| **Mitigation** | WiX `ServiceControl` with `Stop="both"` and `Wait="yes"` before file removal. CustomAction sequencing: stop service → CA removal → registry cleanup → firewall cleanup → file removal. `RemoveFolderEx` for `%PROGRAMDATA%\Qindu\` must be conditional on `DELETEDATA=1` and execute last (after service is fully stopped). Uninstall must log failures (MSI verbose log captures CustomAction output). QA tests TS6, TS7, TS8 verify cleanup completeness. |
| **Residual** | If the MSI engine crashes mid-uninstall, partial artifacts may remain. Windows "Programs and Features" retry can complete cleanup. Manual cleanup instructions should be documented. |

### T6 — CustomAction Command Injection / Path Traversal
| Attribute | Detail |
|---|---|
| **STRIDE** | Elevation of Privilege, Tampering |
| **Severity** | **Medium** |
| **Description** | WiX CustomActions execute commands via `ExeCommand` with string parameters. The `agent.exe ca-init --config <path>` and `certutil` commands have command-line arguments. If any argument is derived from an MSI property sourced from user input (e.g., `UNSAFE_CA`, `DELETEDATA`, installer UI fields) without sanitization, an attacker could inject additional commands. Path arguments (`--config`, `%PROGRAMFILES%`, `%PROGRAMDATA%`) could be vulnerable to path traversal if they contain `..` sequences or unexpected characters. Additionally, `certutil` is invoked by name — if the `PATH` environment variable is poisoned during installation, a malicious `certutil.exe` could be executed instead. |
| **Attack vector** | MSI Public Property injection via `msiexec /i Qindu-Installer-x64.msi CMD_INJECT=...`; Unicode homoglyph paths; PATH poisoning before CustomAction runs; specially crafted `--config` path pointing to attacker-controlled YAML (could expand MITM scope). |
| **Mitigation** | All MSI properties used in `ExeCommand` must be validated: `UNSAFE_CA` must be exactly `"1"` or unset; `DELETEDATA` must be exactly `"1"` or unset; no other user-supplied properties interpolated into command lines. `certutil` must be invoked via absolute path (`%SystemRoot%\System32\certutil.exe`) or the MSI must sanitize `PATH`. `ca-init --config` path must be validated by `agent.exe` to reject paths containing `..` traversal or pointing outside approved directories. |
| **Residual** | Windows installer runs with elevated privileges (`SYSTEM` in some contexts). A command injection in a CustomAction would be extremely damaging. Defense-in-depth: keep `ExeCommand` surface minimal; prefer WiX native elements (`<ServiceInstall>`, `<RegistryKey>`) over `ExeCommand` where possible. |

### T7 — Unsafe CA Mode: Expanded Blast Radius
| Attribute | Detail |
|---|---|
| **STRIDE** | Information Disclosure |
| **Severity** | **High** |
| **Description** | The `--unsafe` mode (triggered by `UNSAFE_CA=1` MSI checkbox) generates a CA **without** X.509 Name Constraints. This CA can sign valid certificates for **any** domain on the internet — banking, healthcare, email, corporate SSO. If the CA private key is later compromised (stolen by malware, exfiltrated via DPAPI decryption, leaked in backup), the attacker can MITM **all** TLS traffic from that machine, not just AI domains. This is a "blast radius" expansion from "AI domains only" to "the entire internet." |
| **Attack vector** | User enables `--unsafe` checkbox; CA key is compromised later; attacker uses unrestrained CA to MITM any domain. |
| **Mitigation** | `UNSAFE_CA` checkbox must be **unchecked by default** (opt-in). The checkbox must be clearly labeled: "Skip domain restrictions (reduces security)". Selecting it must trigger the interactive warning banner in `ca-init` (DPO R7): explicit English-language warning explaining the risk, requiring stdin confirmation. The MSI dialog should also surface this warning text. Regular (default) mode generates Name Constraints from provider domains — this limits the CA to AI domains even if the key is compromised. |
| **Residual** | Some Chrome/Edge versions may not fully respect Name Constraints (making the default mode non-functional). The `--unsafe` option is a necessary compatibility escape hatch. Users who enable it accept the expanded risk. This caveat is tracked as DPO C3. |

### T8 — ACL TOCTOU on `%PROGRAMDATA%\Qindu\`
| Attribute | Detail |
|---|---|
| **STRIDE** | Information Disclosure |
| **Severity** | **Medium** |
| **Description** | The `%PROGRAMDATA%\Qindu\` directory is created and then ACL-restricted. If there is a time window between directory creation and ACL application, a non-admin process could enumerate or create files in the directory before it's locked down. Similarly, `agent.exe ca-init` writes `ca.key` and `ca.crt` to `%PROGRAMDATA%\Qindu\` — the ACL must be in place **before** these writes, or the files may inherit permissive parent-directory permissions. |
| **Attack vector** | Racing directory creation with file enumeration; inheriting `Authenticated Users` read from `%PROGRAMDATA%\` before ACL is applied; CA key written with world-readable permissions because directory ACL was not yet set. |
| **Mitigation** | WiX `<CreateFolder>` with `<Permission>` elements must apply ACL **atomically** with directory creation (WiX v3/v4 `<util:PermissionEx>` or native `<Permission>` supports this). CA key file written by `ca-init` must use `os.WriteFile` with `0600` permissions (owner read/write only) — this is the innermost permission envelope regardless of directory ACL. |
| **Residual** | `0600` file permission + directory ACL is defense-in-depth. Even if directory ACL fails, the file itself is `0600`. The DPAPI encryption layer provides further protection (file content is encrypted). |

### T9 — CI Supply Chain: Windows Runner and WiX Toolset
| Attribute | Detail |
|---|---|
| **STRIDE** | Tampering |
| **Severity** | **Low** |
| **Description** | The CI pipeline uses GitHub Actions `windows-latest` runner and installs WiX Toolset via `choco install wixtoolset -y`. The `choco` feed and the WiX Toolset binary could be compromised, injecting malicious behavior into the MSI build process. The runner itself is managed by GitHub and could be compromised (low probability, high impact). |
| **Attack vector** | Compromised WiX Toolset chocolatey package; compromised GitHub Actions runner image; malicious PR that modifies CI workflow to exfiltrate signing material (not applicable: no signing in QINDU-0002). |
| **Mitigation** | WiX Toolset is an open-source Microsoft project. Pin to a specific version in CI (`choco install wixtoolset --version=3.14.1 -y`). The MSI is built from auditable WiX source files in the repo — even if WiX is compromised, the MSI structure is deterministic and can be inspected. No secrets (signing keys, CA keys) are present in CI at this stage. |
| **Residual** | This is a general CI supply-chain risk, not specific to Qindu. Future sprints: Authenticode signing will use a dedicated, tightly-controlled signing pipeline. |

### T10 — Service Binary Path Hijacking (Unquoted Service Path)
| Attribute | Detail |
|---|---|
| **STRIDE** | Elevation of Privilege |
| **Severity** | **Medium** |
| **Description** | When the WiX `<ServiceInstall>` creates the `QinduAgent` service, the binary path is set to `%PROGRAMFILES%\Qindu\agent.exe`. If the path or any parent directory contains spaces (e.g., `C:\Program Files\Qindu\agent.exe`), Windows may interpret an unquoted path as multiple possibilities: `C:\Program.exe`, `C:\Program Files\Qindu\agent.exe`. An attacker who can write to `C:\Program.exe` (requires admin) could hijack the service. This is a well-known Windows privilege escalation vector (CWE-428). |
| **Attack vector** | Unquoted service binary path; attacker with write access to a parent directory places a malicious executable at the misparsed path. |
| **Mitigation** | The WiX `<ServiceInstall>` element must use a **quoted** binary path: `"C:\Program Files\Qindu\agent.exe"` (with quotes). WiX v3/v4 typically quotes paths automatically when using `<File>` references, but this must be verified. Alternatively, the service can be installed with `Start="auto"` and `Account="NT AUTHORITY\LocalService"`. |
| **Residual** | WiX `<ServiceInstall>` with `<File>` key references generally handles quoting correctly. QA must verify via `sc qc QinduAgent` that the `BINARY_PATH_NAME` is quoted. |

---

## Protected Assets

| Asset | Sensitivity | Storage | Access Control | Lifespan |
|---|---|---|---|---|
| CA Root Private Key (ECDSA P-256) | **Critical** | Disk: `%PROGRAMDATA%\Qindu\ca.key` (DPAPI-encrypted) | ACL: SYSTEM + Administrators + LocalService; `0600` file perms | 10 years (configurable via `ca_validity_years`) |
| CA Root Certificate (public) | **Medium** | Disk: `%PROGRAMDATA%\Qindu\ca.crt` + Windows machine trust store | ACL: same as key (not secret, but integrity important) | 10 years |
| MSI Installer Binary | **High** | GitHub Actions artifact; user's download location | File hash verification on download (manual) | Per-release |
| `agent.exe` Binary | **High** | `%PROGRAMFILES%\Qindu\agent.exe` | Standard Program Files ACL (readable by all, writable by admin) | Until upgrade/uninstall |
| `configs/default.yaml` | **Low** | `%PROGRAMFILES%\Qindu\configs\default.yaml` | Standard Program Files ACL | Until upgrade overwrites |
| Config Override `config.yaml` | **Low** | `%PROGRAMDATA%\Qindu\config.yaml` | ACL-restricted directory (R6) | User-managed |
| Registry Policies (Chrome/Edge) | **Low** | `HKLM\Software\Policies\...` | HKLM (admin-write only) | Until uninstall |
| Firewall Rules | **Low** | Windows Firewall store | Admin-only modification | Until uninstall |
| Installer Logs (MSI verbose) | **Medium** | `%TEMP%\MSI*.log` (if `/l*v` is used) | User's temp directory | Ephemeral |
| Uninstall Consent (DELETEDATA property) | **Low** | Transient in MSI session | MSI session only | Duration of uninstall |
| Service Account Context | **Medium** | `NT AUTHORITY\LocalService` SID | System-defined | Service lifetime |

---

## Security Requirements

### SR-INSTALLER-1 — CA Key Encrypted Before Any Disk Write (Critical)
**OWASP ASVS**: V6.2.1, V6.4.1
**Extends**: QINDU-0001 SR1

**Requirement**: The `agent.exe ca-init` subcommand must encrypt the CA private key via DPAPI before writing it to `%PROGRAMDATA%\Qindu\ca.key`. The plaintext key must never touch disk — not even in a temporary file, not in a swap-backed buffer, not in an MSI log, and not in CustomAction output. The encryption sequence must be: generate key in memory → DPAPI encrypt → `os.WriteFile` with `0600` permissions. The encrypted blob must be the **only** form of the key stored on disk.

**Rationale**: The CA key is the highest-value asset in the Qindu architecture. The installer passes through multiple subsystems (MSI engine, CustomAction host, `agent.exe` process, Windows filesystem). Each boundary is a potential leak point. DPAPI-before-write must be enforced in the `ca-init` code path, not deferred to later proxy startup. If a CustomAction writes the key plaintext and DPAPI is applied later by the proxy, a verbose MSI log (`/l*v`) or a crash dump would expose it.

**Verification**:
- Review `cmd/agent/main.go` `runCAInit` for the write sequence — DPAPI encrypt must precede `os.WriteFile` to the key path.
- Confirm the `internal/tls/ca.go` `SaveCA` path encrypts before writing (reused from QINDU-0001 — verify no regression).
- Grep WiX CustomAction `ExeCommand` for any `--debug-print-key`, `--export-key`, or verbose flags on `ca-init` that could produce key output.
- QA test: run `msiexec /i Qindu-Installer-x64.msi /l*v install.log` and grep for `PRIVATE KEY`, `BEGIN EC`, hex key patterns. Zero matches required. (Matches DPO TS2.)

---

### SR-INSTALLER-2 — `certutil` Must Use Absolute Path; CA Certificate Integrity Verified Before Trust Store Install (Critical)
**OWASP ASVS**: V5.1.1 (path sanitization)

**Requirement**: The WiX CustomAction invoking `certutil` to add/remove the CA from the Windows trust store must:
- Use the absolute path `%SystemRoot%\System32\certutil.exe` (not just `certutil`) to prevent PATH hijacking.
- Add: `certutil -addstore Root "%PROGRAMDATA%\Qindu\ca.crt"` — the path must be absolute and quoted.
- Remove: `certutil -delstore Root "Qindu AI Privacy CA"` — removal by **CA Common Name**, not by file path.
- The CA certificate file (`ca.crt`) must exist and be non-empty before `certutil -addstore` executes.
- The `certutil` exit code should be logged (if feasible in WiX) but non-zero exit on CA already present (upgrade scenario) must not fail the install.

**Rationale**: `certutil` is a SYSTEM-privileged tool. If an attacker redirects `certutil` to a malicious binary via PATH poisoning, they can install arbitrary CAs. Absolute path invocation mitigates this. Removal by Common Name ensures clean uninstall even if `ca.crt` has been deleted. Non-zero exit on upgrade (CA already present) is expected and must not block.

**Verification**:
- Inspect `installer/wix/includes/ca-trust.wxs` and `cleanup.wxs` for the exact `certutil` command strings.
- Confirm absolute path `%SystemRoot%\System32\certutil.exe` is used.
- Confirm removal uses `"Qindu AI Privacy CA"` (Common Name from `configs/default.yaml` `tls.ca_name`).
- Confirm the `ca-init` CustomAction executes **before** the `certutil` CustomAction in the WiX `InstallExecuteSequence`.

---

### SR-INSTALLER-3 — Unsafe CA Mode: Unchecked by Default, Gated Behind Interactive Warning (High)
**OWASP ASVS**: V2.1.1 (security controls opt-in), V4.1.2 (least privilege)

**Requirement**: The `UNSAFE_CA` MSI checkbox (controlling whether `agent.exe ca-init --unsafe` is invoked) must be:
- **Unchecked by default** in the MSI dialog.
- Clearly labeled with a warning message: "Skip domain restrictions (reduces security — the CA will be able to intercept ANY website, not just AI services)."
- When checked, must pass `UNSAFE_CA=1` to the CustomAction, which invokes `agent.exe ca-init --unsafe`.
- `ca-init --unsafe` must display an interactive English-language warning banner via stdout (DPO R7) that clearly states the risk of a CA with no Name Constraints, and must require explicit `stdin` confirmation (type "yes" or "I understand") before proceeding.
- If `ca-init --unsafe` runs in a non-interactive context (e.g., MSI silent install `/quiet`), it must **fail** with an error message — it must not proceed with the unsafe CA without explicit confirmation.

**Rationale**: A CA without Name Constraints can sign certificates for any domain. If the key is ever compromised, the attacker can MITM banking, healthcare, email, and SSO traffic — not just AI domains. The unchecked-by-default checkbox ensures consent is affirmative (GDPR Art. 4(11), Art. 7; DPO R7). The interactive confirmation prevents accidental activation through scripts or silent installs.

**Verification**:
- Inspect `installer/wix/includes/dialogs.wxs` for the `UNSAFE_CA` checkbox: confirm `CheckboxValue` defaults to off.
- Review `cmd/agent/main.go` `runCAInit` for the `--unsafe` flag handling: confirm interactive prompt appears, requires stdin input, and refuses to proceed in non-interactive mode.
- QA test: run `agent.exe ca-init --unsafe` with stdin not a terminal (pipe/redirect) — verify it fails.
- QA test: run MSI installer UI — verify `UNSAFE_CA` checkbox is unchecked by default (DPO TS5).

---

### SR-INSTALLER-4 — Firewall Rules: Loopback Allow Must Have Higher Priority Than Block (High)
**OWASP ASVS**: V4.1.1 (network segmentation)

**Requirement**: The firewall CustomActions must create two rules:
1. **Allow Loopback**: `netsh advfirewall firewall add rule name="Qindu Agent (Allow Loopback)" dir=in action=allow remoteip=127.0.0.1,::1 localport=8787 protocol=TCP`
2. **Block External**: `netsh advfirewall firewall add rule name="Qindu Agent (Block External)" dir=in action=block remoteip=any localport=8787 protocol=TCP`

The allow rule must be evaluated **before** the block rule. This can be achieved by:
- Inserting the allow rule first (Windows firewall evaluates rules in order of creation within the same group by default), **OR**
- Using explicit `profiling` or rule ordering attributes to force priority.

During uninstall, both rules must be removed by exact name match:
- `netsh advfirewall firewall delete rule name="Qindu Agent (Allow Loopback)"`
- `netsh advfirewall firewall delete rule name="Qindu Agent (Block External)"`

**Rationale**: If the block rule takes priority, loopback traffic on port 8787 is blocked — the proxy becomes unreachable. The allow rule must win on loopback IPs. Uninstall cleanup must not leave orphaned firewall rules that permanently block port 8787.

**Verification**:
- Inspect `installer/wix/includes/firewall.wxs` for exact `netsh` commands.
- Confirm rule names are consistent between install and uninstall CustomActions.
- QA test TS10: verify both rules exist with correct parameters post-install.
- QA test TS9: verify `curl http://127.0.0.1:8787/health` succeeds post-install (rules don't block loopback).
- Uninstall QA (TS6): verify both rules are absent after uninstall.

---

### SR-INSTALLER-5 — No Secrets, Keys, or PII in MSI Logs or CustomAction Output (Critical)
**OWASP ASVS**: V7.1.1, V7.1.2
**Extends**: QINDU-0001 SR5

**Requirement**: The MSI installer logs (WiX session logs, CustomAction stdout/stderr, `msiexec /l*v` verbose logs) must **never** contain:
- CA private key material (PEM, DER, hex, base64, or any representation)
- CA certificate serial number (acceptable — this is a public x509 field, but caution)
- Configuration secrets (none exist in this sprint)
- Any representation of cryptographic key bytes
- Any PII (none processed in this sprint, but rule constrains future changes)

CustomAction `ExeCommand` strings in the WiX source must not contain verbose flags (`--verbose`, `--debug`, `-v`) that would increase log output from `ca-init`. `agent.exe ca-init` must use only `slog.Info` level for status messages — no `slog.Debug` that could include CA metadata.

**Rationale**: Users and support staff may share MSI verbose logs for troubleshooting. These logs capture CustomAction output. A CA private key in an MSI log shared on a forum or support ticket would be catastrophic. Prevention is mandatory.

**Verification**:
- Review `cmd/agent/main.go` `runCAInit` for all `slog.Info`, `slog.Debug`, `fmt.Printf` calls — confirm none include key material.
- Inspect WiX CustomAction `ExeCommand` strings for flags passed to `ca-init` — confirm none trigger debug output.
- QA test TS2: run `msiexec /i installer.msi /l*v install.log` and grep for `PRIVATE KEY`, `EC PRIVATE`, `BEGIN EC`, hex dumps. Zero matches required.
- Review-mode grep for `ca-init` code: all log calls must use structured keys (`"ca_name"`, `"providers"`), never key bytes.

---

### SR-INSTALLER-6 — Service Binary Path Must Be Quoted (Medium)
**OWASP ASVS**: V5.1.1 (CWE-428 unquoted search path)

**Requirement**: The WiX `<ServiceInstall>` element that creates the `QinduAgent` service must use a quoted binary path. When inspecting the installed service via `sc qc QinduAgent`, the `BINARY_PATH_NAME` must be `"C:\Program Files\Qindu\agent.exe"` (with double quotes), not `C:\Program Files\Qindu\agent.exe` (unquoted). The service must run under `NT AUTHORITY\LocalService` (not `LocalSystem` / `SYSTEM`).

**Rationale**: Unquoted service paths are a classic Windows privilege escalation vector. If the path is `C:\Program Files\Qindu\agent.exe` (unquoted), Windows would also search for `C:\Program.exe` and `C:\Program Files\Qindu\agent.exe`. An admin-level attacker who writes a malicious `C:\Program.exe` (unlikely but possible in misconfigured systems) could hijack the service. `LocalService` is the least-privileged viable account.

**Verification**:
- Inspect `installer/wix/includes/service.wxs` for `<ServiceInstall>` attributes: confirm `Account="NT AUTHORITY\LocalService"`, `Start="auto"`.
- Confirm the service references a WiX `<File>` element — WiX auto-quotes file-derived paths. If a raw string is used, verify it is quoted.
- QA test: after install, run `sc qc QinduAgent` and verify `BINARY_PATH_NAME` is quoted and `SERVICE_START_NAME` is `NT AUTHORITY\LocalService`.

---

### SR-INSTALLER-7 — Uninstall Data Deletion: Conditional on Explicit Opt-In Only (High)
**OWASP ASVS**: V2.1.1 (user consent for data operations)

**Requirement**: The uninstall dialog checkbox for data deletion (`DELETEDATA`) must:
- Be **unchecked by default** (opt-in, not opt-out).
- Map the checkbox value to the MSI property `DELETEDATA` (value `"1"` when checked, unset when unchecked).
- The `RemoveFolderEx` CustomAction for `%PROGRAMDATA%\Qindu\` must execute **only** when `DELETEDATA="1"`.
- When `DELETEDATA` is not set (unchecked), `%PROGRAMDATA%\Qindu\` must be **preserved**.
- The checkbox label must clearly state: "Delete all Qindu data (vault, logs, and configuration)".

**Rationale**: The `%PROGRAMDATA%\Qindu\` directory will contain the vault (PII token mappings in future sprints). GDPR Art. 17 (right to erasure) requires users to be able to delete their data. GDPR Art. 4(11) requires consent to be unambiguous and affirmative — pre-checking the box would violate this. Additionally, users may want to reinstall Qindu and retain their vault/tokens.

**Verification**:
- Inspect `installer/wix/includes/dialogs.wxs` for `DELETEDATA` checkbox: confirm `CheckboxValue` is off by default.
- Inspect `installer/wix/includes/cleanup.wxs` for `RemoveFolderEx`: confirm it is guarded by `<Condition>DELETEDATA=1</Condition>` or equivalent.
- QA test TS7: uninstall without checking → `%PROGRAMDATA%\Qindu\` preserved.
- QA test TS6: uninstall with `DELETEDATA=1` → directory deleted.
- QA test TS8: verify checkbox is unchecked by default in uninstall UI.

---

### SR-INSTALLER-8 — ACL on `%PROGRAMDATA%\Qindu\` Applied Atomically (Medium)
**OWASP ASVS**: V4.1.1 (file permission enforcement)

**Requirement**: The `%PROGRAMDATA%\Qindu\` directory must have ACLs restricting access to:
- `NT AUTHORITY\SYSTEM` (Full Control)
- `BUILTIN\Administrators` (Full Control)
- `NT AUTHORITY\LocalService` (Read/Write — the service account)

The following must be **excluded**: `Authenticated Users`, `Users`, `Everyone`, `BUILTIN\Users`.

The ACL must be applied **before** `agent.exe ca-init` writes `ca.key` and `ca.crt` to this directory. If WiX `<CreateFolder>` with `<Permission>` is used, the ACL is applied atomically with directory creation. If `ca-init` creates the directory, it must set the ACL before writing files.

**Rationale**: File permissions (`0600` on `ca.key`) provide inner-layer protection, but directory ACL is defense-in-depth. If the directory is created with inherited permissions from `%PROGRAMDATA%\` (which typically includes `Users`), non-admin users could enumerate the directory, discover Qindu's presence, and potentially access config/log files. DPAPI prevents key decryption but information leakage about Qindu's existence is also a concern.

**Verification**:
- Inspect `installer/wix/includes/files.wxs` for `<CreateFolder>` with `<Permission>` elements on `%PROGRAMDATA%\Qindu\`.
- If ACL is set by `ca-init`, review `cmd/agent/main.go` for `SetNamedSecurityInfo` or `icacls` calls.
- QA test TS11: run `icacls "%PROGRAMDATA%\Qindu"` and verify only SYSTEM, Administrators, and LocalService are listed. Verify `Authenticated Users` and `Everyone` are absent.

---

### SR-INSTALLER-9 — No Telemetry, Phoning Home, or External Connections (Critical)
**OWASP ASVS**: V1.14.3 (no backdoors)
**Extends**: QINDU-0001 SR5 (indirectly), DPO R3, DPO R10

**Requirement**: The installer, the `agent.exe ca-init` subcommand, the Windows service, and all WiX CustomActions must not:
- Initiate any outbound network connection except to AI service destinations through the proxy pipeline (once running as a service)
- Transmit installation telemetry, usage statistics, crash reports, or machine identifiers
- Include a persistent installation ID, machine hash, device fingerprint, or tracking UUID
- Check for updates by contacting any external server
- Embed any analytics SDK or beacon

**Rationale**: Non-negotiable architectural constraint (AGENTS.md, ADR-008, QINDU-0001). The installer is a new code delivery vehicle and must not subvert this principle.

**Verification**:
- Review `cmd/agent/main.go` (both service path and `ca-init` path) for any `http.Get`, `http.Post`, `net.Dial` to non-localhost addresses.
- Grep entire codebase for `uuid.New`, `machineid`, `device_id`, `installation_id`, `analytics`, `telemetry`, `track`, `beacon`, `crash-report`, `update.qindu`.
- Inspect WiX CustomAction `ExeCommand` strings for any `curl`, `wget`, `Invoke-WebRequest`, or PowerShell remote calls.
- QA test TS13: grep codebase for telemetry endpoints — zero matches.

---

### SR-INSTALLER-10 — CustomAction ExeCommand Must Not Interpolate Unsanitized User Input (Medium)
**OWASP ASVS**: V5.1.5 (command injection prevention)

**Requirement**: WiX CustomAction `ExeCommand` strings must only interpolate MSI properties that are:
- Hardcoded in the WiX source (e.g., `[PROGRAMFILES]`, `[PROGRAMDATA]`, `[SystemFolder]`), **OR**
- Boolean-enumerated values (`UNSAFE_CA` = exactly `"1"` or unset; `DELETEDATA` = exactly `"1"` or unset).

No other MSI properties, especially user-configurable Public Properties or properties derived from dialog input fields, may be interpolated into `ExeCommand`. The `agent.exe ca-init --config` path must be hardcoded or derived from `[PROGRAMFILES]`, not from an arbitrary user-supplied property.

**Rationale**: CustomActions run with elevated privileges. Command injection in a CustomAction can execute arbitrary commands as SYSTEM. While WiX `ExeCommand` uses `CreateProcess` (not `cmd.exe /c`), invalid paths or unexpected characters can still cause unintended behavior.

**Verification**:
- Review all `installer/wix/includes/*.wxs` files containing `ExeCommand` attributes.
- Confirm only `[PROGRAMFILES]`, `[PROGRAMDATA]`, `[SystemFolder]`, `UNSAFE_CA`, `DELETEDATA` are used in command strings.
- Confirm no `[CONFIG_PATH]`, `[USER_INPUT]`, or arbitrary Public Properties are interpolated.
- List all CustomAction `ExeCommand` values in a review table.

---

### SR-INSTALLER-11 — `ca-init` Name Constraints Must Derive from Provider Config (Medium)
**OWASP ASVS**: V2.1.1 (least privilege), V9.1.1 (TLS scope)
**Extends**: QINDU-0001 SR6 (MITM scope enforcement)
**Aligns**: ADR-003 (single CA, Name Constraints addition)

**Requirement**: When `agent.exe ca-init` runs in normal mode (no `--unsafe`), the generated CA certificate must include the X.509 **Name Constraints** extension (OID 2.5.29.30) with `PermittedDNSDomains` populated from the provider domain list in the configuration YAML. For each provider domain (e.g., `chatgpt.com`), the constraint must be the domain itself and its wildcard parent (`chatgpt.com`, not `*.chatgpt.com` — per RFC 5280, Name Constraints use the domain subtree, not wildcard notation, but the effective constraint is the subtree).

Specifically, the CA certificate must constrain itself to:
- `chatgpt.com` (allows `chatgpt.com`, `*.chatgpt.com`, `cdn.chatgpt.com`)
- `claude.ai` (allows `claude.ai`, `*.claude.ai`)

Any other domains not in the config must be rejected by the browser when the CA tries to sign a leaf certificate for them.

**Rationale**: Name Constraints are the technical enforcement of the "least decrypt" principle. Even if the CA private key is stolen, the attacker can only impersonate AI provider domains — not banking, healthcare, email, or SSO domains. This is a critical defense-in-depth measure (DPO R7, DPO C3). The constraints must derive from the provider config, not be hardcoded, to ensure future provider additions automatically get constraints.

**Verification**:
- Review `cmd/agent/main.go` `runCAInit`: confirm `x509.Certificate.PermittedDNSDomains` is populated from `cfg.Providers` when `!unsafe`.
- QA test TS3: after installation, `certutil -dump "%PROGRAMDATA%\Qindu\ca.crt"` shows `Application Constraints` / `Name Constraints` with `chatgpt.com` and `claude.ai`.
- Unit test: generate CA with test providers, verify `PermittedDNSDomains` in the certificate.
- Confirm `PermittedDNSDomainsCritical` is `false` (non-critical extension — browsers that don't support it will still work, albeit without constraint enforcement).

---

### SR-INSTALLER-12 — `agent.exe ca-init` Must Destroy and Replace Existing CA (Medium)
**OWASP ASVS**: V6.2.4 (key lifecycle management)

**Requirement**: When `agent.exe ca-init` runs (whether during fresh install or upgrade), it must destroy the **entire** existing CA (key + certificate) in `%PROGRAMDATA%\Qindu\` before generating a new one. The sequence must be:
1. Check if `ca.key` exists → if yes, securely overwrite or delete before generating new key.
2. Generate new CA key + certificate.
3. Write new encrypted `ca.key` + `ca.crt`.

If `ca.crt` exists but `ca.key` does not (corrupted state), `ca-init` must still generate a fresh CA and overwrite the stale certificate. No copy of the old CA key may remain.

**Rationale**: During upgrades, the old CA (which may have Name Constraints for a different set of providers) must be fully replaced. Leaving an orphaned old CA key on disk creates a shadow CA that could be exploited. For forward security, old CA keys must not persist.

**Verification**:
- Review `cmd/agent/main.go` `runCAInit` for the existence check and overwrite logic.
- Unit test: create a dummy `ca.key` file, run `ca-init`, verify the old file is replaced (inode changes, content changes).
- QA test TS18: run `agent.exe ca-init` twice, verify only one CA key exists, content differs between runs.

---

### SR-INSTALLER-13 — Path Resolution Must Not Traverse Outside Approved Directories (Medium)
**OWASP ASVS**: V5.1.3 (path traversal prevention)

**Requirement**: The path resolution logic in `cmd/agent/main.go` (story lines 57–63) must validate all resolved paths to prevent directory traversal. Specifically:
- The `--config` flag and `QINDU_CONFIG` env var must resolve to a path within `%PROGRAMFILES%\Qindu\` or `%PROGRAMDATA%\Qindu\` (or a working directory for dev fallback). Paths containing `..` that traverse outside these directories must be rejected.
- The `%PROGRAMDATA%\Qindu\` path for CA key/cert/logs must be computed from `%PROGRAMDATA%` (Windows) or `./data/` (fallback), not user-overridable to arbitrary locations.
- The `agent.exe ca-init --config <path>` must validate that the config file path is within an approved directory.

**Rationale**: If an attacker can point `--config` to a malicious YAML file in a world-writable directory (e.g., `%TEMP%\evil.yaml`), they can expand the MITM scope by adding arbitrary domains to the provider list, or set `upstream_validation: "insecure"` to disable TLS verification. Path traversal in `ca-init` could also cause certificate files to be written to unexpected locations.

**Verification**:
- Review `cmd/agent/main.go` path resolution code for `filepath.Clean`, `strings.Contains("..")` checks, or `filepath.IsAbs` validation.
- Unit test: `agent.exe ca-init --config "../../etc/evil.yaml"` → rejected.
- Unit test: `agent.exe ca-init --config "/tmp/evil.yaml"` → accepted only if `/tmp/` is an approved dev path; on Windows service path, reject non-`%PROGRAMFILES%`/`%PROGRAMDATA%` paths.
- Grep for `os.Getenv("PROGRAMDATA")` usage — confirm it is not overridable by attacker-controlled env vars.

---

### SR-INSTALLER-14 — Silent Install Must Not Proceed with Unsafe CA (Medium)
**OWASP ASVS**: V2.1.1 (informed consent)

**Requirement**: If the MSI is installed in silent/quiet mode (`msiexec /i Qindu-Installer-x64.msi /quiet` or `/qn`), and the `UNSAFE_CA` property is set to `"1"`, the installation must **fail** with an error. Silent installs cannot present the interactive `ca-init` warning banner (SR-INSTALLER-3), so unsafe CA generation cannot obtain informed consent.

Silent install without `UNSAFE_CA=1` (normal constrained CA) is acceptable.

**Rationale**: The `ca-init --unsafe` interactive warning is the only consent mechanism for unsafe CA generation. Silent installs bypass this consent. An organization deploying Qindu via SCCM/GPO must not accidentally deploy an unconstrained CA.

**Verification**:
- Implement in WiX: `<Condition>NOT (UNSAFE_CA=1 AND UILevel=2)</Condition>` or similar check that blocks silent + unsafe.
- Alternatively, implement in `agent.exe ca-init --unsafe`: if stdin is not a terminal (non-interactive), refuse with error.
- QA test: `msiexec /i installer.msi /quiet UNSAFE_CA=1` → install fails.

---

### SR-INSTALLER-15 — CI Build: MSI Must Be Reproducible and Versioned (Low)
**OWASP ASVS**: V10.3.1 (build integrity)

**Requirement**: The CI pipeline (`windows-latest` job) must:
- Build `agent.exe` from the same source commit that triggered the build (no separate binary download).
- Compile the WiX source files from the same repository commit.
- Produce `Qindu-Installer-x64.msi` tagged with the release version (from git tag).
- Publish the MSI as a GitHub Actions artifact with a checksum (`sha256sum`).
- The MSI `ProductVersion` must match the git tag version.

**Rationale**: Supply chain integrity. Users must be able to verify the MSI was built from a specific, auditable commit. Checksums allow verification after download. Version matching prevents confusion about what code is in the installer.

**Verification**:
- Inspect `.github/workflows/` for the `build-msi` job.
- Confirm `agent.exe` is compiled from `./cmd/agent/` in the build step (not downloaded).
- Confirm WiX `candle` and `light` run on the in-repo `.wxs` files.
- Verify artifact upload includes `Qindu-Installer-x64.msi` and a `sha256sum.txt`.
- Confirm `ProductVersion` is extracted from the git tag via WiX preprocessor variable.

---

### SR-INSTALLER-16 — `agent.exe ca-init` Must Not Log CA Key, Certificate, or Serial Number at DEBUG Level (Medium)
**OWASP ASVS**: V7.1.1, V7.1.2
**Extends**: QINDU-0001 SR5

**Requirement**: `ca-init` may log informational status messages at `slog.Info` level (e.g., `"CA generation complete"`, `"providers: chatgpt.com, claude.ai"`). However, it must not log at **any** log level:
- CA private key material (PEM, DER, hex, or any representation)
- The full CA certificate PEM (certificate metadata like Common Name is acceptable)
- The CA certificate serial number (acceptable — this is an x509 public field)
- The `ca.key` file path (this reveals the key location — acceptable at `Info` level on a local-only agent)

The `ca-init` subcommand must respect the same logging hygiene rules as the proxy (QINDU-0001 SR5).

**Rationale**: If verbose logging is enabled for debugging (`--log-level debug`), the key must still not appear. Users may share debug logs for support — they must not accidentally share the CA key. The path is consistent with DPO R2 and QINDU-0001 SR5.

**Verification**:
- Review all `slog.Info`, `slog.Debug`, `slog.Warn`, `fmt.Printf` calls in `cmd/agent/main.go` `runCAInit` and related functions.
- Confirm no key material passed to log functions.
- Unit test: run `ca-init` with `--log-level debug`, capture stderr, grep for `PRIVATE KEY`, `BEGIN EC`, key hex. Zero matches required.

---

### SR-INSTALLER-17 — QINDU-0001 Security Findings Must Be Addressed or Explicitly Deferred (Low)
**References**: QINDU-0001 `ciso-review.md` SEC-F1 through SEC-F4

**Requirement**: The four security findings from QINDU-0001 review (SEC-F1: MITM dial timeout, SEC-F2: silent write error, SEC-F3: SystemCertPool error discarded, SEC-F4: panic on non-ECDSA CA key) must be:
- **Addressed in this sprint** if they are within scope of `cmd/agent/main.go` or `internal/tls/ca.go` modifications, **OR**
- **Documented as explicitly deferred** in `dev-notes.md` with a target sprint.

At minimum, SEC-F4 (panic on non-ECDSA key at `ca_helper.go:78`) is in scope because `ca-init` reuses `internal/tls/ca.go` and must be resilient to corrupted CA files.

**Rationale**: These are non-blocking quality findings from QINDU-0001. Fixing them improves robustness. Tracking them ensures they are not forgotten.

**Verification**:
- Review `cmd/agent/main.go` `runCAInit` — if it calls `parseCAFromPEM`, confirm it uses the comma-ok type assertion (SEC-F4).
- Review `dev-notes.md` for explicit mention of which SEC-F1–SEC-F4 items are fixed vs. deferred.
- If SEC-F1 (dial timeout) is deferred, confirm `dev-notes.md` documents the target sprint.

---

## Compliance with Existing SRs (QINDU-0001)

The following security requirements from QINDU-0001 remain applicable and must not be regressed by QINDU-0002 changes:

| SR | Title | Status | Notes |
|---|---|---|---|
| SR1 | CA Key Encrypted at Rest | ✅ **Sustained** | `ca-init` reuses `internal/tls/ca.go` `SaveCA` — must use DPAPI-before-write path. SR-INSTALLER-1 reinforces this for the installer context. |
| SR2 | Leaf Certificates Ephemeral Only | ✅ **Sustained** | No changes to leaf cert generation. `ca-init` does not generate leaf certs. |
| SR3 | Upstream TLS Not Disabled by Default | ✅ **Sustained** | `ca-init` does not modify TLS config. Default `upstream_validation: "system"` remains. No `InsecureSkipVerify` in default config. |
| SR4 | Proxy Binds to Loopback Exclusively | ✅ **Sustained** | `listen_addr: "127.0.0.1"` in `default.yaml`. No config changes that weaken loopback enforcement. Path resolution (story line 58–63) must not allow non-default configs to override listen address to a non-loopback value without validation (config validation in `internal/policy/config.go` handles this). |
| SR5 | Zero PII in Logs | ✅ **Sustained** | Extended by SR-INSTALLER-16 for `ca-init` logging. No PII in installer or proxy logs. |
| SR6 | Config-Directed MITM Scope Enforcement | ✅ **Sustained** | Provider domain list from config remains the sole MITM routing source. Config override (`%PROGRAMDATA%\Qindu\config.yaml`) can expand scope — this is an admin-only feature (ACL-restricted directory per SR-INSTALLER-8). |
| SR7 | NoOp Interceptor Strictly Transparent | ✅ **Sustained** | No interceptor changes in this sprint. |
| SR8 | Concurrency Safety | ✅ **Sustained** | No changes to cert cache. `go test -race` must still pass. |
| SR9 | Graceful Shutdown Integrity | ✅ **Sustained** | Service stop handler (ADR-006) must trigger `http.Server.Shutdown(ctx)`. `sc stop QinduAgent` must drain connections within 30s. SR-INSTALLER-6 ensures LocalService context. |
| SR10 | PAC File Security | ✅ **Sustained** | PAC generation unchanged. Browser policy writes (Chrome/Edge) must point to `http://127.0.0.1:8787/proxy.pac` — verified by SR-INSTALLER-18. |

### SR-INSTALLER-18 — PAC URL in Browser Policies Must Be Localhost Only (Medium)
**OWASP ASVS**: V4.1.1
**Extends**: QINDU-0001 SR10

**Requirement**: The browser policy registry writes (Chrome `ProxyPacUrl` and Edge `ProxyPacUrl`) must be `http://127.0.0.1:8787/proxy.pac` — no external host, no DNS name that could be poisoned, no config-driven substitution.

**Rationale**: The PAC URL determines where the browser fetches its proxy configuration. If it points to an external host, an attacker could serve a malicious PAC file that redirects AI traffic elsewhere. Localhost guarantees it is served by the locally-running Qindu proxy.

**Verification**:
- Inspect `installer/wix/includes/registry-chrome.wxs` and `registry-edge.wxs`: confirm `ProxyPacUrl` value is the literal string `http://127.0.0.1:8787/proxy.pac`.
- QA test TS12: verify registry values match.

---

## Quarantine: Non-Blocking Concerns

### Q1 — No Authenticode Code Signing (Supply Chain)
The MSI is unsigned in QINDU-0002. Windows SmartScreen will warn users. This degrades trust UX and makes supply-chain verification impossible for non-technical users. Tracked per story exclusion line 87 and DPO C1. A dedicated release sprint must add Authenticode signing before production distribution.

### Q2 — MSI Rollback May Leave Partial Trust Store State
If the MSI fails partway through installation (e.g., `certutil -addstore` succeeds but service creation fails), Windows triggers a rollback. The rollback script must reverse all completed actions. If rollback is incomplete, the trust store may retain the Qindu CA without the proxy being functional — creating a latent trust relationship with no active proxy to manage it. MSI rollback is limited; manual cleanup may be needed.

### Q3 — No Runtime Integrity Verification of `agent.exe`
Once installed, `agent.exe` has no self-integrity check (no embedded hash, no signature verification at startup). A local admin attacker could replace `agent.exe` with a malicious binary that exfiltrates decrypted traffic. This is outside the local trust boundary (admin owns the machine) but worth noting for future hardening (e.g., Windows Defender Application Control, AppLocker).

### Q4 — `certutil` Non-Zero Exit on Upgrade
During upgrade, if the CA is already in the trust store, `certutil -addstore` will return a non-zero exit code (duplicate entry). The MSI must not treat this as a fatal error. Conversely, if `certutil` fails for a legitimate reason (no permission, Windows Trust Store corruption), the MSI should detect this — but WiX `ExeCommand` return codes are difficult to handle granularly.

### Q5 — Config Override Expands MITM Scope
The `%PROGRAMDATA%\Qindu\config.yaml` shallow-merge override (story line 63) allows an admin to add arbitrary domains to the provider list, expanding the MITM scope beyond AI services. This is a feature, not a bug (per ADR-005, config is the source of truth). However, it should be documented clearly: modifying provider domains expands TLS interception to those domains. ACL restrictions (SR-INSTALLER-8) limit write access to admins.

### Q6 — PAC Served Pre-Install Causes Errors
If the browser policies are written by the MSI before the QinduAgent service starts, the browser will attempt to fetch `http://127.0.0.1:8787/proxy.pac` and receive a connection error. This causes a brief error state until the service starts. The MSI `ServiceControl` with `Start="install"` should minimize this window, but it cannot be eliminated entirely.

---

## Mandatory Security Tests

| Test ID | Source | Test | Type | Rationale |
|---|---|---|---|---|
| INST-SEC-T1 | SR-INSTALLER-1 | Verify `ca-init` writes DPAPI-encrypted key only — no plaintext key on disk. Inspect `%PROGRAMDATA%\Qindu\ca.key` file content: must be DPAPI blob (not PEM). | Unit | CA key must never be stored plaintext. |
| INST-SEC-T2 | SR-INSTALLER-1, DPO TS2 | Run `msiexec /i installer.msi /l*v install.log`. Grep for `PRIVATE KEY`, `BEGIN EC`, `EC PRIVATE`, hex key patterns. Zero matches required. | Integration | Prevent key leakage in MSI verbose logs. |
| INST-SEC-T3 | SR-INSTALLER-2 | Verify `certutil` is invoked with absolute path `%SystemRoot%\System32\certutil.exe` in WiX source. | Review | Prevent PATH hijacking of certutil. |
| INST-SEC-T4 | SR-INSTALLER-3 | Verify `UNSAFE_CA` checkbox is unchecked by default in MSI dialog. | Review + QA | Unsafe CA must be opt-in only. |
| INST-SEC-T5 | SR-INSTALLER-3 | Run `agent.exe ca-init --unsafe` in non-interactive mode (stdin pipe/redirect). Verify it fails with error. | Unit | Silent unsafe CA generation must not be possible. |
| INST-SEC-T6 | SR-INSTALLER-3 | Run `agent.exe ca-init --unsafe` in interactive terminal. Verify English warning banner appears and requires stdin confirmation. | Unit | Informed consent for unsafe CA. |
| INST-SEC-T7 | SR-INSTALLER-4 | After install, run `netsh advfirewall firewall show rule name="Qindu Agent (Allow Loopback)"` and `...name="Qindu Agent (Block External)"`. Verify both exist. Verify `curl http://127.0.0.1:8787/health` succeeds (loopback not blocked). | Integration | Firewall rules must not block loopback. |
| INST-SEC-T8 | SR-INSTALLER-4 | After uninstall, verify both firewall rules are removed. | Integration | Cleanup completeness. |
| INST-SEC-T9 | SR-INSTALLER-6 | Run `sc qc QinduAgent` — verify `BINARY_PATH_NAME` is quoted and `SERVICE_START_NAME` is `NT AUTHORITY\LocalService`. | Integration | Unquoted path prevention and least-privilege account. |
| INST-SEC-T10 | SR-INSTALLER-7 | Verify uninstall dialog `DELETEDATA` checkbox is unchecked by default. | Review + QA | Explicit consent for data deletion (also DPO TS8). |
| INST-SEC-T11 | SR-INSTALLER-7 | Uninstall without `DELETEDATA` — verify `%PROGRAMDATA%\Qindu\` preserved. Uninstall with `DELETEDATA=1` — verify directory deleted. | Integration | Conditional data deletion works correctly (DPO TS6, TS7). |
| INST-SEC-T12 | SR-INSTALLER-8 | Run `icacls "%PROGRAMDATA%\Qindu"` — verify only SYSTEM, Administrators, LocalService are present. Verify `Authenticated Users` and `Everyone` are absent. | Integration | ACL hardening (DPO TS11). |
| INST-SEC-T13 | SR-INSTALLER-9 | Grep full codebase (Go + WiX) for `telemetry`, `analytics`, `uuid`, `machineid`, `device_id`, `installation_id`, `crash-report`, `update.qindu`. Zero matches. | Review | No tracking or phoning home (DPO TS13, TS15). |
| INST-SEC-T14 | SR-INSTALLER-11 | After install, run `certutil -dump "%PROGRAMDATA%\Qindu\ca.crt"` — verify Name Constraints extension contains `chatgpt.com` and `claude.ai`. | Integration | CA constrained by default (DPO TS3). |
| INST-SEC-T15 | SR-INSTALLER-11 | Unit test: generate CA with test providers, assert `PermittedDNSDomains` in x509 certificate. | Unit | Name Constraints enforcement. |
| INST-SEC-T16 | SR-INSTALLER-12 | Run `agent.exe ca-init` twice, verify only one CA key exists and content differs. | Unit | Old CA destroyed on re-generation (DPO TS18). |
| INST-SEC-T17 | SR-INSTALLER-13 | Run `agent.exe ca-init --config "../../etc/evil.yaml"` — verify rejected. | Unit | Path traversal prevention in config loading. |
| INST-SEC-T18 | SR-INSTALLER-14 | Run `msiexec /i installer.msi /quiet UNSAFE_CA=1` — verify install fails. | Integration | Silent unsafe CA blocked. |
| INST-SEC-T19 | SR-INSTALLER-16 | Run `agent.exe ca-init --log-level debug 2>&1` — grep for `PRIVATE KEY`, key PEM. Zero matches. | Unit | No key leakage in debug logs (DPO TS14). |
| INST-SEC-T20 | SR-INSTALLER-18 | Verify Chrome/Edge registry `ProxyPacUrl` value is `http://127.0.0.1:8787/proxy.pac`. | Review + QA | PAC URL must be localhost (DPO TS12). |

---

## Residual Risks

| Risk ID | Risk | Severity | Acceptance Rationale | Tracking |
|---|---|---|---|---|
| RSK1 | **MSI unsigned** — SmartScreen warnings, supply chain verification impossible for non-technical users | **Medium** | Accepted per story exclusion line 87. DPO C1. Dedicated release sprint must add Authenticode signing. | QINDU-RELEASE |
| RSK2 | **Unsafe CA available** — user can opt into unconstrained CA, expanding compromise blast radius to all domains | **Medium** | Accepted per DPO C3. Opt-in only (unchecked by default), interactive warning, strong documentation. Necessary compatibility escape hatch for browsers that don't fully support Name Constraints. | Monitor browser Name Constraints support. Consider removal if no longer needed. |
| RSK3 | **No runtime integrity check** — `agent.exe` could be replaced by admin-level attacker | **Low** | Admin on the machine owns the machine. This is outside Qindu's local-only trust boundary. Windows Defender Application Control or AppLocker could be used by enterprise environments. | Future hardening (post-V1). |
| RSK4 | **Firewall block rule misordering** — if Windows Firewall evaluates the block rule first, proxy becomes unreachable | **Low** | Mitigated by SR-INSTALLER-4 (allow rule first, named rules, removal on uninstall). QA test verifies loopback access post-install. Windows Firewall consistently evaluates allow rules before block rules within the same profile. | Monitor Windows Firewall behavior across OS updates. |
| RSK5 | **MSI rollback incomplete** — trust store CA retained but proxy not functional | **Low** | Mitigated by WiX rollback sequence and manual uninstall option. Uninstall cleanup removes CA from trust store even if initial install failed. | Document manual cleanup procedure. |
| RSK6 | **Config override expands MITM scope** — admin adds non-AI domains to provider list | **Low** | Feature, not a bug. Admin owns the machine and controls config. ACL restrictions (SR-INSTALLER-8) limit write access. Document clearly. | DPO C6. |
| RSK7 | **Browser error state during install** — PAC not available between policy write and service start | **Very Low** | Transient window (< 5 seconds). Browser retries PAC fetch. Acceptable for V1. | None required. |
| RSK8 | **`certutil -addstore` duplicate on upgrade** — non-zero exit treated as error by MSI | **Low** | Addressed by Q4. WiX CustomAction should allow non-zero exit for `certutil` during upgrade. Otherwise manual trust store check may be needed. | Verify during Windows QA on upgrade scenario. |

---

## ADR Compliance Matrix

| ADR | Title | How QINDU-0002 Complies |
|---|---|---|
| ADR-003 | TLS Strategy (single CA, ECDSA P-256, lazy certs, wildcard SAN) | `ca-init` generates single ECDSA P-256 CA. Adds Name Constraints (permitted DNS subtrees) to the CA certificate per ADR-003 update. Leaf cert generation unchanged (QINDU-0001). CA key DPAPI-encrypted, stored in `%PROGRAMDATA%\Qindu\ca.key`. |
| ADR-006 | Windows Service (single binary, auto-detection) | Service created as `QinduAgent` running under `NT AUTHORITY\LocalService` via WiX `<ServiceInstall>`. Single binary `agent.exe` — same binary for `ca-init` subcommand and service mode. Auto-detection via `svc.IsAnInteractiveSession()` retained from QINDU-0001. |
| ADR-010 | TLS Upstream Validation (trust store, enterprise proxy compat) | No changes to upstream TLS validation. `upstream_validation: "system"` remains default. The installer does not modify TLS config or trust store beyond installing the Qindu CA. Enterprise proxy compatibility is preserved. |

All three applicable ADRs are respected. No ADR is weakened, modified, or contradicted.

---

## Verdict

### **PROCEED_WITH_CAVEATS**

**Rationale**: QINDU-0002 introduces the Windows MSI installer — a necessary delivery mechanism for Qindu V1. The installer adds significant new attack surface (MSI supply chain, CA trust store manipulation, Windows service deployment, firewall configuration, browser policy writing), but the 18 security requirements (SR-INSTALLER-1 through SR-INSTALLER-18) comprehensively address each threat, with verifiable tests and clear rationale.

**What the sprint gets right**:
- **CA key protection in the installer context**: SR-INSTALLER-1 extends QINDU-0001 SR1 to ensure DPAPI-before-write in `ca-init`, preventing key leakage through MSI logs and CustomAction boundaries.
- **Name Constraints by default**: SR-INSTALLER-11 enforces "least decrypt" at the CA certificate level, constraining the CA to AI provider domains. The `--unsafe` escape hatch is gated behind explicit opt-in (SR-INSTALLER-3) and blocked in silent installs (SR-INSTALLER-14).
- **Defense in depth** across three layers: firewall (SR-INSTALLER-4), directory ACL (SR-INSTALLER-8), and file permissions (0600 via `ca-init`).
- **No telemetry/tracking**: SR-INSTALLER-9 sustains the non-negotiable architectural principle.
- **Uninstall privacy**: SR-INSTALLER-7 ensures data deletion is opt-in (unchecked by default), respecting GDPR consent requirements.
- **Quoted service path**: SR-INSTALLER-6 addresses the classic CWE-428 privilege escalation vector.
- **CI supply chain**: SR-INSTALLER-15 mandates reproducible, versioned builds from auditable source.

**Blocking issues**: **None.** All concerns are captured as caveats (Q1–Q6) with documented mitigations and tracking. The DPO has already cleared the design phase (PROCEED_WITH_CAVEATS, 12 requirements). The CISO requirements (18 SRs) are testable, verifiable, and aligned with all applicable ADRs.

**Caveats that require attention during implementation and review**:

| # | Caveat | Requirement | Review Gate Action |
|---|---|---|---|
| C1 | MSI unsigned — SmartScreen warnings | Q1 (non-blocking) | Verify Authenticode exclusion is documented in `dev-notes.md`. Confirm CI publishes SHA256 checksum. |
| C2 | `certutil` duplicate CA on upgrade | Q4, SR-INSTALLER-2 | Verify MSI handles non-zero exit from `certutil -addstore` gracefully during upgrade. |
| C3 | Silent install + unsafe CA blocked | SR-INSTALLER-14 | Verify WiX condition or `ca-init` interactive check prevents silent unsafe CA generation. |
| C4 | Name Constraints populated from providers config | SR-INSTALLER-11 | Verify `PermittedDNSDomains` in generated CA matches provider YAML — not hardcoded. |
| C5 | QINDU-0001 SEC-F4 (panic on non-ECDSA key) fixed | SR-INSTALLER-17 | Verify `parseCAFromPEM` or equivalent uses comma-ok type assertion. |
| C6 | `ca-init` output contains zero key material | SR-INSTALLER-16 | Grep all `ca-init` log calls for key-related patterns. |

**Path to BLOCKED**: Any of the following findings during the review phase would change the verdict to BLOCKED:
- CA private key written as plaintext to disk (even temporarily) by `ca-init`
- CA private key appearing in MSI verbose logs, `ca-init` stdout/stderr, or any log output
- `UNSAFE_CA` checkbox checked by default in MSI dialog
- `DELETEDATA` (data deletion) checkbox checked by default in uninstall dialog
- `certutil` invoked without absolute path (PATH hijacking)
- Firewall block rule installed without corresponding loopback allow rule
- Service binary path unquoted (`sc qc QinduAgent` shows unquoted `BINARY_PATH_NAME`)
- Telemetry, analytics, or tracking code present in installer or `ca-init`
- Name Constraints absent from CA certificate in default (non-unsafe) mode
- `agent.exe ca-init --unsafe` proceeds without interactive confirmation
- `ca-init --config` accepts path traversal (`../../etc/passwd` equivalent)

**The CISO gate for QINDU-0002 design phase is PASSED, contingent on verification of all 18 security requirements during the review phase.**

---

**End of CISO Requirements — QINDU-0002 Design Phase**
