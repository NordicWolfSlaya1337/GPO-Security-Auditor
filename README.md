# Nordic's GPO Security Auditor

![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?logo=python&logoColor=white)
![Version](https://img.shields.io/badge/Version-1.0-blue)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20macOS%20%7C%20Linux-brightgreen)
![License](https://img.shields.io/badge/License-Proprietary%20(No%20Modification)-red)

> Comprehensive vulnerability scanner for Active Directory Group Policy Objects.
> Analyzes GPO exports against **120+ security rules** across **21 categories**,
> generates encrypted PDF & CSV reports, and offers AI-powered remediation guidance.

---

## Features

| Feature | Description |
|---------|-------------|
| **120+ Security Rules** | Password, Kerberos, BitLocker, Credential Guard, DCOM, DNS, firewall, RDP, LAPS, AppLocker, SDDL, WinRM, and more |
| **Risk Scoring** | Weighted 0-100 score with severity-based diminishing returns |
| **Web UI** | Drag-and-drop upload, real-time SSE streaming, sortable findings table |
| **CLI Mode** | Color-coded terminal output with severity indicators |
| **Encrypted Reports** | PDF (128-bit) and CSV ZIP (AES-256) with per-session passwords |
| **AI Chat** | Ask questions about findings via local Ollama LLM |
| **GPO Export Script** | Included PowerShell script for domain-wide GPO extraction |

---

## Quick Start

### Prerequisites

- **Python 3.8+** (Windows, macOS, or Linux)
- **Windows** domain-joined machine with RSAT (for GPO export only)
- The **audit and reporting** run on any OS — just feed it the exported ZIP
- *Optional:* [Ollama](https://ollama.ai) with a LLaMA model for AI chat

### 1. Install

```bash
git clone https://github.com/NordicWolfSlaya1337/GPO-Security-Auditor.git
cd GPO-Security-Auditor
pip install -r requirements.txt
```

### 2. Export GPOs

Run on a domain-joined machine with RSAT:

```powershell
.\Export-GPOs.ps1
```

Produces `{domain}_GPOs_{date}.zip` with XML reports and OU link data.

### 3. Run the Audit

**Web (recommended):**

```bash
# Windows
start.bat

# macOS / Linux
chmod +x start.sh
./start.sh
```

Or run directly:

```bash
python app.py --web
```

**CLI:**

```bash
python app.py --zip path/to/domain_GPOs.zip --output-dir ./reports
```

---

## Usage

```
python app.py --zip <path>                     Audit a GPO export ZIP
python app.py --web                            Launch web UI (port 5000)
python app.py --web --port 8080                Custom port
python app.py --zip <path> --output-dir ./out  Custom output directory
```

### Report Password

A unique password is generated each session for encrypting all outputs. Displayed in the UI and saved to `password.txt`.

- **PDF** — 128-bit encryption
- **CSV ZIP** — AES-256 encryption (requires 7-Zip or WinZip)

---

## Security Rules

<details>
<summary><b>View all 21 rule categories (120+ checks)</b></summary>

<br>

| Category | Rule IDs | Count | Examples |
|----------|----------|-------|---------|
| Password Policy | PWD-001 – PWD-007 | 7 | Min length, complexity, age, history |
| Account Lockout | LCK-001 – LCK-004 | 4 | Threshold, duration, reset counter |
| Kerberos | KRB-001 – KRB-005 | 5 | Ticket lifetime, renewal, validation, weak encryption |
| Security Options | SEC-001 – SEC-014 | 14 | Guest account, LM auth, SMB signing, LDAP signing |
| User Rights | URA-* | Dynamic | Dangerous privileges (SeDebugPrivilege, etc.) |
| Audit & Logging | AUD-001, AUD-018 – AUD-021 | 5 | Subcategory coverage, script block logging, event log sizes |
| Registry & Admin Templates | REG-001 – REG-026 | 22 | UAC, WDigest, LLMNR, SMBv1, WinRM, admin shares, USB deny-all |
| Firewall | FW-001 – FW-003 | 3 | Profile state, inbound defaults |
| RDP | RDP-001 – RDP-014 | 14 | NLA, encryption, redirection, session timeouts, hijacking |
| Defender | DEF-001 – DEF-004 | 4 | Real-time protection, MAPS, tamper protection |
| GPO Hygiene | HYG-002 – HYG-012 | 7 | Empty GPOs, naming, version mismatch, WEF conflicts |
| SDDL Permissions | SDDL-001 – SDDL-005 | 5 | Anonymous access, Everyone write, delegation |
| LAPS | LAPS-001 – LAPS-004 | 4 | Deployment, password length/age, encryption |
| Credential Exposure | CRED-001 – CRED-002 | 2 | Embedded cpassword, GPP credentials |
| AppLocker | APL-001 – APL-006 | 6 | Deployment, default-allow, writable paths, DLL rules |
| Script Security | SCR-001 – SCR-003 | 3 | Non-SYSVOL paths, writable locations, PATH hijack |
| Local Admins | ADM-001 – ADM-002 | 2 | Excessive membership, conflicts |
| BitLocker | BIT-001 – BIT-003 | 3 | Deployment, TPM+PIN, AD recovery escrow |
| Credential Guard | CG-001 – CG-002 | 2 | Credential Guard, VBS enforcement |
| DCOM Hardening | DCOM-001 – DCOM-002 | 2 | Auth level, KB5004442 hardening |
| DNS Security | DNS-001 – DNS-003 | 3 | mDNS, secure dynamic updates, DoH |

</details>

<details>
<summary><b>Full rule reference (every rule ID)</b></summary>

<br>

#### Password Policy (PWD)
| Rule | Severity | Description |
|------|----------|-------------|
| PWD-001 | CRITICAL/HIGH | Minimum password length is critically short or below recommended |
| PWD-002 | HIGH | Password complexity requirements disabled |
| PWD-003 | MEDIUM/LOW | Passwords never expire or expire too late |
| PWD-004 | LOW | Minimum password age is zero |
| PWD-005 | MEDIUM | Password history size is too small |
| PWD-006 | CRITICAL | Reversible encryption for passwords is enabled |
| PWD-007 | HIGH | No password policy defined in any GPO |

#### Account Lockout (LCK)
| Rule | Severity | Description |
|------|----------|-------------|
| LCK-001 | CRITICAL | Account lockout threshold is disabled |
| LCK-002 | MEDIUM | Account lockout threshold is too high |
| LCK-003 | MEDIUM | Account lockout duration is too short |
| LCK-004 | LOW | Lockout counter reset time is too short |

#### Kerberos (KRB)
| Rule | Severity | Description |
|------|----------|-------------|
| KRB-001 | MEDIUM | Kerberos maximum ticket lifetime is too long |
| KRB-002 | LOW | Kerberos maximum renewal age is too long |
| KRB-003 | MEDIUM | Kerberos ticket validation is disabled |
| KRB-004 | HIGH | Conflicting Kerberos settings across GPOs |
| KRB-005 | HIGH | Weak Kerberos encryption types are allowed |

#### Security Options (SEC)
| Rule | Severity | Description |
|------|----------|-------------|
| SEC-001 | HIGH | Guest account is enabled |
| SEC-002 | CRITICAL | LAN Manager authentication level is weak |
| SEC-003 | MEDIUM | Anonymous SID/Name translation is allowed |
| SEC-004 | HIGH | Anonymous enumeration of SAM accounts is allowed |
| SEC-005 | HIGH | SMB server signing is not required |
| SEC-006 | MEDIUM | SMB client signing is not required |
| SEC-007 | LOW | Machine inactivity timeout is too long |
| SEC-008 | LOW | Ctrl+Alt+Del is not required for logon |
| SEC-009 | MEDIUM | Too many cached logon credentials stored |
| SEC-010 | CRITICAL | LAN Manager hash storage is enabled |
| SEC-011 | HIGH | Everyone group includes Anonymous users |
| SEC-012 | HIGH | Anonymous access restrictions are not configured |
| SEC-013 | HIGH | LDAP server signing is not required |
| SEC-014 | MEDIUM | LDAP channel binding is not enforced |

#### User Rights Assignment (URA)
| Rule | Severity | Description |
|------|----------|-------------|
| URA-* | Dynamic | Flags dangerous privilege assignments (SeDebugPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeTakeOwnershipPrivilege, SeLoadDriverPrivilege, SeImpersonatePrivilege, SeRemoteInteractiveLogonRight) |

#### Audit & Logging (AUD)
| Rule | Severity | Description |
|------|----------|-------------|
| AUD-001 | HIGH | Audit policy gaps — consolidates 17 subcategories (Process Creation, Kerberos, Logon, Group Management, etc.) |
| AUD-018 | HIGH | Command-line process auditing is not enabled |
| AUD-019 | HIGH | PowerShell Script Block Logging is not enabled |
| AUD-020 | HIGH | Advanced audit policy may be overridden by legacy settings |
| AUD-021 | MEDIUM | Event log maximum sizes too small in default GPOs (Security, System, Application, Setup < 100 MB) |

#### Registry & Administrative Templates (REG)
| Rule | Severity | Description |
|------|----------|-------------|
| REG-001 | CRITICAL | User Account Control (UAC) is disabled |
| REG-002 | HIGH | WDigest authentication stores cleartext credentials |
| REG-005 | MEDIUM | LLMNR is enabled |
| REG-006 | MEDIUM | NetBIOS over TCP/IP is not configured as P-Node |
| REG-007 | HIGH | WinRM allows Basic authentication |
| REG-008 | MEDIUM | WSUS server uses unencrypted HTTP |
| REG-009 | HIGH | PowerShell execution policy set to Bypass or Unrestricted |
| REG-010 | MEDIUM | PowerShell module logging is disabled |
| REG-011 | MEDIUM | PowerShell transcription is disabled |
| REG-013 | HIGH | SMBv1 protocol is enabled |
| REG-015 | HIGH | UAC admin approval mode for built-in Administrator is disabled |
| REG-016 | HIGH | UAC elevates without prompting for administrators |
| REG-017 | MEDIUM | UAC secure desktop is disabled |
| REG-018 | LOW | Removable storage write/execute access is not restricted |
| REG-019 | MEDIUM | Mark of the Web (zone information) preservation is disabled |
| REG-020 | MEDIUM | Windows Script Host (WSH) is not restricted |
| REG-021 | HIGH | Office macro protections are weakened |
| REG-022 | HIGH | WinRM allows unencrypted traffic |
| REG-023 | MEDIUM | WinRM CredSSP authentication is enabled |
| REG-024 | MEDIUM | WinRM configured with HTTP listener (not HTTPS) |
| REG-025 | MEDIUM | Administrative shares (C$, ADMIN$) are enabled |
| REG-026 | MEDIUM | Removable storage deny-all policy is not enforced |

#### Windows Firewall (FW)
| Rule | Severity | Description |
|------|----------|-------------|
| FW-001 | CRITICAL/HIGH | Windows Firewall disabled for profile |
| FW-002 | HIGH | Firewall default inbound action is Allow |
| FW-003 | MEDIUM | Overly broad inbound firewall rule |

#### Remote Desktop Protocol (RDP)
| Rule | Severity | Description |
|------|----------|-------------|
| RDP-001 | HIGH | RDP Network Level Authentication (NLA) is disabled |
| RDP-002 | MEDIUM | RDP encryption level is below High |
| RDP-003 | MEDIUM | RDP is enabled at domain root level |
| RDP-004 | LOW | RDP drive redirection is allowed |
| RDP-005 | MEDIUM | RDP clipboard redirection is allowed |
| RDP-006 | LOW | RDP COM port redirection is allowed |
| RDP-007 | LOW | RDP printer redirection is allowed |
| RDP-008 | LOW | RDP LPT port redirection is allowed |
| RDP-009 | MEDIUM | RDP USB/Plug and Play device redirection is allowed |
| RDP-010 | MEDIUM | RDP idle session timeout is disabled |
| RDP-011 | LOW | RDP active session timeout is disabled |
| RDP-012 | MEDIUM | RDP disconnected session timeout is disabled |
| RDP-013 | HIGH | RDP does not require password on reconnection |
| RDP-014 | MEDIUM | Disconnected RDP sessions are not ended when time limits are reached |

#### Windows Defender (DEF)
| Rule | Severity | Description |
|------|----------|-------------|
| DEF-001 | CRITICAL | Windows Defender is disabled by GPO |
| DEF-002 | HIGH | Defender real-time protection is disabled |
| DEF-003 | MEDIUM | Defender cloud-delivered protection is disabled |
| DEF-004 | HIGH | Defender tamper protection is weakened |

#### GPO Hygiene (HYG)
| Rule | Severity | Description |
|------|----------|-------------|
| HYG-002 | LOW | GPO contains no settings |
| HYG-003 | MEDIUM | GPO has all settings disabled but is still actively linked |
| HYG-005 | MEDIUM | GPO marked as UNUSED but still has active links |
| HYG-006 | MEDIUM | GPO version mismatch between AD and SYSVOL |
| HYG-009 | LOW | Excessive use of Enforced (No Override) |
| HYG-011 | INFO | GPO configures both Computer and User settings |
| HYG-012 | MEDIUM | Multiple GPOs configure WEF subscriptions on the same OU |

#### GPO Permissions / SDDL (SDDL)
| Rule | Severity | Description |
|------|----------|-------------|
| SDDL-001 | CRITICAL | Everyone / Anonymous has edit permissions on GPO(s) |
| SDDL-002 | HIGH | Authenticated Users have edit permissions on GPO(s) |
| SDDL-003 | HIGH | Non-admin group(s) have edit permissions on GPO(s) |
| SDDL-004 | MEDIUM | Creator Owner retains full control on GPO(s) |
| SDDL-005 | MEDIUM | Non-standard account(s) have write access to GPO(s) |

#### LAPS (LAPS)
| Rule | Severity | Description |
|------|----------|-------------|
| LAPS-001 | HIGH | No LAPS configuration found in any GPO |
| LAPS-002 | MEDIUM | LAPS password length is too short |
| LAPS-003 | MEDIUM | LAPS password age is too long |
| LAPS-004 | MEDIUM | LAPS password encryption is not enabled |

#### Credential Exposure (CRED)
| Rule | Severity | Description |
|------|----------|-------------|
| CRED-001 | CRITICAL | GPP cpassword found (MS14-025) |
| CRED-002 | CRITICAL | Embedded credentials in Group Policy Preferences |

#### AppLocker (APL)
| Rule | Severity | Description |
|------|----------|-------------|
| APL-001 | MEDIUM | No AppLocker or WDAC configuration found |
| APL-002 | LOW | AppLocker is in audit-only mode |
| APL-003 | HIGH | AppLocker has overly broad allow-all rule |
| APL-004 | HIGH | AppLocker allows execution from user-writable paths |
| APL-005 | MEDIUM | AppLocker does not include DLL rule collection |
| APL-006 | MEDIUM | AppLocker has only allow rules with no deny restrictions |

#### Script Security (SCR)
| Rule | Severity | Description |
|------|----------|-------------|
| SCR-001 | HIGH | Script executed from non-SYSVOL UNC path |
| SCR-002 | MEDIUM | Script executed from user-writable location |
| SCR-003 | MEDIUM | Script uses unqualified path (PATH hijack risk) |

#### Local Admin Management (ADM)
| Rule | Severity | Description |
|------|----------|-------------|
| ADM-001 | CRITICAL | Broad group added to local Administrators |
| ADM-002 | HIGH | Conflicting local Administrator management across GPOs |

#### BitLocker (BIT)
| Rule | Severity | Description |
|------|----------|-------------|
| BIT-001 | HIGH | BitLocker drive encryption is not configured |
| BIT-002 | MEDIUM | BitLocker does not require TPM+PIN pre-boot authentication |
| BIT-003 | MEDIUM | BitLocker recovery keys are not escrowed to Active Directory |

#### Credential Guard (CG)
| Rule | Severity | Description |
|------|----------|-------------|
| CG-001 | HIGH | Credential Guard is not configured |
| CG-002 | HIGH | Virtualization-Based Security (VBS) is not configured |

#### DCOM Hardening (DCOM)
| Rule | Severity | Description |
|------|----------|-------------|
| DCOM-001 | MEDIUM | DCOM default authentication level is too low |
| DCOM-002 | MEDIUM | DCOM hardening is explicitly disabled (KB5004442) |

#### DNS Security (DNS)
| Rule | Severity | Description |
|------|----------|-------------|
| DNS-001 | MEDIUM | Multicast DNS (mDNS) is not disabled |
| DNS-002 | MEDIUM | DNS dynamic updates are not restricted to secure only |
| DNS-003 | LOW | DNS over HTTPS (DoH) is explicitly disabled or not enabled |

</details>

---

## AI Chat (Optional)

Requires [Ollama](https://ollama.ai) running locally:

```bash
ollama pull llama3.2
```

After an audit completes, click the chat button in the web UI to ask:

- *"What are the most critical issues?"*
- *"How do I fix the Kerberos findings?"*
- *"Give me PowerShell commands to remediate PWD-001"*

The assistant has full context of all findings, GPOs, and their configurations.

---

## Architecture

```
Export-GPOs.ps1        PowerShell script to export GPOs from AD
       |
       v
  GPO Export ZIP       XML reports + OU links CSV
       |
       v
 engine/parser.py      Parses ZIP into GPO data model objects
       |
       v
 engine/rules/*.py     21 rule modules evaluate each GPO (120+ checks)
       |
       v
 engine/runner.py      Orchestrates parsing -> auditing -> report assembly
       |
       v
 engine/models.py      Finding, AuditReport, GPO, Severity dataclasses
       |
       v
 output/pdf_report.py  Professional PDF with severity badges, risk boxes
 output/csv_export.py  AES-256 encrypted CSV ZIP
       |
       v
 web/server.py         Flask app with SSE streaming + chat endpoints
 web/templates/        Single-page web UI (HTML/CSS/JavaScript)
 web/chat.py           AI chat session management + Ollama streaming
```

---

## Requirements

| Package | Version | Purpose |
|---------|---------|---------|
| flask | >= 3.0 | Web framework |
| reportlab | >= 4.0 | PDF generation with encryption |
| pyzipper | >= 0.3.6 | AES-256 ZIP encryption |
| defusedxml | >= 0.7 | Safe XML parsing (prevents XXE) |
| colorama | >= 0.4 | Colored terminal output |
| requests | >= 2.31 | HTTP client (Ollama integration) |

---

## Author

**NordicWolfSlaya1337**

- GitHub: [@NordicWolfSlaya1337](https://github.com/NordicWolfSlaya1337)

---

## License

This software is proprietary and provided under a custom restrictive license. See the [LICENSE](LICENSE) file for full terms.

- Non-commercial / non-profit use only
- No modification or derivative works permitted
- No redistribution or reuse in other projects
- All rights reserved by NordicWolfSlaya1337
- Violators are subject to legal action
