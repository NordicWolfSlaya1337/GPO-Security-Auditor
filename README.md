# Nordic's GPO Security Auditor

![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?logo=python&logoColor=white)
![Version](https://img.shields.io/badge/Version-1.0-blue)
![License](https://img.shields.io/badge/License-Proprietary%20(No%20Modification)-red)

> Comprehensive vulnerability scanner for Active Directory Group Policy Objects.
> Analyzes GPO exports against **100+ security rules** across **21 categories**,
> generates encrypted PDF & CSV reports, and offers AI-powered remediation guidance.

---

## Features

| Feature | Description |
|---------|-------------|
| **100+ Security Rules** | Password, Kerberos, BitLocker, Credential Guard, DCOM, DNS, firewall, RDP, LAPS, AppLocker, SDDL, WinRM, and more |
| **Risk Scoring** | Weighted 0-100 score with severity-based diminishing returns |
| **Web UI** | Drag-and-drop upload, real-time SSE streaming, sortable findings table |
| **CLI Mode** | Color-coded terminal output with severity indicators |
| **Encrypted Reports** | PDF (128-bit) and CSV ZIP (AES-256) with per-session passwords |
| **AI Chat** | Ask questions about findings via local Ollama LLM |
| **GPO Export Script** | Included PowerShell script for domain-wide GPO extraction |

---

## Quick Start

### Prerequisites

- **Python 3.8+**
- **Windows** with Active Directory access (for GPO export)
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
<summary><b>View all 21 rule categories (100+ checks)</b></summary>

<br>

| Category | Rule IDs | Count | Examples |
|----------|----------|-------|---------|
| Password Policy | PWD-001 – PWD-007 | 7 | Min length, complexity, age, history |
| Account Lockout | LCK-001 – LCK-004 | 4 | Threshold, duration, reset counter |
| Kerberos | KRB-001 – KRB-005 | 5 | Ticket lifetime, renewal, validation, weak encryption |
| Security Options | SEC-001 – SEC-014 | 14 | Guest account, LM auth, SMB signing |
| User Rights | URA-* | Dynamic | Dangerous privileges (SeDebugPrivilege, etc.) |
| Audit & Logging | AUD-001, AUD-018 – AUD-020 | 4 | Subcategory coverage, script block logging |
| Registry & Admin Templates | REG-001 – REG-024 | 20 | UAC, WDigest, LLMNR, SMBv1, WinRM |
| Firewall | FW-001 – FW-003 | 3 | Profile state, inbound defaults |
| RDP | RDP-001 – RDP-004 | 4 | NLA, encryption, access control |
| Defender | DEF-001 – DEF-004 | 4 | Real-time protection, MAPS |
| GPO Hygiene | HYG-002 – HYG-011 | 6 | Empty GPOs, naming, version mismatch |
| SDDL Permissions | SDDL-001 – SDDL-005 | 5 | Anonymous access, Everyone write, delegation |
| LAPS | LAPS-001 – LAPS-004 | 4 | Deployment, password length/age |
| Credential Exposure | CRED-001 – CRED-002 | 2 | Embedded cpassword |
| AppLocker | APL-001 – APL-006 | 6 | Deployment, default-allow, writable paths, DLL rules |
| Script Security | SCR-001 – SCR-003 | 3 | Unsigned scripts, suspicious commands |
| Local Admins | ADM-001 – ADM-002 | 2 | Excessive membership, conflicts |
| BitLocker | BIT-001 – BIT-003 | 3 | Deployment, TPM+PIN, AD recovery escrow |
| Credential Guard | CG-001 – CG-002 | 2 | Credential Guard, VBS enforcement |
| DCOM Hardening | DCOM-001 – DCOM-002 | 2 | Auth level, KB5004442 hardening |
| DNS Security | DNS-001 – DNS-003 | 3 | mDNS, secure dynamic updates, DoH |

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
 engine/rules/*.py     17 rule modules evaluate each GPO (80+ checks)
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
