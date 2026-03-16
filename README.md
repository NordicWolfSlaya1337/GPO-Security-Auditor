# Nordic's GPO Security Auditor

A comprehensive vulnerability scanner for Active Directory Group Policy Objects (GPOs). Analyzes GPO exports against 80+ hardcoded security rules across 17 categories, generates professional PDF and CSV reports, and provides an optional AI-powered chat assistant for remediation guidance.

## Features

- **80+ Security Rules** — Password policy, account lockout, Kerberos, audit logging, registry hardening, firewall, RDP, LAPS, AppLocker, credential exposure, SDDL permissions, and more
- **Risk Scoring** — Weighted 0-100 score with diminishing returns per severity level
- **Web UI** — Drag-and-drop upload, real-time progress streaming (SSE), searchable/sortable findings table, detailed finding modals
- **CLI Mode** — Color-coded terminal output with severity indicators
- **PDF Reports** — Professional formatted reports with cover page, executive summary, severity breakdown, detailed findings, and GPO inventory appendix
- **CSV Export** — AES-256 encrypted ZIP containing findings and GPO inventory spreadsheets
- **AI Chat Assistant** — Ask questions about audit findings and get actionable remediation guidance (requires Ollama)
- **Password Protection** — All output files are encrypted (PDF encryption + AES-256 ZIP)
- **GPO Export Script** — Included PowerShell script for domain-wide GPO extraction

## Security Rules

| Category | Rule IDs | Count | Examples |
|----------|----------|-------|---------|
| Password Policy | PWD-001 – PWD-007 | 7 | Minimum length, complexity, age, history, reversible encryption |
| Account Lockout | LCK-001 – LCK-004 | 4 | Threshold, duration, reset counter |
| Kerberos Policy | KRB-001 – KRB-004 | 4 | Ticket lifetime, renewal, validation, cross-GPO conflicts |
| Security Options | SEC-001 – SEC-014 | 14 | Guest account, LM auth, SMB signing, logon cache, LDAP signing |
| User Rights Assignment | URA-* | Dynamic | Dangerous privileges (SeDebugPrivilege, SeTcbPrivilege, etc.) |
| Audit & Logging | AUD-001, AUD-018 – AUD-020 | 4 | Subcategory coverage, command-line auditing, script block logging |
| Registry & Admin Templates | REG-001 – REG-021 | 17 | UAC, WDigest, LLMNR, NetBIOS, WinRM, PowerShell, SMBv1, WSH |
| Windows Firewall | FW-001 – FW-003 | 3 | Profile state, inbound defaults, overly permissive rules |
| Remote Desktop (RDP) | RDP-001 – RDP-004 | 4 | NLA enforcement, encryption level, access control, drive redirection |
| Windows Defender | DEF-001 – DEF-004 | 4 | Defender disabled, real-time protection, MAPS, tamper protection |
| GPO Hygiene | HYG-002 – HYG-011 | 6 | Empty GPOs, disabled sections, naming, version mismatches, enforced links |
| GPO Permissions (SDDL) | SDDL-001 – SDDL-002 | 2 | Anonymous access, Everyone write permissions |
| LAPS | LAPS-001 – LAPS-004 | 4 | LAPS deployment, password length, password age, backup directory |
| Credential Exposure | CRED-001 – CRED-002 | 2 | Embedded passwords in GPO preferences (cpassword) |
| AppLocker | APL-001 – APL-003 | 3 | AppLocker deployment, default-allow rules, audit-only mode |
| Script Security | SCR-001 – SCR-003 | 3 | Unsigned scripts, scripts from network shares, suspicious commands |
| Local Admin Management | ADM-001 – ADM-002 | 2 | Excessive local admin membership, cross-GPO admin conflicts |

## Quick Start

### Prerequisites

- **Python 3.8+**
- **Windows** with Active Directory access (for GPO export)
- **Optional:** [Ollama](https://ollama.ai) with a LLaMA model for AI features

### Installation

```bash
git clone https://github.com/NordicWolfSlaya1337/nordics-gpo-security-auditor.git
cd nordics-gpo-security-auditor
pip install -r requirements.txt
```

### Step 1: Export GPOs from Your Domain

Run the included PowerShell script on a domain-joined machine with RSAT installed:

```powershell
.\Export-GPOs.ps1
```

This produces a ZIP file named `{domain}_GPOs_{date}.zip` containing XML reports for all GPOs and a `GPO_OU_Links.csv` with OU linking data.

### Step 2: Run the Audit

**Web mode** (recommended):

```bash
python app.py --web
```

Opens a browser UI where you can drag-and-drop the GPO export ZIP and watch findings appear in real time.

**CLI mode:**

```bash
python app.py --zip path/to/domain_GPOs.zip --output-dir ./reports
```

Or use the batch launcher:

```bash
start.bat
```

## Usage

### CLI Options

```
python app.py --zip <path>           Audit a GPO export ZIP file
python app.py --web                  Launch web interface (default port 5000)
python app.py --web --port 8080      Custom port
python app.py --zip <path> --output-dir ./out   Custom output directory
```

### Web Interface

1. Open the web UI (auto-launches in browser)
2. Drag-and-drop or click to upload a GPO export ZIP
3. Watch real-time progress and findings stream in
4. Review findings in the searchable table — click any row for full details
5. Download PDF report or CSV export
6. Use the AI chat assistant (bottom-right) to ask questions about your audit

### Report Password

A unique password is generated each session for encrypting all output files. It is displayed prominently in both CLI and web UI, and saved to `password.txt` in the output directory.

- **PDF** — standard PDF encryption (128-bit)
- **CSV ZIP** — AES-256 encryption (requires 7-Zip or WinZip to open)

## AI Features (Optional)

The AI chat feature requires [Ollama](https://ollama.ai) running locally with a LLaMA model.

### Setup

```bash
# Install Ollama from https://ollama.ai
ollama pull llama3.2
```

The auditor auto-detects the available model — no configuration needed.

### AI Chat Assistant

After an audit completes in the web UI, click the chat button (bottom-right) to ask questions like:

- "What are the most critical issues?"
- "Which GPOs have password policy problems?"
- "How do I fix the Kerberos findings?"
- "Give me PowerShell commands to remediate PWD-001"

The assistant has full context of all findings, GPOs, and their configurations.

## Architecture

```
Export-GPOs.ps1          PowerShell script to export GPOs from AD
        |
        v
   GPO Export ZIP        XML reports + OU links CSV
        |
        v
  engine/parser.py       Parses ZIP into GPO data model objects
        |
        v
  engine/rules/*.py      17 rule modules evaluate each GPO (80+ checks)
        |
        v
  engine/runner.py       Orchestrates parsing -> auditing -> report assembly
        |
        v
  engine/models.py       Finding, AuditReport, GPO, Severity dataclasses
        |
        v
  output/pdf_report.py   Professional PDF with severity badges, risk boxes
  output/csv_export.py   AES-256 encrypted CSV ZIP
        |
        v
  web/server.py          Flask app with SSE streaming + chat endpoints
  web/templates/          Single-page web UI (HTML/CSS/JavaScript)
  web/chat.py            AI chat session management + Ollama streaming
```

## Requirements

```
flask>=3.0              Web framework
reportlab>=4.0          PDF generation with encryption
pyzipper>=0.3.6         AES-256 ZIP encryption
defusedxml>=0.7         Safe XML parsing (prevents XXE)
colorama>=0.4           Colored terminal output
requests>=2.31          HTTP client (Ollama integration)
```

## License

Proprietary. All rights reserved.
