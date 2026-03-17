from typing import Generator

from engine.models import GPO, Finding, Severity
from engine.rules.base import AuditRule, register_rule

_SEC_OPT = "Computer Configuration -> Policies -> Windows Settings -> Security Settings -> Local Policies -> Security Options"
_ADMIN_TPL = "Computer Configuration -> Policies -> Administrative Templates"
_GPP_REG = "Computer Configuration -> Preferences -> Windows Settings -> Registry"

# Registry-based checks for both RegistryPolicy (admin templates) and RegistryItem (GPP)
# NOTE: REG-003 (PS script block logging), REG-004 (AutoRun), REG-012 (cmd-line auditing)
# have been moved to audit_policy.py (scoped to Default Domain GPOs only)
REGISTRY_CHECKS = [
    {
        "id": "REG-001",
        "name_pattern": "EnableLUA",
        "key_pattern": "EnableLUA",
        "path": f"{_SEC_OPT} -> User Account Control: Run all administrators in Admin Approval Mode",
        "severity": Severity.CRITICAL,
        "check_policy": lambda p: p.state == "Disabled",
        "check_item": lambda i: i.value_data == "0",
        "title": "User Account Control (UAC) is disabled",
        "description": "UAC has been disabled via Group Policy.",
        "risk": "Disabling UAC removes a critical defense-in-depth layer. All processes run with full administrative privileges, making malware execution and privilege escalation trivial.",
        "recommendation": "Enable UAC. Set 'User Account Control: Run all administrators in Admin Approval Mode' to Enabled.",
        "expected": "Enabled",
    },
    {
        "id": "REG-002",
        "name_pattern": "",
        "key_pattern": "WDigest\\\\.*UseLogonCredential",
        "path": f"{_GPP_REG} -> HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\\UseLogonCredential",
        "severity": Severity.HIGH,
        "check_policy": None,
        "check_item": lambda i: i.value_data == "1",
        "title": "WDigest authentication stores cleartext credentials",
        "description": "WDigest UseLogonCredential is enabled, causing plaintext passwords to be stored in LSASS memory.",
        "risk": "Tools like mimikatz can extract plaintext passwords directly from LSASS process memory. This is one of the most common credential theft techniques.",
        "recommendation": "Disable WDigest authentication by setting HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\\UseLogonCredential to 0.",
        "expected": "0 (Disabled)",
    },
    {
        "id": "REG-005",
        "name_pattern": "LLMNR",
        "key_pattern": "EnableMulticast",
        "path": f"{_ADMIN_TPL} -> Network -> DNS Client -> Turn off multicast name resolution",
        "severity": Severity.MEDIUM,
        "check_policy": lambda p: p.state == "Enabled",
        "check_item": lambda i: i.value_data == "1" or i.value_data == "",
        "title": "LLMNR (Link-Local Multicast Name Resolution) is enabled",
        "description": "LLMNR multicast name resolution is not disabled.",
        "risk": "LLMNR is routinely exploited by tools like Responder to capture NTLMv1/v2 hashes via man-in-the-middle attacks on local networks. This is one of the most common Active Directory attack vectors.",
        "recommendation": "Disable LLMNR by setting 'Turn off multicast name resolution' to Enabled (which sets EnableMulticast to 0).",
        "expected": "Disabled (0)",
    },
    {
        "id": "REG-006",
        "name_pattern": "",
        "key_pattern": "NetBT.*NodeType|NodeType.*NetBT",
        "path": f"{_GPP_REG} -> HKLM\\SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters\\NodeType",
        "severity": Severity.MEDIUM,
        "check_policy": None,
        "check_item": lambda i: "netbt" in i.key.lower() and i.value_name.lower() == "nodetype" and i.value_data != "2",
        "title": "NetBIOS over TCP/IP is not configured as P-Node",
        "description": "NetBIOS node type is not set to P-Node (point-to-point), allowing broadcast name resolution.",
        "risk": "NetBIOS broadcast name resolution (B-Node) is vulnerable to the same spoofing attacks as LLMNR, enabling credential capture and relay attacks.",
        "recommendation": "Set NetBIOS NodeType to 2 (P-Node) to disable broadcast name resolution, or disable NetBIOS over TCP/IP entirely.",
        "expected": "P-Node (2)",
    },
    {
        "id": "REG-007",
        "name_pattern": "Windows Remote Management",
        "key_pattern": "AllowBasic",
        "path": f"{_ADMIN_TPL} -> Windows Components -> Windows Remote Management (WinRM) -> WinRM Client -> Allow Basic authentication",
        "severity": Severity.HIGH,
        "check_policy": lambda p: p.state == "Enabled" and any("true" in str(v).lower() or "1" in str(v) for v in p.values.values()),
        "check_item": lambda i: i.value_name.lower() == "allowbasic" and i.value_data == "1",
        "title": "WinRM allows Basic authentication",
        "description": "Windows Remote Management is configured to allow Basic authentication.",
        "risk": "Basic authentication transmits credentials in Base64 (effectively cleartext). Credentials can be intercepted on the network.",
        "recommendation": "Disable Basic authentication for WinRM. Use Kerberos or CredSSP with HTTPS instead.",
        "expected": "Disabled",
    },
    {
        "id": "REG-008",
        "name_pattern": "",
        "key_pattern": "WindowsUpdate.*WUServer|WUServer",
        "path": f"{_GPP_REG} -> HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\WUServer",
        "severity": Severity.MEDIUM,
        "check_policy": None,
        "check_item": lambda i: i.value_name.lower() == "wuserver" and i.value_data.lower().startswith("http://"),
        "title": "WSUS server uses unencrypted HTTP",
        "description_fn": lambda v: f"Windows Update is configured to use WSUS over HTTP: {v}",
        "risk": "WSUS over HTTP allows man-in-the-middle attacks where malicious updates can be injected (WSUSpendu/WSUXploit attacks), potentially compromising all machines in the domain.",
        "recommendation": "Configure WSUS to use HTTPS. Update the WUServer registry value to use https:// protocol.",
        "expected": "HTTPS URL",
    },
    {
        "id": "REG-009",
        "name_pattern": "PowerShell",
        "key_pattern": "ExecutionPolicy",
        "path": f"{_ADMIN_TPL} -> Windows Components -> Windows PowerShell -> Turn on Script Execution",
        "severity": Severity.HIGH,
        "check_policy": lambda p: p.state == "Enabled" and any("bypass" in str(v).lower() or "unrestricted" in str(v).lower() for v in p.values.values()),
        "check_item": lambda i: i.value_name.lower() == "executionpolicy" and i.value_data.lower() in ("bypass", "unrestricted"),
        "title": "PowerShell execution policy set to Bypass or Unrestricted",
        "description": "PowerShell execution policy allows scripts to run without restriction.",
        "risk": "A Bypass or Unrestricted execution policy allows any PowerShell script to run without warning, "
                "making it trivial for attackers to execute malicious scripts.",
        "recommendation": "Set PowerShell execution policy to 'AllSigned' or 'RemoteSigned'. "
                          "Use constrained language mode for additional protection.",
        "expected": "AllSigned or RemoteSigned",
    },
    {
        "id": "REG-010",
        "name_pattern": "PowerShell",
        "key_pattern": "EnableModuleLogging",
        "path": f"{_ADMIN_TPL} -> Windows Components -> Windows PowerShell -> Turn on Module Logging",
        "severity": Severity.MEDIUM,
        "check_policy": lambda p: p.state == "Disabled",
        "check_item": lambda i: i.value_name.lower() == "enablemodulelogging" and i.value_data == "0",
        "title": "PowerShell module logging is disabled",
        "description": "PowerShell module logging is explicitly disabled via Group Policy.",
        "risk": "Without module logging, PowerShell commands executed by attackers (including imports and cmdlet usage) "
                "are not recorded, hindering incident response and forensic analysis.",
        "recommendation": "Enable 'Turn on Module Logging' and configure it to log all modules (*).",
        "expected": "Enabled",
    },
    {
        "id": "REG-011",
        "name_pattern": "PowerShell",
        "key_pattern": "EnableTranscripting",
        "path": f"{_ADMIN_TPL} -> Windows Components -> Windows PowerShell -> Turn on PowerShell Transcription",
        "severity": Severity.MEDIUM,
        "check_policy": lambda p: p.state == "Disabled",
        "check_item": lambda i: i.value_name.lower() == "enabletranscripting" and i.value_data == "0",
        "title": "PowerShell transcription is disabled",
        "description": "PowerShell transcription (full session recording) is disabled.",
        "risk": "Transcription provides a complete record of all PowerShell input and output. Without it, "
                "sophisticated attack activity using PowerShell cannot be fully reconstructed.",
        "recommendation": "Enable 'Turn on PowerShell Transcription' and configure an output directory with restricted ACLs.",
        "expected": "Enabled",
    },
    {
        "id": "REG-013",
        "name_pattern": "",
        "key_pattern": "SMB1|SMBv1|LanmanServer.*SMB1",
        "path": f"{_ADMIN_TPL} -> MS Security Guide -> Configure SMB v1 client driver",
        "severity": Severity.HIGH,
        "check_policy": None,
        "check_item": lambda i: ("smb1" in i.key.lower() or "smb1" in i.value_name.lower()) and i.value_data == "1",
        "title": "SMBv1 protocol is enabled",
        "description": "The legacy SMBv1 protocol is enabled via registry.",
        "risk": "SMBv1 is vulnerable to EternalBlue (MS17-010) and related exploits used by WannaCry/NotPetya ransomware. "
                "It has no encryption and weak authentication.",
        "recommendation": "Disable SMBv1 entirely. Set 'Configure SMB v1 client driver' and 'Configure SMB v1 server' to Disabled. "
                          "Ensure no legacy systems depend on SMBv1 before disabling.",
        "expected": "Disabled (0)",
    },
    {
        "id": "REG-015",
        "name_pattern": "",
        "key_pattern": "FilterAdministratorToken",
        "path": f"{_SEC_OPT} -> User Account Control: Admin Approval Mode for the Built-in Administrator account",
        "severity": Severity.HIGH,
        "check_policy": None,
        "check_item": lambda i: i.value_name.lower() == "filteradministratortoken" and i.value_data == "0",
        "title": "UAC admin approval mode for built-in Administrator is disabled",
        "description": "The built-in Administrator account bypasses UAC admin approval mode.",
        "risk": "Without filtering the built-in Administrator token, this account runs all processes with full elevated privileges, "
                "making it a high-value target for pass-the-hash and lateral movement attacks.",
        "recommendation": "Enable 'User Account Control: Admin Approval Mode for the Built-in Administrator account' (FilterAdministratorToken=1).",
        "expected": "Enabled (1)",
    },
    {
        "id": "REG-016",
        "name_pattern": "",
        "key_pattern": "ConsentPromptBehaviorAdmin",
        "path": f"{_SEC_OPT} -> User Account Control: Behavior of the elevation prompt for administrators",
        "severity": Severity.HIGH,
        "check_policy": None,
        "check_item": lambda i: i.value_name.lower() == "consentpromptbehavioradmin" and i.value_data == "0",
        "title": "UAC elevates without prompting for administrators",
        "description": "UAC is configured to elevate privileges without any prompt for administrators.",
        "risk": "Silent elevation allows malware running under an admin account to escalate privileges without the user's knowledge, "
                "removing the last line of defense against unauthorized privilege escalation.",
        "recommendation": "Set 'User Account Control: Behavior of the elevation prompt for administrators' to 'Prompt for consent on the secure desktop' (value 2).",
        "expected": "Prompt for consent (2)",
    },
    {
        "id": "REG-017",
        "name_pattern": "",
        "key_pattern": "PromptOnSecureDesktop",
        "path": f"{_SEC_OPT} -> User Account Control: Switch to the secure desktop when prompting for elevation",
        "severity": Severity.MEDIUM,
        "check_policy": None,
        "check_item": lambda i: i.value_name.lower() == "promptonsecuredesktop" and i.value_data == "0",
        "title": "UAC secure desktop is disabled",
        "description": "UAC elevation prompts do not use the secure desktop.",
        "risk": "Without the secure desktop, malware can spoof or manipulate UAC prompts to trick users into approving elevation, "
                "or can programmatically interact with the prompt to auto-approve elevation requests.",
        "recommendation": "Enable 'User Account Control: Switch to the secure desktop when prompting for elevation' (PromptOnSecureDesktop=1).",
        "expected": "Enabled (1)",
    },
    {
        "id": "REG-018",
        "name_pattern": "Removable",
        "key_pattern": "Deny_Write|Deny_Execute|Deny_Read.*Removable|RemovableMedia",
        "path": f"{_ADMIN_TPL} -> System -> Removable Storage Access",
        "severity": Severity.LOW,
        "check_policy": lambda p: "removable" in p.name.lower() and p.state == "Disabled",
        "check_item": lambda i: ("deny_write" in i.value_name.lower() or "deny_execute" in i.value_name.lower()) and i.value_data == "0",
        "title": "Removable storage access is not restricted",
        "description": "Group Policy does not restrict write or execute access to removable storage devices.",
        "risk": "Unrestricted removable media allows data exfiltration via USB drives and introduction of malware from untrusted devices.",
        "recommendation": "Configure 'Removable Disk: Deny write access' and 'Removable Disk: Deny execute access' to restrict USB storage. "
                          "Exceptions can be managed via device ID allow lists.",
        "expected": "Write and Execute denied on removable storage",
    },
    {
        "id": "REG-019",
        "name_pattern": "",
        "key_pattern": "SaveZoneInformation",
        "path": f"{_ADMIN_TPL} -> Windows Components -> Attachment Manager -> Do not preserve zone information in file attachments",
        "severity": Severity.MEDIUM,
        "check_policy": lambda p: "SaveZoneInformation" in p.name and p.state == "Disabled",
        "check_item": lambda i: i.value_name.lower() == "savezoneinformation" and i.value_data == "1",
        "title": "Mark of the Web (zone information) preservation is disabled",
        "description": "Downloaded files do not retain their zone information (Mark of the Web).",
        "risk": "Without MotW, downloaded files from the internet bypass SmartScreen, Protected View in Office, and other "
                "security features that rely on zone information to identify untrusted content.",
        "recommendation": "Enable 'Do not preserve zone information in file attachments' should be set to Disabled (preserve zone info). "
                          "Ensure SaveZoneInformation is set to 2 (preserve).",
        "expected": "Zone information preserved (2)",
    },
    {
        "id": "REG-020",
        "name_pattern": "",
        "key_pattern": "Windows Script Host|WSH.*Enabled|InternalName.*wscript|InternalName.*cscript",
        "path": f"{_GPP_REG} -> HKLM\\SOFTWARE\\Microsoft\\Windows Script Host\\Settings\\Enabled",
        "severity": Severity.MEDIUM,
        "check_policy": None,
        "check_item": lambda i: ("wsh" in i.value_name.lower() or "script host" in i.key.lower()) and i.value_name.lower() == "enabled" and i.value_data == "1",
        "title": "Windows Script Host (WSH) is not restricted",
        "description": "Windows Script Host is enabled, allowing .vbs/.js scripts to execute.",
        "risk": "WSH is commonly abused by malware for initial execution via email attachments (.vbs, .js, .wsf files). "
                "Most enterprise environments do not need WSH for legitimate purposes.",
        "recommendation": "Disable Windows Script Host via registry (HKLM\\Software\\Microsoft\\Windows Script Host\\Settings\\Enabled=0) "
                          "or block script file types via AppLocker/WDAC.",
        "expected": "Disabled (0) or blocked via AppLocker",
    },
    {
        "id": "REG-021",
        "name_pattern": "Office|Macro",
        "key_pattern": "VBAWarnings|BlockContentExecution|AccessVBOM|blockcontentexecutionfrominternet",
        "path": f"{_ADMIN_TPL} -> Microsoft Office -> Security Settings -> VBA Macro Notification Settings",
        "severity": Severity.HIGH,
        "check_policy": lambda p: ("macro" in p.name.lower() or "vba" in p.name.lower()) and p.state == "Disabled",
        "check_item": lambda i: i.value_name.lower() in ("vbawarnings", "blockcontentexecutionfrominternet", "accessvbom") and i.value_data in ("1", "0"),
        "title": "Office macro protections are weakened",
        "description": "Office macro security settings have been weakened or VBA project access is enabled.",
        "risk": "Weak macro protections allow malicious Office documents to execute VBA code automatically. "
                "Macro-based malware remains one of the most common initial access vectors.",
        "recommendation": "Set 'VBA Macro Notification Settings' to 'Disable all macros except digitally signed macros' or higher. "
                          "Enable 'Block macros from running in Office files from the Internet'. Disable 'Trust access to the VBA project object model'.",
        "expected": "Macros disabled or limited to signed only",
    },
    {
        "id": "REG-022",
        "name_pattern": "AllowUnencrypted",
        "key_pattern": "WinRM.*AllowUnencrypted",
        "path": f"{_ADMIN_TPL} -> Windows Components -> Windows Remote Management -> WinRM Service -> Allow unencrypted traffic",
        "severity": Severity.HIGH,
        "check_policy": lambda p: "unencrypted" in p.name.lower() and p.state == "Enabled",
        "check_item": lambda i: i.value_data == "1",
        "title": "WinRM allows unencrypted traffic",
        "description": "Windows Remote Management is configured to allow unencrypted (HTTP) traffic.",
        "risk": "Unencrypted WinRM transmits credentials and commands in plaintext over the network. "
                "Attackers on the same network segment can intercept PowerShell remoting sessions, "
                "steal credentials, and capture sensitive command output.",
        "recommendation": "Disable 'Allow unencrypted traffic' for both WinRM Service and Client. "
                          "Enforce HTTPS listeners and require encrypted transport for all WinRM connections.",
        "expected": "Disabled (encrypted traffic only)",
    },
    {
        "id": "REG-023",
        "name_pattern": "CredSSP",
        "key_pattern": "WinRM.*AllowCredSSP|CredSSP.*AllowCredSSP",
        "path": f"{_ADMIN_TPL} -> Windows Components -> Windows Remote Management -> WinRM Service -> Allow CredSSP authentication",
        "severity": Severity.MEDIUM,
        "check_policy": lambda p: "credssp" in p.name.lower() and p.state == "Enabled",
        "check_item": lambda i: "credssp" in i.value_name.lower() and i.value_data == "1",
        "title": "WinRM CredSSP authentication is enabled",
        "description": "WinRM is configured to allow CredSSP (Credential Security Support Provider) authentication.",
        "risk": "CredSSP sends user credentials in delegatable form to the remote server. If the remote server "
                "is compromised, the attacker gains access to the delegated credentials for lateral movement. "
                "CredSSP is also vulnerable to relay attacks.",
        "recommendation": "Disable CredSSP authentication for WinRM. Use Kerberos authentication instead, "
                          "which provides mutual authentication without exposing credentials.",
        "expected": "Disabled (use Kerberos authentication)",
    },
    {
        "id": "REG-024",
        "name_pattern": "WinRM",
        "key_pattern": "WinRM.*Service.*AllowAutoConfig|WinRM.*Listener",
        "path": f"{_ADMIN_TPL} -> Windows Components -> Windows Remote Management -> WinRM Service",
        "severity": Severity.MEDIUM,
        "check_policy": lambda p: "winrm" in p.name.lower() and "auto" in p.name.lower() and p.state == "Enabled",
        "check_item": lambda i: "transport" in i.value_name.lower() and "http" in i.value_data.lower() and "https" not in i.value_data.lower(),
        "title": "WinRM is configured with HTTP listener (not HTTPS)",
        "description": "WinRM service is configured to accept connections over HTTP rather than HTTPS.",
        "risk": "HTTP WinRM listeners transmit data without TLS encryption. Even if message-level encryption "
                "is used, the initial authentication may be vulnerable to downgrade attacks. "
                "HTTPS provides transport-level security and server authentication.",
        "recommendation": "Configure WinRM to use HTTPS listeners only. Create a certificate for the WinRM "
                          "service and disable HTTP listeners. Use 'winrm quickconfig -transport:https'.",
        "expected": "HTTPS transport only",
    },
    {
        "id": "REG-025",
        "name_pattern": "AutoShareWks|AutoShareServer|AdminShare",
        "key_pattern": "LanmanServer.*Parameters.*AutoShare",
        "path": f"{_GPP_REG} -> HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters",
        "severity": Severity.MEDIUM,
        "check_policy": None,
        "check_item": lambda i: "autoshare" in i.value_name.lower() and i.value_data == "1",
        "title": "Administrative shares (C$, ADMIN$) are enabled",
        "description": "Default administrative shares (C$, D$, ADMIN$) are explicitly enabled via GPO. "
                       "These hidden shares provide remote access to every drive and the Windows directory.",
        "risk": "Administrative shares are a primary lateral movement vector. Once an attacker obtains "
                "admin credentials, they can access C$ on any machine to deploy malware, exfiltrate data, "
                "or execute commands remotely via PsExec or similar tools.",
        "recommendation": "Disable administrative shares on workstations by setting AutoShareWks to 0. "
                          "For servers, evaluate whether ADMIN$ is needed and set AutoShareServer to 0 if not. "
                          "Registry: HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters\\AutoShareWks=0.",
        "expected": "Disabled (0) on workstations",
    },
    {
        "id": "REG-026",
        "name_pattern": "Removable Storage",
        "key_pattern": "RemovableStorage.*Deny_All|Deny_All.*Removable",
        "path": f"{_ADMIN_TPL} -> System -> Removable Storage Access -> All Removable Storage classes: Deny all access",
        "severity": Severity.MEDIUM,
        "check_policy": lambda p: "all removable storage" in p.name.lower() and "deny all" in p.name.lower() and p.state == "Disabled",
        "check_item": lambda i: "deny_all" in i.value_name.lower() and "removable" in i.key.lower() and i.value_data == "0",
        "title": "Removable storage deny-all policy is not enforced",
        "description": "The master 'All Removable Storage classes: Deny all access' policy is not enabled. "
                       "Individual deny-write/deny-execute rules (REG-018) provide partial protection, but "
                       "the deny-all switch blocks read, write, and execute on all removable devices.",
        "risk": "Without the deny-all switch, USB storage devices can still be read even if write/execute "
                "is blocked. Attackers can use USB devices to introduce malware via autorun or social engineering, "
                "and sensitive data can be read from removable media brought into the environment.",
        "recommendation": "Enable 'All Removable Storage classes: Deny all access' to block all access to USB drives, "
                          "SD cards, and other removable media. Grant exceptions via device ID allow lists for approved devices.",
        "expected": "Enabled (Deny all access)",
    },
]


@register_rule
class RegistryRules(AuditRule):
    rule_id_prefix = "REG"
    category = "Registry & Administrative Templates"

    def evaluate(self, gpo: GPO, all_gpos: list) -> Generator[Finding, None, None]:
        import re

        for check in REGISTRY_CHECKS:
            found = False

            # Check registry policies (admin templates)
            if check.get("check_policy"):
                for pol in gpo.registry_policies:
                    name_match = not check["name_pattern"] or check["name_pattern"].lower() in pol.name.lower() or check["name_pattern"].lower() in pol.category.lower()
                    key_match = check["key_pattern"] and re.search(check["key_pattern"], pol.name + pol.category, re.IGNORECASE)
                    if (name_match or key_match) and check["check_policy"](pol):
                        desc = check.get("description_fn", lambda v: check.get("description", ""))(pol.name) if "description_fn" in check else check.get("description", "")
                        yield Finding(
                            gpo_name=gpo.name, gpo_guid=gpo.guid,
                            rule_id=check["id"], category=self.category,
                            severity=check["severity"],
                            title=check["title"],
                            description=desc,
                            risk=check["risk"],
                            recommendation=check["recommendation"],
                            setting_path=check.get("path", ""),
                            current_value=f"{pol.name}: {pol.state}",
                            expected_value=check["expected"],
                        )
                        found = True
                        break

            # Check GPP registry items
            if not found and check.get("check_item"):
                for item in gpo.registry_items:
                    key_full = f"{item.hive}\\{item.key}\\{item.value_name}"
                    if re.search(check["key_pattern"], key_full, re.IGNORECASE):
                        if check["check_item"](item):
                            desc = check.get("description_fn", lambda v: check.get("description", ""))(item.value_data) if "description_fn" in check else check.get("description", "")
                            yield Finding(
                                gpo_name=gpo.name, gpo_guid=gpo.guid,
                                rule_id=check["id"], category=self.category,
                                severity=check["severity"],
                                title=check["title"],
                                description=desc,
                                risk=check["risk"],
                                recommendation=check["recommendation"],
                                setting_path=check.get("path", ""),
                                current_value=f"{key_full} = {item.value_data}",
                                expected_value=check["expected"],
                            )
                            break
