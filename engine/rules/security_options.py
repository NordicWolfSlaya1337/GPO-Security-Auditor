from typing import Generator

from engine.models import GPO, Finding, Severity
from engine.rules.base import AuditRule, register_rule

_SEC_BASE = "Computer Configuration -> Policies -> Windows Settings -> Security Settings -> Local Policies -> Security Options"

# Registry key fragments mapped to security checks
# Format: (key_fragment, check_func_name, rule_id)
SECURITY_CHECKS = [
    {
        "id": "SEC-001",
        "key": "EnableGuestAccount",
        "path": f"{_SEC_BASE} -> Accounts: Guest account status",
        "severity": Severity.HIGH,
        "check": lambda opt: opt.setting_number == 1,
        "title": "Guest account is enabled",
        "description": "The built-in Guest account is enabled.",
        "risk": "The Guest account provides unauthenticated access to the system. Attackers can use it for initial access without needing credentials.",
        "recommendation": "Disable the Guest account. No legitimate use case justifies enabling it in production environments.",
        "current": lambda opt: "Enabled",
        "expected": "Disabled",
    },
    {
        "id": "SEC-002",
        "key": "LmCompatibilityLevel",
        "path": f"{_SEC_BASE} -> Network security: LAN Manager authentication level",
        "severity": Severity.CRITICAL,
        "check": lambda opt: opt.setting_number is not None and opt.setting_number < 3,
        "title": "LAN Manager authentication level is weak",
        "description_fn": lambda opt: f"LAN Manager compatibility level is set to {opt.setting_number}. Values below 3 allow NTLMv1 or LM responses.",
        "risk": "NTLMv1 and LM authentication protocols are cryptographically weak. NTLMv1 hashes can be cracked instantly, and LM hashes can be cracked in seconds. Attackers on the network can capture and crack these credentials.",
        "recommendation": "Set 'Network security: LAN Manager authentication level' to 'Send NTLMv2 response only. Refuse LM & NTLM' (level 5). At minimum set to level 3.",
        "current_fn": lambda opt: f"Level {opt.setting_number}",
        "expected": "Level 5 (NTLMv2 only, refuse LM & NTLM)",
    },
    {
        "id": "SEC-003",
        "key": "LSAAnonymousNameLookup",
        "path": f"{_SEC_BASE} -> Network access: Allow anonymous SID/Name translation",
        "severity": Severity.MEDIUM,
        "check": lambda opt: opt.setting_number == 1,
        "title": "Anonymous SID/Name translation is allowed",
        "description": "Anonymous users can translate SIDs to usernames and vice versa.",
        "risk": "Allows anonymous enumeration of user accounts and group memberships, giving attackers a reconnaissance advantage for targeted attacks.",
        "recommendation": "Disable 'Network access: Allow anonymous SID/Name translation'.",
        "current": lambda opt: "Enabled",
        "expected": "Disabled",
    },
    {
        "id": "SEC-004",
        "key": "RestrictAnonymousSAM",
        "path": f"{_SEC_BASE} -> Network access: Do not allow anonymous enumeration of SAM accounts",
        "severity": Severity.HIGH,
        "check": lambda opt: opt.setting_number == 0,
        "title": "Anonymous enumeration of SAM accounts is allowed",
        "description": "Anonymous users can enumerate Security Account Manager (SAM) accounts.",
        "risk": "Attackers can anonymously enumerate all domain user accounts, making password spraying and targeted attacks trivially easy.",
        "recommendation": "Enable 'Network access: Do not allow anonymous enumeration of SAM accounts' (set to 1).",
        "current": lambda opt: "Not restricted",
        "expected": "Restricted",
    },
    {
        "id": "SEC-005",
        "key": "MACHINE\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters\\RequireSecuritySignature",
        "path": f"{_SEC_BASE} -> Microsoft network server: Digitally sign communications (always)",
        "severity": Severity.HIGH,
        "check": lambda opt: opt.setting_number == 0,
        "title": "SMB server signing is not required",
        "description": "The SMB server does not require packet signing.",
        "risk": "Without required SMB signing, attackers can perform man-in-the-middle attacks on SMB connections, intercepting or modifying file transfers and relaying authentication (NTLM relay attacks).",
        "recommendation": "Enable 'Microsoft network server: Digitally sign communications (always)' to require SMB signing.",
        "current": lambda opt: "Not required",
        "expected": "Required",
    },
    {
        "id": "SEC-006",
        "key": "MACHINE\\System\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters\\RequireSecuritySignature",
        "path": f"{_SEC_BASE} -> Microsoft network client: Digitally sign communications (always)",
        "severity": Severity.MEDIUM,
        "check": lambda opt: opt.setting_number == 0,
        "title": "SMB client signing is not required",
        "description": "The SMB client does not require packet signing.",
        "risk": "Workstations without required SMB signing are vulnerable to NTLM relay and man-in-the-middle attacks when connecting to file shares.",
        "recommendation": "Enable 'Microsoft network client: Digitally sign communications (always)' to require SMB client signing.",
        "current": lambda opt: "Not required",
        "expected": "Required",
    },
    {
        "id": "SEC-007",
        "key": "InactivityTimeoutSecs",
        "path": f"{_SEC_BASE} -> Interactive logon: Machine inactivity limit",
        "severity": Severity.LOW,
        "check": lambda opt: opt.setting_number is not None and opt.setting_number > 900,
        "title": "Machine inactivity timeout is too long",
        "description_fn": lambda opt: f"Machine inactivity lock timeout is {opt.setting_number} seconds ({opt.setting_number // 60} minutes).",
        "risk": "Long inactivity timeouts leave sessions open for physical access attacks when users step away from their workstations.",
        "recommendation": "Set machine inactivity limit to 900 seconds (15 minutes) or less.",
        "current_fn": lambda opt: f"{opt.setting_number} seconds",
        "expected": "<=900 seconds (15 minutes)",
    },
    {
        "id": "SEC-008",
        "key": "DisableCAD",
        "path": f"{_SEC_BASE} -> Interactive logon: Do not require CTRL+ALT+DEL",
        "severity": Severity.LOW,
        "check": lambda opt: opt.setting_number == 1,
        "title": "Ctrl+Alt+Del is not required for logon",
        "description": "Interactive logon does not require Ctrl+Alt+Del (Secure Attention Sequence).",
        "risk": "Without requiring Ctrl+Alt+Del, users are vulnerable to trojan logon screens that capture credentials.",
        "recommendation": "Enable 'Interactive logon: Do not require CTRL+ALT+DEL' should be set to Disabled (require Ctrl+Alt+Del).",
        "current": lambda opt: "Not required",
        "expected": "Required",
    },
    {
        "id": "SEC-009",
        "key": "CachedLogonsCount",
        "path": f"{_SEC_BASE} -> Interactive logon: Number of previous logons to cache",
        "severity": Severity.MEDIUM,
        "check": lambda opt: opt.setting_number is not None and opt.setting_number > 4,
        "title": "Too many cached logon credentials stored",
        "description_fn": lambda opt: f"Windows caches {opt.setting_number} previous logon credentials.",
        "risk": "Cached credentials can be extracted from a compromised machine by tools like mimikatz. More cached credentials means more accounts potentially compromised from a single machine.",
        "recommendation": "Reduce cached logon count to 2-4 for workstations, 0-1 for servers.",
        "current_fn": lambda opt: str(opt.setting_number),
        "expected": "<=4 (2 for servers)",
    },
    {
        "id": "SEC-010",
        "key": "NoLMHash",
        "path": f"{_SEC_BASE} -> Network security: Do not store LAN Manager hash value on next password change",
        "severity": Severity.CRITICAL,
        "check": lambda opt: opt.setting_number == 0,
        "title": "LAN Manager hash storage is enabled",
        "description": "Windows is storing LM hashes of passwords.",
        "risk": "LM hashes are cryptographically trivial to crack (seconds on modern hardware). Any password stored as an LM hash should be considered compromised if the hash is obtained.",
        "recommendation": "Enable 'Network security: Do not store LAN Manager hash value on next password change' (set NoLMHash to 1).",
        "current": lambda opt: "LM hashes stored",
        "expected": "LM hashes not stored",
    },
    {
        "id": "SEC-011",
        "key": "EveryoneIncludesAnonymous",
        "path": f"{_SEC_BASE} -> Network access: Let Everyone permissions apply to anonymous users",
        "severity": Severity.HIGH,
        "check": lambda opt: opt.setting_number == 1,
        "title": "Everyone group includes Anonymous users",
        "description": "The 'Everyone' security group includes anonymous (unauthenticated) users.",
        "risk": "When Everyone includes Anonymous, any permission granted to Everyone also applies to unauthenticated users, "
                "allowing anonymous access to shared resources and potential data exposure.",
        "recommendation": "Disable 'Network access: Let Everyone permissions apply to anonymous users' (set EveryoneIncludesAnonymous to 0).",
        "current": lambda opt: "Enabled (Anonymous included)",
        "expected": "Disabled",
    },
    {
        "id": "SEC-012",
        "key": "RestrictAnonymous",
        "path": f"{_SEC_BASE} -> Network access: Restrict anonymous access to Named Pipes and Shares",
        "severity": Severity.HIGH,
        "check": lambda opt: opt.setting_number is not None and opt.setting_number == 0,
        "title": "Anonymous access restrictions are not configured",
        "description": "RestrictAnonymous is set to 0, allowing full anonymous enumeration of shares and accounts.",
        "risk": "Without restricting anonymous access, unauthenticated users can enumerate shares, users, groups, and other "
                "sensitive information from the domain, aiding reconnaissance attacks.",
        "recommendation": "Set 'Network access: Restrict anonymous access to Named Pipes and Shares' and "
                          "'Network access: Do not allow anonymous enumeration of SAM accounts and shares' to restrict anonymous access.",
        "current_fn": lambda opt: f"RestrictAnonymous = {opt.setting_number}",
        "expected": "RestrictAnonymous >= 1",
    },
    {
        "id": "SEC-013",
        "key": "LDAPServerIntegrity",
        "path": f"{_SEC_BASE} -> Domain controller: LDAP server signing requirements",
        "severity": Severity.HIGH,
        "check": lambda opt: opt.setting_number is not None and opt.setting_number < 2,
        "title": "LDAP server signing is not required",
        "description_fn": lambda opt: f"LDAP server signing level is {opt.setting_number} (0=None, 1=Negotiate, 2=Require).",
        "risk": "Without required LDAP signing, attackers can perform man-in-the-middle attacks on LDAP queries, "
                "intercepting or modifying directory lookups and potentially injecting malicious responses.",
        "recommendation": "Set 'Domain controller: LDAP server signing requirements' to 'Require signing' (value 2).",
        "current_fn": lambda opt: f"Level {opt.setting_number}",
        "expected": "Level 2 (Require signing)",
    },
    {
        "id": "SEC-014",
        "key": "LdapEnforceChannelBinding",
        "path": f"{_SEC_BASE} -> Domain controller: LDAP server channel binding token requirements",
        "severity": Severity.MEDIUM,
        "check": lambda opt: opt.setting_number is not None and opt.setting_number < 2,
        "title": "LDAP channel binding is not enforced",
        "description_fn": lambda opt: f"LDAP channel binding token level is {opt.setting_number} (0=Never, 1=When supported, 2=Always).",
        "risk": "Without enforced LDAP channel binding, attackers can relay LDAP authentication tokens via man-in-the-middle attacks, "
                "potentially gaining unauthorized access to directory services.",
        "recommendation": "Set LDAP channel binding to 'Always' (value 2) after verifying client compatibility. "
                          "This protects against LDAP relay attacks (CVE-2017-8563).",
        "current_fn": lambda opt: f"Level {opt.setting_number}",
        "expected": "Level 2 (Always)",
    },
]


@register_rule
class SecurityOptionsRules(AuditRule):
    rule_id_prefix = "SEC"
    category = "Security Options"

    def evaluate(self, gpo: GPO, all_gpos: list) -> Generator[Finding, None, None]:
        if not gpo.security_options:
            return

        for check in SECURITY_CHECKS:
            key_fragment = check["key"]
            matching_opts = [
                opt for opt in gpo.security_options
                if key_fragment.lower() in opt.key_name.lower()
            ]

            for opt in matching_opts:
                if check["check"](opt):
                    desc = check.get("description_fn", lambda o: check.get("description", ""))(opt) if "description_fn" in check else check.get("description", "")
                    current = check.get("current_fn", check.get("current", lambda o: ""))(opt) if callable(check.get("current_fn")) else (check.get("current", lambda o: "")(opt) if callable(check.get("current")) else str(check.get("current", "")))

                    yield Finding(
                        gpo_name=gpo.name, gpo_guid=gpo.guid,
                        rule_id=check["id"], category=self.category,
                        severity=check["severity"],
                        title=check["title"],
                        description=desc,
                        risk=check["risk"],
                        recommendation=check["recommendation"],
                        setting_path=check.get("path", ""),
                        current_value=current,
                        expected_value=check["expected"],
                    )
