from typing import Generator

from engine.models import GPO, Finding, Severity
from engine.rules.base import AuditRule, register_rule

# Well-known SIDs that indicate overly broad access
EVERYONE_SID = "S-1-1-0"
AUTH_USERS_SID = "S-1-5-11"
DOMAIN_USERS_SID_SUFFIX = "-513"
USERS_SID = "S-1-5-32-545"

# Dangerous privileges and their expected restricted membership
DANGEROUS_PRIVILEGES = {
    "SeDebugPrivilege": {
        "display": "Debug programs",
        "severity": Severity.CRITICAL,
        "risk": "Allows memory inspection of any process, including LSASS. Attackers can extract credentials, inject code, and bypass virtually all security controls.",
        "allowed_sids": set(),  # Should ideally be empty or Administrators only
    },
    "SeTcbPrivilege": {
        "display": "Act as part of the operating system",
        "severity": Severity.CRITICAL,
        "risk": "Grants the ability to act as a trusted part of the OS, enabling complete system compromise including token manipulation and privilege escalation.",
        "allowed_sids": set(),  # Should be empty
    },
    "SeBackupPrivilege": {
        "display": "Back up files and directories",
        "severity": Severity.HIGH,
        "risk": "Allows reading any file on the system regardless of ACLs, including SAM database, NTDS.dit, and registry hives containing credential material.",
        "allowed_sids": {"S-1-5-32-544", "S-1-5-32-551"},  # Administrators, Backup Operators
    },
    "SeRestorePrivilege": {
        "display": "Restore files and directories",
        "severity": Severity.HIGH,
        "risk": "Allows writing to any file on the system regardless of ACLs. Can be used to replace system binaries, modify security configurations, or plant backdoors.",
        "allowed_sids": {"S-1-5-32-544", "S-1-5-32-551"},  # Administrators, Backup Operators
    },
    "SeTakeOwnershipPrivilege": {
        "display": "Take ownership of files or other objects",
        "severity": Severity.HIGH,
        "risk": "Allows taking ownership of any securable object, effectively bypassing all access controls to gain full control over files, registry keys, and AD objects.",
        "allowed_sids": {"S-1-5-32-544"},  # Administrators only
    },
    "SeLoadDriverPrivilege": {
        "display": "Load and unload device drivers",
        "severity": Severity.HIGH,
        "risk": "Allows loading kernel-mode drivers, which can be used to install rootkits, disable security software, or gain ring-0 access to the system.",
        "allowed_sids": {"S-1-5-32-544"},  # Administrators only
    },
    "SeImpersonatePrivilege": {
        "display": "Impersonate a client after authentication",
        "severity": Severity.HIGH,
        "risk": "Allows impersonating other users' tokens. Combined with token manipulation techniques (e.g., potato attacks), can escalate to SYSTEM.",
        "allowed_sids": {"S-1-5-32-544", "S-1-5-6", "S-1-5-19", "S-1-5-20"},  # Admins, Service, LocalService, NetworkService
    },
    "SeRemoteInteractiveLogonRight": {
        "display": "Allow log on through Remote Desktop Services",
        "severity": Severity.MEDIUM,
        "risk": "Broad RDP access increases the attack surface for lateral movement and credential theft via interactive sessions.",
        "allowed_sids": {"S-1-5-32-544", "S-1-5-32-555"},  # Administrators, Remote Desktop Users
    },
}


_URA_BASE = "Computer Configuration -> Policies -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment"


def _is_broad_sid(sid: str) -> bool:
    """Check if a SID represents a broad/dangerous group."""
    return (
        sid == EVERYONE_SID
        or sid == AUTH_USERS_SID
        or sid == USERS_SID
        or sid.endswith(DOMAIN_USERS_SID_SUFFIX)
    )


@register_rule
class UserRightsRules(AuditRule):
    rule_id_prefix = "URA"
    category = "User Rights Assignment"

    def evaluate(self, gpo: GPO, all_gpos: list) -> Generator[Finding, None, None]:
        if not gpo.user_rights:
            return

        counter = 1
        for ura in gpo.user_rights:
            priv_info = DANGEROUS_PRIVILEGES.get(ura.name)
            if not priv_info:
                # Still check for broad assignments on any privilege
                broad = [m for m in ura.members if _is_broad_sid(m.get("sid", ""))]
                if broad:
                    names = ", ".join(m.get("name", m.get("sid", "")) for m in broad)
                    yield Finding(
                        gpo_name=gpo.name, gpo_guid=gpo.guid,
                        rule_id=f"URA-{counter:03d}", category=self.category,
                        severity=Severity.MEDIUM,
                        title=f"Privilege '{ura.name}' granted to broad group",
                        description=f"The privilege '{ura.name}' is assigned to: {names}.",
                        risk="Granting privileges to broad groups (Everyone, Authenticated Users, Domain Users) exposes the capability to potentially all users in the domain.",
                        recommendation=f"Restrict '{ura.name}' to only the specific users or groups that require it. Remove broad groups like Everyone or Domain Users.",
                        setting_path=f"{_URA_BASE} -> {ura.name}",
                        current_value=names,
                        expected_value="Restricted groups only",
                    )
                counter += 1
                continue

            member_sids = {m.get("sid", "") for m in ura.members}
            member_names = [m.get("name", m.get("sid", "")) for m in ura.members]
            allowed = priv_info["allowed_sids"]

            # Check for broad group membership
            broad = [m for m in ura.members if _is_broad_sid(m.get("sid", ""))]
            unauthorized = member_sids - allowed - {""}

            if broad:
                names = ", ".join(m.get("name", m.get("sid", "")) for m in broad)
                yield Finding(
                    gpo_name=gpo.name, gpo_guid=gpo.guid,
                    rule_id=f"URA-{counter:03d}", category=self.category,
                    severity=priv_info["severity"],
                    title=f"'{priv_info['display']}' granted to broad group",
                    description=f"The dangerous privilege '{ura.name}' ({priv_info['display']}) is assigned to broad groups: {names}.",
                    risk=priv_info["risk"],
                    recommendation=f"Remove broad groups from '{ura.name}'. This privilege should only be assigned to: {', '.join(allowed) if allowed else 'no accounts (remove entirely)'}.",
                    setting_path=f"{_URA_BASE} -> {ura.name}",
                    current_value=", ".join(member_names),
                    expected_value="Administrators only" if allowed else "No assignments",
                )
            elif unauthorized and allowed:
                extra_names = ", ".join(m.get("name", m.get("sid", "")) for m in ura.members if m.get("sid", "") in unauthorized)
                yield Finding(
                    gpo_name=gpo.name, gpo_guid=gpo.guid,
                    rule_id=f"URA-{counter:03d}", category=self.category,
                    severity=Severity.MEDIUM,
                    title=f"'{priv_info['display']}' granted to non-standard accounts",
                    description=f"The privilege '{ura.name}' is assigned to accounts beyond the expected set: {extra_names}.",
                    risk=priv_info["risk"],
                    recommendation=f"Review and restrict '{ura.name}' assignments. Expected members: Administrators and Backup Operators only.",
                    setting_path=f"{_URA_BASE} -> {ura.name}",
                    current_value=", ".join(member_names),
                    expected_value="Standard groups only",
                )

            counter += 1
