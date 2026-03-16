import re
from typing import Generator

from engine.models import GPO, Finding, Severity
from engine.rules.base import AuditRule, register_rule

# Well-known SID abbreviations in SDDL
SDDL_SIDS = {
    "WD": ("Everyone", "S-1-1-0"),
    "AU": ("Authenticated Users", "S-1-5-11"),
    "BU": ("Built-in Users", "S-1-5-32-545"),
    "AN": ("Anonymous", "S-1-5-7"),
    "CO": ("Creator Owner", ""),
    "BA": ("Built-in Administrators", "S-1-5-32-544"),
    "DA": ("Domain Admins", ""),
    "EA": ("Enterprise Admins", ""),
    "SO": ("Server Operators", "S-1-5-32-549"),
    "PO": ("Print Operators", "S-1-5-32-550"),
}

# SDDL access rights that indicate write/modify capability
WRITE_RIGHTS = {"WP", "WD", "WO", "SW", "GA", "GW", "CC", "DC", "FA"}


def _parse_dacl(sddl: str) -> list:
    """Parse DACL portion of SDDL string into ACE entries."""
    aces = []
    # Find DACL section
    dacl_match = re.search(r'D:[A-Z]*(\(.*)', sddl)
    if not dacl_match:
        return aces
    dacl_str = dacl_match.group(1)
    # Extract individual ACEs
    for ace_match in re.finditer(r'\(([^)]+)\)', dacl_str):
        parts = ace_match.group(1).split(";")
        if len(parts) >= 6:
            aces.append({
                "type": parts[0],      # A=Allow, D=Deny
                "flags": parts[1],
                "rights": parts[2],
                "object_guid": parts[3],
                "inherit_guid": parts[4],
                "trustee": parts[5],
            })
    return aces


def _has_write_rights(rights_str: str) -> bool:
    """Check if the rights string contains any write/modify permissions."""
    # Check 2-letter right codes
    for i in range(0, len(rights_str) - 1, 2):
        code = rights_str[i:i+2]
        if code in WRITE_RIGHTS:
            return True
    # Check hex mask for write bits
    if rights_str.startswith("0x"):
        try:
            mask = int(rights_str, 16)
            # WRITE_DAC=0x40000, WRITE_OWNER=0x80000, GENERIC_WRITE=0x40000000
            if mask & 0x400C0000:
                return True
        except ValueError:
            pass
    return False


@register_rule
class SDDLRules(AuditRule):
    rule_id_prefix = "SDDL"
    category = "GPO Permissions (SDDL)"

    def evaluate(self, gpo: GPO, all_gpos: list) -> Generator[Finding, None, None]:
        # Check parsed permissions first (from XML TrusteePermissions)
        for perm in gpo.permissions:
            sid = perm.get("sid", "")
            name = perm.get("name", "")
            access = perm.get("access", "")
            ptype = perm.get("type", "")

            if ptype != "Allow":
                continue

            is_write = "edit" in access.lower() or "delete" in access.lower() or "modify" in access.lower()

            # SDDL-001: Everyone can edit
            if sid == "S-1-1-0" and is_write:
                yield Finding(
                    gpo_name=gpo.name, gpo_guid=gpo.guid,
                    rule_id="SDDL-001", category=self.category,
                    severity=Severity.CRITICAL,
                    title="Everyone has edit permissions on GPO",
                    description=f"The 'Everyone' group has '{access}' permissions on GPO '{gpo.name}'.",
                    risk="Any user in the domain (including guests) can modify this GPO's settings. An attacker could inject malicious policies affecting all computers/users the GPO targets.",
                    recommendation="Remove 'Everyone' from GPO edit permissions. Only Domain Admins and Enterprise Admins should have edit access.",
                    setting_path=f"GPO Properties -> Security -> Delegation -> {name}",
                    current_value=f"Everyone: {access}",
                    expected_value="Domain Admins/Enterprise Admins only",
                )

            # SDDL-002: Authenticated Users can edit
            if sid == "S-1-5-11" and is_write:
                yield Finding(
                    gpo_name=gpo.name, gpo_guid=gpo.guid,
                    rule_id="SDDL-002", category=self.category,
                    severity=Severity.HIGH,
                    title="Authenticated Users have edit permissions on GPO",
                    description=f"'Authenticated Users' group has '{access}' permissions on GPO '{gpo.name}'.",
                    risk="Any domain-authenticated user can modify this GPO. A compromised standard user account could alter policies to escalate privileges or deploy malware domain-wide.",
                    recommendation="Remove 'Authenticated Users' edit permissions. Grant only 'Read' and 'Apply Group Policy' to Authenticated Users.",
                    setting_path=f"GPO Properties -> Security -> Delegation -> {name}",
                    current_value=f"Authenticated Users: {access}",
                    expected_value="Read and Apply Group Policy only",
                )

        # SDDL-003: Non-admin groups with edit permissions
        _ADMIN_SIDS = {"S-1-5-32-544", "S-1-5-18"}  # Built-in Admins, SYSTEM
        _ADMIN_NAMES = {"domain admins", "enterprise admins", "system", "builtin\\administrators"}
        for perm in gpo.permissions:
            sid = perm.get("sid", "")
            name = perm.get("name", "")
            access = perm.get("access", "")
            ptype = perm.get("type", "")
            if ptype != "Allow":
                continue
            is_write = "edit" in access.lower() or "delete" in access.lower() or "modify" in access.lower()
            if not is_write:
                continue
            if sid in _ADMIN_SIDS or sid == "S-1-1-0" or sid == "S-1-5-11":
                continue  # Already caught by SDDL-001/002
            if name.lower() in _ADMIN_NAMES:
                continue
            if name and sid != "S-1-1-0":
                yield Finding(
                    gpo_name=gpo.name, gpo_guid=gpo.guid,
                    rule_id="SDDL-003", category=self.category,
                    severity=Severity.HIGH,
                    title=f"Non-admin group '{name}' has edit permissions on GPO",
                    description=f"'{name}' (SID: {sid}) has '{access}' permissions on GPO '{gpo.name}'.",
                    risk="Non-admin accounts with GPO edit access create shadow admin paths. A compromised "
                         "member of this group can modify policies to escalate privileges domain-wide.",
                    recommendation=f"Remove '{name}' from GPO edit permissions. Only Domain Admins and "
                                   "Enterprise Admins should have edit access to Group Policy Objects.",
                    setting_path=f"GPO Properties -> Security -> Delegation -> {name}",
                    current_value=f"{name}: {access}",
                    expected_value="Domain Admins/Enterprise Admins only",
                )

        # Also check SDDL string directly if available
        if gpo.sddl:
            aces = _parse_dacl(gpo.sddl)
            for ace in aces:
                if ace["type"] != "A":  # Only check Allow ACEs
                    continue
                trustee = ace["trustee"]
                trustee_info = SDDL_SIDS.get(trustee)
                if not trustee_info:
                    continue

                trustee_name = trustee_info[0]

                has_write = _has_write_rights(ace["rights"])

                # SDDL-004: Creator Owner retains full control
                if trustee == "CO" and has_write:
                    yield Finding(
                        gpo_name=gpo.name, gpo_guid=gpo.guid,
                        rule_id="SDDL-004", category=self.category,
                        severity=Severity.MEDIUM,
                        title="Creator Owner retains full control on GPO",
                        description=f"Creator Owner has write permissions ({ace['rights']}) on GPO '{gpo.name}'.",
                        risk="If Creator Owner has full control, the user who created the GPO retains admin access "
                             "even if later removed from admin groups, creating a persistent backdoor.",
                        recommendation="Remove Creator Owner from GPO permissions. Use explicit group-based delegation.",
                        setting_path=f"GPO Properties -> Security -> Delegation -> Creator Owner",
                        current_value=f"Creator Owner: {ace['rights']}",
                        expected_value="No Creator Owner permissions",
                    )
                    continue

                if not has_write:
                    continue

                # Additional SDDL checks for broad groups
                if trustee in ("AN",):  # Anonymous
                    yield Finding(
                        gpo_name=gpo.name, gpo_guid=gpo.guid,
                        rule_id="SDDL-001", category=self.category,
                        severity=Severity.CRITICAL,
                        title=f"Anonymous has write permissions on GPO via SDDL",
                        description=f"'{trustee_name}' has write access to GPO '{gpo.name}'.",
                        risk="Anonymous write access to a GPO is a critical vulnerability. Unauthenticated attackers can modify domain policies.",
                        recommendation="Remove Anonymous access from GPO SDDL immediately.",
                        setting_path=f"GPO Properties -> Security -> Delegation -> {trustee_name}",
                        current_value=f"{trustee_name}: {ace['rights']}",
                        expected_value="No anonymous access",
                    )

            # SDDL-005: Non-standard SIDs with write access
            _KNOWN_ADMIN_TRUSTEES = {"BA", "DA", "EA", "SY", "CO"}
            for ace in aces:
                if ace["type"] != "A":
                    continue
                trustee = ace["trustee"]
                if trustee in SDDL_SIDS or trustee in _KNOWN_ADMIN_TRUSTEES:
                    continue  # Known SID, handled above
                if not _has_write_rights(ace["rights"]):
                    continue
                # This is a raw SID (like S-1-5-21-...) with write access
                if trustee.startswith("S-1-5-21-"):
                    yield Finding(
                        gpo_name=gpo.name, gpo_guid=gpo.guid,
                        rule_id="SDDL-005", category=self.category,
                        severity=Severity.MEDIUM,
                        title="Non-standard account has write access to GPO",
                        description=f"SID '{trustee}' has write permissions ({ace['rights']}) on GPO '{gpo.name}'. "
                                    "This appears to be a specific user, service account, or custom group.",
                        risk="Undocumented accounts with GPO write access create shadow admin paths. "
                             "If this account is compromised, an attacker can modify domain-wide policies.",
                        recommendation=f"Identify the account behind SID '{trustee}' and evaluate whether it "
                                       "requires GPO edit permissions. Remove if not necessary.",
                        setting_path=f"GPO Properties -> Security -> Delegation -> {trustee}",
                        current_value=f"{trustee}: {ace['rights']}",
                        expected_value="Only admin groups should have write access",
                    )
