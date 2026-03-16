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

_ADMIN_SIDS = {"S-1-5-32-544", "S-1-5-18"}
_ADMIN_NAMES = {"domain admins", "enterprise admins", "system", "builtin\\administrators"}
_KNOWN_ADMIN_TRUSTEES = {"BA", "DA", "EA", "SY", "CO"}


def _parse_dacl(sddl: str) -> list:
    """Parse DACL portion of SDDL string into ACE entries."""
    aces = []
    dacl_match = re.search(r'D:[A-Z]*(\(.*)', sddl)
    if not dacl_match:
        return aces
    dacl_str = dacl_match.group(1)
    for ace_match in re.finditer(r'\(([^)]+)\)', dacl_str):
        parts = ace_match.group(1).split(";")
        if len(parts) >= 6:
            aces.append({
                "type": parts[0],
                "flags": parts[1],
                "rights": parts[2],
                "object_guid": parts[3],
                "inherit_guid": parts[4],
                "trustee": parts[5],
            })
    return aces


def _has_write_rights(rights_str: str) -> bool:
    """Check if the rights string contains any write/modify permissions."""
    for i in range(0, len(rights_str) - 1, 2):
        code = rights_str[i:i+2]
        if code in WRITE_RIGHTS:
            return True
    if rights_str.startswith("0x"):
        try:
            mask = int(rights_str, 16)
            if mask & 0x400C0000:
                return True
        except ValueError:
            pass
    return False


def _check_gpo_permissions(gpo):
    """Analyze a single GPO's permissions and SDDL. Returns dict of rule_id -> list of detail strings."""
    hits = {}

    # --- Check parsed XML permissions ---
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

        # SDDL-001: Everyone can edit
        if sid == "S-1-1-0":
            hits.setdefault("SDDL-001", []).append(gpo.name)

        # SDDL-002: Authenticated Users can edit
        if sid == "S-1-5-11":
            hits.setdefault("SDDL-002", []).append(gpo.name)

        # SDDL-003: Non-admin groups with edit permissions
        if sid not in _ADMIN_SIDS and sid not in ("S-1-1-0", "S-1-5-11"):
            if name.lower() not in _ADMIN_NAMES and name:
                hits.setdefault("SDDL-003", []).append(f"{gpo.name} ({name})")

    # --- Check raw SDDL string ---
    if gpo.sddl:
        aces = _parse_dacl(gpo.sddl)
        for ace in aces:
            if ace["type"] != "A":
                continue
            trustee = ace["trustee"]
            trustee_info = SDDL_SIDS.get(trustee)

            if trustee_info and _has_write_rights(ace["rights"]):
                # SDDL-001 via SDDL: Anonymous write
                if trustee == "AN":
                    hits.setdefault("SDDL-001", []).append(gpo.name)

                # SDDL-004: Creator Owner retains full control
                if trustee == "CO":
                    hits.setdefault("SDDL-004", []).append(gpo.name)

            # SDDL-005: Non-standard SIDs with write access
            if trustee not in SDDL_SIDS and trustee not in _KNOWN_ADMIN_TRUSTEES:
                if _has_write_rights(ace["rights"]) and trustee.startswith("S-1-5-21-"):
                    hits.setdefault("SDDL-005", []).append(f"{gpo.name} (SID: {trustee})")

    return hits


@register_rule
class SDDLRules(AuditRule):
    rule_id_prefix = "SDDL"
    category = "GPO Permissions (SDDL)"

    _checked_global = False

    def evaluate(self, gpo: GPO, all_gpos: list) -> Generator[Finding, None, None]:
        if SDDLRules._checked_global:
            return
        SDDLRules._checked_global = True

        # Scan all GPOs and aggregate hits per rule
        aggregated = {}
        for g in all_gpos:
            for rule_id, entries in _check_gpo_permissions(g).items():
                aggregated.setdefault(rule_id, []).extend(entries)

        # Deduplicate entries per rule
        for rule_id in aggregated:
            seen = []
            for entry in aggregated[rule_id]:
                if entry not in seen:
                    seen.append(entry)
            aggregated[rule_id] = seen

        # --- Yield one finding per rule ---

        if "SDDL-001" in aggregated:
            gpos = aggregated["SDDL-001"]
            bullet_list = "\n".join(f"  \u2022 {g}" for g in gpos)
            yield Finding(
                gpo_name=f"{len(gpos)} GPO(s) affected", gpo_guid="",
                rule_id="SDDL-001", category=self.category,
                severity=Severity.CRITICAL,
                title="Everyone / Anonymous has edit permissions on GPO(s)",
                description=f"The 'Everyone' or 'Anonymous' group has write permissions on {len(gpos)} GPO(s):\n\n{bullet_list}",
                risk="Any user in the domain (including guests or unauthenticated users) can modify these GPOs. "
                     "An attacker could inject malicious policies affecting all computers and users targeted by these GPOs.",
                recommendation="Remove 'Everyone' and 'Anonymous' from GPO edit permissions. "
                               "Only Domain Admins and Enterprise Admins should have edit access.",
                setting_path="GPO Properties -> Security -> Delegation",
                current_value=f"{len(gpos)} GPO(s) with Everyone/Anonymous write access",
                expected_value="Domain Admins/Enterprise Admins only",
            )

        if "SDDL-002" in aggregated:
            gpos = aggregated["SDDL-002"]
            bullet_list = "\n".join(f"  \u2022 {g}" for g in gpos)
            yield Finding(
                gpo_name=f"{len(gpos)} GPO(s) affected", gpo_guid="",
                rule_id="SDDL-002", category=self.category,
                severity=Severity.HIGH,
                title="Authenticated Users have edit permissions on GPO(s)",
                description=f"'Authenticated Users' group has write permissions on {len(gpos)} GPO(s):\n\n{bullet_list}",
                risk="Any domain-authenticated user can modify these GPOs. A compromised standard user account "
                     "could alter policies to escalate privileges or deploy malware domain-wide.",
                recommendation="Remove 'Authenticated Users' edit permissions. "
                               "Grant only 'Read' and 'Apply Group Policy' to Authenticated Users.",
                setting_path="GPO Properties -> Security -> Delegation",
                current_value=f"{len(gpos)} GPO(s) with Authenticated Users write access",
                expected_value="Read and Apply Group Policy only",
            )

        if "SDDL-003" in aggregated:
            entries = aggregated["SDDL-003"]
            bullet_list = "\n".join(f"  \u2022 {e}" for e in entries)
            yield Finding(
                gpo_name=f"{len(entries)} delegation issue(s)", gpo_guid="",
                rule_id="SDDL-003", category=self.category,
                severity=Severity.HIGH,
                title="Non-admin group(s) have edit permissions on GPO(s)",
                description=f"Non-admin groups have write permissions on GPO(s):\n\n{bullet_list}",
                risk="Non-admin accounts with GPO edit access create shadow admin paths. A compromised "
                     "member of these groups can modify policies to escalate privileges domain-wide.",
                recommendation="Remove non-admin groups from GPO edit permissions. Only Domain Admins and "
                               "Enterprise Admins should have edit access to Group Policy Objects.",
                setting_path="GPO Properties -> Security -> Delegation",
                current_value=f"{len(entries)} non-admin delegation(s) with write access",
                expected_value="Domain Admins/Enterprise Admins only",
            )

        if "SDDL-004" in aggregated:
            gpos = aggregated["SDDL-004"]
            bullet_list = "\n".join(f"  \u2022 {g}" for g in gpos)
            yield Finding(
                gpo_name=f"{len(gpos)} GPO(s) affected", gpo_guid="",
                rule_id="SDDL-004", category=self.category,
                severity=Severity.MEDIUM,
                title="Creator Owner retains full control on GPO(s)",
                description=f"Creator Owner has write permissions on {len(gpos)} GPO(s):\n\n{bullet_list}",
                risk="If Creator Owner has full control, the user who created the GPO retains admin access "
                     "even if later removed from admin groups, creating a persistent backdoor.",
                recommendation="Remove Creator Owner from GPO permissions. Use explicit group-based delegation.",
                setting_path="GPO Properties -> Security -> Delegation -> Creator Owner",
                current_value=f"{len(gpos)} GPO(s) with Creator Owner write access",
                expected_value="No Creator Owner permissions",
            )

        if "SDDL-005" in aggregated:
            entries = aggregated["SDDL-005"]
            bullet_list = "\n".join(f"  \u2022 {e}" for e in entries)
            yield Finding(
                gpo_name=f"{len(entries)} GPO(s) affected", gpo_guid="",
                rule_id="SDDL-005", category=self.category,
                severity=Severity.MEDIUM,
                title="Non-standard account(s) have write access to GPO(s)",
                description=f"Unresolved SIDs have write permissions on GPO(s):\n\n{bullet_list}",
                risk="Undocumented accounts with GPO write access create shadow admin paths. "
                     "If these accounts are compromised, an attacker can modify domain-wide policies.",
                recommendation="Identify the accounts behind these SIDs and evaluate whether they "
                               "require GPO edit permissions. Remove if not necessary.",
                setting_path="GPO Properties -> Security -> Delegation",
                current_value=f"{len(entries)} non-standard SID(s) with write access",
                expected_value="Only admin groups should have write access",
            )
