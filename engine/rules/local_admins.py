from typing import Generator

from engine.models import GPO, Finding, Severity
from engine.rules.base import AuditRule, register_rule

BROAD_GROUPS = {
    "everyone", "domain users", "authenticated users", "users",
    "domain computers", "builtin\\users",
}

ADMIN_GROUP_NAMES = {"administrators", "builtin\\administrators", "local administrators"}


def _is_admin_group(name: str) -> bool:
    return any(ag in name.lower() for ag in ADMIN_GROUP_NAMES)


def _is_broad_group(name: str) -> bool:
    return name.lower().strip() in BROAD_GROUPS or any(bg in name.lower() for bg in BROAD_GROUPS)


@register_rule
class LocalAdminRules(AuditRule):
    rule_id_prefix = "ADM"
    category = "Local Administrator Management"

    def evaluate(self, gpo: GPO, all_gpos: list) -> Generator[Finding, None, None]:
        # Check Restricted Groups
        for rg in gpo.restricted_groups:
            if _is_admin_group(rg.group_name):
                broad_members = [
                    m.get("name", m.get("sid", ""))
                    for m in rg.members
                    if _is_broad_group(m.get("name", ""))
                ]
                if broad_members:
                    yield Finding(
                        gpo_name=gpo.name, gpo_guid=gpo.guid,
                        rule_id="ADM-001", category=self.category,
                        severity=Severity.CRITICAL,
                        title="Broad group added to local Administrators via Restricted Groups",
                        description=f"Restricted Groups policy adds broad groups to local Administrators: {', '.join(broad_members)}.",
                        risk="Adding broad groups (Domain Users, Authenticated Users, Everyone) to local Administrators "
                             "grants every matching user full administrative access to the machine. This effectively removes "
                             "all privilege boundaries and enables trivial privilege escalation across the domain.",
                        recommendation="Remove broad groups from local Administrators. Use dedicated security groups with "
                                       "only approved personnel. Implement a tiered access model.",
                        setting_path="Computer Configuration -> Policies -> Windows Settings -> Security Settings -> Restricted Groups -> Administrators",
                        current_value=f"Administrators members include: {', '.join(broad_members)}",
                        expected_value="Only approved admin security groups",
                        confidence="High",
                        applies_to="workstations, servers",
                        architecture_fix="tighten filtering",
                    )

        # Check GPP Local Users and Groups preferences
        for item in gpo.preference_items:
            if item.item_type != "LocalGroup":
                continue
            if not _is_admin_group(item.name):
                continue
            members = item.properties.get("members", [])
            if not isinstance(members, list):
                continue
            broad_members = [
                m.get("name", "") for m in members
                if _is_broad_group(m.get("name", "")) and m.get("action", "").upper() != "REMOVE"
            ]
            if broad_members:
                yield Finding(
                    gpo_name=gpo.name, gpo_guid=gpo.guid,
                    rule_id="ADM-001", category=self.category,
                    severity=Severity.CRITICAL,
                    title="Broad group added to local Administrators via GPP Local Group",
                    description=f"GPP Local Users and Groups adds broad groups to Administrators: {', '.join(broad_members)}.",
                    risk="Granting local admin to broad groups gives every user full machine control, "
                         "enabling credential theft, lateral movement, and complete domain compromise.",
                    recommendation="Remove broad groups. Use targeted security groups for admin access.",
                    setting_path=f"Computer Configuration -> Preferences -> Control Panel Settings -> Local Users and Groups -> {item.name}",
                    current_value=f"Members include: {', '.join(broad_members)}",
                    expected_value="Only specific admin security groups",
                    confidence="High",
                    applies_to="workstations, servers",
                )

        # ADM-002: Cross-GPO conflict on local admin membership
        # Check if multiple GPOs modify Administrators on overlapping OUs
        if gpo.restricted_groups or any(
            p.item_type == "LocalGroup" and _is_admin_group(p.name) for p in gpo.preference_items
        ):
            conflicting = []
            my_ous = set(gpo.get_linked_ou_paths())
            for other in all_gpos:
                if other.guid == gpo.guid:
                    continue
                other_modifies_admins = (
                    any(_is_admin_group(rg.group_name) for rg in other.restricted_groups) or
                    any(p.item_type == "LocalGroup" and _is_admin_group(p.name) for p in other.preference_items)
                )
                if not other_modifies_admins:
                    continue
                other_ous = set(other.get_linked_ou_paths())
                # Check overlap
                overlap = my_ous & other_ous
                if not overlap:
                    # Check parent-child
                    for my_ou in my_ous:
                        for other_ou in other_ous:
                            if my_ou.startswith(other_ou + "/") or other_ou.startswith(my_ou + "/"):
                                overlap.add(other_ou if my_ou.startswith(other_ou + "/") else my_ou)
                if overlap:
                    conflicting.append(other.name)

            if conflicting and gpo.name < conflicting[0]:  # Report once per pair
                yield Finding(
                    gpo_name=gpo.name, gpo_guid=gpo.guid,
                    rule_id="ADM-002", category=self.category,
                    severity=Severity.HIGH,
                    title="Conflicting local Administrator management across GPOs",
                    description=f"GPO '{gpo.name}' and GPOs [{', '.join(conflicting)}] both modify local Administrators "
                                f"membership on overlapping OUs.",
                    risk="Multiple GPOs managing the same local group creates unpredictable membership. "
                         "Restricted Groups replaces members entirely while GPP can add/remove individually. "
                         "Mixing these approaches often results in unintended admin access.",
                    recommendation="Consolidate local Administrator management into a single authoritative GPO per scope. "
                                   "Use either Restricted Groups OR GPP Local Groups, not both.",
                    setting_path="Computer Configuration -> Policies -> Windows Settings -> Security Settings -> Restricted Groups -> Administrators",
                    current_value=f"Multiple GPOs: {gpo.name}, {', '.join(conflicting)}",
                    expected_value="Single authoritative GPO",
                    confidence="Medium",
                    applies_to="workstations, servers",
                    architecture_fix="merge",
                )
