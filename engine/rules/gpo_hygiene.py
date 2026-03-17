from typing import Generator

from engine.models import GPO, Finding, Severity
from engine.rules.base import AuditRule, register_rule


@register_rule
class GPOHygieneRules(AuditRule):
    rule_id_prefix = "HYG"
    category = "GPO Hygiene"

    _checked_wef = False

    def evaluate(self, gpo: GPO, all_gpos: list) -> Generator[Finding, None, None]:
        # HYG-012: WEF subscription URL conflicts (run once)
        if not GPOHygieneRules._checked_wef:
            GPOHygieneRules._checked_wef = True
            yield from self._check_wef_conflicts(all_gpos)

        # HYG-002: Empty GPO
        if gpo.is_empty:
            yield Finding(
                gpo_name=gpo.name, gpo_guid=gpo.guid,
                rule_id="HYG-002", category=self.category,
                severity=Severity.LOW,
                title="GPO contains no settings",
                description=f"GPO '{gpo.name}' has no configured settings (version 0/0).",
                risk="Empty GPOs slow down Group Policy processing without providing any value. They add unnecessary overhead during logon/startup.",
                recommendation="Delete this empty GPO, or configure it with the intended settings if it was created for future use.",
                setting_path="GPO Properties -> Settings",
                current_value="No settings (v0)",
                expected_value="Configured settings",
            )

        # HYG-003: All settings disabled but still linked
        if gpo.gpo_status == "AllSettingsDisabled" and gpo.is_linked and gpo.has_enabled_links:
            yield Finding(
                gpo_name=gpo.name, gpo_guid=gpo.guid,
                rule_id="HYG-003", category=self.category,
                severity=Severity.MEDIUM,
                title="GPO has all settings disabled but is still actively linked",
                description=f"GPO '{gpo.name}' has all settings disabled (both Computer and User) but remains linked to: {', '.join(gpo.get_linked_ou_paths())}.",
                risk="A disabled GPO that remains linked causes unnecessary Group Policy processing overhead and may confuse administrators into thinking policies are applied.",
                recommendation="Either unlink this GPO from all OUs, or re-enable the settings if they should be active. Remove the GPO if no longer needed.",
                setting_path="GPO Properties -> GPO Status",
                current_value=f"AllSettingsDisabled, linked to {len(gpo.links)} OUs",
                expected_value="Either unlinked or settings enabled",
            )

        # HYG-005: UNUSED prefix but still linked/enabled
        if gpo.name.upper().startswith("UNUSED") and gpo.is_linked and gpo.has_enabled_links:
            linked_ous = gpo.get_linked_ou_paths()
            yield Finding(
                gpo_name=gpo.name, gpo_guid=gpo.guid,
                rule_id="HYG-005", category=self.category,
                severity=Severity.MEDIUM,
                title="GPO marked as UNUSED but still has active links",
                description=f"GPO '{gpo.name}' is prefixed with 'UNUSED' indicating it should be decommissioned, but it is still linked to: {', '.join(linked_ous)}.",
                risk="A GPO marked as unused but still linked may be applying unintended settings or may have been improperly decommissioned.",
                recommendation="Unlink this GPO from all OUs immediately. After verifying no impact, delete the GPO to complete decommissioning.",
                setting_path="GPO Properties -> Display Name",
                current_value=f"UNUSED but linked to {', '.join(linked_ous)}",
                expected_value="Unlinked and deleted",
            )

        # HYG-006: Version mismatch (Directory vs Sysvol)
        comp_mismatch = gpo.computer_version_directory != gpo.computer_version_sysvol
        user_mismatch = gpo.user_version_directory != gpo.user_version_sysvol
        if comp_mismatch or user_mismatch:
            parts = []
            if comp_mismatch:
                parts.append(f"Computer: Dir={gpo.computer_version_directory} vs Sysvol={gpo.computer_version_sysvol}")
            if user_mismatch:
                parts.append(f"User: Dir={gpo.user_version_directory} vs Sysvol={gpo.user_version_sysvol}")
            yield Finding(
                gpo_name=gpo.name, gpo_guid=gpo.guid,
                rule_id="HYG-006", category=self.category,
                severity=Severity.MEDIUM,
                title="GPO version mismatch between AD and SYSVOL",
                description=f"GPO '{gpo.name}' has inconsistent versions: {'; '.join(parts)}.",
                risk="Version mismatches indicate AD replication issues or SYSVOL replication failures (DFS-R/FRS). Clients may receive outdated or inconsistent policy settings.",
                recommendation="Investigate AD and SYSVOL replication health. Run 'dcdiag /test:sysvolcheck' and check DFS-R status. Force replication if needed.",
                setting_path="GPO Properties -> Version (AD vs SYSVOL)",
                current_value="; ".join(parts),
                expected_value="Matching versions",
            )

        # HYG-009: Excessive use of Enforced (check domain-wide, only flag once)
        if gpo.links:
            enforced_links = [l for l in gpo.links if l.no_override]
            if enforced_links:
                total_enforced = sum(
                    1 for g in all_gpos
                    if any(l.no_override for l in g.links)
                )
                if total_enforced > 3 and gpo.name <= min(
                    (g.name for g in all_gpos if any(l.no_override for l in g.links)),
                    default=gpo.name
                ):
                    yield Finding(
                        gpo_name=gpo.name, gpo_guid=gpo.guid,
                        rule_id="HYG-009", category=self.category,
                        severity=Severity.LOW,
                        title=f"Excessive use of Enforced (No Override) — {total_enforced} GPOs",
                        description=f"{total_enforced} GPOs use the Enforced flag. Overuse of enforcement undermines "
                                    f"the OU delegation model and makes policy troubleshooting difficult.",
                        risk="Excessive enforcement creates a rigid policy structure that bypasses OU-level delegation. "
                             "It can cause unexpected policy application and makes it harder to grant exceptions to specific OUs.",
                        recommendation="Reserve Enforced for critical security baselines only (e.g., password policy, Defender settings). "
                                       "Review all enforced GPOs and remove enforcement where delegation should apply.",
                        setting_path="GPO Link Properties -> Enforced",
                        current_value=f"{total_enforced} GPOs enforced",
                        expected_value="<=3 enforced GPOs (critical baselines only)",
                        confidence="Medium",
                        applies_to="domain",
                    )

        # HYG-011: Computer + User both enabled with settings in both
        if (gpo.computer_enabled and gpo.user_enabled and
                gpo.computer_version_directory > 0 and gpo.user_version_directory > 0):
            comp_settings = (
                len(gpo.account_settings) + len(gpo.security_options) +
                len(gpo.firewall_rules) + len(gpo.firewall_profiles)
            )
            user_settings = len(gpo.registry_policies)
            if comp_settings > 3 and user_settings > 3:
                yield Finding(
                    gpo_name=gpo.name, gpo_guid=gpo.guid,
                    rule_id="HYG-011", category=self.category,
                    severity=Severity.INFO,
                    title="GPO configures both Computer and User settings — consider splitting",
                    description=f"GPO '{gpo.name}' has significant settings in both Computer and User configurations.",
                    risk="Mixed Computer/User GPOs slow down Group Policy processing because both sections are evaluated "
                         "for every applicable scope. They also complicate WMI filtering and security group targeting.",
                    recommendation="Split into separate Computer and User GPOs. Disable the unused section in each "
                                   "to optimize processing. This also improves troubleshooting and delegation.",
                    setting_path="GPO Properties -> Computer/User Configuration",
                    current_value=f"Computer settings: ~{comp_settings}, User settings: ~{user_settings}",
                    expected_value="Separate Computer and User GPOs",
                    confidence="Low",
                    applies_to="domain",
                )

    def _check_wef_conflicts(self, all_gpos: list) -> Generator[Finding, None, None]:
        """Detect OUs where multiple GPOs configure Windows Event Forwarding subscriptions."""
        # Map each WEF-configuring GPO to its linked OUs
        ou_to_gpos = {}  # ou_path -> [gpo_name, ...]

        for g in all_gpos:
            is_wef = False

            # Check registry policies for event forwarding / subscription manager
            for pol in g.registry_policies:
                combined = (pol.name + (pol.category or "")).lower()
                if ("event forwarding" in combined or "subscription manager" in combined) and pol.state == "Enabled":
                    is_wef = True
                    break

            # Check GPP registry items for SubscriptionManager
            if not is_wef:
                for item in g.registry_items:
                    if "subscriptionmanager" in item.key.lower() or "subscriptionmanager" in item.value_name.lower():
                        is_wef = True
                        break

            if is_wef:
                for link in g.links:
                    if link.enabled and link.som_path:
                        ou_to_gpos.setdefault(link.som_path, [])
                        if g.name not in ou_to_gpos[link.som_path]:
                            ou_to_gpos[link.som_path].append(g.name)

        # Yield one finding per OU with 2+ WEF GPOs
        for ou_path, gpo_names in ou_to_gpos.items():
            if len(gpo_names) >= 2:
                bullet_list = "\n".join(f"  \u2022 {name}" for name in gpo_names)
                yield Finding(
                    gpo_name=f"OU: {ou_path}",
                    gpo_guid="",
                    rule_id="HYG-012",
                    category=self.category,
                    severity=Severity.MEDIUM,
                    title=f"Multiple GPOs configure WEF subscriptions on the same OU",
                    description=(
                        f"{len(gpo_names)} GPOs linked to '{ou_path}' each configure "
                        f"Windows Event Forwarding subscription URLs:\n\n{bullet_list}"
                    ),
                    risk=(
                        "When multiple GPOs set the WEF SubscriptionManager value on the same OU, "
                        "GPO precedence determines which one wins. The losing GPO's subscription URL "
                        "is silently ignored, causing events to not be forwarded to the intended collector."
                    ),
                    recommendation=(
                        f"Consolidate WEF subscription configuration into a single GPO per OU. "
                        f"Remove the WEF subscription settings from all but one GPO linked to '{ou_path}'."
                    ),
                    setting_path="Computer Configuration -> Policies -> Administrative Templates -> Windows Components -> Event Forwarding -> Configure target Subscription Manager",
                    current_value=f"{len(gpo_names)} GPOs configuring WEF on this OU",
                    expected_value="1 GPO per OU for WEF subscription configuration",
                )
