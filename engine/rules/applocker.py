import re
from typing import Generator

from engine.models import GPO, Finding, Severity
from engine.rules.base import AuditRule, register_rule

_APL_BASE = "Computer Configuration -> Policies -> Windows Settings -> Security Settings -> Application Control Policies -> AppLocker"

APPLOCKER_KEYWORDS = ["applocker", "application control", "srp", "software restriction"]
WDAC_KEYWORDS = ["wdac", "windows defender application control", "code integrity", "cipolicy"]


def _has_app_control(gpo: GPO) -> bool:
    for pol in gpo.registry_policies:
        text = f"{pol.name} {pol.category}".lower()
        if any(kw in text for kw in APPLOCKER_KEYWORDS + WDAC_KEYWORDS):
            return True
    for item in gpo.registry_items:
        text = f"{item.key} {item.value_name}".lower()
        if any(kw in text for kw in APPLOCKER_KEYWORDS + WDAC_KEYWORDS):
            return True
    return False


@register_rule
class AppLockerRules(AuditRule):
    rule_id_prefix = "APL"
    category = "Application Control (AppLocker/WDAC)"

    _checked_global = False

    def evaluate(self, gpo: GPO, all_gpos: list) -> Generator[Finding, None, None]:
        # APL-001: Global check - no application control configured anywhere
        if not AppLockerRules._checked_global:
            AppLockerRules._checked_global = True
            has_any = any(_has_app_control(g) for g in all_gpos)
            if not has_any:
                yield Finding(
                    gpo_name="N/A (Domain-wide)", gpo_guid="",
                    rule_id="APL-001", category=self.category,
                    severity=Severity.MEDIUM,
                    title="No AppLocker or WDAC configuration found in any GPO",
                    description="No Group Policy configures AppLocker, WDAC, or Software Restriction Policies.",
                    risk="Without application control, any executable can run on domain computers. This allows malware, "
                         "unauthorized software, and living-off-the-land binaries to execute freely.",
                    recommendation="Deploy AppLocker or Windows Defender Application Control (WDAC) in phased mode: "
                                   "start with audit mode to identify required applications, then enforce. "
                                   "At minimum, block execution from user-writable directories.",
                    setting_path=_APL_BASE,
                    current_value="Not configured",
                    expected_value="AppLocker or WDAC deployed",
                    confidence="High",
                    applies_to="workstations, servers",
                )

        if not _has_app_control(gpo):
            return

        # APL-002: AppLocker in audit-only mode
        for pol in gpo.registry_policies:
            text = f"{pol.name} {pol.category}".lower()
            if any(kw in text for kw in APPLOCKER_KEYWORDS):
                # Check for audit mode indicators
                if pol.state == "Enabled":
                    for key, val in pol.values.items():
                        if "auditonly" in str(val).lower() or "audit" in key.lower():
                            yield Finding(
                                gpo_name=gpo.name, gpo_guid=gpo.guid,
                                rule_id="APL-002", category=self.category,
                                severity=Severity.LOW,
                                title="AppLocker is in audit-only mode",
                                description=f"AppLocker policy '{pol.name}' is configured in audit-only mode.",
                                risk="Audit-only mode logs but does not block unauthorized applications. "
                                     "It provides visibility but no actual protection against malware execution.",
                                recommendation="After sufficient audit period to identify legitimate applications, "
                                               "transition AppLocker rules from audit to enforce mode.",
                                setting_path=f"{_APL_BASE} -> {pol.name}",
                                current_value="Audit Only",
                                expected_value="Enforce",
                                confidence="Medium",
                                applies_to="workstations",
                            )
                            break

        # APL-003: Broad allow-all rules
        for pol in gpo.registry_policies:
            text = f"{pol.name} {pol.category}".lower()
            if any(kw in text for kw in APPLOCKER_KEYWORDS) and pol.state == "Enabled":
                for key, val in pol.values.items():
                    val_str = str(val).lower()
                    if "*" in val_str and ("allow" in val_str or "allow" in key.lower()):
                        yield Finding(
                            gpo_name=gpo.name, gpo_guid=gpo.guid,
                            rule_id="APL-003", category=self.category,
                            severity=Severity.HIGH,
                            title="AppLocker has overly broad allow-all rule",
                            description=f"AppLocker policy '{pol.name}' contains a wildcard allow rule.",
                            risk="A wildcard allow rule negates the purpose of AppLocker, "
                                 "allowing any application to run regardless of other restrictions.",
                            recommendation="Replace wildcard allow rules with specific publisher, path, or hash rules "
                                           "for approved applications only.",
                            setting_path=f"{_APL_BASE} -> {pol.name}",
                            current_value=f"Allow * rule detected",
                            expected_value="Specific application rules only",
                            confidence="Medium",
                            applies_to="workstations",
                        )
                        break
