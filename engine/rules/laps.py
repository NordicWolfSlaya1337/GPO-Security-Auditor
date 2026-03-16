from typing import Generator

from engine.models import GPO, Finding, Severity
from engine.rules.base import AuditRule, register_rule

_LAPS_BASE = "Computer Configuration -> Policies -> Administrative Templates -> LAPS"

LAPS_REGISTRY_PATTERNS = [
    "LAPS", "AdmPwd", "Local Administrator Password Solution",
    "BackupDirectory", "PasswordLength", "PasswordAgeDays",
]


def _is_laps_policy(pol) -> bool:
    text = f"{pol.name} {pol.category}".lower()
    return any(p.lower() in text for p in LAPS_REGISTRY_PATTERNS)


def _is_laps_item(item) -> bool:
    text = f"{item.key} {item.value_name}".lower()
    return "admpwd" in text or "laps" in text


@register_rule
class LAPSRules(AuditRule):
    rule_id_prefix = "LAPS"
    category = "Local Admin Password Solution (LAPS)"

    _checked_global = False

    def evaluate(self, gpo: GPO, all_gpos: list) -> Generator[Finding, None, None]:
        # LAPS-001: Check if any GPO configures LAPS (global check, run once)
        if not LAPSRules._checked_global:
            LAPSRules._checked_global = True
            has_laps = False
            for g in all_gpos:
                for pol in g.registry_policies:
                    if _is_laps_policy(pol):
                        has_laps = True
                        break
                if has_laps:
                    break
                for item in g.registry_items:
                    if _is_laps_item(item):
                        has_laps = True
                        break
                if has_laps:
                    break

            if not has_laps:
                yield Finding(
                    gpo_name="N/A (Domain-wide)",
                    gpo_guid="",
                    rule_id="LAPS-001", category=self.category,
                    severity=Severity.HIGH,
                    title="No LAPS configuration found in any GPO",
                    description="No Group Policy Object configures Microsoft LAPS (Local Administrator Password Solution).",
                    risk="Without LAPS, local administrator passwords are likely identical across many machines (set during imaging). Compromising one machine's local admin password gives access to all machines with the same password, enabling rapid lateral movement.",
                    recommendation="Deploy Microsoft LAPS to automatically manage and rotate local administrator passwords. Create a dedicated GPO to configure LAPS settings and link it to all computer OUs.",
                    setting_path=_LAPS_BASE,
                    current_value="Not configured",
                    expected_value="LAPS deployed and configured",
                )

        # Per-GPO LAPS checks
        laps_policies = [p for p in gpo.registry_policies if _is_laps_policy(p)]
        laps_items = [i for i in gpo.registry_items if _is_laps_item(i)]

        if not laps_policies and not laps_items:
            return

        # LAPS-002: Password length
        for pol in laps_policies:
            for key, val in pol.values.items():
                if "passwordlength" in key.lower():
                    try:
                        length = int(val)
                        if length < 14:
                            yield Finding(
                                gpo_name=gpo.name, gpo_guid=gpo.guid,
                                rule_id="LAPS-002", category=self.category,
                                severity=Severity.MEDIUM,
                                title="LAPS password length is too short",
                                description=f"LAPS is configured with a password length of {length} characters.",
                                risk="Short LAPS passwords are more vulnerable to brute-force attacks if the hash is obtained.",
                                recommendation="Set LAPS password length to at least 14 characters (20+ recommended).",
                                setting_path=f"{_LAPS_BASE} -> Password Settings -> Password Length",
                                current_value=str(length),
                                expected_value=">=14 characters",
                            )
                    except ValueError:
                        pass

        # LAPS-003: Password age
        for pol in laps_policies:
            for key, val in pol.values.items():
                if "passwordagedays" in key.lower() or "passwordage" in key.lower():
                    try:
                        days = int(val)
                        if days > 30:
                            yield Finding(
                                gpo_name=gpo.name, gpo_guid=gpo.guid,
                                rule_id="LAPS-003", category=self.category,
                                severity=Severity.MEDIUM,
                                title="LAPS password age is too long",
                                description=f"LAPS passwords are rotated every {days} days.",
                                risk="Long password rotation intervals increase the window during which a compromised local admin password remains valid.",
                                recommendation="Set LAPS password age to 30 days or less.",
                                setting_path=f"{_LAPS_BASE} -> Password Settings -> Password Age (Days)",
                                current_value=f"{days} days",
                                expected_value="<=30 days",
                            )
                    except ValueError:
                        pass

        # LAPS-004: Check for password encryption (Windows LAPS v2)
        for item in laps_items:
            if "backupdirectory" in item.value_name.lower() and item.value_data == "1":
                # BackupDirectory=1 means AD without encryption, 2 means AD with encryption
                yield Finding(
                    gpo_name=gpo.name, gpo_guid=gpo.guid,
                    rule_id="LAPS-004", category=self.category,
                    severity=Severity.MEDIUM,
                    title="LAPS password encryption is not enabled",
                    description="LAPS is backing up passwords to AD without encryption.",
                    risk="Unencrypted LAPS passwords in AD can be read by any user with read access to the computer object's ms-Mcs-AdmPwd attribute.",
                    recommendation="Enable LAPS password encryption (BackupDirectory=2) if using Windows LAPS. Also ensure ms-Mcs-AdmPwd ACLs are properly restricted.",
                    setting_path="Computer Configuration -> Preferences -> Windows Settings -> Registry -> LAPS\\BackupDirectory",
                    current_value="Unencrypted (1)",
                    expected_value="Encrypted (2)",
                )
