import re
from typing import Generator

from engine.models import GPO, Finding, Severity
from engine.rules.base import AuditRule, register_rule

_DEF_BASE = "Computer Configuration -> Policies -> Administrative Templates -> Windows Components -> Microsoft Defender Antivirus"

DEFENDER_CHECKS = [
    {
        "id": "DEF-001",
        "policy_pattern": r"Turn off (Microsoft Defender Antivirus|Windows Defender)",
        "reg_pattern": r"DisableAntiSpyware|DisableAntiVirus",
        "path": f"{_DEF_BASE} -> Turn off Microsoft Defender Antivirus",
        "check_policy": lambda p: p.state == "Enabled",
        "check_item": lambda i: i.value_data == "1",
        "severity": Severity.CRITICAL,
        "title": "Windows Defender is disabled by GPO",
        "description": "A Group Policy is configured to completely disable Microsoft Defender Antivirus.",
        "risk": "Disabling Defender removes the primary endpoint protection layer. Malware, ransomware, and fileless attacks "
                "can execute freely without any detection or prevention.",
        "recommendation": "Remove the policy disabling Defender unless an approved third-party endpoint protection solution "
                          "is centrally managed and verified. If using a third-party AV, ensure it's actually deployed before disabling Defender.",
        "expected": "Enabled (Defender active)",
    },
    {
        "id": "DEF-002",
        "policy_pattern": r"Turn off real-time protection",
        "reg_pattern": r"DisableRealtimeMonitoring",
        "path": f"{_DEF_BASE} -> Real-time Protection -> Turn off real-time protection",
        "check_policy": lambda p: p.state == "Enabled",
        "check_item": lambda i: i.value_data == "1",
        "severity": Severity.HIGH,
        "title": "Defender real-time protection is disabled",
        "description": "Real-time protection in Microsoft Defender is disabled via Group Policy.",
        "risk": "Without real-time protection, malware can execute and establish persistence before any scheduled scan detects it. "
                "This significantly increases dwell time and damage potential.",
        "recommendation": "Enable real-time protection. If temporarily disabled for compatibility testing, ensure it's re-enabled promptly.",
        "expected": "Real-time protection enabled",
    },
    {
        "id": "DEF-003",
        "policy_pattern": r"(Join Microsoft MAPS|SpyNet|Cloud.delivered protection|MpCloud)",
        "reg_pattern": r"SpynetReporting|MAPSReporting|SubmitSamplesConsent",
        "path": f"{_DEF_BASE} -> MAPS -> Join Microsoft MAPS",
        "check_policy": lambda p: p.state == "Disabled",
        "check_item": lambda i: i.value_data == "0",
        "severity": Severity.MEDIUM,
        "title": "Defender cloud-delivered protection is disabled",
        "description": "Microsoft Defender cloud protection (MAPS/SpyNet) is disabled.",
        "risk": "Cloud-delivered protection provides rapid detection of new and emerging threats using cloud intelligence. "
                "Without it, Defender relies only on local signature definitions, missing zero-day and polymorphic threats.",
        "recommendation": "Enable cloud-delivered protection for internet-connected endpoints. "
                          "For air-gapped environments, ensure frequent signature updates are deployed.",
        "expected": "Cloud protection enabled",
    },
    {
        "id": "DEF-004",
        "policy_pattern": r"Tamper Protection|TamperProtection",
        "reg_pattern": r"TamperProtection",
        "path": f"{_DEF_BASE} -> Tamper Protection",
        "check_policy": lambda p: p.state == "Disabled",
        "check_item": lambda i: i.value_data in ("0", "4"),
        "severity": Severity.HIGH,
        "title": "Defender tamper protection is weakened",
        "description": "Microsoft Defender tamper protection has been disabled or weakened via Group Policy.",
        "risk": "Tamper protection prevents malware and attackers from disabling Defender components. "
                "Without it, malicious software can turn off real-time protection, cloud protection, and other defenses.",
        "recommendation": "Enable tamper protection. Note that tamper protection is best managed via Microsoft Intune/MDE "
                          "rather than GPO for cloud-connected endpoints.",
        "expected": "Tamper protection enabled",
    },
]


@register_rule
class DefenderRules(AuditRule):
    rule_id_prefix = "DEF"
    category = "Windows Defender / Antivirus"

    def evaluate(self, gpo: GPO, all_gpos: list) -> Generator[Finding, None, None]:
        for check in DEFENDER_CHECKS:
            found = False

            # Check registry policies (admin templates)
            for pol in gpo.registry_policies:
                search_text = f"{pol.name} {pol.category}"
                if re.search(check["policy_pattern"], search_text, re.IGNORECASE):
                    if check["check_policy"](pol):
                        yield Finding(
                            gpo_name=gpo.name, gpo_guid=gpo.guid,
                            rule_id=check["id"], category=self.category,
                            severity=check["severity"],
                            title=check["title"],
                            description=check["description"],
                            risk=check["risk"],
                            recommendation=check["recommendation"],
                            setting_path=check.get("path", ""),
                            current_value=f"Policy: {pol.name} = {pol.state}",
                            expected_value=check["expected"],
                            confidence="High",
                            applies_to="workstations, servers",
                        )
                        found = True
                        break

            # Check registry items
            if not found:
                for item in gpo.registry_items:
                    key_full = f"{item.key}\\{item.value_name}"
                    if re.search(check["reg_pattern"], key_full, re.IGNORECASE):
                        if check["check_item"](item):
                            yield Finding(
                                gpo_name=gpo.name, gpo_guid=gpo.guid,
                                rule_id=check["id"], category=self.category,
                                severity=check["severity"],
                                title=check["title"],
                                description=check["description"],
                                risk=check["risk"],
                                recommendation=check["recommendation"],
                                setting_path=check.get("path", ""),
                                current_value=f"Registry: {key_full} = {item.value_data}",
                                expected_value=check["expected"],
                                confidence="High",
                                applies_to="workstations, servers",
                            )
                            break
