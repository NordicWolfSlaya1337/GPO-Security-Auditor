import re
from typing import Generator

from engine.models import GPO, Finding, Severity
from engine.rules.base import AuditRule, register_rule

_DCOM_BASE = "Computer Configuration -> Policies -> Windows Settings -> Security Settings -> Local Policies -> Security Options"

AUTH_LEVELS = {
    "1": "None", "2": "Connect", "3": "Call",
    "4": "Packet", "5": "Packet Integrity", "6": "Packet Privacy",
}


@register_rule
class DCOMRules(AuditRule):
    rule_id_prefix = "DCOM"
    category = "DCOM Hardening"

    def evaluate(self, gpo: GPO, all_gpos: list) -> Generator[Finding, None, None]:
        # DCOM-001: Authentication level too low
        for item in gpo.registry_items:
            if re.search(r"Microsoft\\Ole\\.*DefaultAuthenticationLevel",
                         item.key + "\\" + item.value_name, re.IGNORECASE):
                try:
                    level = int(item.value_data)
                except (ValueError, TypeError):
                    continue
                if level < 5:
                    level_name = AUTH_LEVELS.get(str(level), f"Unknown ({level})")
                    yield Finding(
                        gpo_name=gpo.name, gpo_guid=gpo.guid,
                        rule_id="DCOM-001", category=self.category,
                        severity=Severity.MEDIUM,
                        title="DCOM default authentication level is too low",
                        description=f"DCOM default authentication level is set to {level} ({level_name}).",
                        risk="Low DCOM authentication levels allow relay attacks and man-in-the-middle "
                             "exploitation of DCOM/RPC communications. Attackers can intercept or tamper with "
                             "inter-process communication across the network.",
                        recommendation="Set DCOM default authentication level to at least 5 (Packet Integrity) "
                                       "or 6 (Packet Privacy) for encrypted communications.",
                        setting_path=f"{_DCOM_BASE} -> DCOM: Machine Access/Launch Restrictions",
                        current_value=f"DefaultAuthenticationLevel = {level} ({level_name})",
                        expected_value=">=5 (Packet Integrity) or 6 (Packet Privacy)",
                    )

        for opt in gpo.security_options:
            if "authentication" in opt.key_name.lower() and "dcom" in opt.display_name.lower():
                if opt.setting_number is not None and opt.setting_number < 5:
                    level_name = AUTH_LEVELS.get(str(opt.setting_number), f"Unknown")
                    yield Finding(
                        gpo_name=gpo.name, gpo_guid=gpo.guid,
                        rule_id="DCOM-001", category=self.category,
                        severity=Severity.MEDIUM,
                        title="DCOM default authentication level is too low",
                        description=f"DCOM authentication is set to {opt.setting_number} ({level_name}).",
                        risk="Low DCOM authentication enables relay and MITM attacks on RPC communications.",
                        recommendation="Raise DCOM authentication to Packet Integrity (5) or Packet Privacy (6).",
                        setting_path=f"{_DCOM_BASE} -> {opt.display_name}",
                        current_value=f"{opt.setting_number} ({level_name})",
                        expected_value=">=5 (Packet Integrity)",
                    )

        # DCOM-002: DCOM hardening not enforced (KB5004442)
        for item in gpo.registry_items:
            if re.search(r"Microsoft\\Ole\\.*RequireIntegrityActivationAuthenticationLevel",
                         item.key + "\\" + item.value_name, re.IGNORECASE):
                if item.value_data == "0":
                    yield Finding(
                        gpo_name=gpo.name, gpo_guid=gpo.guid,
                        rule_id="DCOM-002", category=self.category,
                        severity=Severity.MEDIUM,
                        title="DCOM hardening is explicitly disabled (KB5004442)",
                        description="The DCOM authentication hardening change (KB5004442) has been disabled.",
                        risk="Disabling DCOM hardening re-enables legacy authentication behavior that allows "
                             "unauthenticated or weakly-authenticated DCOM activation. This is commonly exploited "
                             "in potato-style privilege escalation and NTLM relay attacks.",
                        recommendation="Remove the registry override to allow DCOM hardening enforcement. "
                                       "Set RequireIntegrityActivationAuthenticationLevel to 1.",
                        setting_path="HKLM\\SOFTWARE\\Microsoft\\Ole -> RequireIntegrityActivationAuthenticationLevel",
                        current_value="RequireIntegrityActivationAuthenticationLevel = 0 (Disabled)",
                        expected_value="1 (Enabled) or not set (default enforcement)",
                    )

            if re.search(r"Microsoft\\Ole\\.*RaiseActivationAuthenticationLevel",
                         item.key + "\\" + item.value_name, re.IGNORECASE):
                if item.value_data == "0":
                    yield Finding(
                        gpo_name=gpo.name, gpo_guid=gpo.guid,
                        rule_id="DCOM-002", category=self.category,
                        severity=Severity.MEDIUM,
                        title="DCOM activation authentication hardening is disabled",
                        description="RaiseActivationAuthenticationLevel is set to 0, bypassing DCOM hardening.",
                        risk="This disables the hardened DCOM activation security, allowing legacy low-authentication "
                             "DCOM calls that can be exploited for privilege escalation.",
                        recommendation="Remove this override or set RaiseActivationAuthenticationLevel to 1.",
                        setting_path="HKLM\\SOFTWARE\\Microsoft\\Ole -> RaiseActivationAuthenticationLevel",
                        current_value="RaiseActivationAuthenticationLevel = 0",
                        expected_value="1 (Enabled) or not set",
                    )
