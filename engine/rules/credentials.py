from typing import Generator

from engine.models import GPO, Finding, Severity
from engine.rules.base import AuditRule, register_rule


@register_rule
class CredentialRules(AuditRule):
    rule_id_prefix = "CRED"
    category = "Credential Exposure"

    def evaluate(self, gpo: GPO, all_gpos: list) -> Generator[Finding, None, None]:
        for item in gpo.preference_items:
            # CRED-001: GPP cpassword (MS14-025)
            if item.cpassword:
                yield Finding(
                    gpo_name=gpo.name, gpo_guid=gpo.guid,
                    rule_id="CRED-001", category=self.category,
                    severity=Severity.CRITICAL,
                    title=f"GPP cpassword found in {item.item_type}: {item.name}",
                    description=f"Group Policy Preference item '{item.name}' (type: {item.item_type}) contains a cpassword attribute. "
                                f"The cpassword encryption key was published by Microsoft (MS14-025) and any cpassword can be instantly decrypted.",
                    risk="This is a classic critical vulnerability. The AES key used to encrypt cpassword was published by Microsoft in 2014. "
                         "Any domain user can read SYSVOL and decrypt these passwords instantly using tools like gpp-decrypt. "
                         "This provides immediate credential access for lateral movement or privilege escalation.",
                    recommendation="Remove ALL Group Policy Preferences that contain cpassword immediately. Rotate all affected passwords. "
                                   "Migrate to LAPS for local admin passwords, gMSA for service accounts, or Credential Guard for other scenarios.",
                    setting_path=f"Computer Configuration -> Preferences -> {item.item_type} -> {item.name}",
                    current_value=f"cpassword present in {item.item_type}",
                    expected_value="No embedded credentials",
                    confidence="High",
                    applies_to="domain",
                )

            # CRED-002: Embedded username/password in preference items
            props = item.properties
            username = props.get("runAs", props.get("accountName", props.get("userName", "")))
            if username and not item.cpassword:
                # Has username but we already flagged cpassword above
                has_pw_hint = any(k.lower() in ("password", "cpassword") and v for k, v in props.items())
                if has_pw_hint:
                    yield Finding(
                        gpo_name=gpo.name, gpo_guid=gpo.guid,
                        rule_id="CRED-002", category=self.category,
                        severity=Severity.CRITICAL,
                        title=f"Embedded credentials in GPP {item.item_type}: {item.name}",
                        description=f"GPP item '{item.name}' contains embedded username '{username}' with a password field.",
                        risk="Embedded credentials in Group Policy Preferences are readable by any authenticated domain user "
                             "via SYSVOL access, providing immediate credential theft opportunities.",
                        recommendation="Remove embedded credentials. Use Group Managed Service Accounts (gMSA) for services, "
                                       "LAPS for local admin passwords, or certificate-based authentication.",
                        setting_path=f"Computer Configuration -> Preferences -> {item.item_type} -> {item.name}",
                        current_value=f"Username: {username} with embedded password",
                        expected_value="No embedded credentials",
                        confidence="High",
                        applies_to="domain",
                    )
