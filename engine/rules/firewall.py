from typing import Generator

from engine.models import GPO, Finding, Severity
from engine.rules.base import AuditRule, register_rule

_FW_BASE = "Computer Configuration -> Policies -> Windows Settings -> Security Settings -> Windows Firewall with Advanced Security"


@register_rule
class FirewallRules(AuditRule):
    rule_id_prefix = "FW"
    category = "Windows Firewall"

    def evaluate(self, gpo: GPO, all_gpos: list) -> Generator[Finding, None, None]:
        # FW-001: Firewall disabled for any profile
        for profile in gpo.firewall_profiles:
            if profile.enabled is False:
                yield Finding(
                    gpo_name=gpo.name, gpo_guid=gpo.guid,
                    rule_id="FW-001", category=self.category,
                    severity=Severity.CRITICAL if profile.name == "Domain" else Severity.HIGH,
                    title=f"Windows Firewall disabled for {profile.name} profile",
                    description=f"The Windows Firewall is disabled for the {profile.name} network profile.",
                    risk=f"Disabling the firewall for the {profile.name} profile removes network-level protection against unauthorized inbound connections, lateral movement, and network-based attacks.",
                    recommendation=f"Enable the Windows Firewall for the {profile.name} profile. Configure specific inbound allow rules for required services instead of disabling the entire firewall.",
                    setting_path=f"{_FW_BASE} -> {profile.name} Profile -> Firewall state",
                    current_value="Disabled",
                    expected_value="Enabled",
                )

            # FW-002: Default inbound action is Allow
            if profile.default_inbound and profile.default_inbound.lower() == "allow":
                yield Finding(
                    gpo_name=gpo.name, gpo_guid=gpo.guid,
                    rule_id="FW-002", category=self.category,
                    severity=Severity.HIGH,
                    title=f"Firewall default inbound action is Allow for {profile.name}",
                    description=f"The {profile.name} firewall profile allows all inbound connections by default.",
                    risk="Allowing all inbound traffic by default negates the purpose of the firewall, exposing all listening services to network attacks.",
                    recommendation=f"Set the default inbound action to 'Block' for the {profile.name} profile. Create explicit allow rules for required services.",
                    setting_path=f"{_FW_BASE} -> {profile.name} Profile -> Inbound connections",
                    current_value="Allow",
                    expected_value="Block",
                )

        # FW-003: Overly broad firewall rules
        for rule in gpo.firewall_rules:
            if not rule.enabled:
                continue

            is_broad = False
            reasons = []

            # Any port + any address = very broad
            if rule.local_port == "" and rule.remote_address == "" and rule.program == "":
                is_broad = True
                reasons.append("no port, address, or program restriction")

            # Remote address is * or any
            if rule.remote_address in ("*", "Any", "LocalSubnet") and rule.local_port == "":
                is_broad = True
                reasons.append("allows any remote address without port restriction")

            # All ports open
            if rule.local_port == "*":
                is_broad = True
                reasons.append("allows all ports")

            if is_broad and rule.action.lower() == "allow" and rule.direction == "In":
                yield Finding(
                    gpo_name=gpo.name, gpo_guid=gpo.guid,
                    rule_id="FW-003", category=self.category,
                    severity=Severity.MEDIUM,
                    title=f"Overly broad inbound firewall rule: {rule.name}",
                    description=f"Inbound firewall rule '{rule.name}' is overly permissive ({', '.join(reasons)}).",
                    risk="Broad firewall exceptions undermine network segmentation and increase the attack surface for lateral movement and remote exploitation.",
                    recommendation=f"Restrict firewall rule '{rule.name}' by specifying exact ports, remote addresses/subnets, and target programs. Apply the principle of least privilege.",
                    setting_path=f"{_FW_BASE} -> Inbound Rules -> {rule.name}",
                    current_value=f"Port={rule.local_port or 'Any'}, Address={rule.remote_address or 'Any'}, Program={rule.program or 'Any'}",
                    expected_value="Specific port, address, and program",
                )
