import re
from typing import Generator

from engine.models import GPO, Finding, Severity
from engine.rules.base import AuditRule, register_rule

_CG_BASE = "Computer Configuration -> Policies -> Administrative Templates -> System -> Device Guard"

CG_KEYWORDS = ["deviceguard", "device guard", "credential guard", "virtualization based security",
               "virtualization-based security"]


def _has_device_guard(gpo: GPO) -> bool:
    for pol in gpo.registry_policies:
        text = f"{pol.name} {pol.category}".lower()
        if any(kw in text for kw in CG_KEYWORDS):
            return True
    for item in gpo.registry_items:
        if re.search(r"DeviceGuard|Control\\LSA\\LsaCfgFlags", item.key, re.IGNORECASE):
            return True
    return False


@register_rule
class CredentialGuardRules(AuditRule):
    rule_id_prefix = "CG"
    category = "Credential Guard & Virtualization-Based Security"

    _checked_global = False

    def evaluate(self, gpo: GPO, all_gpos: list) -> Generator[Finding, None, None]:
        # Domain-wide check: no Device Guard / Credential Guard configured
        if not CredentialGuardRules._checked_global:
            CredentialGuardRules._checked_global = True
            has_any = any(_has_device_guard(g) for g in all_gpos)
            if not has_any:
                yield Finding(
                    gpo_name="N/A (Domain-wide)", gpo_guid="",
                    rule_id="CG-001", category=self.category,
                    severity=Severity.HIGH,
                    title="Credential Guard is not configured in any GPO",
                    description="No Group Policy enables Windows Credential Guard or Virtualization-Based Security.",
                    risk="Without Credential Guard, LSASS stores credentials in memory in a form that tools like "
                         "Mimikatz can extract. Credential theft enables lateral movement and domain compromise.",
                    recommendation="Enable Virtualization-Based Security and Credential Guard via GPO. "
                                   "Set 'Turn On Virtualization Based Security' to Enabled with "
                                   "'Credential Guard Configuration' set to 'Enabled with UEFI lock'.",
                    setting_path=_CG_BASE,
                    current_value="Not configured",
                    expected_value="VBS and Credential Guard enabled",
                    confidence="High",
                    applies_to="workstations, servers",
                )
                yield Finding(
                    gpo_name="N/A (Domain-wide)", gpo_guid="",
                    rule_id="CG-002", category=self.category,
                    severity=Severity.HIGH,
                    title="Virtualization-Based Security (VBS) is not configured in any GPO",
                    description="No Group Policy enables Virtualization-Based Security, which is required for Credential Guard, "
                                "HVCI, and other hardware-backed security features.",
                    risk="Without VBS, the kernel and LSASS run without hardware isolation. This leaves the system "
                         "vulnerable to kernel exploits, credential theft, and code integrity bypass.",
                    recommendation="Enable 'Turn On Virtualization Based Security' with Secure Boot and DMA Protection.",
                    setting_path=f"{_CG_BASE} -> Turn On Virtualization Based Security",
                    current_value="Not configured",
                    expected_value="Enabled with Secure Boot",
                    confidence="High",
                    applies_to="workstations, servers",
                )
                return

        if not _has_device_guard(gpo):
            return

        # CG-001: Credential Guard explicitly disabled
        for item in gpo.registry_items:
            if re.search(r"LsaCfgFlags", item.value_name, re.IGNORECASE):
                if item.value_data == "0":
                    yield Finding(
                        gpo_name=gpo.name, gpo_guid=gpo.guid,
                        rule_id="CG-001", category=self.category,
                        severity=Severity.HIGH,
                        title="Credential Guard is explicitly disabled",
                        description="Credential Guard (LsaCfgFlags) is set to 0 (disabled).",
                        risk="With Credential Guard disabled, LSASS credentials are stored in memory unprotected. "
                             "Mimikatz and similar tools can extract plaintext passwords and NTLM hashes.",
                        recommendation="Set LsaCfgFlags to 1 (Enabled with UEFI lock) for maximum protection, "
                                       "or 2 (Enabled without lock) for easier rollback.",
                        setting_path=f"{_CG_BASE} -> Credential Guard Configuration",
                        current_value="LsaCfgFlags = 0 (Disabled)",
                        expected_value="LsaCfgFlags = 1 (Enabled with UEFI lock)",
                    )

        for pol in gpo.registry_policies:
            text = f"{pol.name} {pol.category}".lower()
            if "credential guard" in text and pol.state == "Disabled":
                yield Finding(
                    gpo_name=gpo.name, gpo_guid=gpo.guid,
                    rule_id="CG-001", category=self.category,
                    severity=Severity.HIGH,
                    title="Credential Guard is explicitly disabled via policy",
                    description=f"Policy '{pol.name}' disables Credential Guard.",
                    risk="With Credential Guard disabled, LSASS credentials are unprotected in memory.",
                    recommendation="Enable Credential Guard with UEFI lock.",
                    setting_path=f"{_CG_BASE} -> {pol.name}",
                    current_value=f"{pol.name}: Disabled",
                    expected_value="Enabled with UEFI lock",
                )

        # CG-002: VBS explicitly disabled
        for item in gpo.registry_items:
            if re.search(r"EnableVirtualizationBasedSecurity", item.value_name, re.IGNORECASE):
                if item.value_data == "0":
                    yield Finding(
                        gpo_name=gpo.name, gpo_guid=gpo.guid,
                        rule_id="CG-002", category=self.category,
                        severity=Severity.HIGH,
                        title="Virtualization-Based Security is explicitly disabled",
                        description="VBS (EnableVirtualizationBasedSecurity) is set to 0 (disabled).",
                        risk="Without VBS, Credential Guard, HVCI, and other hardware-backed security "
                             "features cannot function. The system lacks kernel-level isolation.",
                        recommendation="Enable Virtualization-Based Security with Secure Boot and DMA Protection.",
                        setting_path=f"{_CG_BASE} -> Turn On Virtualization Based Security",
                        current_value="EnableVirtualizationBasedSecurity = 0 (Disabled)",
                        expected_value="EnableVirtualizationBasedSecurity = 1 (Enabled)",
                    )

        for pol in gpo.registry_policies:
            text = f"{pol.name} {pol.category}".lower()
            if "virtualization" in text and "security" in text and pol.state == "Disabled":
                yield Finding(
                    gpo_name=gpo.name, gpo_guid=gpo.guid,
                    rule_id="CG-002", category=self.category,
                    severity=Severity.HIGH,
                    title="Virtualization-Based Security is explicitly disabled via policy",
                    description=f"Policy '{pol.name}' disables VBS.",
                    risk="Without VBS, hardware-backed security features cannot function.",
                    recommendation="Enable Virtualization-Based Security.",
                    setting_path=f"{_CG_BASE} -> {pol.name}",
                    current_value=f"{pol.name}: Disabled",
                    expected_value="Enabled",
                )
