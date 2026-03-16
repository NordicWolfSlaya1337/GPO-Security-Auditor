import re
from typing import Generator

from engine.models import GPO, Finding, Severity
from engine.rules.base import AuditRule, register_rule

_BIT_BASE = "Computer Configuration -> Policies -> Administrative Templates -> Windows Components -> BitLocker Drive Encryption"

BITLOCKER_KEYWORDS = ["bitlocker", "fve", "fullvolumeencryption", "drive encryption"]


def _has_bitlocker(gpo: GPO) -> bool:
    for pol in gpo.registry_policies:
        text = f"{pol.name} {pol.category}".lower()
        if any(kw in text for kw in BITLOCKER_KEYWORDS):
            return True
    for item in gpo.registry_items:
        if re.search(r"SOFTWARE\\Policies\\Microsoft\\FVE", item.key, re.IGNORECASE):
            return True
    return False


@register_rule
class BitLockerRules(AuditRule):
    rule_id_prefix = "BIT"
    category = "BitLocker Drive Encryption"

    _checked_global = False

    def evaluate(self, gpo: GPO, all_gpos: list) -> Generator[Finding, None, None]:
        # BIT-001: Global check - no BitLocker configured anywhere
        if not BitLockerRules._checked_global:
            BitLockerRules._checked_global = True
            has_any = any(_has_bitlocker(g) for g in all_gpos)
            if not has_any:
                yield Finding(
                    gpo_name="N/A (Domain-wide)", gpo_guid="",
                    rule_id="BIT-001", category=self.category,
                    severity=Severity.HIGH,
                    title="BitLocker drive encryption is not configured in any GPO",
                    description="No Group Policy configures BitLocker Drive Encryption settings.",
                    risk="Without BitLocker enforcement, lost or stolen devices expose sensitive data. "
                         "An attacker with physical access can read the hard drive contents directly.",
                    recommendation="Deploy BitLocker via GPO: enable BitLocker for OS drives, "
                                   "require TPM+PIN authentication, and escrow recovery keys to Active Directory.",
                    setting_path=_BIT_BASE,
                    current_value="Not configured",
                    expected_value="BitLocker deployed via GPO",
                    confidence="High",
                    applies_to="workstations, laptops",
                )

        if not _has_bitlocker(gpo):
            return

        # BIT-002: No TPM+PIN requirement
        for item in gpo.registry_items:
            if re.search(r"FVE\\.*UseTPMPIN", item.key + "\\" + item.value_name, re.IGNORECASE):
                if item.value_data in ("0", ""):
                    yield Finding(
                        gpo_name=gpo.name, gpo_guid=gpo.guid,
                        rule_id="BIT-002", category=self.category,
                        severity=Severity.MEDIUM,
                        title="BitLocker does not require TPM+PIN pre-boot authentication",
                        description="BitLocker is configured without requiring a PIN at startup.",
                        risk="Without a pre-boot PIN, BitLocker relies solely on TPM protection. "
                             "Cold boot attacks, DMA attacks, and TPM sniffing can bypass TPM-only BitLocker.",
                        recommendation="Enable 'Require additional authentication at startup' and set "
                                       "'Configure TPM startup PIN' to 'Require startup PIN with TPM'.",
                        setting_path=f"{_BIT_BASE} -> Operating System Drives -> Require additional authentication at startup",
                        current_value=f"UseTPMPIN = {item.value_data}",
                        expected_value="UseTPMPIN = 1 (Required)",
                    )
                break

        for pol in gpo.registry_policies:
            text = f"{pol.name} {pol.category}".lower()
            if "additional authentication" in text or "tpm" in text and "pin" in text:
                if pol.state == "Disabled":
                    yield Finding(
                        gpo_name=gpo.name, gpo_guid=gpo.guid,
                        rule_id="BIT-002", category=self.category,
                        severity=Severity.MEDIUM,
                        title="BitLocker does not require TPM+PIN pre-boot authentication",
                        description=f"Policy '{pol.name}' is disabled, allowing TPM-only BitLocker.",
                        risk="Without a pre-boot PIN, BitLocker relies solely on TPM protection. "
                             "Cold boot attacks, DMA attacks, and TPM sniffing can bypass TPM-only BitLocker.",
                        recommendation="Enable 'Require additional authentication at startup' and require a startup PIN.",
                        setting_path=f"{_BIT_BASE} -> Operating System Drives -> {pol.name}",
                        current_value=f"{pol.name}: Disabled",
                        expected_value="Enabled with TPM+PIN required",
                    )
                break

        # BIT-003: Recovery key not escrowed to AD
        ad_backup_found = False
        for item in gpo.registry_items:
            if re.search(r"FVE\\.*ActiveDirectoryBackup", item.key + "\\" + item.value_name, re.IGNORECASE):
                ad_backup_found = True
                if item.value_data != "1":
                    yield Finding(
                        gpo_name=gpo.name, gpo_guid=gpo.guid,
                        rule_id="BIT-003", category=self.category,
                        severity=Severity.MEDIUM,
                        title="BitLocker recovery keys are not escrowed to Active Directory",
                        description="BitLocker is configured but recovery key backup to AD DS is not enabled.",
                        risk="Without AD-escrowed recovery keys, locked-out users cannot recover their drives "
                             "through IT support. Data loss is likely if the TPM is cleared or hardware fails.",
                        recommendation="Enable 'Store BitLocker recovery information in AD DS' and "
                                       "'Require BitLocker backup to AD DS before enabling BitLocker'.",
                        setting_path=f"{_BIT_BASE} -> Operating System Drives -> Choose how BitLocker-protected OS drives can be recovered",
                        current_value=f"ActiveDirectoryBackup = {item.value_data}",
                        expected_value="ActiveDirectoryBackup = 1",
                    )
                break

        if not ad_backup_found:
            for pol in gpo.registry_policies:
                text = f"{pol.name} {pol.category}".lower()
                if ("recovery" in text or "backup" in text) and "bitlocker" in text:
                    if pol.state == "Disabled":
                        yield Finding(
                            gpo_name=gpo.name, gpo_guid=gpo.guid,
                            rule_id="BIT-003", category=self.category,
                            severity=Severity.MEDIUM,
                            title="BitLocker recovery keys are not escrowed to Active Directory",
                            description=f"Recovery policy '{pol.name}' is disabled.",
                            risk="Without AD-escrowed recovery keys, locked-out users cannot recover their drives.",
                            recommendation="Enable BitLocker recovery key backup to Active Directory.",
                            setting_path=f"{_BIT_BASE} -> {pol.name}",
                            current_value=f"{pol.name}: Disabled",
                            expected_value="Enabled with AD backup required",
                        )
                    break
