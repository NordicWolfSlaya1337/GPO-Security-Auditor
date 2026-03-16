import re
from typing import Generator
from collections import defaultdict

from engine.models import GPO, Finding, Severity
from engine.rules.base import AuditRule, register_rule


_KRB_BASE = "Computer Configuration -> Policies -> Windows Settings -> Security Settings -> Account Policies -> Kerberos Policy"


@register_rule
class KerberosRules(AuditRule):
    rule_id_prefix = "KRB"
    category = "Kerberos Policy"

    _checked_conflicts = False

    def evaluate(self, gpo: GPO, all_gpos: list) -> Generator[Finding, None, None]:
        krb_settings = {s.name: s for s in gpo.account_settings if s.setting_type == "Kerberos"}
        if not krb_settings:
            # Cross-GPO conflict check (run once)
            if not KerberosRules._checked_conflicts:
                KerberosRules._checked_conflicts = True
                yield from self._check_kerberos_conflicts(all_gpos)
            return

        # KRB-001: Max ticket lifetime too long
        s = krb_settings.get("MaxTicketAge")
        if s and s.value_number is not None and s.value_number > 10:
            yield Finding(
                gpo_name=gpo.name, gpo_guid=gpo.guid,
                rule_id="KRB-001", category=self.category,
                severity=Severity.MEDIUM,
                title="Kerberos maximum ticket lifetime is too long",
                description=f"Kerberos TGT maximum lifetime is set to {s.value_number} hours.",
                risk="Long TGT lifetimes extend the window during which stolen Kerberos tickets (Golden Ticket, "
                     "pass-the-ticket attacks) remain valid. An attacker with a stolen TGT has extended persistence.",
                recommendation="Set maximum ticket lifetime to 10 hours or less per CIS Benchmark. "
                               "For high-security environments, consider 4 hours.",
                setting_path=f"{_KRB_BASE} -> MaxTicketAge",
                current_value=f"{s.value_number} hours",
                expected_value="<=10 hours",
                confidence="High",
                applies_to="domain",
            )

        # KRB-002: Max renewal lifetime too long
        s = krb_settings.get("MaxRenewAge")
        if s and s.value_number is not None and s.value_number > 7:
            yield Finding(
                gpo_name=gpo.name, gpo_guid=gpo.guid,
                rule_id="KRB-002", category=self.category,
                severity=Severity.LOW,
                title="Kerberos maximum renewal age is too long",
                description=f"Kerberos ticket maximum renewal age is set to {s.value_number} days.",
                risk="Longer renewal windows allow attackers to maintain access with stolen tickets for extended periods "
                     "without requiring re-authentication.",
                recommendation="Set maximum ticket renewal age to 7 days or less.",
                setting_path=f"{_KRB_BASE} -> MaxRenewAge",
                current_value=f"{s.value_number} days",
                expected_value="<=7 days",
                confidence="High",
                applies_to="domain",
            )

        # KRB-003: TicketValidateClient disabled
        s = krb_settings.get("TicketValidateClient")
        if s and s.value_boolean is False:
            yield Finding(
                gpo_name=gpo.name, gpo_guid=gpo.guid,
                rule_id="KRB-003", category=self.category,
                severity=Severity.MEDIUM,
                title="Kerberos ticket validation is disabled",
                description="The 'Enforce user logon restrictions' Kerberos setting is disabled.",
                risk="Without ticket validation, the KDC does not verify that the user account is still valid "
                     "when issuing service tickets, potentially allowing disabled/locked accounts to access services.",
                recommendation="Enable 'Enforce user logon restrictions' for the Kerberos policy.",
                setting_path=f"{_KRB_BASE} -> TicketValidateClient",
                current_value="Disabled",
                expected_value="Enabled",
                confidence="High",
                applies_to="domain",
            )

        # KRB-005: Weak encryption types allowed (DES/RC4)
        yield from self._check_weak_encryption(gpo)

        # Run cross-GPO check
        if not KerberosRules._checked_conflicts:
            KerberosRules._checked_conflicts = True
            yield from self._check_kerberos_conflicts(all_gpos)

    def _check_weak_encryption(self, gpo: GPO) -> Generator[Finding, None, None]:
        """KRB-005: Check for weak Kerberos encryption types (DES, RC4)."""
        _ENC_PATH = "Computer Configuration -> Policies -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> Network security: Configure encryption types allowed for Kerberos"

        # Check security options
        for opt in gpo.security_options:
            if "supportedencryptiontypes" in opt.key_name.lower() or "encryption types" in opt.display_name.lower():
                val = opt.setting_number
                if val is not None and val & 0x7:  # DES_CBC_CRC(1) | DES_CBC_MD5(2) | RC4_HMAC(4)
                    weak = []
                    if val & 0x1:
                        weak.append("DES_CBC_CRC")
                    if val & 0x2:
                        weak.append("DES_CBC_MD5")
                    if val & 0x4:
                        weak.append("RC4_HMAC_MD5")
                    yield Finding(
                        gpo_name=gpo.name, gpo_guid=gpo.guid,
                        rule_id="KRB-005", category=self.category,
                        severity=Severity.HIGH,
                        title="Weak Kerberos encryption types are allowed",
                        description=f"Kerberos is configured to allow weak encryption: {', '.join(weak)}.",
                        risk="DES and RC4 encryption are cryptographically broken. Attackers can crack Kerberoasted "
                             "service tickets encrypted with RC4 in minutes. DES provides even less protection.",
                        recommendation="Configure allowed encryption types to AES128 and AES256 only (value 0x18 = 24). "
                                       "Remove DES and RC4 support after verifying all systems support AES.",
                        setting_path=_ENC_PATH,
                        current_value=f"0x{val:X} ({', '.join(weak)} enabled)",
                        expected_value="0x18 (AES128 + AES256 only)",
                        confidence="High",
                        applies_to="domain",
                    )
                    return

        # Check registry items
        for item in gpo.registry_items:
            if re.search(r"Kerberos.*Parameters.*SupportedEncryptionTypes|SupportedEncryptionTypes",
                         item.key + "\\" + item.value_name, re.IGNORECASE):
                try:
                    val = int(item.value_data)
                except (ValueError, TypeError):
                    continue
                if val & 0x7:
                    weak = []
                    if val & 0x1:
                        weak.append("DES_CBC_CRC")
                    if val & 0x2:
                        weak.append("DES_CBC_MD5")
                    if val & 0x4:
                        weak.append("RC4_HMAC_MD5")
                    yield Finding(
                        gpo_name=gpo.name, gpo_guid=gpo.guid,
                        rule_id="KRB-005", category=self.category,
                        severity=Severity.HIGH,
                        title="Weak Kerberos encryption types are allowed",
                        description=f"SupportedEncryptionTypes includes weak ciphers: {', '.join(weak)}.",
                        risk="DES and RC4 are cryptographically broken. RC4-encrypted Kerberos tickets "
                             "can be cracked in minutes via Kerberoasting attacks.",
                        recommendation="Set SupportedEncryptionTypes to 0x18 (24) for AES128+AES256 only.",
                        setting_path=_ENC_PATH,
                        current_value=f"0x{val:X} ({', '.join(weak)} enabled)",
                        expected_value="0x18 (AES128 + AES256 only)",
                        confidence="High",
                        applies_to="domain",
                    )
                    return

    def _check_kerberos_conflicts(self, all_gpos: list) -> Generator[Finding, None, None]:
        """Detect contradictory Kerberos settings across GPOs."""
        krb_map = defaultdict(list)
        for g in all_gpos:
            for s in g.account_settings:
                if s.setting_type == "Kerberos" and s.value_number is not None:
                    krb_map[s.name].append((g.name, s.value_number))

        for setting_name, entries in krb_map.items():
            if len(entries) < 2:
                continue
            values = set(v for _, v in entries)
            if len(values) > 1:
                detail = "; ".join(f"{name}={val}" for name, val in entries)
                yield Finding(
                    gpo_name="Multiple GPOs", gpo_guid="",
                    rule_id="KRB-004", category=self.category,
                    severity=Severity.HIGH,
                    title=f"Conflicting Kerberos setting: {setting_name}",
                    description=f"Multiple GPOs define different values for Kerberos setting '{setting_name}': {detail}.",
                    risk="Contradictory Kerberos settings create unpredictable security posture. The effective value depends "
                         "on GPO precedence, which may not result in the most secure configuration.",
                    recommendation=f"Consolidate Kerberos policy into a single authoritative GPO (typically Default Domain Policy). "
                                   f"Remove '{setting_name}' from all other GPOs.",
                    setting_path=f"{_KRB_BASE} -> {setting_name}",
                    current_value=detail,
                    expected_value="Single authoritative GPO",
                    confidence="High",
                    applies_to="domain",
                    architecture_fix="merge",
                )
