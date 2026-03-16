from typing import Generator

from engine.models import GPO, Finding, Severity
from engine.rules.base import AuditRule, register_rule


_PW_BASE = "Computer Configuration -> Policies -> Windows Settings -> Security Settings -> Account Policies -> Password Policy"


@register_rule
class PasswordPolicyRules(AuditRule):
    rule_id_prefix = "PWD"
    category = "Password Policy"

    _checked_global = False

    def evaluate(self, gpo: GPO, all_gpos: list) -> Generator[Finding, None, None]:
        # PWD-007: Domain-wide check — no password policy defined anywhere
        if not PasswordPolicyRules._checked_global:
            PasswordPolicyRules._checked_global = True
            has_any_pw = any(
                any(s.setting_type == "Password" for s in g.account_settings)
                for g in all_gpos
            )
            if not has_any_pw:
                yield Finding(
                    gpo_name="N/A (Domain-wide)", gpo_guid="",
                    rule_id="PWD-007", category=self.category,
                    severity=Severity.HIGH,
                    title="No password policy defined in any GPO",
                    description="No Group Policy defines password policy settings (minimum length, complexity, history, max age).",
                    risk="Without a centrally defined password policy, domain users may use weak or trivial passwords. "
                         "Default domain password policy may be insufficient or absent if not explicitly configured.",
                    recommendation="Define a comprehensive password policy in the Default Domain Policy GPO with at least: "
                                   "minimum length 14, complexity enabled, history 24, max age 60-90 days.",
                    setting_path=_PW_BASE,
                    current_value="Not configured",
                    expected_value="Password policy defined in Default Domain Policy",
                    confidence="High",
                    applies_to="domain",
                )

        # Only check GPOs that have account settings of type Password
        pw_settings = {s.name: s for s in gpo.account_settings if s.setting_type == "Password"}
        if not pw_settings:
            return

        # PWD-001: Minimum password length
        s = pw_settings.get("MinimumPasswordLength")
        if s and s.value_number is not None:
            if s.value_number < 8:
                yield Finding(
                    gpo_name=gpo.name, gpo_guid=gpo.guid,
                    rule_id="PWD-001", category=self.category,
                    severity=Severity.CRITICAL,
                    title="Minimum password length is critically short",
                    description=f"Minimum password length is set to {s.value_number} characters.",
                    risk="Short passwords are trivially brute-forced. Passwords under 8 characters can be cracked in minutes with modern hardware.",
                    recommendation="Set minimum password length to at least 14 characters. Microsoft recommends 14+ for privileged accounts.",
                    setting_path=f"{_PW_BASE} -> MinimumPasswordLength",
                    current_value=str(s.value_number),
                    expected_value=">=14",
                )
            elif s.value_number < 14:
                yield Finding(
                    gpo_name=gpo.name, gpo_guid=gpo.guid,
                    rule_id="PWD-001", category=self.category,
                    severity=Severity.HIGH,
                    title="Minimum password length is below recommended",
                    description=f"Minimum password length is set to {s.value_number} characters.",
                    risk="Passwords shorter than 14 characters are increasingly vulnerable to offline brute-force attacks.",
                    recommendation="Increase minimum password length to at least 14 characters per CIS Benchmark and Microsoft best practices.",
                    setting_path=f"{_PW_BASE} -> MinimumPasswordLength",
                    current_value=str(s.value_number),
                    expected_value=">=14",
                )

        # PWD-002: Password complexity
        s = pw_settings.get("PasswordComplexity")
        if s and s.value_boolean is False:
            yield Finding(
                gpo_name=gpo.name, gpo_guid=gpo.guid,
                rule_id="PWD-002", category=self.category,
                severity=Severity.HIGH,
                title="Password complexity requirements disabled",
                description="Password complexity requirements are not enforced.",
                risk="Without complexity requirements, users can set simple passwords like '12345678' or 'password', making them highly susceptible to dictionary and brute-force attacks.",
                recommendation="Enable password complexity requirements. This forces passwords to contain characters from at least 3 of 5 categories (uppercase, lowercase, digits, special characters, unicode).",
                setting_path=f"{_PW_BASE} -> PasswordComplexity",
                current_value="Disabled",
                expected_value="Enabled",
            )

        # PWD-003: Maximum password age
        s = pw_settings.get("MaximumPasswordAge")
        if s and s.value_number is not None:
            if s.value_number == 0:
                yield Finding(
                    gpo_name=gpo.name, gpo_guid=gpo.guid,
                    rule_id="PWD-003", category=self.category,
                    severity=Severity.MEDIUM,
                    title="Passwords never expire",
                    description="Maximum password age is set to 0 (passwords never expire).",
                    risk="Passwords that never expire give attackers unlimited time to crack stolen hashes and allow compromised credentials to persist indefinitely.",
                    recommendation="Set maximum password age to 60-90 days, or implement a complementary monitoring strategy if using passphrase-based policies.",
                    setting_path=f"{_PW_BASE} -> MaximumPasswordAge",
                    current_value="0 (Never expires)",
                    expected_value="60-90 days",
                )
            elif s.value_number > 90:
                yield Finding(
                    gpo_name=gpo.name, gpo_guid=gpo.guid,
                    rule_id="PWD-003", category=self.category,
                    severity=Severity.LOW,
                    title="Maximum password age is longer than recommended",
                    description=f"Maximum password age is set to {s.value_number} days.",
                    risk="Longer password lifetimes increase the window of opportunity for attackers to use compromised credentials.",
                    recommendation="Consider reducing maximum password age to 60-90 days per CIS Benchmark recommendations.",
                    setting_path=f"{_PW_BASE} -> MaximumPasswordAge",
                    current_value=f"{s.value_number} days",
                    expected_value="<=90 days",
                )

        # PWD-004: Minimum password age
        s = pw_settings.get("MinimumPasswordAge")
        if s and s.value_number is not None and s.value_number == 0:
            yield Finding(
                gpo_name=gpo.name, gpo_guid=gpo.guid,
                rule_id="PWD-004", category=self.category,
                severity=Severity.LOW,
                title="Minimum password age is zero",
                description="Users can change passwords immediately without waiting.",
                risk="A zero minimum password age allows users to cycle through password history rapidly, effectively reusing old passwords.",
                recommendation="Set minimum password age to at least 1 day to enforce password history effectively.",
                setting_path=f"{_PW_BASE} -> MinimumPasswordAge",
                current_value="0 days",
                expected_value=">=1 day",
            )

        # PWD-005: Password history
        s = pw_settings.get("PasswordHistorySize")
        if s and s.value_number is not None and s.value_number < 12:
            yield Finding(
                gpo_name=gpo.name, gpo_guid=gpo.guid,
                rule_id="PWD-005", category=self.category,
                severity=Severity.MEDIUM,
                title="Password history size is too small",
                description=f"Password history remembers only {s.value_number} passwords.",
                risk="A small password history allows users to cycle back to previously compromised passwords quickly.",
                recommendation="Set password history to remember at least 24 passwords (CIS Benchmark recommendation).",
                setting_path=f"{_PW_BASE} -> PasswordHistorySize",
                current_value=str(s.value_number),
                expected_value=">=24",
            )

        # PWD-006: Reversible encryption
        s = pw_settings.get("ClearTextPassword")
        if s and s.value_boolean is True:
            yield Finding(
                gpo_name=gpo.name, gpo_guid=gpo.guid,
                rule_id="PWD-006", category=self.category,
                severity=Severity.CRITICAL,
                title="Reversible encryption for passwords is enabled",
                description="Passwords are stored using reversible encryption, equivalent to storing plaintext.",
                risk="An attacker who gains access to the AD database can extract all user passwords in cleartext. This completely undermines password security.",
                recommendation="Disable 'Store passwords using reversible encryption' immediately. Any application requiring this should be redesigned to use proper authentication.",
                setting_path=f"{_PW_BASE} -> ClearTextPassword",
                current_value="Enabled",
                expected_value="Disabled",
            )
