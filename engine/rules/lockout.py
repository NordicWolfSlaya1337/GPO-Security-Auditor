from typing import Generator

from engine.models import GPO, Finding, Severity
from engine.rules.base import AuditRule, register_rule

_LCK_BASE = "Computer Configuration -> Policies -> Windows Settings -> Security Settings -> Account Policies -> Account Lockout Policy"


@register_rule
class AccountLockoutRules(AuditRule):
    rule_id_prefix = "LCK"
    category = "Account Lockout"

    def evaluate(self, gpo: GPO, all_gpos: list) -> Generator[Finding, None, None]:
        lock_settings = {s.name: s for s in gpo.account_settings if s.setting_type == "Account Lockout"}
        if not lock_settings:
            return

        # LCK-001: No lockout threshold
        s = lock_settings.get("LockoutBadCount")
        if s and s.value_number is not None:
            if s.value_number == 0:
                yield Finding(
                    gpo_name=gpo.name, gpo_guid=gpo.guid,
                    rule_id="LCK-001", category=self.category,
                    severity=Severity.CRITICAL,
                    title="Account lockout threshold is disabled",
                    description="Account lockout is set to 0 (never lock out).",
                    risk="Without account lockout, attackers can perform unlimited password guessing attempts against any account, making brute-force attacks trivially easy.",
                    recommendation="Set account lockout threshold to 5-10 invalid attempts. Combine with smart lockout or progressive delays where possible.",
                    setting_path=f"{_LCK_BASE} -> LockoutBadCount",
                    current_value="0 (Disabled)",
                    expected_value="5-10 attempts",
                )
            elif s.value_number > 10:
                # LCK-002: Threshold too high
                yield Finding(
                    gpo_name=gpo.name, gpo_guid=gpo.guid,
                    rule_id="LCK-002", category=self.category,
                    severity=Severity.MEDIUM,
                    title="Account lockout threshold is too high",
                    description=f"Account lockout triggers after {s.value_number} invalid attempts.",
                    risk="A high lockout threshold gives attackers many guessing attempts before triggering a lockout.",
                    recommendation="Reduce account lockout threshold to 5-10 invalid attempts per CIS Benchmark.",
                    setting_path=f"{_LCK_BASE} -> LockoutBadCount",
                    current_value=str(s.value_number),
                    expected_value="5-10 attempts",
                )

        # LCK-003: Lockout duration too short
        s = lock_settings.get("LockoutDuration")
        if s and s.value_number is not None and s.value_number < 15 and s.value_number != 0:
            yield Finding(
                gpo_name=gpo.name, gpo_guid=gpo.guid,
                rule_id="LCK-003", category=self.category,
                severity=Severity.MEDIUM,
                title="Account lockout duration is too short",
                description=f"Locked accounts unlock after {s.value_number} minutes.",
                risk="Short lockout durations allow attackers to wait briefly and resume brute-force attacks.",
                recommendation="Set lockout duration to at least 15-30 minutes, or require manual unlock for sensitive environments.",
                setting_path=f"{_LCK_BASE} -> LockoutDuration",
                current_value=f"{s.value_number} minutes",
                expected_value=">=15 minutes",
            )

        # LCK-004: Reset counter too short
        s = lock_settings.get("ResetLockoutCount")
        if s and s.value_number is not None and s.value_number < 15 and s.value_number != 0:
            yield Finding(
                gpo_name=gpo.name, gpo_guid=gpo.guid,
                rule_id="LCK-004", category=self.category,
                severity=Severity.LOW,
                title="Lockout counter reset time is too short",
                description=f"Failed attempt counter resets after {s.value_number} minutes.",
                risk="A short reset window lets attackers space out their guesses to avoid lockout while still conducting slow brute-force attacks.",
                recommendation="Set the lockout counter reset time to at least 15-30 minutes.",
                setting_path=f"{_LCK_BASE} -> ResetLockoutCount",
                current_value=f"{s.value_number} minutes",
                expected_value=">=15 minutes",
            )
