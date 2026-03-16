import re
from typing import Generator

from engine.models import GPO, Finding, Severity
from engine.rules.base import AuditRule, register_rule

# ---------------------------------------------------------------------------
# Well-known GUIDs for the two built-in default GPOs (used for identification
# only — never hardcoded into findings; findings always use gpo.guid).
# ---------------------------------------------------------------------------
_DEFAULT_DOMAIN_POLICY_GUID = "31B2F340-016D-11D2-945F-00C04FB984F9"
_DEFAULT_DC_POLICY_GUID = "6AC1786C-016F-11D2-945F-00C04FB984F9"


def _normalize_guid(guid: str) -> str:
    """Strip braces/whitespace and upper-case for comparison."""
    return guid.strip().strip("{}").upper()


def is_default_domain_policy(gpo: GPO) -> bool:
    """Match Default Domain Policy by well-known GUID, then name fallback."""
    if gpo.guid and _normalize_guid(gpo.guid) == _DEFAULT_DOMAIN_POLICY_GUID:
        return True
    return gpo.name.lower().strip() == "default domain policy"


def is_default_dc_policy(gpo: GPO) -> bool:
    """Match Default Domain Controllers Policy by well-known GUID, then name fallback."""
    if gpo.guid and _normalize_guid(gpo.guid) == _DEFAULT_DC_POLICY_GUID:
        return True
    return gpo.name.lower().strip() == "default domain controllers policy"


def is_default_gpo(gpo: GPO) -> bool:
    return is_default_domain_policy(gpo) or is_default_dc_policy(gpo)


def default_gpo_label(gpo: GPO) -> str:
    """Human-readable canonical label (used in recommendation text only)."""
    if is_default_domain_policy(gpo):
        return "Default Domain Policy"
    if is_default_dc_policy(gpo):
        return "Default Domain Controllers Policy"
    return gpo.name


# ---------------------------------------------------------------------------
# Required Advanced Audit Policy subcategories — one rule per subcategory.
# Each entry drives a discrete AUD-### finding when the setting is missing
# or incomplete in either of the two default GPOs.
# ---------------------------------------------------------------------------
AUDIT_SUBCATEGORY_RULES = [
    {
        "rule_id": "AUD-001",
        "subcategory_name": "Audit Process Creation",
        "display_name": "Process Creation",
        "gp_group": "Detailed Tracking",
        "success_required": True,
        "failure_required": True,
        "severity": Severity.HIGH,
        "risk": (
            "Without Process Creation auditing, new process execution (including "
            "malware, LOLBins, and lateral movement tools) goes unrecorded. This "
            "is the single most important audit subcategory for endpoint detection."
        ),
    },
    {
        "rule_id": "AUD-002",
        "subcategory_name": "Audit Process Termination",
        "display_name": "Process Termination",
        "gp_group": "Detailed Tracking",
        "success_required": True,
        "failure_required": False,
        "severity": Severity.MEDIUM,
        "risk": (
            "Without Process Termination auditing, the lifecycle of processes "
            "cannot be correlated, reducing the ability to detect long-running "
            "malicious tools or injected processes."
        ),
    },
    {
        "rule_id": "AUD-003",
        "subcategory_name": "Audit Registry",
        "display_name": "Registry",
        "gp_group": "Object Access",
        "success_required": True,
        "failure_required": True,
        "severity": Severity.MEDIUM,
        "risk": (
            "Without Registry auditing, modifications to critical registry keys "
            "(Run keys, services, security providers) by attackers go undetected."
        ),
    },
    {
        "rule_id": "AUD-004",
        "subcategory_name": "Audit Kerberos Authentication Service",
        "display_name": "Kerberos Authentication Service",
        "gp_group": "Account Logon",
        "success_required": True,
        "failure_required": True,
        "severity": Severity.HIGH,
        "risk": (
            "Without Kerberos Authentication Service auditing, Kerberos TGT "
            "requests and failures (AS-REQ/AS-REP) are not logged, preventing "
            "detection of AS-REP roasting, brute force, and pre-authentication attacks."
        ),
    },
    {
        "rule_id": "AUD-005",
        "subcategory_name": "Audit Kerberos Service Ticket Operations",
        "display_name": "Kerberos Service Ticket Operations",
        "gp_group": "Account Logon",
        "success_required": True,
        "failure_required": True,
        "severity": Severity.HIGH,
        "risk": (
            "Without Kerberos Service Ticket auditing, TGS requests are not "
            "logged, preventing detection of Kerberoasting, Silver Ticket attacks, "
            "and suspicious service ticket patterns."
        ),
    },
    {
        "rule_id": "AUD-006",
        "subcategory_name": "Audit Credential Validation",
        "display_name": "Credential Validation",
        "gp_group": "Account Logon",
        "success_required": True,
        "failure_required": True,
        "severity": Severity.HIGH,
        "risk": (
            "Without Credential Validation auditing, NTLM authentication attempts "
            "and failures are not logged, preventing detection of pass-the-hash, "
            "credential stuffing, and brute force attacks against NTLM."
        ),
    },
    {
        "rule_id": "AUD-007",
        "subcategory_name": "Audit Security Group Management",
        "display_name": "Security Group Management",
        "gp_group": "Account Management",
        "success_required": True,
        "failure_required": True,
        "severity": Severity.HIGH,
        "risk": (
            "Without Security Group Management auditing, additions to privileged "
            "groups (Domain Admins, Enterprise Admins, local Administrators) are "
            "not logged, allowing silent privilege escalation."
        ),
    },
    {
        "rule_id": "AUD-008",
        "subcategory_name": "Audit User Account Management",
        "display_name": "User Account Management",
        "gp_group": "Account Management",
        "success_required": True,
        "failure_required": False,
        "severity": Severity.HIGH,
        "risk": (
            "Without User Account Management auditing, account creation, deletion, "
            "password resets, and permission changes are not logged, hiding "
            "attacker persistence and unauthorized account modifications."
        ),
    },
    {
        "rule_id": "AUD-009",
        "subcategory_name": "Audit Computer Account Management",
        "display_name": "Computer Account Management",
        "gp_group": "Account Management",
        "success_required": True,
        "failure_required": False,
        "severity": Severity.MEDIUM,
        "risk": (
            "Without Computer Account Management auditing, rogue computer accounts "
            "or unauthorized machine joins to the domain are not logged, enabling "
            "shadow IT and potential resource-based constrained delegation attacks."
        ),
    },
    {
        "rule_id": "AUD-010",
        "subcategory_name": "Audit Directory Service Changes",
        "display_name": "Directory Service Changes",
        "gp_group": "DS Access",
        "success_required": True,
        "failure_required": False,
        "severity": Severity.HIGH,
        "risk": (
            "Without Directory Service Changes auditing, modifications to AD "
            "objects (ACL changes, attribute tampering, schema changes) are not "
            "logged, hiding DCSync preparations and persistence mechanisms."
        ),
    },
    {
        "rule_id": "AUD-011",
        "subcategory_name": "Audit Account Lockout",
        "display_name": "Account Lockout",
        "gp_group": "Logon/Logoff",
        "success_required": True,
        "failure_required": False,
        "severity": Severity.HIGH,
        "risk": (
            "Without Account Lockout auditing, lockout events from brute force or "
            "password spraying attacks are not logged, preventing early detection "
            "of credential attacks in progress."
        ),
    },
    {
        "rule_id": "AUD-012",
        "subcategory_name": "Audit Logoff",
        "display_name": "Logoff",
        "gp_group": "Logon/Logoff",
        "success_required": True,
        "failure_required": False,
        "severity": Severity.MEDIUM,
        "risk": (
            "Without Logoff auditing, session duration cannot be correlated with "
            "logon events, reducing the ability to reconstruct attacker session "
            "timelines during incident response."
        ),
    },
    {
        "rule_id": "AUD-013",
        "subcategory_name": "Audit Logon",
        "display_name": "Logon",
        "gp_group": "Logon/Logoff",
        "success_required": True,
        "failure_required": True,
        "severity": Severity.HIGH,
        "risk": (
            "Without Logon auditing (Success and Failure), both successful "
            "unauthorized access and failed brute-force/password-spray attempts "
            "go unrecorded. This is the foundational audit category for identity "
            "security monitoring."
        ),
    },
    {
        "rule_id": "AUD-014",
        "subcategory_name": "Audit Other Logon/Logoff Events",
        "display_name": "Other Logon/Logoff Events",
        "gp_group": "Logon/Logoff",
        "success_required": True,
        "failure_required": True,
        "severity": Severity.MEDIUM,
        "risk": (
            "Without Other Logon/Logoff Events auditing, network disconnects, "
            "terminal server session events, and screensaver-related logon/logoff "
            "events are not logged, creating gaps in session tracking."
        ),
    },
    {
        "rule_id": "AUD-015",
        "subcategory_name": "Audit Handle Manipulation",
        "display_name": "Handle Manipulation",
        "gp_group": "Object Access",
        "success_required": True,
        "failure_required": False,
        "severity": Severity.MEDIUM,
        "risk": (
            "Without Handle Manipulation auditing, object access through handle "
            "duplication (a technique used in process injection and token theft) "
            "is not logged."
        ),
    },
    {
        "rule_id": "AUD-016",
        "subcategory_name": "Audit Other Object Access Events",
        "display_name": "Other Object Access Events",
        "gp_group": "Object Access",
        "success_required": True,
        "failure_required": True,
        "severity": Severity.MEDIUM,
        "risk": (
            "Without Other Object Access Events auditing, Task Scheduler job "
            "access, COM+ catalog events, and other important object access events "
            "are not logged, reducing detection of scheduled-task-based persistence."
        ),
    },
    {
        "rule_id": "AUD-017",
        "subcategory_name": "Audit Audit Policy Change",
        "display_name": "Audit Policy Change",
        "gp_group": "Policy Change",
        "success_required": True,
        "failure_required": False,
        "severity": Severity.HIGH,
        "risk": (
            "Without Audit Policy Change auditing, an attacker who disables or "
            "modifies audit settings to cover their tracks will not generate an "
            "alert. This is the audit setting that protects all other audit settings."
        ),
    },
]

# Lookup for use by the conflict engine
AUDIT_SUBCATEGORY_NAMES = frozenset(
    r["subcategory_name"] for r in AUDIT_SUBCATEGORY_RULES
)


def _required_state_text(need_success: bool, need_failure: bool) -> str:
    if need_success and need_failure:
        return "Success and Failure"
    if need_success:
        return "Success"
    if need_failure:
        return "Failure"
    return "No Auditing"


def _gp_path(gp_group: str, subcategory_name: str) -> str:
    """Path for recommendation text (uses > separator)."""
    return (
        f"Computer Configuration > Policies > Windows Settings > Security Settings "
        f"> Advanced Audit Policy Configuration > System Audit Policies "
        f"> {gp_group} > {subcategory_name}"
    )


def _gp_path_arrow(gp_group: str, subcategory_name: str) -> str:
    """Path for description text (uses \u2192 separator for visual clarity)."""
    return (
        f"Computer Configuration \u2192 Policies \u2192 Windows Settings \u2192 Security Settings "
        f"\u2192 Advanced Audit Policy Configuration \u2192 System Audit Policies "
        f"\u2192 {gp_group} \u2192 {subcategory_name}"
    )


def _applies_to(gpo: GPO) -> str:
    if is_default_dc_policy(gpo):
        return "DCs"
    return "domain computers"


# ---------------------------------------------------------------------------
# Rule class — registered via @register_rule decorator
# ---------------------------------------------------------------------------

@register_rule
class AuditPolicyRules(AuditRule):
    rule_id_prefix = "AUD"
    category = "Audit & Logging Policy"

    def evaluate(self, gpo: GPO, all_gpos: list) -> Generator[Finding, None, None]:
        # ---------------------------------------------------------------
        # AUD-001 to AUD-017: only fire against the two default GPOs
        # ---------------------------------------------------------------
        if is_default_gpo(gpo):
            yield from self._check_subcategories(gpo)
            yield from self._check_cmdline_auditing(gpo)
            yield from self._check_scriptblock_logging(gpo)

        # ---------------------------------------------------------------
        # AUD-020: legacy vs advanced audit conflict (applies to ALL GPOs)
        # ---------------------------------------------------------------
        yield from self._check_legacy_conflict(gpo, all_gpos)

    # -- AUD-001 to AUD-017 ------------------------------------------------

    def _check_subcategories(self, gpo: GPO) -> Generator[Finding, None, None]:
        """Yield a single consolidated finding listing all audit subcategory gaps."""
        audit_map = {s.name: s for s in gpo.audit_settings}
        label = default_gpo_label(gpo)

        # Collect all issues
        issues = []          # (bullet_text, severity)
        rec_bullets = []     # (subcategory_name, required_state)
        affected_groups = set()

        for rule_def in AUDIT_SUBCATEGORY_RULES:
            subcat = rule_def["subcategory_name"]
            display = rule_def["display_name"]
            need_s = rule_def["success_required"]
            need_f = rule_def["failure_required"]
            severity = rule_def["severity"]
            gp_group = rule_def["gp_group"]
            required = _required_state_text(need_s, need_f)

            s = audit_map.get(subcat)

            if s is None:
                issues.append((
                    f"{display} — not configured (requires {required})",
                    severity,
                ))
                rec_bullets.append((subcat, required))
                affected_groups.add(gp_group)
            else:
                missing = []
                if need_s and not s.success_attempts:
                    missing.append("Success")
                if need_f and not s.failure_attempts:
                    missing.append("Failure")
                if missing:
                    current_state = (
                        f"{'Success' if s.success_attempts else ''}"
                        f"{' and ' if s.success_attempts and s.failure_attempts else ''}"
                        f"{'Failure' if s.failure_attempts else ''}"
                    ).strip() or "No Auditing"
                    issues.append((
                        f"{display} — missing {' and '.join(missing)} auditing "
                        f"(currently: {current_state} only)",
                        severity,
                    ))
                    rec_bullets.append((subcat, required))
                    affected_groups.add(gp_group)

        if not issues:
            return

        # Worst severity across all issues
        sev_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        worst_severity = min((sev for _, sev in issues), key=lambda s: sev_order.index(s))
        n = len(issues)
        total = len(AUDIT_SUBCATEGORY_RULES)

        # Build bullet lists
        desc_bullets = "\n".join(f"  \u2022 {text}" for text, _ in issues)
        rec_list = "\n".join(
            f"  \u2022 {subcat} \u2192 {required}"
            for subcat, required in rec_bullets
        )

        groups_text = ", ".join(sorted(affected_groups))

        yield Finding(
            gpo_name=gpo.name,
            gpo_guid=gpo.guid,
            rule_id="AUD-001",
            category=self.category,
            severity=worst_severity,
            title=f"Audit policy gaps — {n} subcategories missing or incomplete",
            description=(
                f"The following audit subcategories are not properly configured "
                f"in '{gpo.name}':\n\n{desc_bullets}"
            ),
            risk=(
                f"Missing audit coverage across {n} of {total} subcategories "
                f"reduces visibility into security-relevant activity. Affected "
                f"audit groups: {groups_text}. Without these audit settings, "
                f"critical events such as logon attempts, privilege escalation, "
                f"process execution, and AD changes may go unrecorded."
            ),
            recommendation=(
                f"Configure the following subcategories in {label}:\n\n"
                f"{rec_list}\n\n"
                f"Path: Computer Configuration > Policies > Windows Settings > "
                f"Security Settings > Advanced Audit Policy Configuration > "
                f"System Audit Policies\n\n"
                f"These settings should be configured exclusively in Default "
                f"Domain Policy and Default Domain Controllers Policy to "
                f"maintain a clean, centralized audit baseline."
            ),
            setting_path="Computer Configuration -> Policies -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration",
            current_value=f"{n} of {total} subcategories missing or incomplete",
            expected_value=f"All {total} subcategories configured per security baseline",
            confidence="High",
            applies_to=_applies_to(gpo),
            architecture_fix="centralize",
        )

    # -- AUD-018: command-line process auditing -----------------------------

    def _check_cmdline_auditing(self, gpo: GPO) -> Generator[Finding, None, None]:
        has_cmdline = False

        # Check admin template policies
        for pol in gpo.registry_policies:
            combined = (pol.name + pol.category).lower()
            if "processcreation" in combined and "cmdline" in combined:
                if pol.state == "Enabled":
                    has_cmdline = True
                    break
            if "include command line" in pol.name.lower():
                if pol.state == "Enabled":
                    has_cmdline = True
                    break

        # Check GPP registry items
        if not has_cmdline:
            for item in gpo.registry_items:
                if re.search(
                    r"ProcessCreationIncludeCmdLine|IncludeCommandLine",
                    item.value_name,
                    re.IGNORECASE,
                ):
                    if item.value_data == "1":
                        has_cmdline = True
                        break

        if not has_cmdline:
            label = default_gpo_label(gpo)
            yield Finding(
                gpo_name=gpo.name,
                gpo_guid=gpo.guid,
                rule_id="AUD-018",
                category=self.category,
                severity=Severity.HIGH,
                title="Command-line process auditing is not enabled",
                description=(
                    f"'{gpo.name}' does not enable 'Include command line in "
                    f"process creation events'.\n\n"
                    f"Setting path: Computer Configuration \u2192 Policies \u2192 "
                    f"Administrative Templates \u2192 System \u2192 Audit Process Creation "
                    f"\u2192 Include command line in process creation events"
                ),
                risk=(
                    "Without command-line auditing, security teams cannot see "
                    "what arguments were passed to processes, missing critical "
                    "context for detecting encoded PowerShell commands, LOLBin "
                    "abuse, and lateral movement."
                ),
                recommendation=(
                    f"Enable 'Include command line in process creation events' "
                    f"in {label}.\n\n"
                    f"Path: Computer Configuration > Policies > Administrative "
                    f"Templates > System > Audit Process Creation > Include "
                    f"command line in process creation events > Enabled\n\n"
                    f"This setting should be configured exclusively in "
                    f"Default Domain Policy and Default Domain Controllers "
                    f"Policy."
                ),
                setting_path="Computer Configuration -> Policies -> Administrative Templates -> System -> Audit Process Creation -> Include command line in process creation events",
                current_value="Not configured",
                expected_value="Enabled",
                confidence="High",
                applies_to=_applies_to(gpo),
                architecture_fix="centralize",
            )

    # -- AUD-019: PowerShell Script Block Logging ---------------------------

    def _check_scriptblock_logging(self, gpo: GPO) -> Generator[Finding, None, None]:
        has_scriptblock = False

        # Check admin template policies
        for pol in gpo.registry_policies:
            if "scriptblocklogging" in (pol.name + pol.category).lower():
                if pol.state == "Enabled":
                    has_scriptblock = True
                    break
            if "script block logging" in pol.name.lower():
                if pol.state == "Enabled":
                    has_scriptblock = True
                    break

        # Check GPP registry items
        if not has_scriptblock:
            for item in gpo.registry_items:
                if (
                    item.value_name.lower() == "enablescriptblocklogging"
                    and item.value_data == "1"
                ):
                    has_scriptblock = True
                    break

        if not has_scriptblock:
            label = default_gpo_label(gpo)
            yield Finding(
                gpo_name=gpo.name,
                gpo_guid=gpo.guid,
                rule_id="AUD-019",
                category=self.category,
                severity=Severity.HIGH,
                title="PowerShell Script Block Logging is not enabled",
                description=(
                    f"'{gpo.name}' does not enable 'Turn on PowerShell Script "
                    f"Block Logging'.\n\n"
                    f"Setting path: Computer Configuration \u2192 Policies \u2192 "
                    f"Administrative Templates \u2192 Windows Components \u2192 "
                    f"Windows PowerShell \u2192 Turn on PowerShell Script Block Logging"
                ),
                risk=(
                    "Without Script Block Logging, malicious PowerShell activity "
                    "(fileless malware, obfuscated scripts, living-off-the-land "
                    "attacks) cannot be detected or investigated in security logs."
                ),
                recommendation=(
                    f"Enable 'Turn on PowerShell Script Block Logging' in "
                    f"{label}.\n\n"
                    f"Path: Computer Configuration > Policies > Administrative "
                    f"Templates > Windows Components > Windows PowerShell > Turn "
                    f"on PowerShell Script Block Logging > Enabled\n\n"
                    f"This setting should be configured exclusively in "
                    f"Default Domain Policy and Default Domain Controllers "
                    f"Policy."
                ),
                setting_path="Computer Configuration -> Policies -> Administrative Templates -> Windows Components -> Windows PowerShell -> Turn on PowerShell Script Block Logging",
                current_value="Not configured",
                expected_value="Enabled",
                confidence="High",
                applies_to=_applies_to(gpo),
                architecture_fix="centralize",
            )

    # -- AUD-020: advanced vs legacy audit conflict -------------------------

    def _check_legacy_conflict(
        self, gpo: GPO, all_gpos: list
    ) -> Generator[Finding, None, None]:
        legacy_cats = {
            "AuditLogonEvents", "AuditAccountManage", "AuditPolicyChange",
            "AuditAccountLogon", "AuditObjectAccess", "AuditPrivilegeUse",
            "AuditSystemEvents", "AuditDSAccess", "AuditProcessTracking",
        }
        has_legacy = any(s.name in legacy_cats for s in gpo.audit_settings)
        has_advanced = any(
            s.name in AUDIT_SUBCATEGORY_NAMES for s in gpo.audit_settings
        )

        if has_legacy and has_advanced:
            sce_set = any(
                "scenoapplylegacyauditpolicy" in s.key_name.lower()
                and s.setting_number == 1
                for g in all_gpos
                for s in g.security_options
            )
            if not sce_set:
                yield Finding(
                    gpo_name=gpo.name,
                    gpo_guid=gpo.guid,
                    rule_id="AUD-020",
                    category=self.category,
                    severity=Severity.HIGH,
                    title="Advanced audit policy may be overridden by legacy settings",
                    description=(
                        f"'{gpo.name}' contains both legacy and advanced audit "
                        f"settings, and 'Audit: Force audit policy subcategory "
                        f"settings to override audit policy category settings' "
                        f"(SCENoApplyLegacyAuditPolicy) is not enabled.\n\n"
                        f"Setting path: Computer Configuration \u2192 Policies \u2192 "
                        f"Windows Settings \u2192 Security Settings \u2192 Local Policies "
                        f"\u2192 Security Options \u2192 Audit: Force audit policy "
                        f"subcategory settings (Windows Vista or later) to override "
                        f"audit policy category settings"
                    ),
                    risk=(
                        "When both legacy and advanced audit policies exist "
                        "without SCENoApplyLegacyAuditPolicy enabled, the "
                        "legacy settings override advanced subcategory settings, "
                        "potentially reducing audit coverage to the less "
                        "granular legacy categories."
                    ),
                    recommendation=(
                        "Set 'Audit: Force audit policy subcategory settings to "
                        "override audit policy category settings' to Enabled.\n\n"
                        "Path: Computer Configuration > Policies > Windows "
                        "Settings > Security Settings > Local Policies > "
                        "Security Options > Audit: Force audit policy "
                        "subcategory settings (Windows Vista or later) to "
                        "override audit policy category settings\n\n"
                        "Alternatively, remove all legacy audit settings and "
                        "use only Advanced Audit Policy Configuration."
                    ),
                    setting_path="Computer Configuration -> Policies -> Windows Settings -> Security Settings -> Local Policies -> Audit Policy",
                    current_value=(
                        "Both legacy and advanced audit settings present; "
                        "SCENoApplyLegacyAuditPolicy not enabled"
                    ),
                    expected_value=(
                        "SCENoApplyLegacyAuditPolicy = Enabled, or legacy "
                        "settings removed"
                    ),
                    confidence="High",
                    applies_to=_applies_to(gpo),
                )
