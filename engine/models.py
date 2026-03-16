from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
from datetime import datetime


class Severity(Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


@dataclass
class GPOLink:
    som_name: str
    som_path: str
    enabled: bool
    no_override: bool


@dataclass
class AccountSetting:
    name: str
    setting_type: str  # "Password", "Account Lockout", "Kerberos"
    value_number: Optional[int] = None
    value_boolean: Optional[bool] = None


@dataclass
class AuditSetting:
    name: str
    success_attempts: bool = False
    failure_attempts: bool = False


@dataclass
class UserRightsAssignment:
    name: str
    members: list = field(default_factory=list)  # [{"sid": "...", "name": "..."}]


@dataclass
class SecurityOption:
    key_name: str
    setting_number: Optional[int] = None
    setting_string: Optional[str] = None
    display_name: str = ""
    display_string: str = ""
    display_boolean: Optional[bool] = None


@dataclass
class RegistryPolicy:
    name: str
    state: str  # "Enabled", "Disabled", "Not Configured"
    category: str = ""
    explain: str = ""
    values: dict = field(default_factory=dict)


@dataclass
class RegistryItem:
    hive: str
    key: str
    value_name: str
    value_type: str
    value_data: str
    action: str = "U"


@dataclass
class FirewallProfile:
    name: str  # "Domain", "Standard", "Public"
    enabled: Optional[bool] = None
    default_inbound: str = ""
    default_outbound: str = ""
    notifications_disabled: Optional[bool] = None
    log_dropped: Optional[bool] = None
    log_successful: Optional[bool] = None


@dataclass
class FirewallRule:
    name: str = ""
    direction: str = ""
    action: str = ""
    protocol: str = ""
    local_port: str = ""
    remote_port: str = ""
    remote_address: str = ""
    program: str = ""
    enabled: bool = True


@dataclass
class ScriptEntry:
    command: str
    parameters: str = ""
    script_type: str = ""  # Logon, Logoff, Startup, Shutdown
    order: int = 0


@dataclass
class RestrictedGroup:
    group_name: str
    members: list = field(default_factory=list)
    member_of: list = field(default_factory=list)


@dataclass
class PreferenceItem:
    item_type: str  # ScheduledTask, Service, Drive, LocalGroup, etc.
    name: str = ""
    properties: dict = field(default_factory=dict)
    cpassword: str = ""


@dataclass
class GPO:
    name: str
    guid: str
    domain: str
    created_time: Optional[datetime] = None
    modified_time: Optional[datetime] = None
    read_time: Optional[datetime] = None
    sddl: str = ""
    description: str = ""

    computer_enabled: bool = True
    computer_version_directory: int = 0
    computer_version_sysvol: int = 0

    user_enabled: bool = True
    user_version_directory: int = 0
    user_version_sysvol: int = 0

    account_settings: list = field(default_factory=list)
    audit_settings: list = field(default_factory=list)
    user_rights: list = field(default_factory=list)
    security_options: list = field(default_factory=list)
    registry_policies: list = field(default_factory=list)
    registry_items: list = field(default_factory=list)
    scripts: list = field(default_factory=list)
    script_entries: list = field(default_factory=list)
    restricted_groups: list = field(default_factory=list)
    preference_items: list = field(default_factory=list)
    firewall_profiles: list = field(default_factory=list)
    firewall_rules: list = field(default_factory=list)

    links: list = field(default_factory=list)
    gpo_status: str = ""
    permissions: list = field(default_factory=list)

    @property
    def is_linked(self) -> bool:
        return len(self.links) > 0

    @property
    def has_enabled_links(self) -> bool:
        return any(link.enabled for link in self.links)

    @property
    def has_any_settings(self) -> bool:
        return any([
            self.account_settings, self.audit_settings, self.user_rights,
            self.security_options, self.registry_policies, self.registry_items,
            self.scripts, self.script_entries, self.restricted_groups,
            self.preference_items, self.firewall_profiles, self.firewall_rules,
        ])

    @property
    def is_empty(self) -> bool:
        return (self.computer_version_directory == 0 and
                self.user_version_directory == 0 and
                not self.has_any_settings)

    def get_account_setting(self, name: str) -> Optional[AccountSetting]:
        for s in self.account_settings:
            if s.name == name:
                return s
        return None

    def get_security_option_by_key(self, partial_key: str) -> Optional[SecurityOption]:
        for s in self.security_options:
            if partial_key.lower() in s.key_name.lower():
                return s
        return None

    def get_linked_ou_paths(self) -> list:
        return [link.som_path for link in self.links if link.enabled]


@dataclass
class Finding:
    gpo_name: str
    gpo_guid: str
    rule_id: str
    category: str
    severity: Severity
    title: str
    description: str
    risk: str
    recommendation: str
    setting_path: str = ""        # GPMC path to the setting (e.g., "Computer Configuration -> ... -> SettingName")
    current_value: str = ""
    expected_value: str = ""
    confidence: str = ""          # High, Medium, Low
    applies_to: str = ""          # domain, DCs, servers, workstations, users
    architecture_fix: str = ""    # merge, split, remove, change precedence, tighten filtering


@dataclass
class AuditReport:
    domain: str
    scan_time: datetime
    total_gpos: int
    findings: list = field(default_factory=list)
    gpos: list = field(default_factory=list)

    @property
    def risk_score(self) -> int:
        """0-100 score where 100 = perfect. Uses weighted severity with diminishing returns."""
        import math
        counts = self.severity_counts
        # Weighted penalty per severity with diminishing returns per count
        # Each additional finding of same severity adds less penalty
        penalty = 0.0
        weights = {
            Severity.CRITICAL: (25.0, 5.0),   # (first finding, each additional via log)
            Severity.HIGH: (12.0, 3.0),
            Severity.MEDIUM: (4.0, 1.5),
            Severity.LOW: (1.0, 0.5),
            Severity.INFO: (0.0, 0.0),
        }
        for sev, count in counts.items():
            if count == 0:
                continue
            base, extra = weights.get(sev, (0, 0))
            penalty += base + extra * math.log2(max(1, count))
        return max(0, min(100, round(100 - penalty)))

    @property
    def severity_counts(self) -> dict:
        counts = {s: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity] += 1
        return counts

    @property
    def risk_label(self) -> str:
        score = self.risk_score
        if score >= 80:
            return "Low Risk"
        elif score >= 60:
            return "Medium Risk"
        elif score >= 40:
            return "High Risk"
        else:
            return "Critical Risk"
