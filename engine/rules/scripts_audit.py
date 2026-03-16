from typing import Generator

from engine.models import GPO, Finding, Severity
from engine.rules.base import AuditRule, register_rule

# Common user-writable local paths
USER_WRITABLE_PATHS = [
    "\\users\\", "\\temp\\", "\\tmp\\", "%temp%", "%tmp%",
    "\\appdata\\", "%appdata%", "%userprofile%", "\\desktop\\",
    "\\downloads\\", "c:\\temp", "c:\\tmp",
]


@register_rule
class ScriptSecurityRules(AuditRule):
    rule_id_prefix = "SCR"
    category = "Script Security"

    def evaluate(self, gpo: GPO, all_gpos: list) -> Generator[Finding, None, None]:
        domain = gpo.domain.lower() if gpo.domain else ""

        for entry in gpo.script_entries:
            cmd = entry.command
            cmd_lower = cmd.lower()

            # SCR-001: Script from non-SYSVOL/NETLOGON UNC path
            if cmd.startswith("\\\\"):
                is_sysvol = False
                if domain:
                    is_sysvol = (
                        f"\\\\{domain}\\sysvol" in cmd_lower or
                        f"\\\\{domain}\\netlogon" in cmd_lower
                    )
                # Also check common DC share patterns
                if not is_sysvol:
                    is_sysvol = "\\sysvol\\" in cmd_lower or "\\netlogon\\" in cmd_lower

                if not is_sysvol:
                    yield Finding(
                        gpo_name=gpo.name, gpo_guid=gpo.guid,
                        rule_id="SCR-001", category=self.category,
                        severity=Severity.HIGH,
                        title=f"Script executed from non-SYSVOL UNC path",
                        description=f"Script '{cmd}' is loaded from a UNC path outside SYSVOL/NETLOGON. "
                                    f"Script type: {entry.script_type or 'Unknown'}.",
                        risk="Scripts from arbitrary file shares may be writable by non-administrators. "
                             "An attacker who can modify the script gains code execution on all machines processing this GPO, "
                             "enabling mass compromise and privilege escalation.",
                        recommendation="Move scripts to SYSVOL or NETLOGON which have controlled permissions. "
                                       "Verify ACLs on the source share. Use signed scripts where possible.",
                        setting_path=f"{'Computer' if entry.script_type in ('Startup', 'Shutdown') else 'User'} Configuration -> Policies -> Windows Settings -> Scripts ({entry.script_type or 'Unknown'})",
                        current_value=cmd,
                        expected_value="\\\\<domain>\\SYSVOL\\ or \\\\<domain>\\NETLOGON\\",
                        confidence="High",
                        applies_to="workstations, servers",
                    )

            # SCR-002: Script from user-writable local path
            elif any(p in cmd_lower for p in USER_WRITABLE_PATHS):
                yield Finding(
                    gpo_name=gpo.name, gpo_guid=gpo.guid,
                    rule_id="SCR-002", category=self.category,
                    severity=Severity.MEDIUM,
                    title="Script executed from user-writable location",
                    description=f"Script '{cmd}' is loaded from a potentially user-writable path. "
                                f"Script type: {entry.script_type or 'Unknown'}.",
                    risk="Scripts in user-writable locations can be replaced by malware or a malicious user, "
                         "gaining code execution in the context of the GPO script (often SYSTEM for startup scripts).",
                    recommendation="Move scripts to a protected location (SYSVOL, Program Files, or a locked-down share). "
                                   "Set restrictive ACLs.",
                    setting_path=f"{'Computer' if entry.script_type in ('Startup', 'Shutdown') else 'User'} Configuration -> Policies -> Windows Settings -> Scripts ({entry.script_type or 'Unknown'})",
                    current_value=cmd,
                    expected_value="Protected location with restricted ACLs",
                    confidence="Medium",
                    applies_to="workstations, servers",
                )

            # SCR-003: Unqualified script name (no path separator)
            elif "\\" not in cmd and "/" not in cmd and ":" not in cmd and cmd.strip():
                yield Finding(
                    gpo_name=gpo.name, gpo_guid=gpo.guid,
                    rule_id="SCR-003", category=self.category,
                    severity=Severity.MEDIUM,
                    title="Script uses unqualified path (PATH hijack risk)",
                    description=f"Script '{cmd}' has no directory path, relying on PATH resolution. "
                                f"Script type: {entry.script_type or 'Unknown'}.",
                    risk="Unqualified script names resolve via the PATH environment variable. An attacker who can place "
                         "a malicious file with the same name in a higher-priority PATH directory gains code execution.",
                    recommendation="Use fully qualified paths for all GPO scripts (e.g., \\\\domain\\NETLOGON\\script.bat).",
                    setting_path=f"{'Computer' if entry.script_type in ('Startup', 'Shutdown') else 'User'} Configuration -> Policies -> Windows Settings -> Scripts ({entry.script_type or 'Unknown'})",
                    current_value=cmd,
                    expected_value="Fully qualified path",
                    confidence="Medium",
                    applies_to="workstations, servers",
                )
