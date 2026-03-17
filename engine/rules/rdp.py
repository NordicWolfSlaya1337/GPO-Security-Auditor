from typing import Generator

from engine.models import GPO, Finding, Severity
from engine.rules.base import AuditRule, register_rule

_RDP_TPL = "Computer Configuration -> Policies -> Administrative Templates -> Windows Components -> Remote Desktop Services -> Remote Desktop Session Host"
_RDP_SEC_OPT = "Computer Configuration -> Policies -> Windows Settings -> Security Settings -> Local Policies -> Security Options"


@register_rule
class RDPRules(AuditRule):
    rule_id_prefix = "RDP"
    category = "Remote Desktop Protocol"

    def evaluate(self, gpo: GPO, all_gpos: list) -> Generator[Finding, None, None]:
        rdp_enabled = False
        nla_configured = False
        encryption_level = None

        for pol in gpo.registry_policies:
            cat_lower = pol.category.lower() if pol.category else ""
            name_lower = pol.name.lower()

            # Check if RDP is enabled
            if "remote desktop" in cat_lower or "terminal services" in cat_lower:
                if "allow users to connect remotely" in name_lower and pol.state == "Enabled":
                    rdp_enabled = True

                # RDP-001: NLA not required
                if "require user authentication" in name_lower or "network level authentication" in name_lower:
                    nla_configured = True
                    if pol.state == "Disabled":
                        yield Finding(
                            gpo_name=gpo.name, gpo_guid=gpo.guid,
                            rule_id="RDP-001", category=self.category,
                            severity=Severity.HIGH,
                            title="RDP Network Level Authentication (NLA) is disabled",
                            description="Network Level Authentication is not required for Remote Desktop connections.",
                            risk="Without NLA, the RDP session is established before authentication, exposing the logon screen to unauthenticated users. This enables BlueKeep-style exploits and man-in-the-middle attacks on RDP sessions.",
                            recommendation="Enable 'Require user authentication for remote connections by using Network Level Authentication' in Remote Desktop Session Host > Security.",
                            setting_path=f"{_RDP_TPL} -> Security -> Require user authentication for remote connections by using Network Level Authentication",
                            current_value="Disabled",
                            expected_value="Enabled",
                        )

                # RDP-002: Encryption level
                if "encryption level" in name_lower or "set client connection encryption level" in name_lower:
                    if pol.state == "Enabled":
                        for v in pol.values.values():
                            try:
                                encryption_level = int(v)
                            except (ValueError, TypeError):
                                if "low" in str(v).lower():
                                    encryption_level = 1
                                elif "client" in str(v).lower():
                                    encryption_level = 2
                                elif "high" in str(v).lower():
                                    encryption_level = 3

                # Check for drive redirection (data exfil risk)
                if "do not allow drive redirection" in name_lower and pol.state == "Disabled":
                    yield Finding(
                        gpo_name=gpo.name, gpo_guid=gpo.guid,
                        rule_id="RDP-004", category=self.category,
                        severity=Severity.LOW,
                        title="RDP drive redirection is allowed",
                        description="Client drive redirection is allowed in RDP sessions.",
                        risk="Drive redirection allows data transfer between RDP client and server, which can be used for data exfiltration or malware delivery.",
                        recommendation="Disable client drive redirection unless specifically required. Set 'Do not allow drive redirection' to Enabled.",
                        setting_path=f"{_RDP_TPL} -> Device and Resource Redirection -> Do not allow drive redirection",
                        current_value="Allowed",
                        expected_value="Disabled",
                    )

                # RDP-005: Clipboard redirection allowed
                if "do not allow clipboard redirection" in name_lower and pol.state == "Disabled":
                    yield Finding(
                        gpo_name=gpo.name, gpo_guid=gpo.guid,
                        rule_id="RDP-005", category=self.category,
                        severity=Severity.MEDIUM,
                        title="RDP clipboard redirection is allowed",
                        description="Clipboard copy-paste and drag-and-drop are allowed in RDP sessions.",
                        risk="Clipboard redirection enables data exfiltration by copying sensitive data from the remote session to the local machine. "
                             "It also allows malware transfer via paste operations and drag-and-drop.",
                        recommendation="Set 'Do not allow clipboard redirection' to Enabled to block clipboard sharing in RDP sessions.",
                        setting_path=f"{_RDP_TPL} -> Device and Resource Redirection -> Do not allow clipboard redirection",
                        current_value="Allowed",
                        expected_value="Disabled",
                    )

                # RDP-006: COM port redirection allowed
                if "do not allow com port redirection" in name_lower and pol.state == "Disabled":
                    yield Finding(
                        gpo_name=gpo.name, gpo_guid=gpo.guid,
                        rule_id="RDP-006", category=self.category,
                        severity=Severity.LOW,
                        title="RDP COM port redirection is allowed",
                        description="COM port redirection is allowed in RDP sessions.",
                        risk="COM port redirection exposes local serial devices to the remote session, which can be exploited for unauthorized hardware access.",
                        recommendation="Set 'Do not allow COM port redirection' to Enabled.",
                        setting_path=f"{_RDP_TPL} -> Device and Resource Redirection -> Do not allow COM port redirection",
                        current_value="Allowed",
                        expected_value="Disabled",
                    )

                # RDP-007: Printer redirection allowed
                if "do not allow client printer redirection" in name_lower and pol.state == "Disabled":
                    yield Finding(
                        gpo_name=gpo.name, gpo_guid=gpo.guid,
                        rule_id="RDP-007", category=self.category,
                        severity=Severity.LOW,
                        title="RDP printer redirection is allowed",
                        description="Client printer redirection is allowed in RDP sessions.",
                        risk="Printer redirection can be abused to exfiltrate data by printing sensitive documents to a local printer from a remote session.",
                        recommendation="Set 'Do not allow client printer redirection' to Enabled.",
                        setting_path=f"{_RDP_TPL} -> Device and Resource Redirection -> Do not allow client printer redirection",
                        current_value="Allowed",
                        expected_value="Disabled",
                    )

                # RDP-008: LPT port redirection allowed
                if "do not allow lpt port redirection" in name_lower and pol.state == "Disabled":
                    yield Finding(
                        gpo_name=gpo.name, gpo_guid=gpo.guid,
                        rule_id="RDP-008", category=self.category,
                        severity=Severity.LOW,
                        title="RDP LPT port redirection is allowed",
                        description="LPT (parallel) port redirection is allowed in RDP sessions.",
                        risk="LPT port redirection exposes local parallel port devices to the remote session, increasing the attack surface.",
                        recommendation="Set 'Do not allow LPT port redirection' to Enabled.",
                        setting_path=f"{_RDP_TPL} -> Device and Resource Redirection -> Do not allow LPT port redirection",
                        current_value="Allowed",
                        expected_value="Disabled",
                    )

                # RDP-009: USB/PnP device redirection allowed
                if "do not allow supported plug and play" in name_lower and pol.state == "Disabled":
                    yield Finding(
                        gpo_name=gpo.name, gpo_guid=gpo.guid,
                        rule_id="RDP-009", category=self.category,
                        severity=Severity.MEDIUM,
                        title="RDP USB/Plug and Play device redirection is allowed",
                        description="Supported Plug and Play device redirection is allowed in RDP sessions.",
                        risk="USB/PnP redirection allows local USB devices to be accessed from the remote session. "
                             "This can be exploited for BadUSB attacks, unauthorized data transfer, or keystroke injection.",
                        recommendation="Set 'Do not allow supported Plug and Play device redirection' to Enabled.",
                        setting_path=f"{_RDP_TPL} -> Device and Resource Redirection -> Do not allow supported Plug and Play device redirection",
                        current_value="Allowed",
                        expected_value="Disabled",
                    )

                # RDP-010: Idle session timeout not configured
                if "set time limit for active but idle" in name_lower and pol.state == "Disabled":
                    yield Finding(
                        gpo_name=gpo.name, gpo_guid=gpo.guid,
                        rule_id="RDP-010", category=self.category,
                        severity=Severity.MEDIUM,
                        title="RDP idle session timeout is disabled",
                        description="No time limit is set for idle RDP sessions.",
                        risk="Idle RDP sessions remain open indefinitely. An attacker with physical or network access "
                             "can hijack an abandoned session without needing credentials.",
                        recommendation="Set 'Set time limit for active but idle Remote Desktop Services sessions' to 15 or 30 minutes.",
                        setting_path=f"{_RDP_TPL} -> Session Time Limits -> Set time limit for active but idle Remote Desktop Services sessions",
                        current_value="Disabled (no timeout)",
                        expected_value="15-30 minutes",
                    )

                # RDP-011: Active session timeout not configured
                if "set time limit for active remote desktop" in name_lower and "idle" not in name_lower and pol.state == "Disabled":
                    yield Finding(
                        gpo_name=gpo.name, gpo_guid=gpo.guid,
                        rule_id="RDP-011", category=self.category,
                        severity=Severity.LOW,
                        title="RDP active session timeout is disabled",
                        description="No maximum time limit is set for active RDP sessions.",
                        risk="Without a maximum session duration, RDP sessions can persist indefinitely. "
                             "Long-lived sessions increase the window for credential theft and session hijacking.",
                        recommendation="Set 'Set time limit for active Remote Desktop Services sessions' to a reasonable duration (e.g., 8-12 hours).",
                        setting_path=f"{_RDP_TPL} -> Session Time Limits -> Set time limit for active Remote Desktop Services sessions",
                        current_value="Disabled (no timeout)",
                        expected_value="8-12 hours",
                    )

                # RDP-012: Disconnected session timeout not configured
                if "set time limit for disconnected sessions" in name_lower and pol.state == "Disabled":
                    yield Finding(
                        gpo_name=gpo.name, gpo_guid=gpo.guid,
                        rule_id="RDP-012", category=self.category,
                        severity=Severity.MEDIUM,
                        title="RDP disconnected session timeout is disabled",
                        description="Disconnected RDP sessions are not terminated after a time limit.",
                        risk="Disconnected sessions remain in memory on the server indefinitely. An attacker who gains "
                             "network access can reconnect to an existing disconnected session without re-authentication, "
                             "inheriting the original user's privileges.",
                        recommendation="Set 'Set time limit for disconnected sessions' to 1-5 minutes to ensure disconnected sessions are terminated promptly.",
                        setting_path=f"{_RDP_TPL} -> Session Time Limits -> Set time limit for disconnected sessions",
                        current_value="Disabled (never terminates)",
                        expected_value="1-5 minutes",
                    )

                # RDP-013: Password not required upon reconnection (session hijacking)
                if "always prompt for password upon connection" in name_lower and pol.state == "Disabled":
                    yield Finding(
                        gpo_name=gpo.name, gpo_guid=gpo.guid,
                        rule_id="RDP-013", category=self.category,
                        severity=Severity.HIGH,
                        title="RDP does not require password on reconnection",
                        description="Users are not prompted for a password when reconnecting to an RDP session.",
                        risk="Without a password prompt on reconnection, an attacker who gains access to a disconnected "
                             "or idle session can resume it without credentials. This is the primary RDP session hijacking vector.",
                        recommendation="Enable 'Always prompt for password upon connection' to force re-authentication on every RDP connection.",
                        setting_path=f"{_RDP_TPL} -> Security -> Always prompt for password upon connection",
                        current_value="Disabled",
                        expected_value="Enabled",
                    )

        # Check security options for RDP-related settings
        for opt in gpo.security_options:
            if "TerminalServices" in opt.key_name or "Terminal Services" in opt.key_name:
                if "MinEncryptionLevel" in opt.key_name and opt.setting_number is not None:
                    encryption_level = opt.setting_number

                if "UserAuthentication" in opt.key_name and opt.setting_number == 0:
                    if not nla_configured:
                        yield Finding(
                            gpo_name=gpo.name, gpo_guid=gpo.guid,
                            rule_id="RDP-001", category=self.category,
                            severity=Severity.HIGH,
                            title="RDP Network Level Authentication (NLA) is disabled",
                            description="NLA is disabled via security option registry setting.",
                            risk="Without NLA, the RDP session is established before authentication, exposing the logon screen to unauthenticated users.",
                            recommendation="Enable Network Level Authentication for all RDP connections.",
                            setting_path=f"{_RDP_SEC_OPT} -> UserAuthentication",
                            current_value="Disabled (0)",
                            expected_value="Enabled (1)",
                        )

        if encryption_level is not None and encryption_level < 3:
            yield Finding(
                gpo_name=gpo.name, gpo_guid=gpo.guid,
                rule_id="RDP-002", category=self.category,
                severity=Severity.MEDIUM,
                title="RDP encryption level is below High",
                description=f"RDP encryption level is set to {encryption_level} (High=3, Client Compatible=2, Low=1).",
                risk="Lower encryption levels use weaker ciphers that may be vulnerable to cryptographic attacks, allowing interception of RDP session data.",
                recommendation="Set RDP encryption level to 'High' (3) to ensure strong encryption for all RDP connections.",
                setting_path=f"{_RDP_TPL} -> Security -> Set client connection encryption level",
                current_value=f"Level {encryption_level}",
                expected_value="Level 3 (High)",
            )

        # RDP-003: RDP enabled and linked to broad OU
        if rdp_enabled:
            for link in gpo.links:
                if link.enabled and link.som_path and "/" not in link.som_path:
                    yield Finding(
                        gpo_name=gpo.name, gpo_guid=gpo.guid,
                        rule_id="RDP-003", category=self.category,
                        severity=Severity.MEDIUM,
                        title="RDP is enabled at domain root level",
                        description=f"RDP is enabled by GPO '{gpo.name}' which is linked to the domain root '{link.som_path}'.",
                        risk="Enabling RDP at the domain root applies to all computers in the domain, greatly increasing the attack surface for lateral movement and brute-force attacks.",
                        recommendation="Apply RDP-enabling GPOs only to specific OUs containing servers or workstations that require remote access. Never enable RDP domain-wide.",
                        setting_path=f"{_RDP_TPL} -> Connections -> Allow users to connect remotely by using Remote Desktop Services",
                        current_value=f"Linked to {link.som_path}",
                        expected_value="Linked to specific server/workstation OUs only",
                    )
                    break
