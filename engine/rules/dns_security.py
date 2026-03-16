import re
from typing import Generator

from engine.models import GPO, Finding, Severity
from engine.rules.base import AuditRule, register_rule

_DNS_BASE = "Computer Configuration -> Policies -> Administrative Templates -> Network -> DNS Client"


@register_rule
class DNSSecurityRules(AuditRule):
    rule_id_prefix = "DNS"
    category = "DNS Security"

    def evaluate(self, gpo: GPO, all_gpos: list) -> Generator[Finding, None, None]:
        for pol in gpo.registry_policies:
            text = f"{pol.name} {pol.category}".lower()

            # DNS-001: mDNS not disabled
            if ("multicast" in text and "dns" in pol.category.lower()) or "mdns" in text:
                if pol.state == "Disabled":
                    yield Finding(
                        gpo_name=gpo.name, gpo_guid=gpo.guid,
                        rule_id="DNS-001", category=self.category,
                        severity=Severity.MEDIUM,
                        title="Multicast DNS (mDNS) is not disabled",
                        description=f"Policy '{pol.name}' is disabled, leaving mDNS active.",
                        risk="mDNS broadcasts name resolution queries on the local network. Attackers can respond "
                             "to these queries to redirect traffic and capture credentials (similar to LLMNR poisoning "
                             "but via a different protocol).",
                        recommendation="Enable 'Turn off Multicast Name Resolution' to disable mDNS alongside LLMNR.",
                        setting_path=f"{_DNS_BASE} -> {pol.name}",
                        current_value=f"{pol.name}: Disabled (mDNS active)",
                        expected_value="Enabled (mDNS disabled)",
                    )

            # DNS-002: Dynamic updates not secured
            if "dynamic update" in text or "registrationenabled" in text.replace(" ", ""):
                if pol.state == "Enabled":
                    for key, val in pol.values.items():
                        if "nonsecure" in str(val).lower() or str(val) == "0":
                            yield Finding(
                                gpo_name=gpo.name, gpo_guid=gpo.guid,
                                rule_id="DNS-002", category=self.category,
                                severity=Severity.MEDIUM,
                                title="DNS dynamic updates are not restricted to secure only",
                                description=f"DNS dynamic update policy '{pol.name}' allows non-secure updates.",
                                risk="Non-secure DNS dynamic updates allow any client to register or modify DNS records "
                                     "without authentication. Attackers can hijack DNS names to redirect traffic.",
                                recommendation="Configure DNS dynamic updates to 'Secure only' to require "
                                               "authenticated (Kerberos) updates.",
                                setting_path=f"{_DNS_BASE} -> {pol.name}",
                                current_value="Non-secure updates allowed",
                                expected_value="Secure dynamic updates only",
                            )
                            break

            # DNS-003: DoH not configured
            if "dns over https" in text or "doh" in text:
                if pol.state == "Disabled":
                    yield Finding(
                        gpo_name=gpo.name, gpo_guid=gpo.guid,
                        rule_id="DNS-003", category=self.category,
                        severity=Severity.LOW,
                        title="DNS over HTTPS (DoH) is explicitly disabled",
                        description=f"Policy '{pol.name}' disables DNS over HTTPS.",
                        risk="Without DoH, DNS queries are sent in plaintext, allowing network observers to monitor "
                             "browsing activity and potentially modify DNS responses (DNS spoofing).",
                        recommendation="Consider enabling DNS over HTTPS for privacy and integrity of DNS resolution. "
                                       "Set DoH policy to 'Require DoH' or 'Allow DoH' for compatible resolvers.",
                        setting_path=f"{_DNS_BASE} -> {pol.name}",
                        current_value=f"{pol.name}: Disabled",
                        expected_value="Enabled (DoH required or allowed)",
                    )

        # Also check registry items for DNS settings
        for item in gpo.registry_items:
            key_full = f"{item.key}\\{item.value_name}".lower()

            # DNS-001: mDNS via registry
            if "dnsclient" in key_full and "enablemulticast" in key_full:
                if item.value_data == "1":
                    yield Finding(
                        gpo_name=gpo.name, gpo_guid=gpo.guid,
                        rule_id="DNS-001", category=self.category,
                        severity=Severity.MEDIUM,
                        title="Multicast DNS (mDNS) is explicitly enabled",
                        description="EnableMulticast is set to 1, keeping mDNS active.",
                        risk="mDNS enables network name resolution poisoning attacks similar to LLMNR.",
                        recommendation="Set EnableMulticast to 0 to disable mDNS.",
                        setting_path="HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient -> EnableMulticast",
                        current_value="EnableMulticast = 1 (Enabled)",
                        expected_value="EnableMulticast = 0 (Disabled)",
                    )

            # DNS-003: DoH via registry
            if "dnsclient" in key_full and "dohpolicy" in key_full:
                if item.value_data not in ("2", "3"):
                    yield Finding(
                        gpo_name=gpo.name, gpo_guid=gpo.guid,
                        rule_id="DNS-003", category=self.category,
                        severity=Severity.LOW,
                        title="DNS over HTTPS (DoH) is not enabled",
                        description=f"DoHPolicy is set to {item.value_data} (not requiring or allowing DoH).",
                        risk="DNS queries are sent in plaintext without DoH, exposing browsing activity.",
                        recommendation="Set DoHPolicy to 2 (require DoH) or 3 (allow DoH).",
                        setting_path="HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient -> DoHPolicy",
                        current_value=f"DoHPolicy = {item.value_data}",
                        expected_value="2 (Require DoH) or 3 (Allow DoH)",
                    )
