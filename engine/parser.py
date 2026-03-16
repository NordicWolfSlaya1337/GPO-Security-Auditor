import csv
import io
import zipfile
from datetime import datetime
from typing import Optional

import defusedxml.ElementTree as ET

from engine.models import (
    GPO, GPOLink, AccountSetting, AuditSetting, UserRightsAssignment,
    SecurityOption, RegistryPolicy, RegistryItem, FirewallProfile, FirewallRule,
    ScriptEntry, RestrictedGroup, PreferenceItem,
)

# XML namespaces used in GPO reports
NS = {
    "gp": "http://www.microsoft.com/GroupPolicy/Settings",
    "types": "http://www.microsoft.com/GroupPolicy/Types",
    "sec_types": "http://www.microsoft.com/GroupPolicy/Types/Security",
    "security": "http://www.microsoft.com/GroupPolicy/Settings/Security",
    "audit": "http://www.microsoft.com/GroupPolicy/Settings/Auditing",
    "firewall": "http://www.microsoft.com/GroupPolicy/Settings/WindowsFirewall",
    "registry": "http://www.microsoft.com/GroupPolicy/Settings/Registry",
    "pubkey": "http://www.microsoft.com/GroupPolicy/Settings/PublicKey",
    "scripts": "http://www.microsoft.com/GroupPolicy/Settings/Scripts",
    "xsi": "http://www.w3.org/2001/XMLSchema-instance",
}


def parse_zip(zip_path: str) -> list:
    gpos = []
    csv_data = {}

    with zipfile.ZipFile(zip_path, "r") as zf:
        # First pass: look for CSV
        for name in zf.namelist():
            if name.lower().endswith(".csv"):
                try:
                    raw = zf.read(name)
                    csv_data = _parse_csv(raw)
                except Exception:
                    pass

        # Second pass: parse all XML files
        for name in zf.namelist():
            if not name.lower().endswith(".xml"):
                continue
            try:
                raw = zf.read(name)
                gpo = parse_gpo_xml(raw, name)
                if gpo:
                    # Supplement with CSV data
                    if gpo.name in csv_data:
                        gpo.gpo_status = csv_data[gpo.name].get("status", "")
                    gpos.append(gpo)
            except Exception as e:
                print(f"  [!] Failed to parse {name}: {e}")

    return gpos


def _parse_csv(raw: bytes) -> dict:
    """Parse GPO_OU_Links.csv -> {gpo_name: {status, links}}"""
    result = {}
    # Try common encodings
    text = None
    for enc in ("utf-8-sig", "utf-16", "utf-8", "latin-1"):
        try:
            text = raw.decode(enc)
            break
        except (UnicodeDecodeError, UnicodeError):
            continue
    if not text:
        return result

    reader = csv.DictReader(io.StringIO(text))
    for row in reader:
        name = row.get("GPOName", "").strip()
        if not name:
            continue
        if name not in result:
            result[name] = {"status": row.get("GPOStatus", ""), "links": []}
        result[name]["links"].append({
            "ou": row.get("LinkedOU", ""),
            "enabled": row.get("LinkEnabled", "").lower() == "true",
        })
    return result


def parse_gpo_xml(raw: bytes, filename: str = "") -> Optional[GPO]:
    """Parse a single GPO XML report into a GPO object."""
    # Handle UTF-16 encoding
    text = None
    for enc in ("utf-16", "utf-8-sig", "utf-8", "latin-1"):
        try:
            text = raw.decode(enc)
            break
        except (UnicodeDecodeError, UnicodeError):
            continue
    if not text:
        return None

    # Fix encoding declaration mismatch: XML says utf-16 but we re-encoded to utf-8
    import re
    text = re.sub(r'<\?xml[^?]*\?>', '<?xml version="1.0" encoding="utf-8"?>', text, count=1)

    # Parse XML
    root = ET.fromstring(text.encode("utf-8"))

    # Basic metadata
    name = _text(root, "gp:Name") or filename.replace(".xml", "")
    guid = _text(root, "gp:Identifier/types:Identifier") or ""
    domain = _text(root, "gp:Identifier/types:Domain") or ""

    gpo = GPO(name=name, guid=guid, domain=domain)
    gpo.description = _text(root, "gp:Comment") or ""
    gpo.created_time = _parse_dt(_text(root, "gp:CreatedTime"))
    gpo.modified_time = _parse_dt(_text(root, "gp:ModifiedTime"))
    gpo.read_time = _parse_dt(_text(root, "gp:ReadTime"))

    # SDDL
    sddl_el = root.find(".//sec_types:SDDL/sec_types:InheritableSDDL", NS)
    if sddl_el is not None and sddl_el.text:
        gpo.sddl = sddl_el.text.strip()
    else:
        sddl_el = root.find(".//sec_types:SDDL", NS)
        if sddl_el is not None and sddl_el.text:
            gpo.sddl = sddl_el.text.strip()

    # Permissions
    for tp in root.findall(".//sec_types:TrusteePermissions", NS):
        perm = _parse_trustee_permission(tp)
        if perm:
            gpo.permissions.append(perm)

    # Computer section
    comp = root.find("gp:Computer", NS)
    if comp is not None:
        gpo.computer_enabled = _text(comp, "gp:Enabled") == "true"
        gpo.computer_version_directory = _int(_text(comp, "gp:VersionDirectory"))
        gpo.computer_version_sysvol = _int(_text(comp, "gp:VersionSysvol"))
        _parse_extensions(comp, gpo)

    # User section
    user = root.find("gp:User", NS)
    if user is not None:
        gpo.user_enabled = _text(user, "gp:Enabled") == "true"
        gpo.user_version_directory = _int(_text(user, "gp:VersionDirectory"))
        gpo.user_version_sysvol = _int(_text(user, "gp:VersionSysvol"))
        _parse_extensions(user, gpo)

    # Links
    for link_el in root.findall("gp:LinksTo", NS):
        link = GPOLink(
            som_name=_text(link_el, "gp:SOMName") or "",
            som_path=_text(link_el, "gp:SOMPath") or "",
            enabled=_text(link_el, "gp:Enabled") == "true",
            no_override=_text(link_el, "gp:NoOverride") == "true",
        )
        gpo.links.append(link)

    # Infer gpo_status from XML if not set by CSV
    if not gpo.gpo_status:
        if gpo.computer_enabled and gpo.user_enabled:
            gpo.gpo_status = "AllSettingsEnabled"
        elif not gpo.computer_enabled and not gpo.user_enabled:
            gpo.gpo_status = "AllSettingsDisabled"
        elif not gpo.computer_enabled:
            gpo.gpo_status = "ComputerSettingsDisabled"
        else:
            gpo.gpo_status = "UserSettingsDisabled"

    return gpo


def _parse_extensions(section, gpo: GPO):
    """Parse all ExtensionData/Extension elements in a Computer or User section."""
    for ext in section.findall(".//gp:ExtensionData/gp:Extension", NS):
        xsi_type = ext.get(f"{{{NS['xsi']}}}type", "")

        # Security Settings (Account, Audit, UserRights, SecurityOptions)
        if "SecuritySettings" in xsi_type:
            _parse_security_settings(ext, gpo)

        # Advanced Audit Settings
        elif "AuditSettings" in xsi_type:
            _parse_advanced_audit(ext, gpo)

        # Windows Firewall
        elif "WindowsFirewallSettings" in xsi_type:
            _parse_firewall(ext, gpo)

        # Registry (admin templates + GPP registry items)
        elif "RegistrySettings" in xsi_type:
            _parse_registry(ext, gpo)

        # Scripts (logon/logoff/startup/shutdown)
        elif "Scripts" in xsi_type:
            _parse_scripts(ext, gpo)

        # All other extensions: scan for GPP cpassword and preference items
        else:
            _parse_gpp_preferences(ext, gpo)


def _parse_security_settings(ext, gpo: GPO):
    """Parse SecuritySettings extension: Account, Audit, UserRights, SecurityOptions."""
    # Account settings (password, lockout, kerberos)
    for acc in ext.findall("security:Account", NS):
        name = _text(acc, "security:Name") or ""
        stype = _text(acc, "security:Type") or ""
        setting = AccountSetting(name=name, setting_type=stype)
        num = _text(acc, "security:SettingNumber")
        if num is not None:
            try:
                setting.value_number = int(num)
            except ValueError:
                pass
        bval = _text(acc, "security:SettingBoolean")
        if bval is not None:
            setting.value_boolean = bval.lower() == "true"
        gpo.account_settings.append(setting)

    # Legacy audit settings
    for aud in ext.findall("security:Audit", NS):
        name = _text(aud, "security:Name") or ""
        setting = AuditSetting(
            name=name,
            success_attempts=_text(aud, "security:SuccessAttempts") == "true",
            failure_attempts=_text(aud, "security:FailureAttempts") == "true",
        )
        gpo.audit_settings.append(setting)

    # User rights assignments
    for ura in ext.findall("security:UserRightsAssignment", NS):
        name = _text(ura, "security:Name") or ""
        members = []
        for member in ura.findall("security:Member", NS):
            sid = _text(member, "types:SID") or ""
            mname = _text(member, "types:Name") or ""
            members.append({"sid": sid, "name": mname})
        gpo.user_rights.append(UserRightsAssignment(name=name, members=members))

    # Security options
    for so in ext.findall("security:SecurityOptions", NS):
        key_name = _text(so, "security:KeyName") or ""
        opt = SecurityOption(key_name=key_name)
        num = _text(so, "security:SettingNumber")
        if num is not None:
            try:
                opt.setting_number = int(num)
            except ValueError:
                pass
        opt.setting_string = _text(so, "security:SettingString")
        display = so.find("security:Display", NS)
        if display is not None:
            opt.display_name = _text(display, "security:Name") or ""
            opt.display_string = _text(display, "security:DisplayString") or ""
            dnum = _text(display, "security:DisplayNumber")
            if dnum:
                try:
                    opt.setting_number = opt.setting_number or int(dnum)
                except ValueError:
                    pass
            dbool = _text(display, "security:DisplayBoolean")
            if dbool is not None:
                opt.display_boolean = dbool.lower() == "true"
        gpo.security_options.append(opt)

    # Restricted Groups
    for rg in ext.findall("security:RestrictedGroups", NS):
        group_name = _text(rg, "security:GroupName") or ""
        if not group_name:
            continue
        members = []
        for member in rg.findall("security:Member", NS):
            sid = _text(member, "types:SID") or ""
            mname = _text(member, "types:Name") or ""
            members.append({"sid": sid, "name": mname})
        member_of = []
        for mo in rg.findall("security:MemberOf", NS):
            sid = _text(mo, "types:SID") or ""
            mname = _text(mo, "types:Name") or ""
            member_of.append({"sid": sid, "name": mname})
        gpo.restricted_groups.append(RestrictedGroup(
            group_name=group_name, members=members, member_of=member_of
        ))


def _parse_advanced_audit(ext, gpo: GPO):
    """Parse Advanced Audit Configuration subcategories."""
    for asetting in ext.findall("audit:AuditSetting", NS):
        subcat = _text(asetting, "audit:SubcategoryName") or ""
        val_str = _text(asetting, "audit:SettingValue") or "0"
        try:
            val = int(val_str)
        except ValueError:
            val = 0
        setting = AuditSetting(
            name=subcat,
            success_attempts=(val & 1) != 0,
            failure_attempts=(val & 2) != 0,
        )
        gpo.audit_settings.append(setting)


def _parse_firewall(ext, gpo: GPO):
    """Parse WindowsFirewallSettings: profiles and inbound rules."""
    # Domain/Standard/Public profiles
    for profile_name in ("DomainProfile", "PrivateProfile", "PublicProfile"):
        profile_el = ext.find(f"firewall:{profile_name}", NS)
        if profile_el is not None:
            fp = FirewallProfile(name=profile_name.replace("Profile", ""))
            enabled_el = profile_el.find("firewall:EnableFirewall", NS)
            if enabled_el is not None:
                val = _text(enabled_el, "firewall:Value")
                fp.enabled = val == "true" if val else None
            default_in = profile_el.find("firewall:DefaultInboundAction", NS)
            if default_in is not None:
                fp.default_inbound = _text(default_in, "firewall:Value") or ""
            default_out = profile_el.find("firewall:DefaultOutboundAction", NS)
            if default_out is not None:
                fp.default_outbound = _text(default_out, "firewall:Value") or ""
            gpo.firewall_profiles.append(fp)

    # Inbound firewall rules
    for rule_el in ext.findall("firewall:InboundFirewallRules", NS):
        rule = FirewallRule(
            name=_text(rule_el, "firewall:Name") or "",
            direction="In",
            action=_text(rule_el, "firewall:Action") or "",
            protocol=_text(rule_el, "firewall:Protocol") or "",
            local_port=_text(rule_el, "firewall:LPort") or "",
            remote_port=_text(rule_el, "firewall:RPort") or "",
            remote_address=_text(rule_el, "firewall:RA4") or _text(rule_el, "firewall:RA6") or "",
            program=_text(rule_el, "firewall:App") or "",
            enabled=_text(rule_el, "firewall:Active") != "false",
        )
        gpo.firewall_rules.append(rule)

    # Outbound firewall rules
    for rule_el in ext.findall("firewall:OutboundFirewallRules", NS):
        rule = FirewallRule(
            name=_text(rule_el, "firewall:Name") or "",
            direction="Out",
            action=_text(rule_el, "firewall:Action") or "",
            protocol=_text(rule_el, "firewall:Protocol") or "",
            local_port=_text(rule_el, "firewall:LPort") or "",
            remote_port=_text(rule_el, "firewall:RPort") or "",
            remote_address=_text(rule_el, "firewall:RA4") or _text(rule_el, "firewall:RA6") or "",
            program=_text(rule_el, "firewall:App") or "",
            enabled=_text(rule_el, "firewall:Active") != "false",
        )
        gpo.firewall_rules.append(rule)


def _parse_registry(ext, gpo: GPO):
    """Parse Registry settings: Administrative Template policies and GPP registry items."""
    # Administrative Template policies (q:Policy elements)
    for pol in ext.findall("registry:Policy", NS):
        name = _text(pol, "registry:Name") or ""
        state = _text(pol, "registry:State") or ""
        category = _text(pol, "registry:Category") or ""
        explain = _text(pol, "registry:Explain") or ""
        values = {}
        # Some policies have sub-elements like DropDownList, Numeric, EditText, etc.
        for child in pol:
            tag = child.tag.split("}")[-1] if "}" in child.tag else child.tag
            if tag in ("Name", "State", "Category", "Explain", "Supported"):
                continue
            val_name = child.get("Name", tag)
            val_state = child.get("State", "")
            if child.text:
                values[val_name] = child.text.strip()
            elif val_state:
                values[val_name] = val_state
        gpo.registry_policies.append(RegistryPolicy(
            name=name, state=state, category=category, explain=explain, values=values
        ))

    # GPP-style direct registry items
    for rs in ext.findall("registry:RegistrySetting", NS):
        key_path = _text(rs, "registry:KeyPath") or ""
        val_name = _text(rs, "registry:ValueName") or ""
        # These are simple registry pointers, store as RegistryItem
        if key_path:
            gpo.registry_items.append(RegistryItem(
                hive="HKLM",  # Most GPP settings target HKLM
                key=key_path,
                value_name=val_name,
                value_type=_text(rs, "registry:ValueType") or "",
                value_data=_text(rs, "registry:Value") or "",
            ))


def _parse_scripts(ext, gpo: GPO):
    """Parse Scripts extension: logon/logoff/startup/shutdown scripts."""
    for script in ext.findall("scripts:Script", NS):
        command = _text(script, "scripts:Command") or ""
        parameters = _text(script, "scripts:Parameters") or ""
        stype = _text(script, "scripts:Type") or ""
        order_str = _text(script, "scripts:Order") or "0"
        try:
            order = int(order_str)
        except ValueError:
            order = 0
        if command:
            gpo.script_entries.append(ScriptEntry(
                command=command, parameters=parameters,
                script_type=stype, order=order,
            ))
    # Also look for script commands in non-namespaced elements
    for elem in ext.iter():
        tag = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
        if tag == "Command" and elem.text and elem.text.strip():
            cmd = elem.text.strip()
            # Avoid duplicates from the namespaced parse above
            if not any(s.command == cmd for s in gpo.script_entries):
                gpo.script_entries.append(ScriptEntry(command=cmd))


def _parse_gpp_preferences(ext, gpo: GPO):
    """Scan GPP extension for cpassword and embedded credentials."""
    for elem in ext.iter():
        attrib = elem.attrib
        # Check for cpassword attribute (MS14-025)
        cpassword = attrib.get("cpassword", "")
        if cpassword:
            tag = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
            parent_tag = ""
            # Try to get parent context
            name = attrib.get("name", attrib.get("Name", tag))
            gpo.preference_items.append(PreferenceItem(
                item_type=tag,
                name=name,
                properties=dict(attrib),
                cpassword=cpassword,
            ))

        # Check for username/password in properties (scheduled tasks, services, etc.)
        username = attrib.get("runAs", attrib.get("accountName", attrib.get("userName", "")))
        password = attrib.get("password", attrib.get("cpassword", ""))
        if username and password:
            tag = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
            name = attrib.get("name", attrib.get("Name", tag))
            if not any(p.name == name and p.item_type == tag for p in gpo.preference_items):
                gpo.preference_items.append(PreferenceItem(
                    item_type=tag,
                    name=name,
                    properties=dict(attrib),
                    cpassword=password,
                ))

        # Capture LocalGroup preference items for local admin analysis
        tag = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
        if tag in ("Group", "LocalGroup") and attrib.get("name"):
            members = []
            for member_el in elem.iter():
                mtag = member_el.tag.split("}")[-1] if "}" in member_el.tag else member_el.tag
                if mtag == "Member":
                    members.append({
                        "name": member_el.attrib.get("name", ""),
                        "action": member_el.attrib.get("action", ""),
                        "sid": member_el.attrib.get("sid", ""),
                    })
            if members:
                gpo.preference_items.append(PreferenceItem(
                    item_type="LocalGroup",
                    name=attrib.get("name", ""),
                    properties={"members": members},
                ))


def _parse_trustee_permission(tp):
    """Parse a TrusteePermissions element."""
    trustee = tp.find("sec_types:Trustee", NS)
    if trustee is None:
        return None
    sid = _text(trustee, "types:SID") or ""
    name = _text(trustee, "types:Name") or ""
    ptype_el = tp.find("sec_types:Type", NS)
    ptype = ptype_el.text.strip() if ptype_el is not None and ptype_el.text else ""
    standard = tp.find("sec_types:Standard", NS)
    access = ""
    if standard is not None:
        access_el = standard.find("sec_types:GPOGroupedAccessEnum", NS)
        if access_el is not None and access_el.text:
            access = access_el.text.strip()
    return {"sid": sid, "name": name, "type": ptype, "access": access}


# --- helpers ---

def _text(el, path: str) -> Optional[str]:
    """Find a child element by namespace-prefixed path and return its text."""
    child = el.find(path, NS)
    if child is not None and child.text:
        return child.text.strip()
    return None


def _int(val) -> int:
    if val is None:
        return 0
    try:
        return int(val)
    except (ValueError, TypeError):
        return 0


def _parse_dt(val) -> Optional[datetime]:
    if not val:
        return None
    try:
        # Handle ISO 8601 format with Z suffix
        val = val.replace("Z", "+00:00")
        return datetime.fromisoformat(val)
    except (ValueError, TypeError):
        return None
