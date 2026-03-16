import csv
import io

import pyzipper

from engine.models import AuditReport


def generate_csv_zip(report: AuditReport, output_path: str, password: str):
    """Generate a password-protected ZIP containing findings CSVs."""
    pwd_bytes = password.encode("utf-8")

    with pyzipper.AESZipFile(
        output_path, "w",
        compression=pyzipper.ZIP_DEFLATED,
        encryption=pyzipper.WZ_AES,
    ) as zf:
        zf.setpassword(pwd_bytes)

        # findings.csv
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow([
            "Rule ID", "Severity", "Category", "GPO Name", "GPO GUID",
            "Title", "Description", "Risk", "Recommendation",
            "Setting Path", "Current Value", "Expected Value",
            "Confidence", "Applies To", "Architecture Fix",
        ])
        for f in report.findings:
            writer.writerow([
                f.rule_id, f.severity.value, f.category, f.gpo_name, f.gpo_guid,
                f.title, f.description, f.risk, f.recommendation,
                f.setting_path, f.current_value, f.expected_value,
                f.confidence, f.applies_to, f.architecture_fix,
            ])
        zf.writestr("findings.csv", buf.getvalue().encode("utf-8-sig"))

        # gpo_inventory.csv
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow([
            "GPO Name", "GUID", "Domain", "Status", "Created", "Modified",
            "Linked OUs", "Computer Enabled", "User Enabled",
            "Settings Count",
        ])
        for g in report.gpos:
            linked = "; ".join(link.som_path for link in g.links if link.enabled)
            settings_count = (
                len(g.account_settings) + len(g.audit_settings) +
                len(g.user_rights) + len(g.security_options) +
                len(g.registry_policies) + len(g.registry_items) +
                len(g.firewall_rules)
            )
            writer.writerow([
                g.name, g.guid, g.domain, g.gpo_status,
                g.created_time.strftime("%Y-%m-%d") if g.created_time else "",
                g.modified_time.strftime("%Y-%m-%d") if g.modified_time else "",
                linked, g.computer_enabled, g.user_enabled,
                settings_count,
            ])
        zf.writestr("gpo_inventory.csv", buf.getvalue().encode("utf-8-sig"))
