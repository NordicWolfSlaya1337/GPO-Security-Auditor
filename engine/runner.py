from datetime import datetime, timezone
from typing import Optional, Callable

from engine.models import AuditReport, Finding
from engine.parser import parse_zip
from engine.rules.base import get_all_rules


def run_audit(
    zip_path: str,
    progress_callback: Optional[Callable] = None,
) -> AuditReport:
    """
    Run full GPO security audit.

    progress_callback(percent: int, message: str, finding: Optional[Finding])
    """
    def emit(pct, msg, finding=None):
        if progress_callback:
            progress_callback(pct, msg, finding)

    emit(0, "Starting GPO audit...")

    # Phase 1: Parse ZIP
    emit(5, "Parsing GPO export ZIP file...")
    gpos = parse_zip(zip_path)
    if not gpos:
        emit(100, "No GPOs found in ZIP file.")
        return AuditReport(
            domain="Unknown", scan_time=datetime.now(timezone.utc),
            total_gpos=0, gpos=[]
        )

    domain = gpos[0].domain or "Unknown"
    emit(10, f"Parsed {len(gpos)} GPOs from domain '{domain}'")

    # Phase 2: Run audit rules
    rules = get_all_rules()
    findings = []
    total_gpos = len(gpos)

    for i, gpo in enumerate(gpos):
        pct = 10 + int((i / total_gpos) * 70)  # 10-80%
        emit(pct, f"Auditing GPO: {gpo.name}")

        for rule in rules:
            try:
                for finding in rule.evaluate(gpo, gpos):
                    findings.append(finding)
                    emit(pct, f"[{finding.severity.value}] {finding.title}", finding=finding)
            except Exception as e:
                print(f"  [!] Rule {rule.rule_id_prefix} failed on '{gpo.name}': {e}")

    emit(90, f"Audit complete. {len(findings)} findings.")

    # Build report
    report = AuditReport(
        domain=domain,
        scan_time=datetime.now(timezone.utc),
        total_gpos=total_gpos,
        findings=sorted(findings, key=lambda f: [
            "Critical", "High", "Medium", "Low", "Info"
        ].index(f.severity.value)),
        gpos=gpos,
    )

    emit(95, "Generating outputs...")
    return report
