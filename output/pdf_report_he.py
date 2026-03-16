"""Hebrew PDF report generation — thin wrapper around the locale-aware generate_pdf."""

from engine.models import AuditReport
from output.pdf_report import generate_pdf


def generate_hebrew_pdf(report: AuditReport, output_path: str, password: str):
    """Generate a Hebrew RTL PDF report with the same design as the English version."""
    generate_pdf(report, output_path, password, locale="he")
