#!/usr/bin/env python3
"""GPO Security Auditor - Audit Group Policy Objects for vulnerabilities and misconfigurations."""

import argparse
import os
import subprocess
import sys

from colorama import init as colorama_init, Fore, Style

from engine.models import Severity
from engine.runner import run_audit
from output.password_mgr import generate_password, get_password
from output.pdf_report import generate_pdf
from output.csv_export import generate_csv_zip

SEVERITY_COLORS = {
    Severity.CRITICAL: Fore.RED + Style.BRIGHT,
    Severity.HIGH: Fore.YELLOW + Style.BRIGHT,
    Severity.MEDIUM: Fore.YELLOW,
    Severity.LOW: Fore.CYAN,
    Severity.INFO: Fore.WHITE + Style.DIM,
}


def main():
    colorama_init()

    parser = argparse.ArgumentParser(
        description="GPO Security Auditor - Audit GPO exports for vulnerabilities",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--zip", help="Path to GPO export ZIP file (required for CLI mode)")
    parser.add_argument("--web", action="store_true", help="Launch web interface")
    parser.add_argument("--port", type=int, default=5000, help="Web server port (default: 5000)")
    parser.add_argument("--output-dir", default="./reports", help="Output directory for reports (default: ./reports)")
    args = parser.parse_args()

    if not args.web and not args.zip:
        parser.error("--zip is required for CLI mode. Use --web to launch the web interface.")

    if args.zip and not os.path.exists(args.zip):
        print(f"{Fore.RED}Error: ZIP file not found: {args.zip}{Style.RESET_ALL}")
        sys.exit(1)

    # Generate password at startup
    password = generate_password()
    print(f"\n{Style.BRIGHT}{'='*60}")
    print(f"  GPO Security Auditor")
    print(f"  {Fore.CYAN}Created by NordicWolfSlaya1337{Style.RESET_ALL}")
    print(f"{Style.BRIGHT}{'='*60}{Style.RESET_ALL}")
    print(f"\n  {Fore.YELLOW}Report Password: {Style.BRIGHT}{password}{Style.RESET_ALL}")
    print(f"  {Fore.WHITE + Style.DIM}(Use this password to open PDF and CSV reports){Style.RESET_ALL}\n")

    if args.web:
        _run_web(args)
    else:
        _run_cli(args, password)


BRAVE_PATH = r"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe"


def _run_web(args):
    """Launch Flask web interface."""
    from web.server import app
    password = get_password()
    url = f"http://localhost:{args.port}"
    print(f"  {Fore.CYAN}Starting web interface on port {args.port}...{Style.RESET_ALL}")
    print(f"  {Fore.GREEN}Open: {url}{Style.RESET_ALL}\n")

    # Open in Brave if available, otherwise fall back to default browser
    if os.path.exists(BRAVE_PATH):
        subprocess.Popen([BRAVE_PATH, url])
    else:
        import webbrowser
        webbrowser.open(url)

    import logging
    logging.getLogger("werkzeug").setLevel(logging.ERROR)
    app.run(host="0.0.0.0", port=args.port, debug=False, use_reloader=False)


def _run_cli(args, password):
    """Run audit in CLI mode with colored output."""
    os.makedirs(args.output_dir, exist_ok=True)

    def progress_callback(pct, msg, finding=None, **kwargs):
        if finding:
            sev = finding.severity
            color = SEVERITY_COLORS.get(sev, "")
            print(f"  {color}[{sev.value:8s}]{Style.RESET_ALL} {finding.title}")
            print(f"             {Fore.WHITE + Style.DIM}GPO: {finding.gpo_name}{Style.RESET_ALL}")
        elif pct in (0, 5, 10, 80, 90, 95, 100) or "Auditing GPO:" not in msg:
            print(f"  [{pct:3d}%] {msg}")

    print(f"  Scanning: {args.zip}\n")
    report = run_audit(args.zip, progress_callback)

    # Print summary
    counts = report.severity_counts
    print(f"\n{Style.BRIGHT}{'='*60}")
    print(f"  AUDIT RESULTS")
    print(f"{'='*60}{Style.RESET_ALL}\n")
    print(f"  Domain:     {report.domain}")
    print(f"  GPOs:       {report.total_gpos}")
    print(f"  Risk Score: {_colored_score(report.risk_score)} ({report.risk_label})")
    print()
    print(f"  {Fore.RED + Style.BRIGHT}Critical: {counts[Severity.CRITICAL]:<5}{Style.RESET_ALL}"
          f"  {Fore.YELLOW + Style.BRIGHT}High: {counts[Severity.HIGH]:<5}{Style.RESET_ALL}"
          f"  {Fore.YELLOW}Medium: {counts[Severity.MEDIUM]:<5}{Style.RESET_ALL}"
          f"  {Fore.CYAN}Low: {counts[Severity.LOW]:<5}{Style.RESET_ALL}"
          f"  {Style.DIM}Info: {counts[Severity.INFO]}{Style.RESET_ALL}")
    print()

    # Generate outputs
    pdf_path = os.path.join(args.output_dir, "gpo_audit_report.pdf")
    csv_path = os.path.join(args.output_dir, "gpo_audit_findings.zip")

    print(f"  Generating PDF report... ", end="", flush=True)
    generate_pdf(report, pdf_path, password)
    print(f"{Fore.GREEN}Done{Style.RESET_ALL} -> {pdf_path}")

    print(f"  Generating CSV export... ", end="", flush=True)
    generate_csv_zip(report, csv_path, password)
    print(f"{Fore.GREEN}Done{Style.RESET_ALL} -> {csv_path}")

    # Save password.txt alongside reports
    pw_path = os.path.join(args.output_dir, "password.txt")
    with open(pw_path, "w") as f:
        f.write(password)
    print(f"  Password saved to: {pw_path}")

    print(f"\n  {Fore.YELLOW}Password: {Style.BRIGHT}{password}{Style.RESET_ALL}")
    print(f"  {Style.DIM}(CSV ZIP requires 7-Zip or WinZip to open - AES-256 encrypted){Style.RESET_ALL}")
    print()


def _colored_score(score):
    if score < 40:
        return f"{Fore.RED + Style.BRIGHT}{score}/100{Style.RESET_ALL}"
    elif score < 60:
        return f"{Fore.YELLOW + Style.BRIGHT}{score}/100{Style.RESET_ALL}"
    elif score < 80:
        return f"{Fore.YELLOW}{score}/100{Style.RESET_ALL}"
    else:
        return f"{Fore.GREEN}{score}/100{Style.RESET_ALL}"


if __name__ == "__main__":
    main()
