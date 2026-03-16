"""AI Chat Assistant — Ollama-powered chatbot for GPO audit data Q&A."""

import json
import os
import time
from datetime import datetime, timezone, timedelta
from typing import Optional, Generator

import requests

from engine.models import AuditReport, Severity

OLLAMA_BASE = "http://localhost:11434"
CHAT_DIR = os.path.join(os.path.dirname(__file__), "..", "chat_sessions")
TTL_SECONDS = 2 * 24 * 3600  # 2 days

os.makedirs(CHAT_DIR, exist_ok=True)


def check_ollama_available() -> bool:
    try:
        r = requests.get(f"{OLLAMA_BASE}/api/tags", timeout=3)
        return r.status_code == 200
    except Exception:
        return False


def get_available_model() -> Optional[str]:
    """Auto-detect first available model from Ollama."""
    try:
        r = requests.get(f"{OLLAMA_BASE}/api/tags", timeout=5)
        r.raise_for_status()
        models = r.json().get("models", [])
        if not models:
            return None
        for m in models:
            if "llama" in m.get("name", "").lower():
                return m["name"]
        return models[0]["name"]
    except Exception:
        return None


def build_report_context(report: AuditReport) -> str:
    """Serialize audit data into structured text for the LLM system prompt."""
    lines = []
    counts = report.severity_counts

    # Header
    lines.append(f"DOMAIN: {report.domain}")
    lines.append(f"SCAN TIME: {report.scan_time.strftime('%Y-%m-%d %H:%M UTC')}")
    lines.append(f"TOTAL GPOs: {report.total_gpos}")
    lines.append(f"RISK SCORE: {report.risk_score}/100 ({report.risk_label})")
    lines.append(
        f"SEVERITY COUNTS: Critical={counts.get(Severity.CRITICAL, 0)}, "
        f"High={counts.get(Severity.HIGH, 0)}, "
        f"Medium={counts.get(Severity.MEDIUM, 0)}, "
        f"Low={counts.get(Severity.LOW, 0)}, "
        f"Info={counts.get(Severity.INFO, 0)}"
    )
    lines.append("")

    # Findings
    lines.append(f"=== FINDINGS ({len(report.findings)} total) ===")
    for f in report.findings:
        lines.append(f"[{f.rule_id}] {f.severity.value.upper()} | {f.category} | GPO: \"{f.gpo_name}\"")
        lines.append(f"  Title: {f.title}")
        if f.current_value or f.expected_value:
            lines.append(f"  Current: {f.current_value or 'N/A'} | Expected: {f.expected_value or 'N/A'}")
        lines.append(f"  Risk: {f.risk}")
        lines.append(f"  Recommendation: {f.recommendation}")
        if f.applies_to:
            lines.append(f"  Applies To: {f.applies_to}")
        if f.architecture_fix:
            lines.append(f"  Fix Strategy: {f.architecture_fix}")
        lines.append("---")
    lines.append("")

    # GPO Inventory
    lines.append(f"=== GPO INVENTORY ({report.total_gpos} total) ===")
    for g in sorted(report.gpos, key=lambda x: x.name.lower()):
        linked = ", ".join(l.som_path for l in g.links if l.enabled) or "UNLINKED"
        status_parts = []
        if g.is_empty:
            status_parts.append("EMPTY")
        if not g.has_enabled_links:
            status_parts.append("NO ACTIVE LINKS")
        status_str = f" ({', '.join(status_parts)})" if status_parts else ""
        settings_count = (
            len(g.account_settings) + len(g.audit_settings) +
            len(g.user_rights) + len(g.security_options) +
            len(g.registry_policies) + len(g.registry_items) +
            len(g.firewall_rules)
        )
        modified = g.modified_time.strftime("%Y-%m-%d") if g.modified_time else "N/A"
        lines.append(
            f"- \"{g.name}\" {{{g.guid}}} linked=[{linked}] "
            f"settings={settings_count} modified={modified}{status_str}"
        )

    return "\n".join(lines)


SYSTEM_PROMPT_TEMPLATE = (
    "You are a GPO security audit assistant with deep expertise in Active Directory, "
    "Group Policy, and Windows security. You have been provided with the complete "
    "results of a GPO security audit below.\n\n"
    "Answer questions about the findings, risks, and GPO configurations. "
    "Be specific — reference actual GPO names, rule IDs, and settings. When asked "
    "for remediation, provide actionable PowerShell commands or Group Policy Management "
    "Console (GPMC) instructions.\n\n"
    "If asked about something not covered in the audit data, say so clearly.\n\n"
    "[AUDIT DATA]\n{context}\n[END AUDIT DATA]"
)


def _session_path(job_id: str) -> str:
    return os.path.join(CHAT_DIR, f"{job_id}.json")


def save_session(job_id: str, messages: list, report_context: str):
    """Persist chat session to disk."""
    data = {
        "job_id": job_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "report_context": report_context,
        "messages": messages,
    }
    path = _session_path(job_id)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def load_session(job_id: str) -> Optional[dict]:
    """Load a chat session from disk. Returns None if missing or expired."""
    path = _session_path(job_id)
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        # Check TTL
        created = datetime.fromisoformat(data.get("created_at", ""))
        if datetime.now(timezone.utc) - created > timedelta(seconds=TTL_SECONDS):
            os.remove(path)
            return None
        return data
    except Exception:
        return None


def cleanup_old_sessions():
    """Delete chat session files older than 2 days."""
    if not os.path.isdir(CHAT_DIR):
        return
    now = time.time()
    for fname in os.listdir(CHAT_DIR):
        if not fname.endswith(".json"):
            continue
        fpath = os.path.join(CHAT_DIR, fname)
        try:
            if now - os.path.getmtime(fpath) > TTL_SECONDS:
                os.remove(fpath)
        except OSError:
            pass


def stream_chat_response(
    job_id: str,
    user_message: str,
    report: Optional[AuditReport] = None,
) -> Generator[str, None, None]:
    """Stream a chat response from Ollama.

    Yields JSON strings: {"type": "token", "content": "..."} or {"type": "error/done", ...}
    """
    model = get_available_model()
    if not model:
        yield json.dumps({"type": "error", "content": "No model found in Ollama. Run 'ollama pull llama3.2' to download one."})
        return

    # Load or create session
    session = load_session(job_id)
    if session:
        messages = session.get("messages", [])
        report_context = session.get("report_context", "")
    else:
        messages = []
        report_context = ""

    # Build report context if not yet available
    if not report_context and report:
        report_context = build_report_context(report)

    if not report_context:
        yield json.dumps({"type": "error", "content": "No audit data available for this session."})
        return

    # Add user message
    now_str = datetime.now(timezone.utc).isoformat()
    messages.append({"role": "user", "content": user_message, "timestamp": now_str})

    # Build Ollama messages
    system_prompt = SYSTEM_PROMPT_TEMPLATE.format(context=report_context)
    ollama_messages = [{"role": "system", "content": system_prompt}]
    for m in messages:
        ollama_messages.append({"role": m["role"], "content": m["content"]})

    # Stream from Ollama
    full_response = ""
    try:
        r = requests.post(
            f"{OLLAMA_BASE}/api/chat",
            json={
                "model": model,
                "messages": ollama_messages,
                "stream": True,
                "options": {"num_predict": -1, "num_ctx": 32768},
            },
            stream=True,
            timeout=300,
        )
        r.raise_for_status()

        for line in r.iter_lines():
            if not line:
                continue
            try:
                chunk = json.loads(line)
                if chunk.get("done"):
                    break
                token = chunk.get("message", {}).get("content", "")
                if token:
                    full_response += token
                    yield json.dumps({"type": "token", "content": token})
            except json.JSONDecodeError:
                continue

    except requests.ConnectionError:
        yield json.dumps({"type": "error", "content": "Could not connect to Ollama at localhost:11434. Make sure Ollama is running."})
        # Remove the user message we just added since the exchange failed
        messages.pop()
        return
    except requests.Timeout:
        yield json.dumps({"type": "error", "content": "Ollama response timed out."})
        messages.pop()
        return
    except Exception as e:
        yield json.dumps({"type": "error", "content": f"Error communicating with Ollama: {str(e)}"})
        messages.pop()
        return

    # Save assistant response
    if full_response:
        messages.append({
            "role": "assistant",
            "content": full_response,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        save_session(job_id, messages, report_context)

    yield json.dumps({"type": "done"})


# Cleanup old sessions on import
cleanup_old_sessions()
