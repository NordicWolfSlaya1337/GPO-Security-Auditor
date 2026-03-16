"""Local LLaMA translation via Ollama — translates audit reports to Hebrew."""

import copy
import json
import re
from typing import Optional, Callable

import requests

from engine.models import AuditReport

OLLAMA_BASE = "http://localhost:11434"
_model_cache: Optional[str] = None


def check_ollama_available() -> bool:
    """Return True if Ollama is reachable."""
    try:
        r = requests.get(f"{OLLAMA_BASE}/api/tags", timeout=3)
        return r.status_code == 200
    except Exception:
        return False


def get_available_model() -> Optional[str]:
    """Auto-detect first available model from Ollama."""
    global _model_cache
    if _model_cache:
        return _model_cache
    try:
        r = requests.get(f"{OLLAMA_BASE}/api/tags", timeout=5)
        r.raise_for_status()
        models = r.json().get("models", [])
        if not models:
            return None
        # Prefer a model with "llama" in the name
        for m in models:
            if "llama" in m.get("name", "").lower():
                _model_cache = m["name"]
                return _model_cache
        _model_cache = models[0]["name"]
        return _model_cache
    except Exception:
        return None


SYSTEM_PROMPT = (
    "You are a professional Hebrew translator specializing in cybersecurity documentation. "
    "Translate the following text to Hebrew. Rules:\n"
    "1. Keep ALL technical terms in English: GPO, Group Policy, Active Directory, AD, "
    "Kerberos, NLA, RDP, NTLM, NTLMv2, LM, LAPS, AppLocker, SDDL, SYSVOL, LDAP, "
    "DNS, DHCP, SMB, WMI, PowerShell, BitLocker, Defender, UAC, SID, ACL, ACE, "
    "OU, DC, Domain Controller, Registry, Firewall, TCP, UDP, IP, SSL, TLS, AES, "
    "SHA, MD5, RADIUS, VPN, WSUS, GPResult, RSoP, cpassword, and any similar terms.\n"
    "2. Keep ALL identifiers in English: rule IDs (PWD-001, FW-002, etc.), "
    "GPO names, GUIDs, registry paths, file paths, setting names, values.\n"
    "3. Keep severity names in English: Critical, High, Medium, Low, Info.\n"
    "4. Produce natural, professional Hebrew prose — as a native Hebrew cybersecurity "
    "expert would write. Technical sentences should flow naturally in Hebrew with "
    "English terms embedded where appropriate.\n"
    "5. Output ONLY the translated text. No explanations, no notes, no prefixes."
)


def _translate_text(text: str, model: str) -> str:
    """Translate a single text field via Ollama."""
    if not text or not text.strip():
        return text

    try:
        r = requests.post(
            f"{OLLAMA_BASE}/api/generate",
            json={
                "model": model,
                "system": SYSTEM_PROMPT,
                "prompt": text,
                "stream": False,
                "options": {"num_predict": -1},
            },
            timeout=120,
        )
        r.raise_for_status()
        result = r.json().get("response", "").strip()

        # Validate: must contain at least one Hebrew character
        if result and _has_hebrew(result):
            return result
        # Retry once
        r2 = requests.post(
            f"{OLLAMA_BASE}/api/generate",
            json={
                "model": model,
                "system": SYSTEM_PROMPT,
                "prompt": f"Translate to Hebrew:\n{text}",
                "stream": False,
                "options": {"num_predict": -1},
            },
            timeout=120,
        )
        r2.raise_for_status()
        result2 = r2.json().get("response", "").strip()
        if result2 and _has_hebrew(result2):
            return result2

        return text  # Fall back to English
    except Exception:
        return text  # Fall back to English on any error


def _translate_batch(fields: dict, model: str) -> dict:
    """Batch-translate multiple short fields in one prompt.

    fields: {key: text, ...}
    Returns: {key: translated_text, ...}
    """
    if not fields:
        return fields

    keys = list(fields.keys())
    numbered = "\n".join(f"[{i+1}] {fields[k]}" for i, k in enumerate(keys))
    prompt = (
        f"Translate each numbered item to Hebrew. Keep the [N] markers in your output. "
        f"Output ONLY the translations, one per marker:\n\n{numbered}"
    )

    try:
        r = requests.post(
            f"{OLLAMA_BASE}/api/generate",
            json={
                "model": model,
                "system": SYSTEM_PROMPT,
                "prompt": prompt,
                "stream": False,
                "options": {"num_predict": -1},
            },
            timeout=180,
        )
        r.raise_for_status()
        response = r.json().get("response", "")

        # Parse numbered responses
        result = {}
        for i, key in enumerate(keys):
            marker = f"[{i+1}]"
            next_marker = f"[{i+2}]"
            start = response.find(marker)
            if start == -1:
                result[key] = fields[key]  # Fallback
                continue
            start += len(marker)
            end = response.find(next_marker, start) if i < len(keys) - 1 else len(response)
            if end == -1:
                end = len(response)
            translated = response[start:end].strip()
            if translated and _has_hebrew(translated):
                result[key] = translated
            else:
                result[key] = fields[key]
        return result
    except Exception:
        return dict(fields)  # Return originals on error


def _has_hebrew(text: str) -> bool:
    """Check if text contains any Hebrew characters."""
    return bool(re.search(r'[\u0590-\u05FF]', text))


def translate_report(
    report: AuditReport,
    progress_callback: Optional[Callable] = None,
) -> AuditReport:
    """Deep-copy report and translate all text fields to Hebrew.

    progress_callback(current: int, total: int) for UI updates.
    """
    model = get_available_model()
    if not model:
        raise RuntimeError("No model available in Ollama")

    he_report = copy.deepcopy(report)

    total = len(he_report.findings)
    current = 0

    # Translation cache for repeated strings (e.g., same category across findings)
    cache: dict[str, str] = {}

    def _cached_translate(text: str) -> str:
        if not text or not text.strip():
            return text
        if text in cache:
            return cache[text]
        result = _translate_text(text, model)
        cache[text] = result
        return result

    # Translate findings
    for finding in he_report.findings:
        current += 1
        if progress_callback:
            progress_callback(current, total)

        # Try batch for short fields
        short_fields = {}
        long_fields = []

        for attr in ("title", "category", "architecture_fix"):
            val = getattr(finding, attr, "")
            if val and len(val) < 200:
                short_fields[attr] = val

        if short_fields:
            translated = _translate_batch(short_fields, model)
            for attr, val in translated.items():
                setattr(finding, attr, val)

        # Translate longer fields individually
        for attr in ("description", "risk", "recommendation"):
            val = getattr(finding, attr, "")
            if val:
                setattr(finding, attr, _cached_translate(val))

    return he_report
