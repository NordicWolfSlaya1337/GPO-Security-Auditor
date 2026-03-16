import json
import os
import queue
import tempfile
import threading
import uuid
import zipfile
from pathlib import Path

from flask import Flask, render_template, request, jsonify, Response, send_file

from engine.runner import run_audit
from output.password_mgr import get_password
from output.pdf_report import generate_pdf
from output.csv_export import generate_csv_zip
from web.chat import (
    check_ollama_available as chat_ollama_available,
    stream_chat_response,
    load_session,
    cleanup_old_sessions,
)

app = Flask(__name__, template_folder=os.path.join(os.path.dirname(__file__), "templates"))

# Job storage: job_id -> {queue, report, status, output_dir}
jobs = {}

# Cleanup old chat sessions on startup
cleanup_old_sessions()


@app.route("/")
def index():
    return render_template("index.html", password=get_password())


@app.route("/api/upload", methods=["POST"])
def upload():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    f = request.files["file"]
    if not f.filename or not f.filename.lower().endswith(".zip"):
        return jsonify({"error": "Please upload a ZIP file"}), 400

    job_id = str(uuid.uuid4())[:8]
    output_dir = tempfile.mkdtemp(prefix=f"gpoaudit_{job_id}_")
    zip_path = os.path.join(output_dir, f.filename)
    f.save(zip_path)

    q = queue.Queue()
    jobs[job_id] = {
        "queue": q,
        "report": None,
        "status": "running",
        "output_dir": output_dir,
        "zip_path": zip_path,
    }

    thread = threading.Thread(target=_run_job, args=(job_id,), daemon=True)
    thread.start()

    return jsonify({"job_id": job_id})


@app.route("/api/stream/<job_id>")
def stream(job_id):
    if job_id not in jobs:
        return jsonify({"error": "Job not found"}), 404

    def generate():
        q = jobs[job_id]["queue"]
        while True:
            try:
                event = q.get(timeout=30)
                if event is None:
                    # End of stream
                    yield f"data: {json.dumps({'type': 'complete'})}\n\n"
                    break
                yield f"data: {json.dumps(event)}\n\n"
            except queue.Empty:
                yield f"data: {json.dumps({'type': 'heartbeat'})}\n\n"

    return Response(generate(), mimetype="text/event-stream")


@app.route("/api/download/pdf/<job_id>")
def download_pdf(job_id):
    if job_id not in jobs or jobs[job_id]["status"] != "complete":
        return jsonify({"error": "Report not ready"}), 404
    pdf_path = os.path.join(jobs[job_id]["output_dir"], "gpo_audit_report.pdf")
    if not os.path.exists(pdf_path):
        return jsonify({"error": "PDF not generated"}), 404
    return send_file(pdf_path, as_attachment=True, download_name="gpo_audit_report.pdf")


@app.route("/api/download/csv/<job_id>")
def download_csv(job_id):
    if job_id not in jobs or jobs[job_id]["status"] != "complete":
        return jsonify({"error": "Report not ready"}), 404
    csv_path = os.path.join(jobs[job_id]["output_dir"], "gpo_audit_findings.zip")
    if not os.path.exists(csv_path):
        return jsonify({"error": "CSV not generated"}), 404
    return send_file(csv_path, as_attachment=True, download_name="gpo_audit_findings.zip")


@app.route("/api/download/password/<job_id>")
def download_password(job_id):
    if job_id not in jobs or jobs[job_id]["status"] != "complete":
        return jsonify({"error": "Report not ready"}), 404
    pw_path = os.path.join(jobs[job_id]["output_dir"], "password.txt")
    if not os.path.exists(pw_path):
        return jsonify({"error": "Password file not generated"}), 404
    return send_file(pw_path, as_attachment=True, download_name="password.txt")


@app.route("/api/download/all/<job_id>")
def download_all(job_id):
    if job_id not in jobs or jobs[job_id]["status"] != "complete":
        return jsonify({"error": "Report not ready"}), 404
    output_dir = jobs[job_id]["output_dir"]
    bundle_path = os.path.join(output_dir, "gpo_audit_all_reports.zip")
    with zipfile.ZipFile(bundle_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for name in ["gpo_audit_report.pdf", "gpo_audit_findings.zip", "password.txt"]:
            fpath = os.path.join(output_dir, name)
            if os.path.exists(fpath):
                zf.write(fpath, name)
    return send_file(bundle_path, as_attachment=True, download_name="gpo_audit_all_reports.zip")


@app.route("/api/generate/<job_id>", methods=["POST"])
def manual_generate(job_id):
    """Manually trigger report generation for a completed job."""
    if job_id not in jobs or jobs[job_id]["report"] is None:
        return jsonify({"error": "No audit results available"}), 404

    report = jobs[job_id]["report"]
    output_dir = jobs[job_id]["output_dir"]
    password = get_password()

    try:
        pdf_path = os.path.join(output_dir, "gpo_audit_report.pdf")
        generate_pdf(report, pdf_path, password)
        csv_path = os.path.join(output_dir, "gpo_audit_findings.zip")
        generate_csv_zip(report, csv_path, password)
        _save_password_file(output_dir, password)

        return jsonify({"status": "ok", "message": "Reports generated successfully"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# --- Chat endpoints ---

@app.route("/api/chat/status")
def chat_status():
    """Check if Ollama is available for chat."""
    return jsonify({"available": chat_ollama_available()})


@app.route("/api/chat/<job_id>", methods=["POST"])
def chat(job_id):
    """Send a chat message, get streaming SSE response."""
    # Check if we have a report — either in memory or stored in a chat session
    report = None
    if job_id in jobs and jobs[job_id].get("report"):
        report = jobs[job_id]["report"]

    session = load_session(job_id)
    if not report and not session:
        return jsonify({"error": "No audit data available"}), 404

    data = request.get_json()
    message = (data or {}).get("message", "").strip()
    if not message:
        return jsonify({"error": "Message is required"}), 400

    def generate():
        for chunk in stream_chat_response(job_id, message, report):
            yield f"data: {chunk}\n\n"

    return Response(generate(), mimetype="text/event-stream")


@app.route("/api/chat/<job_id>/history")
def chat_history(job_id):
    """Load existing chat history for a job."""
    session = load_session(job_id)
    if not session:
        return jsonify({"messages": []})
    return jsonify({"messages": session.get("messages", [])})


# --- Internal helpers ---

def _run_job(job_id: str):
    job = jobs[job_id]
    q = job["queue"]
    password = get_password()

    def progress_callback(pct, msg, finding=None, **kwargs):
        event = {"type": "progress", "percent": pct, "message": msg}
        if finding:
            event["type"] = "finding"
            event["finding"] = {
                "rule_id": finding.rule_id,
                "severity": finding.severity.value,
                "category": finding.category,
                "gpo_name": finding.gpo_name,
                "title": finding.title,
                "description": finding.description,
                "risk": finding.risk,
                "recommendation": finding.recommendation,
                "setting_path": finding.setting_path,
                "current_value": finding.current_value,
                "expected_value": finding.expected_value,
            }
        q.put(event)

    try:
        report = run_audit(job["zip_path"], progress_callback)
        job["report"] = report

        # Auto-generate outputs
        output_dir = job["output_dir"]
        pdf_path = os.path.join(output_dir, "gpo_audit_report.pdf")
        generate_pdf(report, pdf_path, password)
        q.put({"type": "progress", "percent": 93, "message": "PDF report generated"})

        csv_path = os.path.join(output_dir, "gpo_audit_findings.zip")
        generate_csv_zip(report, csv_path, password)
        q.put({"type": "progress", "percent": 95, "message": "CSV export generated"})

        _save_password_file(output_dir, password)

        job["status"] = "complete"
        q.put({
            "type": "progress", "percent": 100,
            "message": f"Audit complete! {len(report.findings)} findings. Risk score: {report.risk_score}/100",
        })
        q.put({
            "type": "summary",
            "risk_score": report.risk_score,
            "risk_label": report.risk_label,
            "total_findings": len(report.findings),
            "severity_counts": {k.value: v for k, v in report.severity_counts.items()},
        })
    except Exception as e:
        q.put({"type": "error", "message": str(e)})
        job["status"] = "error"
    finally:
        q.put(None)  # Signal end of stream


def _save_password_file(output_dir: str, password: str):
    pw_path = os.path.join(output_dir, "password.txt")
    with open(pw_path, "w") as f:
        f.write(password)
