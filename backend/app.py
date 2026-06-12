from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, send_from_directory

# -----------------------------------------------------------------------------
# Simple Flask dashboard bridge
# -----------------------------------------------------------------------------
# This file only serves the dashboard and exposes read-only API routes.
# It does not import, run, or modify any triage, investigation, or reporting agent.
# Future integration point:
# - Add POST routes later if you want buttons to trigger agents.
# - Keep these GET routes stable so the frontend does not break.
# -----------------------------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DASHBOARD_DIR = PROJECT_ROOT / "dashboard"
OUTPUTS_DIR = PROJECT_ROOT / "outputs"

app = Flask(
    __name__,
    static_folder=str(DASHBOARD_DIR),
    static_url_path="",
)


def safe_read_json(filename: str, label: str) -> dict[str, Any]:
    """
    Safely read one JSON output file.

    If the file is missing, empty, or invalid, return a predictable fallback object
    instead of raising an exception. This lets the dashboard show "Not ready yet"
    while other agents are still unfinished.
    """
    file_path = OUTPUTS_DIR / filename

    fallback = {
        "ready": False,
        "status": "Not ready yet",
        "agent": label,
        "source_file": str(file_path.relative_to(PROJECT_ROOT)),
        "data": None,
    }

    if not file_path.exists():
        return {
            **fallback,
            "reason": "Output file does not exist yet.",
        }

    try:
        if file_path.stat().st_size == 0:
            return {
                **fallback,
                "reason": "Output file is empty.",
            }

        with file_path.open("r", encoding="utf-8") as f:
            data = json.load(f)

        return {
            "ready": True,
            "status": "Ready",
            "agent": label,
            "source_file": str(file_path.relative_to(PROJECT_ROOT)),
            "data": data,
        }

    except json.JSONDecodeError as exc:
        return {
            **fallback,
            "reason": f"Invalid JSON: {exc.msg}",
        }
    except OSError as exc:
        return {
            **fallback,
            "reason": f"Could not read file: {exc}",
        }


def value_from(data: dict[str, Any] | None, *keys: str, default: Any = "Not ready yet") -> Any:
    """
    Look for the first available key in a dict.

    This avoids forcing triage, investigation, and reporting into one shared schema
    before your teammates' agents are ready.
    """
    if not isinstance(data, dict):
        return default

    for key in keys:
        value = data.get(key)
        if value not in (None, "", [], {}):
            return value
    return default


@app.route("/")
def index():
    """Serve the new dashboard HTML."""
    return send_from_directory(DASHBOARD_DIR, "index.html")


@app.route("/api/triage")
def api_triage():
    """Return outputs/triage_result.json, or a safe fallback."""
    return jsonify(safe_read_json("triage_result.json", "Triage Agent"))


@app.route("/api/investigation")
def api_investigation():
    """Return outputs/investigation_result.json, or a safe fallback."""
    return jsonify(safe_read_json("investigation_result.json", "Investigation Agent"))


@app.route("/api/reporting")
def api_reporting():
    """Return outputs/final_report.json, or a safe fallback."""
    return jsonify(safe_read_json("final_report.json", "Reporting Agent"))


@app.route("/api/case")
def api_case():
    """
    Return combined case data for the dashboard.

    This route intentionally keeps each agent result separate. It only extracts a
    few common display fields for dashboard cards.
    """
    triage = safe_read_json("triage_result.json", "Triage Agent")
    investigation = safe_read_json("investigation_result.json", "Investigation Agent")
    reporting = safe_read_json("final_report.json", "Reporting Agent")

    triage_data = triage.get("data") if triage.get("ready") else None
    investigation_data = investigation.get("data") if investigation.get("ready") else None
    reporting_data = reporting.get("data") if reporting.get("ready") else None

    # Prefer triage fields first, then investigation, then reporting.
    display_source = triage_data or investigation_data or reporting_data or {}

    case_summary = {
        "incident_id": value_from(
            display_source,
            "incident_id",
            "case_id",
            "id",
            "alert_id",
        ),
        "title": value_from(
            display_source,
            "incident_title",
            "title",
            "alert_title",
            default="SOC case dashboard",
        ),
        "severity": value_from(
            display_source,
            "severity",
            "classification",
            "risk_level",
        ),
        "confidence": value_from(
            display_source,
            "confidence",
            "confidence_level",
        ),
        "risk_score": value_from(
            display_source,
            "risk_score",
            "enrichment_risk_score",
            "score",
        ),
        "current_stage": value_from(
            display_source,
            "current_stage",
            "stage",
            "report_status",
        ),
        "next_action": value_from(
            display_source,
            "next_action",
            "recommended_action",
            "recommendation",
        ),
    }

    return jsonify(
        {
            "ready": any([triage.get("ready"), investigation.get("ready"), reporting.get("ready")]),
            "status": "Ready" if any([triage.get("ready"), investigation.get("ready"), reporting.get("ready")]) else "Not ready yet",
            "case": case_summary,
            "agents": {
                "triage": triage,
                "investigation": investigation,
                "reporting": reporting,
            },
        }
    )


@app.errorhandler(404)
def not_found(_error):
    return jsonify({"ready": False, "status": "Not found"}), 404


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False,
        use_reloader=False
    )
