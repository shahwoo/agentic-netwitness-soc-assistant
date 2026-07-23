from __future__ import annotations

import json
import shutil
import time
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.export_cache import collect_ticket_export_status, load_metadata
from reporting.template_document_exporter import generate_agent_export

TEST_ROOT = PROJECT_ROOT / "testdata" / "export_cache"
OUTPUT_DIR = TEST_ROOT / "outputs"
RESULTS_PATH = TEST_ROOT / "test_results.json"
TICKET_ID = "TKT-CACHE-0001"


def write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def seed_outputs(version: str = "v1") -> dict:
    shutil.rmtree(TEST_ROOT, ignore_errors=True)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    alert_id = f"ALERT-CACHE-{version.upper()}"
    parser_result = {
        "parser_status": "completed",
        "input_shape": "incident_with_alerts",
        "normalised_alert_count": 1,
        "selected_alert_id": alert_id,
        "parser_confidence": "High",
        "parser_confidence_score": 95,
        "important_extracted_fields": {
            "alert_id": alert_id,
            "incident_id": TICKET_ID,
            "alert_name": "Export Cache Parser Test",
            "severity": "High",
            "risk_score": 82,
            "alert_time": "2026-06-18T10:00:00Z",
            "source_ips": ["10.0.0.5"],
            "destination_ips": ["8.8.8.8"],
            "hosts": ["wkstn-cache-001"],
            "users": ["alice"],
            "file_hashes": ["44d88612fea8a8f36de82e1278abb02f"],
            "process_names": ["powershell.exe"],
        },
        "missing_important_fields": [],
        "warnings": [],
    }
    processed_alert = {
        "incident_id": TICKET_ID,
        "alert_id": alert_id,
        "alert_name": "Export Cache Parser Test",
        "severity": "High",
        "confidence": "High",
        "hostname": "wkstn-cache-001",
        "destination_ip": "8.8.8.8",
        "file_hash": "44d88612fea8a8f36de82e1278abb02f",
        "iocs": [{"type": "file_hash", "value": "44d88612fea8a8f36de82e1278abb02f"}],
    }
    write_json(OUTPUT_DIR / "parser_result.json", parser_result)
    write_json(OUTPUT_DIR / "processed_alert.json", processed_alert)
    write_json(OUTPUT_DIR / "enriched_alert.json", {**processed_alert, "threat_intelligence": {"notes": []}, "enrichment_risk_level": "Low", "enrichment_risk_score": 0})
    write_json(OUTPUT_DIR / "triage_result.json", {"status": "completed", "severity": "High", "confidence": "High", "summary": "Triage completed."})
    write_json(OUTPUT_DIR / "investigation_result.json", {"status": "completed_limited", "summary": "Investigation completed with evidence gaps.", "findings": ["Usable finding"]})
    write_json(OUTPUT_DIR / "approval_result.json", {"decision": "approved", "analyst": "Test Analyst"})
    return {"ticket_id": TICKET_ID, "title": "Export Cache Test", "parser_result": parser_result}


def assert_true(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> int:
    results = []
    ticket = seed_outputs("v1")

    try:
        # 1. First DOCX generation should create a Word file and ready cache metadata.
        docx1 = generate_agent_export(PROJECT_ROOT, OUTPUT_DIR, ticket, "parsing", "docx")
        assert_true(docx1.exists() and docx1.stat().st_size > 0, "First DOCX export was not created")
        meta = load_metadata(docx1.parent)
        assert_true(meta.get("entries", {}).get("docx", {}).get("status") == "ready", "DOCX cache metadata is not ready")
        results.append({"case": "first_docx_generation", "status": "passed", "path": str(docx1)})

        # 2. Second DOCX download should return the cached file without changing mtime.
        mtime1 = docx1.stat().st_mtime_ns
        time.sleep(0.05)
        docx2 = generate_agent_export(PROJECT_ROOT, OUTPUT_DIR, ticket, "parsing", "docx")
        assert_true(docx1 == docx2, "Cached DOCX path changed")
        assert_true(docx2.stat().st_mtime_ns == mtime1, "Cached DOCX was regenerated unnecessarily")
        results.append({"case": "second_docx_uses_cache", "status": "passed", "path": str(docx2)})

        # 3. PDF generation should reuse cached DOCX, create PDF, and mark PDF ready.
        pdf1 = generate_agent_export(PROJECT_ROOT, OUTPUT_DIR, ticket, "parsing", "pdf")
        assert_true(pdf1.exists() and pdf1.stat().st_size > 0, "PDF export was not created")
        meta = load_metadata(pdf1.parent)
        assert_true(meta.get("entries", {}).get("pdf", {}).get("status") == "ready", "PDF cache metadata is not ready")
        results.append({"case": "pdf_generation_from_cached_docx", "status": "passed", "path": str(pdf1)})

        # 4. Export status collection should report ready Word and PDF.
        status = collect_ticket_export_status(OUTPUT_DIR, TICKET_ID)
        parsing_status = status.get("agents", {}).get("parsing", {})
        assert_true(parsing_status.get("docx", {}).get("status") == "ready", "Status route data does not show DOCX ready")
        assert_true(parsing_status.get("pdf", {}).get("status") == "ready", "Status route data does not show PDF ready")
        results.append({"case": "export_status_reports_ready", "status": "passed", "status_payload": parsing_status})

        # 5. Changing source JSON should invalidate cache and regenerate DOCX.
        parser_result_path = OUTPUT_DIR / "parser_result.json"
        parser_result = json.loads(parser_result_path.read_text(encoding="utf-8"))
        parser_result["selected_alert_id"] = "ALERT-CACHE-V2"
        parser_result["important_extracted_fields"]["alert_id"] = "ALERT-CACHE-V2"
        write_json(parser_result_path, parser_result)
        time.sleep(0.05)
        docx3 = generate_agent_export(PROJECT_ROOT, OUTPUT_DIR, ticket, "parsing", "docx")
        assert_true(docx3.exists(), "Regenerated DOCX missing")
        assert_true(docx3.stat().st_mtime_ns != mtime1, "DOCX cache was not invalidated after source changed")
        results.append({"case": "source_hash_invalidation", "status": "passed", "path": str(docx3)})

        summary = {"success": True, "passed": len(results), "failed": 0, "results": results}
    except Exception as exc:
        results.append({"case": "failure", "status": "failed", "error": str(exc)})
        summary = {"success": False, "passed": len([r for r in results if r.get("status") == "passed"]), "failed": 1, "results": results}

    RESULTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    RESULTS_PATH.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))
    return 0 if summary["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
