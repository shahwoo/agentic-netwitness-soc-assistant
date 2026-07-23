from __future__ import annotations

import json
import shutil
import sys
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.casework_store import CaseworkStore
from backend import ticket_workflow
from adapters import run_reporting
from adapters.common import OUTPUTS_DIR, INPUTS_DIR


def assert_true(cond: bool, msg: str) -> None:
    if not cond:
        raise AssertionError(msg)


def make_ticket(store: CaseworkStore) -> dict:
    raw_alert = {
        "alert_id": "ALERT-EG-0001",
        "alert_name": "Endpoint malware evidence gap test",
        "incident_id": "INC-EG-0001",
        "severity": "High",
        "risk_score": 88,
        "source": "NetWitness Endpoint",
        "hostname": "wkstn-eg-001",
        "username": "CORP\\analyst",
        "iocs": [{"type": "ip", "value": "8.8.8.8"}],
    }
    store.upsert_alert(raw_alert)
    ticket = store.create_ticket_from_alert("ALERT-EG-0001", owner="Soong Yang", status="To Parse")
    store.update_ticket(ticket["ticket_id"], {
        "parsing_result": {"status": "completed", "processed_alert": {"incident_id": "INC-EG-0001", "alert_id": "ALERT-EG-0001"}},
        "triage_result": {"status": "completed", "incident_id": "INC-EG-0001", "severity": "High"},
        "threat_intel_result": {"status": "completed", "enriched_alert": {"incident_id": "INC-EG-0001", "alert_id": "ALERT-EG-0001"}},
        "approval_result": {"decision": "approved", "status": "completed"},
        "current_stage": "investigation",
        "status": "Needs Investigation",
    })
    inv = {
        "status": "completed_with_evidence_gaps",
        "incident_id": "INC-EG-0001",
        "alert_id": "ALERT-EG-0001",
        "summary": "Investigation produced usable findings, but some telemetry is missing.",
        "missing_evidence": [{"gap": "email_subject", "reason": "Not present"}],
        "findings": ["IOC observed: 8.8.8.8"],
        "reporting_allowed": True,
        "reporting_mode": "with_limitations",
        "triage_requery_request": {"requested_metakeys": ["email_subject"], "query_terms": ["wkstn-eg-001"]},
    }
    return store.attach_agent_result(ticket["ticket_id"], "investigation", inv)


def test_decision_buttons_and_branches() -> dict:
    with tempfile.TemporaryDirectory() as td:
        store = CaseworkStore(Path(td) / "casework.db")
        ticket = make_ticket(store)
        decorated = ticket_workflow.decorate_ticket(ticket)
        actions = []
        for agent in decorated["agent_panel"]:
            if agent["key"] == "investigation":
                actions = [a["id"] for a in agent.get("actions", [])]
                status = agent["status"]
                break
        else:
            raise AssertionError("Investigation agent card missing")
        assert_true(status == "Evidence Gap Decision Required", f"unexpected investigation status: {status}")
        assert_true("continue-to-reporting" in actions, "Continue to Reporting Agent action missing")
        assert_true("return-to-triage" in actions, "Go back to Triage action missing")
        allowed, reason = ticket_workflow.can_run_agent(ticket, "reporting")
        assert_true(not allowed and "Choose Continue" in reason, "Reporting should wait for evidence-gap decision")

        continued = store.record_evidence_gap_decision(ticket["ticket_id"], "continue_to_reporting", analyst="Test Analyst")
        assert_true(continued["current_stage"] == "reporting", "Continue decision should move to reporting")
        allowed, reason = ticket_workflow.can_run_agent(continued, "reporting")
        assert_true(allowed, f"Reporting should be allowed after continue decision: {reason}")

    with tempfile.TemporaryDirectory() as td:
        store = CaseworkStore(Path(td) / "casework.db")
        ticket = make_ticket(store)
        returned = store.record_evidence_gap_decision(ticket["ticket_id"], "return_to_triage", analyst="Test Analyst")
        assert_true(returned["current_stage"] == "triage", "Return decision should move to triage")
        assert_true(returned["status"] == "Needs Triage Evidence", "Return decision should mark Needs Triage Evidence")
        assert_true((returned.get("triage_result") or {}).get("investigation_throwback") is True, "Triage throwback flag missing")
        allowed, reason = ticket_workflow.can_run_agent(returned, "reporting")
        assert_true(not allowed, "Reporting should be locked after return to triage")

    return {"decision_branching": "passed"}


def test_reporting_wrapper_backfill() -> dict:
    ticket_id = "TKT-EG-WRAPPER"
    ticket_dir = OUTPUTS_DIR / ticket_id / "reporting"
    if ticket_dir.exists():
        shutil.rmtree(ticket_dir)
    ticket_dir.mkdir(parents=True, exist_ok=True)

    # Simulate report artefacts existing but no reporting_result.json wrapper.
    manifest_dir = OUTPUTS_DIR / "INC-EG-0001" / "reports"
    manifest_dir.mkdir(parents=True, exist_ok=True)
    (manifest_dir / "report_manifest.json").write_text(json.dumps({
        "incident_id": "INC-EG-0001",
        "sections": {"executive_summary": {"status": "draft", "title": "Executive Summary"}},
    }), encoding="utf-8")
    (INPUTS_DIR / "processed_alert.json").write_text(json.dumps({"incident_id": "INC-EG-0001", "alert_id": "ALERT-EG-0001", "alert_title": "Endpoint malware evidence gap test"}), encoding="utf-8")
    (INPUTS_DIR / "investigation_result.json").write_text(json.dumps({"status": "completed_with_evidence_gaps", "missing_evidence": [{"gap": "email_subject"}]}), encoding="utf-8")
    (INPUTS_DIR / "investigation_approval_result.json").write_text(json.dumps({"decision": "approved", "evidence_gap_decision": "continue_to_reporting", "reporting_mode": "with_limitations"}), encoding="utf-8")

    result = run_reporting._normalise_reporting_result({"success": True, "returncode": 0}, ticket_id=ticket_id)
    wrapper_path = ticket_dir / "reporting_result.json"
    assert_true(wrapper_path.exists(), "Ticket-specific reporting_result.json wrapper was not written")
    assert_true(result["status"] in {"completed_with_warnings", "completed", "completed_limited"}, f"Unexpected wrapper status: {result['status']}")
    assert_true(result["incident_id"] == "INC-EG-0001", "Wrapper did not recover incident ID")
    assert_true(result["alert_id"] == "ALERT-EG-0001", "Wrapper did not recover alert ID")
    assert_true(result["reporting_mode"] == "with_limitations", "Wrapper did not preserve reporting_mode")
    return {"reporting_wrapper": "passed", "wrapper_path": str(wrapper_path)}


def main() -> int:
    results = {
        **test_decision_buttons_and_branches(),
        **test_reporting_wrapper_backfill(),
    }
    out = Path("testdata/evidence_gap_branching/test_results.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"passed": True, "results": results}, indent=2), encoding="utf-8")
    print(json.dumps({"passed": True, "results": results}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
