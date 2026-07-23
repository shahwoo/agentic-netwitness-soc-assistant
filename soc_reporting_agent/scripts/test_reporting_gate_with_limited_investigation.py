from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend import ticket_workflow

OUT = ROOT / "testdata" / "workflow_gating" / "test_results.json"

BASE_TICKET = {
    "ticket_id": "TKT-GATE-TEST",
    "parsing_result": {"status": "completed", "summary": "Parser output ready."},
    "triage_result": {"status": "completed", "summary": "Triage complete."},
    "threat_intel_result": {"status": "completed", "summary": "Threat intel complete."},
    "approval_result": {"decision": "approved", "status": "completed"},
    "investigation_approval_result": {"decision": "approved", "status": "completed"},
}


def ticket_with(inv: dict) -> dict:
    t = dict(BASE_TICKET)
    t["investigation_result"] = inv
    return t


def run_case(name: str, inv: dict, expected_allowed: bool, expected_label_contains: str | None = None) -> dict:
    ticket = ticket_with(inv)
    allowed, reason = ticket_workflow.can_run_agent(ticket, "reporting")
    next_step = ticket_workflow.next_agent(ticket)
    usable = ticket_workflow.is_investigation_usable_for_reporting(inv)
    ok = allowed == expected_allowed
    if expected_label_contains:
        ok = ok and expected_label_contains.lower() in str(next_step.get("label", "")).lower()
    return {
        "name": name,
        "passed": ok,
        "expected_allowed": expected_allowed,
        "actual_allowed": allowed,
        "reason": reason,
        "next_step": next_step,
        "usable_for_reporting": usable,
    }


def main() -> int:
    cases = [
        run_case(
            "completed investigation unlocks reporting",
            {"status": "completed", "summary": "Investigation complete.", "findings": ["Finding A"]},
            True,
            "Generate Report",
        ),
        run_case(
            "completed_limited unlocks reporting with limitations",
            {"status": "completed_limited", "summary": "Investigation ran with limited telemetry.", "missing_evidence": [{"gap": "dns_logs"}]},
            True,
            "Limitations",
        ),
        run_case(
            "completed_with_evidence_gaps unlocks reporting with limitations",
            {"status": "completed_with_evidence_gaps", "summary": "Playbook could not be fully answered.", "missing_fields": ["alert_timestamp"]},
            True,
            "Limitations",
        ),
        run_case(
            "needs_more_data with findings unlocks reporting with limitations",
            {"status": "needs_more_data", "summary": "Missing telemetry is an evidence gap, not a crash.", "findings": ["Affected host observed"], "missing_evidence": [{"gap": "endpoint_process_tree"}]},
            True,
            "Limitations",
        ),
        run_case(
            "failed investigation still blocks reporting",
            {"status": "failed", "summary": "Investigation crashed.", "error": "invalid JSON"},
            False,
        ),
    ]
    result = {"passed": sum(1 for c in cases if c["passed"]), "failed": sum(1 for c in cases if not c["passed"]), "cases": cases}
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))
    return 0 if result["failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
