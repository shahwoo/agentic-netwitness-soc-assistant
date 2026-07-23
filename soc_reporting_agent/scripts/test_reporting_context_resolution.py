from __future__ import annotations

import json
import shutil
import sys
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.reporting_context_resolver import (  # noqa: E402
    ensure_reporting_inputs,
    resolve_investigation_approval_context,
    resolve_investigation_context,
)
from backend import ticket_workflow  # noqa: E402


def write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def run_case(name: str, setup_fn, expected_exists: bool, expected_usable: bool, expected_approval: bool | None = None) -> dict:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "outputs").mkdir()
        (root / "inputs").mkdir()
        ticket = setup_fn(root)
        resolved = resolve_investigation_context(root, ticket_id="TKT-TEST-001", ticket=ticket)
        approval = resolve_investigation_approval_context(root, ticket_id="TKT-TEST-001", ticket=ticket)
        ensure_result = ensure_reporting_inputs(root, ticket_id="TKT-TEST-001", ticket=ticket)
        copied_input = (root / "inputs" / "investigation_result.json").exists()
        passed = (
            resolved.exists == expected_exists
            and resolved.usable == expected_usable
            and (expected_approval is None or approval.usable == expected_approval)
            and ((not expected_usable) or copied_input)
        )
        return {
            "name": name,
            "passed": passed,
            "resolved_exists": resolved.exists,
            "resolved_usable": resolved.usable,
            "resolved_source": resolved.source,
            "approval_usable": approval.usable,
            "input_copied": copied_input,
            "ensure_result": ensure_result,
        }


def case_ticket_limited(root: Path) -> dict:
    return {
        "investigation_result": {
            "status": "completed_limited",
            "summary": "Investigation completed with limited endpoint telemetry.",
            "missing_evidence": [{"gap": "process_tree", "priority": "High"}],
        },
        "investigation_approval_result": {"decision": "approved", "analyst": "SOC Analyst"},
    }


def case_outputs_completed_with_gaps(root: Path) -> dict:
    write_json(root / "outputs" / "investigation_result.json", {
        "status": "completed_with_evidence_gaps",
        "summary": "Investigation produced usable findings, but DNS telemetry is missing.",
        "findings": ["Host executed suspicious binary."],
    })
    write_json(root / "outputs" / "investigation_approval_result.json", {"decision": "approved"})
    return {}


def case_unknown_needs_more_data(root: Path) -> dict:
    write_json(root / "outputs" / "unknown" / "investigation_result.json", {
        "status": "needs_more_data",
        "summary": "Playbook could not be fully answered due to missing network telemetry.",
        "missing_fields": ["netflow", "dns_logs"],
    })
    write_json(root / "inputs" / "investigation_approval_result.json", {"status": "completed"})
    return {}


def case_failed_blocks(root: Path) -> dict:
    write_json(root / "outputs" / "investigation_result.json", {
        "status": "failed",
        "summary": "Investigation adapter crashed.",
    })
    write_json(root / "outputs" / "investigation_approval_result.json", {"decision": "approved"})
    return {}


def case_missing_blocks(root: Path) -> dict:
    return {}


def main() -> int:
    tests = [
        ("ticket completed_limited unlocks reporting with approval", case_ticket_limited, True, True, True),
        ("outputs completed_with_evidence_gaps is discovered", case_outputs_completed_with_gaps, True, True, True),
        ("outputs/unknown needs_more_data with summary is discovered", case_unknown_needs_more_data, True, True, True),
        ("failed investigation remains blocked", case_failed_blocks, True, False, True),
        ("missing investigation remains blocked", case_missing_blocks, False, False, None),
    ]
    results = [run_case(*case) for case in tests]
    out_dir = PROJECT_ROOT / "testdata" / "reporting_context_resolution"
    out_dir.mkdir(parents=True, exist_ok=True)
    write_json(out_dir / "test_results.json", {"results": results, "passed": sum(1 for r in results if r["passed"]), "failed": sum(1 for r in results if not r["passed"])})
    for result in results:
        print(("PASS" if result["passed"] else "FAIL") + " - " + result["name"])
    failed = [r for r in results if not r["passed"]]
    print(f"Passed: {len(results) - len(failed)}")
    print(f"Failed: {len(failed)}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
