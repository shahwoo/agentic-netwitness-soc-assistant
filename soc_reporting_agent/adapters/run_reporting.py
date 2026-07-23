from __future__ import annotations

import json
import os
import shutil
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

PROJECT_ROOT_BOOTSTRAP = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT_BOOTSTRAP) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT_BOOTSTRAP))

from adapters.common import INPUTS_DIR, OUTPUTS_DIR, PROJECT_ROOT, copy_if_exists, latest_file, now_iso, read_json, run_script, write_json
from backend.reporting_context_resolver import ensure_reporting_inputs


def _copy_first_existing(candidates: list[Path], dest: Path) -> bool:
    for path in candidates:
        if path.exists() and path.stat().st_size > 0:
            if path.resolve() != dest.resolve():
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(path, dest)
            return True
    return False


def _prepare_inputs(ticket_id: str | None = None) -> None:
    copy_if_exists(OUTPUTS_DIR / "triage_result.json", INPUTS_DIR / "triage_result.json")
    inv_candidates = []
    approval_candidates = []
    if ticket_id:
        inv_candidates.extend([
            OUTPUTS_DIR / ticket_id / "investigation" / "investigation_result.json",
            OUTPUTS_DIR / ticket_id / "investigation_result.json",
        ])
        approval_candidates.extend([
            OUTPUTS_DIR / ticket_id / "investigation_approval_result.json",
            OUTPUTS_DIR / ticket_id / "approval" / "investigation_approval_result.json",
        ])
    inv_candidates.extend([
        OUTPUTS_DIR / "investigation_result.json",
        INPUTS_DIR / "investigation_result.json",
        OUTPUTS_DIR / "unknown" / "investigation_result.json",
    ])
    approval_candidates.extend([
        OUTPUTS_DIR / "investigation_approval_result.json",
        INPUTS_DIR / "investigation_approval_result.json",
        OUTPUTS_DIR / "approval_result.json",
        INPUTS_DIR / "approval_result.json",
    ])
    _copy_first_existing(inv_candidates, INPUTS_DIR / "investigation_result.json")
    _copy_first_existing(approval_candidates, INPUTS_DIR / "approval_result.json")
    ensure_reporting_inputs(PROJECT_ROOT, ticket_id=ticket_id)
    if not (INPUTS_DIR / "enriched_alert.json").exists():
        copy_if_exists(OUTPUTS_DIR / "enriched_alert.json", INPUTS_DIR / "enriched_alert.json")


def _clean(value: Any) -> Any:
    if value in (None, "", [], {}):
        return None
    if isinstance(value, str) and value.strip().lower() in {"unknown", "unknown-incident", "inc-0001", "not provided", "untitled"}:
        return None
    return value


def _first(*values: Any, default: Any = None) -> Any:
    for value in values:
        cleaned = _clean(value)
        if cleaned is not None:
            return cleaned
    return default


def _iso_to_ts(value: Any) -> float | None:
    try:
        if not value:
            return None
        text = str(value).replace("Z", "+00:00")
        return datetime.fromisoformat(text).timestamp()
    except Exception:
        return None


def _is_new_enough(path: Path, started_ts: float | None) -> bool:
    if not path.exists() or path.stat().st_size == 0:
        return False
    if started_ts is None:
        return True
    # Allow a small clock-resolution tolerance for files written at process start.
    return path.stat().st_mtime >= started_ts - 1.0


def _run_succeeded(run_result: dict[str, Any]) -> bool:
    return bool(run_result.get("success")) and int(run_result.get("returncode", 1)) == 0


def _normalise_status(value: Any) -> str:
    return str(value or "").strip().lower().replace(" ", "_").replace("-", "_")


def _has_limitations(inv: dict[str, Any], approval: dict[str, Any]) -> bool:
    status = _normalise_status(inv.get("status") or inv.get("workflow_decision"))
    limited_statuses = {
        "completed_limited",
        "completed_with_warnings",
        "completed_with_evidence_gaps",
        "needs_more_data",
        "waiting_for_telemetry",
        "insufficient_telemetry",
        "partial",
        "partial_success",
        "needs_analyst_review",
    }
    return (
        status in limited_statuses
        or bool(inv.get("missing_evidence") or inv.get("missing_fields"))
        or _normalise_status(approval.get("reporting_mode")) == "with_limitations"
        or _normalise_status(inv.get("reporting_mode")) == "with_limitations"
    )


def _resolve_reporting_mode(inv: dict[str, Any], approval: dict[str, Any], wrapper: dict[str, Any] | None = None) -> str:
    explicit = _first(
        approval.get("reporting_mode"),
        approval.get("approved_reporting_mode"),
        inv.get("reporting_mode"),
        (wrapper or {}).get("reporting_mode"),
        default=None,
    )
    if explicit:
        return str(explicit)
    return "with_limitations" if _has_limitations(inv, approval) else "standard"


def _limitations(inv: dict[str, Any]) -> list[Any]:
    value = inv.get("missing_evidence") or inv.get("limitations") or inv.get("missing_fields") or []
    if isinstance(value, list):
        return value
    return [value] if value else []


def _error_summary(run_result: dict[str, Any]) -> str:
    stderr = str(run_result.get("stderr") or "").strip()
    stdout = str(run_result.get("stdout") or "").strip()
    text = stderr or stdout or "Reporting Agent failed before generating report sections."
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    for line in reversed(lines):
        if "Error" in line or "Exception" in line or "UndefinedError" in line or "Traceback" not in line:
            if len(line) > 500:
                return line[:497] + "..."
            return line
    return lines[-1][:500] if lines else "Reporting Agent failed before generating report sections."


def _clear_stale_reporting_wrappers(ticket_id: str | None = None) -> None:
    candidates = [
        OUTPUTS_DIR / "reporting_result.json",
        INPUTS_DIR / "reporting_result.json",
        OUTPUTS_DIR / "final_report.json",
    ]
    if ticket_id:
        candidates.extend([
            OUTPUTS_DIR / ticket_id / "reporting" / "reporting_result.json",
            OUTPUTS_DIR / ticket_id / "reporting" / "final_report.json",
            OUTPUTS_DIR / ticket_id / "reporting_result.json",
        ])
    for path in candidates:
        try:
            if path.exists():
                path.unlink()
        except Exception:
            pass


def _artifact_candidates(ticket_id: str | None = None) -> list[Path]:
    candidates: list[Path] = []
    if ticket_id:
        candidates.extend([
            OUTPUTS_DIR / ticket_id / "reporting" / "reporting_result.json",
            OUTPUTS_DIR / ticket_id / "reporting_result.json",
            OUTPUTS_DIR / ticket_id / "reports" / "report_manifest.json",
            OUTPUTS_DIR / ticket_id / "reporting" / "final_report.json",
        ])
    candidates.extend([
        OUTPUTS_DIR / "final_report.json",
        OUTPUTS_DIR / "reporting_result.json",
        latest_file("*/reporting_result.json", OUTPUTS_DIR) or Path("/__missing__"),
        latest_file("*/reports/report_manifest.json", OUTPUTS_DIR) or Path("/__missing__"),
        latest_file("*/reports/editable/final_incident_report.txt", OUTPUTS_DIR) or Path("/__missing__"),
        latest_file("*/final_report.txt", OUTPUTS_DIR) or Path("/__missing__"),
    ])
    out: list[Path] = []
    seen: set[str] = set()
    for p in candidates:
        if p and str(p) != "/__missing__":
            key = str(p.resolve()) if p.exists() else str(p)
            if key not in seen:
                out.append(p)
                seen.add(key)
    return out


def _find_reporting_result(ticket_id: str | None = None, started_ts: float | None = None) -> Path | None:
    for path in _artifact_candidates(ticket_id):
        if path.name == "reporting_result.json" and _is_new_enough(path, started_ts):
            return path
    return None


def _real_report_artifact_paths(ticket_id: str | None = None) -> list[Path]:
    paths: list[Path] = []
    if ticket_id:
        paths.extend([
            OUTPUTS_DIR / ticket_id / "reports" / "report_manifest.json",
            OUTPUTS_DIR / ticket_id / "reports" / "editable" / "final_incident_report.txt",
            OUTPUTS_DIR / ticket_id / "reports" / "drafts" / "final_incident_report.txt",
            OUTPUTS_DIR / ticket_id / "reporting" / "report_manifest.json",
        ])
    latest_manifest = latest_file("*/reports/report_manifest.json", OUTPUTS_DIR)
    latest_final = latest_file("*/reports/editable/final_incident_report.txt", OUTPUTS_DIR)
    latest_draft = latest_file("*/reports/drafts/final_incident_report.txt", OUTPUTS_DIR)
    for p in (latest_manifest, latest_final, latest_draft):
        if p:
            paths.append(p)
    out: list[Path] = []
    seen: set[str] = set()
    for path in paths:
        key = str(path.resolve()) if path.exists() else str(path)
        if key not in seen:
            out.append(path)
            seen.add(key)
    return out


def _has_report_artifacts(ticket_id: str | None = None, started_ts: float | None = None) -> bool:
    for path in _real_report_artifact_paths(ticket_id):
        if _is_new_enough(path, started_ts):
            return True
    return False


def _latest_manifest(ticket_id: str | None = None, started_ts: float | None = None) -> dict[str, Any]:
    paths: list[Path] = []
    if ticket_id:
        paths.extend([
            OUTPUTS_DIR / ticket_id / "reports" / "report_manifest.json",
            OUTPUTS_DIR / ticket_id / "reporting" / "report_manifest.json",
        ])
    latest = latest_file("*/reports/report_manifest.json", OUTPUTS_DIR)
    if latest:
        paths.append(latest)
    for path in paths:
        data = read_json(path, {}) if path and _is_new_enough(path, started_ts) else {}
        if data:
            return data
    return {}


def _copy_report_artifacts(ticket_id: str | None, wrapper: dict[str, Any]) -> None:
    if not ticket_id:
        return
    ticket_dir = OUTPUTS_DIR / ticket_id / "reporting"
    ticket_dir.mkdir(parents=True, exist_ok=True)
    write_json(ticket_dir / "reporting_result.json", wrapper)
    write_json(OUTPUTS_DIR / "reporting_result.json", wrapper)
    write_json(INPUTS_DIR / "reporting_result.json", wrapper)


def _normalise_reporting_result(run_result: dict, ticket_id: str | None = None) -> dict[str, Any]:
    started_ts = _iso_to_ts(run_result.get("started_at"))
    result_path = _find_reporting_result(ticket_id, started_ts=started_ts)
    final_txt_path = latest_file("*/reports/editable/final_incident_report.txt", OUTPUTS_DIR) or latest_file("*/final_report.txt", OUTPUTS_DIR)
    if final_txt_path and _is_new_enough(final_txt_path, started_ts):
        shutil.copy2(final_txt_path, OUTPUTS_DIR / "final_report.txt")

    generated = read_json(result_path, {}) if result_path else {}
    processed = read_json(INPUTS_DIR / "processed_alert.json", {}) or read_json(OUTPUTS_DIR / "processed_alert.json", {}) or {}
    enriched = read_json(INPUTS_DIR / "enriched_alert.json", {}) or read_json(OUTPUTS_DIR / "enriched_alert.json", {}) or {}
    triage = read_json(OUTPUTS_DIR / "triage_result.json", {}) or read_json(INPUTS_DIR / "triage_result.json", {}) or {}
    inv = read_json(OUTPUTS_DIR / "investigation_result.json", {}) or read_json(INPUTS_DIR / "investigation_result.json", {}) or read_json(OUTPUTS_DIR / "unknown" / "investigation_result.json", {}) or {}
    approval = read_json(OUTPUTS_DIR / "investigation_approval_result.json", {}) or read_json(INPUTS_DIR / "investigation_approval_result.json", {}) or {}
    manifest = _latest_manifest(ticket_id, started_ts=started_ts)

    if generated:
        wrapper = dict(generated)
        wrapper.setdefault("agent", "Reporting Agent")
        wrapper.setdefault("agent_source", "agents/reporting_agent.py")
        reports = wrapper.get("generated_reports") or {}
        has_reports = bool(reports or manifest)
        if _run_succeeded(run_result):
            wrapper["status"] = "completed"
            wrapper["report_status"] = wrapper.get("report_status") or "completed"
        elif has_reports:
            wrapper["status"] = "completed_with_warnings"
            wrapper["report_status"] = "completed_with_warnings"
        else:
            wrapper["status"] = "failed"
            wrapper["report_status"] = "failed"
        wrapper.setdefault("ticket_id", ticket_id)
        wrapper["incident_id"] = _first(processed.get("incident_id"), enriched.get("incident_id"), triage.get("incident_id"), inv.get("incident_id"), wrapper.get("incident_id"), default=ticket_id or "INC-0001")
        wrapper["alert_id"] = _first(processed.get("alert_id"), enriched.get("alert_id"), triage.get("alert_id"), inv.get("alert_id"), wrapper.get("alert_id"), default="UNKNOWN-ALERT")
        wrapper["title"] = _first(processed.get("alert_title"), processed.get("alert_name"), enriched.get("alert_title"), enriched.get("alert_name"), triage.get("title"), inv.get("title"), wrapper.get("title"), default="SOC incident")
        wrapper["reporting_mode"] = _resolve_reporting_mode(inv, approval, wrapper)
        wrapper["investigation_status"] = inv.get("status") or wrapper.get("investigation_status")
        wrapper["investigation_limitations"] = _limitations(inv) or wrapper.get("investigation_limitations") or []
        wrapper["limitations"] = wrapper.get("limitations") or wrapper["investigation_limitations"]
        if wrapper["status"] == "failed":
            wrapper["summary"] = "Reporting Agent failed before generating report sections."
            wrapper["error_summary"] = _error_summary(run_result)
        wrapper["report_manifest"] = manifest or wrapper.get("report_manifest") or {}
        wrapper["dashboard_copy_created_at"] = now_iso()
        wrapper["real_reporting_result_path"] = str(result_path.relative_to(PROJECT_ROOT)) if result_path else None
        wrapper["final_report_text_path"] = str(final_txt_path.relative_to(PROJECT_ROOT)) if final_txt_path else None
        wrapper["subprocess"] = run_result
        _copy_report_artifacts(ticket_id, wrapper)
        return wrapper

    artifacts_exist = _has_report_artifacts(ticket_id, started_ts=started_ts)
    fallback_status = "completed" if _run_succeeded(run_result) and artifacts_exist else ("completed_with_warnings" if artifacts_exist else "failed")
    wrapper = {
        "agent": "Reporting Agent",
        "agent_source": "agents/reporting_agent.py",
        "status": fallback_status,
        "report_status": fallback_status,
        "ticket_id": ticket_id,
        "incident_id": _first(processed.get("incident_id"), enriched.get("incident_id"), triage.get("incident_id"), inv.get("incident_id"), default=ticket_id or "INC-0001"),
        "alert_id": _first(processed.get("alert_id"), enriched.get("alert_id"), triage.get("alert_id"), inv.get("alert_id"), default="UNKNOWN-ALERT"),
        "title": _first(processed.get("alert_title"), processed.get("alert_name"), enriched.get("alert_title"), enriched.get("alert_name"), triage.get("title"), inv.get("title"), default="SOC incident"),
        "reporting_mode": _resolve_reporting_mode(inv, approval),
        "summary": (
            "Reporting completed and a dashboard reporting_result.json wrapper was generated from report artefacts."
            if fallback_status == "completed" else
            "Reporting completed with warnings. A dashboard reporting_result.json wrapper was generated from available report artefacts."
            if artifacts_exist else
            "Reporting Agent failed before generating report sections."
        ),
        "error_summary": None if artifacts_exist or _run_succeeded(run_result) else _error_summary(run_result),
        "limitations": _limitations(inv),
        "investigation_status": inv.get("status"),
        "investigation_limitations": _limitations(inv),
        "report_manifest": manifest,
        "generated_reports": manifest.get("sections", {}) if isinstance(manifest, dict) else {},
        "recommended_next_action": "Review the generated report sections and confirm SOC Analyst Review." if artifacts_exist else "Fix the Reporting Agent error and rerun Reporting.",
        "subprocess": run_result,
        "created_at": now_iso(),
    }
    _copy_report_artifacts(ticket_id, wrapper)
    return wrapper


def main() -> int:
    strict = os.getenv("STRICT_AGENT_MODE", "false").lower() == "true"
    ticket_id = os.getenv("SOC_TICKET_ID") or None
    _prepare_inputs(ticket_id=ticket_id)
    _clear_stale_reporting_wrappers(ticket_id=ticket_id)
    openai_key = os.getenv("OPENAI_API_KEY", "").strip()
    key_looks_real = bool(openai_key and not openai_key.lower().startswith("replace_with"))
    use_llm = os.getenv("REPORTING_USE_LLM", "true").lower() == "true" and key_looks_real
    extra_env = {
        "REPORTING_USE_LLM": "true" if use_llm else "false",
        "REPORTING_LLM_PROVIDER": os.getenv("REPORTING_LLM_PROVIDER", "openai"),
        "REPORTING_LLM_MODEL": os.getenv("REPORTING_LLM_MODEL", os.getenv("OPENAI_MODEL", "gpt-4o-mini")),
        "REPORTING_INPUT_DIR": str(INPUTS_DIR),
        "REPORTING_OUTPUT_DIR": str(OUTPUTS_DIR),
    }
    if ticket_id:
        extra_env["SOC_TICKET_ID"] = ticket_id
    print("[Reporting Adapter] Running original reporting agent with OpenAI settings from .env")
    run_result = run_script(PROJECT_ROOT / "agents" / "reporting_agent.py", timeout=int(os.getenv("REPORTING_TIMEOUT", "420")), extra_env=extra_env)
    if strict and not run_result.get("success"):
        raise RuntimeError(run_result.get("stderr") or "Reporting agent failed")
    output = _normalise_reporting_result(run_result, ticket_id=ticket_id)
    write_json(OUTPUTS_DIR / "final_report.json", output)
    write_json(OUTPUTS_DIR / "reporting_result.json", output)
    write_json(INPUTS_DIR / "reporting_result.json", output)
    print(f"[Reporting Adapter] Wrote {OUTPUTS_DIR / 'final_report.json'}")
    if ticket_id:
        print(f"[Reporting Adapter] Wrote {OUTPUTS_DIR / ticket_id / 'reporting' / 'reporting_result.json'}")
    print(f"[Reporting Adapter] Status: {output.get('status')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
