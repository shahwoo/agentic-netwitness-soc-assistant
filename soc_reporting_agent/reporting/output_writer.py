from pathlib import Path
import json
from typing import Any
from config import settings
from reporting.status_display import get_status_metadata, calculate_llm_enhancement_score


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=4), encoding="utf-8")


def _display_fields(prefix: str, category: str, technical_status: Any) -> dict[str, str]:
    meta = get_status_metadata(category, technical_status)
    return {
        f"{prefix}_display": meta["display"],
        f"{prefix}_explanation": meta["explanation"],
        f"{prefix}_workflow_impact": meta["workflow_impact"],
    }


def build_reporting_result(context: dict[str, Any], generated_reports: dict[str, str]) -> dict[str, Any]:
    report_status = context["report_status"]
    validation_status = context["validation_status"]
    rag_status = context["rag_status"]
    llm_status = context["llm_status"]
    cache_status = context.get("llm_cache_status", "not_recorded")
    completeness_status = context.get("report_quality_status", "not_recorded")
    llm_enhancement = calculate_llm_enhancement_score(context.get("llm_section_results", {}), llm_status)

    result = {
        "schema_version": "reporting-result-v1",
        "incident_id": context["incident_id"],
        "alert_id": context["alert_id"],
        "report_status": report_status,
        "report_generation_mode": context["report_generation_mode"],
        "validation_status": validation_status,
        "missing_required_fields": context["missing_required_fields"],
        "recovered_fields": context["recovered_fields"],
        "report_completeness_score": context.get("report_quality_score"),
        "report_completeness_status": completeness_status,
        "report_completeness": context.get("report_quality", {}),
        "quality_checks": context.get("quality_checks", {}),
        "field_provenance": context.get("field_provenance", {}),
        "evidence_index": context.get("evidence_index", {}),
        # Backwards-compatible aliases kept for existing tests and scripts.
        "report_quality_score": context.get("report_quality_score"),
        "report_quality_status": completeness_status,
        "report_quality": context.get("report_quality", {}),
        "generated_reports": generated_reports,
        "warnings": context["warnings"],
        "data_consistency_status": context.get("data_consistency_status", context.get("data_consistency", {}).get("status", "passed")),
        "data_consistency": context.get("data_consistency", {}),
        "input_context_hash": context.get("input_context_hash"),
        "rag_used": context["rag_used"],
        "rag_status": rag_status,
        "llm_used": context["llm_used"],
        "llm_provider": context.get("llm_provider", "not_recorded"),
        "llm_model": context.get("llm_model", "not_recorded"),
        "llm_status": llm_status,
        "llm_quality_status": context.get("llm_quality_status", "not_recorded"),
        "llm_quality_issues": context.get("llm_quality_issues", []),
        "llm_section_results": context.get("llm_section_results", {}),
        "llm_enhancement_score": llm_enhancement["score"],
        "llm_enhancement_score_detail": llm_enhancement,
        "llm_attempt_count": context.get("llm_attempt_count", 0),
        "llm_cache_status": cache_status,
        "created_at": context["created_at"],
    }
    result.update(_display_fields("report_status", "report", report_status))
    result.update(_display_fields("validation_status", "validation", validation_status))
    result.update(_display_fields("rag_status", "rag", rag_status))
    result.update(_display_fields("llm_status", "llm", llm_status))
    result.update(_display_fields("llm_cache_status", "cache", cache_status))
    result.update(_display_fields("report_completeness_status", "quality", completeness_status))
    result.update(_display_fields("data_consistency_status", "data_consistency", result.get("data_consistency_status")))
    return result


def write_outputs(context: dict[str, Any], generated_reports: dict[str, str], output_dir: Path | None = None) -> dict[str, Any]:
    root_output_dir = output_dir or settings.OUTPUT_DIR
    incident_output_dir = root_output_dir / context["incident_id"]
    incident_output_dir.mkdir(parents=True, exist_ok=True)

    reporting_result = build_reporting_result(context, generated_reports)
    write_json(incident_output_dir / "reporting_result.json", reporting_result)
    write_json(incident_output_dir / "enriched_reporting_context.json", context)
    return reporting_result


def try_store_postgres(reporting_result: dict[str, Any], context: dict[str, Any]) -> tuple[bool, str]:
    if not settings.USE_POSTGRES:
        return False, "postgres_disabled"

    try:
        import psycopg2

        conn = psycopg2.connect(settings.POSTGRES_DSN)
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO report_results (
                incident_id, alert_id, report_status, validation_status,
                report_generation_mode, llm_used, rag_used, result_json
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                reporting_result["incident_id"],
                reporting_result["alert_id"],
                reporting_result["report_status"],
                reporting_result["validation_status"],
                reporting_result["report_generation_mode"],
                reporting_result["llm_used"],
                reporting_result["rag_used"],
                json.dumps(reporting_result),
            ),
        )
        conn.commit()
        cur.close()
        conn.close()
        return True, "postgres_store_success"
    except Exception as error:
        return False, f"postgres_store_failed: {error}"
