from pathlib import Path
import json
from typing import Any
from config import settings


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=4), encoding="utf-8")


def build_reporting_result(context: dict[str, Any], generated_reports: dict[str, str]) -> dict[str, Any]:
    return {
        "schema_version": "reporting-result-v1",
        "incident_id": context["incident_id"],
        "alert_id": context["alert_id"],
        "report_status": context["report_status"],
        "report_generation_mode": context["report_generation_mode"],
        "validation_status": context["validation_status"],
        "missing_required_fields": context["missing_required_fields"],
        "recovered_fields": context["recovered_fields"],
        "generated_reports": generated_reports,
        "warnings": context["warnings"],
        "rag_used": context["rag_used"],
        "rag_status": context["rag_status"],
        "llm_used": context["llm_used"],
        "llm_status": context["llm_status"],
        "llm_quality_status": context.get("llm_quality_status", "not_recorded"),
        "llm_quality_issues": context.get("llm_quality_issues", []),
        "created_at": context["created_at"],
    }


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
