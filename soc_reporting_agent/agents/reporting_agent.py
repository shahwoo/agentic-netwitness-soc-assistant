import argparse
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from config import settings
from reporting.input_loader import load_reporting_inputs
from reporting.context_builder import build_context
from reporting.export_context_enhancer import enhance_export_context
from reporting.report_renderer import render_reports
from reporting.output_writer import write_outputs, try_store_postgres, write_json
from reporting.status_display import get_status_metadata, calculate_llm_enhancement_score


def parse_args():
    parser = argparse.ArgumentParser(description="Reporting Agent")
    parser.add_argument("--input-dir", type=Path, default=settings.INPUT_DIR)
    parser.add_argument("--output-dir", type=Path, default=settings.OUTPUT_DIR)
    parser.add_argument("--detail-level", default=getattr(settings, "REPORT_DETAIL_LEVEL", "analyst"), choices=["triage", "analyst", "post_incident_review", "executive"], help="Report detail level label recorded in output context.")
    parser.add_argument("--no-cache", action="store_true", help="Disable LLM cache for this run.")
    return parser.parse_args()


def _status_word(loaded: bool, optional: bool = False) -> str:
    if loaded:
        return "Loaded"
    return "Not found, optional" if optional else "Not found or empty"


def _print_loaded_sources(inputs: dict, warnings: list[str]) -> None:
    print("\n[Reporting Agent] Context sources:")
    sources = [
        ("processed_alert.json", "processed_alert", False),
        ("enriched_alert.json", "enriched_alert", False),
        ("triage_result.json", "triage_result", False),
        ("investigation_result.json", "investigation_result", False),
        ("approval_result.json", "approval_result", True),
    ]
    for filename, key, optional in sources:
        print(f"- {filename}: {_status_word(bool(inputs.get(key)), optional=optional)}")
    if warnings:
        print("\n[Reporting Agent] Input warnings:")
        for warning in warnings:
            print(f"- {warning}")


def _print_status(label: str, category: str, technical_status: str) -> None:
    meta = get_status_metadata(category, technical_status)
    print(f"[Reporting Agent] {label}: {meta['display']}")
    print(f"[Reporting Agent] {label} explanation: {meta['explanation']}")
    print(f"[Reporting Agent] {label} workflow impact: {meta['workflow_impact']}")


def _add_postgres_display_fields(reporting_result: dict, postgres_status: str) -> None:
    meta = get_status_metadata("postgresql", postgres_status)
    reporting_result["postgres_used"] = reporting_result.get("postgres_used", False)
    reporting_result["postgres_status"] = postgres_status
    reporting_result["postgres_status_display"] = meta["display"]
    reporting_result["postgres_status_explanation"] = meta["explanation"]
    reporting_result["postgres_status_workflow_impact"] = meta["workflow_impact"]


def _friendly_report_name(name: str) -> str:
    mapping = {
        "final_report": "Final incident report",
        "executive_summary": "Executive summary",
        "technical_findings": "Technical findings report",
        "soc_analyst_review": "SOC analyst review report",
        "soc_triage_review": "SOC triage review report",
        "reporting_result": "Reporting result JSON",
    }
    return mapping.get(name, name.replace("_", " ").title())


def main():
    args = parse_args()
    print("[Reporting Agent] Starting reporting workflow...")
    print(f"[Reporting Agent] Input directory: {args.input_dir}")
    print(f"[Reporting Agent] Output directory: {args.output_dir}")
    print(f"[Reporting Agent] LLM provider: {settings.LLM_PROVIDER if settings.USE_LLM else 'disabled'}")
    print(f"[Reporting Agent] LLM model: {settings.selected_llm_model() if settings.USE_LLM else 'not used'}")

    if args.no_cache:
        settings.LLM_CACHE_ENABLED = False
    inputs, warnings = load_reporting_inputs(args.input_dir)
    _print_loaded_sources(inputs, warnings)

    context = build_context(inputs, warnings, output_dir=args.output_dir)
    context["report_detail_level"] = args.detail_level
    context = enhance_export_context(context, ticket=None)
    generated = render_reports(context, output_dir=args.output_dir)
    reporting_result = write_outputs(context, generated, output_dir=args.output_dir)
    postgres_used, postgres_status = try_store_postgres(reporting_result, context)
    reporting_result["postgres_used"] = postgres_used
    _add_postgres_display_fields(reporting_result, postgres_status)
    write_json(args.output_dir / context["incident_id"] / "reporting_result.json", reporting_result)

    llm_enhancement = calculate_llm_enhancement_score(context.get("llm_section_results", {}), context.get("llm_status", "not_recorded"))

    print("\n[Reporting Agent] Reports generated.")
    print(f"[Reporting Agent] Incident ID: {context['incident_id']}")

    _print_status("Final report status", "report", context["report_status"])
    _print_status("Validation status", "validation", context["validation_status"])
    _print_status("Data consistency status", "data_consistency", context.get("data_consistency_status", "passed"))
    if context.get("data_consistency", {}).get("issues"):
        print("[Reporting Agent] Data consistency issues:")
        for issue in context.get("data_consistency", {}).get("issues", []):
            print(f"- {issue.get('field')}: {issue.get('issue')} | details: {issue.get('details')}")

    recovered_count = len(context.get("recovered_fields", []))
    if recovered_count:
        print(f"[Reporting Agent] Context recovery: {recovered_count} field(s) recovered from earlier agent outputs")
        for item in context.get("recovered_fields", []):
            print(f"- {item.get('field')}: recovered from {item.get('recovered_from')} ({item.get('reason')})")
    else:
        print("[Reporting Agent] Context recovery: No missing fields needed recovery")

    print(f"[Reporting Agent] Report completeness score: {context.get('report_quality_score', 'not recorded')}/100")
    _print_status("Report completeness status", "quality", context.get("report_quality_status", "not_recorded"))

    _print_status("RAG status", "rag", context["rag_status"])
    _print_status("LLM enhancement status", "llm", context["llm_status"])
    print(f"[Reporting Agent] LLM selected provider/model: {context.get('llm_provider', 'not used')} / {context.get('llm_model', 'not used')}")
    print(f"[Reporting Agent] LLM attempts: {context.get('llm_attempt_count', 'not recorded')}")
    print(f"[Reporting Agent] LLM enhancement score: {llm_enhancement['score']}/100")
    _print_status("LLM cache status", "cache", context.get("llm_cache_status", "not_recorded"))
    _print_status("PostgreSQL storage status", "postgresql", postgres_status)

    if context.get("llm_section_results"):
        print("[Reporting Agent] LLM section results:")
        for section, result in context["llm_section_results"].items():
            status = result.get("status", "not_recorded") if isinstance(result, dict) else str(result)
            status_meta = get_status_metadata("llm_section", status)
            hard = result.get("hard_fail_issues", []) if isinstance(result, dict) else []
            soft = result.get("soft_warnings", []) if isinstance(result, dict) else []
            repairs = result.get("repair_actions", []) if isinstance(result, dict) else []
            detail = []
            if repairs:
                detail.append("repairs: " + ", ".join(repairs))
            if hard:
                detail.append("hard issues: " + ", ".join(hard))
            if soft:
                detail.append("warnings: " + ", ".join(soft))
            suffix = f" ({'; '.join(detail)})" if detail else ""
            readable_section = section.replace("_", " ").title()
            print(f"- {readable_section}: {status_meta['display']}{suffix}")

    if context["missing_required_fields"]:
        print("[Reporting Agent] Missing required fields:")
        for field in context["missing_required_fields"]:
            print(f"- {field}")

    print("[Reporting Agent] Generated reports:")
    for name, path in generated.items():
        print(f"- {_friendly_report_name(name)}: {path}")
    print(f"- Reporting result JSON: {args.output_dir / context['incident_id'] / 'reporting_result.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
