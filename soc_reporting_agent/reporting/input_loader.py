from pathlib import Path
import json
from typing import Any

# Core files are expected for the Reporting Agent. processed_alert.json is optional
# because some versions of the project write directly to enriched_alert.json.
INPUT_FILES = {
    "processed_alert": "processed_alert.json",
    "enriched_alert": "enriched_alert.json",
    "triage_result": "triage_result.json",
    "investigation_result": "investigation_result.json",
    "approval_result": "approval_result.json",
    "ticket_context": "ticket_context.json",
    "grouped_incident_context": "grouped_incident_context.json",
    "correlation_recommendations": "correlation_recommendations.json",
}
OPTIONAL_INPUT_KEYS = {"processed_alert", "approval_result", "ticket_context", "grouped_incident_context", "correlation_recommendations"}


def load_json_file(path: Path, *, required: bool = True) -> tuple[dict[str, Any], str | None]:
    if not path.exists():
        if required:
            return {}, f"Input file missing: {path}"
        return {}, None
    try:
        return json.loads(path.read_text(encoding="utf-8")), None
    except json.JSONDecodeError as error:
        return {}, f"Invalid JSON in {path}: {error}"
    except Exception as error:
        return {}, f"Failed to read {path}: {error}"


def load_reporting_inputs(input_dir: Path) -> tuple[dict[str, dict[str, Any]], list[str]]:
    loaded: dict[str, dict[str, Any]] = {}
    warnings: list[str] = []
    for key, filename in INPUT_FILES.items():
        data, warning = load_json_file(input_dir / filename, required=key not in OPTIONAL_INPUT_KEYS)
        loaded[key] = data
        if warning:
            warnings.append(warning)
    return loaded, warnings
