from pathlib import Path
import json
from typing import Any
INPUT_FILES = {'enriched_alert':'enriched_alert.json','triage_result':'triage_result.json','investigation_result':'investigation_result.json','approval_result':'approval_result.json'}
def load_json_file(path: Path) -> tuple[dict[str, Any], str | None]:
    if not path.exists(): return {}, f'Input file missing: {path}'
    try: return json.loads(path.read_text(encoding='utf-8')), None
    except json.JSONDecodeError as error: return {}, f'Invalid JSON in {path}: {error}'
    except Exception as error: return {}, f'Failed to read {path}: {error}'
def load_reporting_inputs(input_dir: Path) -> tuple[dict[str, dict[str, Any]], list[str]]:
    loaded, warnings = {}, []
    for key, filename in INPUT_FILES.items():
        data, warning = load_json_file(input_dir / filename)
        loaded[key] = data
        if warning: warnings.append(warning)
    return loaded, warnings
