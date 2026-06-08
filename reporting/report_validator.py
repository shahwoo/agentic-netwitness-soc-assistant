from typing import Any
from reporting.schema_normaliser import get_nested
REQUIRED_FIELDS=['incident_id','alert_id','severity.label','confidence.label','classification','likely_scenario','affected_assets','affected_users','iocs','evidence','investigation_summary']
def validate_required_fields(context: dict[str, Any]) -> list[str]:
    missing=[]
    for f in REQUIRED_FIELDS:
        v=get_nested(context,f)
        if v in [None,'',[],{},'Not Provided']: missing.append(f)
    return missing
def build_missing_field_gaps(missing_fields: list[str]) -> list[dict[str,str]]:
    return [{'priority':'High','gap':f'Missing required reporting field: {f}','required_data':f'Provide {f} from enriched alert, triage, investigation, or approval output.'} for f in missing_fields]
