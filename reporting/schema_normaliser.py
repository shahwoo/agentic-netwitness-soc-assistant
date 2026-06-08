import re
from typing import Any
def get_nested(data: dict[str, Any], path: str, default: Any=None) -> Any:
    cur=data
    for part in path.split('.'):
        if isinstance(cur, dict) and part in cur: cur=cur[part]
        else: return default
    return cur
def first_present(*values: Any, fallback: Any='Not Provided') -> Any:
    for v in values:
        if v not in [None,'',[],{}]: return v
    return fallback
def to_list(value: Any) -> list[Any]:
    if value is None: return []
    return value if isinstance(value, list) else [value]
def yes_no(value: Any) -> str:
    if value is True: return 'Yes'
    if value is False: return 'No'
    if value in [None,'']: return 'Not Provided'
    return str(value)
def classify_ioc(value: str) -> str:
    value=str(value)
    if value.startswith(('http://','https://','hxxp://','hxxps://')): return 'URL'
    if re.fullmatch(r'\d{1,3}(\.\d{1,3}){3}', value): return 'IP Address'
    if re.fullmatch(r'[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}', value): return 'File Hash'
    if '@' in value: return 'Email Address'
    if '.' in value: return 'Domain'
    return 'Indicator'
def normalise_severity(triage, investigation, recovered_fields):
    triage_sev=first_present(get_nested(triage,'triage.severity'), triage.get('severity'), fallback=None)
    inv_sev=first_present(investigation.get('updated_severity'), investigation.get('severity'), fallback=None)
    value=triage_sev if triage_sev is not None else inv_sev
    if triage_sev is not None and inv_sev in [None,'',{},[]]: recovered_fields.append({'field':'severity','recovered_from':'triage_result.json','reason':'Investigation output did not explicitly provide severity.'})
    if isinstance(value, dict): return {'label':first_present(value.get('label'), value.get('severity')), 'score':first_present(value.get('score')), 'reason':first_present(value.get('reason'), value.get('severity_reason'))}
    return {'label':first_present(value), 'score':first_present(triage.get('risk_score'), investigation.get('severity_score')), 'reason':first_present(triage.get('severity_reason'), investigation.get('severity_change_reason'))}
def normalise_confidence(triage, investigation, recovered_fields):
    triage_conf=first_present(get_nested(triage,'triage.confidence'), triage.get('confidence'), fallback=None)
    inv_conf=first_present(investigation.get('updated_confidence'), investigation.get('confidence'), fallback=None)
    value=triage_conf if triage_conf is not None else inv_conf
    if triage_conf is not None and inv_conf in [None,'',{},[]]: recovered_fields.append({'field':'confidence','recovered_from':'triage_result.json','reason':'Investigation output did not explicitly provide confidence.'})
    if isinstance(value, dict): return {'label':first_present(value.get('label'), value.get('confidence')), 'score':first_present(value.get('score')), 'reason':first_present(value.get('reason'), value.get('confidence_reason'))}
    return {'label':first_present(value), 'score':first_present(triage.get('confidence_score'), investigation.get('confidence_score')), 'reason':first_present(triage.get('confidence_reason'), investigation.get('confidence_change_reason'))}
def normalise_asset(asset):
    if isinstance(asset, dict):
        return {'hostname':first_present(asset.get('hostname'),asset.get('host'),asset.get('name')), 'ip_address':first_present(asset.get('ip_address'),asset.get('ip'),asset.get('host_ip')), 'asset_type':first_present(asset.get('asset_type'),asset.get('type')), 'criticality':first_present(asset.get('criticality'),asset.get('asset_criticality')), 'owner':first_present(asset.get('owner'),asset.get('business_owner')), 'business_function':first_present(asset.get('business_function'),asset.get('role')), 'isolation_status':yes_no(first_present(asset.get('isolation_status'), fallback='Not Provided'))}
    return {'hostname':str(asset),'ip_address':'Not Provided','asset_type':'Not Provided','criticality':'Not Provided','owner':'Not Provided','business_function':'Not Provided','isolation_status':'Not Provided'}
def normalise_user(user):
    if isinstance(user, dict):
        groups=user.get('group_memberships', [])
        return {'username':first_present(user.get('username'),user.get('email'),user.get('name')), 'email':first_present(user.get('email'),user.get('username')), 'role':first_present(user.get('role'),user.get('user_role')), 'privilege_level':first_present(user.get('privilege_level'),user.get('privilege')), 'groups':groups if isinstance(groups,list) else [str(groups)], 'mfa_status':first_present(user.get('mfa_status'),user.get('mfa')), 'account_status':first_present(user.get('account_status'),user.get('status'))}
    text=str(user); return {'username':text,'email':text if '@' in text else 'Not Provided','role':'Not Provided','privilege_level':'Not Provided','groups':[],'mfa_status':'Not Provided','account_status':'Not Provided'}
def normalise_ioc(ioc, source):
    if isinstance(ioc, dict):
        val=first_present(ioc.get('value'), ioc.get('ioc'), ioc.get('indicator'))
        return {'value':val,'type':first_present(ioc.get('type'), ioc.get('ioc_type'), fallback=classify_ioc(val)), 'reputation':first_present(ioc.get('reputation'), ioc.get('verdict'), ioc.get('risk_level')), 'confidence':first_present(ioc.get('confidence'), ioc.get('confidence_level')), 'source':first_present(ioc.get('source'), fallback=source), 'evidence_refs':to_list(ioc.get('evidence_refs', []))}
    val=str(ioc); return {'value':val,'type':classify_ioc(val),'reputation':'Not Provided','confidence':'Not Provided','source':source,'evidence_refs':[]}
def normalise_evidence(evidence, index):
    if isinstance(evidence, dict):
        return {'id':first_present(evidence.get('id'), evidence.get('evidence_id'), fallback=f'EVID-{index:03d}'), 'source':first_present(evidence.get('source')), 'type':first_present(evidence.get('type'), evidence.get('evidence_type')), 'description':first_present(evidence.get('description'), evidence.get('summary'), fallback=str(evidence)), 'timestamp':first_present(evidence.get('timestamp'), evidence.get('time')), 'confidence':first_present(evidence.get('confidence')), 'raw_reference':first_present(evidence.get('raw_reference'), evidence.get('reference'))}
    return {'id':f'EVID-{index:03d}','source':'investigation_result.json','type':'Observation','description':str(evidence),'timestamp':'Not Provided','confidence':'Not Provided','raw_reference':'Not Provided'}
def normalise_action(action, index):
    if isinstance(action, dict):
        return {'priority':first_present(action.get('priority'), fallback=f'P{index}'), 'action':first_present(action.get('action'), action.get('recommendation'), fallback=str(action)), 'owner':first_present(action.get('owner')), 'approval_required':yes_no(action.get('approval_required')), 'rationale':first_present(action.get('rationale'), action.get('reason'))}
    return {'priority':f'P{index}','action':str(action),'owner':'Not Provided','approval_required':'Not Provided','rationale':'Not Provided'}
def combine_iocs(enriched_alert, investigation):
    raw=[]
    for path in ['iocs','extracted_iocs','enrichment.iocs','threat_intelligence.iocs']:
        found=get_nested(enriched_alert,path)
        if found: raw += [(x,'enriched_alert.json') for x in to_list(found)]
    for path in ['iocs','final_iocs','extracted_iocs']:
        found=get_nested(investigation,path)
        if found: raw += [(x,'investigation_result.json') for x in to_list(found)]
    out=[]; seen=set()
    for item, src in raw:
        n=normalise_ioc(item, src); key=(n['type'],n['value'])
        if n['value']!='Not Provided' and key not in seen: out.append(n); seen.add(key)
    return out
