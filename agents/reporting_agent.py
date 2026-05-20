import json
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

import requests


INPUT_FILE = "outputs/orchestration_decision.json"
OUTPUT_FILE = "outputs/report_result.json"

OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "hf.co/Mungert/Foundation-Sec-8B-Instruct-GGUF:Q4_K_M"
REPORT_APPROVAL_TYPE = "report_approval"
LEARNING_UPDATE_APPROVAL_TYPE = "learning_update_approval"
REPORTING_POLICY_REFERENCES = [
    "Appendix J: Post-Incident Inquiry Report Requirements",
    "Appendix K: Reporting and Learning Agent Rules",
    "Appendix M: Audit Log Requirements",
    "Appendix T: Workflow-to-Policy Mapping"
]


def load_case_context() -> Dict[str, Any]:
    with open(INPUT_FILE, "r", encoding="utf-8") as file:
        return json.load(file)


def save_json(data: Dict[str, Any]) -> None:
    os.makedirs("outputs", exist_ok=True)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=4)


def get_nested_value(data: Dict[str, Any], key_path: List[str], fallback: Optional[Any] = None) -> Any:
    current_value = data

    for key in key_path:
        if not isinstance(current_value, dict):
            return fallback

        current_value = current_value.get(key)

        if current_value is None:
            return fallback

    return current_value


def get_list_value(value: Any) -> List[str]:
    if isinstance(value, list):
        return value

    if isinstance(value, str) and value.strip():
        return [value]

    return []


def is_report_field_available(value: Any) -> bool:
    missing_strings = {
        "",
        "unknown",
        "not available",
        "null",
        "none"
    }

    if value is None:
        return False

    if isinstance(value, str):
        return value.strip().lower() not in missing_strings

    if isinstance(value, list):
        return any(is_report_field_available(item) for item in value)

    if isinstance(value, dict):
        if len(value) == 0:
            return False

        if str(value.get("status", "")).strip().lower() == "not_available":
            return False

        return any(is_report_field_available(item) for item in value.values())

    return True


def call_local_llm(prompt: str) -> str:
    payload = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.2,
            "num_predict": 250
        }
    }

    try:
        response = requests.post(OLLAMA_URL, json=payload, timeout=180)
        response.raise_for_status()

        result = response.json()
        llm_response = result.get("response", "").strip()

        if not llm_response:
            return "LLM returned an empty response."

        return llm_response

    except requests.RequestException as error:
        return f"LLM unavailable or failed: {str(error)}"


def build_executive_summary(case_data: Dict[str, Any]) -> str:
    incident_id = case_data.get("incident_id", "UNKNOWN")
    alert_title = case_data.get("alert_title", "No alert title")

    severity = (
        case_data.get("severity")
        or get_nested_value(case_data, ["triage_result", "severity"], "Unknown")
    )

    confidence = (
        case_data.get("confidence")
        or get_nested_value(case_data, ["triage_result", "confidence"], "Unknown")
    )

    likely_scenario = (
        case_data.get("likely_scenario")
        or get_nested_value(case_data, ["triage_result", "likely_scenario"], "Unknown scenario")
    )

    possible_file_name = case_data.get("possible_file_name", "Not available")
    enrichment_risk_level = case_data.get("enrichment_risk_level", "Unknown")

    return (
        f"Incident {incident_id} was assessed as {severity} severity with {confidence} confidence. "
        f"The likely scenario is {likely_scenario}. The alert is titled '{alert_title}', involving the suspicious file "
        f"{possible_file_name}. Threat intelligence enrichment risk is {enrichment_risk_level}. "
        f"The case should be reviewed by a SOC Analyst before report approval or closure."
    )


def build_technical_summary(case_data: Dict[str, Any]) -> str:
    incident_priority = case_data.get("incident_priority", "Unknown")
    incident_risk_score = case_data.get("incident_risk_score", "Unknown")
    alert_source = case_data.get("alert_source", "Unknown")
    alert_type = case_data.get("alert_type", "Unknown")
    event_domain = case_data.get("event_domain", "Unknown")
    enrichment_risk_level = case_data.get("enrichment_risk_level", "Unknown")
    enrichment_risk_score = case_data.get("enrichment_risk_score", "Unknown")

    investigation_summary = (
        case_data.get("investigation_summary")
        or get_nested_value(case_data, ["investigation_result", "investigation_summary"], "No investigation summary available.")
    )

    return (
        f"The alert originated from {alert_source} and is categorised as {alert_type}. "
        f"The incident priority is {incident_priority}, with an incident risk score of {incident_risk_score}. "
        f"The associated domain is {event_domain}. Threat intelligence enrichment produced a risk level of "
        f"{enrichment_risk_level} with score {enrichment_risk_score}. "
        f"Investigation summary: {investigation_summary}"
    )


def collect_key_findings(case_data: Dict[str, Any]) -> List[str]:
    findings = []

    findings.append(
        f"Likely scenario: {case_data.get('likely_scenario') or get_nested_value(case_data, ['triage_result', 'likely_scenario'], 'Unknown')}."
    )
    findings.append(
        f"Classification: {case_data.get('classification') or get_nested_value(case_data, ['triage_result', 'classification'], 'Unknown')}."
    )
    findings.append(
        f"Severity: {case_data.get('severity') or get_nested_value(case_data, ['triage_result', 'severity'], 'Unknown')}."
    )
    findings.append(
        f"Confidence: {case_data.get('confidence') or get_nested_value(case_data, ['triage_result', 'confidence'], 'Unknown')}."
    )

    investigation_findings = (
        case_data.get("key_findings")
        or get_nested_value(case_data, ["investigation_result", "key_findings"], [])
    )

    findings.extend(get_list_value(investigation_findings))

    if len(findings) == 0:
        findings.append("No key findings were available.")

    return findings


def collect_missing_evidence(case_data: Dict[str, Any]) -> List[str]:
    missing_evidence = (
        case_data.get("missing_evidence")
        or get_nested_value(case_data, ["investigation_result", "missing_evidence"], [])
    )

    missing_evidence = get_list_value(missing_evidence)

    if len(missing_evidence) == 0:
        missing_evidence.append("No missing evidence was explicitly recorded.")

    return missing_evidence


def collect_recommended_actions(case_data: Dict[str, Any]) -> List[str]:
    actions = (
        case_data.get("recommended_actions")
        or get_nested_value(case_data, ["investigation_result", "recommended_actions"], [])
    )

    actions = get_list_value(actions)

    containment = (
        case_data.get("containment_recommendation")
        or get_nested_value(case_data, ["triage_result", "containment_recommendation"], {})
    )

    if isinstance(containment, dict):
        containment_action = containment.get("containment_action")
        approval_required = containment.get("approval_required")

        if containment_action:
            if approval_required:
                actions.append(
                    f"Containment recommendation: {containment_action}. SOC Analyst approval is required before execution."
                )
            else:
                actions.append(f"Containment recommendation: {containment_action}.")

    if len(actions) == 0:
        actions.append("No recommended actions were available.")

    return actions


def collect_threat_intelligence_summary(case_data: Dict[str, Any]) -> Dict[str, Any]:
    threat_intel = case_data.get("threat_intelligence", {})

    if not isinstance(threat_intel, dict):
        return {
            "status": "not_available",
            "summary": ["Threat intelligence data is not available."]
        }

    virustotal = threat_intel.get("virustotal", {})
    abuseipdb = threat_intel.get("abuseipdb", {})
    alienvault_otx = threat_intel.get("alienvault_otx", {})
    notes = threat_intel.get("notes", [])

    summary = []

    vt_file = virustotal.get("file_hash", {})

    if isinstance(vt_file, dict):
        if vt_file.get("status") == "completed":
            summary.append(
                f"VirusTotal file result: {vt_file.get('malicious', 0)} malicious, "
                f"{vt_file.get('suspicious', 0)} suspicious detections."
            )
        elif vt_file.get("status") == "skipped":
            summary.append(f"VirusTotal file lookup skipped: {vt_file.get('reason')}")

    for result in virustotal.get("ip_results", []):
        summary.append(
            f"VirusTotal IP result for {result.get('indicator')}: "
            f"{result.get('malicious', 0)} malicious, {result.get('suspicious', 0)} suspicious."
        )

    for result in virustotal.get("domain_results", []):
        summary.append(
            f"VirusTotal domain result for {result.get('indicator')}: "
            f"{result.get('malicious', 0)} malicious, {result.get('suspicious', 0)} suspicious."
        )

    for result in abuseipdb.get("ip_results", []):
        summary.append(
            f"AbuseIPDB result for {result.get('indicator')}: abuse confidence score "
            f"{result.get('abuse_confidence_score')}."
        )

    for result in alienvault_otx.get("otx_results", []):
        if result.get("status") == "completed":
            summary.append(
                f"AlienVault OTX result for {result.get('indicator')}: "
                f"{result.get('pulse_count', 0)} related pulse(s)."
            )
        elif result.get("status") == "error":
            summary.append(
                f"AlienVault OTX lookup error for {result.get('indicator')}: {result.get('reason')}"
            )

    summary.extend(get_list_value(notes))

    if len(summary) == 0:
        summary.append("No threat intelligence summary was available.")

    return {
        "status": "available",
        "summary": summary
    }


def build_timeline(case_data: Dict[str, Any]) -> List[Dict[str, str]]:
    timeline = []

    incident_created_time = case_data.get("incident_created_time")
    first_alert_time = case_data.get("incident_first_alert_time")
    alert_created_time = case_data.get("alert_created_time")
    incident_history_date = case_data.get("incident_history_date")

    if first_alert_time:
        timeline.append({
            "time": first_alert_time,
            "event": "First alert observed."
        })

    if alert_created_time:
        timeline.append({
            "time": alert_created_time,
            "event": "Alert item created."
        })

    if incident_created_time:
        timeline.append({
            "time": incident_created_time,
            "event": "Incident created in NetWitness."
        })

    if incident_history_date:
        timeline.append({
            "time": incident_history_date,
            "event": "Incident history recorded."
        })

    if len(timeline) == 0:
        timeline.append({
            "time": "Unknown",
            "event": "No timeline information available."
        })

    return timeline


def build_soc_approval_section(case_data: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "approval_required": True,
        "approval_type": REPORT_APPROVAL_TYPE,
        "approval_status": "pending",
        "approval_question": "Does the SOC Analyst approve this incident report?",
        "approval_options": [
            "approved",
            "rejected",
            "changes_required",
            "more_investigation_required"
        ],
        "soc_analyst_comments": None
    }


def build_containment_summary(case_data: Dict[str, Any]) -> Dict[str, Any]:
    containment_recommendation = (
        case_data.get("containment_recommendation")
        or get_nested_value(case_data, ["triage_result", "containment_recommendation"], {})
        or get_nested_value(case_data, ["investigation_result", "containment_recommendation"], {})
    )

    containment_decision = (
        case_data.get("containment_decision")
        or get_nested_value(case_data, ["triage_result", "containment_decision"], {})
        or get_nested_value(case_data, ["investigation_result", "containment_decision"], {})
    )

    if not isinstance(containment_recommendation, dict):
        containment_recommendation = {}

    if not isinstance(containment_decision, dict):
        containment_decision = {}

    containment_required = containment_recommendation.get("containment_required", False)
    containment_action = containment_recommendation.get("containment_action", "No immediate containment required")
    approval_required = containment_recommendation.get("approval_required", False)
    approval_status = (
        containment_decision.get("soc_analyst_approval_status")
        or containment_decision.get("containment_approval_status")
        or case_data.get("containment_approval_status")
    )
    containment_status = (
        containment_decision.get("containment_status")
        or case_data.get("containment_status")
    )
    containment_outcome = (
        containment_decision.get("containment_outcome")
        or case_data.get("containment_outcome")
    )

    if not approval_status:
        approval_status = "pending" if approval_required else "not_required"

    if not containment_status:
        containment_status = "pending_approval" if approval_required else "not_required"

    if not containment_outcome:
        containment_outcome = (
            "Pending SOC Analyst approval"
            if approval_required
            else "No containment approval is required at this reporting stage"
        )

    return {
        "containment_required": containment_required,
        "containment_action": containment_action,
        "approval_required": approval_required,
        "approval_status": approval_status,
        "execution_status": case_data.get("containment_execution_status", "not_executed"),
        "containment_outcome": containment_outcome,
        "policy_reference": [
            "Appendix G: Human Approval and Containment Rules",
            "Appendix U: Containment Action Playbook",
            "Appendix T: Workflow-to-Policy Mapping"
        ]
    }


def build_learning_update_draft(
    case_data: Dict[str, Any],
    report_data: Dict[str, Any]
) -> Dict[str, Any]:
    return {
        "learning_update_status": "draft_prepared",
        "approval_required": True,
        "approval_type": LEARNING_UPDATE_APPROVAL_TYPE,
        "learning_update_note": (
            "Learning update draft prepared. SOC learning approval should only be "
            "requested after report approval."
        ),
        "playbook_gaps": get_list_value(case_data.get("playbook_gaps")),
        "scoring_biases": get_list_value(case_data.get("scoring_biases")),
        "recommended_learning_points": get_list_value(
            case_data.get("recommended_learning_points")
            or report_data.get("investigation_summary", {}).get("missing_evidence")
        ),
        "chroma_storage_allowed": False
    }


def check_report_completeness(report_data: Dict[str, Any]) -> Dict[str, Any]:
    required_fields = {
        "incident_id": report_data.get("incident_id"),
        "alert_id": report_data.get("alert_id"),
        "severity": get_nested_value(report_data, ["triage_summary", "severity"]),
        "confidence": get_nested_value(report_data, ["triage_summary", "confidence"]),
        "triage_summary": report_data.get("triage_summary"),
        "investigation_summary": report_data.get("investigation_summary", {}).get("summary"),
        "key_findings": report_data.get("investigation_summary", {}).get("key_findings"),
        "missing_evidence": report_data.get("investigation_summary", {}).get("missing_evidence"),
        "recommended_actions": report_data.get("investigation_summary", {}).get("recommended_actions"),
        "threat_intelligence_summary": report_data.get("threat_intelligence_summary"),
        "timeline": report_data.get("timeline"),
        "soc_approval": report_data.get("soc_approval")
    }

    missing_report_fields = [
        field_name
        for field_name, field_value in required_fields.items()
        if not is_report_field_available(field_value)
    ]

    report_status = "draft_ready" if len(missing_report_fields) == 0 else "missing_information_required"

    return {
        "is_complete": len(missing_report_fields) == 0,
        "missing_report_fields": missing_report_fields,
        "report_status": report_status
    }


def build_reporting_audit_record(
    case_data: Dict[str, Any],
    report_status: str,
    current_stage: str,
    next_action: str,
    report_completeness: Dict[str, Any]
) -> Dict[str, Any]:
    incident_id = case_data.get("incident_id", "UNKNOWN")
    decision_made = (
        "prepare_report_for_approval"
        if report_completeness.get("is_complete")
        else "request_missing_report_information"
    )

    return {
        "audit_id": f"AUDIT-{incident_id}-REPORTING-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
        "incident_id": case_data.get("incident_id"),
        "alert_id": case_data.get("alert_id"),
        "agent_name": "reporting_agent",
        "decision_point": "Reporting Agent report completeness and approval preparation",
        "decision_made": decision_made,
        "current_stage": current_stage,
        "report_status": report_status,
        "approval_type": REPORT_APPROVAL_TYPE,
        "human_review_required": report_completeness.get("is_complete", False),
        "policy_reference": REPORTING_POLICY_REFERENCES,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "input_summary": {
            "incident_id": case_data.get("incident_id"),
            "alert_id": case_data.get("alert_id"),
            "severity": (
                case_data.get("severity")
                or get_nested_value(case_data, ["triage_result", "severity"])
            ),
            "confidence": (
                case_data.get("confidence")
                or get_nested_value(case_data, ["triage_result", "confidence"])
            ),
            "previous_stage": case_data.get("current_stage"),
            "previous_agent": case_data.get("agent_completed"),
            "missing_report_fields": report_completeness.get("missing_report_fields", []),
            "next_action": next_action
        }
    }


def build_llm_report_prompt(
    case_data: Dict[str, Any],
    executive_summary: str,
    technical_summary: str,
    key_findings: List[str],
    missing_evidence: List[str],
    recommended_actions: List[str],
    threat_intelligence_summary: Dict[str, Any]
) -> str:
    selected_findings = key_findings[:6]
    selected_missing = missing_evidence[:5]
    selected_actions = recommended_actions[:6]
    selected_ti = threat_intelligence_summary.get("summary", [])[:6]

    return f"""
You are a SOC Reporting Assistant.

Using only the evidence below, write a concise SOC incident report draft.

Case:
- Incident ID: {case_data.get("incident_id")}
- Alert Title: {case_data.get("alert_title")}
- Severity: {case_data.get("severity") or get_nested_value(case_data, ["triage_result", "severity"])}
- Confidence: {case_data.get("confidence") or get_nested_value(case_data, ["triage_result", "confidence"])}
- Likely Scenario: {case_data.get("likely_scenario") or get_nested_value(case_data, ["triage_result", "likely_scenario"])}
- Suspicious File: {case_data.get("possible_file_name")}
- File Hash: {case_data.get("file_hash")}
- Domain: {case_data.get("event_domain")}

Rule-based executive summary:
{executive_summary}

Rule-based technical summary:
{technical_summary}

Key findings:
{selected_findings}

Missing evidence:
{selected_missing}

Threat intelligence summary:
{selected_ti}

Recommended actions:
{selected_actions}

Write the report in these sections:
1. Executive summary
2. Technical findings
3. Evidence gaps
4. Recommended actions
5. SOC Analyst approval note

Keep it concise and practical.
"""


def generate_report(case_data: Dict[str, Any]) -> Dict[str, Any]:
    generated_at = datetime.utcnow().isoformat() + "Z"

    executive_summary = build_executive_summary(case_data)
    technical_summary = build_technical_summary(case_data)
    key_findings = collect_key_findings(case_data)
    missing_evidence = collect_missing_evidence(case_data)
    recommended_actions = collect_recommended_actions(case_data)
    threat_intelligence_summary = collect_threat_intelligence_summary(case_data)
    timeline = build_timeline(case_data)
    soc_approval = build_soc_approval_section(case_data)
    containment_summary = build_containment_summary(case_data)

    llm_prompt = build_llm_report_prompt(
        case_data,
        executive_summary,
        technical_summary,
        key_findings,
        missing_evidence,
        recommended_actions,
        threat_intelligence_summary
    )

    llm_report_draft = call_local_llm(llm_prompt)

    report = {
        "report_title": f"SOC Incident Report: {case_data.get('incident_id', 'UNKNOWN')}",
        "generated_at": generated_at,
        "incident_id": case_data.get("incident_id"),
        "alert_id": case_data.get("alert_id"),
        "approval_type": REPORT_APPROVAL_TYPE,
        "report_status": "draft_ready",

        "executive_summary": executive_summary,
        "technical_summary": technical_summary,
        "llm_report_draft": llm_report_draft,

        "case_overview": {
            "incident_title": case_data.get("incident_title"),
            "alert_title": case_data.get("alert_title"),
            "incident_priority": case_data.get("incident_priority"),
            "incident_risk_score": case_data.get("incident_risk_score"),
            "alert_source": case_data.get("alert_source"),
            "alert_type": case_data.get("alert_type"),
            "event_domain": case_data.get("event_domain"),
            "possible_file_name": case_data.get("possible_file_name"),
            "file_hash": case_data.get("file_hash")
        },

        "triage_summary": {
            "likely_scenario": (
                case_data.get("likely_scenario")
                or get_nested_value(case_data, ["triage_result", "likely_scenario"])
            ),
            "classification": (
                case_data.get("classification")
                or get_nested_value(case_data, ["triage_result", "classification"])
            ),
            "severity": (
                case_data.get("severity")
                or get_nested_value(case_data, ["triage_result", "severity"])
            ),
            "confidence": (
                case_data.get("confidence")
                or get_nested_value(case_data, ["triage_result", "confidence"])
            ),
            "recommended_playbook": (
                case_data.get("recommended_playbook")
                or get_nested_value(case_data, ["triage_result", "recommended_playbook"])
            ),
            "next_action": (
                case_data.get("next_action")
                or get_nested_value(case_data, ["triage_result", "next_action"])
            )
        },

        "investigation_summary": {
            "investigation_status": (
                case_data.get("investigation_status")
                or get_nested_value(case_data, ["investigation_result", "investigation_status"])
            ),
            "summary": (
                case_data.get("investigation_summary")
                or get_nested_value(case_data, ["investigation_result", "investigation_summary"])
            ),
            "llm_investigation_analysis": (
                case_data.get("llm_investigation_analysis")
                or get_nested_value(case_data, ["investigation_result", "llm_investigation_analysis"])
            ),
            "key_findings": key_findings,
            "missing_evidence": missing_evidence,
            "recommended_actions": recommended_actions
        },

        "threat_intelligence_summary": threat_intelligence_summary,
        "timeline": timeline,
        "soc_approval": soc_approval,
        "containment_summary": containment_summary,
        "correction_status": "not_requested",
        "soc_analyst_comments": None,
        "revision_count": 0
    }

    report["learning_update"] = build_learning_update_draft(case_data, report)

    report_completeness = check_report_completeness(report)
    report_status = report_completeness["report_status"]
    current_stage = "report_completed" if report_completeness["is_complete"] else "report_incomplete"
    next_action = (
        "Send to SOC Analyst Approval"
        if report_completeness["is_complete"]
        else "Request missing information"
    )

    report["report_status"] = report_status

    reporting_audit_record = build_reporting_audit_record(
        case_data,
        report_status,
        current_stage,
        next_action,
        report_completeness
    )

    report_result = {
        **case_data,

        "current_stage": current_stage,
        "agent_completed": "reporting_agent",
        "approval_type": REPORT_APPROVAL_TYPE,
        "report_status": report_status,
        "report_completeness": report_completeness,
        "draft_report": report,
        "reporting_audit_record": reporting_audit_record,

        "report_result": {
            "incident_id": case_data.get("incident_id"),
            "alert_id": case_data.get("alert_id"),
            "approval_type": REPORT_APPROVAL_TYPE,
            "report_status": report_status,
            "generated_at": generated_at,
            "approval_required": report["soc_approval"]["approval_required"],
            "report_completeness": report_completeness,
            "next_action": next_action
        },

        "next_action": next_action
    }

    return report_result


def main() -> None:
    if not os.path.exists(INPUT_FILE):
        raise FileNotFoundError(f"Input file not found: {INPUT_FILE}")

    case_context = load_case_context()

    next_agent = case_context.get("next_agent")

    if next_agent and next_agent != "reporting_agent":
        print(
            f"Warning: Orchestration decision next_agent is '{next_agent}', "
            "not 'reporting_agent'. Continuing for manual test."
        )

    result = generate_report(case_context)
    save_json(result)

    print(json.dumps(result, indent=4))
    print()
    print(f"Report result saved to: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
