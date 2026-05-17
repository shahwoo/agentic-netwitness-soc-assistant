import json
import os
from typing import Any, Dict, List, Optional

import requests


INPUT_FILE = "outputs/orchestration_decision.json"
OUTPUT_FILE = "outputs/triage_result.json"

OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "hf.co/Mungert/Foundation-Sec-8B-Instruct-GGUF:Q4_K_M"


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


def get_threat_intel_notes(case_data: Dict[str, Any]) -> List[str]:
    threat_intel = case_data.get("threat_intelligence", {})
    notes = threat_intel.get("notes", [])

    if isinstance(notes, list):
        return notes

    return []


def call_local_llm(prompt: str) -> str:
    payload = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.2,
            "num_predict": 150
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


def determine_likely_scenario(case_data: Dict[str, Any]) -> str:
    alert_title = case_data.get("alert_title", "").lower()
    alert_type = case_data.get("alert_type", "").lower()
    possible_file_name = case_data.get("possible_file_name", "Not available")
    enrichment_risk_level = case_data.get("enrichment_risk_level", "Low")

    if "potential malicious file" in alert_title:
        return "Possible endpoint malware execution"

    if possible_file_name.lower().endswith((".exe", ".dll", ".ps1", ".bat", ".cmd", ".vbs", ".js")):
        return "Suspicious executable or script detected on endpoint"

    if enrichment_risk_level == "High":
        return "Potential malicious activity supported by external threat intelligence"

    if "endpoint" in alert_type:
        return "Endpoint security alert requiring triage"

    return "Unclear security scenario"


def classify_alert(case_data: Dict[str, Any], likely_scenario: str) -> str:
    alert_title = case_data.get("alert_title", "").lower()
    enrichment_risk_level = case_data.get("enrichment_risk_level", "Low")

    if "potential malicious file" in alert_title:
        return "Potential malicious executable detected"

    if enrichment_risk_level == "High":
        return "Threat intelligence supported suspicious activity"

    if likely_scenario == "Suspicious executable or script detected on endpoint":
        return "Suspicious endpoint file activity"

    if likely_scenario == "Endpoint security alert requiring triage":
        return "Endpoint security alert"

    return "Unclassified security alert"


def assign_severity(case_data: Dict[str, Any]) -> str:
    incident_priority = case_data.get("incident_priority", "Unknown")
    incident_risk_score = case_data.get("incident_risk_score", 0)
    enrichment_risk_level = case_data.get("enrichment_risk_level", "Low")
    enrichment_risk_score = case_data.get("enrichment_risk_score", 0)

    if enrichment_risk_level == "High" or enrichment_risk_score >= 70:
        return "Critical"

    if incident_priority == "Critical" or incident_risk_score >= 80:
        return "Critical"

    if incident_priority == "High" or incident_risk_score >= 50:
        return "High"

    if incident_priority == "Medium" or incident_risk_score >= 30:
        return "Medium"

    return "Low"


def assign_confidence(case_data: Dict[str, Any], severity: str) -> str:
    file_hash = case_data.get("file_hash")
    source_ip = case_data.get("source_ip")
    destination_ip = case_data.get("destination_ip")
    event_domain = case_data.get("event_domain")
    enrichment_risk_level = case_data.get("enrichment_risk_level", "Low")
    possible_file_name = case_data.get("possible_file_name", "Not available")

    evidence_count = 0

    if possible_file_name != "Not available":
        evidence_count += 1

    if file_hash:
        evidence_count += 1

    if source_ip and source_ip not in ["Not available", "Unknown", ""]:
        evidence_count += 1

    if destination_ip and destination_ip not in ["Not available", "Unknown", ""]:
        evidence_count += 1

    if event_domain and event_domain not in ["Not available", "Unknown", ""]:
        evidence_count += 1

    if enrichment_risk_level in ["Medium", "High"]:
        evidence_count += 1

    if severity in ["Critical", "High"] and evidence_count >= 3:
        return "High"

    if severity in ["Critical", "High"] and evidence_count >= 1:
        return "Medium"

    if evidence_count >= 2:
        return "Medium"

    return "Low"


def recommend_playbook(likely_scenario: str, classification: str) -> str:
    if likely_scenario == "Possible endpoint malware execution":
        return "Endpoint Malware Investigation Playbook"

    if classification == "Potential malicious executable detected":
        return "Endpoint Malware Investigation Playbook"

    if classification == "Suspicious endpoint file activity":
        return "Suspicious File Investigation Playbook"

    if classification == "Threat intelligence supported suspicious activity":
        return "Threat Intelligence Enrichment Review Playbook"

    if likely_scenario == "Endpoint security alert requiring triage":
        return "General Endpoint Investigation Playbook"

    return "General Security Alert Investigation Playbook"


def recommend_containment(severity: str, confidence: str) -> Dict[str, Any]:
    if severity == "Critical" and confidence in ["Medium", "High"]:
        return {
            "containment_required": True,
            "containment_action": "Recommend endpoint isolation",
            "approval_required": True,
            "reason": "Critical severity with sufficient confidence requires SOC Analyst approval before containment."
        }

    if severity == "High":
        return {
            "containment_required": True,
            "containment_action": "Prepare endpoint isolation or enhanced monitoring recommendation",
            "approval_required": True,
            "reason": "High severity alert should be reviewed by SOC Analyst before containment."
        }

    if severity == "Medium":
        return {
            "containment_required": False,
            "containment_action": "Monitor endpoint and collect additional evidence",
            "approval_required": False,
            "reason": "Medium severity does not require immediate containment."
        }

    return {
        "containment_required": False,
        "containment_action": "No immediate containment required",
        "approval_required": False,
        "reason": "Low severity alert does not require immediate containment."
    }


def decide_next_action(severity: str, confidence: str) -> str:
    if severity in ["Critical", "High"]:
        return "Send to Investigation Agent"

    if severity == "Medium" and confidence == "Low":
        return "Review by SOC Analyst"

    if severity == "Medium":
        return "Generate triage summary"

    return "Close or monitor case"


def build_rule_based_reasoning_summary(
    case_data: Dict[str, Any],
    likely_scenario: str,
    classification: str,
    severity: str,
    confidence: str
) -> str:
    incident_priority = case_data.get("incident_priority", "Unknown")
    incident_risk_score = case_data.get("incident_risk_score", 0)
    possible_file_name = case_data.get("possible_file_name", "Not available")
    alert_source = case_data.get("alert_source", "Unknown")
    enrichment_risk_level = case_data.get("enrichment_risk_level", "Low")
    enrichment_risk_score = case_data.get("enrichment_risk_score", 0)

    return (
        f"The alert is classified as '{classification}' with likely scenario '{likely_scenario}'. "
        f"The alert source is {alert_source}. "
        f"The suspicious file is {possible_file_name}. "
        f"The incident priority is {incident_priority} with risk score {incident_risk_score}. "
        f"The enrichment risk level is {enrichment_risk_level} with score {enrichment_risk_score}. "
        f"Based on these factors, severity is assigned as {severity} and confidence as {confidence}."
    )


def build_llm_triage_prompt(case_data: Dict[str, Any], rule_result: Dict[str, Any]) -> str:
    incident_id = case_data.get("incident_id")
    alert_title = case_data.get("alert_title")
    possible_file_name = case_data.get("possible_file_name")
    file_hash = case_data.get("file_hash")
    source_ip = case_data.get("source_ip")
    destination_ip = case_data.get("destination_ip")
    event_domain = case_data.get("event_domain")
    enrichment_risk_level = case_data.get("enrichment_risk_level")
    enrichment_risk_score = case_data.get("enrichment_risk_score")
    enrichment_risk_reasons = case_data.get("enrichment_risk_reasons", [])
    threat_intel_notes = get_threat_intel_notes(case_data)

    return f"""
You are a SOC Triage Assistant.

Explain the triage decision using only the evidence below. Do not invent facts.

Case:
- Incident ID: {incident_id}
- Alert Title: {alert_title}
- Possible File: {possible_file_name}
- File Hash: {file_hash}
- Source IP: {source_ip}
- Destination IP: {destination_ip}
- Domain: {event_domain}
- Enrichment Risk Level: {enrichment_risk_level}
- Enrichment Risk Score: {enrichment_risk_score}
- Enrichment Risk Reasons: {enrichment_risk_reasons}
- Threat Intel Notes: {threat_intel_notes}

Rule-based decision:
- Likely Scenario: {rule_result.get("likely_scenario")}
- Classification: {rule_result.get("classification")}
- Severity: {rule_result.get("severity")}
- Confidence: {rule_result.get("confidence")}
- Recommended Playbook: {rule_result.get("recommended_playbook")}
- Next Action: {rule_result.get("next_action")}

Write a concise SOC analyst triage explanation with:
1. Likely attack scenario
2. Why the severity was assigned
3. Confidence assessment
4. Evidence gaps
5. Recommended investigation focus

Keep it short and practical.
"""


def triage_case(case_data: Dict[str, Any]) -> Dict[str, Any]:
    likely_scenario = determine_likely_scenario(case_data)
    classification = classify_alert(case_data, likely_scenario)
    severity = assign_severity(case_data)
    confidence = assign_confidence(case_data, severity)
    recommended_playbook = recommend_playbook(likely_scenario, classification)
    containment_recommendation = recommend_containment(severity, confidence)
    next_action = decide_next_action(severity, confidence)

    rule_based_reasoning_summary = build_rule_based_reasoning_summary(
        case_data,
        likely_scenario,
        classification,
        severity,
        confidence
    )

    rule_result = {
        "likely_scenario": likely_scenario,
        "classification": classification,
        "severity": severity,
        "confidence": confidence,
        "recommended_playbook": recommended_playbook,
        "next_action": next_action,
        "containment_recommendation": containment_recommendation
    }

    llm_prompt = build_llm_triage_prompt(case_data, rule_result)
    llm_triage_analysis = call_local_llm(llm_prompt)

    triage_result = {
        **case_data,

        "current_stage": "triage_completed",
        "agent_completed": "triage_agent",

        "likely_scenario": likely_scenario,
        "classification": classification,
        "severity": severity,
        "confidence": confidence,
        "recommended_playbook": recommended_playbook,
        "next_action": next_action,
        "containment_recommendation": containment_recommendation,
        "reasoning_summary": rule_based_reasoning_summary,
        "llm_triage_analysis": llm_triage_analysis,

        "triage_result": {
            "incident_id": case_data.get("incident_id"),
            "alert_id": case_data.get("alert_id"),
            "alert_title": case_data.get("alert_title"),

            "likely_scenario": likely_scenario,
            "classification": classification,
            "severity": severity,
            "confidence": confidence,
            "recommended_playbook": recommended_playbook,
            "next_action": next_action,
            "containment_recommendation": containment_recommendation,

            "rule_based_reasoning_summary": rule_based_reasoning_summary,
            "llm_triage_analysis": llm_triage_analysis,

            "threat_intelligence_notes": get_threat_intel_notes(case_data),
            "enrichment_risk_score": case_data.get("enrichment_risk_score"),
            "enrichment_risk_level": case_data.get("enrichment_risk_level"),
            "enrichment_risk_reasons": case_data.get("enrichment_risk_reasons", [])
        }
    }

    return triage_result


def main() -> None:
    if not os.path.exists(INPUT_FILE):
        raise FileNotFoundError(f"Input file not found: {INPUT_FILE}")

    case_context = load_case_context()

    next_agent = case_context.get("next_agent")

    if next_agent and next_agent != "triage_agent":
        print(
            f"Warning: Orchestration decision next_agent is '{next_agent}', "
            "not 'triage_agent'. Continuing for manual test."
        )

    result = triage_case(case_context)
    save_json(result)

    print(json.dumps(result, indent=4))
    print()
    print(f"Triage result saved to: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()