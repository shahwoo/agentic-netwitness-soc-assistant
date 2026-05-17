import json
import os
from typing import Any, Dict, List, Optional

import requests


INPUT_FILE = "outputs/orchestration_decision.json"
OUTPUT_FILE = "outputs/investigation_result.json"

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


def get_list_value(value: Any) -> List[str]:
    if isinstance(value, list):
        return value

    if isinstance(value, str) and value.strip():
        return [value]

    return []


def call_local_llm(prompt: str) -> str:
    payload = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.2,
            "num_predict": 120
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


def collect_available_evidence(case_data: Dict[str, Any]) -> Dict[str, Any]:
    evidence = {
        "incident_id": case_data.get("incident_id"),
        "alert_id": case_data.get("alert_id"),
        "alert_title": case_data.get("alert_title"),
        "alert_source": case_data.get("alert_source"),
        "alert_type": case_data.get("alert_type"),
        "event_domain": case_data.get("event_domain"),
        "possible_file_name": case_data.get("possible_file_name"),
        "file_hash": case_data.get("file_hash"),
        "source_ip": case_data.get("source_ip"),
        "destination_ip": case_data.get("destination_ip"),
        "source_username": case_data.get("source_username"),
        "destination_username": case_data.get("destination_username"),
        "incident_priority": case_data.get("incident_priority"),
        "incident_risk_score": case_data.get("incident_risk_score"),
        "enrichment_risk_score": case_data.get("enrichment_risk_score"),
        "enrichment_risk_level": case_data.get("enrichment_risk_level"),

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
        "containment_recommendation": (
            case_data.get("containment_recommendation")
            or get_nested_value(case_data, ["triage_result", "containment_recommendation"])
        ),
        "threat_intelligence": case_data.get("threat_intelligence", {}),
        "enrichment_risk_reasons": case_data.get("enrichment_risk_reasons", [])
    }

    return evidence


def identify_missing_evidence(evidence: Dict[str, Any]) -> List[str]:
    missing = []

    if not evidence.get("file_hash"):
        missing.append("File hash is missing. Retrieve MD5, SHA1, or SHA256 for the suspicious file.")

    if evidence.get("source_ip") in [None, "", "Not available", "Unknown"]:
        missing.append("Source IP is missing. Retrieve endpoint or network source IP from NetWitness events.")

    if evidence.get("destination_ip") in [None, "", "Not available", "Unknown"]:
        missing.append("Destination IP is missing. Retrieve destination IP or external communication details.")

    if evidence.get("source_username") in [None, "", "Not available", "Unknown"]:
        missing.append("Source username is missing. Identify the logged-in user on the affected endpoint.")

    if evidence.get("possible_file_name") in [None, "", "Not available", "Unknown"]:
        missing.append("Suspicious file name is missing. Retrieve file name and file path from endpoint telemetry.")

    missing.append("Process tree is not available. Retrieve parent process, child processes, and command-line arguments.")
    missing.append("File path is not available. Retrieve the full file location on the endpoint.")
    missing.append("Endpoint hostname is not available. Retrieve the affected endpoint hostname.")
    missing.append("Execution evidence is incomplete. Confirm whether the suspicious file was executed.")
    missing.append("MITRE ATT&CK mapping is not fully available. Map behaviour after endpoint evidence is collected.")

    return missing


def analyse_threat_intelligence(case_data: Dict[str, Any]) -> Dict[str, Any]:
    threat_intel = case_data.get("threat_intelligence", {})

    vt = threat_intel.get("virustotal", {})
    abuseipdb = threat_intel.get("abuseipdb", {})
    otx = threat_intel.get("alienvault_otx", {})
    notes = threat_intel.get("notes", [])

    vt_file_result = vt.get("file_hash", {})
    vt_ip_results = vt.get("ip_results", [])
    vt_domain_results = vt.get("domain_results", [])
    abuseipdb_results = abuseipdb.get("ip_results", [])
    otx_results = otx.get("otx_results", [])

    summary = []
    confirmed_findings = []

    if vt_file_result.get("status") == "completed":
        malicious = vt_file_result.get("malicious", 0)
        suspicious = vt_file_result.get("suspicious", 0)
        indicator = vt_file_result.get("indicator")

        summary.append(
            f"VirusTotal file lookup completed for {indicator}. "
            f"Malicious detections: {malicious}, suspicious detections: {suspicious}."
        )

        if malicious > 0 or suspicious > 0:
            confirmed_findings.append(
                f"VirusTotal indicates the file hash is suspicious or malicious: "
                f"{malicious} malicious, {suspicious} suspicious."
            )

    elif vt_file_result.get("status") == "skipped":
        summary.append(f"VirusTotal file lookup skipped: {vt_file_result.get('reason')}")

    for result in vt_ip_results:
        if result.get("status") == "completed":
            summary.append(
                f"VirusTotal IP lookup completed for {result.get('indicator')}. "
                f"Malicious: {result.get('malicious', 0)}, suspicious: {result.get('suspicious', 0)}."
            )

            if result.get("malicious", 0) > 0 or result.get("suspicious", 0) > 0:
                confirmed_findings.append(
                    f"VirusTotal reports suspicious or malicious detections for IP {result.get('indicator')}."
                )

    for result in vt_domain_results:
        if result.get("status") == "completed":
            summary.append(
                f"VirusTotal domain lookup completed for {result.get('indicator')}. "
                f"Malicious: {result.get('malicious', 0)}, suspicious: {result.get('suspicious', 0)}."
            )

            if result.get("malicious", 0) > 0 or result.get("suspicious", 0) > 0:
                confirmed_findings.append(
                    f"VirusTotal reports suspicious or malicious detections for domain {result.get('indicator')}."
                )

    for result in abuseipdb_results:
        if result.get("status") == "completed":
            abuse_score = result.get("abuse_confidence_score") or 0

            summary.append(
                f"AbuseIPDB lookup completed for {result.get('indicator')}. "
                f"Abuse confidence score: {abuse_score}."
            )

            if abuse_score >= 30:
                confirmed_findings.append(
                    f"AbuseIPDB shows moderate or high abuse confidence for {result.get('indicator')}: {abuse_score}."
                )

    for result in otx_results:
        if result.get("status") == "completed":
            pulse_count = result.get("pulse_count") or 0

            summary.append(
                f"AlienVault OTX lookup completed for {result.get('indicator')}. "
                f"Pulse count: {pulse_count}."
            )

            if pulse_count > 0:
                confirmed_findings.append(
                    f"AlienVault OTX found {pulse_count} related pulse(s) for {result.get('indicator')}."
                )

        elif result.get("status") == "error":
            summary.append(
                f"AlienVault OTX lookup error for {result.get('indicator')}: {result.get('reason')}"
            )

    summary.extend(get_list_value(notes))

    if len(summary) == 0:
        summary.append("No threat intelligence results were available.")

    return {
        "summary": summary,
        "confirmed_findings": confirmed_findings
    }


def build_key_findings(evidence: Dict[str, Any], threat_intel_analysis: Dict[str, Any]) -> List[str]:
    findings = []

    possible_file_name = evidence.get("possible_file_name", "Not available")
    likely_scenario = evidence.get("likely_scenario", "Unknown")
    classification = evidence.get("classification", "Unknown")
    severity = evidence.get("severity", "Unknown")
    confidence = evidence.get("confidence", "Unknown")
    alert_source = evidence.get("alert_source", "Unknown")
    event_domain = evidence.get("event_domain", "Unknown")

    findings.append(f"Likely scenario from triage: {likely_scenario}.")
    findings.append(f"Triage classification: {classification}.")
    findings.append(f"Triage severity: {severity}, confidence: {confidence}.")
    findings.append(f"Alert source is {alert_source}, indicating endpoint-based evidence.")
    findings.append(f"Suspicious file identified: {possible_file_name}.")
    findings.append(f"Associated domain or endpoint domain: {event_domain}.")

    confirmed_findings = threat_intel_analysis.get("confirmed_findings", [])

    if confirmed_findings:
        findings.extend(confirmed_findings)
    else:
        findings.append("No confirmed malicious external intelligence was found, or the alert lacks usable IOCs.")

    return findings


def recommend_investigation_actions(evidence: Dict[str, Any], missing_evidence: List[str]) -> List[str]:
    possible_file_name = evidence.get("possible_file_name", "the suspicious file")

    actions = [
        f"Retrieve the file hash for {possible_file_name}.",
        "Retrieve the full file path from the affected endpoint.",
        "Review the process tree, including parent process, child processes, and command-line arguments.",
        "Check whether the file was executed, downloaded, copied, or created by another process.",
        "Search NetWitness Endpoint for other hosts that have seen the same file name or file hash.",
        "Review user activity around the first alert time.",
        "Check for external network connections made by the suspicious process.",
        "Check whether the suspicious file created persistence, scheduled tasks, registry keys, or dropped additional files.",
        "Map confirmed behaviours to MITRE ATT&CK techniques.",
        "Escalate to SOC Analyst before performing endpoint isolation or containment."
    ]

    if missing_evidence:
        actions.append("Prioritise collecting missing evidence before confirming malware execution.")

    return actions


def determine_investigation_status(evidence: Dict[str, Any], missing_evidence: List[str]) -> str:
    severity = evidence.get("severity", "Unknown")
    confidence = evidence.get("confidence", "Unknown")
    enrichment_risk_level = evidence.get("enrichment_risk_level", "Low")

    if severity in ["Critical", "High"] and confidence == "High" and enrichment_risk_level == "High":
        return "completed_with_strong_threat_intel_but_endpoint_evidence_required"

    if severity in ["Critical", "High"] and confidence == "High" and len(missing_evidence) <= 4:
        return "completed_with_strong_evidence"

    if severity in ["Critical", "High"]:
        return "completed_with_limited_endpoint_evidence"

    return "completed_for_triage_summary"


def decide_next_action(investigation_status: str) -> str:
    if investigation_status in [
        "completed_with_strong_threat_intel_but_endpoint_evidence_required",
        "completed_with_strong_evidence",
        "completed_with_limited_endpoint_evidence"
    ]:
        return "Send to Reporting Agent"

    return "Generate investigation summary"


def build_rule_based_investigation_summary(
    evidence: Dict[str, Any],
    investigation_status: str,
    missing_evidence: List[str]
) -> str:
    possible_file_name = evidence.get("possible_file_name", "Not available")
    severity = evidence.get("severity", "Unknown")
    confidence = evidence.get("confidence", "Unknown")
    enrichment_risk_level = evidence.get("enrichment_risk_level", "Low")

    return (
        f"The Investigation Agent reviewed the triage output and enriched case context for {possible_file_name}. "
        f"The case is assessed as severity {severity} with confidence {confidence}. "
        f"The enrichment risk level is {enrichment_risk_level}. "
        f"The investigation status is {investigation_status}. "
        f"{len(missing_evidence)} evidence gap(s) were identified and should be addressed during deeper endpoint investigation."
    )


def build_llm_investigation_prompt(
    case_data: Dict[str, Any],
    evidence: Dict[str, Any],
    key_findings: List[str],
    missing_evidence: List[str],
    recommended_actions: List[str],
    threat_intel_analysis: Dict[str, Any],
    investigation_status: str
) -> str:
    selected_findings = key_findings[:5]
    selected_missing = missing_evidence[:4]
    selected_actions = recommended_actions[:4]
    selected_threat_summary = threat_intel_analysis.get("summary", [])[:7]

    return f"""
You are a SOC Investigation Assistant.

Explain the investigation result using only the evidence provided. Do not invent facts.

Case:
- Incident ID: {case_data.get("incident_id")}
- Alert Title: {case_data.get("alert_title")}
- Likely Scenario: {evidence.get("likely_scenario")}
- Classification: {evidence.get("classification")}
- Severity: {evidence.get("severity")}
- Confidence: {evidence.get("confidence")}
- Possible File: {evidence.get("possible_file_name")}
- File Hash: {evidence.get("file_hash")}
- Source IP: {evidence.get("source_ip")}
- Destination IP: {evidence.get("destination_ip")}
- Domain: {evidence.get("event_domain")}
- Investigation Status: {investigation_status}

Threat Intel Summary:
{selected_threat_summary}

Key Findings:
{selected_findings}

Missing Evidence:
{selected_missing}

Recommended Actions:
{selected_actions}

Write a short SOC investigation analysis in 5 bullet points:
- What is suspected
- What evidence supports it
- What evidence is missing
- What should be checked next
- Whether this is ready for reporting
"""


def investigate_case(case_data: Dict[str, Any]) -> Dict[str, Any]:
    evidence = collect_available_evidence(case_data)
    missing_evidence = identify_missing_evidence(evidence)
    threat_intel_analysis = analyse_threat_intelligence(case_data)
    key_findings = build_key_findings(evidence, threat_intel_analysis)
    recommended_actions = recommend_investigation_actions(evidence, missing_evidence)
    investigation_status = determine_investigation_status(evidence, missing_evidence)
    next_action = decide_next_action(investigation_status)

    rule_based_investigation_summary = build_rule_based_investigation_summary(
        evidence,
        investigation_status,
        missing_evidence
    )

    llm_prompt = build_llm_investigation_prompt(
        case_data,
        evidence,
        key_findings,
        missing_evidence,
        recommended_actions,
        threat_intel_analysis,
        investigation_status
    )

    llm_investigation_analysis = call_local_llm(llm_prompt)

    investigation_result = {
        **case_data,

        "current_stage": "investigation_completed",
        "agent_completed": "investigation_agent",

        "investigation_status": investigation_status,
        "investigation_summary": rule_based_investigation_summary,
        "llm_investigation_analysis": llm_investigation_analysis,
        "key_findings": key_findings,
        "missing_evidence": missing_evidence,
        "recommended_actions": recommended_actions,
        "next_action": next_action,

        "investigation_result": {
            "incident_id": case_data.get("incident_id"),
            "alert_id": case_data.get("alert_id"),
            "likely_scenario": evidence.get("likely_scenario"),
            "classification": evidence.get("classification"),
            "severity": evidence.get("severity"),
            "confidence": evidence.get("confidence"),
            "investigation_status": investigation_status,
            "rule_based_investigation_summary": rule_based_investigation_summary,
            "llm_investigation_analysis": llm_investigation_analysis,
            "key_findings": key_findings,
            "missing_evidence": missing_evidence,
            "recommended_actions": recommended_actions,
            "next_action": next_action,
            "threat_intelligence_summary": threat_intel_analysis.get("summary", [])
        }
    }

    return investigation_result


def main() -> None:
    if not os.path.exists(INPUT_FILE):
        raise FileNotFoundError(f"Input file not found: {INPUT_FILE}")

    case_context = load_case_context()

    next_agent = case_context.get("next_agent")

    if next_agent and next_agent != "investigation_agent":
        print(
            f"Warning: Orchestration decision next_agent is '{next_agent}', "
            "not 'investigation_agent'. Continuing for manual test."
        )

    result = investigate_case(case_context)
    save_json(result)

    print(json.dumps(result, indent=4))
    print()
    print(f"Investigation result saved to: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()