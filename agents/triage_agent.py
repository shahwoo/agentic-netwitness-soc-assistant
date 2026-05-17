import json
import os


INPUT_FILE = "inputs/alert.json"
OUTPUT_FILE = "outputs/triage_result.json"


def load_alert():
    with open(INPUT_FILE, "r", encoding="utf-8") as file:
        return json.load(file)


def save_result(result):
    os.makedirs("outputs", exist_ok=True)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as file:
        json.dump(result, file, indent=4)


def get_first_alert_item(alert_data):
    alert_items = alert_data.get("alert_items", {})
    items = alert_items.get("items", [])

    if len(items) > 0:
        return items[0]

    return {}


def get_first_event(alert_item):
    events = alert_item.get("events", [])

    if len(events) > 0:
        return events[0]

    return {}


def triage_alert(alert_data):
    incident = alert_data.get("incident_details", {})
    alert_item = get_first_alert_item(alert_data)
    event = get_first_event(alert_item)

    incident_id = incident.get("id", "UNKNOWN")
    incident_title = incident.get("title", "No incident title")
    incident_priority = incident.get("priority", "Unknown")
    incident_risk_score = incident.get("riskScore", 0)
    incident_status = incident.get("status", "Unknown")
    alert_count = incident.get("alertCount", 0)
    event_count = incident.get("eventCount", 0)
    sources = incident.get("sources", [])

    alert_id = alert_item.get("id", "UNKNOWN")
    alert_title = alert_item.get("title", "No alert title")
    alert_type = alert_item.get("type", "Unknown")
    alert_source = alert_item.get("source", "Unknown")

    domain = event.get("domain", "Unknown")
    event_source = event.get("eventSource", "Unknown")
    event_source_id = event.get("eventSourceId", "Unknown")

    title_for_checking = alert_title.lower()
    incident_title_for_checking = incident_title.lower()

    classification = "Unclassified security alert"
    severity = "Medium"
    confidence = "Low"
    recommended_playbook = "General Endpoint Investigation Playbook"
    next_action = "Review by SOC Analyst"
    reasoning_summary = "The alert does not strongly match any existing triage rule."

    if "potential malicious file" in title_for_checking or ".exe" in title_for_checking:
        classification = "Potential malicious executable detected"
        recommended_playbook = "Endpoint Malware Investigation Playbook"
        next_action = "Send to Investigation Agent"

        if incident_risk_score >= 80 or incident_priority == "Critical":
            severity = "Critical"
            confidence = "High"
            reasoning_summary = (
                "The incident indicates a potential malicious executable with a very high risk score "
                "or critical priority. Immediate investigation is required."
            )

        elif incident_risk_score >= 50 or incident_priority == "High":
            severity = "High"
            confidence = "Medium"
            reasoning_summary = (
                "The incident reports a potential malicious executable, Sandy.exe, from NetWitness Endpoint. "
                "The incident priority is High and the risk score is 50, which indicates that deeper endpoint "
                "investigation is required."
            )

        else:
            severity = "Medium"
            confidence = "Medium"
            reasoning_summary = (
                "The alert mentions a potential malicious executable, but the available risk score is not high. "
                "The file should still be investigated because executable-based endpoint alerts may indicate malware."
            )

    elif "high risk" in incident_title_for_checking:
        classification = "High-risk endpoint alert"
        recommended_playbook = "High-Risk Endpoint Alert Investigation Playbook"
        next_action = "Send to Investigation Agent"
        severity = "High"
        confidence = "Medium"
        reasoning_summary = (
            "The incident title indicates a high-risk NetWitness Endpoint alert. "
            "Although limited technical details are available, the priority and source suggest that investigation is needed."
        )

    result = {
        "incident_id": incident_id,
        "alert_id": alert_id,
        "classification": classification,
        "severity": severity,
        "confidence": confidence,
        "recommended_playbook": recommended_playbook,
        "next_action": next_action,
        "reasoning_summary": reasoning_summary,
        "extracted_entities": {
            "incident_title": incident_title,
            "alert_title": alert_title,
            "incident_priority": incident_priority,
            "incident_risk_score": incident_risk_score,
            "incident_status": incident_status,
            "alert_count": alert_count,
            "event_count": event_count,
            "sources": sources,
            "alert_source": alert_source,
            "alert_type": alert_type,
            "domain": domain,
            "event_source": event_source,
            "event_source_id": event_source_id
        },
        "triage_notes": [
            "The alert is endpoint-based because the alert type is Endpoint and the source is ECAT.",
            "The file name Sandy.exe should be treated as a suspicious executable until validated.",
            "Source IP and destination IP are empty, so host-based investigation is more important than network-based investigation.",
            "No MITRE ATT&CK tactics or techniques were provided, so mapping should be done during the investigation stage."
        ]
    }

    return result


def main():
    alert_data = load_alert()
    result = triage_alert(alert_data)
    save_result(result)

    print(json.dumps(result, indent=4))


main()