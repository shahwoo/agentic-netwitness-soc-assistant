import json
import csv
import os
import re


INPUT_FILE = "inputs/alert.json"
JSON_OUTPUT_FILE = "outputs/processed_alert.json"
CSV_OUTPUT_FILE = "outputs/processed_alert.csv"


def clean_value(value, fallback=None):
    if value is None or value == "":
        return fallback
    return value


def first_array_value(array, fallback=None):
    if not isinstance(array, list) or len(array) == 0:
        return fallback
    return clean_value(array[0], fallback)


def load_alert():
    print(f"Reading input file from: {os.path.abspath(INPUT_FILE)}")

    with open(INPUT_FILE, "r", encoding="utf-8") as file:
        alert = json.load(file)

    print("Top-level keys found:", list(alert.keys()))

    return alert


def parse_and_normalise(alert):
    incident = alert.get("incident_details", {})
    alert_items = alert.get("alert_items", {})
    incident_history = alert.get("incident_history", [])

    items = alert_items.get("items", [])
    first_item = items[0] if len(items) > 0 else {}

    events = first_item.get("events", [])
    first_event = events[0] if len(events) > 0 else {}

    source = first_event.get("source", {})
    destination = first_event.get("destination", {})

    source_device = source.get("device", {})
    source_user = source.get("user", {})

    destination_device = destination.get("device", {})
    destination_user = destination.get("user", {})

    alert_meta = incident.get("alertMeta", {})
    source_ip_meta = alert_meta.get("SourceIp", [])
    destination_ip_meta = alert_meta.get("DestinationIp", [])

    first_history = incident_history[0] if len(incident_history) > 0 else {}

    normalised_alert = {
        "current_stage": "new_alert",

        "incident_id": clean_value(incident.get("id"), "UNKNOWN"),
        "incident_title": clean_value(incident.get("title"), "No incident title"),
        "incident_summary": clean_value(incident.get("summary"), ""),
        "incident_priority": clean_value(incident.get("priority"), "Unknown"),
        "incident_risk_score": clean_value(incident.get("riskScore"), 0),
        "incident_status": clean_value(incident.get("status"), "Unknown"),
        "incident_alert_count": clean_value(incident.get("alertCount"), 0),
        "incident_average_alert_risk_score": clean_value(incident.get("averageAlertRiskScore"), 0),
        "incident_event_count": clean_value(incident.get("eventCount"), 0),
        "incident_sealed": clean_value(incident.get("sealed"), False),
        "incident_rule_id": clean_value(incident.get("ruleId"), "Unknown"),
        "incident_created_by": clean_value(incident.get("createdBy"), "Unknown"),
        "incident_created_time": clean_value(incident.get("created"), None),
        "incident_last_updated_time": clean_value(incident.get("lastUpdated"), None),
        "incident_first_alert_time": clean_value(incident.get("firstAlertTime"), None),
        "incident_assignee": clean_value(incident.get("assignee"), "Unassigned"),

        "incident_sources": ", ".join(incident.get("sources", [])),
        "incident_categories": ", ".join(incident.get("categories", [])),
        "incident_tactics": ", ".join(incident.get("tactics", [])),
        "incident_techniques": ", ".join(incident.get("techniques", [])),

        "total_remediation_task_count": clean_value(incident.get("totalRemediationTaskCount"), 0),
        "open_remediation_task_count": clean_value(incident.get("openRemediationTaskCount"), 0),

        "alert_id": clean_value(first_item.get("id"), "UNKNOWN"),
        "alert_title": clean_value(first_item.get("title"), "No alert title"),
        "alert_detail": clean_value(first_item.get("detail"), ""),
        "alert_created_time": clean_value(first_item.get("created"), None),
        "alert_source": clean_value(first_item.get("source"), "Unknown"),
        "alert_risk_score": clean_value(first_item.get("riskScore"), None),
        "alert_type": clean_value(first_item.get("type"), "Unknown"),
        "alert_tactics": ", ".join(first_item.get("tactics", [])),
        "alert_techniques": ", ".join(first_item.get("techniques", [])),

        "event_domain": clean_value(first_event.get("domain"), "Unknown"),
        "event_source": clean_value(first_event.get("eventSource"), "Unknown"),
        "event_source_id": clean_value(first_event.get("eventSourceId"), "Unknown"),

        "source_ip": clean_value(
            source_device.get("ipAddress"),
            first_array_value(source_ip_meta, "Not available")
        ),
        "source_port": clean_value(source_device.get("port"), "Not available"),
        "source_mac_address": clean_value(source_device.get("macAddress"), "Not available"),
        "source_dns_hostname": clean_value(source_device.get("dnsHostname"), "Not available"),
        "source_dns_domain": clean_value(source_device.get("dnsDomain"), "Not available"),

        "source_username": clean_value(source_user.get("username"), "Not available"),
        "source_email_address": clean_value(source_user.get("emailAddress"), "Not available"),
        "source_ad_username": clean_value(source_user.get("adUsername"), "Not available"),
        "source_ad_domain": clean_value(source_user.get("adDomain"), "Not available"),

        "destination_ip": clean_value(
            destination_device.get("ipAddress"),
            first_array_value(destination_ip_meta, "Not available")
        ),
        "destination_port": clean_value(destination_device.get("port"), "Not available"),
        "destination_mac_address": clean_value(destination_device.get("macAddress"), "Not available"),
        "destination_dns_hostname": clean_value(destination_device.get("dnsHostname"), "Not available"),
        "destination_dns_domain": clean_value(destination_device.get("dnsDomain"), "Not available"),

        "destination_username": clean_value(destination_user.get("username"), "Not available"),
        "destination_email_address": clean_value(destination_user.get("emailAddress"), "Not available"),
        "destination_ad_username": clean_value(destination_user.get("adUsername"), "Not available"),
        "destination_ad_domain": clean_value(destination_user.get("adDomain"), "Not available"),

        "incident_history_type": clean_value(first_history.get("type"), "Unknown"),
        "incident_history_date": clean_value(first_history.get("date"), None),
        "incident_history_changed_by": clean_value(first_history.get("changedBy"), "Unknown")
    }

    return normalised_alert


def extract_entities(normalised_alert):
    alert_title = normalised_alert.get("alert_title", "")

    file_match = re.search(
        r"[A-Za-z0-9_\-]+\.(exe|dll|ps1|bat|cmd|vbs|js)",
        alert_title,
        re.IGNORECASE
    )

    possible_file_name = "Not available"

    if file_match:
        possible_file_name = file_match.group(0)

    normalised_alert["possible_file_name"] = possible_file_name
    normalised_alert["entity_domain"] = normalised_alert.get("event_domain")
    normalised_alert["entity_source_ip"] = normalised_alert.get("source_ip")
    normalised_alert["entity_destination_ip"] = normalised_alert.get("destination_ip")
    normalised_alert["entity_source_username"] = normalised_alert.get("source_username")
    normalised_alert["entity_destination_username"] = normalised_alert.get("destination_username")

    return normalised_alert


def save_json(data):
    os.makedirs("outputs", exist_ok=True)

    with open(JSON_OUTPUT_FILE, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=4)


def save_csv(data):
    os.makedirs("outputs", exist_ok=True)

    with open(CSV_OUTPUT_FILE, "w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=data.keys())
        writer.writeheader()
        writer.writerow(data)


def main():
    raw_alert = load_alert()

    normalised_alert = parse_and_normalise(raw_alert)
    extracted_alert = extract_entities(normalised_alert)

    save_json(extracted_alert)
    save_csv(extracted_alert)

    print(json.dumps(extracted_alert, indent=4))
    print(f"\nCSV saved to: {CSV_OUTPUT_FILE}")


if __name__ == "__main__":
    main()