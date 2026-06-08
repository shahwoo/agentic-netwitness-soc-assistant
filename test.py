import yaml
import json
import os

UNREAD_ALERTS_FOLDER = "triaged_alerts/"
INCIDENT_REPORTS_FOLDER = "incident_reports/"

def load_yaml_playbook(filepath: str) -> tuple[str, dict]:
    fallback_playbook = {
        "steps": {
            "step_1_check_scope": {
                "instruction": "Determine if the attacker has successfully pivoted to adjacent systems or endpoints using compromised assets.",
                "routing": {"yes": "step_2_isolate_host", "no": "step_terminal_close"}
            },
            "step_2_isolate_host": {
                "instruction": "Evaluate if immediate isolation of the host infrastructure is necessary based on critical access logs.",
                "routing": {"yes": "step_terminal_escalate", "no": "step_terminal_close"}
            }
        }
    }
    if not os.path.exists(filepath):
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, 'w') as f:
            yaml.dump(fallback_playbook, f, default_flow_style=False)
        return yaml.dump(fallback_playbook, default_flow_style=False), fallback_playbook
    try:
        with open(filepath, 'r', encoding='utf-8') as file:
            parsed_yaml = yaml.safe_load(file)
            return yaml.dump(parsed_yaml, default_flow_style=False), parsed_yaml
    except Exception as e:
        log_error(f"Failed to parse playbook: {e}")
        return yaml.dump(fallback_playbook, default_flow_style=False), fallback_playbook

    
def get_unread_alerts_inventory() -> str:
    files = [f for f in os.listdir(UNREAD_ALERTS_FOLDER) if f.endswith('.json')]
    if not files:
        return "No unread alerts in inventory."

    inventory_summary = []
    for f in files:
        path = os.path.join(UNREAD_ALERTS_FOLDER, f)
        try:
            with open(path, 'r') as file:
                data = json.load(file)
                # Extract only vital metadata to keep context footprint tiny
                src = data.get("IOCs", {}).get("SourceIp", ["Unknown"])[0]
                event = data.get("AlertName", "Generic Alert")
                inventory_summary.append(f"- File: {f} | Alert: {event} | SrcIP: {src}")
        except Exception:
            inventory_summary.append(f"- File: {f} (Unreadable JSON)")
    return "\n".join(inventory_summary)

def get_or_create_incident_folder() -> str:
    existing = [d for d in os.listdir(INCIDENT_REPORTS_FOLDER) if d.startswith("Incident-")]
    if not existing:
        print("not existing")
        next_id = "Incident-001"
    else:
        ids = [int(d.split("-")[1]) for d in existing if d.split("-")[1].isdigit()]
        print(ids)
        next_id = f"Incident-{max(ids)+1:03d}"
        print(next_id)
        
    print(next_id)
    path = os.path.join(INCIDENT_REPORTS_FOLDER, next_id)
    os.makedirs(path, exist_ok=True)
    return path

PLAYBOOK_TEXT, PLAYBOOK_DICT = load_yaml_playbook("playbooks/phishing.yaml")

get_or_create_incident_folder()