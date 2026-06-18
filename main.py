import os
import sys
import shutil
import argparse
import json
from dotenv import load_dotenv

import ingest_pipeline
import vector_engine
import orchestrator

load_dotenv()

UNREAD_ALERTS_FOLDER = "triaged_alerts/"
INCIDENT_REPORTS_FOLDER = "incident_reports/"
PLAYBOOKS_FOLDER = "playbooks/"

os.makedirs(UNREAD_ALERTS_FOLDER, exist_ok=True)
os.makedirs(INCIDENT_REPORTS_FOLDER, exist_ok=True)

def get_or_create_incident_folder() -> tuple[str, str]:
    """Retrieves or creates the next incremented Incident directory."""
    existing = [d for d in os.listdir(INCIDENT_REPORTS_FOLDER) if d.startswith("Incident-")]
    if not existing:
        next_id = "Incident-001"
    else:
        ids = [int(d.split("-")[1]) for d in existing if d.split("-")[1].isdigit()]
        next_id = f"Incident-{max(ids)+1:03d}" if ids else "Incident-001"
    
    path = os.path.join(INCIDENT_REPORTS_FOLDER, next_id)
    os.makedirs(path, exist_ok=True)
    return path, next_id

def find_file_by_incident_id(incident_id: str) -> str:
    """Finds the raw alert JSON file in the unread queue by incident ID."""
    files = [f for f in os.listdir(UNREAD_ALERTS_FOLDER) if f.endswith('.json')]
    for f in files:
        if incident_id.lower() in f.lower():
            return os.path.join(UNREAD_ALERTS_FOLDER, f)
    return None

def write_markdown_report(dest_folder: str, incident_num_id: str, report: orchestrator.FinalIncidentAnalysis):
    """Writes a beautifully formatted markdown incident report to the target folder."""
    report_path = os.path.join(dest_folder, "final_analysis_report.md")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(f"# EXECUTIVE INCIDENT OUTCOME REPORT: {report.incident_id} ({incident_num_id})\n\n")
        f.write(f"**Final Severity:** {report.severity}\n")
        f.write(f"**Confidence Level:** {report.confidence}\n\n")
        
        f.write("## Technical Chronology Summary\n")
        f.write(f"{report.incident_summary}\n\n")
        
        f.write("## Playbook Execution Trace\n")
        f.write("| Step ID | Instruction | Status | Findings |\n")
        f.write("| --- | --- | --- | --- |\n")
        for step in report.execution_trace:
            f.write(f"| `{step.step_id}` | {step.instruction} | **{step.status}** | {step.findings} |\n")
        f.write("\n")
        
        f.write("## Actions Taken\n")
        for action in report.actions_taken:
            f.write(f"- {action}\n")
        f.write("\n")
        
        f.write("## Lessons Learnt\n")
        f.write(f"{report.lessons_learnt}\n\n")
        
        f.write("## Recommended Containment Actions\n")
        for recommendation in report.recommended_containment:
            f.write(f"- {recommendation}\n")
            
    orchestrator.log_success(f"Case report stored securely inside: {report_path}")

def select_playbook_automatically(seed_file_path: str) -> str:
    """Automatically selects the best playbook based on the seed alert's classification."""
    try:
        with open(seed_file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        alert_type = data.get("classification", {}).get("alert_type", "").lower()
        tactic = data.get("incident_details", {}).get("mitre_att&ck", {}).get("tactic", "").lower()
        
        if "privilege" in alert_type or "privilege" in tactic or "escalation" in alert_type:
            path = os.path.join(PLAYBOOKS_FOLDER, "privilegeEscalation.yaml")
            if os.path.exists(path):
                orchestrator.log_info(f"Auto-selected Privilege Escalation playbook based on alert type: '{alert_type}'")
                return path
        
        # Default fallback
        path = os.path.join(PLAYBOOKS_FOLDER, "phishing.yaml")
        orchestrator.log_info(f"Auto-selected Phishing playbook for alert type: '{alert_type}'")
        return path
    except Exception as e:
        orchestrator.log_warning(f"Error auto-detecting playbook: {e}. Defaulting to phishing.yaml")
        return os.path.join(PLAYBOOKS_FOLDER, "phishing.yaml")

def main():
    parser = argparse.ArgumentParser(description="Advanced Hybrid SOC Incident Response Pipeline")
    parser.add_argument("--playbook", help="Path to playbook YAML file (omitted for auto-selection)")
    args = parser.parse_args()
    
    orchestrator.log_info("Initializing SOC Incident Response Pipeline...")
    
    # 1. Bulk Ingestion Step
    unread_files = sorted([f for f in os.listdir(UNREAD_ALERTS_FOLDER) if f.endswith('.json')])
    if not unread_files:
        orchestrator.log_warning("No alert files found in 'triaged_alerts/'. Ingestion skipped.")
        sys.exit(0)
        
    orchestrator.log_info(f"Starting Bulk Ingestion of {len(unread_files)} raw alert logs...")
    
    # Reset vector database to avoid stale items
    vector_engine.clear_collection()
    
    ingested_logs = []
    for f in unread_files:
        path = os.path.join(UNREAD_ALERTS_FOLDER, f)
        try:
            log_data = ingest_pipeline.process_log_file(path)
            ingested_logs.append(log_data)
        except Exception as e:
            orchestrator.log_error(f"Failed to ingest log {f}: {e}")
            
    vector_engine.ingest_logs(ingested_logs)
    orchestrator.log_success(f"Bulk Ingestion completed. Vector store populated with {len(ingested_logs)} items.")
    
    # 2. Drain & Sort Clear-Out Control Loop
    processed_incident_ids = set()
    
    while True:
        # Re-scan current files in triaged_alerts/
        current_files = sorted([f for f in os.listdir(UNREAD_ALERTS_FOLDER) if f.endswith('.json')])
        if not current_files:
            orchestrator.log_success("All alert files in 'triaged_alerts/' have been handled. Queue is empty!")
            break
            
        seed_file = current_files[0]
        seed_path = os.path.join(UNREAD_ALERTS_FOLDER, seed_file)
        
        orchestrator.log_info(f"Evaluating remaining queue. Picked investigative Seed Alert: {seed_file}")
        
        # Auto-select or use command line playbook
        playbook_path = args.playbook if args.playbook else select_playbook_automatically(seed_path)
        
        # Run correlation and playbook checkpoints
        try:
            result = orchestrator.orchestrate_incident(seed_path, playbook_path)
        except Exception as e:
            orchestrator.log_error(f"Failed during orchestration of seed {seed_file}: {e}")
            # Safe recovery: move seed out of queue to prevent infinite loop
            dest_dir, inst_id = get_or_create_incident_folder()
            shutil.move(seed_path, os.path.join(dest_dir, seed_file))
            continue
            
        correlated_alerts = result["correlated_alerts"]
        report = result["report"]
        
        # Create incident archive directory
        dest_dir, inst_id = get_or_create_incident_folder()
        orchestrator.log_info(f"Archiving correlated cluster under incident folder: {dest_dir}")
        
        # Write final markdown report
        write_markdown_report(dest_dir, inst_id, report)
        
        # Move raw files and delete from vector DB to maintain states
        correlated_ids = []
        for alert in correlated_alerts:
            alert_id = alert["id"]
            correlated_ids.append(alert_id)
            processed_incident_ids.add(alert_id)
            
            # Find file and physically move it
            filepath = find_file_by_incident_id(alert_id)
            if filepath and os.path.exists(filepath):
                filename = os.path.basename(filepath)
                dest_path = os.path.join(dest_dir, filename)
                try:
                    shutil.move(filepath, dest_path)
                    orchestrator.log_success(f"Archived {filename} -> {dest_path}")
                except Exception as e:
                    orchestrator.log_error(f"Failed to move file {filename}: {e}")
                    
        # Remove handled alerts from ChromaDB collection to prevent future matches
        try:
            vector_engine.collection.delete(ids=correlated_ids)
            orchestrator.log_info(f"Cleared resolved IDs {correlated_ids} from ChromaDB.")
        except Exception as e:
            orchestrator.log_error(f"Failed to delete items from ChromaDB: {e}")
            
    orchestrator.log_info("SOC Incident Response Pipeline shut down successfully.")

if __name__ == "__main__":
    main()
