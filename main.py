import os
import sys
import shutil
import argparse
import json
import threading
import asyncio
import time
from dotenv import load_dotenv

import ingest_pipeline
import vector_engine
import orchestrator
from correlation_engine import CorrelationEngine
from sync_engine import (
    RealtimeSyncService,
    Incident,
    IncidentMetadata,
    IncidentSeverity,
    IncidentStatus
)

load_dotenv()

UNREAD_ALERTS_FOLDER = "triaged_alerts/"
INCIDENT_REPORTS_FOLDER = "incident_reports/"
PLAYBOOKS_FOLDER = "playbooks/"

os.makedirs(UNREAD_ALERTS_FOLDER, exist_ok=True)
os.makedirs(INCIDENT_REPORTS_FOLDER, exist_ok=True)

def start_background_sync(base_folder: str, db_path: str) -> tuple[RealtimeSyncService, threading.Thread, asyncio.AbstractEventLoop]:
    loop = asyncio.new_event_loop()
    service = RealtimeSyncService(base_folder=base_folder, db_path=db_path)
    
    def thread_target():
        asyncio.set_event_loop(loop)
        loop.run_until_complete(service.start())
        while service._running:
            loop.run_until_complete(asyncio.sleep(0.5))
        loop.run_until_complete(service.stop())
        loop.close()

    t = threading.Thread(target=thread_target, daemon=True)
    t.start()
    return service, t, loop

def stop_background_sync(service: RealtimeSyncService, thread: threading.Thread, loop: asyncio.AbstractEventLoop):
    service._running = False
    thread.join(timeout=5.0)

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

async def main_async():
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
    
    # Start background realtime sync daemon
    sync_service, sync_thread, sync_loop = start_background_sync(INCIDENT_REPORTS_FOLDER, "ChromaDatabase")
    
    # 2. Instantiate the Two-Tier Correlation Engine
    engine = CorrelationEngine(INCIDENT_REPORTS_FOLDER, "ChromaDatabase")
    
    # 3. Drain & Sort Clear-Out Control Loop
    dirty_incidents = set()
    incident_playbooks = {}
    
    while True:
        # Re-scan current files in triaged_alerts/
        current_files = sorted([f for f in os.listdir(UNREAD_ALERTS_FOLDER) if f.endswith('.json')])
        if not current_files:
            orchestrator.log_success("All alert files in 'triaged_alerts/' have been handled. Queue is empty!")
            break
            
        seed_file = current_files[0]
        seed_path = os.path.join(UNREAD_ALERTS_FOLDER, seed_file)
        
        orchestrator.log_info(f"Evaluating remaining queue. Picked investigative Seed Alert: {seed_file}")
        
        # Load the seed alert
        try:
            alert_log = ingest_pipeline.process_log_file(seed_path)
        except Exception as e:
            orchestrator.log_error(f"Failed to process seed file {seed_file}: {e}")
            dest_dir, inst_id = get_or_create_incident_folder()
            shutil.move(seed_path, os.path.join(dest_dir, seed_file))
            continue
            
        # Parse all OTHER unassigned alerts currently in the queue
        unassigned_alerts = []
        for other_file in current_files[1:]:
            other_path = os.path.join(UNREAD_ALERTS_FOLDER, other_file)
            try:
                unassigned_alerts.append(ingest_pipeline.process_log_file(other_path))
            except Exception:
                pass

        # Execute Two-Tier Correlation
        try:
            res = await engine.correlate_alert(alert_log, unassigned_alerts)
        except Exception as e:
            orchestrator.log_error(f"Failed during correlation of seed {seed_file}: {e}")
            dest_dir, inst_id = get_or_create_incident_folder()
            shutil.move(seed_path, os.path.join(dest_dir, seed_file))
            continue
            
        decision = res["decision"]
        similar_to = res.get("similar_to_incident")
        playbook_path = args.playbook if args.playbook else select_playbook_automatically(seed_path)
        
        if decision == "MERGE":
            target_inc_id = res["incident_id"]
            incident = engine.active_incidents.get(target_inc_id)
            if not incident:
                incident = await engine.repo.get(target_inc_id)
                
            if not incident:
                orchestrator.log_error(f"Target incident {target_inc_id} not found in repository. Defaulting to standalone incident creation.")
                decision = "STANDALONE"
            else:
                orchestrator.log_success(f"Confirmed Match. Merging alert {alert_log['id']} into Incident {target_inc_id}")
                incident.raw_alerts.append(alert_log)
                
                # Re-run playbook analysis synchronously (supporting active indicator pivoting)
                analysis_res = orchestrator.analyze_alert_group(incident.raw_alerts, playbook_path)
                
                # Retrieve the updated list of alerts (including any new ones pulled in via pivots)
                updated_alerts = analysis_res["correlated_alerts"]
                incident.raw_alerts = updated_alerts
                report = analysis_res["report"]
                
                # Update incident state indicators
                incident.summary_text = report.incident_summary
                
                # severity mapping
                sev_map = {
                    "low": IncidentSeverity.LOW,
                    "medium": IncidentSeverity.MEDIUM,
                    "high": IncidentSeverity.HIGH,
                    "critical": IncidentSeverity.CRITICAL
                }
                mapped_severity = sev_map.get(report.severity.lower(), IncidentSeverity.MEDIUM)
                incident.metadata.severity = mapped_severity
                incident.metadata.updated_at = time.time()
                
                indicators_set = set()
                for alert in incident.raw_alerts:
                    for ind in engine._extract_indicators(alert):
                        indicators_set.add(ind)
                incident.indicators = list(indicators_set)
                
                # Save & sync updated incident
                await engine.sync_update_incident(incident)
                
                # Archive all files in the updated group
                dest_dir = os.path.join(INCIDENT_REPORTS_FOLDER, target_inc_id)
                cluster_ids = []
                for alert in incident.raw_alerts:
                    alert_id = alert["id"]
                    cluster_ids.append(alert_id)
                    
                    filepath = find_file_by_incident_id(alert_id)
                    if filepath and os.path.exists(filepath):
                        filename = os.path.basename(filepath)
                        shutil.move(filepath, os.path.join(dest_dir, filename))
                
                # Write final markdown report
                write_markdown_report(dest_dir, target_inc_id, report)
                
                # Delete matched alerts from raw collection
                try:
                    vector_engine.collection.delete(ids=cluster_ids)
                except Exception as e:
                    orchestrator.log_error(f"Failed to delete alert items from ChromaDB: {e}")

        if decision in ("NEW_CLUSTER", "STANDALONE"):
            # Create brand new incident
            dest_dir, inst_id = get_or_create_incident_folder()
            cluster_alerts = res.get("cluster_alerts", [alert_log])
            
            action_desc = f"New Incident Cluster of {len(cluster_alerts)} alerts" if decision == "NEW_CLUSTER" else "Standalone Incident"
            orchestrator.log_info(f"Forming {action_desc} -> {inst_id}")
            
            # Run playbook analysis synchronously (supporting active indicator pivoting)
            analysis_res = orchestrator.analyze_alert_group(cluster_alerts, playbook_path)
            
            # Retrieve the updated list of alerts (including any new ones pulled in via pivots)
            updated_alerts = analysis_res["correlated_alerts"]
            report = analysis_res["report"]
            
            # severity mapping
            sev_map = {
                "low": IncidentSeverity.LOW,
                "medium": IncidentSeverity.MEDIUM,
                "high": IncidentSeverity.HIGH,
                "critical": IncidentSeverity.CRITICAL
            }
            mapped_severity = sev_map.get(report.severity.lower(), IncidentSeverity.MEDIUM)
            
            # Gather indicators
            indicators_set = set()
            for alert in updated_alerts:
                for ind in engine._extract_indicators(alert):
                    indicators_set.add(ind)
                    
            incident_data = Incident(
                id=inst_id,
                metadata=IncidentMetadata(
                    severity=mapped_severity,
                    status=IncidentStatus.TRIAGED,
                    assigned_analyst="Automated Agent",
                    created_at=time.time(),
                    updated_at=time.time(),
                    source_type=updated_alerts[0]["metadata"].get("source_type", "Default"),
                    similar_to_incident=similar_to
                ),
                raw_alerts=updated_alerts,
                summary_text=report.incident_summary,
                indicators=list(indicators_set)
            )
            
            # Save & sync new incident
            await engine.sync_create_incident(incident_data)
            
            # Write report
            write_markdown_report(dest_dir, inst_id, report)
            
            # Archive files and delete from vector store
            cluster_ids = []
            for alert in updated_alerts:
                alert_id = alert["id"]
                cluster_ids.append(alert_id)
                
                filepath = find_file_by_incident_id(alert_id)
                if filepath and os.path.exists(filepath):
                    filename = os.path.basename(filepath)
                    shutil.move(filepath, os.path.join(dest_dir, filename))
                    
            # Clear alerts from raw collection
            try:
                vector_engine.collection.delete(ids=cluster_ids)
                orchestrator.log_info(f"Cleared resolved IDs {cluster_ids} from ChromaDB raw collection.")
            except Exception as e:
                orchestrator.log_error(f"Failed to delete items from ChromaDB: {e}")

    # Stop background realtime sync daemon
    stop_background_sync(sync_service, sync_thread, sync_loop)
    orchestrator.log_info("SOC Incident Response Pipeline shut down successfully.")

def main():
    asyncio.run(main_async())

if __name__ == "__main__":
    main()
