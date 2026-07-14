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
import policy_engine
from correlation_engine import CorrelationEngine
from sync_engine import (
    RealtimeSyncService,
    Incident,
    IncidentMetadata,
    IncidentSeverity,
    IncidentStatus
)
from collections import defaultdict

load_dotenv()

UNREAD_ALERTS_FOLDER = "triaged_alerts/"
INCIDENT_REPORTS_FOLDER = "incident_reports/"
PLAYBOOKS_FOLDER = "playbooks/"

os.makedirs(UNREAD_ALERTS_FOLDER, exist_ok=True)
os.makedirs(INCIDENT_REPORTS_FOLDER, exist_ok=True)

def start_background_sync(base_folder: str, db_path: str) -> tuple[RealtimeSyncService, threading.Thread, asyncio.AbstractEventLoop]:
    # Redundant background sync disabled to prevent database contention and cut down latency.
    # The pipeline already performs synchronous dual-write updates itself.
    service = RealtimeSyncService(base_folder=base_folder, db_path=db_path)
    return service, None, None

def stop_background_sync(service: RealtimeSyncService, thread: threading.Thread, loop: asyncio.AbstractEventLoop):
    pass

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
        if getattr(report, "severity_justification", None):
            f.write(f"*{report.severity_justification}*\n")
        f.write(f"\n**Confidence Level:** {report.confidence}\n")
        if getattr(report, "confidence_justification", None):
            f.write(f"*{report.confidence_justification}*\n\n")
        else:
            f.write("\n")
            
        f.write("## Business Impact Assessment (Appendix C)\n")
        checklist_data = getattr(report, "business_impact_checklist", None)
        if checklist_data:
            if hasattr(checklist_data, "model_dump"):
                checklist_dict = checklist_data.model_dump()
            else:
                checklist_dict = dict(checklist_data)
            for factor, answer in checklist_dict.items():
                factor_name = factor.replace("_", " ").title()
                f.write(f"- **{factor_name}**: {answer}\n")
        else:
            f.write("No business impact checklist compiled.\n")
        f.write("\n")
        
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
        f.write("\n")
        
        # Format and append Appendix M Audit Log Table
        f.write("## Appendix M: Policy-Based Compliance Audit Log\n\n")
        f.write("| Audit ID | Decision Point | Policy Reference | Input Summary | Result | Decision Made | Human Review? | Timestamp |\n")
        f.write("| --- | --- | --- | --- | --- | --- | --- | --- |\n")
        
        audit_logs = getattr(report, "policy_audit_logs", [])
        if audit_logs:
            for log in audit_logs:
                readable_ts = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(log.timestamp))
                hr_req = "Yes" if log.human_review_required else "No"
                f.write(f"| `{log.audit_id}` | **{log.decision_point}** | {log.policy_reference} | {log.input_summary} | *{log.result}* | `{log.decision_made}` | {hr_req} | {readable_ts} |\n")
        else:
            f.write("| N/A | N/A | N/A | No policy audit logs recorded | N/A | N/A | N/A | N/A |\n")
            
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
        return os.path.join(PLAYBOOKS_FOLDER, "phishing.yaml")
    except Exception as e:
        orchestrator.log_warning(f"Error auto-detecting playbook: {e}. Defaulting to phishing.yaml")
        return os.path.join(PLAYBOOKS_FOLDER, "phishing.yaml")

def extract_indicators_locally(doc: str) -> List[str]:
    import re
    indicators = []
    ips = re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', doc)
    indicators.extend(ips)
    domains = re.findall(r'\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,4}\b', doc)
    for d in domains:
        if d not in indicators and not d.endswith(('.exe', '.dll', '.sys', '.txt', '.log')):
            indicators.append(d)
    return indicators

def generate_local_standalone_report(alert: dict, playbook_path: str):
    import yaml
    with open(playbook_path, "r", encoding="utf-8") as f:
        playbook_dict = yaml.safe_load(f)
        
    playbook_name = playbook_dict.get("name", "Unknown Playbook")
    alert_id = alert["id"]
    alert_type = alert["metadata"].get("source_type", "SIEM Log")
    timestamp = alert["metadata"].get("timestamp", "unknown time")
    doc = alert.get("document", "")
    
    summary = f"On {timestamp}, a security alert '{alert_type}' was triaged for alert ID {alert_id}. "
    summary += f"The raw log contains details: {doc}. "
    summary += "No further associated events or indicators were found in the active time window, confirming the incident is standalone."
    
    execution_trace = []
    for step_id, step_data in sorted(playbook_dict.get("steps", {}).items()):
        is_met = False
        findings = "Timeline lacks necessary data to satisfy step."
        
        keywords = step_data.get("instructions", "").lower()
        if "phishing" in keywords or "email" in keywords:
            if "phish" in doc.lower() or "mail" in doc.lower() or "sender" in doc.lower() or "attachment" in doc.lower():
                is_met = True
                findings = f"Identified phishing elements in alert doc: {doc}"
        elif "privilege" in keywords or "escalation" in keywords:
            if "privilege" in doc.lower() or "admin" in doc.lower() or "escalat" in doc.lower():
                is_met = True
                findings = f"Identified privilege escalation signs: {doc}"
        elif "brute force" in keywords or "failed login" in keywords:
            if "brute" in doc.lower() or "fail" in doc.lower() or "auth" in doc.lower():
                is_met = True
                findings = f"Identified brute force signs: {doc}"
        elif "tunnel" in keywords or "dns" in keywords:
            if "tunnel" in doc.lower() or "dns" in doc.lower() or "port" in doc.lower():
                is_met = True
                findings = f"Identified network/DNS anomalies: {doc}"
                
        execution_trace.append(orchestrator.MilestoneExecution(
            step_id=step_id,
            instruction=step_data.get("instructions", ""),
            status="MET" if is_met else "NOT_MET",
            findings=findings
        ))
        
    checklist = {
        "critical_system": "yes" if any(k in doc.lower() for k in ("database", "dc", "domain controller", "production", "prod")) else "no",
        "essential_service": "no",
        "data_sensitivity": "yes" if any(k in doc.lower() for k in ("personal", "sensitive", "confidential", "email", "recipient", "sender")) else "no",
        "operational_impact": "no"
    }
    
    severity_val = alert["metadata"].get("severity", "High")
    
    compliance = policy_engine.run_policy_compliance_rules(
        incident_id=alert_id,
        severity=severity_val,
        confidence="High",
        incident_summary=summary,
        recommended_containment=[f"Monitor host for anomalous baseline transitions."],
        business_impact_checklist=checklist,
        timeline_text=doc
    )
    
    report = orchestrator.FinalIncidentAnalysis(
        incident_id=alert_id,
        severity=severity_val,
        confidence="High",
        execution_trace=execution_trace,
        incident_summary=summary,
        actions_taken=["Initial triage", "Indicator search", "Playbook heuristic validation"],
        lessons_learnt="No indicators associated with larger campaign identified.",
        recommended_containment=compliance["modified_containment"],
        business_impact_checklist=checklist,
        severity_justification="Programmatic baseline triage for standalone alert.",
        confidence_justification="Heuristic lookup with no temporal correlation window overlaps.",
        policy_audit_logs=compliance["audit_records"]
    )
    
    return {
        "report": report,
        "suggested_pivots": []
    }

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
    
    # 3. Drain & Sort Sequential Playbook-Guided Active Correlation Engine (Fast Grouping Phase 1)
    modified_incidents = set()
    incident_playbooks = {}
    incident_is_new = {}
    incident_similar_to = {}

    while True:
        # Re-scan current files in triaged_alerts/
        current_files = sorted([f for f in os.listdir(UNREAD_ALERTS_FOLDER) if f.endswith('.json')])
        if not current_files:
            orchestrator.log_success("All alert files in 'triaged_alerts/' have been handled. Queue is empty!")
            break
            
        seed_file = current_files[0]
        seed_path = os.path.join(UNREAD_ALERTS_FOLDER, seed_file)
        orchestrator.log_info(f"Evaluating remaining queue. Picked investigative Seed Alert: {seed_file}")
        
        # Load seed
        try:
            alert_log = ingest_pipeline.process_log_file(seed_path)
        except Exception as e:
            orchestrator.log_error(f"Failed to process seed file {seed_file}: {e}")
            dest_dir, inst_id = get_or_create_incident_folder()
            shutil.move(seed_path, os.path.join(dest_dir, seed_file))
            continue
            
        # Parse unassigned candidate alerts
        unassigned_alerts = []
        for other_file in current_files[1:]:
            other_path = os.path.join(UNREAD_ALERTS_FOLDER, other_file)
            try:
                unassigned_alerts.append(ingest_pipeline.process_log_file(other_path))
            except Exception:
                pass
                
        # Execute Two-Tier Baseline Correlation
        try:
            res = await engine.correlate_alert(alert_log, unassigned_alerts)
        except Exception as e:
            orchestrator.log_error(f"Failed baseline correlation for alert {alert_log['id']}: {e}")
            dest_dir, inst_id = get_or_create_incident_folder()
            shutil.move(seed_path, os.path.join(dest_dir, seed_file))
            continue
            
        decision = res["decision"]
        similar_to = res.get("similar_to_incident")
        playbook_path = args.playbook if args.playbook else select_playbook_automatically(seed_path)
        
        # Determine baseline alert list and incident destination
        is_new = True
        inst_id = None
        current_alerts = []
        
        if decision == "MERGE":
            inst_id = res["incident_id"]
            incident = engine.active_incidents.get(inst_id)
            if not incident:
                incident = await engine.repo.get(inst_id)
                
            if not incident:
                is_new = True
                _, inst_id = get_or_create_incident_folder()
                current_alerts = [alert_log]
            else:
                is_new = False
                orchestrator.log_success(f"Confirmed Match. Merging alert {alert_log['id']} into Incident {inst_id}")
                incident.raw_alerts.append(alert_log)
                current_alerts = list(incident.raw_alerts)
        else:
            # NEW_CLUSTER or STANDALONE
            is_new = True
            dest_dir, inst_id = get_or_create_incident_folder()
            current_alerts = res.get("cluster_alerts", [alert_log])
            action_desc = f"New Incident Cluster of {len(current_alerts)} alerts" if decision == "NEW_CLUSTER" else "Standalone Incident"
            orchestrator.log_info(f"Forming {action_desc} -> {inst_id}")
            
        modified_incidents.add(inst_id)
        if inst_id not in incident_playbooks:
            incident_playbooks[inst_id] = playbook_path
        if inst_id not in incident_is_new:
            incident_is_new[inst_id] = is_new
        incident_similar_to[inst_id] = similar_to

        # Sync temporary placeholder state so subsequent alerts can correlate
        indicators_set = set()
        for alert in current_alerts:
            for ind in engine._extract_indicators(alert):
                indicators_set.add(ind)
                
        temp_summary = " | ".join(a["document"] for a in current_alerts)
        dest_dir = os.path.join(INCIDENT_REPORTS_FOLDER, inst_id)
        os.makedirs(dest_dir, exist_ok=True)
        
        if is_new:
            incident_data = Incident(
                id=inst_id,
                metadata=IncidentMetadata(
                    severity=IncidentSeverity.MEDIUM,
                    status=IncidentStatus.TRIAGED,
                    assigned_analyst="Automated Agent",
                    created_at=time.time(),
                    updated_at=time.time(),
                    source_type=current_alerts[0]["metadata"].get("source_type", "Default"),
                    similar_to_incident=similar_to
                ),
                raw_alerts=current_alerts,
                summary_text=temp_summary,
                indicators=list(indicators_set)
            )
            await engine.sync_create_incident(incident_data)
        else:
            incident = engine.active_incidents.get(inst_id)
            if not incident:
                incident = await engine.repo.get(inst_id)
            if incident:
                incident.raw_alerts = current_alerts
                incident.summary_text = temp_summary
                incident.metadata.updated_at = time.time()
                incident.indicators = list(indicators_set)
                await engine.sync_update_incident(incident)
                
        # Archive files and delete from vector store
        cluster_ids = []
        for alert in current_alerts:
            alert_id = alert["id"]
            cluster_ids.append(alert_id)
            filepath = find_file_by_incident_id(alert_id)
            if filepath and os.path.exists(filepath):
                filename = os.path.basename(filepath)
                shutil.move(filepath, os.path.join(dest_dir, filename))
                
        # Clear matched alerts from ChromaDB raw collection
        try:
            vector_engine.collection.delete(ids=cluster_ids)
            orchestrator.log_info(f"Cleared resolved IDs {cluster_ids} from ChromaDB raw collection.")
        except Exception as e:
            orchestrator.log_error(f"Failed to delete items from ChromaDB: {e}")

    # Phase 2: Parallelized Report Generation and Enrichment
    if modified_incidents:
        orchestrator.log_info(f"Running parallel report generation and enrichment for {len(modified_incidents)} incidents...")
        
        db_lock = asyncio.Lock()
        
        async def process_incident_report(inst_id):
            incident = engine.active_incidents.get(inst_id)
            if not incident:
                incident = await engine.repo.get(inst_id)
            if not incident:
                return
                
            current_alerts = incident.raw_alerts
            playbook_path = incident_playbooks[inst_id]
            is_new = incident_is_new[inst_id]
            similar_to = incident_similar_to.get(inst_id)
            
            # --- PLAYBOOK-GUIDED ACTIVE EXPANSION ---
            # Heuristic fast check for database relations
            local_pivots = []
            for a in current_alerts:
                local_pivots.extend(extract_indicators_locally(a.get("document", "")))
                
            cleaned_local_pivots = []
            for p in local_pivots:
                p_clean = p.strip()
                p_lower = p_clean.lower()
                if not p_clean or p_lower in ("unknown", "null", "none", "", "localhost", "127.0.0.1", "0.0.0.0"):
                    continue
                cleaned_local_pivots.append(p_clean)
                
            has_externals = False
            if cleaned_local_pivots:
                seed_epoch = current_alerts[0]["metadata"]["timestamp_epoch"]
                extra_fused = await asyncio.to_thread(
                    vector_engine.correlate_rrf,
                    active_indicators=cleaned_local_pivots,
                    query_text=" ".join(cleaned_local_pivots),
                    timestamp_epoch=seed_epoch,
                    time_window_sec=86400
                )
                current_ids = {a["id"] for a in current_alerts}
                for alert_id, score, doc, meta in extra_fused:
                    if alert_id not in current_ids:
                        has_externals = True
                        break
                        
            # Check if this incident should bypass LLM call for report generation
            if len(current_alerts) == 1 and not has_externals:
                orchestrator.log_info(f"Incident {inst_id}: Standalone alert with no DB relations. Generating report locally (0 LLM calls)...")
                local_res = generate_local_standalone_report(current_alerts[0], playbook_path)
                report = local_res["report"]
            else:
                # 1. Pass 1 (Lightweight trace & pivot extraction)
                p1_res = await orchestrator.analyze_alert_group_p1(current_alerts, playbook_path)
                p1_trace = p1_res["execution_trace"]
                suggested_pivots = p1_res["suggested_pivots"]
                
                # 2. Database query for pivots
                if suggested_pivots:
                    cleaned_pivots = []
                    for p in suggested_pivots:
                        p_clean = str(p).strip()
                        p_lower = p_clean.lower()
                        if not p_clean or p_lower in ("unknown", "null", "none", "", "localhost", "127.0.0.1", "0.0.0.0"):
                            continue
                        cleaned_pivots.append(p_clean)
                        
                    if cleaned_pivots:
                        seed_epoch = current_alerts[0]["metadata"]["timestamp_epoch"]
                        extra_fused = await asyncio.to_thread(
                            vector_engine.correlate_rrf,
                            active_indicators=cleaned_pivots,
                            query_text=" ".join(cleaned_pivots),
                            timestamp_epoch=seed_epoch,
                            time_window_sec=86400
                        )
                        
                        correlated_ids = {a["id"] for a in current_alerts}
                        for alert_id, score, doc, meta in extra_fused:
                            if alert_id not in correlated_ids:
                                correlated_ids.add(alert_id)
                                current_alerts.append({
                                    "id": alert_id,
                                    "document": doc,
                                    "metadata": meta
                                })
                                orchestrator.log_success(f"Dynamic retrieval matched alert {alert_id} (RRF: {score:.4f})")
                                
                # 3. Pass 2 (Always compile final report for dynamic/cluster incidents)
                report = await orchestrator.compile_final_report(current_alerts, playbook_path, p1_trace)
                
            # Save and sync final report
            sev_map = {
                "low": IncidentSeverity.LOW,
                "medium": IncidentSeverity.MEDIUM,
                "high": IncidentSeverity.HIGH,
                "critical": IncidentSeverity.CRITICAL
            }
            mapped_severity = sev_map.get(report.severity.lower(), IncidentSeverity.MEDIUM)
            
            indicators_set = set()
            for alert in current_alerts:
                for ind in engine._extract_indicators(alert):
                    indicators_set.add(ind)
                    
            dest_dir = os.path.join(INCIDENT_REPORTS_FOLDER, inst_id)
            
            incident.raw_alerts = current_alerts
            incident.summary_text = report.incident_summary
            incident.metadata.severity = mapped_severity
            incident.metadata.updated_at = time.time()
            incident.indicators = list(indicators_set)
            
            async with db_lock:
                await engine.sync_update_incident(incident)
            
            # Write final markdown report
            write_markdown_report(dest_dir, inst_id, report)

        await asyncio.gather(*(process_incident_report(inst_id) for inst_id in modified_incidents))
        
    # Stop background realtime sync daemon
    stop_background_sync(sync_service, sync_thread, sync_loop)
    orchestrator.log_info("SOC Incident Response Pipeline shut down successfully.")

def main():
    asyncio.run(main_async())

if __name__ == "__main__":
    main()
