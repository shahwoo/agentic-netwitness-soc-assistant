import os
import sys
import json
import yaml
import re
from typing import List, Literal, Optional
from pydantic import BaseModel, Field
from dotenv import load_dotenv
from langchain_openai import ChatOpenAI
from langchain_core.prompts import ChatPromptTemplate

import ingest_pipeline
import vector_engine

load_dotenv()

# --- ANSI COLOR CODES ---
class Color:
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    MAGENTA = '\033[95m'
    RESET = '\033[0m'

def log_info(message: str): print(f"{Color.CYAN}[*] {message}{Color.RESET}", file=sys.stderr)
def log_success(message: str): print(f"{Color.GREEN}[+] {message}{Color.RESET}", file=sys.stderr)
def log_warning(message: str): print(f"{Color.YELLOW}[~] {message}{Color.RESET}", file=sys.stderr)
def log_error(message: str): print(f"{Color.RED}[!] ERROR: {message}{Color.RESET}", file=sys.stderr)

# --- PYDANTIC SCHEMAS FOR STRUCTURED OUTPUT ---

class SuspiciousSeeds(BaseModel):
    seeds: List[str] = Field(description="A list of suspicious IOCs/tokens to query for, excluding generic benign items.")

class MilestoneCheck(BaseModel):
    milestone_met: bool = Field(description="True if the active playbook step can be fully answered with the current incident timeline, otherwise False.")
    reasoning: str = Field(description="Explanation of whether the milestone is met, detailing what was found or what is missing.")
    extracted_data: Optional[str] = Field(description="The extracted data for this step if the milestone is met, otherwise null.")
    suggested_pivots: List[str] = Field(default_factory=list, description="List of suspected IOCs/keys/pivots to query ChromaDB for to gather more context. Return concrete indicators (values), not descriptions.")

class MilestoneExecution(BaseModel):
    step_id: str
    instruction: str
    status: Literal["MET", "NOT_MET", "SKIPPED"]
    findings: str

class FinalIncidentAnalysis(BaseModel):
    incident_id: str
    severity: Literal["Low", "Medium", "High", "Critical"]
    confidence: Literal["Low", "Medium", "High"]
    execution_trace: List[MilestoneExecution] = Field(description="The step-by-step trace of how the playbook was executed.")
    incident_summary: str = Field(description="Chronological summary of what happened.")
    actions_taken: List[str] = Field(description="Actions taken during investigation.")
    lessons_learnt: str
    recommended_containment: List[str] = Field(description="Recommended containment actions based on policies.")

class Pass1IncidentResult(BaseModel):
    report: FinalIncidentAnalysis = Field(description="The final incident report based on the current timeline.")
    suggested_pivots: List[str] = Field(default_factory=list, description="Concrete indicator values (IPs, domains, hashes, usernames) to query to resolve any unmet steps.")

# --- LLM INITIALIZATION ---

def get_llm():
    api_key = os.getenv("OPENAI_API_KEY")
    return ChatOpenAI(
        model="gpt-4o-mini",
        temperature=0,
        openai_api_key=api_key
    )

# --- MICRO-TASK IMPLEMENTATIONS ---

def filter_suspicious_seeds(raw_tokens: List[str]) -> List[str]:
    """Micro-Task 1: Stateless LLM filtering to strip benign infrastructure noise from seeds."""
    if not raw_tokens:
        return []
    
    log_info(f"[LLM CALL] Invoking Micro-Task 1: Intelligent Indicator Filter on {len(raw_tokens)} tokens...")
    
    system_prompt = (
        "You are an expert SOC Analyst. You are given a list of extracted tokens from raw SIEM logs.\n"
        "Filter out benign infrastructure noise (such as localhost, 127.0.0.1, 8.8.8.8, 1.1.1.1, common microsoft/windows domains,\n"
        "generic system files like svchost.exe or cmd.exe, and empty/invalid values).\n"
        "Return a clean list of only suspicious or investigative tokens (IPs, subnets, domains, hashes, usernames, hosts) to serve as search seeds."
    )
    
    prompt = ChatPromptTemplate.from_messages([
        ("system", system_prompt),
        ("human", "Extracted raw tokens: {tokens}")
    ])
    
    try:
        chain = prompt | get_llm().with_structured_output(SuspiciousSeeds, method="json_schema")
        result = chain.invoke({"tokens": str(raw_tokens)})
        log_success(f"[LLM RESPONSE] Filtered tokens: {result.seeds}")
        return result.seeds
    except Exception as e:
        log_error(f"Failed to filter seeds with LLM: {e}. Falling back to original tokens.")
        benign = {"127.0.0.1", "0.0.0.0", "localhost", "svchost.exe", "Unknown"}
        return [t for t in raw_tokens if t not in benign]

def check_milestone_sufficiency(timeline_str: str, instruction: str, step_id: str) -> MilestoneCheck:
    """Micro-Task 2: Stateless LLM checking to verify if timeline evidence meets playbook step criteria."""
    log_info(f"[LLM CALL] Invoking Micro-Task 2: Milestone Sufficiency Check for step {step_id}...")
    
    system_prompt = (
        "You are a SOC automation sub-agent validating a specific playbook milestone.\n"
        "Review the chronological Incident Timeline provided, and determine if it contains enough evidence\n"
        "to satisfy the active step instruction.\n"
        "If yes, set milestone_met = True and populate the extracted_data field with a direct answer to the instruction.\n"
        "If no, set milestone_met = False, explain in reasoning what is missing, and suggest new IOCs/pivots (values only) to search for."
    )
    
    prompt = ChatPromptTemplate.from_messages([
        ("system", system_prompt),
        ("human", "=== INCIDENT TIMELINE ===\n{timeline}\n\n=== PLAYBOOK STEP INSTRUCTION ===\n{instruction}")
    ])
    
    try:
        chain = prompt | get_llm().with_structured_output(MilestoneCheck, method="json_schema")
        result = chain.invoke({"timeline": timeline_str, "instruction": instruction})
        log_success(f"[LLM RESPONSE] Step {step_id} Met: {result.milestone_met} | Reasoning: {result.reasoning}")
        return result
    except Exception as e:
        log_error(f"Failed to verify milestone with LLM: {e}")
        return MilestoneCheck(
            milestone_met=False,
            reasoning=f"Error calling LLM: {e}",
            extracted_data=None,
            suggested_pivots=[]
        )

def generate_final_analysis(incident_id: str, playbook_name: str, timeline_str: str, execution_trace: List[MilestoneExecution]) -> FinalIncidentAnalysis:
    """Final Structural Reporting: Invoked exactly once at the end of the analysis phase."""
    log_info(f"[LLM CALL] Invoking Final Structural Reporting for incident {incident_id}...")
    
    system_prompt = (
        "You are a Lead SOC Incident Responder. Review the provided Incident Timeline and the Playbook Execution Trace,\n"
        "and generate a final, structured incident report using the specified Pydantic schema.\n"
        "Your report must follow cybersecurity policies: assign final severity/confidence, summarize the timeline,\n"
        "document execution steps, list actions taken, highlight lessons learnt, and detail containment recommendations."
    )
    
    trace_json = json.dumps([t.model_dump() for t in execution_trace], indent=2)
    
    prompt = ChatPromptTemplate.from_messages([
        ("system", system_prompt),
        ("human", "=== INCIDENT ID ===\n{incident_id}\n\n=== PLAYBOOK ===\n{playbook}\n\n=== INCIDENT TIMELINE ===\n{timeline}\n\n=== PLAYBOOK TRACE ===\n{trace}")
    ])
    
    try:
        chain = prompt | get_llm().with_structured_output(FinalIncidentAnalysis, method="json_schema")
        result = chain.invoke({
            "incident_id": incident_id,
            "playbook": playbook_name,
            "timeline": timeline_str,
            "trace": trace_json
        })
        log_success(f"[LLM RESPONSE] Generated final report with severity: {result.severity} | confidence: {result.confidence}")
        return result
    except Exception as e:
        log_error(f"Failed to generate final structured report: {e}")
        return FinalIncidentAnalysis(
            incident_id=incident_id,
            severity="High",
            confidence="Low",
            execution_trace=execution_trace,
            incident_summary=f"Analysis failed due to error: {e}. Timeline: {timeline_str}",
            actions_taken=["Triage", "Vector Correlation"],
            lessons_learnt="Verify LLM API limits and schema compatibility.",
            recommended_containment=["Isolate system and review logs manually."]
        )

# --- CONSTRUCT TIMELINE TEXT ---

def build_timeline_text(correlated_alerts: List[dict]) -> str:
    """Formats list of correlated alerts into a chronological summary string."""
    lines = []
    sorted_alerts = sorted(correlated_alerts, key=lambda x: x["metadata"]["timestamp_epoch"])
    
    for alert in sorted_alerts:
        ts = alert["metadata"]["timestamp_str"]
        alert_id = alert["id"]
        doc = alert["document"]
        lines.append(f"[{ts}] {alert_id}: {doc}")
        
    return "\n".join(lines)

# --- INFRASTRUCTURE BROADENING ---

IP_PAT = re.compile(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.)\d{1,3}$')

def broaden_indicators(indicators: List[str]) -> List[str]:
    """Returns the indicators list directly without broadening (subnet/domain expansion disabled)."""
    return list(indicators)

# --- SEED PREPARATION AND FILTER WHITELISTING ---

def prepare_seeds(raw_tokens: List[str]) -> List[str]:
    """Protects high-fidelity indicators (private IPs, subnets, hashes, emails, names) from LLM filter."""
    high_fidelity = []
    to_filter = []
    
    for token in raw_tokens:
        token_str = str(token).strip()
        token_lower = token_str.lower()
        if not token_str or token_lower in ("unknown", "null", "none", ""):
            continue
            
        # Check if it's an IP address or subnet
        is_ip_or_subnet = False
        if token_lower.endswith('.'):
            is_ip_or_subnet = True
        elif re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', token_str):
            is_ip_or_subnet = True
            
        if is_ip_or_subnet:
            # Check if it is a private (RFC 1918) network
            if (token_str.startswith("10.") or 
                token_str.startswith("192.168.") or 
                (token_str.startswith("172.") and len(token_str.split('.')) > 1 and token_str.split('.')[1].isdigit() and 16 <= int(token_str.split('.')[1]) <= 31)):
                high_fidelity.append(token_str)
            else:
                to_filter.append(token_str)
        # Check if it is a cryptographic hash (MD5 or SHA256)
        elif len(token_str) in (32, 64) and re.match(r'^[a-fA-F0-9]+$', token_str):
            high_fidelity.append(token_str)
        # Check if it is an email
        elif '@' in token_str and '.' in token_str:
            high_fidelity.append(token_str)
        # Check if hostname or username (usually doesn't have dots)
        elif '.' not in token_str:
            high_fidelity.append(token_str)
        else:
            # Public IPs and external domains go to the LLM filter
            to_filter.append(token_str)
            
    # Filter noisy domains/public IPs using Micro-Task 1
    filtered = filter_suspicious_seeds(to_filter)
    
    # Combine whitelisted structural indicators and filtered seeds
    return list(set(high_fidelity + filtered))

# --- HYBRID ORCHESTRATOR CORRELATION FLOW ---

def orchestrate_incident(seed_alert_path: str, playbook_path: str) -> dict:
    """Orchestrates ingestion, transitive-closure metadata pivoting, milestone checks, and final reporting."""
    # 1. Process Seed Alert
    seed_log = ingest_pipeline.process_log_file(seed_alert_path)
    seed_id = seed_log["id"]
    
    log_info(f"Starting orchestration for Seed Alert: {seed_id}")
    
    # 2. Extract initial seeds from Seed Alert
    seed_indicators = ingest_pipeline.scan_indicators(json.dumps(seed_log["metadata"]))
    raw_tokens = []
    raw_tokens.extend(seed_indicators["ips"])
    raw_tokens.extend(seed_indicators["sha256s"])
    raw_tokens.extend(seed_indicators["md5s"])
    raw_tokens.extend(seed_indicators["emails"])
    raw_tokens.extend(seed_indicators["domains"])
    if seed_log["metadata"]["username"] and seed_log["metadata"]["username"] != "Unknown":
        raw_tokens.append(seed_log["metadata"]["username"])
    if seed_log["metadata"]["hostname"] and seed_log["metadata"]["hostname"] != "Unknown":
        raw_tokens.append(seed_log["metadata"]["hostname"])
        
    # Apply initial broadening and prepare clean whitelisted seeds
    broadened_initial = broaden_indicators(list(set(raw_tokens)))
    active_seeds = prepare_seeds(broadened_initial)
    
    # Initialize pivoting collections
    correlated_alerts = [seed_log]
    correlated_ids = {seed_id}
    processed_seeds = set()
    
    # Transitive Closure fixed-point loop
    stable = False
    hop_count = 0
    MAX_HOPS = 6
    
    while not stable:
        hop_count += 1
        if hop_count > MAX_HOPS:
            log_warning(f"CIRCUIT BREAKER TRIGGERED: Attack chain topology runs deeper than {MAX_HOPS} hops!")
            break
            
        previous_ids = set(correlated_ids)
        
        # Get seeds not yet queried
        new_seeds = [s for s in active_seeds if s not in processed_seeds]
        if not new_seeds:
            stable = True
            break
            
        log_info(f"Pivoting Hop [{hop_count}] on seeds: {new_seeds}")
        seed_epoch = seed_log["metadata"]["timestamp_epoch"]
        
        # Query ChromaDB using RRF
        fused = vector_engine.correlate_rrf(
            active_indicators=new_seeds,
            query_text=" ".join(new_seeds),
            timestamp_epoch=seed_epoch,
            time_window_sec=86400  # 24 hour window
        )
        
        # Mark seeds as processed
        for s in new_seeds:
            processed_seeds.add(s)
            
        for alert_id, score, doc, meta in fused:
            if alert_id not in correlated_ids:
                correlated_ids.add(alert_id)
                new_alert = {
                    "id": alert_id,
                    "document": doc,
                    "metadata": meta
                }
                correlated_alerts.append(new_alert)
                log_success(f"Correlated related alert {alert_id} (RRF Score: {score:.4f})")
                
                # Scan new alert for additional indicators
                flat_meta = json.dumps(meta)
                new_inds = ingest_pipeline.scan_indicators(flat_meta)
                new_tokens = []
                new_tokens.extend(new_inds["ips"])
                new_tokens.extend(new_inds["sha256s"])
                new_tokens.extend(new_inds["md5s"])
                new_tokens.extend(new_inds["emails"])
                new_tokens.extend(new_inds["domains"])
                if meta.get("username") and meta.get("username") != "Unknown":
                    new_tokens.append(meta["username"])
                if meta.get("hostname") and meta.get("hostname") != "Unknown":
                    new_tokens.append(meta["hostname"])
                    
                # Apply broadening and filter
                broadened_new = broaden_indicators(list(set(new_tokens)))
                new_active = prepare_seeds(broadened_new)
                
                for ns in new_active:
                    if ns not in active_seeds:
                        active_seeds.append(ns)
                        
        # Check if set of correlated alerts has changed
        if correlated_ids == previous_ids:
            stable = True

    log_success(f"Transitive closure complete in {hop_count} hops. Total correlated alerts: {len(correlated_alerts)}")
    
    # Load playbook
    with open(playbook_path, "r", encoding="utf-8") as f:
        playbook_dict = yaml.safe_load(f)
        
    playbook_name = playbook_dict.get("name", "Unknown Playbook")
    
    # 3. Traversal of the Playbook nodes using Milestone Checkpoints
    current_node = "step_1"
    execution_trace = []
    visited_nodes = set()
    
    while current_node and current_node != "complete":
        if current_node in visited_nodes:
            break
        visited_nodes.add(current_node)
        
        node_data = playbook_dict.get("steps", {}).get(current_node, {})
        if not node_data:
            break
            
        instruction = node_data.get("instructions", "No instruction available.")
        routing = node_data.get("routing", "complete")
        
        # Sort and build timeline
        timeline_str = build_timeline_text(correlated_alerts)
        
        # Check sufficiency via Micro-Task 2
        check = check_milestone_sufficiency(timeline_str, instruction, current_node)
        
        status = "MET" if check.milestone_met else "NOT_MET"
        execution_trace.append(MilestoneExecution(
            step_id=current_node,
            instruction=instruction,
            status=status,
            findings=check.reasoning + (f" | Extracted Findings: {check.extracted_data}" if check.extracted_data else "")
        ))
        
        if check.milestone_met:
            # Continue to next node in schema
            if isinstance(routing, dict):
                current_node = routing.get("yes", "complete")
            else:
                current_node = routing
        else:
            # Check if there are suggested pivots to perform additional dynamic retrieval
            broadened_suggested = broaden_indicators(check.suggested_pivots)
            new_pivots = [p for p in broadened_suggested if p not in processed_seeds]
            if new_pivots:
                log_info(f"Playbook step {current_node} requested extra queries for: {new_pivots}")
                seed_epoch = seed_log["metadata"]["timestamp_epoch"]
                extra_fused = vector_engine.correlate_rrf(
                    active_indicators=new_pivots,
                    query_text=" ".join(new_pivots),
                    timestamp_epoch=seed_epoch,
                    time_window_sec=86400
                )
                
                added_any_extra = False
                for alert_id, score, doc, meta in extra_fused:
                    if alert_id not in correlated_ids:
                        correlated_ids.add(alert_id)
                        correlated_alerts.append({
                            "id": alert_id,
                            "document": doc,
                            "metadata": meta
                        })
                        added_any_extra = True
                        log_success(f"Dynamic retrieval matched alert {alert_id} (RRF: {score:.4f})")
                        
                for p in new_pivots:
                    processed_seeds.add(p)
                    
                if added_any_extra:
                    # Retry the current milestone check with enriched timeline
                    continue
            
            # Follow routing for failed checks
            if isinstance(routing, dict):
                current_node = routing.get("no", "complete")
            else:
                current_node = routing

    # 4. Generate Final Structural Analysis (Exactly once at the end)
    timeline_str = build_timeline_text(correlated_alerts)
    final_report = generate_final_analysis(seed_id, playbook_name, timeline_str, execution_trace)
    
    return {
        "correlated_alerts": correlated_alerts,
        "report": final_report
    }

def analyze_alert_group(correlated_alerts: List[dict], playbook_path: str) -> dict:
    """
    Runs the optimized two-pass consolidated playbook evaluation with active pivoting.
    
    Pass 1: Consolidated playbook check + final report draft + pivot extraction (1 LLM call).
    Database Query: Queries ChromaDB for pivots to pull in new alerts (no LLM seed filtering).
    Pass 2 (Only if new alerts found): Re-runs consolidated step check + final report with enriched timeline (1 LLM call).
    """
    with open(playbook_path, "r", encoding="utf-8") as f:
        playbook_dict = yaml.safe_load(f)
        
    playbook_name = playbook_dict.get("name", "Unknown Playbook")
    
    seed_alert = correlated_alerts[0]
    seed_id = seed_alert["id"]
    
    correlated_ids = {a["id"] for a in correlated_alerts}
    processed_seeds = set()
    
    # 1. Format playbook steps description for LLM context
    steps_desc = []
    for step_id, step_data in sorted(playbook_dict.get("steps", {}).items()):
        steps_desc.append(f"Step '{step_id}': {step_data.get('instructions')}")
    playbook_steps_str = "\n".join(steps_desc)
    
    # --- PASS 1: Consolidated Check and Report Draft ---
    timeline_str = build_timeline_text(correlated_alerts)
    log_info(f"[LLM CALL] Pass 1: Consolidated Playbook Evaluation & Pivot Extraction for {seed_id}...")
    
    system_prompt_p1 = (
        "You are a Lead SOC Incident Responder. You are given a security Playbook (list of steps) and a chronological Incident Timeline.\n"
        "Your task is to evaluate the timeline against the playbook and generate the report.\n"
        "First, for each step in the playbook, populate a MilestoneExecution:\n"
        "  - step_id: the ID of the step (e.g., 'step_1')\n"
        "  - instruction: the exact instruction of the step\n"
        "  - status: 'MET' if the timeline contains enough evidence to answer/satisfy it, otherwise 'NOT_MET'\n"
        "  - findings: a clear answer to the instruction if MET, or reasoning explaining what is missing and why if NOT_MET.\n"
        "Then, compile a list of suggested_pivots: concrete indicator values (IPs, domains, hashes, usernames) to query the logs for to resolve any NOT_MET steps. Return concrete values, not descriptions.\n"
        "Finally, generate a draft FinalIncidentAnalysis report based on the current timeline."
    )
    
    prompt_p1 = ChatPromptTemplate.from_messages([
        ("system", system_prompt_p1),
        ("human", "=== PLAYBOOK STEPS ===\n{playbook}\n\n=== INCIDENT TIMELINE ===\n{timeline}\n\n=== INCIDENT ID ===\n{incident_id}")
    ])
    
    p1_report = None
    all_suggested_pivots = []
    
    try:
        chain_p1 = prompt_p1 | get_llm().with_structured_output(Pass1IncidentResult, method="json_schema")
        p1_res = chain_p1.invoke({
            "playbook": playbook_steps_str,
            "timeline": timeline_str,
            "incident_id": seed_id
        })
        p1_report = p1_res.report
        all_suggested_pivots = p1_res.suggested_pivots
        log_success(f"[LLM RESPONSE] Pass 1 completed for {seed_id}. Suggested pivots: {all_suggested_pivots}")
    except Exception as e:
        log_error(f"Pass 1 LLM call failed: {e}")
        # Default fallback
        execution_trace = []
        for step_id, step_data in playbook_dict.get("steps", {}).items():
            execution_trace.append(MilestoneExecution(
                step_id=step_id,
                instruction=step_data.get("instructions", ""),
                status="NOT_MET",
                findings=f"Pass 1 Error: {e}"
            ))
        p1_report = FinalIncidentAnalysis(
            incident_id=seed_id,
            severity="High",
            confidence="Low",
            execution_trace=execution_trace,
            incident_summary=f"Analysis failed due to error: {e}. Timeline: {timeline_str}",
            actions_taken=["Triage"],
            lessons_learnt="Check LLM API status.",
            recommended_containment=["Isolate system and review manually."]
        )

    # --- ACTIVE DATABASE PIVOTING ---
    added_any_new = False
    if all_suggested_pivots:
        # Local fast Python indicator cleaning to avoid any LLM filter calls
        cleaned_pivots = []
        for p in all_suggested_pivots:
            p_clean = str(p).strip()
            p_lower = p_clean.lower()
            if not p_clean or p_lower in ("unknown", "null", "none", "", "localhost", "127.0.0.1", "0.0.0.0"):
                continue
            cleaned_pivots.append(p_clean)
            
        new_pivots = [p for p in cleaned_pivots if p not in processed_seeds]
        
        if new_pivots:
            log_info(f"Playbook step requested extra queries for: {new_pivots}")
            seed_epoch = seed_alert["metadata"]["timestamp_epoch"]
            extra_fused = vector_engine.correlate_rrf(
                active_indicators=new_pivots,
                query_text=" ".join(new_pivots),
                timestamp_epoch=seed_epoch,
                time_window_sec=86400
            )
            
            for alert_id, score, doc, meta in extra_fused:
                if alert_id not in correlated_ids:
                    correlated_ids.add(alert_id)
                    correlated_alerts.append({
                        "id": alert_id,
                        "document": doc,
                        "metadata": meta
                    })
                    added_any_new = True
                    log_success(f"Dynamic retrieval matched alert {alert_id} (RRF: {score:.4f})")
                    
            for p in new_pivots:
                processed_seeds.add(p)

    # --- PASS 2: Final Report (Only if new alerts found) ---
    if added_any_new:
        timeline_str = build_timeline_text(correlated_alerts)
        log_info(f"[LLM CALL] Pass 2: Re-evaluating playbook and compiling final report for {seed_id}...")
        
        system_prompt_p2 = (
            "You are a Lead SOC Incident Responder. Review the provided Incident Timeline and the previous Playbook Execution Trace,\n"
            "and generate a final, structured incident report using the specified Pydantic schema.\n"
            "First, re-evaluate each step in the playbook using the updated timeline and populate the execution_trace.\n"
            "Then, generate the final incident analysis: assign severity/confidence, summarize the chronology, list actions taken, highlight lessons learnt, and recommend containment steps based on the outcomes."
        )
        
        trace_json = json.dumps([t.model_dump() for t in p1_report.execution_trace], indent=2)
        prompt_p2 = ChatPromptTemplate.from_messages([
            ("system", system_prompt_p2),
            ("human", "=== INCIDENT ID ===\n{incident_id}\n\n=== PLAYBOOK ===\n{playbook}\n\n=== INCIDENT TIMELINE ===\n{timeline}\n\n=== PLAYBOOK TRACE ===\n{trace}")
        ])
        
        try:
            chain_p2 = prompt_p2 | get_llm().with_structured_output(FinalIncidentAnalysis, method="json_schema")
            final_report = chain_p2.invoke({
                "incident_id": seed_id,
                "playbook": playbook_name,
                "timeline": timeline_str,
                "trace": trace_json
            })
            log_success(f"[LLM RESPONSE] Generated final report for {seed_id} (Severity: {final_report.severity})")
            return {
                "correlated_alerts": correlated_alerts,
                "report": final_report
            }
        except Exception as e:
            log_error(f"Pass 2 LLM call failed: {e}")
            # Fall back to Pass 1 report with alert list update
            return {
                "correlated_alerts": correlated_alerts,
                "report": p1_report
            }
    else:
        # No new alerts found, return the Pass 1 report directly! (Saves an LLM call)
        log_info(f"Skipping Pass 2 LLM call: timeline unchanged.")
        return {
            "correlated_alerts": correlated_alerts,
            "report": p1_report
        }
