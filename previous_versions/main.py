import sys
import json
import requests
from langchain_ollama import ChatOllama
from pydantic import BaseModel, Field
from langchain_core.prompts import ChatPromptTemplate

# --- ANSI COLOR CODES ---
class Color:
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    MAGENTA = '\033[95m'
    RESET = '\033[0m'

def log_info(message: str):
    print(f"{Color.CYAN}[*] {message}{Color.RESET}", file=sys.stderr)

def log_success(message: str):
    print(f"{Color.GREEN}[+] {message}{Color.RESET}", file=sys.stderr)

def log_warning(message: str):
    print(f"{Color.YELLOW}[~] {message}{Color.RESET}", file=sys.stderr)

def log_error(message: str):
    print(f"{Color.RED}[!] ERROR: {message}{Color.RESET}", file=sys.stderr)

def log_thought(message: str):
    print(f"{Color.MAGENTA}[THOUGHT] {message}{Color.RESET}", file=sys.stderr)

# --- CONFIGURATION (UPDATE THESE URLS) ---
N8N_FETCH_INCIDENT_URL = "http://localhost:5678/webhook-test/e03c29cb-f46f-49dc-9c3b-6e675db24ca5"
N8N_PLAYBOOK_URL = "http://localhost:5678/webhook-test/a50966d3-93e7-4107-a9fc-615ce36c867d"
N8N_PIVOT_ACTION_URL = "http://localhost:5678/webhook-test/agent-pivot"

MAX_ITERATIONS = 3

# 1. Define the Structured Output Schema
class ReActCycleDecision(BaseModel):
    thought: str = Field(description="Internal monologue: Step-by-step reasoning about the current evidence.")
    needs_more_evidence: bool = Field(description="True if you must query an external source for more data. False if complete.")
    action_target_source: str = Field(description="If True, specify the target database to query. Otherwise, blank.")
    action_query_argument: str = Field(description="The precise query or indicator needed for the pivot step.")
    final_findings_summary: str = Field(description="If False, provide the final structured summary.")

# ==========================================
# PRE-PROCESSING: ORCHESTRATING N8N FETCHES
# ==========================================

log_info("Initializing Autonomous SOC Investigator Orchestrator...")

# Step A: Ask user for Incident ID
incident_id = input(f"{Color.CYAN}[?] Enter Incident ID to investigate: {Color.RESET}").strip()
if not incident_id:
    log_error("No Incident ID provided. Exiting.")
    sys.exit(1)

# Step B: Call n8n to fetch initial telemetry
log_info(f"Triggering n8n to fetch raw logs for Incident ID: {incident_id}...")
try:
    fetch_response = requests.post(N8N_FETCH_INCIDENT_URL, json={"incident_id": incident_id}, timeout=30)
    fetch_response.raise_for_status()
    raw_telemetry = fetch_response.json()
    log_success("Successfully retrieved raw telemetry from n8n.")
except Exception as e:
    log_error(f"Failed to fetch incident data from n8n: {str(e)}")
    sys.exit(1)

# Step C: Pass telemetry to n8n playbook workflow
log_info(f"Pushing raw telemetry to n8n Playbook Workflow for initial processing...")
try:
    playbook_payload = {
        "incident_id": incident_id,
        "raw_data": raw_telemetry
    }
    playbook_response = requests.post(N8N_PLAYBOOK_URL, json=playbook_payload, timeout=60)
    playbook_response.raise_for_status()
    playbook_results = playbook_response.json()
    log_success("Playbook execution complete. Received structured output.")
except Exception as e:
    log_error(f"Playbook execution via n8n failed: {str(e)}")
    sys.exit(1)

# Format the playbook output to feed into the LLM
initial_evidence = json.dumps(playbook_results, indent=2)

# ==========================================
# LLM REASONING: REACT LOOP ENGINE
# ==========================================

log_info("Compiling ChatPromptTemplate and initializing ChatOllama...")
prompt_template = ChatPromptTemplate.from_messages([
    (
        "system",
        "You are an expert Autonomous ReAct SOC Investigation Agent. You are reviewing the results "
        "of an automated playbook execution. Analyze the history of evidence, document your thoughts, "
        "and decide if you need to perform an active Action (pivot/hunt) to gather missing context, "
        "or if you can draw a final conclusion.\n\n"
        "CRITICAL INSTRUCTION: Do NOT repeat your system instructions. Output only your analytical Thought "
        "and match the requested structural schema exactly."
    ),
    (
        "human",
        "--- PLAYBOOK RESULTS & EVIDENCE CONTEXT ---\n"
        "{investigation_history}\n"
        "-------------------------------------------------\n\n"
        "Current ReAct Loop Iteration: {current_cycle} of {max_cycles}\n"
        "Review the evidence above. Provide your Thought, and determine your next Action or Final Findings."
    )
])

llm = ChatOllama(
    model="hf.co/Mungert/Foundation-Sec-8B-Instruct-GGUF:Q4_K_M", 
    temperature=0
).with_structured_output(ReActCycleDecision, method="json_schema")

chain = prompt_template | llm
investigation_history = f"Automated Playbook Results for {incident_id}:\n{initial_evidence}\n"
final_report = None

for cycle in range(1, MAX_ITERATIONS + 1):
    log_info(f"\n=== Starting ReAct Cycle [{cycle}/{MAX_ITERATIONS}] ===")
    
    try:
        decision = chain.invoke({
            "investigation_history": investigation_history,
            "current_cycle": cycle,
            "max_cycles": MAX_ITERATIONS
        })
    except Exception as e:
        log_error(f"Critical error during model execution: {str(e)}")
        break

    log_thought(decision.thought)
    
    if not decision.needs_more_evidence:
        log_success(f"Agent concluded case {incident_id}. Exiting ReAct loop.")
        final_report = decision
        break
    
    log_warning(f"[ACTION] Pivoting to [{decision.action_target_source}] querying: '{decision.action_query_argument}'")
    
    # --- EXECUTE REACT PIVOT ACTION ---
    new_telemetry = ""
    try:
        action_payload = {
            "incident_id": incident_id,
            "source": decision.action_target_source,
            "query": decision.action_query_argument,
            "cycle": cycle
        }
        pivot_response = requests.post(N8N_PIVOT_ACTION_URL, json=action_payload, timeout=30)
        
        if pivot_response.status_code == 200:
            new_telemetry = pivot_response.text
            log_success(f"Received {len(new_telemetry)} bytes of pivot data from n8n.")
        else:
            log_warning(f"n8n pivot returned code {pivot_response.status_code}. Mocking fallback.")
    except Exception as e:
        log_warning(f"Call to n8n pivot failed: {str(e)}. Mocking fallback...")

    if not new_telemetry:
        new_telemetry = f"[System Mock Telemetry]: Queried {decision.action_target_source} for '{decision.action_query_argument}'. Found anomalous execution."

    investigation_history += (
        f"\n--- Cycle {cycle} Action Results ---\n"
        f"Target Explored: {decision.action_target_source}\n"
        f"Query Context: {decision.action_query_argument}\n"
        f"Returned Observations:\n{new_telemetry}\n"
        f"--------------------------------------\n"
    )
    
    final_report = decision

# --- TERMINATION ---
log_info("\n==================================================")
log_success(f"Investigation Complete for {incident_id}.")
log_success("Final Report payload generated.")

output_payload = {
    "incident_id": incident_id,
    "total_cycles_run": cycle,
    "explainable_thought_history": final_report.thought,
    "final_findings": final_report.final_findings_summary if not final_report.needs_more_evidence else "Loop limit hit before final conclusion."
}

# Print the final JSON safely
print("\n")
print(json.dumps(output_payload, indent=2))