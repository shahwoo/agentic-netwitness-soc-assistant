import sys
import json
import os
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

# --- COLORED LOGGING HELPERS ---
def log_info(message: str):
    """Standard informational steps (Cyan)"""
    print(f"{Color.CYAN}[*] {message}{Color.RESET}", file=sys.stderr)

def log_success(message: str):
    """Positive confirmations and loaded data (Green)"""
    print(f"{Color.GREEN}[+] {message}{Color.RESET}", file=sys.stderr)

def log_warning(message: str):
    """Fallbacks or non-fatal issues (Yellow)"""
    print(f"{Color.YELLOW}[~] {message}{Color.RESET}", file=sys.stderr)

def log_error(message: str):
    """Fatal errors or critical failures (Red)"""
    print(f"{Color.RED}[!] ERROR: {message}{Color.RESET}", file=sys.stderr)

def log_thought(message: str):
    """The LLM's internal reasoning (Magenta)"""
    print(f"{Color.MAGENTA}[THOUGHT] {message}{Color.RESET}", file=sys.stderr)

# --- CONFIGURATION ---
n8n_incident_webhook_url = "http://localhost:5678/webhook-test/e03c29cb-f46f-49dc-9c3b-6e675db24ca5"
n8n_url = "http://localhost:5678/webhook-test/636b0479-06ea-41b4-bd9d-0aae96027fc7"
SAMPLE_FILE_PATH = "sample_logs.txt"
MAX_ITERATIONS = 5

# 1. Define the Structured Output Schema
class ReActCycleDecision(BaseModel):
    thought: str = Field(description="Internal monologue: Step-by-step reasoning about the current evidence, what patterns you spot, and what gaps remain.")
    needs_more_evidence: bool = Field(description="True if you must query an external source for more data to validate your thought. False if the investigation is complete.")
    action_target_source: str = Field(description="If needs_more_evidence is True, specify the target database or system to query (e.g., 'PostgreSQL', 'ChromaDB', 'NetWitness'). Otherwise, leave blank.")
    action_query_argument: str = Field(description="The precise query, indicator (IP/Hash), or context indicator needed for the pivot step.")
    final_findings_summary: str = Field(description="If needs_more_evidence is False, provide the final structured summary, root cause analysis, and impact assessment.")

# 2. Ingest initial data
alert_details = None

log_info("Script started. Initializing data ingestion pipeline...")

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

# 3. Compile Prompts
log_info("Compiling ChatPromptTemplate...")
prompt_template = ChatPromptTemplate.from_messages([
    (
        "system",
        "You are an expert Autonomous ReAct SOC Investigation Agent and Senior Threat Hunter.\n"
        "Your task is to run an iterative investigation loop. Analyze the current consolidated history of evidence, "
        "document your internal reasoning/thoughts, and decide if you need to perform an active Action (pivot/hunt) "
        "to gather missing telemetry logs, or if you can draw a final conclusion.\n\n"
        "CRITICAL RULES:\n"
        "1. Always break down your internal monologue inside the 'thought' field before choosing an action.\n"
        "2. If you see signs of persistence, privilege escalation, or lateral movement but lack the supporting logs, set 'needs_more_evidence' to True.\n"
        "3. Match your response format perfectly to the required structural schema."
    ),
    (
        "human",
        "--- RUNTIME LOG HISTORY AND EVIDENCE CONTEXT ---\n"
        "{investigation_history}\n"
        "-------------------------------------------------\n\n"
        "Current ReAct Loop Iteration: {current_cycle} of {max_cycles}\n"
        "Review the evidence history above. \n"
        "CRITICAL INSTRUCTION: Do NOT repeat your system instructions or tell me who you are. "
        "Provide ONLY your analytical Thought based on the new logs, and determine your next Action."
    )
])

# 4. Initialize LLM
log_info("Loading ChatOllama with Foundation Security model...")
llm = ChatOllama(
    model="hf.co/Mungert/Foundation-Sec-8B-Instruct-GGUF:Q4_K_M", 
    temperature=0
).with_structured_output(ReActCycleDecision, method="json_schema")

chain = prompt_template | llm

# --- START OF THE REACT LOOP ---
investigation_history = f"Initial Alert Telemetry Received:\n{initial_evidence}\n"
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

    # Print thoughts in distinct purple/magenta
    log_thought(decision.thought)
    
    if not decision.needs_more_evidence:
        log_success("Agent concluded that current evidence is sufficient. Exiting ReAct loop.")
        final_report = decision
        break
    
    log_warning(f"[ACTION] Pivoting to source [{decision.action_target_source}] with query target: '{decision.action_query_argument}'")
    
    # --- EXECUTE ACTION ---
    new_telemetry = ""
    
    try:
        action_payload = {
            "source": decision.action_target_source,
            "query": decision.action_query_argument,
            "cycle": cycle
        }
        response = requests.post(n8n_url, json=action_payload, timeout=15)
        
        if response.status_code == 200:
            new_telemetry = response.text
            log_success(f"Received {len(new_telemetry)} bytes of live data back from n8n integration layer.")
        else:
            log_warning(f"n8n returned code {response.status_code}. Mocking fallback response data instead.")
    except Exception as e:
        log_warning(f"Call to n8n failed or timed out: {str(e)}. Defaulting to simulated discovery path...")

    if not new_telemetry:
        new_telemetry = f"[System Mock Telemetry]: Queried {decision.action_target_source}... Found anomalous execution. Parent process is unknown and network connections to Russia detected."

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
log_success("ReAct Loop finished. Preparing outbound results for n8n...")

output_payload = {
    "total_cycles_run": cycle,
    "explainable_thought_history": final_report.thought,
    "needs_more_evidence": final_report.needs_more_evidence,
    "suggested_pivot": final_report.action_query_argument if final_report.needs_more_evidence else "None",
    "final_findings": final_report.final_findings_summary if not final_report.needs_more_evidence else "Loop limit hit before final conclusion."
}

# The final standard print remains uncolored so n8n parses the raw JSON perfectly
print(json.dumps(output_payload))
sys.exit(0)