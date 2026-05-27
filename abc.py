import sys
import json
import yaml
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

def log_info(message: str): print(f"{Color.CYAN}[*] {message}{Color.RESET}", file=sys.stderr)
def log_success(message: str): print(f"{Color.GREEN}[+] {message}{Color.RESET}", file=sys.stderr)
def log_warning(message: str): print(f"{Color.YELLOW}[~] {message}{Color.RESET}", file=sys.stderr)
def log_error(message: str): print(f"{Color.RED}[!] ERROR: {message}{Color.RESET}", file=sys.stderr)
def log_thought(step: str, message: str): 
    print(f"{Color.MAGENTA}[PLAYBOOK NODE: {step}]\n{message}{Color.RESET}\n", file=sys.stderr)

# ==========================================
# 1. FILE LOADERS
# ==========================================
def load_text_file(filepath: str) -> str:
    try:
        with open(filepath, 'r', encoding='utf-8') as file:
            return file.read()
    except Exception as e:
        log_error(f"Failed to load document {filepath}: {e}")
        return "File not found."

def load_yaml_playbook(filepath: str) -> tuple[str, dict]:
    try:
        with open(filepath, 'r', encoding='utf-8') as file:
            parsed_yaml = yaml.safe_load(file)
            return yaml.dump(parsed_yaml, default_flow_style=False), parsed_yaml
    except Exception as e:
        log_error(f"Failed to load playbook {filepath}: {e}")
        return "Playbook not found.", {}

POLICIES_FILE = load_text_file("policies/soc_policies.md")
CONTAINMENT_FILE = load_text_file("policies/soc_policies.md")
PLAYBOOK_TEXT, PLAYBOOK_DICT = load_yaml_playbook("playbooks/phishing.yaml")
UNREAD_ALERTS_FOLDER = "triaged_alerts/"
INCIDENT_REPORTS_FOLDER = "incident_reports/"

# ==========================================
# 2. THE PLAYBOOK REASONING ENGINE (SCHEMA)
# ==========================================
class PlaybookDrivenDecision(BaseModel):
    thought_process: str = Field(
        description="1. Does this node require gathering new data, or just analyzing existing data? 2. Look at the Investigation History: Did I ALREADY query and get a response for this specific step? 3. What is my next move?"
    )
    needs_external_query: bool = Field(
        description="True ONLY if the node requires querying AND the response is NOT yet in the Investigation History. False if the node is passive analysis, OR if the query response is already present in the history."
    )
    action_target_agent: str = Field(
        description="If needs_external_query is True, write the agent name (e.g., 'Triage_Agent'). Otherwise, write 'None'."
    )
    action_query_argument: str = Field(
        description="CRITICAL: If needs_external_query is True, write ONLY the technical query parameters STRICTLY using the format 'key=value' (e.g., 'ip.dst=188.40.170.197', 'domain=example.com'). DO NOT write any words. DO NOT repeat the playbook instructions. Otherwise, write 'None'. Failures will break the pipline."
    )
    next_routing_step: str = Field(
        description="If needs_external_query is True, write 'WAITING'. If False, evaluate the routing rules based on the data and write the exact YAML ID of the NEXT step."
    )
    final_findings_summary: str = Field(
        description="If next_routing_step is 'TERMINAL', provide the final structured summary. Otherwise, write 'None'."
    )

# ==========================================
# 3. UPSTREAM: TRIAGE AGENT PLACEHOLDER
# ==========================================
def fetch_from_triage_agent() -> str:
    log_info("Awaiting payload from Upstream Triage Agent...")
    triage_payload = {
        "Severity": "High",
        "IOCs": {
            "SourceIp": ["192.168.10.210"],
            "DestinationIp": ["188.40.170.197"]
        }
    }
    return json.dumps(triage_payload, indent=2)

# ==========================================
# 4. SYSTEM PROMPT COMPILATION
# ==========================================
SYSTEM_PROMPT = """You are the Lead Playbook Execution Agent. You operate as a strict State Machine, with the purpose of mapping out the entire attack and categorizing all related alerts into 1 incident.
You are currently evaluating the node: [{current_node}].

### REFERENCE FILES
--- POLICIES ---
{policies}
--- CONTAINMENT ---
{containment}
--- PLAYBOOK YAML ---
{playbook}

### STATE MACHINE EXECUTION PROTOCOL:
Read the `instructions` for [{current_node}], then follow this exact decision tree:

IF the instruction is Passive Analysis (e.g., "Identify", "Analyze", "Compare"):
  - Set `needs_external_query` to False.
  - Read the YAML `routing` rules and output the next step ID.

IF the instruction is Data Gathering (e.g., "Query"):
  - Check the Investigation History. Do you have enough information to execute this node, or do you need to query an external agent?
  - IF INSUFFICIENT DATA: 
      - Set `needs_external_query` to True.
      - Extract the specific Indicators of Compromise to search. 
      - Evaluate the YAML `routing` rules based on the new data and output the next step ID.
  - IF SUFFICIENT DATA: 
      - Set `needs_external_query` to False. 
      - Evaluate the YAML `routing` rules based on the new data and output the next step ID.

IF [{current_node}] contains a `status` field instead of `routing`:
  - Set `next_routing_step` to 'TERMINAL' and write the `final_findings_summary`.
"""

prompt_template = ChatPromptTemplate.from_messages([
    ("system", SYSTEM_PROMPT),
    (
        "human",
        "--- INVESTIGATION HISTORY ---\n"
        "{investigation_history}\n"
        "-----------------------------\n\n"
        "Execute node [{current_node}]. Follow the State Machine Execution Protocol strictly."
    )
])

# ==========================================
# 5. EXECUTION & ROUTING LOOP
# ==========================================
if __name__ == "__main__":
    MAX_ITERATIONS = 8
    
    log_info("Loading ChatOllama with Foundation Security model...")
    llm = ChatOllama(
        model="hf.co/Mungert/Foundation-Sec-8B-Instruct-GGUF:Q4_K_M", 
        temperature=0
    ).with_structured_output(PlaybookDrivenDecision, method="json_schema")

    chain = prompt_template | llm

    initial_evidence = fetch_from_triage_agent()
    investigation_history = f"Initial Payload from Triage Agent:\n{initial_evidence}\n"
    final_report = None
    
    current_yaml_node = "step_1"

    for cycle in range(1, MAX_ITERATIONS + 1):
        log_info(f"\n=== Starting Playbook Cycle [{cycle}/{MAX_ITERATIONS}] ===")
        
        try:
            decision = chain.invoke({
                "policies": POLICIES_FILE,
                "containment": CONTAINMENT_FILE,
                "playbook": PLAYBOOK_TEXT,
                "investigation_history": investigation_history,
                "current_node": current_yaml_node
            })
        except Exception as e:
            log_error(f"Failed to parse structured JSON. Retrying: {str(e)}")
            continue

        log_thought(current_yaml_node, decision.thought_process)
        
        # 1. Evaluate Data Gathering requirements
        print(decision.needs_external_query, decision.action_target_agent, decision.action_query_argument, decision.next_routing_step)
        if decision.needs_external_query:
            log_warning(f"Data gap detected. Routing query to [{decision.action_target_agent}]: '{decision.action_query_argument}'")
            
            # --- DYNAMIC MOCK RESPONSE FOR TESTING THE PIVOT LOOP ---
            if current_yaml_node == "step_2_query_triage_agent" and "192.168.10.210" in decision.action_query_argument: # This simulates the Triage Agent responding with new intelligence that the Lead Agent can use to pivot its investigation.
                simulated_response = "[Triage Agent]: Found new associated IP 10.5.5.5 communicating with this host."
                
                lenOldInvHist = len(investigation_history)
                investigation_history += (
                f"\n--- Cycle {cycle} Evidence Gathered ---\n"
                f"Source: {decision.action_target_agent}\n"
                f"Data: {simulated_response}\n"
                f"--------------------------------------\n"
            )
            
            log_success(f"Received new data from [{decision.action_target_agent}]. Updated Investigation History.")
            current_yaml_node = "step_2a_expand_search"
            
        # ==========================================
        # 2. PYTHON-ENFORCED STOP CONDITION (THE REFEREE)
        # ==========================================
        current_node_data = PLAYBOOK_DICT.get('steps', {}).get(current_yaml_node, {})
        
        if 'status' in current_node_data:
            log_success(f"Terminal node [{current_yaml_node}] reached. Status: '{current_node_data['status']}'. Investigation concluded.")
            final_report = decision
            break
            
        # Advance the pointer using the LLM's routing choice
        log_success(f"Node [{current_yaml_node}] resolved. Routing to -> {decision.next_routing_step}")
        current_yaml_node = decision.next_routing_step
        final_report = decision

    # ==========================================
    # 6. DOWNSTREAM: REPORTING AGENT HANDOFF
    # ==========================================
    log_info("\n==================================================")
    log_success("Initiating handoff to Downstream Reporting Agent...")

    handoff_payload = {
        "status": "PLAYBOOK_COMPLETE",
        "total_cycles_run": cycle,
        "final_node_reached": current_yaml_node,
        "summary_for_reporting_agent": final_report.final_findings_summary if final_report else "Error"
    }

    # Print raw JSON for downstream agents or webhooks to catch
    print(json.dumps(handoff_payload, indent=2))
    sys.exit(0)