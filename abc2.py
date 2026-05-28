import sys
import json
import yaml
import os
import shutil
from langchain_ollama import ChatOllama
from pydantic import BaseModel, Field
from langchain_core.prompts import ChatPromptTemplate
from typing import List

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
def log_analyst(step: str, thought: str, answer: str):
    print(f"\n{Color.MAGENTA}==================================================")
    print(f"[PLAYBOOK: {step}]")
    print(f"\n{thought}")
    print(f"\n{Color.GREEN}{answer}")
    print(f"=================================================={Color.RESET}\n", file=sys.stderr)

# ==========================================
# 1. FILE, DIRECTORY, & CONTAINMENT MANAGERS
# ==========================================
UNREAD_ALERTS_FOLDER = "triaged_alerts/"
INCIDENT_REPORTS_FOLDER = "incident_reports/"

os.makedirs(UNREAD_ALERTS_FOLDER, exist_ok=True)
os.makedirs(INCIDENT_REPORTS_FOLDER, exist_ok=True)

def load_text_file(filepath: str) -> str:
    if not os.path.exists(filepath):
        return "File not found or empty."
    try:
        with open(filepath, 'r', encoding='utf-8') as file:
            return file.read()
    except Exception as e:
        return f"Error reading file: {e}"

def load_yaml_playbook(filepath: str) -> tuple[str, dict]:
    fallback_playbook = {
        "steps": {
            "step_1": {
                "instruction": "Determine if the attacker has successfully pivoted to adjacent systems or endpoints using compromised assets.",
                "routing": {"yes": "step_2", "no": "step_terminal_close"}
            },
            "step_2": {
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

def get_or_create_incident_folder() -> str:
    existing = [d for d in os.listdir(INCIDENT_REPORTS_FOLDER) if d.startswith("Incident-")]
    if not existing:
        next_id = "Incident-001"
    else:
        ids = [int(d.split("-")[1]) for d in existing if d.split("-")[1].isdigit()]
        next_id = f"Incident-{max(ids):03d}" if ids else "Incident-001"
    
    path = os.path.join(INCIDENT_REPORTS_FOLDER, next_id)
    os.makedirs(path, exist_ok=True)
    return path

# ==========================================
# 2. IN-MEMORY FILE SEARCH ENGINE
# ==========================================
def search_unread_alerts(query_string: str, destination_folder: str) -> str:
    if not query_string or query_string.lower() == "none":
        return ""
        
    files = [f for f in os.listdir(UNREAD_ALERTS_FOLDER) if f.endswith('.json')]
    matched_content = ""
    matched_any = False
    
    log_info(f"Executing flat-file SIEM query across unread alerts for string: '{query_string}'")
    
    for f in files:
        path = os.path.join(UNREAD_ALERTS_FOLDER, f)
        try:
            with open(path, 'r', encoding='utf-8') as file:
                file_text = file.read()
                
            if query_string.lower() in file_text.lower():
                matched_any = True
                matched_content += f"\n[Ingested Alert File: {f}]\n{file_text}\n"
                
                dest_path = os.path.join(destination_folder, f)
                shutil.move(path, dest_path)
                log_success(f"Match isolated! Archived {f} -> {dest_path}")
        except Exception as e:
            log_error(f"Failed parsing file {f} during string scan: {e}")
            
    if not matched_any:
        return f"\n[System Notification]: Query for tracking string '{query_string}' returned 0 new records from unread alerts queue.\n"
    return matched_content

def count_unread_queue() -> int:
    return len([f for f in os.listdir(UNREAD_ALERTS_FOLDER) if f.endswith('.json')])

# ==========================================
# 3. STRUCTURED LOGIC SCHEMA
# ==========================================
class PlaybookDrivenDecision(BaseModel):
    thought_process: str = Field(
        description="Internal step-by-step reasoning tree. Break down your analysis of the logs, correlate the data points, and justify your next action. Use a 'Thinking:' style narrative. Do NOT write the final answer or search queries here."
    )
    answer: str = Field(
        description="The final standalone factual conclusion to the CRITICAL INSTRUCTION. Must be a single sentence. Strictly forbid any 'Because...', 'Based on...', or explanatory text. Just the raw conclusion."
    )
    has_sufficient_data: bool = Field(
        description="True ONLY if the active history contains 100% of the evidence needed to answer. False if you must search to fill a data gap."
    )
    search_query_string: List[str] = Field(
        default=[],
        description="CRITICAL: Extract ONLY the raw target indicators needed for the next search. Max 1 word per item (e.g. ['10.100.20.16', 'RPSOCWSWin2']). Leave list completely empty [] if has_sufficient_data is True. ABSOLUTELY NO SENTENCES."
    )
    final_findings_summary: str = Field(
        description="The ultimate SOC incident report summary for terminal nodes. Outline the threat actor vector and impact. Output 'None' if this is an intermediate playbook step."
    )

# ==========================================
# 4. RUNTIME SYSTEM EXECUTION PROMPT
# ==========================================
SYSTEM_PROMPT = """You are the Lead Playbook Execution Agent performing active investigations, and deeply integrated into the RSA NetWitness SIEM, your only goal is to analyse data and answer the questions directly, querying for additional information when necessary.

### SYSTEM POLICIES
{policies}

### GROUND RULES:
1. 'thought_process' is your inner monologue. 
2. 'answer' is a blunt 1-sentence state change conclusion. Do not reuse any words from your thought process here.
3. 'search_query_string' must NEVER contain spaces, letters of instructions, or verbs. It is an array of raw indicators only.
4. You are not a suggestor, you are an executor. Only answer questions and explicitly state if are unable to do so.
5. You MUST look at the investigation history and determine if there is enough info to answer the question. DO NOT jump to conclusions.
6. You are supposed to QUERY for missing data should the provided information be insufficient. If you think all the relevant details are not included, QUERY!

### PROTOCOL EXTRACTION RULES:
1. Check the Investigation History. Do you have enough information to execute this instruction, or do you need to query for more data?
- IF INSUFFICIENT DATA: 
      - Set `has_sufficient_data` to False
      - Extract the specific Indicators of Compromise to search and place inside `search_query_string` (e.g. IP addresses, domains, file hashes, email subjects). DO NOT write any explanatory text OR any metadata attached by SIEM, just the raw query values. The system will handle the rest.
- IF SUFFICIENT DATA: 
      - Set `has_sufficient_data` to True

### EXAMPLE OUTPUT ANSWER:
Q: Analyze the given telemetry and identify who all the victim endpoints are and group their characteristics (IP, Host, process trees).
A: The identified victim endpoint is IP address 192.168.2.101 and his compromised email address is jacob@gmail.com, his host is RPSOCWin10.

Q: Does the phishing attempt contain a URL or attachment?
A: The phishing attempt contains a URL, which is hxxp://maliciousdomain.com/login.

Q: Has the URL or attachment been clicked or opened by the user?
A: The URL has been clicked by the user, as evidenced by the access logs showing a connection to hxxp://maliciousdomain.com/login from the user's IP address.
"""

prompt_template = ChatPromptTemplate.from_messages([
    ("system", SYSTEM_PROMPT),
    (
        "human",
        "--- ACTIVE INVESTIGATION HISTORY ---\n"
        "{investigation_history}\n"
        "------------------------------------\n\n"
        "{current_node_instruction}\n"
    )
])

# ==========================================
# 5. MAIN PIPELINE EXECUTION
# ==========================================
if __name__ == "__main__":
    MAX_ITERATIONS = 6
    active_incident_dir = get_or_create_incident_folder()
    log_info(f"Dynamic workspace locked onto path target: {active_incident_dir}")
    
    # --- DYNAMIC TARGET INITIALIZATION ---
    # Find all unread alert files and sort them alphabetically
    unread_files = sorted([f for f in os.listdir(UNREAD_ALERTS_FOLDER) if f.endswith('.json')])
    
    if not unread_files:
        log_error(f"No alert files found in '{UNREAD_ALERTS_FOLDER}' to begin investigation. Exiting.")
        sys.exit(1)
        
    # Pick the first file to seed the baseline incident history context
    seed_file = unread_files[0]
    seed_path = os.path.join(UNREAD_ALERTS_FOLDER, seed_file)
    
    log_info(f"Seeding investigation with baseline event file: {seed_file}")
    investigation_history = load_text_file(seed_path)
    
    # Isolate the seed file into the incident directory immediately so it isn't parsed by subsequent query loops
    seed_dest_path = os.path.join(active_incident_dir, seed_file)
    shutil.move(seed_path, seed_dest_path)
    log_success(f"Baseline alert isolated! Archived {seed_file} -> {seed_dest_path}")
    # -------------------------------------

    PLAYBOOK_TEXT, PLAYBOOK_DICT = load_yaml_playbook("playbooks/phishing.yaml")
    POLICIES_FILE = load_text_file("policies/soc_policies.md")
    
    log_info("Powering up Ollama Foundation Security LLM node layer...")
    llm = ChatOllama(
        model="hf.co/Mungert/Foundation-Sec-8B-Instruct-GGUF:Q4_K_M", 
        temperature=0.1
    ).with_structured_output(PlaybookDrivenDecision, method="json_schema")

    chain = prompt_template | llm
    current_yaml_node = "step_1"

    for cycle in range(1, MAX_ITERATIONS + 1):
        log_info(f"Starting Investigation Iteration [{cycle}/{MAX_ITERATIONS}]")
        
        queue_count = count_unread_queue()
        node_data = PLAYBOOK_DICT.get('steps', {}).get(current_yaml_node, {})
        node_instruction = node_data.get('instructions', 'No active instruction set.')
        current_node_routing = node_data.get('routing', 'No routing set.')

        try:
            decision = chain.invoke({
                "current_node_id": current_yaml_node,
                "current_node_instruction": node_instruction,
                "current_node_routing": current_node_routing,
                "policies": POLICIES_FILE,
                "investigation_history": investigation_history
            })
        except Exception as e:
            log_error(f"Schema deserialization failure: {e}")
            continue
        
        log_analyst(node_instruction, decision.thought_process, decision.answer)
        print(decision.search_query_string, decision.has_sufficient_data)
        # Handle Active Query Tool Call
        if not decision.has_sufficient_data and decision.search_query_string != "None":
            query_results = search_unread_alerts(decision.search_query_string, active_incident_dir)
            investigation_history += query_results
            log_warning("Engine requested a hold state waiting for query strings.")
            continue
        
        if "complete" in current_node_routing:
            log_success(f"Routing pointer hit final terminal designation: [{current_node_routing}]")
            
            report_path = os.path.join(active_incident_dir, "final_analysis_report.txt")
            with open(report_path, 'w', encoding='utf-8') as rf:
                rf.write("EXECUTIVE INCIDENT OUTCOME REPORT\n=================================\n")
                rf.write(f"Layman Briefing:\n{decision.layman_analyst_explanation}\n\n")
                rf.write(f"Technical Chronology Summary:\n{decision.final_findings_summary}\n")
                
            log_success(f"Investigation Complete. Case report stored securely inside: {report_path}")
            break
            
        log_success(f"Node [{current_yaml_node}] completed. Routing path links -> {current_node_routing}")
        if decision.has_sufficient_data:
            current_yaml_node = current_node_routing

    log_info("Pipeline shutdown.")