import sys
import yaml
import os
import shutil
import chromadb
from dotenv import load_dotenv
from langchain_openai import ChatOpenAI
from langchain_core.tools import tool
from pydantic import BaseModel, Field
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_core.messages import ToolMessage, HumanMessage
from typing import List, Literal, Optional


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
PLAYBOOKS_FOLDER = "playbooks/"
load_dotenv()

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
        next_id = f"Incident-{max(ids)+1:03d}" if ids else "Incident-001"
    
    path = os.path.join(INCIDENT_REPORTS_FOLDER, next_id)
    os.makedirs(path, exist_ok=True)
    return path

# ==========================================
# 2. IN-MEMORY FILE SEARCH ENGINE
# ==========================================
def search_unread_alerts(query_list: list) -> str:
    if not query_list:
        return ""
        
    keywords = []
    # Extract data values from every query string in the list
    for query in query_list:
        values = [item.split("=", 1)[1] for item in query_list if "=" in item]
        if values:
            keywords.extend(values)
        elif query.strip(): 
            # Fallback: if an item in the list has no quotes, use the whole string
            keywords.append(query.strip())
            
    # Remove any potential duplicate keywords to optimize the search
    keywords = list(dict.fromkeys(keywords))
    
    if not keywords:
        return ""
    
    files = [f for f in os.listdir(UNREAD_ALERTS_FOLDER) if f.endswith('.json')]
    matched_content = ""
    matched_any = False
    
    log_info(f"Executing flat-file SIEM keyword query for values: {keywords}")

    for f in files:
        path = os.path.join(UNREAD_ALERTS_FOLDER, f)
        try:
            with open(path, 'r', encoding='utf-8') as file:
                file_text = file.read()
                
            # Perform case-insensitive search ensuring ALL extracted keywords match
            if any(kw.lower() in file_text.lower() for kw in keywords):
                matched_any = True
                investigation_history.append(
                    HumanMessage(
                        content=file_text
                    )
                )
                
                dest_path = os.path.join(active_incident_dir, f)
                shutil.move(path, dest_path)
                log_success(f"Match isolated! Archived {f} -> {dest_path}")
        except Exception as e:
            log_error(f"Failed parsing file {f} during string scan: {e}")

    for i in keywords:
        exhausted_pivots.append(i)

    if not matched_any:
        log_warning(f"Query for tracking values {keywords} returned 0 new records from unread alerts queue.")
        return
    return

def count_unread_queue() -> int:
    return len([f for f in os.listdir(UNREAD_ALERTS_FOLDER) if f.endswith('.json')])

# ==========================================
# 3. STRUCTURED LOGIC SCHEMA
# ==========================================
class PlaybookDrivenDecision(BaseModel):

    investigation_state: Literal[
        "CONFIRMED",
        "NEEDS_MORE_DATA"
    ] = Field(
        description="""
        CONFIRMED:
        - The current playbook question can be answered from available telemetry.
        - This includes simple field extraction tasks.
        - This includes investigation questions where sufficient evidence exists.
        - DO NOT enter CONFIRMED if there is no evidence supporting either YES/NO.
        - DO NOT enter CONFIRMED just because evidence DOESN'T EXIST. Must have evidence to APPROVE/DISPROVE.

        NEEDS_MORE_DATA:
        - The current playbook question cannot be answered with available telemetry.
        - Additional telemetry must be collected.

        HARD RULE:
        If answer is empty -> MUST be NEEDS_MORE_DATA.
        If answer is populated -> MUST be CONFIRMED.
        """
    )

    reasoning: str = Field(
        description="""
        Investigation audit trail.

        Structure:

        Observed:
        - Relevant telemetry reviewed

        Assessment:
        - Whether telemetry is sufficient

        Decision:
        - Why the chosen state was selected

        RULES:

        - Only use observed facts.
        - Never answer the question here.
        - Never use:
          likely
          probably
          appears
          seems
          suspected
        """
    )

    answer: Optional[str] = Field(
        description="""
        Direct answer to the current playbook question.

        RULES:

        CONFIRMED:
        - MUST be populated
        - MUST directly answer the playbook question

        NEEDS_MORE_DATA:
        - MUST be null

        Examples:

        Question:
        Identify source IP.

        Answer:
        10.100.20.16

        Question:
        Does the phishing email contain an attachment?

        Answer:
        The phishing email contains a malicious attachment.

        Keep concise.
        """
    )

    search_query_string: List[str] = Field(
        default_factory=[],
        description="""
        IOC values to pivot on for additional investigation.

        MUST contain ONLY pivot values given by user, as a list of ONLY values.

        VALID EXAMPLE: (DO NOT USE AS ACTUAL OUTPUT)
        - 10.100.20.16
        - WIN-CLIENT01
        - alice@company.com
        - invoice.docm
        - powershell.exe
        - evil-domain.com

        INVALID EXAMPLE: (DO NOT USE AS ACTUAL OUTPUT)
        - questions
        - sentences
        - instructions
        - telemetry
        - logs
        - hosts
        - processes
        - ip_addresses
        - ip.src=192.168.1.1

        RULES:

        If investigation_state = CONFIRMED:
        search_query_string MUST be []

        If investigation_state = NEEDS_MORE_DATA:
        search_query_string may contain observed IOC values.

        If value is EXHAUSTED PIVOT, USE A DIFFERENT VALUE ON NEXT QUERY

        e.g. (DO NOT USE AS OUTPUT)
        -> Returned 0 results for '10.100.20.16'
        -> search_query_string on NEXT iteration = 'process=powershell.exe'

        VALID:
        ['10.100.20.16', 'WIN-CLIENT01']

        INVALID:
        ['ip.src == 10.100.20.16']
        ['email.dst=abc@company.com AND process=notepad.exe']
        """
    )

    final_findings_summary: str = Field(
        default="None",
        description="""
        Final SOC incident summary.

        STATE what happend in CHRONOLOGICAL ORDER, based on evidence ONLY GIVEN by user.
        """
    )

# ==========================================
# 4. RUNTIME SYSTEM EXECUTION PROMPT
# ==========================================
SYSTEM_PROMPT = """You are a SOC Investigation Agent operating inside RSA NetWitness SIEM.

Your responsibility is to execute playbook steps using available telemetry.

UNDERSTAND that all available telemtry is not given immediately, your role is to BUILD the full attack chain by QUERYING for information.

You do not guess.
You do not speculate.
You do not assume.
You only answer questions supported by telemetry.

==================================================
CORE PRINCIPLE
==================================================

ABSENCE OF EVIDENCE DOES NOT MEAN IT DIDNT HAPPEN.

Missing telemetry does not prove an event did or did not occur.

Successful attacks are considered when compromise is evident.

==================================================
PRIMARY OBJECTIVE
==================================================

For every playbook question determine:

Can the question be answered using currently available telemetry?

If YES:
    investigation_state = CONFIRMED

If NO:
    investigation_state = NEEDS_MORE_DATA

==================================================
STATE DEFINITIONS
==================================================

CONFIRMED

The playbook question can be answered directly from available telemetry.

Examples:

Question:
Identify source IP.

Telemetry:
ip.src=10.100.20.16

Result:
CONFIRMED

Answer:
10.100.20.16

--------------------------------------------------

Question:
Does the email contain an attachment?

Telemetry:
attachment_name=invoice.docm

Result:
CONFIRMED

Answer:
The email contains an attachment named invoice.docm.

==================================================

NEEDS_MORE_DATA

The playbook question cannot yet be answered.

Additional telemetry is required.

Example:

Question:
Did the user execute the attachment?

Telemetry:
attachment_name=invoice.docm

Result:
NEEDS_MORE_DATA

Reason:
No execution telemetry exists.

==================================================
EVIDENCE SUFFICIENCY RULE
==================================================

Questions may only be CONFIRMED when telemetry directly proves the event being asked about.

Related evidence is NOT proof.

Examples:

File Downloaded DOES NOT MEAN File Opened

File Opened DOES NOT MEAN File Executed

Email Delivered DOES NOT MEAN Email Opened

Email Opened DOES NOT MEAN Attachment Executed

URL Exists DOES NOT MEAN URL Clicked

==================================================
WORKFLOW
==================================================

1. Read the playbook question.

2. Review all telemetry in investigation history.

3. Determine whether enough evidence exists to answer question directly.

4. If sufficient evidence exists:

    investigation_state = CONFIRMED
    answer = direct answer
    search_query_string = []

5. If sufficient evidence does not exist:

    investigation_state = NEEDS_MORE_DATA
    answer = null

    Generate search_query_string using IOC values found in investigation history.

==================================================
SEARCH QUERY RULES
==================================================

search_query_string must contain ONLY IOC values in investigation history, and EXCLUDE values in exhausted pivots.

Valid examples:

["10.100.20.16"]
["RPSOCWSWin2"]
["invoice.docm"]
["powershell.exe"]
["user@company.com"]

Invalid examples:

["Did the attachment execute?"]
["Search for powershell activity"]
["ip.src == 10.100.20.16"]
["telemetry"]
["processes"]

Never generate:
- questions
- sentences
- search expressions
- telemetry categories

==================================================
EXHAUSTED PIVOT RULE
==================================================

Before generating search_query_string:

1. Review investigation history.

2. Identify all IOC values that are EXHAUSTED PIVOTS, as specified by the user.

5. Never reuse exhausted IOC values.

6. Select an unexplored IOC value instead.

INVALID EXAMPLE: (DO NOT USE AS OUTPUT)
--- EXHAUSTED PIVOTS ---
['powershell.exe', 'invoice.docm']

search_query_string = ['powershell.exe']

VALID EXAMPLE: (DO NOT USE AS OUTPUT)
--- EXHAUSTED PIVOTS ---
['powershell.exe', 'invoice.docm'] 

search_query_string = ['bob@company.com']

==================================================
NO RESULT RULE
==================================================

A search returning 0 results is NOT evidence.

A failed pivot is NOT evidence.

0 results must NEVER automatically change:

NEEDS_MORE_DATA -> CONFIRMED

Only newly observed telemetry may justify CONFIRMED.

==================================================
ALL PIVOTS EXHAUSTED
==================================================

If all observable IOC values have already been queried and EXHAUSTED:

investigation_state = NEEDS_MORE_DATA

search_query_string = []

Do not repeat pivots.
Do not create alternative pivots.
Do not generate wildcard searches.

Wait for new telemetry.

==================================================
CRITICAL RULE
==================================================

If the answer already exists in telemetry:

- Answer immediately.
- Do not generate pivots.
- Do not request additional data.
- Set investigation_state = CONFIRMED.
"""

prompt_template = ChatPromptTemplate.from_messages([
    ("system", SYSTEM_PROMPT),
    MessagesPlaceholder(variable_name="investigation_history"),
    (
        "human",
        "------------------------------------\n\n"
        "{current_node_instruction}\n"
        "--- EXHAUSTED PIVOTS(DO NOT USE TO QUERY) ---\n"
        "{exhausted_pivots}\n"
    )
])

# ==========================================
# 5. MAIN PIPELINE EXECUTION
# ==========================================
if __name__ == "__main__":
    MAX_ITERATIONS = 12
    PLAYBOOK_TEXT, PLAYBOOK_DICT = load_yaml_playbook("playbooks/phishing.yaml")
    POLICIES_FILE = load_text_file("policies/soc_policies.md")
    InvestigationComplete = True
    exhausted_pivots = []
    investigation_history = []

    log_info("Initializing LLM...")
    llm = ChatOpenAI(
       model="gpt-5.5",
       temperature=0,
       max_tokens=10000
    ).with_structured_output(PlaybookDrivenDecision, method="json_schema")

    chain = prompt_template | llm
    current_yaml_node = "step_1"

    active_incident_dir = get_or_create_incident_folder()
    log_info(f"Creating new incident folder: {active_incident_dir}")
    
    # --- DYNAMIC TARGET INITIALIZATION ---
    # Find all unread alert files and sort them alphabetically
    unread_files = sorted([f for f in os.listdir(UNREAD_ALERTS_FOLDER) if f.endswith('.json')])
    
    if not unread_files:
        log_error(f"No alert files found in '{UNREAD_ALERTS_FOLDER}' to begin investigation. Exiting.")
        sys.exit(1)
        
    # Pick the first file to seed the baseline incident history context
    seed_file = unread_files[0]
    seed_path = os.path.join(UNREAD_ALERTS_FOLDER, seed_file)
    
    log_info(f"Starting NEW investigation with baseline event file: {seed_file}")
    investigation_history.append(
    HumanMessage(
        content=load_text_file(seed_path)
    ))
    
    # Isolate the seed file into the incident directory immediately so it isn't parsed by subsequent query loops
    seed_dest_path = os.path.join(active_incident_dir, seed_file)
    shutil.move(seed_path, seed_dest_path)
    log_success(f"Baseline alert isolated! Archived {seed_file} -> {seed_dest_path}")

    for cycle in range(1, MAX_ITERATIONS + 1):
        log_info(f"Starting Investigation Iteration [{cycle}/{MAX_ITERATIONS}]")
        
        queue_count = count_unread_queue()
        node_data = PLAYBOOK_DICT.get('steps', {}).get(current_yaml_node, {})
        node_instruction = node_data.get('instructions', 'No active instruction set.')
        current_node_routing = node_data.get('routing', 'No routing set.')

        try:
            decision = chain.invoke({
                "current_node_instruction": node_instruction,
                "investigation_history": investigation_history,
                "exhausted_pivots": exhausted_pivots
            })
        except Exception as e:
            log_error(f"Schema deserialization failure: {e}")
            continue

        log_analyst(node_instruction, decision.reasoning, decision.answer)
        print(decision.search_query_string, exhausted_pivots, decision.investigation_state)
        # Handle Active Query Tool 
        if decision.investigation_state == "NEEDS_MORE_DATA" and decision.search_query_string != []:
            search_unread_alerts(decision.search_query_string)
            continue
        
        if "complete" in current_node_routing or cycle == MAX_ITERATIONS:
            log_success(f"Routing pointer hit final terminal designation: [{current_node_routing}]")
            
            report_path = os.path.join(active_incident_dir, "final_analysis_report.txt")
            with open(report_path, 'w', encoding='utf-8') as rf:
                rf.write("EXECUTIVE INCIDENT OUTCOME REPORT\n=================================\n")
                rf.write(f"Technical Chronology Summary:\n{decision.final_findings_summary}\n")
                InvestigationComplete = True
                
            log_success(f"Investigation Complete. Case report stored securely inside: {report_path}")
            break
            
        log_success(f"Node [{current_yaml_node}] completed. Routing path links -> {current_node_routing}")
        if decision.investigation_state != "NEEDS_MORE_DATA":
            current_yaml_node = current_node_routing
            

    log_info("Pipeline shutdown.")