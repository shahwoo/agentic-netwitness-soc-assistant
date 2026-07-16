"""
INTEGRATION GUIDE — Wiring soc_triage_agent.py into app.py
===========================================================
Three edits to app.py, nothing else needs to change.

════════════════════════════════════════════════════════════════
EDIT 1 — Add imports  (top of app.py, with the existing imports)
════════════════════════════════════════════════════════════════

    from soc_triage_agent import (
        CiscoLLMConfig,
        soc_triage_chat_respond,
    )

════════════════════════════════════════════════════════════════
EDIT 2 — Configure the Cisco LLM  (after imports, before st.set_page_config)
════════════════════════════════════════════════════════════════

    CISCO_CFG = CiscoLLMConfig(
        base_url    = os.environ.get("CISCO_LLM_URL",   "https://foundation-llm.cisco.com/v1"),
        api_key     = os.environ.get("CISCO_LLM_KEY",   ""),
        model       = os.environ.get("CISCO_LLM_MODEL", "cisco-foundation-llm"),
        temperature = 0.1,
        max_tokens  = 2048,
        timeout     = 120,
    )

════════════════════════════════════════════════════════════════
EDIT 3 — Replace the chat_respond() stub  (~line 671 in app.py)
════════════════════════════════════════════════════════════════

REMOVE:

    def chat_respond(user_msg: str, incident: Optional[dict] = None) -> str:
        ctx = (f" [Incident {incident.get('id','?')}: {incident.get('title','?')}]"
               if incident else "")
        return (f"**[LangChain stub]**{ctx}\\n\\n"
                f"You said: _{user_msg}_\\n\\n"
                f"→ Replace `chat_respond()` with your LangChain chain.")

ADD:

    def chat_respond(user_msg: str, incident: Optional[dict] = None) -> str:
        return soc_triage_chat_respond(user_msg, incident, llm_config=CISCO_CFG)

════════════════════════════════════════════════════════════════
ENVIRONMENT VARIABLES  (add to .env or export in shell)
════════════════════════════════════════════════════════════════

    CISCO_LLM_URL   = https://foundation-llm.cisco.com/v1   # your Cisco endpoint
    CISCO_LLM_KEY   = <your-api-key>
    CISCO_LLM_MODEL = cisco-foundation-llm                  # model name from Cisco

════════════════════════════════════════════════════════════════
TRIGGERING THE AGENT (from the Chat tab)
════════════════════════════════════════════════════════════════

1. Open SOC Platform → Chat tab
2. Select an incident from the dropdown
3. Send any message containing one of these words:
       triage  |  analyse / analyze  |  ioc  |  classify  |  ticket  |  investigate
4. The full 3-phase pipeline runs automatically:

   ┌──────────────────────────────────────────────────────────────┐
   │  Phase 1 · IOC Checklists                                    │
   │     → Availability (7 IOCs)                                  │
   │     → Confidentiality (8 IOCs)                               │
   │     → Integrity (12 IOCs)                                    │
   │     Each phase = LangChain LCEL chain: prompt | llm | parser │
   ├──────────────────────────────────────────────────────────────┤
   │  Phase 2 · Risk Rating Methodology                           │
   │     → Likelihood of initiation                               │
   │     → Likelihood of occurrence                               │
   │     → Likelihood of adverse impact                           │
   │     → Overall risk level derived                             │
   ├──────────────────────────────────────────────────────────────┤
   │  Phase 3 · SOC Classification Template                       │
   │     → Critical / High / Medium / Low                         │
   │     → Incident category + response time                      │
   │     → Recommended actions                                    │
   └──────────────────────────────────────────────────────────────┘
   Outputs:
       metakeys_payload  → queued for downstream meta-key agent
       ticket            → queued for downstream ticketing agent (UNC assigned)

════════════════════════════════════════════════════════════════
LANGCHAIN ARCHITECTURE SUMMARY
════════════════════════════════════════════════════════════════

LLM wrapper
    build_llm(cfg)  →  ChatOpenAI(base_url=Cisco, ...)

Tools  (@lc_tool decorated functions)
    run_ioc_checklists(incident_json)       → JSON string
    run_risk_rating(incident_and_iocs_json) → JSON string
    run_soc_classification(payload_json)    → JSON string

Each tool internally runs an LCEL chain:
    ChatPromptTemplate | ChatOpenAI | JsonOutputParser

Agent pipeline  (LCEL RunnablePassthrough.assign composition)
    RunnablePassthrough.assign(ioc_results  = _phase1_ioc)
    | RunnablePassthrough.assign(risk_results = _phase2_risk)
    | RunnablePassthrough.assign(cls_results  = _phase3_classify)

QA fallback chain  (plain analyst chat)
    ChatPromptTemplate | ChatOpenAI | StrOutputParser

════════════════════════════════════════════════════════════════
OUTPUT SCHEMAS
════════════════════════════════════════════════════════════════

OUTPUT 1 — metakeys_payload  (for downstream meta-key agent)
─────────────────────────────────────────────────────────────
{
    "incident_id":      "INC-12345",
    "incident_title":   "Suspicious outbound connection",
    "timestamp":        "2025-06-02T10:30:00",
    "matched_metakeys": ["ip.dst", "ip.src", "bytes.out", "geo.country", ...],
    "metakey_values": {
        "ip.src":    "10.0.1.55",
        "ip.dst":    "185.220.101.9",
        "bytes.out": 524288
    },
    "ioc_summary":    "...",
    "risk_level":     "high",
    "classification": "high"
}

OUTPUT 2 — ticket  (for downstream ticketing agent)
─────────────────────────────────────────────────────────────
{
    "unc":             "#00001A",
    "incident_id":     "INC-12345",
    "title":           "Suspicious outbound connection",
    "created_at":      "2025-06-02T10:30:00",
    "classification":  "HIGH",
    "risk_rating": {
        "likelihood_initiation":     "High",
        "likelihood_occurrence":     "Medium",
        "likelihood_adverse_impact": "High",
        "overall_risk":              "High",
        "rationale":                 "..."
    },
    "incident_category":     "External Hacking (inactive)",
    "initial_response_time": "30 to 60 minutes",
    "summary":               "...",
    "recommended_actions":   ["Isolate host", "Block IP at perimeter firewall", ...],
    "matched_ioc_count":     4,
    "metakeys":              ["ip.dst", "ip.src", "bytes.out", ...]
}

════════════════════════════════════════════════════════════════
TICKET UNC FORMAT
════════════════════════════════════════════════════════════════

#00000A → #00001A → ... → #99999A
#00000B → ...            → #99999B
...
#00000Z → ...            → #99999Z
#00000AA → ...           → #99999AA
...

Counter persists across restarts in soc_tickets.db  (same directory as app.py).
"""