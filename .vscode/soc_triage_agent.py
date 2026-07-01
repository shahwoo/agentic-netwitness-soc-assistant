"""
SOC Triage Agent  —  soc_triage_agent.py
=========================================
Built entirely with LangChain (LCEL chains + tools).

Pipeline per incident
─────────────────────
  Phase 1  IOC Checklist  ·  3 parallel chains (Availability / Confidentiality / Integrity)
  Phase 2  Risk Rating    ·  1 chain using SOC Risk Rating Methodology
  Phase 3  Classification ·  1 chain using SOC Classification Template

Two outputs
───────────
  metakeys_payload  →  downstream meta-key agent
  ticket            →  downstream ticketing agent (UNC #XXXXXL format)

LLM backend: Cisco Foundation LLM  (OpenAI-compatible, configured via env vars)
LangChain version: 1.x  (LCEL / langchain-core 1.x pattern)
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
import threading
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

# ── LangChain imports ──────────────────────────────────────────────────────────
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser
from langchain_core.runnables import (
    RunnableParallel,
    RunnableLambda,
    RunnablePassthrough,
)
from langchain_core.messages import SystemMessage, HumanMessage
from langchain_core.tools import tool as lc_tool
from langchain_openai import ChatOpenAI


# ══════════════════════════════════════════════════════════════════════════════
# 0.  CISCO FOUNDATION LLM  —  LangChain ChatOpenAI wrapper
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class CiscoLLMConfig:
    """
    Cisco Foundation LLM settings.
    All fields fall back to environment variables so you can configure via .env.
    """
    base_url: str = field(
        default_factory=lambda: os.environ.get(
            "CISCO_LLM_URL", "https://api-inference.huggingface.co/v1"
        )
    )
    api_key: str = field(
        default_factory=lambda: os.environ.get("CISCO_LLM_KEY", "changeme")
    )
    model: str = field(
        default_factory=lambda: os.environ.get(
            "CISCO_LLM_MODEL", "fdtn-ai/Foundation-Sec-8B-Reasoning"
        )
    )
    temperature: float  = 0.1
    max_tokens:  int    = 1024
    timeout:     int    = 300   # 5 min — covers cold-start on dedicated endpoints


def build_llm(cfg: CiscoLLMConfig) -> ChatOpenAI:
    """
    Instantiate a LangChain ChatOpenAI pointed at the Cisco Foundation LLM.
    Cisco exposes an OpenAI-compatible /v1 endpoint, so ChatOpenAI works
    without any custom subclassing.
    """
    return ChatOpenAI(
        base_url=cfg.base_url,
        api_key=cfg.api_key,
        model=cfg.model,
        temperature=cfg.temperature,
        max_tokens=cfg.max_tokens,
        timeout     = cfg.timeout,
        max_retries = 2,          # auto-retry on transient failures
    )


# ══════════════════════════════════════════════════════════════════════════════
# 1.  IOC CHECKLISTS  (sourced from uploaded .docx files)
# ══════════════════════════════════════════════════════════════════════════════

IOC_AVAILABILITY: list[dict] = [
    {
        "ioc": "Frequent core dump and/or traceback generation",
        "description": "Frequent software crashes during normal device operation",
        "example": "Refer to description",
        "metakeys": ["event.type", "device.type", "host.name"],
    },
    {
        "ioc": "High CPU usage",
        "description": "Abnormally high CPU usage caused by a malicious actor",
        "example": "Refer to description",
        "metakeys": ["cpu.usage", "process.name", "host.name"],
    },
    {
        "ioc": "Frequent rebooting",
        "description": "Altered device software causing frequent reload",
        "example": "Device reloading frequently",
        "metakeys": ["event.type", "device.type", "host.name"],
    },
    {
        "ioc": "Saturated interface input/output buffers",
        "description": "High traffic volumes initiated by a malicious actor",
        "example": "Refer to description",
        "metakeys": ["network.interface", "bytes.in", "bytes.out", "packets.in", "packets.out"],
    },
    {
        "ioc": "Abnormally high malformed packet counts",
        "description": "High numbers of malformed packets destined to a device",
        "example": "Refer to description",
        "metakeys": ["packets.malformed", "ip.dst", "ip.src"],
    },
    {
        "ioc": "Configuration changes",
        "description": "Changes in routes, routing protocols, NAT, ACLs, SNMP, logging, syslog, VPNs, GRE tunneling",
        "example": "Refer to description",
        "metakeys": ["change.type", "config.change", "user.name", "host.name"],
    },
    {
        "ioc": "Unexplained/unexpected changes initiated from privileged accounts",
        "description": "Unusual activity from privileged accounts",
        "example": "Systems accessed, Time of activity, Data accessed/modified, Amount of data",
        "metakeys": ["user.name", "user.role", "event.time", "file.path", "bytes.transferred"],
    },
]

IOC_CONFIDENTIALITY: list[dict] = [
    {
        "ioc": "Changes in network traffic telemetry (known bad IPs/domains)",
        "description": "Changes in egress/ingress traffic patterns; traffic to/from known malicious domains",
        "example": "Exfiltration of data",
        "metakeys": ["ip.dst", "ip.src", "domain", "bytes.out", "alert.type"],
    },
    {
        "ioc": "Unknown traffic originating from/terminating on the device",
        "description": "Unusual traffic directed to/originating from host devices",
        "example": "Telnet, SSH, HTTP/HTTPS, RDP",
        "metakeys": ["ip.src", "ip.dst", "network.service", "port.dst", "protocol"],
    },
    {
        "ioc": "Anomalous file transfers initiated from/received by the device",
        "description": "Unusual file transfers sent to/received from unexpected hosts",
        "example": "Exfiltration via FTP/TFTP/SNMP",
        "metakeys": ["file.name", "file.size", "ip.dst", "ip.src", "protocol", "bytes.out"],
    },
    {
        "ioc": "Geographic-based anomalies",
        "description": "Traffic to/from countries the organisation does not normally engage",
        "example": "Login activity from unexpected geographic regions",
        "metakeys": ["geo.country", "ip.src", "ip.dst", "user.name", "event.type"],
    },
    {
        "ioc": "File system permissions changed",
        "description": "Changes in file system authorisations",
        "example": "Changing a folder's permissions from Administrator to Everyone",
        "metakeys": ["file.path", "permission.change", "user.name", "host.name"],
    },
    {
        "ioc": "Configuration changes",
        "description": "Changes in routes, routing protocols, NAT, ACLs, SNMP, logging, syslog, VPNs, GRE tunneling",
        "example": "Refer to description",
        "metakeys": ["change.type", "config.change", "user.name", "host.name"],
    },
    {
        "ioc": "Device account/password additions/deletions/changes",
        "description": "Changes to device account or credential information",
        "example": "Reset password, Request password change, Deleting password",
        "metakeys": ["user.name", "event.type", "account.action", "host.name"],
    },
    {
        "ioc": "Unexplained/unexpected changes initiated from privileged accounts",
        "description": "Unusual activity from privileged accounts",
        "example": "Systems accessed, Time of activity, Data accessed/modified, Amount of data",
        "metakeys": ["user.name", "user.role", "event.time", "file.path", "bytes.transferred"],
    },
]

IOC_INTEGRITY: list[dict] = [
    {
        "ioc": "Generation of core dumps and/or tracebacks",
        "description": "Frequent software crashes during normal device operation",
        "example": "Refer to description",
        "metakeys": ["event.type", "device.type", "host.name"],
    },
    {
        "ioc": "Odd device/platform behaviour",
        "description": "Behaviour deviating from expected normal operation not explained by defects/misconfiguration",
        "example": "Refer to description",
        "metakeys": ["event.type", "host.name", "device.type"],
    },
    {
        "ioc": "Anomalies in OS/package hash values",
        "description": "Inconsistent hash values that deviate from expected",
        "example": "Refer to description",
        "metakeys": ["file.hash", "file.name", "host.name", "os.version"],
    },
    {
        "ioc": "Anomalies in OS/package certificate signing",
        "description": "Bypassing code signing checks; installing certificates from unknown CA",
        "example": "Installing additional certificates signed by unknown CA",
        "metakeys": ["cert.issuer", "cert.hash", "file.name", "host.name"],
    },
    {
        "ioc": "Unknown binaries installed",
        "description": "Binary files and associated configs not part of the OS",
        "example": "Refer to description",
        "metakeys": ["file.name", "file.path", "file.hash", "host.name", "process.name"],
    },
    {
        "ioc": "Unknown process running",
        "description": "Processes in memory with unusual attributes or arbitrary names",
        "example": "Refer to description",
        "metakeys": ["process.name", "process.pid", "process.path", "host.name"],
    },
    {
        "ioc": "Unexpected OS/ROMMON release versions installed",
        "description": "Presence of unexpected system software or bootstrap versions",
        "example": "Refer to description",
        "metakeys": ["os.version", "firmware.version", "host.name"],
    },
    {
        "ioc": "File system permissions changed",
        "description": "Changes in file system authorisations",
        "example": "Changing a folder's permissions from Administrator to Everyone",
        "metakeys": ["file.path", "permission.change", "user.name", "host.name"],
    },
    {
        "ioc": "Unexpected changes in boot sequence or boot variables",
        "description": "Alteration of system startup files",
        "example": "Refer to description",
        "metakeys": ["boot.config", "file.path", "host.name"],
    },
    {
        "ioc": "Configuration changes",
        "description": "Changes in routes, routing protocols, NAT, ACLs, SNMP, logging, syslog, VPNs, GRE tunneling",
        "example": "Refer to description",
        "metakeys": ["change.type", "config.change", "user.name", "host.name"],
    },
    {
        "ioc": "Device account/password additions/deletions/changes",
        "description": "Changes to device account or credential information",
        "example": "Reset password, Request password change, Deleting password",
        "metakeys": ["user.name", "event.type", "account.action", "host.name"],
    },
    {
        "ioc": "Unexplained/unexpected changes initiated from privileged accounts",
        "description": "Unusual activity from privileged accounts",
        "example": "Systems accessed, Time of activity, Data accessed/modified, Amount of data",
        "metakeys": ["user.name", "user.role", "event.time", "file.path", "bytes.transferred"],
    },
]

ALL_IOCS: dict[str, list[dict]] = {
    "availability":    IOC_AVAILABILITY,
    "confidentiality": IOC_CONFIDENTIALITY,
    "integrity":       IOC_INTEGRITY,
}


# ══════════════════════════════════════════════════════════════════════════════
# 2.  RISK RATING & CLASSIFICATION DATA
# ══════════════════════════════════════════════════════════════════════════════

RISK_RATING_GUIDANCE = """
LIKELIHOOD OF THREAT EVENT INITIATION (adversarial threats):
  Critical  — Adversary is almost certain to initiate the threat event
  High      — Adversary is highly likely to initiate the threat event
  Medium    — Adversary is somewhat likely to initiate the threat event
  Low       — Adversary is unlikely to initiate the threat event

LIKELIHOOD OF THREAT EVENT OCCURRENCE (errors / accidents / acts of nature):
  Critical  — Almost certain to occur, or occurs more than 100 times a year
  High      — Highly likely to occur, or occurs between 10–100 times a year
  Medium    — Somewhat likely to occur, or occurs between 1–10 times a year
  Low       — Unlikely to occur, or occurs less than once a year (but > once per 10 years)

LIKELIHOOD OF ADVERSE IMPACT:
  Critical  — Almost certain to have adverse impacts if the threat event occurs/is initiated
  High      — Highly likely to have adverse impacts
  Medium    — Somewhat likely to have adverse impacts
  Low       — Unlikely to have adverse impacts
"""

SOC_CLASSIFICATION_TABLE = {
    "critical": {
        "definition": "Urgent & high-risk security issue requiring immediate investigation & action",
        "categories": [
            "Internal Hacking (active)", "External Hacking (active)",
            "Virus/Worm (outbreak)", "Destruction of property (critical)",
        ],
        "initial_response_time": "<= 15 minutes",
        "ongoing_response": "SOC Triage Agent assigned to perform triaging activities immediately.",
    },
    "high": {
        "definition": "Significant security threats that require investigation",
        "categories": [
            "Internal Hacking (inactive)", "External Hacking (inactive)",
            "Unauthorized access", "Policy violations", "Unlawful activity",
            "Compromised information", "Compromised asset (non-critical)",
            "Destruction of property (non-critical)",
        ],
        "initial_response_time": "30 to 60 minutes",
        "ongoing_response": "SOC Triage Agent assigned to perform triaging activities immediately.",
    },
    "medium": {
        "definition": "Suspicious activity that warrants investigation but no immediate emergency response",
        "categories": [
            "Email Forensics Request", "Inappropriate use of property", "Policy violations",
        ],
        "initial_response_time": "~4 hours",
        "ongoing_response": "SOC Triage Agent assigned to perform triaging activities upon analyst request.",
    },
    "low": {
        "definition": "Events with minimal immediate risk of security breach",
        "categories": [
            "Email", "Unknown websites", "Unknown Source IP address",
            "AV Alert with minimal consequences",
        ],
        "initial_response_time": ">= 24 hours",
        "ongoing_response": "SOC Triage Agent assigned to perform triaging activities upon analyst request.",
    },
}


# ══════════════════════════════════════════════════════════════════════════════
# 3.  TICKET UNC COUNTER  (SQLite-persisted, thread-safe)
# ══════════════════════════════════════════════════════════════════════════════

_TICKET_DB  = Path(__file__).parent / "soc_tickets.db"
_TICKET_LOCK = threading.Lock()


def _ticket_db_init() -> None:
    with sqlite3.connect(str(_TICKET_DB)) as con:
        con.execute("""
            CREATE TABLE IF NOT EXISTS ticket_counter (
                id      INTEGER PRIMARY KEY CHECK (id = 1),
                number  INTEGER NOT NULL DEFAULT 0,
                letter  TEXT    NOT NULL DEFAULT 'A'
            )
        """)
        con.execute("""
            INSERT OR IGNORE INTO ticket_counter (id, number, letter) VALUES (1, 0, 'A')
        """)
        con.execute("""
            CREATE TABLE IF NOT EXISTS tickets (
                unc         TEXT PRIMARY KEY,
                incident_id TEXT,
                severity    TEXT,
                created_at  TEXT,
                payload     TEXT
            )
        """)
        con.commit()


def _increment_suffix(s: str) -> str:
    """
    Base-26 alphabetic suffix increment.
    A→B, Z→AA, AZ→BA, ZZ→AAA
    """
    chars = list(s)
    i = len(chars) - 1
    while i >= 0:
        if chars[i] < "Z":
            chars[i] = chr(ord(chars[i]) + 1)
            return "".join(chars)
        chars[i] = "A"
        i -= 1
    return "A" + "".join(chars)


def _next_unc() -> str:
    """
    Thread-safe UNC generator.
    Format : #XXXXXL   (X = 00000-99999, L = A-Z then AA-AZ …)
    Sequence: #00000A … #99999A → #00000B … #99999Z → #00000AA …
    """
    with _TICKET_LOCK:
        with sqlite3.connect(str(_TICKET_DB)) as con:
            row = con.execute(
                "SELECT number, letter FROM ticket_counter WHERE id = 1"
            ).fetchone()
            number, letter = row[0], row[1]
            unc = f"#{number:05d}{letter}"

            next_number = number + 1
            next_letter = letter
            if next_number > 99999:
                next_number = 0
                next_letter = _increment_suffix(letter)

            con.execute(
                "UPDATE ticket_counter SET number=?, letter=? WHERE id=1",
                (next_number, next_letter),
            )
            con.commit()
    return unc


def _store_ticket(unc: str, incident_id: str, severity: str, payload: dict) -> None:
    with sqlite3.connect(str(_TICKET_DB)) as con:
        con.execute(
            "INSERT OR REPLACE INTO tickets VALUES (?,?,?,?,?)",
            (unc, incident_id, severity,
             datetime.utcnow().isoformat(), json.dumps(payload)),
        )
        con.commit()


_ticket_db_init()


# ══════════════════════════════════════════════════════════════════════════════
# 4a. ROBUST JSON EXTRACTOR  (handles reasoning model output)
#     Foundation-Sec-8B-Reasoning thinks out loud before answering.
#     This parser finds the JSON block wherever it appears in the output.
# ══════════════════════════════════════════════════════════════════════════════

from langchain_core.output_parsers import StrOutputParser

def _extract_json(text: str) -> dict:
    """
    Extract a JSON object from raw model output.
    Handles reasoning models that emit prose before/after the JSON block.
    Strategy (in order):
      1. Strip ```json ... ``` fences
      2. Direct parse
      3. Find the LAST {...} block  (reasoning models put JSON at the end)
      4. Walk backwards from the final } to find its matching {
      5. Try each {...} block right-to-left as last resort
    """
    if not text:
        return {}

    cleaned = re.sub(r"```(?:json)?", "", text).replace("```", "").strip()

    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass

    last_close = cleaned.rfind("}")
    if last_close == -1:
        return {}

    depth = 0
    for i in range(last_close, -1, -1):
        if cleaned[i] == "}":
            depth += 1
        elif cleaned[i] == "{":
            depth -= 1
            if depth == 0:
                candidate = cleaned[i: last_close + 1]
                try:
                    return json.loads(candidate)
                except json.JSONDecodeError:
                    break

    for match in reversed(list(re.finditer(r"\{[^{}]+\}", cleaned, re.DOTALL))):
        try:
            return json.loads(match.group())
        except json.JSONDecodeError:
            continue

    return {}


def _repair_json(raw_text: str, required_keys: list[str], llm) -> dict:
    """
    If _extract_json fails or misses required keys, make a focused repair
    call asking the model to output ONLY the JSON.
    """
    keys_str = ", ".join(f'"{k}"' for k in required_keys)
    repair_prompt = ChatPromptTemplate.from_messages([
        SystemMessage(content=(
            "You are a JSON formatter. Extract or reconstruct a JSON object from "
            "the text below. Return ONLY valid JSON — absolutely no prose, no markdown, "
            f"no explanation. Required keys: {keys_str}"
        )),
        HumanMessage(content=(
            f"TEXT TO EXTRACT FROM:\n{raw_text[-3000:]}\n\n"
            "Return ONLY the JSON object:"
        )),
    ])
    try:
        repair_chain = repair_prompt | llm | StrOutputParser()
        repair_raw   = repair_chain.invoke({})
        result       = _extract_json(repair_raw)
        if result:
            return result
    except Exception:
        pass
    return {}


def _make_json_chain(prompt: ChatPromptTemplate, llm: "ChatOpenAI"):
    """
    LCEL chain that tolerates reasoning-model output.
    Returns (full_chain, text_chain).
    text_chain yields raw text; full_chain extracts JSON from it.
    """
    text_chain = prompt | llm | StrOutputParser()
    full_chain = text_chain | RunnableLambda(_extract_json)
    return full_chain, text_chain


def _stream_or_invoke(text_chain, thinking_container=None) -> str:
    """
    Stream tokens live into a Streamlit container if one is provided,
    otherwise fall back to a plain blocking invoke.
    Falls back to invoke() silently if streaming is unsupported.
    """
    if thinking_container is None:
        return text_chain.invoke({})

    full_text = ""
    _STYLE = (
        "background:#02040A;border-left:3px solid #1A3550;"
        "padding:8px 14px;font-family:monospace;font-size:0.62rem;"
        "color:#5A7A99;border-radius:0 4px 4px 0;margin:3px 0;"
        "word-break:break-word;line-height:1.7;white-space:pre-wrap"
    )
    try:
        for chunk in text_chain.stream({}):
            if isinstance(chunk, str):
                full_text += chunk
            display = full_text
            if len(display) > 600:
                display = "…" + display[-600:]
            thinking_container.markdown(
                f'<div style="{_STYLE}">💭 {display}▌</div>',
                unsafe_allow_html=True,
            )
    except Exception:
        full_text = text_chain.invoke({})

    return full_text


# ── Incident time extraction ───────────────────────────────────────────────────
_INCIDENT_TIME_FIELDS = [
    "created", "createdAt", "created_at", "timestamp", "alertTime", "alert_time",
    "eventTime", "event_time", "occurredTime", "occurred", "detectedTime",
    "detected_at", "firstEventTime", "lastEventTime", "reportedTime", "time",
]

def _extract_incident_time(incident: dict) -> str:
    """
    Best-effort extraction of the incident/alert time from an incident dict.
    Returns a formatted string or '—' if not found.
    """
    flat = _flatten(incident)
    for field in _INCIDENT_TIME_FIELDS:
        val = flat.get(field) or incident.get(field)
        if val:
            raw = str(val).strip()
            # Try to parse and reformat ISO timestamps
            for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ",
                        "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S",
                        "%Y/%m/%d %H:%M:%S"):
                try:
                    from datetime import timezone
                    dt = datetime.strptime(raw[:26], fmt[:len(raw)])
                    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
                except ValueError:
                    continue
            # Return raw if parse fails but field exists
            if len(raw) >= 8:
                return raw
    return "—"

_METAKEY_FIELD_MAP: dict[str, list[str]] = {
    "ip.src":              ["sourceIp", "source_ip", "srcIp", "src_ip"],
    "ip.dst":              ["destinationIp", "dest_ip", "dstIp", "dst_ip"],
    "host.name":           ["hostname", "host", "deviceName", "device_name"],
    "user.name":           ["username", "user", "assignee"],
    "domain":              ["domain", "fqdn"],
    "event.type":          ["type", "eventType", "event_type"],
    "alert.type":          ["alertType", "alert_type", "ruleType"],
    "bytes.out":           ["bytesOut", "bytes_out", "egress_bytes"],
    "bytes.in":            ["bytesIn", "bytes_in", "ingress_bytes"],
    "protocol":            ["protocol", "networkProtocol"],
    "geo.country":         ["country", "geoCountry", "geo_country"],
    "file.name":           ["fileName", "file_name"],
    "file.hash":           ["fileHash", "file_hash", "md5", "sha256"],
    "process.name":        ["processName", "process_name"],
    "os.version":          ["osVersion", "os_version", "operatingSystem"],
}


def _flatten(d: Any, prefix: str = "", sep: str = ".") -> dict:
    items: dict = {}
    if isinstance(d, dict):
        for k, v in d.items():
            new_key = f"{prefix}{sep}{k}" if prefix else str(k)
            items.update(_flatten(v, new_key, sep))
    elif isinstance(d, list):
        for i, v in enumerate(d):
            items.update(_flatten(v, f"{prefix}[{i}]", sep))
    else:
        items[prefix] = d
    return items


def _extract_metakey_values(incident: dict, metakeys: list[str]) -> dict:
    flat = _flatten(incident)
    values: dict = {}
    for mk in metakeys:
        for candidate in _METAKEY_FIELD_MAP.get(mk, []):
            if flat.get(candidate) not in (None, "", [], {}):
                values[mk] = flat[candidate]
                break
    return values


# ══════════════════════════════════════════════════════════════════════════════
# 5.  LANGCHAIN TOOLS  (each phase is a @tool so the agent can call them)
# ══════════════════════════════════════════════════════════════════════════════

def _make_tools(llm: ChatOpenAI, progress_fn=None, thinking_container=None):
    """
    Build the three triage tools bound to the supplied LLM.

    progress_fn(event, label, text) — phase lifecycle callbacks
    thinking_container              — Streamlit st.empty(); when provided,
                                      model tokens stream into it live
    """
    def _emit(event: str, label: str, text: str = "") -> None:
        if progress_fn:
            try:
                progress_fn(event, label, text)
            except Exception:
                pass

    # ── 5a: IOC Checklist tool ────────────────────────────────────────────────

    @lc_tool
    def run_ioc_checklists(incident_json: str) -> str:
        """
        Run all three IOC checklists (Availability, Confidentiality, Integrity)
        against the incident and return matched IOCs and meta-keys as JSON.
        Input: incident as a JSON string.
        """
        try:
            incident = json.loads(incident_json)
        except json.JSONDecodeError:
            return json.dumps({"error": "Invalid incident JSON"})

        results: dict[str, dict] = {}
        all_metakeys: set[str] = set()
        summary_parts: list[str] = []


        for category, ioc_list in ALL_IOCS.items():
            ioc_text = "\n".join(
                f"[{i+1}] {item['ioc']}: {item['description']}"
                for i, item in enumerate(ioc_list)
            )

            prompt = ChatPromptTemplate.from_messages([
                SystemMessage(content=(
                    "You are a SOC Analyst performing IOC triage. "
                    "Analyse the incident and determine which IOCs from the checklist are present. "
                    "After your reasoning, output ONLY a single JSON object as your final answer. "
                    'Final JSON schema: {"matched_iocs": [<1-based indices of matched IOCs>], '
                    '"reasoning": "<one sentence summary>", '
                    '"metakeys": [<relevant meta-key strings>]}'
                )),
                HumanMessage(content=(
                    f"INCIDENT:\n{json.dumps(incident, indent=2)}\n\n"
                    f"IOC CHECKLIST — {category.upper()}:\n{ioc_text}\n\n"
                    "Which IOCs are present or suspected? "
                    "End your response with the JSON object."
                )),
            ])

            _emit("phase_start", f"IOC — {category.capitalize()}")

            # Capture raw reasoning then extract JSON
            _, text_chain = _make_json_chain(prompt, llm)
            raw_text = _stream_or_invoke(text_chain, thinking_container)
            data = _extract_json(raw_text)
            # Repair if required keys are missing
            if not data.get("matched_iocs") and not data.get("metakeys"):
                data = _repair_json(raw_text, ["matched_iocs", "reasoning", "metakeys"], llm)

            matched_indices = data.get("matched_iocs", [])
            reasoning       = data.get("reasoning", "")
            extra_mkeys     = data.get("metakeys", [])

            matched_ioc_names = []
            matched_ioc_mkeys: set[str] = set()
            for idx in matched_indices:
                try:
                    entry = ioc_list[int(idx) - 1]
                    matched_ioc_names.append(entry["ioc"])
                    matched_ioc_mkeys.update(entry["metakeys"])
                except (IndexError, ValueError, TypeError):
                    pass

            all_metakeys.update(matched_ioc_mkeys)
            all_metakeys.update(str(m) for m in extra_mkeys)

            results[category] = {
                "matched_ioc_names": matched_ioc_names,
                "matched_indices":   matched_indices,
                "reasoning":         reasoning,
                "raw_thinking":      raw_text,
                "category_metakeys": sorted(matched_ioc_mkeys),
            }

            if matched_ioc_names:
                summary_parts.append(
                    f"[{category.upper()}] {', '.join(matched_ioc_names)} — {reasoning}"
                )
            _emit("phase_complete", f"IOC — {category.capitalize()}",
                  f"{len(matched_ioc_names)} IOC(s) matched")

        return json.dumps({
            "per_category":    results,
            "all_metakeys":    sorted(all_metakeys),
            "ioc_summary":     "\n".join(summary_parts) if summary_parts else "No IOCs matched.",
            "total_ioc_count": sum(len(v["matched_ioc_names"]) for v in results.values()),
        })

    # ── 5b: Risk Rating tool ──────────────────────────────────────────────────

    @lc_tool
    def run_risk_rating(incident_and_iocs_json: str) -> str:
        """
        Apply the SOC Risk Rating Methodology across three dimensions
        (likelihood of initiation, occurrence, adverse impact) and derive
        an overall risk level.
        Input: JSON string with keys 'incident' and 'ioc_summary'.
        """
        try:
            payload     = json.loads(incident_and_iocs_json)
            incident    = payload.get("incident", {})
            ioc_summary = payload.get("ioc_summary", "")
        except json.JSONDecodeError:
            return json.dumps({"error": "Invalid input JSON"})


        prompt = ChatPromptTemplate.from_messages([
            SystemMessage(content=(
                "You are a SOC Risk Analyst applying the SOC Risk Rating Methodology. "
                "After your reasoning, output ONLY a single JSON object as your final answer. "
                'Final JSON schema: {"likelihood_initiation": "<Critical|High|Medium|Low>", '
                '"likelihood_occurrence": "<Critical|High|Medium|Low>", '
                '"likelihood_adverse_impact": "<Critical|High|Medium|Low>", '
                '"overall_risk": "<Critical|High|Medium|Low>", '
                '"rationale": "<one sentence rationale>"}'
            )),
            HumanMessage(content=(
                f"INCIDENT:\n{json.dumps(incident, indent=2)}\n\n"
                f"IOC FINDINGS:\n{ioc_summary}\n\n"
                f"RISK RATING GUIDANCE:\n{RISK_RATING_GUIDANCE}\n\n"
                "Rate all three dimensions and derive an overall risk level. "
                "The overall risk should reflect the highest dimension. "
                "End your response with the JSON object."
            )),
        ])

        _emit("phase_start", "Risk Rating")
        _, text_chain = _make_json_chain(prompt, llm)
        raw_text = _stream_or_invoke(text_chain, thinking_container)
        data = _extract_json(raw_text)
        data["raw_thinking"] = raw_text
        _emit("phase_complete", "Risk Rating",
              f"Overall risk: {data.get('overall_risk', '—')}")
        return json.dumps(data)

    # ── 5c: SOC Classification tool ───────────────────────────────────────────

    @lc_tool
    def run_soc_classification(risk_and_iocs_json: str) -> str:
        """
        Classify the incident using the SOC Classification Template,
        assign a severity level, response time, and recommended actions.
        Input: JSON string with keys 'incident', 'risk_level', 'ioc_summary'.
        """
        try:
            payload     = json.loads(risk_and_iocs_json)
            incident    = payload.get("incident", {})
            risk_level  = payload.get("risk_level", "medium")
            ioc_summary = payload.get("ioc_summary", "")
        except json.JSONDecodeError:
            return json.dumps({"error": "Invalid input JSON"})


        prompt = ChatPromptTemplate.from_messages([
            SystemMessage(content=(
                "You are a SOC Analyst applying the SOC Classification Template. "
                "After your reasoning, output ONLY a single JSON object as your final answer. "
                'Final JSON schema: {"classification": "<Critical|High|Medium|Low>", '
                '"incident_category": "<best matching category from the template>", '
                '"response_time": "<initial response time>", '
                '"summary": "<2-3 sentence triage summary>", '
                '"recommended_actions": ["<action 1>", "<action 2>", ...]}'
            )),
            HumanMessage(content=(
                f"INCIDENT:\n{json.dumps(incident, indent=2)}\n\n"
                f"RISK RATING RESULT: {risk_level.upper()}\n\n"
                f"IOC FINDINGS:\n{ioc_summary}\n\n"
                f"SOC CLASSIFICATION TEMPLATE:\n{json.dumps(SOC_CLASSIFICATION_TABLE, indent=2)}\n\n"
                "Classify this incident. "
                "End your response with the JSON object."
            )),
        ])

        _emit("phase_start", "SOC Classification")
        _, text_chain = _make_json_chain(prompt, llm)
        raw_text = _stream_or_invoke(text_chain, thinking_container)
        data = _extract_json(raw_text)
        data["raw_thinking"] = raw_text
        _emit("phase_complete", "SOC Classification",
              f"Classification: {data.get('classification', '—')}")
        return json.dumps(data)

    return run_ioc_checklists, run_risk_rating, run_soc_classification


# ══════════════════════════════════════════════════════════════════════════════
# 6.  TRIAGE AGENT
# ══════════════════════════════════════════════════════════════════════════════

class TriageAgent:
    """
    SOC Triage Agent built with LangChain LCEL chains and @tool functions.

    The agent orchestrates three sequential phases via an LCEL pipeline:

        incident_dict
            │
            ▼
        ┌─────────────────────────────────┐
        │  Phase 1: IOC Checklists        │  ← run_ioc_checklists tool
        │  (Availability / Confidentiality│
        │   / Integrity in parallel)      │
        └───────────────┬─────────────────┘
                        │ ioc_results
                        ▼
        ┌─────────────────────────────────┐
        │  Phase 2: Risk Rating           │  ← run_risk_rating tool
        └───────────────┬─────────────────┘
                        │ risk_data
                        ▼
        ┌─────────────────────────────────┐
        │  Phase 3: SOC Classification    │  ← run_soc_classification tool
        └───────────────┬─────────────────┘
                        │
                        ▼
              metakeys_payload  +  ticket

    Usage
    -----
        agent  = TriageAgent(cfg=CiscoLLMConfig(...))
        result = agent.triage(incident_dict)

        result["metakeys_payload"]  → downstream meta-key agent
        result["ticket"]            → downstream ticketing agent
        result["trace"]             → step-by-step reasoning for UI display
    """

    def __init__(self, cfg: CiscoLLMConfig | None = None, progress_fn=None,
                 thinking_container=None) -> None:
        self.cfg         = cfg or CiscoLLMConfig()
        self.llm         = build_llm(self.cfg)
        self.progress_fn = progress_fn
        (
            self._ioc_tool,
            self._risk_tool,
            self._cls_tool,
        ) = _make_tools(self.llm, progress_fn=progress_fn,
                        thinking_container=thinking_container)

        # ── LCEL pipeline ─────────────────────────────────────────────────────
        #
        # Each step is a RunnableLambda that calls the appropriate @tool.
        # RunnablePassthrough threads the original incident through so each
        # stage has access to the full incident dict.

        self._ioc_chain = RunnableLambda(self._phase1_ioc)
        self._risk_chain = RunnableLambda(self._phase2_risk)
        self._cls_chain  = RunnableLambda(self._phase3_classify)

        # Full sequential pipeline
        self._pipeline = (
            RunnablePassthrough.assign(ioc_results=self._ioc_chain)
            | RunnablePassthrough.assign(risk_results=self._risk_chain)
            | RunnablePassthrough.assign(cls_results=self._cls_chain)
        )

    # ── Pipeline step implementations ─────────────────────────────────────────

    def _phase1_ioc(self, state: dict) -> dict:
        """Call the IOC checklist tool and parse results."""
        incident_json = json.dumps(state["incident"])
        raw           = self._ioc_tool.invoke(incident_json)
        return json.loads(raw) if isinstance(raw, str) else raw

    def _phase2_risk(self, state: dict) -> dict:
        """Call the risk rating tool using incident + IOC summary."""
        ioc_data    = state.get("ioc_results", {})
        ioc_summary = ioc_data.get("ioc_summary", "No IOC data")
        payload     = json.dumps({"incident": state["incident"], "ioc_summary": ioc_summary})
        raw         = self._risk_tool.invoke(payload)
        return json.loads(raw) if isinstance(raw, str) else raw

    def _phase3_classify(self, state: dict) -> dict:
        """Call the classification tool using incident + risk level + IOC summary."""
        ioc_data    = state.get("ioc_results", {})
        risk_data   = state.get("risk_results", {})
        risk_level  = risk_data.get("overall_risk", "medium")
        ioc_summary = ioc_data.get("ioc_summary", "No IOC data")
        payload     = json.dumps({
            "incident":    state["incident"],
            "risk_level":  risk_level,
            "ioc_summary": ioc_summary,
        })
        raw = self._cls_tool.invoke(payload)
        return json.loads(raw) if isinstance(raw, str) else raw

    # ── Main entry point ──────────────────────────────────────────────────────

    def triage(self, incident: dict) -> dict:
        """
        Run the full triage pipeline on a NetWitness incident dict.

        Returns
        -------
        dict
            metakeys_payload  — for the downstream meta-key agent
            ticket            — for the downstream ticketing agent
            trace             — step-by-step results (for UI rendering)
            error             — None on success, error string on failure
        """
        inc_id       = str(incident.get("id") or incident.get("incidentId") or "unknown")
        inc_title    = incident.get("title") or incident.get("name") or "Untitled"
        timestamp    = datetime.utcnow().isoformat()
        inc_time     = _extract_incident_time(incident)
        trace: list[dict] = []

        try:
            final_state = self._pipeline.invoke({"incident": incident})
        except Exception as exc:
            return {
                "error":            str(exc),
                "metakeys_payload": {},
                "ticket":           {},
                "trace":            trace,
            }

        ioc_data  = final_state.get("ioc_results", {})
        risk_data = final_state.get("risk_results", {})
        cls_data  = final_state.get("cls_results", {})

        # ── Build trace for display ───────────────────────────────────────────
        trace = [
            {
                "step":            "IOC Checklist",
                "status":          "ok",
                "matched_metakeys": ioc_data.get("all_metakeys", []),
                "ioc_summary":     ioc_data.get("ioc_summary", ""),
                "total_ioc_count": ioc_data.get("total_ioc_count", 0),
                "per_category":    ioc_data.get("per_category", {}),
            },
            {
                "step":    "Risk Rating",
                "status":  "ok",
                "data":    risk_data,
            },
            {
                "step":    "SOC Classification",
                "status":  "ok",
                "data":    cls_data,
            },
        ]

        matched_metakeys = ioc_data.get("all_metakeys", [])
        risk_level       = (risk_data.get("overall_risk") or "medium").lower()
        classification   = (cls_data.get("classification") or risk_level).lower()
        cls_meta         = SOC_CLASSIFICATION_TABLE.get(
            classification, SOC_CLASSIFICATION_TABLE["medium"]
        )

        # ── Output 1: Meta-keys payload ───────────────────────────────────────
        metakeys_payload = {
            "incident_id":      inc_id,
            "incident_title":   inc_title,
            "timestamp":        timestamp,
            "matched_metakeys": matched_metakeys,
            "metakey_values":   _extract_metakey_values(incident, matched_metakeys),
            "ioc_summary":      ioc_data.get("ioc_summary", ""),
            "risk_level":       risk_level,
            "classification":   classification,
        }

        # ── Output 2: Ticket ──────────────────────────────────────────────────
        unc    = _next_unc()
        ticket = {
            "unc":             unc,
            "incident_id":     inc_id,
            "title":           inc_title,
            "incident_time":   inc_time,
            "created_at":      timestamp,
            "classification":  classification.upper(),
            "risk_rating": {
                "likelihood_initiation":    risk_data.get("likelihood_initiation", "—"),
                "likelihood_occurrence":    risk_data.get("likelihood_occurrence", "—"),
                "likelihood_adverse_impact":risk_data.get("likelihood_adverse_impact", "—"),
                "overall_risk":             risk_data.get("overall_risk", "—"),
                "rationale":                risk_data.get("rationale", ""),
            },
            "incident_category":     cls_data.get("incident_category", "—"),
            "initial_response_time": cls_meta["initial_response_time"],
            "summary":               cls_data.get("summary", ""),
            "recommended_actions":   cls_data.get("recommended_actions", []),
            "matched_ioc_count":     ioc_data.get("total_ioc_count", 0),
            "metakeys":              matched_metakeys,
        }

        _store_ticket(unc, inc_id, classification, ticket)

        return {
            "metakeys_payload": metakeys_payload,
            "ticket":           ticket,
            "trace":            trace,
            "error":            None,
        }


# ══════════════════════════════════════════════════════════════════════════════
# 7.  STREAMLIT DISPLAY HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def render_triage_trace(trace: list[dict]) -> str:
    """Convert the triage trace into a markdown string for the chat bubble."""
    lines: list[str] = ["## 🛡️ SOC Triage Report\n"]

    for step in trace:
        name   = step.get("step", "Step")
        status = "✅" if step.get("status") == "ok" else "❌"
        lines.append(f"### {status} Phase — {name}")

        if name == "IOC Checklist":
            ioc_summary = step.get("ioc_summary", "")
            mkeys       = step.get("matched_metakeys", [])
            count       = step.get("total_ioc_count", 0)
            lines.append(f"**Total IOCs matched:** {count}")
            lines.append(f"**Summary:** {ioc_summary}")
            if mkeys:
                lines.append(f"**Matched Meta-Keys:** `{'`, `'.join(mkeys)}`")
            per_cat = step.get("per_category", {})
            for cat, cat_data in per_cat.items():
                matched = cat_data.get("matched_ioc_names", [])
                if matched:
                    lines.append(f"- **{cat.capitalize()}:** {', '.join(matched)}")

        elif name == "Risk Rating":
            d = step.get("data", {})
            lines.append(f"| Dimension | Rating |")
            lines.append(f"|-----------|--------|")
            lines.append(f"| Likelihood of Initiation | **{d.get('likelihood_initiation','—')}** |")
            lines.append(f"| Likelihood of Occurrence | **{d.get('likelihood_occurrence','—')}** |")
            lines.append(f"| Likelihood of Adverse Impact | **{d.get('likelihood_adverse_impact','—')}** |")
            lines.append(f"| **Overall Risk** | **{d.get('overall_risk','—')}** |")
            if d.get("rationale"):
                lines.append(f"\n*Rationale: {d['rationale']}*")

        elif name == "SOC Classification":
            d = step.get("data", {})
            lines.append(f"- **Classification:** {d.get('classification','—').upper()}")
            lines.append(f"- **Category:** {d.get('incident_category','—')}")
            lines.append(f"- **Initial Response Time:** {d.get('response_time','—')}")
            if d.get("summary"):
                lines.append(f"- **Summary:** {d['summary']}")
            actions = d.get("recommended_actions", [])
            if actions:
                lines.append("\n**Recommended Actions:**")
                for a in actions:
                    lines.append(f"  - {a}")

        lines.append("")

    return "\n".join(lines)


def format_ticket_display(ticket: dict) -> str:
    """Return a formatted markdown ticket for the chat bubble."""
    rr    = ticket.get("risk_rating", {})
    unc   = ticket.get("unc", "—")
    cls   = ticket.get("classification", "—")
    icons = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}
    icon  = icons.get(cls, "⚪")

    lines = [
        f"---",
        f"## {icon} Ticket `{unc}`",
        f"| Field | Value |",
        f"|-------|-------|",
        f"| **Incident ID** | `{ticket.get('incident_id','—')}` |",
        f"| **Title** | {ticket.get('title','—')} |",
        f"| **Incident Time** | {ticket.get('incident_time','—')} |",
        f"| **Ticket Created** | {ticket.get('created_at','—')} |",
        f"| **Classification** | **{cls}** |",
        f"| **Category** | {ticket.get('incident_category','—')} |",
        f"| **Initial Response Time** | {ticket.get('initial_response_time','—')} |",
        f"| **IOCs Matched** | {ticket.get('matched_ioc_count',0)} |",
        "",
        "### Risk Rating",
        f"| Dimension | Rating |",
        f"|-----------|--------|",
        f"| Initiation | {rr.get('likelihood_initiation','—')} |",
        f"| Occurrence | {rr.get('likelihood_occurrence','—')} |",
        f"| Adverse Impact | {rr.get('likelihood_adverse_impact','—')} |",
        f"| **Overall** | **{rr.get('overall_risk','—')}** |",
        "",
        f"### Triage Summary",
        ticket.get("summary", "—"),
        "",
        "### Recommended Actions",
    ]
    for a in ticket.get("recommended_actions", []):
        lines.append(f"- {a}")

    metakeys = ticket.get("metakeys", [])
    if metakeys:
        lines += ["", "### Matched Meta-Keys",
                  f"`{'`, `'.join(metakeys)}`"]

    return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════════════════
# 8.  DROP-IN  chat_respond()  REPLACEMENT  (plug into app.py)
# ══════════════════════════════════════════════════════════════════════════════

# Trigger keywords that activate the triage pipeline
_TRIAGE_TRIGGER = re.compile(
    r"\b(triage|analys[ei]s?|ioc|classify|classification|ticket|investigate)\b",
    re.IGNORECASE,
)

# LangChain StrOutputParser chain for plain Q&A fallback
def _build_qa_chain(llm: ChatOpenAI):
    prompt = ChatPromptTemplate.from_messages([
        SystemMessage(content=(
            "You are an expert SOC Analyst. Answer questions concisely and accurately. "
            "Use IOC analysis, threat intelligence, and security best practices."
        )),
        HumanMessage(content="{user_input}"),
    ])
    return prompt | llm | StrOutputParser()


def soc_triage_chat_respond(
    user_msg:           str,
    incident:           dict | None = None,
    llm_config:         CiscoLLMConfig | None = None,
    progress_fn                      = None,
    thinking_container               = None,
) -> str:
    """
    Drop-in replacement for the chat_respond() stub in app.py.

    If the analyst message contains a triage trigger word AND an incident
    is selected, the full 3-phase pipeline runs.
    Otherwise falls back to a plain SOC analyst Q&A via LangChain.

    Wiring in app.py (3 lines):
    ────────────────────────────
    from soc_triage_agent import soc_triage_chat_respond, CiscoLLMConfig

    CISCO_CFG = CiscoLLMConfig()   # reads CISCO_LLM_URL / KEY / MODEL from env

    def chat_respond(user_msg, incident=None):
        return soc_triage_chat_respond(user_msg, incident, llm_config=CISCO_CFG)
    """
    cfg = llm_config or CiscoLLMConfig()
    llm = build_llm(cfg)

    if incident and _TRIAGE_TRIGGER.search(user_msg):
        agent  = TriageAgent(cfg=cfg, progress_fn=progress_fn,
                             thinking_container=thinking_container)
        result = agent.triage(incident)

        if result.get("error"):
            return f"❌ Triage error: {result['error']}"

        trace_md  = render_triage_trace(result["trace"])
        ticket_md = format_ticket_display(result["ticket"])
        unc       = result["ticket"].get("unc", "—")

        return (
            trace_md
            + "\n\n"
            + ticket_md
            + "\n\n---\n\n"
            + f"📤 **Meta-key payload queued for downstream agent** "
            + f"({len(result['metakeys_payload'].get('matched_metakeys', []))} keys)\n\n"
            + f"📋 **Ticket `{unc}` created and queued for ticketing agent.**"
        )

    # Plain Q&A fallback
    ctx = ""
    if incident:
        ctx = (
            f"\n\nCurrent incident context (truncated):\n"
            f"{json.dumps(incident, indent=2)[:600]}"
        )
    qa_chain = _build_qa_chain(llm)
    try:
        return qa_chain.invoke({"user_input": user_msg + ctx})
    except Exception as exc:
        return f"⚠️ LLM error: {exc}"