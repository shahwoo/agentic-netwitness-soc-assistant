"""
SOC Triage Agent  —  soc_triage_agent.py
=========================================
Architecture: 3 direct LLM calls (no LCEL pipeline, no tool wrappers).

  Call 1 — IOC Checklists   (all 27 IOCs across 3 categories in one call)
  Call 2 — Risk Rating
  Call 3 — SOC Classification

Each call: ChatPromptTemplate → ChatOpenAI → StrOutputParser → _extract_json
Repair call fires if required keys are missing from the JSON.

Public API (app.py imports):
  CiscoLLMConfig, build_llm, TriageAgent,
  soc_triage_chat_respond, _TRIAGE_TRIGGER,
  render_triage_trace, format_ticket_display
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

# ── LangChain imports (minimal) ───────────────────────────────────────────────
from langchain_core.messages import SystemMessage, HumanMessage
from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI


# ══════════════════════════════════════════════════════════════════════════════
# 1.  LLM CONFIG & BUILDER
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class CiscoLLMConfig:
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
    # temperature=0 -> greedy decoding, so the same incident produces the same
    # triage output instead of drifting between runs/users. A fixed seed is
    # sent too, since HF/TGI's Messages API takes it for reproducibility.
    temperature: float = 0.0
    seed:        int | None = field(
        default_factory=lambda: int(os.environ["CISCO_LLM_SEED"])
        if os.environ.get("CISCO_LLM_SEED") else 42
    )
    max_tokens:  int   = 2048
    timeout:     int   = 300


def build_llm(cfg: CiscoLLMConfig) -> ChatOpenAI:
    return ChatOpenAI(
        base_url     = cfg.base_url,
        api_key      = cfg.api_key,
        model        = cfg.model,
        temperature  = cfg.temperature,
        max_tokens   = cfg.max_tokens,
        timeout      = cfg.timeout,
        max_retries  = 2,
        model_kwargs = {"seed": cfg.seed} if cfg.seed is not None else {},
    )


# ══════════════════════════════════════════════════════════════════════════════
# 2.  IOC CHECKLISTS
# ══════════════════════════════════════════════════════════════════════════════

IOC_AVAILABILITY = [
    {"ioc": "Frequent core dump and/or traceback generation",
     "desc": "Frequent software crashes during normal device operation",
     "metakeys": ["event.type", "device.type", "host.name"]},
    {"ioc": "High CPU usage",
     "desc": "Abnormally high CPU usage caused by a malicious actor",
     "metakeys": ["cpu.usage", "process.name", "host.name"]},
    {"ioc": "Frequent rebooting",
     "desc": "Altered device software causing frequent reload",
     "metakeys": ["event.type", "device.type", "host.name"]},
    {"ioc": "Saturated interface input/output buffers",
     "desc": "High traffic volumes initiated by a malicious actor",
     "metakeys": ["network.interface", "bytes.in", "bytes.out", "packets.in", "packets.out"]},
    {"ioc": "Abnormally high malformed packet counts",
     "desc": "High numbers of malformed packets destined to a device",
     "metakeys": ["packets.malformed", "ip.dst", "ip.src"]},
    {"ioc": "Configuration changes",
     "desc": "Changes in routes, routing protocols, NAT, ACLs, SNMP, logging, syslog, VPNs",
     "metakeys": ["change.type", "config.change", "user.name", "host.name"]},
    {"ioc": "Unexplained changes from privileged accounts",
     "desc": "Unusual activity from privileged accounts",
     "metakeys": ["user.name", "user.role", "event.time", "file.path", "bytes.transferred"]},
]

IOC_CONFIDENTIALITY = [
    {"ioc": "Changes in network traffic telemetry (known bad IPs/domains)",
     "desc": "Traffic to/from known malicious IPs or domains; data exfiltration",
     "metakeys": ["ip.dst", "ip.src", "domain", "bytes.out", "alert.type"]},
    {"ioc": "Unknown traffic originating from/terminating on the device",
     "desc": "Unusual traffic e.g. Telnet, SSH, HTTP/HTTPS, RDP",
     "metakeys": ["ip.src", "ip.dst", "network.service", "port.dst", "protocol"]},
    {"ioc": "Anomalous file transfers",
     "desc": "Unusual file transfers via FTP/TFTP/SNMP to unexpected hosts",
     "metakeys": ["file.name", "file.size", "ip.dst", "ip.src", "protocol", "bytes.out"]},
    {"ioc": "Geographic-based anomalies",
     "desc": "Traffic to/from countries the organisation does not normally engage",
     "metakeys": ["geo.country", "ip.src", "ip.dst", "user.name", "event.type"]},
    {"ioc": "File system permissions changed",
     "desc": "Changes in file system authorisations",
     "metakeys": ["file.path", "permission.change", "user.name", "host.name"]},
    {"ioc": "Configuration changes",
     "desc": "Changes in routes, routing protocols, NAT, ACLs, SNMP, logging, VPNs",
     "metakeys": ["change.type", "config.change", "user.name", "host.name"]},
    {"ioc": "Device account/password additions/deletions/changes",
     "desc": "Changes to device account or credential information",
     "metakeys": ["user.name", "event.type", "account.action", "host.name"]},
    {"ioc": "Unexplained changes from privileged accounts",
     "desc": "Unusual activity from privileged accounts",
     "metakeys": ["user.name", "user.role", "event.time", "file.path", "bytes.transferred"]},
]

IOC_INTEGRITY = [
    {"ioc": "Generation of core dumps and/or tracebacks",
     "desc": "Frequent software crashes during normal device operation",
     "metakeys": ["event.type", "device.type", "host.name"]},
    {"ioc": "Odd device/platform behaviour",
     "desc": "Behaviour deviating from expected normal operation",
     "metakeys": ["event.type", "host.name", "device.type"]},
    {"ioc": "Anomalies in OS/package hash values",
     "desc": "Inconsistent hash values that deviate from expected",
     "metakeys": ["file.hash", "file.name", "host.name", "os.version"]},
    {"ioc": "Anomalies in OS/package certificate signing",
     "desc": "Bypassing code signing checks; unknown CA certificates",
     "metakeys": ["cert.issuer", "cert.hash", "file.name", "host.name"]},
    {"ioc": "Unknown binaries installed",
     "desc": "Binary files and configs not part of the OS",
     "metakeys": ["file.name", "file.path", "file.hash", "host.name", "process.name"]},
    {"ioc": "Unknown process running",
     "desc": "Processes in memory with unusual attributes or arbitrary names",
     "metakeys": ["process.name", "process.pid", "process.path", "host.name"]},
    {"ioc": "Unexpected OS/ROMMON release versions installed",
     "desc": "Presence of unexpected system software or bootstrap versions",
     "metakeys": ["os.version", "firmware.version", "host.name"]},
    {"ioc": "File system permissions changed",
     "desc": "Changes in file system authorisations",
     "metakeys": ["file.path", "permission.change", "user.name", "host.name"]},
    {"ioc": "Unexpected changes in boot sequence or boot variables",
     "desc": "Alteration of system startup files",
     "metakeys": ["boot.config", "file.path", "host.name"]},
    {"ioc": "Configuration changes",
     "desc": "Changes in routes, routing protocols, NAT, ACLs, SNMP, logging, VPNs",
     "metakeys": ["change.type", "config.change", "user.name", "host.name"]},
    {"ioc": "Device account/password additions/deletions/changes",
     "desc": "Changes to device account or credential information",
     "metakeys": ["user.name", "event.type", "account.action", "host.name"]},
    {"ioc": "Unexplained changes from privileged accounts",
     "desc": "Unusual activity from privileged accounts",
     "metakeys": ["user.name", "user.role", "event.time", "file.path", "bytes.transferred"]},
]

ALL_IOCS = {
    "availability":    IOC_AVAILABILITY,
    "confidentiality": IOC_CONFIDENTIALITY,
    "integrity":       IOC_INTEGRITY,
}


# ══════════════════════════════════════════════════════════════════════════════
# 3.  RISK RATING & CLASSIFICATION DATA
# ══════════════════════════════════════════════════════════════════════════════

RISK_RATING_GUIDANCE = """
LIKELIHOOD OF THREAT EVENT INITIATION:
  Critical — Adversary is almost certain to initiate the threat event
  High     — Adversary is highly likely to initiate the threat event
  Medium   — Adversary is somewhat likely to initiate the threat event
  Low      — Adversary is unlikely to initiate the threat event

LIKELIHOOD OF THREAT EVENT OCCURRENCE:
  Critical — Almost certain to occur, or occurs more than 100 times a year
  High     — Highly likely to occur, or occurs 10–100 times a year
  Medium   — Somewhat likely to occur, or occurs 1–10 times a year
  Low      — Unlikely to occur, or occurs less than once a year

LIKELIHOOD OF ADVERSE IMPACT:
  Critical — Almost certain to have adverse impacts
  High     — Highly likely to have adverse impacts
  Medium   — Somewhat likely to have adverse impacts
  Low      — Unlikely to have adverse impacts
"""

SOC_CLASSIFICATION_TABLE = {
    "critical": {
        "definition": "Urgent & high-risk security issue requiring immediate action",
        "categories": ["Internal Hacking (active)", "External Hacking (active)",
                       "Virus/Worm (outbreak)", "Destruction of property (critical)"],
        "initial_response_time": "<= 15 minutes",
    },
    "high": {
        "definition": "Significant security threats requiring investigation",
        "categories": ["Internal Hacking (inactive)", "External Hacking (inactive)",
                       "Unauthorized access", "Policy violations", "Unlawful activity",
                       "Compromised information", "Compromised asset (non-critical)"],
        "initial_response_time": "30 to 60 minutes",
    },
    "medium": {
        "definition": "Suspicious activity warranting investigation",
        "categories": ["Email Forensics Request", "Inappropriate use of property",
                       "Policy violations"],
        "initial_response_time": "~4 hours",
    },
    "low": {
        "definition": "Events with minimal immediate risk",
        "categories": ["Email", "Unknown websites", "Unknown Source IP",
                       "AV Alert with minimal consequences"],
        "initial_response_time": ">= 24 hours",
    },
}


# ══════════════════════════════════════════════════════════════════════════════
# 4.  TICKET UNC COUNTER
# ══════════════════════════════════════════════════════════════════════════════

_TICKET_DB   = Path(__file__).parent / "soc_tickets.db"
_TICKET_LOCK = threading.Lock()


def _ticket_db_init() -> None:
    with sqlite3.connect(str(_TICKET_DB)) as con:
        con.execute("""
            CREATE TABLE IF NOT EXISTS ticket_counter (
                id      INTEGER PRIMARY KEY CHECK (id = 1),
                number  INTEGER NOT NULL DEFAULT 0,
                letter  TEXT    NOT NULL DEFAULT 'A'
            )""")
        con.execute(
            "INSERT OR IGNORE INTO ticket_counter (id, number, letter) VALUES (1, 0, 'A')")
        con.execute("""
            CREATE TABLE IF NOT EXISTS tickets (
                unc TEXT PRIMARY KEY, incident_id TEXT,
                severity TEXT, created_at TEXT, payload TEXT
            )""")
        con.commit()


def _increment_suffix(s: str) -> str:
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
    with _TICKET_LOCK:
        with sqlite3.connect(str(_TICKET_DB)) as con:
            row = con.execute(
                "SELECT number, letter FROM ticket_counter WHERE id=1").fetchone()
            number, letter = row[0], row[1]
            unc = f"#{number:05d}{letter}"
            next_n = number + 1
            next_l = letter
            if next_n > 99999:
                next_n = 0
                next_l = _increment_suffix(letter)
            con.execute("UPDATE ticket_counter SET number=?,letter=? WHERE id=1",
                        (next_n, next_l))
            con.commit()
    return unc


def _store_ticket(unc: str, incident_id: str, severity: str, payload: dict) -> None:
    with sqlite3.connect(str(_TICKET_DB)) as con:
        con.execute("INSERT OR REPLACE INTO tickets VALUES (?,?,?,?,?)",
                    (unc, incident_id, severity,
                     datetime.utcnow().isoformat(), json.dumps(payload)))
        con.commit()


_ticket_db_init()


# ══════════════════════════════════════════════════════════════════════════════
# 5.  JSON EXTRACTION & REPAIR
# ══════════════════════════════════════════════════════════════════════════════

def _coerce_dict(parsed: Any) -> dict:
    """
    The model doesn't always emit a JSON object — sometimes it's an array
    (e.g. [{...}]) or a bare scalar. Every caller of _extract_json does
    data.get(...), so anything non-dict must be coerced here or it crashes
    with "'list' object has no attribute 'get'".
    """
    if isinstance(parsed, dict):
        return parsed
    if isinstance(parsed, list):
        merged: dict = {}
        for item in parsed:
            if isinstance(item, dict):
                merged.update(item)
        return merged
    return {}


def _extract_json(text: str) -> dict:
    """Extract a JSON object from raw model output (handles reasoning prose)."""
    if not text:
        return {}
    cleaned = re.sub(r"```(?:json)?", "", text).replace("```", "").strip()
    try:
        data = _coerce_dict(json.loads(cleaned))
        if data:
            return data
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
                try:
                    return json.loads(cleaned[i: last_close + 1])
                except json.JSONDecodeError:
                    break
    for m in reversed(list(re.finditer(r"\{[^{}]+\}", cleaned, re.DOTALL))):
        try:
            return json.loads(m.group())
        except json.JSONDecodeError:
            continue
    return {}


_VALID_LEVELS = ("critical", "high", "medium", "low")


def _normalize_level(value: str | None, default: str) -> str:
    """
    Map the model's free-text level to one of the canonical SOC levels.
    Without this, phrasing drift (case, whitespace, "informational", a
    trailing period) silently falls through to the "medium" dict-lookup
    default in SOC_CLASSIFICATION_TABLE, which looks like inconsistent
    output but is really just an un-normalized string miss.
    """
    if not value:
        return default
    v = re.sub(r"[^a-z]", "", value.strip().lower())
    if v in _VALID_LEVELS:
        return v
    if v.startswith("info"):
        return "low"
    for level in _VALID_LEVELS:
        if level in v:
            return level
    return default


def _repair_json(raw_text: str, required_keys: list[str], llm: ChatOpenAI) -> dict:
    """Focused repair call when _extract_json misses required keys."""
    keys_str = ", ".join(f'"{k}"' for k in required_keys)
    prompt = ChatPromptTemplate.from_messages([
        SystemMessage(content=(
            "You are a JSON formatter. Extract or reconstruct a JSON object from "
            "the text. Return ONLY valid JSON — no prose, no markdown, no fences. "
            f"Required keys: {keys_str}"
        )),
        HumanMessage(content=f"TEXT:\n{raw_text[-2000:]}\n\nReturn ONLY JSON:"),
    ])
    try:
        chain = prompt | llm | StrOutputParser()
        raw   = chain.invoke({})
        data  = _extract_json(raw)
        if data:
            return data
    except Exception:
        pass
    return {}


# ══════════════════════════════════════════════════════════════════════════════
# 6.  STREAMING HELPER
# ══════════════════════════════════════════════════════════════════════════════

def _stream_or_invoke(text_chain, thinking_container=None) -> str:
    """Stream tokens into a Streamlit container, or plain invoke if not provided."""
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
            full_text += chunk if isinstance(chunk, str) else str(chunk)
            display = full_text if len(full_text) <= 600 else "…" + full_text[-600:]
            thinking_container.markdown(
                f'<div style="{_STYLE}">💭 {display}▌</div>',
                unsafe_allow_html=True,
            )
    except Exception:
        full_text = text_chain.invoke({})
    return full_text


# ══════════════════════════════════════════════════════════════════════════════
# 7.  INCIDENT TIME EXTRACTION
# ══════════════════════════════════════════════════════════════════════════════

_TIME_FIELDS = [
    "created", "createdAt", "created_at", "timestamp", "alertTime",
    "eventTime", "event_time", "occurredTime", "detectedTime", "time",
]


def _flatten(d: Any, prefix: str = "") -> dict:
    items: dict = {}
    if isinstance(d, dict):
        for k, v in d.items():
            nk = f"{prefix}.{k}" if prefix else str(k)
            items.update(_flatten(v, nk))
    elif isinstance(d, list):
        for i, v in enumerate(d):
            items.update(_flatten(v, f"{prefix}[{i}]"))
    else:
        items[prefix] = d
    return items


def _extract_incident_time(incident: dict) -> str:
    flat = _flatten(incident)
    for field in _TIME_FIELDS:
        val = flat.get(field) or incident.get(field)
        if val:
            raw = str(val).strip()
            for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%SZ",
                        "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
                try:
                    dt = datetime.strptime(raw[:19], fmt[:19])
                    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
                except ValueError:
                    continue
            if len(raw) >= 8:
                return raw
    return "—"


# ══════════════════════════════════════════════════════════════════════════════
# 8.  META-KEY EXTRACTOR
# ══════════════════════════════════════════════════════════════════════════════

_METAKEY_MAP: dict[str, list[str]] = {
    "ip.src":       ["sourceIp", "source_ip", "srcIp"],
    "ip.dst":       ["destinationIp", "dest_ip", "dstIp"],
    "host.name":    ["hostname", "host", "deviceName"],
    "user.name":    ["username", "user", "assignee"],
    "domain":       ["domain", "fqdn"],
    "event.type":   ["type", "eventType", "event_type"],
    "bytes.out":    ["bytesOut", "bytes_out", "egress_bytes"],
    "protocol":     ["protocol", "networkProtocol"],
    "geo.country":  ["country", "geoCountry"],
    "file.name":    ["fileName", "file_name"],
    "file.hash":    ["fileHash", "md5", "sha256"],
    "process.name": ["processName", "process_name"],
    "os.version":   ["osVersion", "os_version"],
}


def _extract_metakey_values(incident: dict, metakeys: list[str]) -> dict:
    flat = _flatten(incident)
    values: dict = {}
    for mk in metakeys:
        for cand in _METAKEY_MAP.get(mk, []):
            if flat.get(cand) not in (None, "", [], {}):
                values[mk] = flat[cand]
                break
    return values


# ══════════════════════════════════════════════════════════════════════════════
# 9.  TRIAGE AGENT  (3 direct LLM calls — no pipeline, no tool wrappers)
# ══════════════════════════════════════════════════════════════════════════════

class TriageAgent:
    """
    SOC Triage Agent.

    Three direct LLM calls, no LCEL pipeline, no @tool decorators:
      _run_ioc()  → 1 call covering all 27 IOCs across 3 categories
      _run_risk() → 1 call for risk rating
      _run_cls()  → 1 call for SOC classification

    Parameters
    ----------
    cfg               : CiscoLLMConfig
    progress_fn       : callable(event, label, text) — live UI callbacks
    thinking_container: Streamlit st.empty() for token streaming
    """

    def __init__(
        self,
        cfg: CiscoLLMConfig | None = None,
        progress_fn=None,
        thinking_container=None,
    ) -> None:
        self.cfg               = cfg or CiscoLLMConfig()
        self.llm               = build_llm(self.cfg)
        self.progress_fn       = progress_fn
        self.thinking_container = thinking_container

    # ── helpers ───────────────────────────────────────────────────────────────

    def _emit(self, event: str, label: str, text: str = "") -> None:
        if self.progress_fn:
            try:
                self.progress_fn(event, label, text)
            except Exception:
                pass

    def _call(self, messages: list, phase_label: str) -> tuple[str, dict]:
        """
        Build a chain, stream/invoke it, extract JSON, repair if needed.
        Returns (raw_text, data_dict).
        """
        self._emit("phase_start", phase_label)
        prompt     = ChatPromptTemplate.from_messages(messages)
        text_chain = prompt | self.llm | StrOutputParser()
        raw_text   = _stream_or_invoke(text_chain, self.thinking_container)
        return raw_text

    # ── Phase 1: IOC Checklists (single combined call) ────────────────────────

    def _run_ioc(self, incident: dict) -> dict:
        """One LLM call covering all three IOC categories."""

        def fmt_list(ioc_list, offset=0):
            return "\n".join(
                f"  [{i+1+offset}] {e['ioc']}: {e['desc']}"
                for i, e in enumerate(ioc_list)
            )

        avail_text = fmt_list(IOC_AVAILABILITY)
        conf_text  = fmt_list(IOC_CONFIDENTIALITY)
        integ_text = fmt_list(IOC_INTEGRITY)

        messages = [
            SystemMessage(content=(
                "You are a SOC Analyst performing IOC triage across three categories. "
                "Analyse the incident and identify which IOCs are present in each category. "
                "After your reasoning, output ONLY a single JSON object as your final answer.\n"
                "Final JSON schema:\n"
                '{"availability": {"matched_iocs": [<1-based indices>], "reasoning": "<brief>", "metakeys": [<strings>]},\n'
                ' "confidentiality": {"matched_iocs": [<1-based indices>], "reasoning": "<brief>", "metakeys": [<strings>]},\n'
                ' "integrity": {"matched_iocs": [<1-based indices>], "reasoning": "<brief>", "metakeys": [<strings>]}}'
            )),
            HumanMessage(content=(
                f"INCIDENT:\n{json.dumps(incident, indent=2)}\n\n"
                f"IOC CHECKLIST — AVAILABILITY:\n{avail_text}\n\n"
                f"IOC CHECKLIST — CONFIDENTIALITY:\n{conf_text}\n\n"
                f"IOC CHECKLIST — INTEGRITY:\n{integ_text}\n\n"
                "Identify all matched IOCs across all three categories. "
                "End your response with the JSON object."
            )),
        ]

        raw_text = self._call(messages, "IOC Checklists")
        data     = _extract_json(raw_text)

        required = ["availability", "confidentiality", "integrity"]
        if not any(data.get(k) for k in required):
            data = _repair_json(raw_text, required, self.llm)

        # Resolve indices → names and metakeys
        all_metakeys: set[str] = set()
        per_category: dict     = {}
        summary_parts: list    = []

        for cat_key, ioc_list in ALL_IOCS.items():
            cat_data = data.get(cat_key) or {}
            # Same shape drift as the top level: the model sometimes emits
            # the category as a bare list of indices ("availability": [1, 2])
            # instead of the documented object.
            if isinstance(cat_data, list):
                cat_data = {"matched_iocs": cat_data}
            elif not isinstance(cat_data, dict):
                cat_data = {}
            indices = cat_data.get("matched_iocs") or []
            if isinstance(indices, (int, str)):
                indices = re.findall(r"\d+", str(indices))
            reasoning = cat_data.get("reasoning", "")
            if not isinstance(reasoning, str):
                reasoning = str(reasoning or "")
            extra_mkeys = cat_data.get("metakeys") or []
            if isinstance(extra_mkeys, str):
                extra_mkeys = [extra_mkeys]

            matched_names: list[str] = []
            cat_metakeys: set[str]   = set()
            for idx in indices:
                try:
                    entry = ioc_list[int(idx) - 1]
                    matched_names.append(entry["ioc"])
                    cat_metakeys.update(entry["metakeys"])
                except (IndexError, ValueError, TypeError):
                    pass

            all_metakeys.update(cat_metakeys)
            all_metakeys.update(str(m) for m in extra_mkeys)

            per_category[cat_key] = {
                "matched_ioc_names": matched_names,
                "matched_indices":   indices,
                "reasoning":         reasoning,
                "category_metakeys": sorted(cat_metakeys),
            }

            if matched_names:
                summary_parts.append(
                    f"[{cat_key.upper()}] {', '.join(matched_names)}"
                    + (f" — {reasoning}" if reasoning else "")
                )

        total = sum(len(v["matched_ioc_names"]) for v in per_category.values())
        self._emit("phase_complete", "IOC Checklists", f"{total} IOC(s) matched")

        return {
            "per_category":    per_category,
            "all_metakeys":    sorted(all_metakeys),
            "ioc_summary":     "\n".join(summary_parts) if summary_parts else "No IOCs matched.",
            "total_ioc_count": total,
        }

    # ── Phase 2: Risk Rating ──────────────────────────────────────────────────

    def _run_risk(self, incident: dict, ioc_summary: str) -> dict:
        messages = [
            SystemMessage(content=(
                "You are a SOC Risk Analyst. Apply the SOC Risk Rating Methodology. "
                "After your reasoning, output ONLY a single JSON object as your final answer.\n"
                "Final JSON schema:\n"
                '{"likelihood_initiation": "<Critical|High|Medium|Low>",\n'
                ' "likelihood_occurrence": "<Critical|High|Medium|Low>",\n'
                ' "likelihood_adverse_impact": "<Critical|High|Medium|Low>",\n'
                ' "overall_risk": "<Critical|High|Medium|Low>",\n'
                ' "rationale": "<one sentence>"}'
            )),
            HumanMessage(content=(
                f"INCIDENT:\n{json.dumps(incident, indent=2)}\n\n"
                f"IOC FINDINGS:\n{ioc_summary}\n\n"
                f"RATING GUIDANCE:\n{RISK_RATING_GUIDANCE}\n\n"
                "Rate all three dimensions; overall_risk = highest dimension. "
                "End your response with the JSON object."
            )),
        ]

        raw_text = self._call(messages, "Risk Rating")
        data     = _extract_json(raw_text)
        if not data.get("overall_risk"):
            data = _repair_json(
                raw_text,
                ["likelihood_initiation", "likelihood_occurrence",
                 "likelihood_adverse_impact", "overall_risk", "rationale"],
                self.llm,
            )
        self._emit("phase_complete", "Risk Rating",
                   f"Overall risk: {data.get('overall_risk') or '—'}")
        return data

    # ── Phase 3: SOC Classification ───────────────────────────────────────────

    def _run_cls(self, incident: dict, risk_level: str, ioc_summary: str) -> dict:
        messages = [
            SystemMessage(content=(
                "You are a SOC Analyst applying the SOC Classification Template. "
                "After your reasoning, output ONLY a single JSON object as your final answer.\n"
                "Final JSON schema:\n"
                '{"classification": "<Critical|High|Medium|Low>",\n'
                ' "incident_category": "<best matching category>",\n'
                ' "response_time": "<initial response time>",\n'
                ' "summary": "<2-3 sentence triage summary>",\n'
                ' "recommended_actions": ["<action 1>", "<action 2>"]}'
            )),
            HumanMessage(content=(
                f"INCIDENT:\n{json.dumps(incident, indent=2)}\n\n"
                f"RISK RATING RESULT: {risk_level.upper()}\n\n"
                f"IOC FINDINGS:\n{ioc_summary}\n\n"
                f"CLASSIFICATION TABLE:\n{json.dumps(SOC_CLASSIFICATION_TABLE, indent=2)}\n\n"
                "Classify this incident. End your response with the JSON object."
            )),
        ]

        raw_text = self._call(messages, "SOC Classification")
        data     = _extract_json(raw_text)
        if not data.get("classification"):
            data = _repair_json(
                raw_text,
                ["classification", "incident_category",
                 "response_time", "summary", "recommended_actions"],
                self.llm,
            )
        self._emit("phase_complete", "SOC Classification",
                   f"Classification: {data.get('classification') or '—'}")
        return data

    # ── Main entry point ──────────────────────────────────────────────────────

    def triage(self, incident: dict) -> dict:
        inc_id    = str(incident.get("id") or incident.get("incidentId") or "unknown")
        inc_title = incident.get("title") or incident.get("name") or "Untitled"
        timestamp = datetime.utcnow().isoformat()
        inc_time  = _extract_incident_time(incident)
        trace: list[dict] = []

        try:
            # Phase 1 — IOC
            ioc_data = self._run_ioc(incident)
            trace.append({
                "step": "IOC Checklist", "status": "ok",
                "matched_metakeys": ioc_data["all_metakeys"],
                "ioc_summary":      ioc_data["ioc_summary"],
                "total_ioc_count":  ioc_data["total_ioc_count"],
                "per_category":     ioc_data["per_category"],
            })

            # Phase 2 — Risk Rating
            risk_data  = self._run_risk(incident, ioc_data["ioc_summary"])
            risk_level = _normalize_level(risk_data.get("overall_risk"), default="medium")
            trace.append({"step": "Risk Rating", "status": "ok", "data": risk_data})

            # Phase 3 — Classification
            cls_data       = self._run_cls(incident, risk_level, ioc_data["ioc_summary"])
            classification = _normalize_level(cls_data.get("classification"), default=risk_level)
            cls_meta       = SOC_CLASSIFICATION_TABLE[classification]
            trace.append({"step": "SOC Classification", "status": "ok", "data": cls_data})

        except Exception as exc:
            return {
                "error": str(exc),
                "metakeys_payload": {}, "ticket": {}, "trace": trace,
            }

        matched_metakeys = ioc_data["all_metakeys"]

        # Output 1 — meta-key payload
        metakeys_payload = {
            "incident_id":      inc_id,
            "incident_title":   inc_title,
            "timestamp":        timestamp,
            "matched_metakeys": matched_metakeys,
            "metakey_values":   _extract_metakey_values(incident, matched_metakeys),
            "ioc_summary":      ioc_data["ioc_summary"],
            "risk_level":       risk_level,
            "classification":   classification,
        }

        # Output 2 — ticket
        unc    = _next_unc()
        ticket = {
            "unc":             unc,
            "incident_id":     inc_id,
            "title":           inc_title,
            "incident_time":   inc_time,
            "created_at":      timestamp,
            "classification":  classification.upper(),
            "risk_rating": {
                "likelihood_initiation":     risk_data.get("likelihood_initiation") or "—",
                "likelihood_occurrence":     risk_data.get("likelihood_occurrence") or "—",
                "likelihood_adverse_impact": risk_data.get("likelihood_adverse_impact") or "—",
                "overall_risk":              risk_data.get("overall_risk") or "—",
                "rationale":                 risk_data.get("rationale") or "",
            },
            "incident_category":     cls_data.get("incident_category") or "—",
            "initial_response_time": cls_meta["initial_response_time"],
            "summary":               cls_data.get("summary") or "",
            "recommended_actions":   (
                [ra] if isinstance(ra := (cls_data.get("recommended_actions") or []), str)
                else list(ra) if isinstance(ra, (list, tuple)) else []
            ),
            "matched_ioc_count":     ioc_data["total_ioc_count"],
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
# 10. DISPLAY HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def render_triage_trace(trace: list[dict]) -> str:
    lines: list[str] = ["## 🛡️ SOC Triage Report\n"]
    for step in trace:
        name   = step.get("step", "Step")
        status = "✅" if step.get("status") == "ok" else "❌"
        lines.append(f"### {status} Phase — {name}")

        if name == "IOC Checklist":
            count   = step.get("total_ioc_count") or 0
            summary = step.get("ioc_summary") or ""
            mkeys   = step.get("matched_metakeys") or []
            lines.append(f"**Total IOCs matched:** {count}")
            if summary:
                lines.append(f"**Summary:** {summary}")
            if mkeys:
                lines.append(f"**Meta-Keys:** `{'`, `'.join(mkeys)}`")
            for cat, cat_data in (step.get("per_category") or {}).items():
                matched = cat_data.get("matched_ioc_names") or []
                if matched:
                    lines.append(f"- **{cat.capitalize()}:** {', '.join(matched)}")

        elif name == "Risk Rating":
            d = step.get("data") or {}
            lines.extend([
                "| Dimension | Rating |",
                "|-----------|--------|",
                f"| Likelihood of Initiation | **{d.get('likelihood_initiation') or '—'}** |",
                f"| Likelihood of Occurrence | **{d.get('likelihood_occurrence') or '—'}** |",
                f"| Likelihood of Adverse Impact | **{d.get('likelihood_adverse_impact') or '—'}** |",
                f"| **Overall Risk** | **{d.get('overall_risk') or '—'}** |",
            ])
            if d.get("rationale"):
                lines.append(f"\n*{d['rationale']}*")

        elif name == "SOC Classification":
            d   = step.get("data") or {}
            cls = (d.get("classification") or "—").upper()
            lines.append(f"- **Classification:** {cls}")
            lines.append(f"- **Category:** {d.get('incident_category') or '—'}")
            lines.append(f"- **Response Time:** {d.get('response_time') or '—'}")
            if d.get("summary"):
                lines.append(f"- **Summary:** {d['summary']}")
            for a in (d.get("recommended_actions") or []):
                lines.append(f"  - {a}")

        lines.append("")
    return "\n".join(lines)


def format_ticket_display(ticket: dict) -> str:
    rr    = ticket.get("risk_rating") or {}
    unc   = ticket.get("unc") or "—"
    cls   = (ticket.get("classification") or "—").upper()
    icons = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}
    icon  = icons.get(cls, "⚪")
    lines = [
        "---",
        f"## {icon} Ticket `{unc}`",
        "| Field | Value |",
        "|-------|-------|",
        f"| **Incident ID** | `{ticket.get('incident_id') or '—'}` |",
        f"| **Title** | {ticket.get('title') or '—'} |",
        f"| **Incident Time** | {ticket.get('incident_time') or '—'} |",
        f"| **Ticket Created** | {ticket.get('created_at') or '—'} |",
        f"| **Classification** | **{cls}** |",
        f"| **Category** | {ticket.get('incident_category') or '—'} |",
        f"| **Initial Response Time** | {ticket.get('initial_response_time') or '—'} |",
        f"| **IOCs Matched** | {ticket.get('matched_ioc_count', 0)} |",
        "",
        "### Risk Rating",
        "| Dimension | Rating |",
        "|-----------|--------|",
        f"| Initiation | {rr.get('likelihood_initiation') or '—'} |",
        f"| Occurrence | {rr.get('likelihood_occurrence') or '—'} |",
        f"| Adverse Impact | {rr.get('likelihood_adverse_impact') or '—'} |",
        f"| **Overall** | **{rr.get('overall_risk') or '—'}** |",
        "",
        "### Triage Summary",
        ticket.get("summary") or "—",
        "",
        "### Recommended Actions",
    ]
    for a in (ticket.get("recommended_actions") or []):
        lines.append(f"- {a}")
    mkeys = ticket.get("metakeys") or []
    if mkeys:
        lines += ["", "### Matched Meta-Keys",
                  f"`{'`, `'.join(mkeys)}`"]
    return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════════════════
# 11.  TRIAGE TRIGGER & CHAT RESPOND
# ══════════════════════════════════════════════════════════════════════════════

_TRIAGE_TRIGGER = re.compile(
    r"\b(triage|analys[ei]s?|ioc|classify|classification|ticket|investigate)\b",
    re.IGNORECASE,
)


def _build_qa_chain(llm: ChatOpenAI):
    prompt = ChatPromptTemplate.from_messages([
        SystemMessage(content=(
            "You are an expert SOC Analyst. Answer questions concisely and accurately "
            "using IOC analysis, threat intelligence, and security best practices."
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
    cfg = llm_config or CiscoLLMConfig()

    if incident and _TRIAGE_TRIGGER.search(user_msg):
        agent  = TriageAgent(
            cfg                = cfg,
            progress_fn        = progress_fn,
            thinking_container = thinking_container,
        )
        result = agent.triage(incident)

        if result.get("error"):
            return f"❌ Triage error: {result['error']}"

        trace_md  = render_triage_trace(result["trace"])
        ticket_md = format_ticket_display(result["ticket"])
        unc       = result["ticket"].get("unc", "—")
        n_keys    = len(result["metakeys_payload"].get("matched_metakeys", []))

        return (
            trace_md + "\n\n" + ticket_md + "\n\n---\n\n"
            + f"📤 **Meta-key payload queued** ({n_keys} keys)\n\n"
            + f"📋 **Ticket `{unc}` created and queued for ticketing agent.**"
        )

    # Plain Q&A fallback
    llm = build_llm(cfg)
    ctx = ""
    if incident:
        ctx = f"\n\nIncident context:\n{json.dumps(incident, indent=2)[:600]}"
    qa_chain = _build_qa_chain(llm)
    try:
        return qa_chain.invoke({"user_input": user_msg + ctx})
    except Exception as exc:
        return f"⚠️ LLM error: {exc}"