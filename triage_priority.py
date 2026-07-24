"""
triage_priority.py — deterministic P1–P4 priority matrix for SOC triage.

Adapted from the "Security Incident Triage Playbook" pattern (mukul975) +
SANS/NIST triage practice: an incident's *priority* is a distinct dimension
from its *severity*. Two HIGH-severity alerts are not equal — one on a
domain controller touching cardholder data across 40 endpoints is P1; one on
a single workstation with no regulated data is P3. This module scores that.

Everything here is deterministic code (no LLM, no network). It combines four
playbook dimensions into a single P1–P4 with an SLA response window:

  1. base severity            — CRITICAL/HIGH/MEDIUM/LOW (from triage/incident)
  2. asset criticality        — reuses asset_criticality.assess_incident()
  3. data sensitivity         — regex/keyword scan for PCI / PHI / PII markers
                                (regulated data raises priority + drives the
                                compliance angle; ties into the SOC-2 work)
  4. blast radius             — distinct affected hosts / users / source IPs
  5. threat state             — active/confirmed vs suspected (severity + verdict)

The four are weighted into a score, mapped to P1–P4, and returned with the
per-driver breakdown so the analyst sees WHY (never a black box). Priority is
an ANNOTATION beside the code-pinned triage classification — it never rewrites
the classification.

Kill switch: NW_DISABLE_TRIAGE_PRIORITY=1 → build_priority() returns
{"available": False}.
"""
from __future__ import annotations

import os
import re
from typing import Any

# ── data-sensitivity signatures (regulated-data markers) ─────────────────────
# Word-boundary keyword sets + a couple of high-signal value regexes. Kept
# conservative so we flag on genuine markers, not incidental words.
_PCI_KW = re.compile(
    r"\b(pci([ -]?dss)?|cardholder|card\s*holder|credit[ -]?card|debit[ -]?card|"
    r"\bpan\b|primary\s+account\s+number|payment|pos\s+(system|terminal)|"
    r"card\s*data|magstripe|track\s*[12]\s*data)\b", re.I)
_PHI_KW = re.compile(
    r"\b(phi|hipaa|patient|medical\s+record|health\s+record|ehr|emr|clinical|"
    r"diagnos(is|es|tic)|prescription|healthcare|protected\s+health)\b", re.I)
_PII_KW = re.compile(
    r"\b(pii|personally\s+identifiable|social\s+security|ssn|passport|"
    r"driver'?s?\s+licen[cs]e|date\s+of\s+birth|\bdob\b|gdpr|personal\s+data|"
    r"national\s+id)\b", re.I)
# value regexes (US SSN / 13-16 digit card-like) — matched against alert text
_SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_CARD_RE = re.compile(r"\b(?:\d[ -]?){13,16}\b")

_SEV_SCORE = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 1,
              "informational": 1}

# priority thresholds on the combined score
_P_SLA = {
    "P1": "15 minutes — critical response",
    "P2": "1 hour — urgent",
    "P3": "4 hours — standard",
    "P4": "24 hours — routine / batch",
}


def _as_list(v: Any) -> list:
    if v in (None, "", [], {}):
        return []
    return v if isinstance(v, list) else [v]


def _sev_level(incident: dict, triage_result: dict | None) -> str:
    """Best-effort severity string (lower-case) from the triage result first,
    then the incident. Deterministic, never raises."""
    cls = None
    if isinstance(triage_result, dict):
        cls = ((triage_result.get("ticket") or {}).get("classification")
               or (triage_result.get("metakeys_payload") or {}).get("risk_level"))
    cls = cls or incident.get("severity") or incident.get("riskLevel")
    s = str(cls or "").strip().lower()
    if s in _SEV_SCORE:
        return s
    # numeric riskScore fallback (NetWitness 0-100)
    try:
        rs = float(incident.get("riskScore") or incident.get("risk_score") or 0)
        if rs >= 75:
            return "critical"
        if rs >= 50:
            return "high"
        if rs >= 25:
            return "medium"
        if rs > 0:
            return "low"
    except (TypeError, ValueError):
        pass
    return "medium"   # honest neutral default


def _incident_text(incident: dict) -> str:
    """Concatenate the human-readable fields a data-sensitivity scan should see."""
    parts: list[str] = [str(incident.get("title") or ""),
                        str(incident.get("summary") or ""),
                        str(incident.get("name") or "")]
    meta = incident.get("alertMeta") or {}
    for k in ("AlertTitles", "Category", "Description"):
        parts.extend(str(x) for x in _as_list(meta.get(k)))
    for a in _as_list(incident.get("alerts")):
        if isinstance(a, dict):
            parts.append(str(a.get("title") or a.get("name") or ""))
        else:
            parts.append(str(a))
    return " \n ".join(p for p in parts if p)


def _data_sensitivity(incident: dict) -> dict:
    """Scan for regulated-data markers → {classes: [...], score, matched}."""
    text = _incident_text(incident)
    classes: list[str] = []
    matched: list[str] = []
    if _PCI_KW.search(text) or _CARD_RE.search(text):
        classes.append("PCI")
        matched.append("cardholder/payment-data markers")
    if _PHI_KW.search(text):
        classes.append("PHI")
        matched.append("protected-health markers")
    if _PII_KW.search(text) or _SSN_RE.search(text):
        classes.append("PII")
        matched.append("personal-identifier markers")
    # score: regulated (PCI/PHI) weigh more than PII
    score = 0
    if "PCI" in classes or "PHI" in classes:
        score = 2
    elif "PII" in classes:
        score = 1
    return {"classes": classes, "score": score, "matched": matched}


def _blast_radius(incident: dict) -> dict:
    """Distinct affected hosts/users/source-IPs → {count, hosts, users, score}."""
    meta = incident.get("alertMeta") or {}
    hosts = {str(h).strip().upper() for h in _as_list(meta.get("Hostname"))
             + _as_list(incident.get("hostname")) if str(h).strip()}
    users = {str(u).strip().upper() for u in _as_list(meta.get("User"))
             if str(u).strip()}
    ips = {str(i).strip() for i in _as_list(meta.get("SourceIp"))
           + _as_list(meta.get("DestinationIp")) if str(i).strip()}
    distinct = len(hosts) + len(users) + len(ips)
    # alertCount is a useful proxy when metakeys are sparse
    try:
        n_alerts = int(incident.get("alertCount") or incident.get("numAlerts") or 0)
    except (TypeError, ValueError):
        n_alerts = 0
    count = max(distinct, min(n_alerts, 50))   # cap alert-count proxy
    if count >= 10:
        score = 2
    elif count >= 2:
        score = 1
    else:
        score = 0
    return {"count": count, "hosts": len(hosts), "users": len(users),
            "ips": len(ips), "alerts": n_alerts, "score": score}


def _threat_state(incident: dict, triage_result: dict | None,
                  ti_result: dict | None) -> dict:
    """Active/confirmed vs suspected → {state, score}. 'Active' when triage
    confirmed a tactic, external TI corroborated, or severity is critical."""
    active = False
    why = []
    if isinstance(triage_result, dict):
        mk = triage_result.get("metakeys_payload") or {}
        if mk.get("confirmed_tactic") or mk.get("mitre_tactic"):
            active = True
            why.append("triage confirmed a MITRE tactic")
    if isinstance(ti_result, dict) and ti_result.get("available"):
        if ti_result.get("malicious") or ti_result.get("known_bad"):
            active = True
            why.append("external threat intel flagged known-bad")
    if _sev_level(incident, triage_result) == "critical":
        active = True
        why.append("critical severity")
    return {"state": "active" if active else "suspected",
            "score": 1 if active else 0, "why": why}


def build_priority(incident: dict, triage_result: dict | None = None,
                   ti_result: dict | None = None,
                   asset_result: dict | None = None) -> dict:
    """Deterministic P1–P4 priority for one incident. Never raises; returns
    {"available": False, ...} when disabled."""
    if os.environ.get("NW_DISABLE_TRIAGE_PRIORITY"):
        return {"available": False, "reason": "disabled via NW_DISABLE_TRIAGE_PRIORITY"}
    incident = incident or {}

    sev = _sev_level(incident, triage_result)
    sev_score = _SEV_SCORE.get(sev, 2)

    # asset criticality — reuse the existing skill; fall back gracefully
    ac_rank = 0
    ac_tier = "unclassified"
    if isinstance(asset_result, dict) and "highest_rank" in asset_result:
        ac_rank = int(asset_result.get("highest_rank") or 0)
        ac_tier = asset_result.get("highest_tier") or "unclassified"
    else:
        try:
            from asset_criticality import assess_incident
            cls = ((triage_result or {}).get("ticket") or {}).get("classification")
            a = assess_incident(incident, cls)
            if isinstance(a, dict):
                ac_rank = int(a.get("highest_rank") or 0)
                ac_tier = a.get("highest_tier") or "unclassified"
        except Exception:
            pass
    ac_score = {3: 2, 2: 1}.get(ac_rank, 0)

    sens = _data_sensitivity(incident)
    blast = _blast_radius(incident)
    threat = _threat_state(incident, triage_result, ti_result)

    total = sev_score + ac_score + sens["score"] + blast["score"] + threat["score"]
    # max = 4 + 2 + 2 + 2 + 1 = 11
    if total >= 8:
        priority = "P1"
    elif total >= 6:
        priority = "P2"
    elif total >= 4:
        priority = "P3"
    else:
        priority = "P4"

    drivers = [
        {"factor": "Base severity", "value": sev.upper(), "points": sev_score},
        {"factor": "Asset criticality",
         "value": ac_tier.replace("_", " "), "points": ac_score},
        {"factor": "Data sensitivity",
         "value": ", ".join(sens["classes"]) or "none detected",
         "points": sens["score"]},
        {"factor": "Blast radius",
         "value": f"{blast['count']} affected entity(ies)", "points": blast["score"]},
        {"factor": "Threat state", "value": threat["state"],
         "points": threat["score"]},
    ]
    rationale = "; ".join(f"{d['factor']}: {d['value']} (+{d['points']})"
                          for d in drivers if d["points"] > 0) or \
                "low signal across all factors"

    return {
        "available": True,
        "priority": priority,
        "score": total,
        "max_score": 11,
        "sla": _P_SLA[priority],
        "severity": sev.upper(),
        "data_sensitivity": sens["classes"],
        "regulated": bool(sens["score"] >= 2),
        "blast_radius": blast["count"],
        "threat_state": threat["state"],
        "drivers": drivers,
        "rationale": rationale,
        "note": ("Priority is an annotation for response ordering — it does not "
                 "change the triage classification."),
    }


def format_priority(p: dict, compact: bool = False) -> str:
    """Markdown block for the written report / analyst view."""
    if not p or not p.get("available"):
        return ""
    reg = " · **regulated data**" if p.get("regulated") else ""
    head = (f"### Response Priority — **{p['priority']}** "
            f"(SLA: {p['sla']}){reg}")
    if compact:
        return (head + f"\n- {p['rationale']} "
                f"(score {p['score']}/{p['max_score']}).")
    lines = [head,
             f"- Score **{p['score']}/{p['max_score']}** · severity "
             f"{p['severity']} · threat {p['threat_state']} · "
             f"{p['blast_radius']} affected entity(ies)"]
    if p.get("data_sensitivity"):
        lines.append(f"- Data sensitivity: **{', '.join(p['data_sensitivity'])}** "
                     "in scope")
    lines.append("- Priority drivers:")
    for d in p["drivers"]:
        lines.append(f"    · {d['factor']}: {d['value']} (+{d['points']})")
    lines.append(f"- _{p['note']}_")
    return "\n".join(lines)


if __name__ == "__main__":  # pragma: no cover — quick manual smoke test
    import json
    demo = {
        "id": "INC-53018", "title": "High Risk Alerts for DC01",
        "severity": "High", "alertCount": 12,
        "summary": "Suspicious access to cardholder data store; possible PCI exposure.",
        "alertMeta": {
            "Hostname": ["DC01", "FILESERV02"], "User": ["kelly.wang", "admin"],
            "SourceIp": ["10.0.0.5", "10.0.0.6"],
            "AlertTitles": ["Malicious HTA", "Access to payment card database"],
        },
    }
    p = build_priority(demo, triage_result={"ticket": {"classification": "High"}})
    print(json.dumps(p, indent=2))
    print("\n" + format_priority(p))
