"""
final_verdict.py — post-investigation "final" incident verdict (standalone capstone).

WHAT IT ADDS OVER triage_verdict.py
    triage_verdict.aggregate_verdict() is a TRIAGE-TIME risk *prediction* (base
    severity + asset + IOC + optional TI), computed before investigation. This
    module runs AFTER investigation and asks the next question: did the
    investigation SUBSTANTIATE that prediction? It re-aggregates the triage verdict
    with investigation-side signals to produce a refined verdict PLUS two things the
    triage verdict can't have yet:
      * a **disposition** — Confirmed / Likely TP / Inconclusive / Possible FP
      * a **confidence** — how well the investigation substantiated the risk.

    Investigation-side signals (each optional; missing degrades to "unavailable",
    never a crash):
      * IOC evidence depth   — # of IOCs the investigation surfaced.
      * Response readiness    — whether concrete response/containment actions exist.
      * Diamond completeness  — diamond_model kill-chain characterisation %.
      * MITRE confirmation    — tactic_inference confidence + whether the confirmed
                                tactic is a high-severity ATT&CK tactic.

HONESTY RULES BAKED IN
    * It ESCALATES one band only on strong, corroborated substantiation of a
      high-severity tactic — never jumps to CRITICAL without corroboration.
    * It NEVER silently downgrades risk. A thin investigation ≠ benign, so an
      unsubstantiated elevated incident keeps its level but is flagged LOW
      confidence / "verify (possible false positive)" — decision SUPPORT, not a
      close-out.
    * Standalone: imports+calls existing skills, edits none of them, no agent edits,
      no LLM, no network. Kill switch: NW_DISABLE_FINAL_VERDICT.

PUBLIC API
    build_final_verdict(incident, triage_result=None,
                        investigation_result=None, ti_result=None) -> dict
    format_final_verdict(verdict, compact=False) -> str
"""
from __future__ import annotations

import os
from typing import Any

_BAND_LEVEL = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0}
_LEVEL_BAND = {3: "CRITICAL", 2: "HIGH", 1: "MEDIUM", 0: "LOW"}

# High-severity ATT&CK tactics — confirming one of these substantiates real impact.
_SEVERE_TACTICS = (
    "impact", "exfiltration", "lateral movement", "command and control",
    "privilege escalation", "credential access",
)


def _disabled() -> bool:
    return bool(os.environ.get("NW_DISABLE_FINAL_VERDICT"))


def _s(v: Any) -> str:
    return str(v or "").strip()


def _as_list(v: Any) -> list:
    if v in (None, "", [], {}):
        return []
    return v if isinstance(v, list) else [v]


# ── investigation-side signal collectors (each -> {level 0-3, label, detail} | None)

def _triage_base(incident, triage_result, ti_result) -> dict | None:
    try:
        from triage_verdict import aggregate_verdict
    except Exception:
        return None
    try:
        v = aggregate_verdict(incident, triage_result, ti_result)
    except Exception:
        return None
    if not isinstance(v, dict) or not v.get("available"):
        return None
    return v


def _ioc_evidence(inv: dict) -> dict:
    n = len(_as_list(inv.get("iocs")))
    level = 3 if n >= 3 else (2 if n >= 1 else 0)
    return {"name": "IOC evidence depth", "level": level,
            "label": f"{n} IOC(s) documented" if n else "no IOCs documented",
            "available": bool(inv)}


def _response_readiness(inv: dict) -> dict:
    actions = _as_list(inv.get("recommended_actions"))
    kw = ("contain", "isolat", "remediat", "reset", "block", "quarantine",
          "re-image", "reimage", "eradicat", "recover", "patch")
    strong = any(any(k in _action_text(a) for k in kw) for a in actions)
    level = 3 if strong else (2 if actions else 0)
    return {"name": "response readiness", "level": level,
            "label": (f"{len(actions)} action(s)"
                      + (", incl. containment" if strong else "")) if actions
                     else "no response actions",
            "available": bool(inv)}


def _diamond_signal(incident, triage_result, ti_result) -> dict:
    try:
        from diamond_model import build_diamond
        d = build_diamond(incident, triage_result, ti_result)
    except Exception:
        return {"name": "kill-chain characterisation", "level": 0,
                "label": "unavailable", "available": False}
    if not isinstance(d, dict) or not d.get("available"):
        return {"name": "kill-chain characterisation", "level": 0,
                "label": "unavailable", "available": False}
    pct = int((d.get("stats") or {}).get("completeness_pct", 0))
    level = 3 if pct >= 60 else (2 if pct >= 40 else (1 if pct >= 20 else 0))
    return {"name": "kill-chain characterisation", "level": level,
            "label": f"Diamond model {pct}% complete", "available": True, "pct": pct}


def _mitre_confirmation(incident, triage_result=None, inv=None) -> dict:
    # 1. A tactic already assigned by investigation/triage/the incident is a
    #    CONFIRMED classification (high confidence). Prefer it over inference.
    tactic, conf, src = "", "high", "confirmed"
    for m in _as_list((inv or {}).get("mitre_mapping")):
        tactic = _s(m if not isinstance(m, dict) else (m.get("tactic") or m.get("value")))
        if tactic:
            break
    if not tactic:
        tactic = _s(incident.get("mitre_tactic"))
    if not tactic and triage_result:
        tactic = _s((triage_result.get("metakeys_payload") or {}).get("mitre_tactic")
                    or (triage_result.get("ticket") or {}).get("mitre_tactic"))
    # 2. Fall back to deterministic inference only when nothing is assigned.
    if not tactic:
        try:
            from tactic_inference import infer_tactics
            r = infer_tactics(incident)
        except Exception:
            r = None
        if not isinstance(r, dict) or not r.get("available"):
            return {"name": "MITRE confirmation", "level": 0,
                    "label": "no tactic confirmed", "available": False, "severe": False}
        tactic = _s(r.get("tactic"))
        conf = _s(r.get("confidence")).lower() or "low"
        src = "inferred"
    severe = any(t in tactic.lower() for t in _SEVERE_TACTICS)
    conf_lv = {"high": 3, "medium": 2, "low": 1}.get(conf, 1)
    level = min(3, conf_lv + (1 if severe else 0)) if severe else conf_lv
    return {"name": "MITRE confirmation", "level": level, "available": True,
            "severe": severe,
            "label": f"{tactic} ({conf} confidence"
                     + (", high-severity tactic" if severe else "") + f", {src})"}


def _action_text(a: Any) -> str:
    if isinstance(a, dict):
        return " ".join(_s(a.get(k)) for k in
                        ("recommendation", "action", "rationale", "risk_addressed")).lower()
    return _s(a).lower()


# ── main aggregation ──────────────────────────────────────────────────────────

_ACTIONS = {
    ("CRITICAL", True):  "Declare incident — Tier 2/3 containment now",
    ("HIGH", True):      "Contain & remediate per playbook (Tier 1)",
    ("MEDIUM", True):    "Standard investigation queue — proceed to remediation",
    ("LOW", True):       "Monitor / low-priority queue",
    ("CRITICAL", False): "Treat as critical until cleared — gather corroborating evidence urgently",
    ("HIGH", False):     "Re-verify detection & gather more evidence before closing",
    ("MEDIUM", False):   "Collect additional evidence; likely low impact",
    ("LOW", False):      "Monitor / candidate for closure after review",
}


def build_final_verdict(incident: dict, triage_result: dict | None = None,
                        investigation_result: dict | None = None,
                        ti_result: dict | None = None) -> dict:
    """Post-investigation verdict. Returns {"available": bool, ...}; never raises.
    Requires an investigation_result with some substance, else available=False."""
    if _disabled():
        return {"available": False, "reason": "disabled via NW_DISABLE_FINAL_VERDICT"}
    try:
        return _build(incident or {}, triage_result, investigation_result or {}, ti_result)
    except Exception as exc:
        return {"available": False, "reason": f"error: {type(exc).__name__}"}


def _build(incident, triage_result, inv, ti_result) -> dict:
    # only meaningful after an investigation actually produced something
    has_investigation = bool(
        _as_list(inv.get("iocs")) or _as_list(inv.get("recommended_actions"))
        or _s(inv.get("investigation_summary")) or _s(inv.get("summary"))
        or _s(inv.get("status")).lower() == "completed")
    base = _triage_base(incident, triage_result, ti_result)
    if not has_investigation and not base:
        return {"available": False, "reason": "no investigation result and no triage verdict"}

    triage_level = _BAND_LEVEL.get((base or {}).get("level", "LOW"), 0)
    triage_band = (base or {}).get("level", "LOW")

    # investigation-side substantiation signals
    ioc = _ioc_evidence(inv)
    resp = _response_readiness(inv)
    diamond = _diamond_signal(incident, triage_result, ti_result)
    mitre = _mitre_confirmation(incident, triage_result, inv)
    inv_signals = [ioc, resp, diamond, mitre]
    scored = [s for s in inv_signals if s.get("available")]
    levels = [s["level"] for s in scored]
    max_inv = max(levels) if levels else 0
    count_ge2 = sum(1 for lv in levels if lv >= 2)

    # substantiation band 0-3 (None/Low/Medium/High)
    if max_inv >= 3 and count_ge2 >= 2:
        subst = 3
    elif max_inv >= 2 and count_ge2 >= 1:
        subst = 2
    elif max_inv >= 1:
        subst = 1
    else:
        subst = 0

    # corroboration = the triage verdict already had ≥2 strong signals or IOC/case hits
    corroborated = bool(base and (base.get("stats", {}).get("corroborating_strong", 0) >= 1))
    severe_confirmed = mitre.get("available") and mitre.get("severe") and mitre["level"] >= 3

    # refined level: escalate ONE band only on strong, corroborated severe-tactic
    # substantiation; otherwise hold the triage level (never silently downgrade).
    refined_level = triage_level
    delta = "unchanged"
    if subst >= 3 and severe_confirmed and (corroborated or count_ge2 >= 2):
        refined_level = min(3, triage_level + 1)
        delta = "escalated" if refined_level > triage_level else "confirmed"
    elif subst >= 2:
        delta = "confirmed"
    elif subst == 0 and triage_level >= 2:
        delta = "held (low confidence)"

    refined_band = _LEVEL_BAND[refined_level]
    substantiated = subst >= 2

    # disposition
    if subst >= 3:
        disposition = "Confirmed — True Positive"
    elif subst == 2:
        disposition = "Likely True Positive"
    elif subst == 1:
        disposition = "Inconclusive — partial substantiation"
    else:
        disposition = ("Unsubstantiated — verify (possible false positive)"
                       if triage_level >= 2 else "No adverse findings")

    confidence = {3: "High", 2: "Medium", 1: "Low", 0: "Low"}[subst]
    priority = {3: 1, 2: 2, 1: 3, 0: 4}[refined_level]
    action = _ACTIONS[(refined_band, substantiated)]

    rationale = sorted([s for s in scored if s["level"] > 0], key=lambda s: -s["level"])
    missing = [s["name"] for s in inv_signals if not s.get("available")]

    return {
        "available": True,
        "stage": "post-investigation",
        "level": refined_band,
        "priority": priority,
        "disposition": disposition,
        "confidence": confidence,
        "action": action,
        "delta": delta,
        "triage_verdict": {"level": triage_band, "priority": (base or {}).get("priority")},
        "signals": inv_signals,
        "rationale": rationale or [{"name": "no substantiating signals", "level": 0, "label": ""}],
        "missing": missing,
        "stats": {"substantiation": subst, "scored_signals": len(scored),
                  "max_inv_level": max_inv, "corroborated": corroborated},
    }


# ── rendering ─────────────────────────────────────────────────────────────────

def format_final_verdict(v: dict | None, compact: bool = False) -> str:
    """Markdown headline section for the report / Map panel."""
    if not v or not v.get("available"):
        return ""
    lines = ["## Final Incident Verdict (post-investigation)"]
    if not compact:
        lines.append("_Refines the triage-time verdict with investigation "
                     "substantiation. Decision support — does not close the incident._")
    tv = v.get("triage_verdict") or {}
    delta_note = {
        "escalated": f" (⬆ escalated from triage {tv.get('level')})",
        "confirmed": f" (confirmed triage {tv.get('level')})",
        "held (low confidence)": f" (held at triage {tv.get('level')} — low confidence)",
        "unchanged": "",
    }.get(v.get("delta"), "")
    lines.append(f"**{v['level']}** · **{v['disposition']}** · confidence **{v['confidence']}** "
                 f"· priority {v['priority']}/5{delta_note}")
    lines.append(f"- **Next action:** {v['action']}")
    drivers = [f"{s['name']} ({s['label']})" for s in v.get("rationale") or []
               if s.get("level", 0) > 0]
    if drivers:
        lines.append(f"- **Substantiated by:** {', '.join(drivers)}")
    if v.get("missing"):
        lines.append(f"- **Signals unavailable:** {', '.join(v['missing'])}")
    return "\n".join(lines)


if __name__ == "__main__":  # pragma: no cover — manual smoke test
    import json
    inc = {"id": "INC-53018", "title": "Malicious HTA + Potential C2 for KELLYWANG",
           "severity": "High", "mitre_tactic": "Command and Control",
           "alertMeta": {"AlertTitles": ["Malicious HTA file detected", "Potential C2 Connection"]}}
    tri = {"metakeys_payload": {"classification": "high", "mitre_tactic": "Command and Control"},
           "ticket": {"classification": "High", "incident_category": "Compromised asset", "unc": "#EVAL"}}
    inv = {"status": "completed",
           "iocs": [{"value": "192.168.10.204"}, {"value": "evil.example.com"}, {"value": "hta.dll"}],
           "recommended_actions": [{"recommendation": "Isolate KELLYWANG and reset credentials"}],
           "investigation_summary": "Endpoint executed a malicious HTA reaching a C2 host."}
    v = build_final_verdict(inc, tri, inv)
    print(json.dumps({k: v[k] for k in ("level", "disposition", "confidence", "delta", "priority")}, indent=2))
    print()
    print(format_final_verdict(v))
