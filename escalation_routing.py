"""
escalation_routing.py — deterministic escalation routing (tier + owner + queue)
derived from the SOC response priority (P1–P4).

WHY THIS EXISTS
    triage_priority.py answers "how urgent is this?" (P1–P4 + SLA). It does not
    answer "who picks it up and who gets told?". In a real SOC those are separate,
    deterministic questions: a P1 is worked by senior Incident Response and paged
    to the SOC Manager/CISO; a P4 sits in the Tier-1 batch queue. This module maps
    the P-level to a concrete routing decision — tier, owning role, work queue,
    acknowledge-SLA, and the notify/escalation chain — so the analyst never has to
    guess assignment.

DESIGN
    Everything here is deterministic code (no LLM, no network). Routing is a clean
    function of the P-level, because the P-level *already* folded in severity, asset
    criticality, data sensitivity, blast radius and threat state (see
    triage_priority.build_priority). We therefore do NOT re-score those here — that
    would double-count. Instead we add cross-functional *notify overlays* on top of
    the P-derived tier:

      * regulated data (PCI/PHI) in scope  -> loop in Compliance / Privacy
      * crown-jewel / critical asset       -> loop in the Asset / Business Owner
      * active (confirmed) threat on P1/P2  -> page the IR on-call immediately

    Overlays only ADD notify parties / actions — they never lower the tier.

    Routing is an ANNOTATION beside the code-pinned triage classification. It sets
    workflow assignment; it never rewrites the classification.

REUSE
    If a priority bundle (from triage_priority.build_priority) is passed in, it is
    used directly. Otherwise this module computes it, and if even that is
    unavailable it falls back to a severity->P mapping so routing is always defined.

Kill switch: NW_DISABLE_ESCALATION_ROUTING=1 -> build_escalation() returns
{"available": False}.
"""
from __future__ import annotations

import os
from typing import Any

# ── P-level -> routing table ─────────────────────────────────────────────────
# tier: SOC analyst tier (1 triage/monitor · 2 investigation · 3 senior IR/hunt).
# Base notify list is the *always* chain for that P-level; overlays add to it.
_ROUTING: dict[str, dict] = {
    "P1": {
        "tier": 3,
        "tier_label": "Tier 3 — Incident Response / Senior Analyst",
        "owner": "Incident Response Lead",
        "queue": "IR-CRITICAL",
        "ack_sla": "15 minutes",
        "major_incident": True,
        "notify": ["SOC Manager", "CISO"],
    },
    "P2": {
        "tier": 2,
        "tier_label": "Tier 2 — Investigation",
        "owner": "Tier 2 Investigator",
        "queue": "SOC-TIER2",
        "ack_sla": "1 hour",
        "major_incident": False,
        "notify": ["SOC Shift Lead"],
    },
    "P3": {
        "tier": 1,
        "tier_label": "Tier 1 — Triage / Monitoring",
        "owner": "Tier 1 Analyst",
        "queue": "SOC-TIER1",
        "ack_sla": "4 hours",
        "major_incident": False,
        # P3 is worked at Tier 1 but has a documented hand-up to Tier 2.
        "notify": [],
        "escalate_to": "Tier 2 Investigator (on need)",
    },
    "P4": {
        "tier": 1,
        "tier_label": "Tier 1 — Triage / Monitoring",
        "owner": "Tier 1 Analyst",
        "queue": "SOC-BATCH",
        "ack_sla": "24 hours",
        "major_incident": False,
        "notify": [],
    },
}

_SEV_TO_P = {"critical": "P1", "high": "P2", "medium": "P3",
             "low": "P4", "info": "P4", "informational": "P4"}


def _sev_level(incident: dict, triage_result: dict | None) -> str:
    """Best-effort lower-case severity. Reuses triage_priority's resolver when
    importable (single source of truth); otherwise a local fallback."""
    try:
        from triage_priority import _sev_level as _tp_sev
        return _tp_sev(incident, triage_result)
    except Exception:
        cls = None
        if isinstance(triage_result, dict):
            cls = (triage_result.get("ticket") or {}).get("classification")
        s = str(cls or incident.get("severity") or "medium").strip().lower()
        return s if s in _SEV_TO_P else "medium"


def _resolve_priority(incident: dict, triage_result: dict | None,
                      ti_result: dict | None, asset_result: dict | None,
                      priority_result: dict | None) -> dict:
    """Return a priority bundle: {priority: 'P1'..'P4', ...}. Prefers a passed-in
    bundle, then triage_priority.build_priority, then a severity->P fallback.
    Never raises."""
    if (isinstance(priority_result, dict) and priority_result.get("available")
            and priority_result.get("priority") in _ROUTING):
        return priority_result
    try:
        from triage_priority import build_priority
        p = build_priority(incident, triage_result, ti_result, asset_result)
        if isinstance(p, dict) and p.get("available") and p.get("priority") in _ROUTING:
            return p
    except Exception:
        pass
    # fallback — derive P from severity so routing is always defined
    sev = _sev_level(incident, triage_result)
    return {"priority": _SEV_TO_P.get(sev, "P3"), "severity": sev.upper(),
            "data_sensitivity": [], "regulated": False,
            "threat_state": "suspected", "drivers": [], "_fallback": True}


def _critical_asset(priority: dict, asset_result: dict | None) -> bool:
    """True when a crown-jewel / critical asset is in scope. Reads the asset
    driver from the priority bundle first, else the asset_criticality result."""
    for d in priority.get("drivers") or []:
        if d.get("factor") == "Asset criticality" and int(d.get("points") or 0) >= 2:
            return True
    if isinstance(asset_result, dict):
        try:
            if int(asset_result.get("highest_rank") or 0) >= 3:
                return True
        except (TypeError, ValueError):
            pass
    return False


def build_escalation(incident: dict, triage_result: dict | None = None,
                     ti_result: dict | None = None,
                     asset_result: dict | None = None,
                     priority_result: dict | None = None) -> dict:
    """Deterministic escalation routing for one incident. Never raises; returns
    {"available": False, ...} when disabled."""
    if os.environ.get("NW_DISABLE_ESCALATION_ROUTING"):
        return {"available": False,
                "reason": "disabled via NW_DISABLE_ESCALATION_ROUTING"}
    incident = incident or {}

    priority = _resolve_priority(incident, triage_result, ti_result,
                                 asset_result, priority_result)
    p_level = priority.get("priority", "P3")
    route = dict(_ROUTING.get(p_level, _ROUTING["P3"]))

    notify: list[str] = list(route.get("notify") or [])
    conditionals: list[dict] = []

    # ── notify overlays (add cross-functional stakeholders; never lower tier) ──
    classes = priority.get("data_sensitivity") or []
    if priority.get("regulated") or any(c in ("PCI", "PHI") for c in classes):
        if "Compliance / Privacy Officer" not in notify:
            notify.append("Compliance / Privacy Officer")
        conditionals.append({
            "trigger": f"Regulated data in scope ({', '.join(classes) or 'PCI/PHI'})",
            "action": "Engage Compliance / Privacy to assess breach-notification "
                      "obligations before closure.",
        })
    elif "PII" in classes:
        conditionals.append({
            "trigger": "PII in scope",
            "action": "Flag for data-handling review; confirm no regulated "
                      "subset before closure.",
        })

    if _critical_asset(priority, asset_result):
        if "Asset / Business Owner" not in notify:
            notify.append("Asset / Business Owner")
        conditionals.append({
            "trigger": "Critical / crown-jewel asset affected",
            "action": "Notify the Asset / Business Owner and confirm containment "
                      "impact with them.",
        })

    if (priority.get("threat_state") == "active"
            and route["tier"] >= 2):
        conditionals.append({
            "trigger": "Active (confirmed) threat",
            "action": "Page the IR on-call immediately — do not wait for the "
                      "ack-SLA window.",
        })

    # ── escalation path: owner up the chain (tier label -> owner -> notify) ────
    path: list[str] = [route["tier_label"], route["owner"]]
    if route.get("escalate_to"):
        path.append(route["escalate_to"])
    for n in notify:
        if n not in path:
            path.append(n)

    reg = " (regulated data)" if priority.get("regulated") else ""
    rationale = (f"{p_level} routes to {route['tier_label'].split(' — ')[0]} "
                 f"(owner: {route['owner']}, queue {route['queue']}, "
                 f"acknowledge within {route['ack_sla']}){reg}."
                 + (f" Overlays: {len(conditionals)} cross-functional trigger(s)."
                    if conditionals else ""))

    return {
        "available": True,
        "priority": p_level,
        "tier": route["tier"],
        "tier_label": route["tier_label"],
        "owner": route["owner"],
        "queue": route["queue"],
        "ack_sla": route["ack_sla"],
        "major_incident": bool(route.get("major_incident")),
        "escalate_to": route.get("escalate_to"),
        "notify": notify,
        "escalation_path": path,
        "conditionals": conditionals,
        "rationale": rationale,
        "priority_source": "fallback(severity)" if priority.get("_fallback")
                           else "triage_priority",
        "note": ("Routing is an annotation for workflow assignment — it sets tier "
                 "and owner, it does not change the triage classification."),
    }


def format_escalation(e: dict, compact: bool = False) -> str:
    """Markdown block for the written report / analyst view."""
    if not e or not e.get("available"):
        return ""
    head = (f"### Escalation Routing — **{e['tier_label']}**"
            + ("  ·  **major incident**" if e.get("major_incident") else ""))
    if compact:
        line = (f"{head}\n- Owner **{e['owner']}** · queue `{e['queue']}` · "
                f"ack within {e['ack_sla']}.")
        if e.get("notify"):
            line += f" Notify: {', '.join(e['notify'])}."
        return line
    lines = [head,
             f"- Owner: **{e['owner']}**  ·  queue `{e['queue']}`  ·  "
             f"acknowledge within **{e['ack_sla']}**"]
    if e.get("major_incident"):
        lines.append("- **Major-incident handling** — activate the IR process.")
    if e.get("escalate_to"):
        lines.append(f"- Hand-up path: escalate to {e['escalate_to']} if scope grows.")
    if e.get("notify"):
        lines.append(f"- Notify: {', '.join(e['notify'])}")
    if e.get("escalation_path"):
        lines.append(f"- Escalation path: {' → '.join(e['escalation_path'])}")
    for c in e.get("conditionals") or []:
        lines.append(f"    · {c['trigger']}: {c['action']}")
    lines.append(f"- _{e['note']}_")
    return "\n".join(lines)


if __name__ == "__main__":  # pragma: no cover — quick manual smoke test
    import json
    import sys
    try:  # legacy Windows console is cp1252; the report itself is always UTF-8
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
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
    e = build_escalation(demo, triage_result={"ticket": {"classification": "High"}})
    print(json.dumps(e, indent=2))
    print("\n" + format_escalation(e))
    print("\n--- kill switch ---")
    os.environ["NW_DISABLE_ESCALATION_ROUTING"] = "1"
    print(build_escalation(demo))
    del os.environ["NW_DISABLE_ESCALATION_ROUTING"]
