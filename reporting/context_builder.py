
from datetime import datetime, timezone, timedelta
from typing import Any

from reporting.schema_normaliser import (
    first_present,
    get_nested,
    to_list,
    normalise_severity,
    normalise_confidence,
    normalise_asset,
    normalise_user,
    normalise_evidence,
    normalise_action,
    combine_iocs,
    yes_no,
)
from reporting.report_validator import validate_required_fields, build_missing_field_gaps
from reporting.rag_context import retrieve_reporting_context
from reporting.llm_narrative import enhance_narrative

SG_TZ = timezone(timedelta(hours=8))


def now_sg_iso() -> str:
    return datetime.now(SG_TZ).isoformat(timespec="seconds")


def humanise_status(value: Any) -> str:
    if value in [None, "", [], {}, "Not Provided"]:
        return "Not Provided"

    text = str(value).strip()
    mapping = {
        "pending": "Pending Analyst Decision",
        "pending_approval": "Pending Approval",
        "approved": "Approved",
        "rejected": "Rejected",
        "not_required": "Not Required",
        "recommended": "Recommended",
        "executed": "Executed",
        "success": "Success",
        "failed": "Failed",
        "ready_for_analyst_review": "Ready for Analyst Review",
        "missing_information_required": "Missing Information Required",
    }
    return mapping.get(text.lower(), text.replace("_", " ").title())


def infer_scenario(likely_scenario: str) -> str:
    text = str(likely_scenario).lower()
    if "phish" in text or "email" in text or "attachment" in text:
        return "phishing"
    if "credential" in text or "oauth" in text or "login" in text:
        return "credential_theft"
    if "ransom" in text or "encrypt" in text:
        return "ransomware"
    if "malware" in text:
        return "malware"
    return "generic_security_incident"


def _contains_any(text: str, terms: list[str]) -> bool:
    lower = str(text).lower()
    return any(term in lower for term in terms)


def _evidence_refs_by_terms(evidence: list[dict[str, Any]], terms: list[str]) -> list[str]:
    refs = []
    for item in evidence:
        searchable = " ".join([
            str(item.get("source", "")),
            str(item.get("type", "")),
            str(item.get("description", "")),
            str(item.get("raw_reference", "")),
        ])
        if _contains_any(searchable, terms):
            refs.append(item.get("id", "UNKNOWN"))
    return refs


def _timeline_refs_by_terms(timeline: list[dict[str, Any]], terms: list[str]) -> list[str]:
    refs = []
    for event in timeline:
        searchable = " ".join([
            str(event.get("event", "")),
            str(event.get("description", "")),
            str(event.get("source", "")),
        ])
        if _contains_any(searchable, terms):
            refs.extend(event.get("evidence_refs", []))
    return list(dict.fromkeys(refs))


def _all_evidence_refs(context: dict[str, Any]) -> list[str]:
    return [item.get("id", "UNKNOWN") for item in context.get("evidence", [])]


def link_iocs_to_evidence(context: dict[str, Any]) -> None:
    """Best-effort IOC evidence linking.

    The function does not create new facts. It only links existing IOCs to existing
    evidence where a direct or conservative source-based relationship exists.
    """

    evidence = context.get("evidence", [])
    timeline = context.get("timeline", [])
    threat_refs = _evidence_refs_by_terms(evidence, ["threat", "intelligence", "reputation", "ioc", "hash", "domain", "url"])
    email_refs = _evidence_refs_by_terms(evidence, ["email", "gateway", "attachment", "phish"])
    network_refs = _evidence_refs_by_terms(evidence, ["network", "netwitness", "connection", "ip", "dns", "url", "domain"])

    for ioc in context.get("iocs", []):
        if ioc.get("evidence_refs"):
            continue

        value = str(ioc.get("value", ""))
        ioc_type = str(ioc.get("type", "")).lower()
        direct_refs = []

        for item in evidence:
            blob = " ".join(str(v) for v in item.values())
            if value and value in blob:
                direct_refs.append(item.get("id", "UNKNOWN"))

        for event in timeline:
            blob = " ".join(str(v) for v in event.values())
            if value and value in blob:
                direct_refs.extend(event.get("evidence_refs", []))

        if direct_refs:
            ioc["evidence_refs"] = list(dict.fromkeys(direct_refs))
        elif ioc_type in ["domain", "url", "file hash"]:
            ioc["evidence_refs"] = list(dict.fromkeys(threat_refs + email_refs))
        elif ioc_type == "ip address":
            ioc["evidence_refs"] = list(dict.fromkeys(network_refs + threat_refs))
        else:
            ioc["evidence_refs"] = threat_refs

        if not ioc["evidence_refs"]:
            ioc["evidence_refs"] = ["Not linked"]


def add_phishing_evidence_gaps(context: dict[str, Any]) -> None:
    if context.get("scenario_type") != "phishing":
        return

    existing = " ".join(str(gap) for gap in context.get("evidence_gaps", [])).lower()
    recommended_gaps = [
        {
            "priority": "High",
            "gap": "Confirm whether the user clicked the link, opened the attachment, or enabled macros.",
            "required_data": "Email gateway click logs, endpoint file open events, Office telemetry, macro execution logs.",
        },
        {
            "priority": "High",
            "gap": "Confirm whether credentials, tokens, mailbox rules, or OAuth grants were abused.",
            "required_data": "Identity provider logs, MFA logs, mailbox audit logs, inbox rule changes, OAuth consent logs.",
        },
        {
            "priority": "Medium",
            "gap": "Confirm whether similar phishing emails were delivered to other recipients.",
            "required_data": "Email gateway search by sender, subject, URL, attachment hash, and campaign indicators.",
        },
        {
            "priority": "Medium",
            "gap": "Confirm whether data exfiltration or sensitive mailbox access occurred.",
            "required_data": "Mailbox access logs, cloud storage audit logs, outbound proxy logs, suspicious upload events.",
        },
    ]
    for gap in recommended_gaps:
        if gap["gap"].lower() not in existing:
            context["evidence_gaps"].append(gap)


def build_policy_application_summary(context: dict[str, Any]) -> list[dict[str, str]]:
    severity = context.get("severity", {}).get("label", "Not Provided")
    scenario = context.get("scenario_type", "generic").replace("_", " ")
    approval_status = context.get("approval", {}).get("approval_status", "Not Provided")

    return [
        {
            "source": "incident_severity_policy.md",
            "relevant_guidance": "High severity is appropriate when malicious IOCs, suspicious process execution, likely compromise, or business impact are present.",
            "application": f"Supports the current severity rating of {severity} based on malicious/suspicious indicators and endpoint activity.",
        },
        {
            "source": "containment_approval_policy.md",
            "relevant_guidance": "High or Critical severity containment actions that may disrupt users or systems require SOC analyst approval.",
            "application": f"Containment/approval remains {approval_status}; the report records the decision without executing containment.",
        },
        {
            "source": "reporting_timeline_policy.md",
            "relevant_guidance": "High severity incidents require investigation reporting and SOC analyst review as soon as evidence is available.",
            "application": f"Supports the current report status: {context.get('report_status')}.",
        },
        {
            "source": "report_writing_sop.md",
            "relevant_guidance": "The Reporting Agent must consolidate triage, investigation, IOCs, timeline, containment, and analyst decision data without inventing missing evidence.",
            "application": "The report separates evidence-backed findings, interpretation, and evidence gaps.",
        },
        {
            "source": "phishing_response_playbook.md",
            "relevant_guidance": "Phishing reporting should document sender/recipient context, URLs/domains/hashes, user interaction, endpoint activity, and missing validation steps.",
            "application": f"The incident is treated as a {scenario} case and includes phishing-specific evidence gaps for analyst follow-up.",
        },
    ]


def build_impact_assessment(context: dict[str, Any]) -> dict[str, str]:
    assets = context.get("affected_assets", [])
    users = context.get("affected_users", [])
    scenario = context.get("scenario_type", "generic_security_incident")
    asset_text = "no confirmed assets" if not assets else ", ".join(
        f"{a.get('hostname')} ({a.get('business_function')}, {a.get('criticality')} criticality)"
        for a in assets
    )
    user_text = "no confirmed users" if not users else ", ".join(
        f"{u.get('username')} ({u.get('role')}, {u.get('privilege_level')})"
        for u in users
    )

    if scenario == "phishing":
        business = (
            f"Current business impact is limited to {asset_text} and {user_text}. "
            "Because this involves invoice-processing context, containment or credential reset may temporarily affect finance workflow."
        )
        security = (
            "Security risk is centred on phishing delivery, suspicious attachment interaction, possible PowerShell execution, "
            "credential exposure, and possible follow-on access if the payload completed successfully."
        )
        unconfirmed = (
            "Payload completion, credential submission, mailbox/OAuth abuse, similar recipient exposure, and data exfiltration are not fully confirmed."
        )
    else:
        business = (
            f"Current business impact is scoped to {asset_text} and {user_text}. Additional impact depends on whether spread, disruption, or sensitive data access is confirmed."
        )
        security = (
            f"Security risk is tied to the {scenario.replace('_', ' ')} scenario and should be validated using the listed evidence and gaps."
        )
        unconfirmed = "Further compromise, spread, persistence, and data exposure remain subject to analyst validation."

    return {
        "business": business,
        "security": security,
        "unconfirmed": unconfirmed,
    }


def build_findings(context: dict[str, Any]) -> list[dict[str, Any]]:
    findings = []
    evidence = context.get("evidence", [])
    timeline = context.get("timeline", [])
    evidence_ids = _all_evidence_refs(context)
    scenario = context.get("scenario_type")

    def add(statement, status, confidence, refs=None, interpretation=""):
        clean_refs = list(dict.fromkeys(refs or []))
        findings.append({
            "statement": statement,
            "status": status,
            "confidence": confidence,
            "evidence_refs": clean_refs if clean_refs else ["Not linked"],
            "interpretation": interpretation,
        })

    add(
        f"The incident classification is {context.get('classification')}.",
        "Fact",
        context.get("confidence", {}).get("label", "Not Provided"),
        evidence_ids[:3],
        "Classification is taken from investigation output first, with triage as fallback."
    )

    if scenario == "phishing":
        email_refs = list(dict.fromkeys(
            _evidence_refs_by_terms(evidence, ["email", "gateway", "phish", "attachment"])
            + _timeline_refs_by_terms(timeline, ["email", "delivered", "attachment"])
        ))
        if email_refs:
            add(
                "Suspicious phishing email delivery was observed.",
                "Evidence-Backed Finding",
                "High",
                email_refs,
                "Email delivery is supported by existing email/timeline evidence."
            )

    powershell_refs = list(dict.fromkeys(
        _evidence_refs_by_terms(evidence, ["powershell", "encoded", "process", "winword"])
        + _timeline_refs_by_terms(timeline, ["powershell", "process", "execution"])
    ))
    if powershell_refs:
        add(
            "Suspicious PowerShell or process activity was observed after the phishing event.",
            "Evidence-Backed Finding",
            "Medium",
            powershell_refs,
            "This supports deeper validation of payload execution, script activity, and created artefacts."
        )

    malicious_iocs = [ioc for ioc in context.get("iocs", []) if str(ioc.get("reputation", "")).lower() in ["malicious", "suspicious"]]
    if malicious_iocs:
        refs = []
        for ioc in malicious_iocs:
            refs.extend(ioc.get("evidence_refs", []))
        add(
            f"{len(malicious_iocs)} malicious or suspicious IOC(s) are present in the reporting context.",
            "Evidence-Backed Finding",
            "Medium",
            [r for r in refs if r != "Not linked"],
            "The Reporting Agent consolidated these IOCs from enrichment and investigation outputs only."
        )

    if context.get("timeline"):
        add(
            "An incident timeline was provided by the investigation output.",
            "Fact",
            "Medium",
            evidence_ids,
            "Timeline entries are rendered as supplied and should be validated by the SOC analyst."
        )
    else:
        add(
            "No incident timeline was provided.",
            "Evidence Gap",
            "High",
            [],
            "A timeline is required for analyst-friendly incident reconstruction."
        )

    add(
        f"Containment/approval status is {context.get('approval', {}).get('approval_status')}.",
        "Fact",
        "High",
        ["approval_result.json"],
        "Approval data is taken only from approval_result.json and is not decided by the Reporting Agent."
    )

    return findings


def build_context(inputs: dict[str, dict[str, Any]], input_warnings: list[str]) -> dict[str, Any]:
    enriched_alert = inputs.get("enriched_alert", {})
    triage = inputs.get("triage_result", {})
    investigation = inputs.get("investigation_result", {})
    approval = inputs.get("approval_result", {})

    recovered_fields = []
    warnings = list(input_warnings)

    incident_id = first_present(
        triage.get("incident_id"),
        investigation.get("incident_id"),
        enriched_alert.get("incident_id"),
        approval.get("incident_id"),
        fallback="UNKNOWN-INCIDENT"
    )

    alert_id = first_present(
        enriched_alert.get("alert_id"),
        triage.get("alert_id"),
        investigation.get("alert_id"),
        approval.get("alert_id"),
        fallback="UNKNOWN-ALERT"
    )

    severity = normalise_severity(triage, investigation, recovered_fields)
    confidence = normalise_confidence(triage, investigation, recovered_fields)

    classification = first_present(
        investigation.get("classification"),
        investigation.get("final_classification"),
        get_nested(triage, "triage.classification"),
        triage.get("classification"),
    )

    likely_scenario = first_present(
        investigation.get("likely_scenario"),
        investigation.get("scenario"),
        get_nested(triage, "triage.likely_scenario"),
        triage.get("likely_scenario"),
    )

    affected_assets = [normalise_asset(a) for a in to_list(first_present(investigation.get("affected_assets"), investigation.get("affected_hosts"), fallback=[]))]
    affected_users = [normalise_user(u) for u in to_list(first_present(investigation.get("affected_users"), fallback=[]))]
    iocs = combine_iocs(enriched_alert, investigation)
    evidence = [normalise_evidence(e, idx) for idx, e in enumerate(to_list(investigation.get("evidence", [])), start=1)]
    timeline = to_list(first_present(investigation.get("timeline"), investigation.get("event_timeline"), fallback=[]))
    recommended_actions = [normalise_action(a, idx) for idx, a in enumerate(to_list(first_present(investigation.get("recommended_actions"), investigation.get("recovery_recommendations"), fallback=[])), start=1)]

    raw_approval_status = first_present(approval.get("approval_status"), approval.get("soc_analyst_approval_status"), fallback="Not Provided")
    raw_containment_status = first_present(
        approval.get("containment_status"),
        approval.get("approval_status"),
        investigation.get("containment_status"),
        get_nested(triage, "triage.containment_status"),
        triage.get("containment_status"),
        fallback="Not Provided"
    )

    context = {
        "schema_version": "enriched-reporting-context-v2",
        "created_at": now_sg_iso(),
        "incident_id": incident_id,
        "alert_id": alert_id,
        "case_title": first_present(triage.get("case_title"), enriched_alert.get("alert_name"), investigation.get("case_title")),
        "alert": {
            "name": first_present(enriched_alert.get("alert_name"), triage.get("alert_name")),
            "source": first_present(enriched_alert.get("source"), enriched_alert.get("detection_source"), fallback="RSA NetWitness SIEM"),
            "timestamp": first_present(enriched_alert.get("alert_timestamp"), triage.get("alert_timestamp")),
        },
        "severity": severity,
        "confidence": confidence,
        "classification": classification,
        "likely_scenario": likely_scenario,
        "scenario_type": infer_scenario(likely_scenario),
        "investigation_summary": first_present(investigation.get("investigation_summary")),
        "triage_summary": first_present(get_nested(triage, "triage.summary"), triage.get("triage_summary")),
        "affected_assets": affected_assets,
        "affected_users": affected_users,
        "iocs": iocs,
        "evidence": evidence,
        "timeline": timeline,
        "mitre_attack_mapping": to_list(investigation.get("mitre_attack_mapping", [])),
        "evidence_gaps": to_list(first_present(investigation.get("evidence_gaps"), investigation.get("missing_evidence"), fallback=[])),
        "recommended_actions": recommended_actions,
        "approval": {
            "approval_required": yes_no(first_present(approval.get("approval_required"), get_nested(triage, "triage.containment_required"), triage.get("containment_required"), fallback="Not Provided")),
            "approval_status": humanise_status(raw_approval_status),
            "approved_by": first_present(approval.get("approved_by"), approval.get("rejected_by")),
            "approved_action": first_present(approval.get("approved_action"), approval.get("approved_containment_action")),
            "analyst_decision": humanise_status(first_present(approval.get("analyst_decision"), raw_approval_status)),
            "analyst_comments": first_present(approval.get("analyst_comments"), approval.get("soc_analyst_comments"), approval.get("rejection_reason")),
        },
        "containment": {
            "status": humanise_status(raw_containment_status),
            "recommended_action": first_present(investigation.get("recommended_containment_action"), get_nested(triage, "triage.recommended_containment_action"), triage.get("recommended_containment_action")),
            "decision_source": "approval_result.json" if approval else "triage_or_investigation_result",
        },
        "recovered_fields": recovered_fields,
        "warnings": warnings,
    }

    missing = validate_required_fields(context)
    context["missing_required_fields"] = missing
    context["validation_status"] = "passed" if not missing else "failed"
    context["report_status"] = "ready_for_analyst_review" if not missing else "missing_information_required"

    context["evidence_gaps"].extend(build_missing_field_gaps(missing))
    add_phishing_evidence_gaps(context)
    link_iocs_to_evidence(context)
    context["evidence_backed_findings"] = build_findings(context)
    context["impact_assessment"] = build_impact_assessment(context)

    rag_result = retrieve_reporting_context(context)
    context.update({
        "rag_used": rag_result["rag_used"],
        "rag_status": rag_result["rag_status"],
        "rag_context_used": rag_result["retrieved_context"],
        "loaded_knowledge_files": rag_result["loaded_knowledge_files"],
        "excluded_playbooks": rag_result["excluded_playbooks"],
    })
    context["policy_application_summary"] = build_policy_application_summary(context)

    narrative = enhance_narrative(context)
    context.update(narrative)

    active_narrative = narrative["llm_enhanced_narrative"] if narrative["llm_enhanced_narrative"] else narrative["deterministic_narrative"]
    context["active_narrative"] = active_narrative

    if context["llm_used"]:
        context["report_generation_mode"] = "deterministic_plus_llm_narrative"
    else:
        context["report_generation_mode"] = "deterministic_only"

    return context
