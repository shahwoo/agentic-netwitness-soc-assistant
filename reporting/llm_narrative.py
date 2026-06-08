from __future__ import annotations

from typing import Any
import json
import os
import re
import urllib.request

from config import settings


PROTECTED_FIELDS = [
    "severity",
    "confidence",
    "classification",
    "iocs",
    "affected_assets",
    "affected_users",
    "evidence",
    "timeline",
    "approval_status",
    "containment_decision",
]

PROMPT_LEAKAGE_PATTERNS = [
    "here's a rewritten",
    "here is a rewritten",
    "below is",
    "this summary",
    "two paragraphs",
    "one paragraph",
    "220 to 320 words",
    "180 to 300 words",
    "100 to 160 words",
    "130 to 190 words",
    "use soc",
    "strict rules",
    "facts:",
    "task:",
    "content requirements",
    "hard safety rules",
    "return final",
    "you are a senior",
    "you are a tier 3",
    "write only",
    "requirements:",
    "output rules:",
]

UNSAFE_OVERCLAIMS = [
    "payload execution completed",
    "payload completed execution",
    "payload completed",
    "credentials were stolen",
    "credential was stolen",
    "credentials were compromised",
    "data was exfiltrated",
    "data exfiltration occurred",
    "lateral movement occurred",
    "persistence was established",
    "command-and-control was established",
    "c2 was established",
    "the host was compromised",
    "host was compromised",
    "attacker gained access",
    "malware executed successfully",
]


def _clean_sentence_join(items: list[str]) -> str:
    cleaned = []

    for item in items:
        text = str(item).strip()

        if not text:
            continue

        text = text.rstrip(" .;")
        cleaned.append(text)

    if not cleaned:
        return "Not Provided"

    return ". ".join(cleaned) + "."


def _words(text: str) -> list[str]:
    return str(text or "").split()


def _asset_summary(context: dict[str, Any]) -> str:
    assets = context.get("affected_assets", [])

    if not assets:
        return "No affected asset provided."

    return "; ".join(
        f"{asset.get('hostname')} "
        f"({asset.get('ip_address')}, "
        f"{asset.get('asset_type')}, "
        f"{asset.get('business_function')}, "
        f"{asset.get('criticality')} criticality, "
        f"owner: {asset.get('owner')})"
        for asset in assets
    )


def _user_summary(context: dict[str, Any]) -> str:
    users = context.get("affected_users", [])

    if not users:
        return "No affected user provided."

    return "; ".join(
        f"{user.get('username')} "
        f"({user.get('role')}, "
        f"{user.get('privilege_level')}, "
        f"MFA: {user.get('mfa_status')}, "
        f"status: {user.get('account_status')})"
        for user in users
    )


def _evidence_summary(context: dict[str, Any], limit: int = 6) -> str:
    evidence = context.get("evidence", [])

    if not evidence:
        return "No evidence provided."

    return _clean_sentence_join(
        [
            f"{item.get('id')}: "
            f"{item.get('source')} {item.get('type')} observed "
            f"{item.get('description')} at {item.get('timestamp')}"
            for item in evidence[:limit]
        ]
    )


def _timeline_summary(context: dict[str, Any], limit: int = 6) -> str:
    timeline = context.get("timeline", [])

    if not timeline:
        return "No timeline provided."

    return _clean_sentence_join(
        [
            f"{event.get('time', event.get('timestamp', 'Not Provided'))}: "
            f"{event.get('event', event.get('description', 'Not Provided'))}"
            for event in timeline[:limit]
        ]
    )


def _ioc_summary(context: dict[str, Any]) -> str:
    iocs = context.get("iocs", [])

    if not iocs:
        return "No IOCs provided."

    return "; ".join(
        f"{ioc.get('value')} "
        f"({ioc.get('type')}, "
        f"reputation: {ioc.get('reputation')}, "
        f"evidence: {', '.join(ioc.get('evidence_refs', []))})"
        for ioc in iocs
    )


def _mitre_summary(context: dict[str, Any]) -> str:
    mappings = context.get("mitre_attack_mapping", [])

    if not mappings:
        return "No MITRE ATT&CK mapping provided."

    return "; ".join(
        f"{mapping.get('tactic', 'Not Provided')} / "
        f"{mapping.get('technique_id', '')} "
        f"{mapping.get('technique_name', '')}: "
        f"{mapping.get('reason', 'Not Provided')}"
        for mapping in mappings
    )


def _findings_summary(context: dict[str, Any]) -> str:
    findings = context.get("evidence_backed_findings", [])

    if not findings:
        return "No evidence-backed findings generated."

    return _clean_sentence_join(
        [
            f"{finding.get('statement')} "
            f"Evidence references: {', '.join(finding.get('evidence_refs', []))}"
            for finding in findings[:8]
        ]
    )


def _gap_summary(context: dict[str, Any]) -> str:
    gaps = context.get("evidence_gaps", [])

    if not gaps:
        return "No evidence gaps recorded."

    return _clean_sentence_join(
        [
            f"{gap.get('priority', 'Unknown')} priority: "
            f"{gap.get('gap', 'Not Provided')} "
            f"Required data: {gap.get('required_data', 'Not Provided')}"
            for gap in gaps[:8]
        ]
    )


def _action_summary(context: dict[str, Any]) -> str:
    actions = context.get("recommended_actions", [])

    if not actions:
        return "No recommended actions provided."

    return _clean_sentence_join(
        [
            f"{action.get('priority')}: "
            f"{action.get('action')} "
            f"Owner: {action.get('owner')} "
            f"Approval required: {action.get('approval_required')}"
            for action in actions[:6]
        ]
    )


def build_llm_safe_context(context: dict[str, Any]) -> dict[str, str]:
    """
    Build a compact, LLM-safe context.

    This avoids sending raw JSON, full RAG chunks, or unnecessary fields to the LLM.
    The LLM should only receive report-safe facts and should not become the source of truth.
    """

    return {
        "alert_name": str(context.get("alert", {}).get("name", "Not Provided")),
        "alert_source": str(context.get("alert", {}).get("source", "Not Provided")),
        "alert_timestamp": str(context.get("alert", {}).get("timestamp", "Not Provided")),
        "classification": str(context.get("classification", "Not Provided")),
        "severity_label": str(context.get("severity", {}).get("label", "Not Provided")),
        "severity_reason": str(context.get("severity", {}).get("reason", "Not Provided")),
        "confidence_label": str(context.get("confidence", {}).get("label", "Not Provided")),
        "confidence_reason": str(context.get("confidence", {}).get("reason", "Not Provided")),
        "likely_scenario": str(context.get("likely_scenario", "Not Provided")),
        "affected_asset_summary": _asset_summary(context),
        "affected_user_summary": _user_summary(context),
        "key_evidence_summary": _evidence_summary(context),
        "timeline_summary": _timeline_summary(context),
        "ioc_summary": _ioc_summary(context),
        "mitre_mapping": _mitre_summary(context),
        "evidence_backed_findings": _findings_summary(context),
        "evidence_gaps": _gap_summary(context),
        "recommended_actions": _action_summary(context),
        "containment_status": str(context.get("containment", {}).get("status", "Not Provided")),
        "approval_status": str(context.get("approval", {}).get("approval_status", "Not Provided")),
        "recommended_containment_action": str(
            context.get("containment", {}).get("recommended_action", "Not Provided")
        ),
        "business_impact": str(context.get("impact_assessment", {}).get("business", "Not Provided")),
        "security_risk": str(context.get("impact_assessment", {}).get("security", "Not Provided")),
        "unconfirmed_items": str(context.get("impact_assessment", {}).get("unconfirmed", "Not Provided")),
    }


def deterministic_narrative(context: dict[str, Any]) -> dict[str, str]:
    """
    Generate a complete deterministic narrative.

    This is the fallback and baseline narrative. It must always work without the LLM.
    """

    safe = build_llm_safe_context(context)
    missing = context.get("missing_required_fields", [])

    executive_summary = (
        f"A {safe['alert_name']} alert from {safe['alert_source']} is assessed as a "
        f"{safe['severity_label']}-severity, {safe['confidence_label']}-confidence "
        f"{safe['classification']} related to {safe['likely_scenario']}. "
        f"The known scope is {safe['affected_asset_summary']} and {safe['affected_user_summary']}. "
        f"Current evidence includes {safe['key_evidence_summary']} "
        f"Malicious or suspicious indicators are {safe['ioc_summary']}. "
        f"The main risk is possible phishing-led endpoint compromise, credential exposure, "
        f"or follow-on access; however, {safe['unconfirmed_items']} "
        f"Containment is {safe['containment_status']} and approval status is {safe['approval_status']}."
    )

    if missing:
        executive_summary += f" Required reporting fields still missing: {', '.join(missing)}."

    technical_analysis = (
        f"The observed sequence indicates phishing delivery followed by suspicious endpoint process activity. "
        f"Timeline context: {safe['timeline_summary']} "
        f"Evidence context: {safe['key_evidence_summary']} "
        f"This supports the current scenario assessment and aligns with {safe['mitre_mapping']}. "
        f"The evidence does not prove payload completion, credential theft, lateral movement, persistence, "
        f"command-and-control, or data exfiltration unless separately confirmed by upstream investigation data. "
        f"Analyst validation should prioritise PowerShell script block logs, process completion, child processes, "
        f"file writes, outbound network connections, identity telemetry, mailbox/OAuth activity, campaign-wide "
        f"email searches, and the currently unresolved evidence gaps."
    )

    business_impact = (
        f"{safe['business_impact']} "
        f"Security risk: {safe['security_risk']} "
        f"Unconfirmed items requiring analyst validation: {safe['unconfirmed_items']}"
    )

    conclusion = (
        f"The report is suitable for SOC analyst review with status {context.get('report_status')}. "
        f"Before closure, the analyst should validate payload execution, credential or session exposure, "
        f"similar recipient exposure, containment approval, and data exposure. Any disruptive action, such as "
        f"endpoint isolation or credential revocation, should follow the recorded approval workflow."
    )

    return {
        "executive_summary": executive_summary,
        "technical_analysis": technical_analysis,
        "business_impact_explanation": business_impact,
        "conclusion": conclusion,
        "analyst_friendly_explanation": (
            "The Reporting Agent uses deterministic logic as the source of truth. "
            "LLM output is accepted only after quality and safety checks."
        ),
    }


def _openai_preflight() -> tuple[bool, str]:
    """
    Fast OpenAI configuration check.

    This does not make a network call. It only checks whether the API key exists.
    """

    api_key = os.getenv("OPENAI_API_KEY")

    if not api_key:
        return False, "openai_api_key_missing"

    if not settings.OPENAI_MODEL:
        return False, "openai_model_missing"

    return True, "openai_config_available"


def _ollama_preflight() -> tuple[bool, str]:
    """
    Fast Ollama availability check.

    This prevents missing Ollama or missing models from causing long waits.
    """

    try:
        url = settings.OLLAMA_BASE_URL.rstrip("/") + "/api/tags"

        with urllib.request.urlopen(url, timeout=settings.OLLAMA_PREFLIGHT_TIMEOUT_SECONDS) as response:
            data = json.loads(response.read().decode("utf-8"))

        model_names = [model.get("name", "") for model in data.get("models", [])]

        if settings.OLLAMA_MODEL not in model_names:
            model_found = any(
                name.startswith(settings.OLLAMA_MODEL) or settings.OLLAMA_MODEL.startswith(name)
                for name in model_names
            )

            if not model_found:
                return False, f"ollama_model_not_found:{settings.OLLAMA_MODEL}"

        return True, "ollama_available"

    except Exception as error:
        return False, f"ollama_unavailable:{error}"


def _invoke_openai_plain_text(prompt: str, max_output_tokens: int = 350) -> str:
    """
    Invoke OpenAI through the official OpenAI Python SDK.

    The SDK reads OPENAI_API_KEY from the environment by default.
    """

    from openai import OpenAI

    client = OpenAI(timeout=settings.OPENAI_TIMEOUT_SECONDS)

    response = client.responses.create(
        model=settings.OPENAI_MODEL,
        input=prompt,
        max_output_tokens=max_output_tokens,
    )

    return response.output_text.strip()


def _invoke_ollama_plain_text(prompt: str, num_predict: int | None = None) -> str:
    """
    Invoke Ollama through LangChain.

    LangChain is imported lazily so the script does not pay the import cost
    when Ollama is not selected.
    """

    try:
        from langchain_ollama import OllamaLLM
    except Exception:
        from langchain_community.llms import Ollama as OllamaLLM

    llm = OllamaLLM(
        model=settings.OLLAMA_MODEL,
        temperature=0.1,
        num_predict=num_predict or settings.LLM_NUM_PREDICT,
    )

    return str(llm.invoke(prompt)).strip()


def _invoke_llm_plain_text(prompt: str, max_output_tokens: int = 350) -> str:
    """
    Route LLM calls based on settings.LLM_PROVIDER.

    Supported providers:
    - openai
    - ollama
    """

    provider = settings.LLM_PROVIDER.strip().lower()

    if provider == "openai":
        return _invoke_openai_plain_text(prompt, max_output_tokens=max_output_tokens)

    if provider == "ollama":
        return _invoke_ollama_plain_text(prompt, num_predict=max_output_tokens)

    raise ValueError(f"Unsupported LLM provider: {settings.LLM_PROVIDER}")


def _llm_preflight() -> tuple[bool, str]:
    """
    Run the correct preflight check for the configured provider.
    """

    provider = settings.LLM_PROVIDER.strip().lower()

    if provider == "openai":
        return _openai_preflight()

    if provider == "ollama":
        return _ollama_preflight()

    return False, f"unsupported_llm_provider:{settings.LLM_PROVIDER}"


def _normalise_output(text: str) -> str:
    text = str(text or "").strip()
    text = text.replace("```markdown", "").replace("```", "").strip()
    text = re.sub(r"(?i)^here(?:'|’)s.*?:\s*", "", text).strip()
    text = re.sub(r"(?i)^sure[,.]?\s*", "", text).strip()

    # Remove accidental heading if the model adds it.
    text = re.sub(r"(?i)^#+\s*(executive summary|technical analysis)\s*", "", text).strip()

    return text


def _has_prompt_leakage(text: str) -> list[str]:
    lower = str(text or "").lower()
    return [pattern for pattern in PROMPT_LEAKAGE_PATTERNS if pattern in lower]


def _has_unsafe_overclaim(text: str) -> list[str]:
    lower = str(text or "").lower()
    return [pattern for pattern in UNSAFE_OVERCLAIMS if pattern in lower]


def validate_llm_section(
    text: str,
    section: str,
    min_words: int,
    max_words: int,
) -> tuple[bool, list[str]]:
    """
    Validate LLM output before it is allowed into the Markdown report.
    """

    issues = []
    raw = str(text or "").strip()
    lower = raw.lower()
    words = _words(raw)

    if not raw:
        issues.append("empty_output")

    if len(words) < min_words:
        issues.append("too_short")

    if len(words) > max_words:
        issues.append("too_long")

    if raw.count("\n") > 3 and section == "executive_summary":
        issues.append("too_many_newlines")

    if lower.endswith((",", "(", ":", "-", ";")):
        issues.append("possibly_truncated")

    if raw.count("(") > raw.count(")"):
        issues.append("unbalanced_parentheses")

    for leakage in _has_prompt_leakage(raw):
        issues.append(f"prompt_leakage:{leakage}")

    for overclaim in _has_unsafe_overclaim(raw):
        issues.append(f"unsafe_overclaim:{overclaim}")

    if section == "executive_summary":
        if (
            "unconfirmed" not in lower
            and "not yet confirmed" not in lower
            and "requires validation" not in lower
        ):
            issues.append("missing_uncertainty_language")

        if "containment" not in lower and "approval" not in lower:
            issues.append("missing_containment_or_approval_status")

    if section == "technical_analysis":
        if "evidence" not in lower and "telemetry" not in lower:
            issues.append("missing_evidence_or_telemetry_language")

        if (
            "not confirm" not in lower
            and "not yet confirmed" not in lower
            and "requires validation" not in lower
            and "does not prove" not in lower
            and "does not yet confirm" not in lower
        ):
            issues.append("missing_limitations_language")

    return len(issues) == 0, issues


def build_executive_summary_prompt(safe: dict[str, str]) -> str:
    return f"""
You are a senior SOC incident response report writer preparing an executive summary for a SOC incident report.

Audience: SOC Lead, Incident Commander, IT Security Manager, and business stakeholder.

Write one polished paragraph only, 110 to 170 words. Use professional SOC and business-cybersecurity language. Explain what triggered the alert, why it is suspicious or malicious, what evidence supports the classification, which asset and user are currently in scope, what the business/security risk is, what remains unconfirmed, and what containment or analyst decision is pending.

Rules: Use only the facts provided. Do not invent hosts, users, IOCs, evidence, timestamps, malware names, threat actors, CVEs, tools, files, domains, URLs, IPs, or data loss. Do not include headings, bullets, tables, field labels, or phrases like "Here's" or "Below is". Do not claim payload execution, credential theft, host compromise, data exfiltration, lateral movement, persistence, or command-and-control unless explicitly confirmed. If uncertain, use "not yet confirmed", "requires validation", "possible", or "suspected". Return report-ready prose only.

Facts:
Alert name: {safe['alert_name']}
Alert source: {safe['alert_source']}
Alert timestamp: {safe['alert_timestamp']}
Classification: {safe['classification']}
Severity: {safe['severity_label']}
Severity reason: {safe['severity_reason']}
Confidence: {safe['confidence_label']}
Confidence reason: {safe['confidence_reason']}
Likely scenario: {safe['likely_scenario']}
Affected asset summary: {safe['affected_asset_summary']}
Affected user summary: {safe['affected_user_summary']}
Key evidence summary: {safe['key_evidence_summary']}
Timeline summary: {safe['timeline_summary']}
IOC summary: {safe['ioc_summary']}
MITRE ATT&CK mapping: {safe['mitre_mapping']}
Containment status: {safe['containment_status']}
Approval status: {safe['approval_status']}
Recommended containment action: {safe['recommended_containment_action']}
Business impact baseline: {safe['business_impact']}
Security risk baseline: {safe['security_risk']}
Unconfirmed items: {safe['unconfirmed_items']}
Evidence gaps: {safe['evidence_gaps']}
""".strip()


def build_technical_analysis_prompt(safe: dict[str, str]) -> str:
    return f"""
You are a Tier 3 SOC analyst writing the Technical Analysis section of an incident report for analyst handover.

Write exactly two paragraphs, 180 to 280 words total. Use SOC and cybersecurity terminology correctly, including phishing delivery, endpoint telemetry, parent-child process relationship, suspicious process activity, encoded PowerShell, IOC reputation, MITRE ATT&CK, blast radius, credential exposure, mailbox rule abuse, OAuth abuse, command-and-control, data exfiltration, containment approval, evidence gap, and analyst validation only where relevant to the facts.

Explain the likely attack sequence based on the evidence, how the timeline supports the scenario, how email telemetry, endpoint telemetry, IOC reputation, and MITRE mapping fit together, what the evidence supports, what it does not yet confirm, what the likely blast radius is, what analysts should validate next, and why containment or approval status matters.

Rules: Use only provided facts. Do not invent hosts, users, IOCs, evidence, timestamps, malware names, threat actors, CVEs, tools, files, registry keys, domains, URLs, IPs, or data loss. Do not include headings, bullets, tables, field labels, or prompt instruction text. Do not claim payload execution completed, credentials were stolen, data was exfiltrated, command-and-control occurred, lateral movement occurred, persistence was established, or the host is compromised unless explicitly confirmed. Use cautious wording such as observed, suspected, possible, requires validation, not yet confirmed, or cannot be ruled out. Return report-ready prose only.

Facts:
Classification: {safe['classification']}
Severity: {safe['severity_label']}
Confidence: {safe['confidence_label']}
Likely scenario: {safe['likely_scenario']}
Affected asset summary: {safe['affected_asset_summary']}
Affected user summary: {safe['affected_user_summary']}
Evidence summary: {safe['key_evidence_summary']}
Timeline summary: {safe['timeline_summary']}
IOC summary: {safe['ioc_summary']}
MITRE ATT&CK mapping: {safe['mitre_mapping']}
Evidence-backed findings: {safe['evidence_backed_findings']}
Evidence gaps: {safe['evidence_gaps']}
Recommended actions: {safe['recommended_actions']}
Containment status: {safe['containment_status']}
Approval status: {safe['approval_status']}
""".strip()


def enhance_narrative(context: dict[str, Any]) -> dict[str, Any]:
    """
    Main LLM narrative enhancement function.

    The LLM is used only for:
    - executive_summary
    - technical_analysis

    Business impact and conclusion remain deterministic for stability.
    """

    deterministic = deterministic_narrative(context)
    safe = build_llm_safe_context(context)

    result = {
        "llm_safe_context": safe,
        "deterministic_narrative": deterministic,
        "llm_enhanced_narrative": {},
        "llm_used": False,
        "llm_status": "disabled",
        "llm_model": "not_used",
        "llm_provider": settings.LLM_PROVIDER,
        "llm_quality_status": "not_used",
        "llm_quality_issues": [],
        "llm_sections": {
            "executive_summary": {
                "used_llm": False,
                "quality_status": "not_used",
                "issues": [],
            },
            "technical_analysis": {
                "used_llm": False,
                "quality_status": "not_used",
                "issues": [],
            },
            "business_impact_explanation": {
                "used_llm": False,
                "quality_status": "deterministic",
                "issues": [],
            },
            "conclusion": {
                "used_llm": False,
                "quality_status": "deterministic",
                "issues": [],
            },
        },
        "llm_narrative_status_human": "LLM disabled. Deterministic narrative used.",
    }

    accepted = {
        "executive_summary": deterministic["executive_summary"],
        "technical_analysis": deterministic["technical_analysis"],
        "business_impact_explanation": deterministic["business_impact_explanation"],
        "conclusion": deterministic["conclusion"],
        "analyst_friendly_explanation": deterministic["analyst_friendly_explanation"],
    }

    if not settings.USE_LLM:
        result["llm_enhanced_narrative"] = accepted
        return result

    available, availability_reason = _llm_preflight()

    if settings.LLM_PROVIDER == "openai":
        result["llm_model"] = settings.OPENAI_MODEL
    else:
        result["llm_model"] = settings.OLLAMA_MODEL

    if not available:
        result["llm_status"] = f"llm_failed_fallback_used:{availability_reason}"
        result["llm_quality_status"] = "failed_fallback_used"
        result["llm_quality_issues"] = [availability_reason]
        result["llm_enhanced_narrative"] = accepted
        result["llm_narrative_status_human"] = "LLM unavailable. Deterministic fallback used."
        return result

    result["llm_used"] = True
    all_issues = []

    # Section 1: Executive Summary
    try:
        executive_raw = _normalise_output(
            _invoke_llm_plain_text(
                build_executive_summary_prompt(safe),
                max_output_tokens=260,
            )
        )

        ok, issues = validate_llm_section(
            executive_raw,
            "executive_summary",
            min_words=90,
            max_words=210,
        )

        if ok:
            accepted["executive_summary"] = executive_raw
            result["llm_sections"]["executive_summary"] = {
                "used_llm": True,
                "quality_status": "accepted",
                "issues": [],
            }
        else:
            all_issues.extend([f"executive_summary:{issue}" for issue in issues])
            result["llm_sections"]["executive_summary"] = {
                "used_llm": False,
                "quality_status": "rejected_fallback_used",
                "issues": issues,
            }

    except Exception as error:
        all_issues.append(f"executive_summary:{error}")
        result["llm_sections"]["executive_summary"] = {
            "used_llm": False,
            "quality_status": "failed_fallback_used",
            "issues": [str(error)],
        }

    # Section 2: Technical Analysis
    try:
        technical_raw = _normalise_output(
            _invoke_llm_plain_text(
                build_technical_analysis_prompt(safe),
                max_output_tokens=420,
            )
        )

        ok, issues = validate_llm_section(
            technical_raw,
            "technical_analysis",
            min_words=140,
            max_words=330,
        )

        if ok:
            accepted["technical_analysis"] = technical_raw
            result["llm_sections"]["technical_analysis"] = {
                "used_llm": True,
                "quality_status": "accepted",
                "issues": [],
            }
        else:
            all_issues.extend([f"technical_analysis:{issue}" for issue in issues])
            result["llm_sections"]["technical_analysis"] = {
                "used_llm": False,
                "quality_status": "rejected_fallback_used",
                "issues": issues,
            }

    except Exception as error:
        all_issues.append(f"technical_analysis:{error}")
        result["llm_sections"]["technical_analysis"] = {
            "used_llm": False,
            "quality_status": "failed_fallback_used",
            "issues": [str(error)],
        }

    result["llm_enhanced_narrative"] = accepted
    result["llm_quality_issues"] = all_issues

    section_values = [
        section
        for section in result["llm_sections"].values()
        if isinstance(section, dict)
    ]

    any_section_accepted = any(section.get("used_llm") for section in section_values)

    if not all_issues:
        result["llm_status"] = "success"
        result["llm_quality_status"] = "accepted"
        result["llm_narrative_status_human"] = "LLM narrative accepted."
    elif any_section_accepted:
        result["llm_status"] = "partial_fallback_used"
        result["llm_quality_status"] = "partial_fallback_used"
        result["llm_narrative_status_human"] = (
            "LLM narrative partially accepted. Deterministic fallback used where needed."
        )
    else:
        result["llm_status"] = "rejected_poor_quality_fallback_used"
        result["llm_quality_status"] = "rejected_fallback_used"
        result["llm_narrative_status_human"] = (
            "LLM output rejected. Deterministic fallback used."
        )

    return result