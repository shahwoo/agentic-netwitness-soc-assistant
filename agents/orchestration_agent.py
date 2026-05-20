import json
import os
import sys
from datetime import datetime
from typing import Any, Dict, List, Optional


DEFAULT_INPUT_FILE = "outputs/enriched_alert.json"
OUTPUT_FILE = "outputs/orchestration_decision.json"


def load_json(file_path: str) -> Dict[str, Any]:
    with open(file_path, "r", encoding="utf-8") as file:
        return json.load(file)


def save_json(data: Dict[str, Any]) -> None:
    os.makedirs("outputs", exist_ok=True)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=4)


def get_nested_value(
    data: Dict[str, Any],
    key_path: List[str],
    fallback: Optional[Any] = None
) -> Any:
    current_value = data

    for key in key_path:
        if not isinstance(current_value, dict):
            return fallback

        current_value = current_value.get(key)

        if current_value is None:
            return fallback

    return current_value


def is_available(value: Any) -> bool:
    if value is None:
        return False

    if isinstance(value, str):
        if value.strip() in ["", "Not available", "Unknown", "null", "None"]:
            return False

    if isinstance(value, list):
        return len(value) > 0

    if isinstance(value, dict):
        return len(value) > 0

    return True


def first_available(case_data: Dict[str, Any], paths: List[List[str]]) -> Any:
    for path in paths:
        value = get_nested_value(case_data, path)

        if is_available(value):
            return value

    return None


def normalise_text(value: Any) -> Optional[str]:
    if not is_available(value):
        return None

    return str(value).strip()


def normalise_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value

    if isinstance(value, str):
        return value.strip().lower() == "true"

    return False


def build_route(
    next_agent: str,
    workflow_decision: str,
    orchestration_reason: str,
    decision_point: str,
    policy_reference: List[str],
    human_review_required: bool = False
) -> Dict[str, Any]:
    return {
        "next_agent": next_agent,
        "workflow_decision": workflow_decision,
        "orchestration_reason": orchestration_reason,
        "decision_point": decision_point,
        "policy_reference": policy_reference,
        "human_review_required": human_review_required
    }


def extract_routing_context(case_data: Dict[str, Any]) -> Dict[str, Any]:
    containment_decision = first_available(case_data, [
        ["containment_decision"],
        ["triage_result", "containment_decision"],
        ["investigation_result", "containment_decision"]
    ])

    containment_recommendation = first_available(case_data, [
        ["containment_recommendation"],
        ["triage_result", "containment_recommendation"],
        ["investigation_result", "containment_recommendation"]
    ])

    containment_action = normalise_text(first_available(case_data, [
        ["containment_action"],
        ["containment_recommendation", "containment_action"],
        ["triage_result", "containment_recommendation", "containment_action"],
        ["investigation_result", "containment_recommendation", "containment_action"]
    ]))

    current_stage = normalise_text(case_data.get("current_stage")) or "unknown_stage"
    approval_status = normalise_text(first_available(case_data, [
        ["approval_status"],
        ["approval_result", "approval_status"],
        ["soc_approval", "approval_status"],
        ["draft_report", "soc_approval", "approval_status"]
    ]))

    soc_analyst_approval_status = normalise_text(first_available(case_data, [
        ["soc_analyst_approval_status"],
        ["containment_decision", "soc_analyst_approval_status"],
        ["triage_result", "containment_decision", "soc_analyst_approval_status"],
        ["investigation_result", "containment_decision", "soc_analyst_approval_status"],
        ["draft_report", "soc_approval", "approval_status"]
    ]))

    containment_approval_status = normalise_text(first_available(case_data, [
        ["containment_approval_status"],
        ["containment_decision", "containment_approval_status"],
        ["triage_result", "containment_decision", "containment_approval_status"],
        ["investigation_result", "containment_decision", "containment_approval_status"]
    ]))

    containment_status = normalise_text(first_available(case_data, [
        ["containment_status"],
        ["containment_decision", "containment_status"],
        ["triage_result", "containment_decision", "containment_status"],
        ["investigation_result", "containment_decision", "containment_status"]
    ]))

    containment_required = first_available(case_data, [
        ["containment_required"],
        ["containment_recommendation", "containment_required"],
        ["triage_result", "containment_recommendation", "containment_required"],
        ["investigation_result", "containment_recommendation", "containment_required"]
    ])

    missing_evidence = first_available(case_data, [
        ["missing_evidence"],
        ["investigation_result", "missing_evidence"],
        ["draft_report", "investigation_summary", "missing_evidence"]
    ])

    if not isinstance(missing_evidence, list):
        missing_evidence = []

    report_status = normalise_text(first_available(case_data, [
        ["report_status"],
        ["report_result", "report_status"],
        ["draft_report", "report_status"]
    ]))

    true_positive_assessment = normalise_text(first_available(case_data, [
        ["true_positive_assessment", "assessment"],
        ["triage_result", "true_positive_assessment", "assessment"]
    ]))

    context = {
        "incident_id": normalise_text(case_data.get("incident_id")),
        "alert_id": normalise_text(case_data.get("alert_id")),
        "current_stage": current_stage,
        "agent_completed": normalise_text(case_data.get("agent_completed")),
        "severity": normalise_text(first_available(case_data, [
            ["severity"],
            ["triage_result", "severity"],
            ["investigation_result", "severity"],
            ["draft_report", "triage_summary", "severity"]
        ])),
        "confidence": normalise_text(first_available(case_data, [
            ["confidence"],
            ["triage_result", "confidence"],
            ["investigation_result", "confidence"],
            ["draft_report", "triage_summary", "confidence"]
        ])),
        "next_action": normalise_text(first_available(case_data, [
            ["next_action"],
            ["triage_result", "next_action"],
            ["investigation_result", "next_action"],
            ["report_result", "next_action"]
        ])),
        "true_positive_assessment": true_positive_assessment,
        "approval_status": approval_status,
        "approval_type": normalise_text(first_available(case_data, [
            ["approval_type"],
            ["approval_result", "approval_type"]
        ])),
        "soc_analyst_approval_status": soc_analyst_approval_status,
        "containment_decision": containment_decision if isinstance(containment_decision, dict) else {},
        "containment_recommendation": containment_recommendation if isinstance(containment_recommendation, dict) else {},
        "containment_action": containment_action,
        "containment_required": normalise_bool(containment_required),
        "containment_approval_status": containment_approval_status,
        "containment_status": containment_status,
        "containment_completed": normalise_bool(case_data.get("containment_completed")),
        "containment_not_executed": normalise_bool(case_data.get("containment_not_executed")),
        "investigation_status": normalise_text(first_available(case_data, [
            ["investigation_status"],
            ["investigation_result", "investigation_status"],
            ["draft_report", "investigation_summary", "investigation_status"]
        ])),
        "required_evidence_complete": first_available(case_data, [
            ["required_evidence_complete"],
            ["investigation_result", "required_evidence_complete"]
        ]),
        "missing_evidence": missing_evidence,
        "missing_evidence_request": first_available(case_data, [
            ["missing_evidence_request"],
            ["investigation_result", "missing_evidence_request"]
        ]),
        "suggested_data_source": normalise_text(first_available(case_data, [
            ["suggested_data_source"],
            ["investigation_result", "suggested_data_source"]
        ])),
        "playbook_pivot_required": normalise_bool(first_available(case_data, [
            ["playbook_pivot_required"],
            ["investigation_result", "playbook_pivot_required"]
        ])),
        "recommended_playbook": normalise_text(first_available(case_data, [
            ["recommended_playbook"],
            ["triage_result", "recommended_playbook"],
            ["investigation_result", "recommended_playbook"],
            ["draft_report", "triage_summary", "recommended_playbook"]
        ])),
        "report_status": report_status,
        "learning_update_status": normalise_text(first_available(case_data, [
            ["learning_update_status"],
            ["report_result", "learning_update_status"],
            ["draft_report", "learning_update_status"]
        ])),
        "learning_approval_status": normalise_text(first_available(case_data, [
            ["learning_approval_status"],
            ["report_result", "learning_approval_status"],
            ["draft_report", "learning_approval_status"]
        ]))
    }

    context["containment_approval_pending"] = (
        context["containment_required"]
        and (
            context["soc_analyst_approval_status"] == "pending"
            or context["containment_approval_status"] == "pending"
            or context["containment_status"] in ["pending_approval", "pending_review"]
        )
    )
    context["missing_evidence_required"] = (
        current_stage == "more_evidence_required"
        or context["required_evidence_complete"] is False
        or is_available(context["missing_evidence_request"])
    )

    return context


def route_from_enrichment(context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if context["current_stage"] != "enrichment_completed":
        return None

    return build_route(
        next_agent="triage_agent",
        workflow_decision="start_triage",
        orchestration_reason="Threat intelligence enrichment is completed. Send case to Triage Agent.",
        decision_point="Enrichment completed routing",
        policy_reference=[
            "Appendix E: Triage Agent Policy-Based Checks",
            "Appendix T: Workflow-to-Policy Mapping"
        ]
    )


def route_from_triage(context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if context["current_stage"] != "triage_completed":
        return None

    severity = context["severity"]
    confidence = context["confidence"]
    next_action = context["next_action"]
    true_positive_assessment = context["true_positive_assessment"]

    if context["containment_approval_pending"]:
        return build_route(
            next_agent="approval_step",
            workflow_decision="request_containment_approval",
            orchestration_reason="Triage recommended containment that requires SOC Analyst approval before execution.",
            decision_point="Triage containment approval routing",
            policy_reference=[
                "Appendix G: Human Approval and Containment Rules",
                "Appendix U: Containment Action Playbook",
                "Appendix T: Workflow-to-Policy Mapping"
            ],
            human_review_required=True
        )

    if true_positive_assessment == "likely_false_positive":
        return build_route(
            next_agent="reporting_agent",
            workflow_decision="generate_false_positive_report",
            orchestration_reason="Triage assessed the alert as a likely false positive. Generate a closure or false-positive report.",
            decision_point="Triage false-positive routing",
            policy_reference=[
                "Appendix E: Triage Agent Policy-Based Checks",
                "Appendix J: Post-Incident Inquiry Report Requirements",
                "Appendix K: Reporting and Learning Agent Rules"
            ]
        )

    if severity == "Medium" and confidence == "Low":
        return build_route(
            next_agent="approval_step",
            workflow_decision="request_triage_review",
            orchestration_reason="Medium severity with Low confidence requires SOC Analyst triage review before choosing investigation or reporting.",
            decision_point="Triage uncertainty review routing",
            policy_reference=[
                "Appendix F: Investigation Evidence and Confidence Rules",
                "Appendix G: Human Approval and Containment Rules"
            ],
            human_review_required=True
        )

    if severity in ["High", "Critical"] or next_action in [
        "Send to Investigation Agent",
        "More investigation required"
    ]:
        return build_route(
            next_agent="investigation_agent",
            workflow_decision="start_investigation",
            orchestration_reason="Triage indicates High or Critical severity, or explicitly requests deeper investigation.",
            decision_point="Triage investigation routing",
            policy_reference=[
                "Appendix A: Incident Severity Classification",
                "Appendix F: Investigation Evidence and Confidence Rules",
                "Appendix T: Workflow-to-Policy Mapping"
            ]
        )

    if severity in ["Low", "Medium"]:
        return build_route(
            next_agent="reporting_agent",
            workflow_decision="generate_triage_report",
            orchestration_reason="Triage completed with Low or Medium severity. Generate a triage summary or report.",
            decision_point="Triage reporting routing",
            policy_reference=[
                "Appendix A: Incident Severity Classification",
                "Appendix J: Post-Incident Inquiry Report Requirements",
                "Appendix K: Reporting and Learning Agent Rules"
            ]
        )

    return build_route(
        next_agent="end",
        workflow_decision="end_after_triage",
        orchestration_reason="Triage completed, but no clear severity or next action was provided.",
        decision_point="Triage fallback routing",
        policy_reference=["Appendix T: Workflow-to-Policy Mapping"]
    )


def route_from_investigation(context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if context["current_stage"] != "investigation_completed":
        return None

    if context["missing_evidence_required"]:
        return route_from_missing_evidence(context)

    if context["playbook_pivot_required"]:
        return route_from_playbook_pivot(context)

    if context["containment_approval_pending"]:
        return build_route(
            next_agent="approval_step",
            workflow_decision="request_containment_approval",
            orchestration_reason="Investigation recommended containment that requires SOC Analyst approval before execution.",
            decision_point="Investigation containment approval routing",
            policy_reference=[
                "Appendix G: Human Approval and Containment Rules",
                "Appendix U: Containment Action Playbook"
            ],
            human_review_required=True
        )

    return build_route(
        next_agent="reporting_agent",
        workflow_decision="generate_report",
        orchestration_reason="Investigation is completed. Send case to Reporting Agent.",
        decision_point="Investigation reporting routing",
        policy_reference=[
            "Appendix F: Investigation Evidence and Confidence Rules",
            "Appendix J: Post-Incident Inquiry Report Requirements"
        ]
    )


def route_from_reporting(context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    report_ready_statuses = [
        "draft_ready",
        "completed",
        "ready_for_review",
        "ready_for_approval"
    ]

    if (
        context["learning_update_status"] == "pending_approval"
        or context["learning_approval_status"] == "pending"
    ):
        return build_route(
            next_agent="approval_step",
            workflow_decision="request_learning_update_approval",
            orchestration_reason="Reporting Agent prepared learning updates that require SOC Analyst approval.",
            decision_point="Learning update approval routing",
            policy_reference=["Appendix K: Reporting and Learning Agent Rules"],
            human_review_required=True
        )

    if (
        context["current_stage"] == "report_completed"
        and context["report_status"] in report_ready_statuses
    ):
        return build_route(
            next_agent="approval_step",
            workflow_decision="request_report_approval",
            orchestration_reason="Draft report is ready. Send to SOC Analyst for report approval.",
            decision_point="Report approval routing",
            policy_reference=[
                "Appendix J: Post-Incident Inquiry Report Requirements",
                "Appendix K: Reporting and Learning Agent Rules"
            ],
            human_review_required=True
        )

    return None


def route_from_approval(context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    approval_status = context["approval_status"]
    approval_type = context["approval_type"]
    current_stage = context["current_stage"]

    if current_stage in [
        "approved",
        "modified",
        "rejected",
        "changes_required",
        "more_investigation_required"
    ]:
        approval_status = current_stage

    if approval_status == "approved" and approval_type == "report_approval":
        return build_route(
            next_agent="end",
            workflow_decision="finalise_case",
            orchestration_reason="SOC Analyst approved the report. Workflow can be finalised.",
            decision_point="Report approval outcome routing",
            policy_reference=[
                "Appendix J: Post-Incident Inquiry Report Requirements",
                "Appendix T: Workflow-to-Policy Mapping"
            ]
        )

    if approval_status == "approved" and approval_type == "containment_approval":
        return build_route(
            next_agent="containment_executor",
            workflow_decision="execute_approved_containment",
            orchestration_reason="SOC Analyst approved containment. Route to the future Containment Executor.",
            decision_point="Containment approval outcome routing",
            policy_reference=[
                "Appendix G: Human Approval and Containment Rules",
                "Appendix U: Containment Action Playbook"
            ]
        )

    if approval_status == "approved" and approval_type == "learning_update_approval":
        return build_route(
            next_agent="reporting_agent",
            workflow_decision="apply_learning_update",
            orchestration_reason="SOC Analyst approved the learning update. Return to Reporting Agent to apply or record it.",
            decision_point="Learning update approval outcome routing",
            policy_reference=["Appendix K: Reporting and Learning Agent Rules"]
        )

    if approval_status == "approved" and approval_type == "triage_review":
        return build_route(
            next_agent="investigation_agent",
            workflow_decision="start_investigation_after_triage_review",
            orchestration_reason="SOC Analyst approved triage review escalation. Send case to Investigation Agent.",
            decision_point="Triage review approval outcome routing",
            policy_reference=[
                "Appendix F: Investigation Evidence and Confidence Rules",
                "Appendix G: Human Approval and Containment Rules"
            ]
        )

    if approval_status == "approved" and approval_type == "investigation_review":
        return build_route(
            next_agent="reporting_agent",
            workflow_decision="generate_report_after_investigation_review",
            orchestration_reason="SOC Analyst approved the investigation review. Send case to Reporting Agent.",
            decision_point="Investigation review approval outcome routing",
            policy_reference=[
                "Appendix F: Investigation Evidence and Confidence Rules",
                "Appendix J: Post-Incident Inquiry Report Requirements"
            ]
        )

    if approval_status == "modified" and approval_type == "containment_approval":
        return build_route(
            next_agent="containment_executor",
            workflow_decision="execute_modified_approved_containment",
            orchestration_reason="SOC Analyst modified and approved the containment action. Route to the future Containment Executor.",
            decision_point="Modified containment approval outcome routing",
            policy_reference=[
                "Appendix G: Human Approval and Containment Rules",
                "Appendix U: Containment Action Playbook"
            ]
        )

    if approval_status == "rejected" and approval_type == "containment_approval":
        return build_route(
            next_agent="reporting_agent",
            workflow_decision="record_containment_rejection",
            orchestration_reason="SOC Analyst rejected containment. Send to Reporting Agent to document the decision.",
            decision_point="Containment rejection routing",
            policy_reference=[
                "Appendix G: Human Approval and Containment Rules",
                "Appendix J: Post-Incident Inquiry Report Requirements"
            ]
        )

    if approval_status == "rejected" and approval_type == "triage_review":
        return build_route(
            next_agent="reporting_agent",
            workflow_decision="document_triage_review_rejection",
            orchestration_reason="SOC Analyst rejected triage escalation. Send case to Reporting Agent to document the review outcome.",
            decision_point="Triage review rejection routing",
            policy_reference=[
                "Appendix G: Human Approval and Containment Rules",
                "Appendix J: Post-Incident Inquiry Report Requirements"
            ]
        )

    if approval_status == "rejected" and approval_type == "investigation_review":
        return build_route(
            next_agent="reporting_agent",
            workflow_decision="document_investigation_review_rejection",
            orchestration_reason="SOC Analyst rejected the investigation review. Send case to Reporting Agent to document the outcome.",
            decision_point="Investigation review rejection routing",
            policy_reference=[
                "Appendix G: Human Approval and Containment Rules",
                "Appendix J: Post-Incident Inquiry Report Requirements"
            ]
        )

    if approval_status == "changes_required" and approval_type == "report_approval":
        return build_route(
            next_agent="reporting_agent",
            workflow_decision="revise_report",
            orchestration_reason="SOC Analyst requested report changes. Send case back to Reporting Agent for revision.",
            decision_point="Report changes-required routing",
            policy_reference=[
                "Appendix J: Post-Incident Inquiry Report Requirements",
                "Appendix K: Reporting and Learning Agent Rules"
            ],
            human_review_required=True
        )

    if approval_status == "changes_required" and approval_type == "triage_review":
        return build_route(
            next_agent="triage_agent",
            workflow_decision="revise_triage",
            orchestration_reason="SOC Analyst requested triage changes. Send case back to Triage Agent.",
            decision_point="Triage review changes-required routing",
            policy_reference=[
                "Appendix E: Triage Agent Policy-Based Checks",
                "Appendix G: Human Approval and Containment Rules"
            ],
            human_review_required=True
        )

    if approval_status == "changes_required" and approval_type == "investigation_review":
        return build_route(
            next_agent="investigation_agent",
            workflow_decision="revise_investigation",
            orchestration_reason="SOC Analyst requested investigation changes. Send case back to Investigation Agent.",
            decision_point="Investigation review changes-required routing",
            policy_reference=[
                "Appendix F: Investigation Evidence and Confidence Rules",
                "Appendix G: Human Approval and Containment Rules"
            ],
            human_review_required=True
        )

    if approval_status == "changes_required":
        return build_route(
            next_agent="reporting_agent",
            workflow_decision="revise_report",
            orchestration_reason="SOC Analyst requested changes. Send case back to Reporting Agent for revision.",
            decision_point="Generic changes-required routing",
            policy_reference=[
                "Appendix J: Post-Incident Inquiry Report Requirements",
                "Appendix K: Reporting and Learning Agent Rules"
            ],
            human_review_required=True
        )

    if approval_status == "more_investigation_required":
        return build_route(
            next_agent="investigation_agent",
            workflow_decision="continue_investigation",
            orchestration_reason="SOC Analyst requested further investigation. Send case back to Investigation Agent.",
            decision_point="More investigation approval routing",
            policy_reference=["Appendix F: Investigation Evidence and Confidence Rules"],
            human_review_required=False
        )

    if approval_status == "approved" and not approval_type:
        return build_route(
            next_agent="approval_step",
            workflow_decision="clarify_approval_type",
            orchestration_reason="SOC Analyst approval was recorded, but approval_type is missing. Return to approval handling for clarification.",
            decision_point="Approval type clarification routing",
            policy_reference=[
                "Appendix G: Human Approval and Containment Rules",
                "Appendix T: Workflow-to-Policy Mapping"
            ],
            human_review_required=True
        )

    return None


def route_from_containment(context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    current_stage = context["current_stage"]

    if current_stage == "containment_completed" or context["containment_completed"]:
        return build_route(
            next_agent="reporting_agent",
            workflow_decision="document_containment_outcome",
            orchestration_reason="Containment completed. Send to Reporting Agent to document the containment outcome.",
            decision_point="Containment completed routing",
            policy_reference=[
                "Appendix U: Containment Action Playbook",
                "Appendix J: Post-Incident Inquiry Report Requirements"
            ]
        )

    if current_stage == "containment_not_executed" or context["containment_not_executed"]:
        return build_route(
            next_agent="reporting_agent",
            workflow_decision="document_containment_not_executed",
            orchestration_reason="Containment was not executed. Send to Reporting Agent to document the reason and residual risk.",
            decision_point="Containment not executed routing",
            policy_reference=[
                "Appendix U: Containment Action Playbook",
                "Appendix J: Post-Incident Inquiry Report Requirements"
            ]
        )

    return None


def route_from_missing_evidence(context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if context["current_stage"] != "more_evidence_required" and not context["missing_evidence_required"]:
        return None

    return build_route(
        next_agent="triage_data_collection_agent",
        workflow_decision="collect_missing_evidence",
        orchestration_reason=(
            "More evidence is required before investigation can continue. Route to the planned "
            "Triage Data Collection Agent; until it exists, this may temporarily map to triage_agent."
        ),
        decision_point="Missing evidence routing",
        policy_reference=[
            "Appendix O: Missing Evidence Request Rules",
            "Appendix T: Workflow-to-Policy Mapping"
        ]
    )


def route_from_playbook_pivot(context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if context["current_stage"] != "playbook_pivot_required" and not context["playbook_pivot_required"]:
        return None

    recommended_playbook = context["recommended_playbook"] or "an updated investigation playbook"

    return build_route(
        next_agent="investigation_agent",
        workflow_decision="continue_with_new_playbook",
        orchestration_reason=f"Investigation requires a playbook pivot. Continue investigation with {recommended_playbook}.",
        decision_point="Playbook pivot routing",
        policy_reference=[
            "Appendix P: Investigation Playbook Pivot Rules",
            "Appendix T: Workflow-to-Policy Mapping"
        ]
    )


def build_input_summary(context: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "current_stage": context["current_stage"],
        "agent_completed": context["agent_completed"],
        "severity": context["severity"],
        "confidence": context["confidence"],
        "next_action": context["next_action"],
        "approval_status": context["approval_status"],
        "approval_type": context["approval_type"],
        "containment_required": context["containment_required"],
        "containment_status": context["containment_status"],
        "soc_analyst_approval_status": context["soc_analyst_approval_status"],
        "investigation_status": context["investigation_status"],
        "report_status": context["report_status"],
        "learning_update_status": context["learning_update_status"],
        "missing_evidence_count": len(context["missing_evidence"]),
        "playbook_pivot_required": context["playbook_pivot_required"],
        "recommended_playbook": context["recommended_playbook"]
    }


def build_orchestration_warnings(context: Dict[str, Any]) -> List[str]:
    warnings = []
    current_stage = context["current_stage"]

    if not context["incident_id"]:
        warnings.append("missing incident_id")

    if current_stage in ["triage_completed", "investigation_completed"]:
        if not context["severity"]:
            warnings.append("missing severity after triage/investigation")

        if not context["confidence"]:
            warnings.append("missing confidence after triage/investigation")

    if (
        (context["approval_status"] == "approved" or current_stage == "approved")
        and not context["approval_type"]
    ):
        warnings.append("approval_status = approved but no approval_type")

    if context["playbook_pivot_required"] and not context["recommended_playbook"]:
        warnings.append("playbook_pivot_required = true but no recommended_playbook")

    if current_stage == "more_evidence_required" and len(context["missing_evidence"]) == 0:
        warnings.append("more_evidence_required but no missing_evidence")

    if is_available(context["missing_evidence_request"]) and len(context["missing_evidence"]) == 0:
        warnings.append("missing_evidence_request exists but has no specific missing_evidence")

    if (
        context["containment_approval_pending"]
        and not context["containment_action"]
        and not context["containment_recommendation"]
    ):
        warnings.append("containment_approval_pending but no containment action or containment recommendation")

    return warnings


def build_audit_record(
    case_data: Dict[str, Any],
    context: Dict[str, Any],
    decision: Dict[str, Any]
) -> Dict[str, Any]:
    incident_id = context["incident_id"] or "UNKNOWN"

    return {
        "audit_id": f"AUDIT-{incident_id}-ORCHESTRATION-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
        "incident_id": context["incident_id"],
        "alert_id": context["alert_id"],
        "agent_name": "orchestration_agent",
        "decision_point": decision["decision_point"],
        "decision_made": decision["workflow_decision"],
        "next_agent": decision["next_agent"],
        "policy_reference": decision["policy_reference"],
        "human_review_required": decision["human_review_required"],
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "input_summary": build_input_summary(context)
    }


def build_decision(
    case_data: Dict[str, Any],
    context: Dict[str, Any],
    route: Dict[str, Any]
) -> Dict[str, Any]:
    warnings = build_orchestration_warnings(context)
    input_summary = build_input_summary(context)

    orchestration_result = {
        "current_stage": context["current_stage"],
        "next_agent": route["next_agent"],
        "workflow_decision": route["workflow_decision"],
        "orchestration_reason": route["orchestration_reason"],
        "severity": context["severity"],
        "confidence": context["confidence"],
        "next_action": context["next_action"],
        "approval_status": context["approval_status"],
        "approval_type": context["approval_type"],
        "investigation_status": context["investigation_status"],
        "report_status": context["report_status"],
        "containment_required": context["containment_required"],
        "containment_approval_status": context["containment_approval_status"],
        "soc_analyst_approval_status": context["soc_analyst_approval_status"],
        "containment_status": context["containment_status"],
        "containment_completed": context["containment_completed"],
        "containment_not_executed": context["containment_not_executed"],
        "required_evidence_complete": context["required_evidence_complete"],
        "missing_evidence": context["missing_evidence"],
        "missing_evidence_request": context["missing_evidence_request"],
        "suggested_data_source": context["suggested_data_source"],
        "playbook_pivot_required": context["playbook_pivot_required"],
        "recommended_playbook": context["recommended_playbook"],
        "learning_update_status": context["learning_update_status"],
        "learning_approval_status": context["learning_approval_status"],
        "policy_reference": route["policy_reference"],
        "human_review_required": route["human_review_required"],
        "decision_point": route["decision_point"],
        "input_summary": input_summary
    }

    decision = {
        **case_data,
        "orchestration_result": orchestration_result,
        "orchestration_warnings": warnings,
        "next_agent": route["next_agent"],
        "workflow_decision": route["workflow_decision"],
        "orchestration_reason": route["orchestration_reason"]
    }

    decision["orchestration_audit_record"] = build_audit_record(
        case_data,
        context,
        route
    )

    return decision


def decide_next_agent(case_data: Dict[str, Any]) -> Dict[str, Any]:
    context = extract_routing_context(case_data)

    route = (
        route_from_approval(context)
        or route_from_containment(context)
        or route_from_missing_evidence(context)
        or route_from_playbook_pivot(context)
        or route_from_enrichment(context)
        or route_from_triage(context)
        or route_from_investigation(context)
        or route_from_reporting(context)
        or build_route(
            next_agent="end",
            workflow_decision="fallback_end",
            orchestration_reason=(
                f"Unknown or unsupported workflow stage: {context['current_stage']}. "
                "Ending workflow safely."
            ),
            decision_point="Fallback routing",
            policy_reference=["Appendix T: Workflow-to-Policy Mapping"]
        )
    )

    return build_decision(case_data, context, route)


def main() -> None:
    input_file = DEFAULT_INPUT_FILE

    if len(sys.argv) > 1:
        input_file = sys.argv[1]

    if not os.path.exists(input_file):
        raise FileNotFoundError(f"Input file not found: {input_file}")

    case_data = load_json(input_file)
    orchestration_result = decide_next_agent(case_data)

    save_json(orchestration_result)

    print(json.dumps(orchestration_result, indent=4))
    print()
    print(f"Orchestration decision saved to: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
