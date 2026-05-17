import json
import os
import sys
from typing import Any, Dict, Optional


DEFAULT_INPUT_FILE = "outputs/enriched_alert.json"
OUTPUT_FILE = "outputs/orchestration_decision.json"


def load_json(file_path: str) -> Dict[str, Any]:
    with open(file_path, "r", encoding="utf-8") as file:
        return json.load(file)


def save_json(data: Dict[str, Any]) -> None:
    os.makedirs("outputs", exist_ok=True)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=4)


def get_nested_value(data: Dict[str, Any], key_path: list, fallback: Optional[Any] = None) -> Any:
    current_value = data

    for key in key_path:
        if not isinstance(current_value, dict):
            return fallback

        current_value = current_value.get(key)

        if current_value is None:
            return fallback

    return current_value


def decide_next_agent(case_data: Dict[str, Any]) -> Dict[str, Any]:
    current_stage = case_data.get("current_stage", "unknown_stage")

    severity = (
        case_data.get("severity")
        or get_nested_value(case_data, ["triage_result", "severity"])
    )

    confidence = (
        case_data.get("confidence")
        or get_nested_value(case_data, ["triage_result", "confidence"])
    )

    next_action = (
        case_data.get("next_action")
        or get_nested_value(case_data, ["triage_result", "next_action"])
    )

    approval_status = case_data.get("approval_status")

    investigation_status = (
        case_data.get("investigation_status")
        or get_nested_value(case_data, ["investigation_result", "investigation_status"])
    )

    report_status = (
        case_data.get("report_status")
        or get_nested_value(case_data, ["draft_report", "report_status"])
    )

    next_agent = "end"
    workflow_decision = "end_workflow"
    orchestration_reason = "No valid next step found."

    if current_stage == "enrichment_completed":
        next_agent = "triage_agent"
        workflow_decision = "start_triage"
        orchestration_reason = "Threat intelligence enrichment is completed. Send case to Triage Agent."

    elif current_stage == "triage_completed":
        if severity in ["High", "Critical"] or next_action in [
            "Send to Investigation Agent",
            "More investigation required"
        ]:
            next_agent = "investigation_agent"
            workflow_decision = "start_investigation"
            orchestration_reason = "Triage result indicates that deeper investigation is required."

        elif severity in ["Low", "Medium"] or next_action == "Review by SOC Analyst":
            next_agent = "reporting_agent"
            workflow_decision = "generate_triage_report"
            orchestration_reason = "Triage result does not require deep investigation, but a report or summary should still be generated."

        else:
            next_agent = "end"
            workflow_decision = "end_after_triage"
            orchestration_reason = "Triage completed, but no clear next action was provided."

    elif current_stage == "investigation_completed":
        next_agent = "reporting_agent"
        workflow_decision = "generate_report"
        orchestration_reason = "Investigation is completed. Send case to Reporting Agent."

    elif current_stage == "report_completed" or report_status == "draft_ready":
        next_agent = "approval_step"
        workflow_decision = "request_soc_approval"
        orchestration_reason = "Draft report is ready. Send to SOC Analyst for approval."

    elif current_stage == "approved" or approval_status == "approved":
        next_agent = "end"
        workflow_decision = "finalise_case"
        orchestration_reason = "SOC Analyst approved the report. Workflow can be finalised."

    elif current_stage == "rejected" or approval_status == "rejected":
        next_agent = "end"
        workflow_decision = "record_rejection"
        orchestration_reason = "SOC Analyst rejected the output. Record rejection reason and stop the workflow."

    elif current_stage == "changes_required" or approval_status == "changes_required":
        next_agent = "reporting_agent"
        workflow_decision = "revise_report"
        orchestration_reason = "SOC Analyst requested changes. Send case back to Reporting Agent for revision."

    elif (
        current_stage == "more_investigation_required"
        or approval_status == "more_investigation_required"
        or next_action == "More investigation required"
    ):
        next_agent = "investigation_agent"
        workflow_decision = "continue_investigation"
        orchestration_reason = "SOC Analyst requested further investigation. Send case back to Investigation Agent."

    else:
        next_agent = "end"
        workflow_decision = "fallback_end"
        orchestration_reason = f"Unknown or unsupported workflow stage: {current_stage}. Ending workflow safely."

    result = {
        **case_data,

        "orchestration_result": {
            "current_stage": current_stage,
            "next_agent": next_agent,
            "workflow_decision": workflow_decision,
            "orchestration_reason": orchestration_reason,
            "severity": severity,
            "confidence": confidence,
            "next_action": next_action,
            "approval_status": approval_status,
            "investigation_status": investigation_status,
            "report_status": report_status
        },

        "next_agent": next_agent,
        "workflow_decision": workflow_decision,
        "orchestration_reason": orchestration_reason
    }

    return result


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