import { agentStageData, decisionOutcomeMap } from "./data.js";
import { applicationState, currentUser } from "./state.js";
import { getElement, showToast } from "./utils.js";
import {
    currentTicketId,
    decisionKey,
    invalidateStageDocs,
} from "./documents.js";
import { renderAgentStage } from "./workflow.js";

const chatEl = getElement;
let pendingDecision = null;
function openDecisionModal(stage, type) {
    pendingDecision = { stage, type };
    const data = agentStageData[stage],
        title = chatEl("modalTitle"),
        text = chatEl("modalText"),
        factRow = chatEl("modalFactRow"),
        examples = chatEl("modalExamples"),
        label = chatEl("modalCommentLabel"),
        comment = chatEl("modalComment"),
        err = chatEl("modalError"),
        confirm = chatEl("modalConfirm");
    comment.value = "";
    err.classList.remove("show");
    err.textContent = "";
    confirm.className = "cta";
    if (type === "approve") {
        title.textContent = "Approve & Continue";
        text.textContent = `Approve endpoint isolation for host ${data.decision.host}? This authorises the recommended containment action and allows the workflow to continue.`;
        factRow.hidden = false;
        factRow.innerHTML = `<div><span>Affected host</span><b>${data.decision.host}</b></div><div><span>Proposed action</span><b>${data.decision.action}</b></div>`;
        examples.hidden = true;
        examples.innerHTML = "";
        label.textContent = "Comment (optional)";
        confirm.textContent = "Approve & Continue Workflow";
    } else if (type === "investigate") {
        title.textContent = "Request Further Analysis";
        text.textContent =
            "Describe what additional investigation is required before a containment decision can be made.";
        factRow.hidden = true;
        factRow.innerHTML = "";
        examples.hidden = false;
        examples.innerHTML = [
            "Review related process activity",
            "Check lateral movement",
            "Retrieve additional endpoint telemetry",
            "Validate the malicious file execution chain",
        ]
            .map((x) => "<li>" + x + "</li>")
            .join("");
        label.textContent = "Investigation request (required)";
        confirm.textContent = "Send to Investigation Agent";
    } else {
        title.textContent = "Reject & Return to Triage";
        text.textContent =
            "Reject the recommended endpoint isolation? A reason is required, and the case will return to triage.";
        factRow.hidden = true;
        factRow.innerHTML = "";
        examples.hidden = true;
        examples.innerHTML = "";
        label.textContent = "Rejection reason (required)";
        confirm.textContent = "Reject & Return to Triage";
        confirm.className = "cta cta-destructive";
    }
    chatEl("decisionModalOverlay").hidden = false;
    comment.focus();
}
function closeDecisionModal() {
    chatEl("decisionModalOverlay").hidden = true;
    pendingDecision = null;
}
function confirmDecision() {
    if (!pendingDecision) return;
    const { stage, type } = pendingDecision,
        comment = chatEl("modalComment").value.trim(),
        err = chatEl("modalError");
    if (type !== "approve" && !comment) {
        err.textContent =
            type === "reject"
                ? "A rejection reason is required."
                : "Please describe the investigation that is required.";
        err.classList.add("show");
        return;
    }
    err.classList.remove("show");
    const ticket = currentTicketId(),
        record = {
            type,
            analyst: "Soong Yang",
            timestamp: new Date().toLocaleString("en-US", {
                month: "numeric",
                day: "numeric",
                year: "numeric",
                hour: "numeric",
                minute: "2-digit",
            }),
            comment,
        };
    applicationState.caseDecisions[decisionKey(ticket, stage)] = record;
    invalidateStageDocs(stage);
    closeDecisionModal();
    showToast(
        decisionOutcomeMap[type].toast,
        comment ? `“${comment}”` : `Decision recorded for ${ticket}.`,
    );
    if (applicationState.activeWorkflowStage === stage) renderAgentStage(stage);
}
document
    .querySelectorAll(".decision-btn")
    .forEach((btn) =>
        btn.addEventListener("click", () =>
            openDecisionModal(
                applicationState.activeWorkflowStage,
                btn.dataset.decision,
            ),
        ),
    );
chatEl("modalCancel").addEventListener("click", closeDecisionModal);
chatEl("modalClose").addEventListener("click", closeDecisionModal);
chatEl("modalConfirm").addEventListener("click", confirmDecision);
chatEl("decisionModalOverlay").addEventListener("click", (e) => {
    if (e.target === chatEl("decisionModalOverlay")) closeDecisionModal();
});
document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && !chatEl("decisionModalOverlay").hidden)
        closeDecisionModal();
});
const incidentsFact = document.getElementById("incidentsFact"),
    incidentsTrigger = document.getElementById("incidentsTrigger"),
    incidentsPopover = document.getElementById("incidentsPopover"),
    incidentsPopoverClose = document.getElementById("incidentsPopoverClose");
incidentsTrigger.addEventListener("click", (e) => {
    e.stopPropagation();
    incidentsPopover.hidden = !incidentsPopover.hidden;
});
incidentsPopoverClose.addEventListener("click", (e) => {
    e.stopPropagation();
    incidentsPopover.hidden = true;
});
document.addEventListener("click", (e) => {
    if (!incidentsPopover.hidden && !incidentsFact.contains(e.target))
        incidentsPopover.hidden = true;
});
document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && !incidentsPopover.hidden)
        incidentsPopover.hidden = true;
});

export function initialiseDecisionModals() {
    // Modal listeners are registered once when this module loads.
}
