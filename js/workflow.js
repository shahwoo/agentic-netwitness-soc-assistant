import { agentStageData, decisionOutcomeMap, stageDocData } from "./data.js";
import { applicationState } from "./state.js";
import { setText } from "./utils.js";
import { currentTicketId, decisionKey, renderDocTable } from "./documents.js";
function renderAgentStage(name) {
    const data = agentStageData[name];
    if (!data) return;
    document
        .querySelectorAll(".workflow-link")
        .forEach((stage) =>
            stage.classList.toggle(
                "selected",
                stage.dataset.workflowStage === name,
            ),
        );
    applicationState.activeWorkflowStage = name;
    setText("stageDetailTitle", data.title);
    document
        .getElementById("agentRing")
        .style.setProperty("--agent-pct", data.pct);
    setText("agentRingPct", data.pct + "%");
    setText("agentReportTime", "Last run " + data.lastRun);
    const headStatus = document.getElementById("agentHeadStatus");
    if (data.headStatus.label === "Completed") {
        headStatus.hidden = true;
    } else {
        headStatus.hidden = false;
        headStatus.textContent = data.headStatus.label;
        headStatus.className = "stage-status " + data.headStatus.tone;
    }
    setText("agentMissingFields", data.missingFields);
    const nextStep = document.getElementById("agentNextStep");
    nextStep.textContent = data.nextStep.label;
    nextStep.className = "stage-status " + data.nextStep.tone;
    const aiText = document.getElementById("aiSummaryText"),
        fallbackTag = document.getElementById("aiFallbackTag");
    if (data.ai.available) {
        aiText.textContent = data.ai.text;
        fallbackTag.hidden = !data.ai.fallback;
    } else {
        aiText.textContent =
            "An AI-generated summary is not available for this stage yet — showing the stage output above only.";
        fallbackTag.hidden = false;
    }
    const warnEl = document.getElementById("agentWarnings"),
        warnHead = document.getElementById("agentWarningHead"),
        warnIcon = document.getElementById("warnIcon"),
        decisionActions = document.getElementById("decisionActions"),
        record = data.decision
            ? applicationState.caseDecisions[
                  decisionKey(currentTicketId(), name)
              ]
            : null;
    warnEl.classList.remove("tone-good", "tone-bad");
    if (record) {
        const outcome = decisionOutcomeMap[record.type],
            toneCls =
                record.type === "approve"
                    ? "tone-good"
                    : record.type === "reject"
                      ? "tone-bad"
                      : null;
        if (toneCls) warnEl.classList.add(toneCls);
        warnEl.hidden = false;
        warnIcon.textContent =
            record.type === "approve"
                ? "✓"
                : record.type === "reject"
                  ? "✕"
                  : "↻";
        warnHead.textContent = outcome.resultLabel;
        setText(
            "agentWarningText",
            `${record.analyst} · ${record.timestamp}${record.comment ? " — “" + record.comment + "”" : ""}`,
        );
        decisionActions.hidden = true;
        nextStep.textContent = outcome.nextStep.label;
        nextStep.className = "stage-status " + outcome.nextStep.tone;
    } else {
        warnEl.hidden = !data.warning;
        warnHead.textContent = "Action required";
        warnIcon.textContent = "⚠";
        if (data.warning) setText("agentWarningText", data.warning);
        decisionActions.hidden = !data.decision;
    }
    const docCard = document.getElementById("docTableCard");
    docCard.hidden = !stageDocData[name];
    if (stageDocData[name]) renderDocTable(name);
}
function showWorkflowStage(name, updateRoute = true) {
    if (!agentStageData[name]) return;
    renderAgentStage(name);
    if (updateRoute) {
        const ticket = document.querySelector(
            ".case-title-meta span:first-child",
        ).textContent;
        location.hash = "case-" + ticket + "/" + name;
    }
    document
        .getElementById("stageDetail")
        .scrollIntoView({ behavior: "smooth", block: "center" });
}
export function initialiseWorkflow() {
    document
        .querySelectorAll(".workflow-link[data-workflow-stage]")
        .forEach((button) => {
            button.addEventListener("click", () =>
                showWorkflowStage(button.dataset.workflowStage),
            );
        });
}

export { renderAgentStage, showWorkflowStage };
