import { applicationState } from "./state.js";
import { setText, showToast } from "./utils.js";
import {
    filterRows,
    rowList,
    ticketSearch,
    globalSearch,
    filterSeverity,
    filterStage,
    filterOwner,
    showAllCasesView,
    configureFilterNavigation,
} from "./filters.js";
import { showWorkflowStage } from "./workflow.js";
import { resetChatForCase } from "./copilot.js";
import { openInvestigationCase } from "./investigation-tabs.js";
const operationsNav = document.getElementById("topOperationsNav"),
    myQueueNav = document.getElementById("topMyQueueNav"),
    stageEls = [...document.querySelectorAll(".pipeline-wrap .stage")];
const operationStages = [
        ["49", "Automated intake", "live"],
        ["1", "1 needs review", "live"],
        ["1", "Enrichment running", "live"],
        ["0", "No active cases", ""],
        ["0", "No reports ready", ""],
    ],
    personalStages = [
        ["0", "No assigned cases", ""],
        ["1", "Needs your review", "live"],
        ["1", "Enrichment running", "action"],
        ["1", "Active investigation", "live"],
        ["1", "Draft needs review", "live"],
    ];

function applyStages(data) {
    stageEls.forEach((stage, i) => {
        stage.className = "stage" + (data[i][2] ? " " + data[i][2] : "");
        stage.querySelector(".node").textContent = data[i][0];
        stage.querySelector("small").textContent = data[i][1];
    });
}
function setView(view) {
    const personal = view === "mine",
        contentEl = document.querySelector(".content");
    contentEl.classList.remove("case-mode");
    contentEl.classList.remove("cases-mode");
    contentEl.classList.toggle("operations-mode", !personal);
    filterOwner.value = personal ? "mine" : "";
    operationsNav.classList.toggle("active", !personal);
    myQueueNav.classList.toggle("active", personal);
    document.getElementById("topAllCasesNav").classList.remove("active");
    setText("pageTitle", personal ? "My Workspace" : "Operations overview");
    setText(
        "viewTitle",
        personal ? "Your assigned tickets" : "System operations",
    );
    setText(
        "viewCopy",
        personal
            ? "Cases owned by you and the actions currently available."
            : "All tickets and workflow activity across the SOC.",
    );
    setText(
        "heroEyebrow",
        personal ? "Your next action" : "Highest-priority ticket",
    );
    setText(
        "heroWhy",
        personal
            ? "This assigned critical ticket is waiting for your decision."
            : "Critical severity · Threat Intelligence Enrichment complete · Approval required",
    );
    setText("metric1Label", personal ? "Assigned cases" : "Critical cases");
    setText("metric1Value", personal ? "10" : "6");
    setText(
        "metric1Copy",
        personal
            ? "Across five workflow stages"
            : "Requires immediate attention",
    );
    setText(
        "metric2Label",
        personal ? "Requires my action" : "Approval required",
    );
    setText("metric2Value", "1");
    setText(
        "metric2Copy",
        personal
            ? "Awaiting your review or approval"
            : "Awaiting SOC analyst approval",
    );
    setText(
        "metric3Label",
        personal ? "Agent work-in-progress" : "Unassigned cases",
    );
    setText("metric3Value", personal ? "1" : "16");
    setText(
        "metric3Copy",
        personal
            ? "Currently being processed by an agent"
            : "Waiting for an owner",
    );
    setText(
        "pipelineTitle",
        personal ? "My cases by stage" : "System case pipeline",
    );
    setText(
        "pipelineCopy",
        personal
            ? "10 tickets assigned to you across the investigation workflow"
            : "51 open tickets moving through the investigation workflow",
    );
    setText("queueTitle", personal ? "My tickets" : "Open tickets");
    setText(
        "queueCopy",
        personal
            ? "Assigned to you, ordered by severity and required action"
            : "All system tickets, ranked by severity and required action",
    );
    document.querySelector(".foot").textContent = personal
        ? "Showing all 10 of your assigned tickets · Use All Cases to see the full queue"
        : "Showing the 26 most relevant of 51 open tickets · Use My Workspace for your assigned work";
    applyStages(personal ? personalStages : operationStages);
    applicationState.selectedQueueFilter = "all";
    filterRows();
}
operationsNav.addEventListener("click", () => {
    location.hash = "";
    setView("operations");
});
myQueueNav.addEventListener("click", () => {
    location.hash = "my-queue";
    setView("mine");
});

function openCase(ticket, updateRoute = true) {
    if (updateRoute) location.hash = "case-" + ticket;
    const row = rowList.find(
        (item) => item.querySelector(".id").textContent.trim() === ticket,
    );
    if (row) {
        document.querySelector(".case-crumb span:last-child").textContent =
            ticket;
        document.querySelector(
            ".case-title-meta span:first-child",
        ).textContent = ticket;
        document.querySelector(".case-header h2").textContent =
            row.querySelector(".case b").textContent;
        document.querySelector(".case-fact:nth-child(1) b").textContent =
            row.children[4].textContent.trim();
        document.querySelector(".case-fact:nth-child(2) b").textContent =
            row.children[3].textContent.trim();
    }
    document.querySelector(".content").classList.remove("operations-mode");
    document.querySelector(".content").classList.add("case-mode");
    applicationState.activeCaseId = ticket;
    setText("pageTitle", "Case Workspace");
    operationsNav.classList.remove("active");
    myQueueNav.classList.add("active");
    showWorkflowStage("threat-intelligence", false);
    resetChatForCase(
        ticket,
        row ? row.querySelector(".case b").textContent : "",
    );
    openInvestigationCase(ticket);
    window.scrollTo(0, 0);
}
rowList.forEach((row) =>
    row.addEventListener("click", (event) => {
        if (event.target.closest("button")) return;
        openCase(row.querySelector(".id").textContent.trim());
    }),
);
document.getElementById("backToQueue").addEventListener("click", () => {
    location.hash = "my-queue";
    setView("mine");
});
function applyRoute() {
    if (location.hash.startsWith("#case-")) {
        const parts = location.hash.slice(6).split("/");
        openCase(parts[0], false);
        if (parts[1]) showWorkflowStage(parts[1], false);
    } else if (location.hash === "#all-cases") {
        showAllCasesView();
    } else {
        setView(location.hash === "#my-queue" ? "mine" : "operations");
    }
}

export function initialiseNavigation() {
    configureFilterNavigation({ setView });
    window.addEventListener("hashchange", applyRoute);
    applyRoute();
}

export { applyRoute, myQueueNav, openCase, operationsNav, setView };
