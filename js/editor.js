import { agentStageData } from "./data.js";
import { applicationState } from "./state.js";
import { showToast } from "./utils.js";
import {
    buildDocBlocks,
    currentTicketId,
    docKey,
    getReportList,
    handleDocAction,
    renderDocTable,
    reportKey,
} from "./documents.js";
let currentReviewStage = null;
let currentReviewReportId = null;
function renderReviewContent(stage, reportId) {
    const container = document.getElementById("reviewContent");
    container.innerHTML = "";
    buildDocBlocks(stage, reportId).forEach((b) => {
        if (b.type === "title" || b.type === "heading") {
            const h = document.createElement("h4");
            h.textContent = b.text;
            container.appendChild(h);
        } else if (b.type === "meta") {
            const p = document.createElement("p");
            p.textContent = b.rows.map((r) => r[0] + ": " + r[1]).join(" · ");
            container.appendChild(p);
        } else if (b.type === "paragraph") {
            const p = document.createElement("p");
            p.textContent = b.text || "—";
            container.appendChild(p);
        } else if (b.type === "list") {
            const ul = document.createElement("ul");
            (b.items && b.items.length ? b.items : ["None"]).forEach((it) => {
                const li = document.createElement("li");
                li.textContent = it;
                ul.appendChild(li);
            });
            container.appendChild(ul);
        } else if (b.type === "table") {
            const table = document.createElement("table"),
                thead = document.createElement("thead"),
                htr = document.createElement("tr");
            b.header.forEach((h) => {
                const th = document.createElement("th");
                th.textContent = h;
                htr.appendChild(th);
            });
            thead.appendChild(htr);
            table.appendChild(thead);
            const tb = document.createElement("tbody");
            (b.rows && b.rows.length ? b.rows : [["—"]]).forEach((r) => {
                const tr = document.createElement("tr");
                r.forEach((c) => {
                    const td = document.createElement("td");
                    td.textContent = c;
                    tr.appendChild(td);
                });
                tb.appendChild(tr);
            });
            table.appendChild(tb);
            container.appendChild(table);
        }
    });
}
function openReviewModal(stage, reportId) {
    currentReviewStage = stage;
    currentReviewReportId = reportId;
    const rep = getReportList(stage).find((r) => r.id === reportId);
    document.getElementById("reviewModalTitle").textContent =
        "Open & Edit — " + (rep ? rep.name : agentStageData[stage].title);
    renderReviewContent(stage, reportId);
    document.getElementById("reviewAmendments").value =
        applicationState.documentEdits[
            reportKey(currentTicketId(), stage, reportId)
        ] || "";
    document.getElementById("reviewModalOverlay").hidden = false;
}
function closeReviewModal() {
    document.getElementById("reviewModalOverlay").hidden = true;
    currentReviewStage = null;
    currentReviewReportId = null;
}
function commitReviewAmendments(stage, reportId) {
    const ticket = currentTicketId(),
        text = document.getElementById("reviewAmendments").value.trim(),
        key = reportKey(ticket, stage, reportId),
        changed = (applicationState.documentEdits[key] || "") !== text;
    if (text) applicationState.documentEdits[key] = text;
    else delete applicationState.documentEdits[key];
    if (changed) {
        ["docx", "pdf"].forEach((format) => {
            delete applicationState.generatedDocuments[
                docKey(ticket, stage, reportId, format)
            ];
        });
        if (applicationState.activeWorkflowStage === stage)
            renderDocTable(stage);
    }
    return changed;
}
function saveReviewAmendments() {
    if (!currentReviewStage || !currentReviewReportId) return;
    const stage = currentReviewStage,
        reportId = currentReviewReportId,
        ticket = currentTicketId();
    commitReviewAmendments(stage, reportId);
    applicationState.reportSaves[reportKey(ticket, stage, reportId)] = {
        time: new Date().toLocaleTimeString("en-US", {
            hour: "numeric",
            minute: "2-digit",
        }),
        analyst: "Soong Yang",
    };
    if (applicationState.activeWorkflowStage === stage) renderDocTable(stage);
    const rep = getReportList(stage).find((r) => r.id === reportId);
    showToast(
        "Saved",
        `${rep ? rep.name : agentStageData[stage].title} has been saved.`,
    );
    closeReviewModal();
}
document
    .getElementById("reviewModalClose")
    .addEventListener("click", closeReviewModal);
document
    .getElementById("reviewCloseBtn")
    .addEventListener("click", closeReviewModal);
document
    .getElementById("reviewSaveBtn")
    .addEventListener("click", saveReviewAmendments);
document.getElementById("reviewDownloadDocx").addEventListener("click", () => {
    if (!currentReviewStage || !currentReviewReportId) return;
    commitReviewAmendments(currentReviewStage, currentReviewReportId);
    handleDocAction(currentReviewStage, currentReviewReportId, "docx");
});
document.getElementById("reviewDownloadPdf").addEventListener("click", () => {
    if (!currentReviewStage || !currentReviewReportId) return;
    commitReviewAmendments(currentReviewStage, currentReviewReportId);
    handleDocAction(currentReviewStage, currentReviewReportId, "pdf");
});
document.getElementById("reviewModalOverlay").addEventListener("click", (e) => {
    if (e.target === document.getElementById("reviewModalOverlay"))
        closeReviewModal();
});
document.addEventListener("keydown", (e) => {
    if (
        e.key === "Escape" &&
        !document.getElementById("reviewModalOverlay").hidden
    )
        closeReviewModal();
});

export function initialiseDocumentEditor() {
    // Editor listeners are registered once when this module loads.
}

export { openReviewModal };
