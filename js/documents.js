import { agentStageData, decisionOutcomeMap, stageDocData } from "./data.js";
import { applicationState } from "./state.js";
import { formatTime as formatGeneratedAt, showToast } from "./utils.js";
import { openReviewModal } from "./editor.js";
function currentTicketId() {
    return document.querySelector(".case-title-meta span:first-child")
        .textContent;
}
function decisionKey(ticket, stage) {
    return ticket + "::" + stage;
}
const reportIconSvg = {
    document:
        '<svg viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>',
    list: '<svg viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="8" y1="6" x2="21" y2="6"/><line x1="8" y1="12" x2="21" y2="12"/><line x1="8" y1="18" x2="21" y2="18"/><line x1="3" y1="6" x2="3.01" y2="6"/><line x1="3" y1="12" x2="3.01" y2="12"/><line x1="3" y1="18" x2="3.01" y2="18"/></svg>',
    person: '<svg viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>',
    clipboard:
        '<svg viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 2h6a1 1 0 0 1 1 1v2H8V3a1 1 0 0 1 1-1z"/><rect x="5" y="4" width="14" height="17" rx="2"/><line x1="9" y1="11" x2="15" y2="11"/><line x1="9" y1="15" x2="15" y2="15"/></svg>',
    search: '<svg viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>',
    code: '<svg viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>',
};
const docActionIconSvg = {
    pencil: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>',
    word: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>',
    pdf: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>',
    clock: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>',
    download:
        '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>',
};

function docKey(ticket, stage, reportId, format) {
    return ticket + "::" + stage + "::" + reportId + "::" + format;
}
function reportKey(ticket, stage, reportId) {
    return ticket + "::" + stage + "::" + reportId;
}
function getReportList(stage) {
    const extra = stageDocData[stage];
    if (!extra) return [];
    return extra.reports || [];
}
function getJsonItem(stage) {
    const extra = stageDocData[stage];
    if (!extra || !extra.json) return null;
    return {
        id: "json",
        type: "json",
        name: extra.json.name,
        fileSlug: extra.json.slug,
        description: extra.json.description,
    };
}
function getFileList(stage) {
    const j = getJsonItem(stage),
        reports = getReportList(stage).map((r) => ({ ...r, type: "report" }));
    return j ? [j, ...reports] : reports;
}
function buildJsonPayload(stage) {
    const extra = stageDocData[stage];
    if (stage === "parsing")
        return {
            entities: extra.entities,
            normalised: extra.normalised,
            warnings: extra.warnings,
            limitations: extra.limitations,
        };
    if (stage === "triage")
        return {
            severity: extra.severity,
            confidence: extra.confidence,
            classification: extra.classification,
            rationale: extra.rationale,
            recommendedAction: extra.recommendedAction,
            approvalStatus: extra.approvalStatus,
        };
    if (stage === "threat-intelligence")
        return {
            iocs: extra.iocs,
            providers: extra.providers,
            conclusion: extra.conclusion,
        };
    if (stage === "investigation")
        return {
            verdict: extra.verdict,
            scenario: extra.scenario,
            evidence: extra.evidence,
            timeline: extra.timeline,
            iocs: extra.iocs,
            mitre: extra.mitre,
            gaps: extra.gaps,
            nextAction: extra.nextAction,
        };
    if (stage === "reporting")
        return {
            executiveSummary: extra.executiveSummary,
            technicalFindings: extra.technicalFindings,
            socReview: extra.socReview,
            finalConclusion: extra.finalConclusion,
            validationWarnings: extra.validationWarnings,
        };
    return {};
}
function downloadJson(stage) {
    const ticket = currentTicketId(),
        extra = stageDocData[stage],
        payload = buildJsonPayload(stage),
        blob = new Blob([JSON.stringify(payload, null, 2)], {
            type: "application/json",
        }),
        filename = `${ticket}_${extra.json.slug}.json`;
    triggerDownload(blob, filename);
    showToast("Download ready", `${filename} downloaded for ${ticket}.`);
}
function reportStatus(stage, reportId) {
    const ticket = currentTicketId(),
        rKey = reportKey(ticket, stage, reportId),
        data = agentStageData[stage];
    if (applicationState.documentsGenerating[rKey])
        return { label: "Generating", tone: "warn" };
    if (applicationState.documentFailures[rKey])
        return { label: "Generation failed", tone: "bad" };
    if (
        stage === "triage" &&
        reportId === "default" &&
        !applicationState.caseDecisions[decisionKey(ticket, "triage")]
    )
        return { label: "Needs your input", tone: "warn" };
    if (data.missingFields && data.missingFields !== "None")
        return { label: "Missing information", tone: "warn" };
    if (applicationState.reportSaves[rKey])
        return { label: "Edited", tone: "good" };
    if (stage === "triage" && reportId === "default")
        return { label: "Ready to export", tone: "good" };
    return { label: "Draft ready", tone: "" };
}
function invalidateStageDocs(stage) {
    const ticket = currentTicketId();
    getReportList(stage).forEach((rep) => {
        const rKey = reportKey(ticket, stage, rep.id);
        delete applicationState.reportSaves[rKey];
        delete applicationState.documentFailures[rKey];
        ["docx", "pdf"].forEach(
            (format) =>
                delete applicationState.generatedDocuments[
                    docKey(ticket, stage, rep.id, format)
                ],
        );
    });
    if (applicationState.activeWorkflowStage === stage && stageDocData[stage])
        renderDocTable(stage);
}
function buildDocBlocks(stage, reportId) {
    const ticket = currentTicketId(),
        titleEl = document.querySelector(".case-header h2"),
        caseTitle = titleEl ? titleEl.textContent : "",
        data = agentStageData[stage],
        extra = stageDocData[stage],
        reportDef = (extra.reports || []).find((r) => r.id === reportId),
        now = new Date().toLocaleString("en-US", {
            month: "numeric",
            day: "numeric",
            year: "numeric",
            hour: "numeric",
            minute: "2-digit",
        });
    const blocks = [
        { type: "title", text: reportDef ? reportDef.name : extra.docName },
        {
            type: "meta",
            rows: [
                ["Ticket ID", ticket],
                ["Case", caseTitle],
                ["Stage", data.title],
                ["Generated", now],
            ],
        },
    ];
    if (stage === "reporting") {
        if (reportId === "executive-summary") {
            blocks.push({ type: "heading", text: "Executive Summary" });
            blocks.push({ type: "paragraph", text: extra.executiveSummary });
        } else if (reportId === "technical-findings") {
            blocks.push({ type: "heading", text: "Technical Findings" });
            blocks.push({ type: "list", items: extra.technicalFindings });
        } else if (reportId === "soc-review") {
            blocks.push({ type: "heading", text: "SOC Analyst Review" });
            blocks.push({ type: "paragraph", text: extra.socReview });
        } else {
            blocks.push({ type: "heading", text: "Executive Summary" });
            blocks.push({ type: "paragraph", text: extra.executiveSummary });
            blocks.push({ type: "heading", text: "Technical Findings" });
            blocks.push({ type: "list", items: extra.technicalFindings });
            blocks.push({ type: "heading", text: "SOC Analyst Review" });
            blocks.push({ type: "paragraph", text: extra.socReview });
            blocks.push({ type: "heading", text: "Final Conclusion" });
            blocks.push({ type: "paragraph", text: extra.finalConclusion });
            blocks.push({ type: "heading", text: "Validation Warnings" });
            blocks.push({ type: "list", items: extra.validationWarnings });
        }
    } else {
        blocks.push({ type: "heading", text: "AI-Generated Summary" });
        blocks.push({ type: "paragraph", text: data.ai.text });
        blocks.push({ type: "heading", text: "Missing Fields" });
        blocks.push({ type: "paragraph", text: data.missingFields });
        blocks.push({ type: "heading", text: "Next Step" });
        blocks.push({ type: "paragraph", text: data.nextStep.label });
        if (data.warning) {
            blocks.push({ type: "heading", text: "Action Required" });
            blocks.push({ type: "paragraph", text: data.warning });
        }
        if (stage === "triage") {
            const record =
                applicationState.caseDecisions[decisionKey(ticket, "triage")];
            if (record) {
                const outcome = decisionOutcomeMap[record.type];
                blocks.push({ type: "heading", text: "Analyst Decision" });
                blocks.push({
                    type: "paragraph",
                    text: `${outcome.resultLabel} by ${record.analyst} on ${record.timestamp}.${record.comment ? " Comment: " + record.comment : ""}`,
                });
            }
        }
        if (stage === "threat-intelligence") {
            blocks.push({ type: "heading", text: "Indicators of Compromise" });
            blocks.push({
                type: "table",
                header: ["Indicator", "Type", "Verdict"],
                rows: extra.iocs,
            });
            blocks.push({ type: "heading", text: "Provider Responses" });
            blocks.push({
                type: "table",
                header: ["Provider", "Verdict"],
                rows: extra.providers,
            });
            blocks.push({ type: "heading", text: "Enrichment Conclusion" });
            blocks.push({ type: "paragraph", text: extra.conclusion });
        } else if (stage === "parsing") {
            blocks.push({
                type: "heading",
                text: "Extracted Entities & Indicators",
            });
            blocks.push({
                type: "table",
                header: ["Entity", "Value"],
                rows: extra.entities,
            });
            blocks.push({ type: "heading", text: "Normalised Alert Details" });
            blocks.push({
                type: "table",
                header: ["Field Mapping", "Value"],
                rows: extra.normalised,
            });
            blocks.push({ type: "heading", text: "Parsing Warnings" });
            blocks.push({ type: "list", items: extra.warnings });
            blocks.push({ type: "heading", text: "Source-Data Limitations" });
            blocks.push({ type: "list", items: extra.limitations });
        } else if (stage === "triage") {
            blocks.push({ type: "heading", text: "Severity & Classification" });
            blocks.push({
                type: "table",
                header: ["Field", "Value"],
                rows: [
                    ["Severity", extra.severity],
                    ["Confidence", extra.confidence],
                    ["Classification", extra.classification],
                    ["Recommended action", extra.recommendedAction],
                ],
            });
            blocks.push({ type: "heading", text: "Triage Rationale" });
            blocks.push({ type: "paragraph", text: extra.rationale });
            blocks.push({
                type: "heading",
                text: "Approval & Containment Status",
            });
            blocks.push({ type: "paragraph", text: extra.approvalStatus });
        } else if (stage === "investigation") {
            blocks.push({ type: "heading", text: "Investigation Verdict" });
            blocks.push({ type: "paragraph", text: extra.verdict });
            blocks.push({ type: "heading", text: "Likely Attack Scenario" });
            blocks.push({ type: "paragraph", text: extra.scenario });
            blocks.push({ type: "heading", text: "Supporting Evidence" });
            blocks.push({ type: "list", items: extra.evidence });
            blocks.push({ type: "heading", text: "Timeline" });
            blocks.push({
                type: "table",
                header: ["Time", "Event"],
                rows: extra.timeline,
            });
            blocks.push({ type: "heading", text: "Indicators of Compromise" });
            blocks.push({
                type: "table",
                header: ["Indicator", "Type", "Verdict"],
                rows: extra.iocs,
            });
            blocks.push({ type: "heading", text: "MITRE ATT&CK Techniques" });
            blocks.push({
                type: "table",
                header: ["Technique ID", "Name"],
                rows: extra.mitre,
            });
            blocks.push({ type: "heading", text: "Evidence Gaps" });
            blocks.push({ type: "list", items: extra.gaps });
            blocks.push({ type: "heading", text: "Recommended Next Action" });
            blocks.push({ type: "paragraph", text: extra.nextAction });
        }
    }
    const amendments =
        applicationState.documentEdits[reportKey(ticket, stage, reportId)];
    if (amendments) {
        blocks.push({ type: "heading", text: "Analyst Amendments" });
        blocks.push({ type: "paragraph", text: amendments });
    }
    return blocks;
}
async function generateDocxBlob(stage, reportId) {
    const {
        Document,
        Packer,
        Paragraph,
        TextRun,
        HeadingLevel,
        Table,
        TableRow,
        TableCell,
        WidthType,
    } = window.docx;
    const blocks = buildDocBlocks(stage, reportId),
        children = [];
    blocks.forEach((b) => {
        if (b.type === "title") {
            children.push(
                new Paragraph({ text: b.text, heading: HeadingLevel.TITLE }),
            );
        } else if (b.type === "meta") {
            b.rows.forEach((r) =>
                children.push(
                    new Paragraph({
                        children: [
                            new TextRun({ text: r[0] + ": ", bold: true }),
                            new TextRun(String(r[1])),
                        ],
                    }),
                ),
            );
            children.push(new Paragraph({ text: "" }));
        } else if (b.type === "heading") {
            children.push(
                new Paragraph({
                    text: b.text,
                    heading: HeadingLevel.HEADING_2,
                    spacing: { before: 200, after: 100 },
                }),
            );
        } else if (b.type === "paragraph") {
            children.push(
                new Paragraph({ text: b.text || "—", spacing: { after: 150 } }),
            );
        } else if (b.type === "list") {
            (b.items && b.items.length ? b.items : ["None"]).forEach((it) =>
                children.push(
                    new Paragraph({ text: it, bullet: { level: 0 } }),
                ),
            );
        } else if (b.type === "table") {
            const headerRow = new TableRow({
                children: b.header.map(
                    (h) =>
                        new TableCell({
                            children: [
                                new Paragraph({
                                    children: [
                                        new TextRun({ text: h, bold: true }),
                                    ],
                                }),
                            ],
                        }),
                ),
            });
            const rows = (b.rows && b.rows.length ? b.rows : [["—"]]).map(
                (r) =>
                    new TableRow({
                        children: r.map(
                            (c) =>
                                new TableCell({
                                    children: [new Paragraph(String(c))],
                                }),
                        ),
                    }),
            );
            children.push(
                new Table({
                    width: { size: 100, type: WidthType.PERCENTAGE },
                    rows: [headerRow, ...rows],
                }),
            );
            children.push(new Paragraph({ text: "" }));
        }
    });
    const doc = new Document({ sections: [{ properties: {}, children }] });
    return await Packer.toBlob(doc);
}
function pdfSafe(s) {
    return String(s == null ? "" : s)
        .replace(/[→↔]/g, "->")
        .replace(/[–—]/g, "-")
        .replace(/[•●]/g, "-")
        .replace(/…/g, "...")
        .replace(/[✓✔]/g, "[OK]")
        .replace(/[✗✕✘✖]/g, "[X]")
        .replace(/[‘’]/g, "'")
        .replace(/[“”]/g, '"');
}
function generatePdfBlob(stage, reportId) {
    const { jsPDF } = window.jspdf;
    const blocks = buildDocBlocks(stage, reportId);
    const doc = new jsPDF({ unit: "pt", format: "a4" });
    const marginX = 48;
    let y = 56;
    const pageHeight = doc.internal.pageSize.getHeight(),
        pageWidth = doc.internal.pageSize.getWidth(),
        maxWidth = pageWidth - marginX * 2;
    function ensureSpace(h) {
        if (y + h > pageHeight - 48) {
            doc.addPage();
            y = 56;
        }
    }
    blocks.forEach((b) => {
        if (b.type === "title") {
            doc.setFont("helvetica", "bold");
            doc.setFontSize(18);
            ensureSpace(28);
            doc.text(pdfSafe(b.text), marginX, y);
            y += 28;
        } else if (b.type === "meta") {
            doc.setFont("helvetica", "normal");
            doc.setFontSize(10);
            b.rows.forEach((r) => {
                ensureSpace(14);
                doc.text(pdfSafe(`${r[0]}: ${r[1]}`), marginX, y);
                y += 14;
            });
            y += 10;
        } else if (b.type === "heading") {
            doc.setFont("helvetica", "bold");
            doc.setFontSize(13);
            ensureSpace(24);
            y += 8;
            doc.text(pdfSafe(b.text), marginX, y);
            y += 16;
        } else if (b.type === "paragraph") {
            doc.setFont("helvetica", "normal");
            doc.setFontSize(10.5);
            const lines = doc.splitTextToSize(pdfSafe(b.text || "-"), maxWidth);
            lines.forEach((line) => {
                ensureSpace(14);
                doc.text(line, marginX, y);
                y += 14;
            });
            y += 6;
        } else if (b.type === "list") {
            doc.setFont("helvetica", "normal");
            doc.setFontSize(10.5);
            (b.items && b.items.length ? b.items : ["None"]).forEach((it) => {
                const lines = doc.splitTextToSize(
                    "-  " + pdfSafe(it),
                    maxWidth - 10,
                );
                lines.forEach((line) => {
                    ensureSpace(14);
                    doc.text(line, marginX, y);
                    y += 14;
                });
            });
            y += 6;
        } else if (b.type === "table") {
            ensureSpace(30);
            doc.autoTable({
                startY: y,
                margin: { left: marginX, right: marginX },
                head: [b.header.map(pdfSafe)],
                body: (b.rows && b.rows.length ? b.rows : [["-"]]).map((r) =>
                    r.map(pdfSafe),
                ),
                styles: { fontSize: 9, cellPadding: 5 },
                headStyles: { fillColor: [40, 50, 70] },
                theme: "grid",
            });
            y = doc.lastAutoTable.finalY + 14;
        }
    });
    return doc.output("blob");
}
function triggerDownload(blob, filename) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    setTimeout(() => {
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }, 1000);
}
function buildDocFilename(ticket, stage, reportId, format) {
    const rep = getReportList(stage).find((r) => r.id === reportId) || {
        fileSlug: stageDocData[stage].fileSlug,
    };
    return `${ticket}_${rep.fileSlug}.${format}`;
}
function renderDocTable(stage) {
    const ticket = currentTicketId(),
        files = getFileList(stage);
    if (!files.length) return;
    const tbody = document.getElementById("docTableBody");
    tbody.innerHTML = files
        .map((item) => {
            const data = agentStageData[stage],
                genAt =
                    data && data.lastRun ? formatGeneratedAt(data.lastRun) : "";
            if (item.type === "json") {
                return `<tr><td><div class="doc-cell-inner"><div class="doc-icon doc-icon-json">${reportIconSvg.code}</div><div class="doc-info"><div class="doc-name-row"><b>${item.name}</b></div><span>${item.description}</span></div></div></td><td><span class="doc-meta-time">Generated today at ${genAt}</span></td><td class="doc-action-cell"><div class="doc-action-row"><button class="doc-action-btn" data-doc-json="${stage}">${docActionIconSvg.download} Download JSON</button></div></td></tr>`;
            }
            const rKey = reportKey(ticket, stage, item.id),
                saved = applicationState.reportSaves[rKey],
                status = reportStatus(stage, item.id),
                timeLine = saved
                    ? `Last saved today at ${saved.time}`
                    : genAt
                      ? `Generated today at ${genAt}`
                      : "";
            return `<tr><td><div class="doc-cell-inner"><div class="doc-icon" style="background:${item.color}">${reportIconSvg[item.icon] || reportIconSvg.document}</div><div class="doc-info"><div class="doc-name-row"><b>${item.name}</b><span class="stage-status ${status.tone}">${status.label}</span></div><span>${item.description}</span></div></div></td><td>${timeLine ? `<span class="doc-meta-time">${timeLine}</span>` : ""}</td><td class="doc-action-cell"><div class="doc-action-row"><button class="doc-action-btn doc-action-cta" data-doc-review="${item.id}">${docActionIconSvg.pencil} Open &amp; Edit</button><button class="doc-action-btn doc-action-word" data-doc-download="${item.id}" data-doc-format="docx">${docActionIconSvg.word} Export Word</button><button class="doc-action-btn doc-action-pdf" data-doc-download="${item.id}" data-doc-format="pdf">${docActionIconSvg.pdf} Export PDF</button></div></td></tr>`;
        })
        .join("");
    tbody
        .querySelectorAll("button[data-doc-json]")
        .forEach((btn) =>
            btn.addEventListener("click", () =>
                downloadJson(btn.dataset.docJson),
            ),
        );
    tbody
        .querySelectorAll("button[data-doc-review]")
        .forEach((btn) =>
            btn.addEventListener("click", () =>
                openReviewModal(stage, btn.dataset.docReview),
            ),
        );
    tbody
        .querySelectorAll("button[data-doc-download]")
        .forEach((btn) =>
            btn.addEventListener("click", () =>
                handleDocAction(
                    stage,
                    btn.dataset.docDownload,
                    btn.dataset.docFormat,
                ),
            ),
        );
}
async function handleDocAction(stage, reportId, format) {
    const ticket = currentTicketId(),
        key = docKey(ticket, stage, reportId, format),
        existing = applicationState.generatedDocuments[key];
    if (existing) {
        triggerDownload(existing.blob, existing.filename);
        return;
    }
    const rKey = reportKey(ticket, stage, reportId);
    applicationState.documentsGenerating[rKey] = true;
    if (applicationState.activeWorkflowStage === stage) renderDocTable(stage);
    try {
        const blob =
            format === "docx"
                ? await generateDocxBlob(stage, reportId)
                : generatePdfBlob(stage, reportId);
        const filename = buildDocFilename(ticket, stage, reportId, format);
        applicationState.generatedDocuments[key] = { blob, filename };
        delete applicationState.documentFailures[rKey];
        triggerDownload(blob, filename);
        showToast("Download ready", `${filename} downloaded for ${ticket}.`);
    } catch (err) {
        applicationState.documentFailures[rKey] = true;
        showToast(
            "Download failed",
            `Could not generate the ${format.toUpperCase()} export. Try again.`,
        );
        console.error(err);
    }
    delete applicationState.documentsGenerating[rKey];
    if (applicationState.activeWorkflowStage === stage) renderDocTable(stage);
}

export function initialiseDocumentActions() {
    // Generated-file actions use delegated listeners created by their renderers.
}

export {
    buildDocBlocks,
    buildDocFilename,
    currentTicketId,
    decisionKey,
    docKey,
    generateDocxBlob,
    generatePdfBlob,
    handleDocAction,
    invalidateStageDocs,
    getReportList,
    renderDocTable,
    reportKey,
};
