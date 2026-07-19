import assert from "node:assert/strict";
import { access, readFile, readdir } from "node:fs/promises";

const { JSDOM } = await import(process.env.JSDOM_MODULE ?? "jsdom");

const projectRoot = new URL("../", import.meta.url);
const html = await readFile(new URL("index.html", projectRoot), "utf8");
const dom = new JSDOM(html, {
    url: "http://localhost/",
    pretendToBeVisual: true,
});

const ids = [...dom.window.document.querySelectorAll("[id]")].map(
    (element) => element.id,
);
assert.equal(new Set(ids).size, ids.length, "Duplicate element IDs found");
assert.equal(
    dom.window.document.querySelectorAll("style, script:not([src]), [style]")
        .length,
    0,
    "Inline styles or scripts found",
);

for (const element of dom.window.document.querySelectorAll(
    "link[href], script[src], img[src]",
)) {
    const source = element.getAttribute("href") ?? element.getAttribute("src");
    if (/^(?:https?:|data:|#)/.test(source)) continue;
    await access(new URL(source, projectRoot));
}

for (const cssFile of (await readdir(new URL("css/", projectRoot))).filter(
    (file) => file.endsWith(".css"),
)) {
    const css = await readFile(new URL(`css/${cssFile}`, projectRoot), "utf8");
    for (const match of css.matchAll(
        /font-size:\s*([0-9]+(?:\.[0-9]+)?)(px|rem)\b/g,
    )) {
        const pixelSize =
            match[2] === "rem" ? Number(match[1]) * 16 : Number(match[1]);
        assert.ok(pixelSize >= 11, `${cssFile} contains ${match[0]}`);
    }
    for (const match of css.matchAll(
        /\bfont:\s*([0-9]+(?:\.[0-9]+)?)(px|rem)\b/g,
    )) {
        const pixelSize =
            match[2] === "rem" ? Number(match[1]) * 16 : Number(match[1]);
        assert.ok(pixelSize >= 11, `${cssFile} contains ${match[0]}`);
    }
}

globalThis.window = dom.window;
globalThis.document = dom.window.document;
globalThis.location = dom.window.location;
globalThis.Blob = dom.window.Blob;
globalThis.URL = dom.window.URL;
globalThis.FileReader = dom.window.FileReader;
globalThis.requestAnimationFrame = (callback) => callback();
Object.defineProperty(globalThis, "navigator", {
    value: dom.window.navigator,
    configurable: true,
});

dom.window.HTMLElement.prototype.scrollIntoView = () => {};
dom.window.scrollTo = () => {};
dom.window.HTMLAnchorElement.prototype.click = () => {};
dom.window.URL.createObjectURL = () => "blob:aegis-test";
dom.window.URL.revokeObjectURL = () => {};

class DocumentPart {
    constructor(options = {}) {
        Object.assign(this, options);
    }
}

dom.window.docx = {
    Document: DocumentPart,
    Paragraph: DocumentPart,
    TextRun: DocumentPart,
    Table: DocumentPart,
    TableRow: DocumentPart,
    TableCell: DocumentPart,
    HeadingLevel: {
        TITLE: "title",
        HEADING_2: "heading-2",
    },
    WidthType: {
        PERCENTAGE: "percentage",
    },
    Packer: {
        toBlob: async () => new Blob(["docx"]),
    },
};

class FakePdf {
    constructor() {
        this.internal = {
            pageSize: {
                getHeight: () => 842,
                getWidth: () => 595,
            },
        };
        this.lastAutoTable = { finalY: 100 };
    }

    addPage() {}
    setFont() {}
    setFontSize() {}
    text() {}
    splitTextToSize(value) {
        return [value];
    }
    autoTable() {
        this.lastAutoTable.finalY = 100;
    }
    output() {
        return new Blob(["pdf"]);
    }
}

dom.window.jspdf = { jsPDF: FakePdf };

await import(new URL("js/app.js", projectRoot));
document.dispatchEvent(
    new dom.window.Event("DOMContentLoaded", { bubbles: true }),
);

const click = (selector) => {
    const element = document.querySelector(selector);
    assert.ok(element, `Expected element: ${selector}`);
    element.dispatchEvent(
        new dom.window.MouseEvent("click", { bubbles: true }),
    );
    return element;
};

click("#topMyQueueNav");
assert.equal(document.querySelector("#pageTitle").textContent, "My Workspace");

click("#topAllCasesNav");
assert.equal(document.querySelector("#pageTitle").textContent, "All Cases");

const search = document.querySelector("#ticketSearch");
search.value = "TKT-2026-00125";
search.dispatchEvent(new dom.window.Event("input", { bubbles: true }));
assert.ok(document.querySelectorAll("#rows tr:not(.hidden)").length >= 1);

click('th[data-sort="severity"]');
click("#rows tr:not(.hidden)");
assert.ok(document.querySelector(".content").classList.contains("case-mode"));

// Investigation workspace: defaults, dynamic counts, and keyboard tabs.
assert.equal(
    document
        .querySelector("#investigation-tab-overview")
        .getAttribute("aria-selected"),
    "true",
);
assert.equal(
    document.querySelector('[data-investigation-count="mitre"]').textContent,
    "3",
);
assert.equal(
    document.querySelector('[data-investigation-count="entities"]').textContent,
    "8",
);
assert.equal(
    document.querySelector('[data-investigation-count="evidence"]').textContent,
    "12",
);

document.querySelector("#investigation-tab-overview").dispatchEvent(
    new dom.window.KeyboardEvent("keydown", {
        key: "ArrowRight",
        bubbles: true,
    }),
);
assert.equal(
    document
        .querySelector("#investigation-tab-timeline")
        .getAttribute("aria-selected"),
    "true",
);
assert.equal(document.querySelectorAll("[data-timeline-event]").length, 5);

// Timeline expansion, ordering, filters, and cross-link to Evidence.
click('[data-timeline-event="EVT-001"] .timeline-event__summary');
assert.ok(
    document.querySelector('[data-timeline-event="EVT-001"].is-selected'),
);
click('[data-timeline-order="newest"]');
assert.equal(
    document.querySelector("[data-timeline-event]").dataset.timelineEvent,
    "EVT-005",
);
const severityFilter = document.querySelector(
    '[data-timeline-filter="severity"]',
);
severityFilter.value = "Critical";
severityFilter.dispatchEvent(new dom.window.Event("change", { bubbles: true }));
assert.equal(document.querySelectorAll("[data-timeline-event]").length, 2);
click("[data-timeline-reset]");
click('[data-timeline-event="EVT-003"] .timeline-event__summary');
click('[data-timeline-event="EVT-003"] [data-timeline-action="evidence"]');
assert.equal(
    document
        .querySelector("#investigation-tab-evidence")
        .getAttribute("aria-selected"),
    "true",
);
assert.ok(document.querySelector("#evidence-EVD-005.is-selected"));
click("[data-evidence-back]");
assert.equal(
    document
        .querySelector("#investigation-tab-timeline")
        .getAttribute("aria-selected"),
    "true",
);

// MITRE tactic filtering, card expansion, validation, and cross-linking.
click("#investigation-tab-mitre");
assert.equal(document.querySelectorAll("[data-mitre-card]").length, 3);
click('[data-mitre-tactic="Execution"]');
assert.equal(document.querySelectorAll("[data-mitre-card]").length, 1);
click('[data-mitre-card="MITRE-001"] .mitre-card__summary');
click('[data-mitre-card="MITRE-001"] [data-mitre-validation="Confirmed"]');
assert.match(
    document.querySelector(
        '[data-mitre-card="MITRE-001"] .mitre-validation-status',
    ).textContent,
    /Confirmed/,
);

// Entity graph node/edge selection, filtering, search, and controls.
click("#investigation-tab-entities");
assert.equal(document.querySelectorAll("[data-entity-id]").length, 8);
assert.equal(document.querySelectorAll("[data-relationship-id]").length, 10);
click('[data-entity-id="ENT-ENDPOINT-001"]');
assert.match(
    document.querySelector(".entity-details").textContent,
    /MSS-ECSVC/,
);
click('[data-relationship-id="REL-005"]');
assert.match(
    document.querySelector(".entity-details").textContent,
    /Connected to/,
);
const viewportBeforeZoom = document
    .querySelector(".entity-graph-viewport")
    .getAttribute("transform");
click('[data-graph-control="zoom-in"]');
assert.notEqual(
    document.querySelector(".entity-graph-viewport").getAttribute("transform"),
    viewportBeforeZoom,
);
click('[data-graph-control="fit"]');
click('[data-graph-control="reset"]');
document.querySelector('[data-entity-id="ENT-PROCESS-001"]').dispatchEvent(
    new dom.window.KeyboardEvent("keydown", {
        key: "Enter",
        bubbles: true,
    }),
);
assert.match(
    document.querySelector(".entity-details").textContent,
    /mssecsvc\.exe/,
);
const fullscreenButton = click('[data-graph-control="fullscreen"]');
assert.ok(
    document
        .querySelector(".entity-graph-panel")
        .classList.contains("is-fullscreen-fallback"),
);
fullscreenButton.dispatchEvent(
    new dom.window.KeyboardEvent("keydown", {
        key: "Escape",
        bubbles: true,
    }),
);
assert.ok(
    !document
        .querySelector(".entity-graph-panel")
        .classList.contains("is-fullscreen-fallback"),
);
const entitySearch = document.querySelector("[data-entity-search]");
entitySearch.value = "185.159";
entitySearch.dispatchEvent(new dom.window.Event("input", { bubbles: true }));
assert.ok(document.querySelector('[data-entity-id="ENT-IP-001"].is-selected'));

// Copilot prompts follow the active Investigation tab.
assert.match(
    document.querySelector("#chatSuggestions").textContent,
    /Explain this entity/,
);

click("#investigation-tab-activity");
assert.ok(
    document.querySelectorAll("#case-activity .activity-item").length >= 1,
);
assert.match(
    document.querySelector("#case-activity").textContent,
    /analysts and Aegis agents/,
);
click("#investigation-tab-entities");

// Same-case tab persistence and different-case reset with zero badges.
const investigationModule = await import(
    new URL("js/investigation-tabs.js", projectRoot)
);
investigationModule.openInvestigationCase("TKT-2026-00125");
assert.equal(
    document
        .querySelector("#investigation-tab-entities")
        .getAttribute("aria-selected"),
    "true",
);
investigationModule.openInvestigationCase("TKT-2026-00999");
assert.equal(
    document
        .querySelector("#investigation-tab-overview")
        .getAttribute("aria-selected"),
    "true",
);
assert.equal(
    document.querySelector('[data-investigation-count="mitre"]').textContent,
    "0",
);
assert.equal(
    document.querySelector('[data-investigation-count="entities"]').textContent,
    "0",
);
assert.equal(
    document.querySelector('[data-investigation-count="evidence"]').textContent,
    "0",
);
click("#investigation-tab-timeline");
assert.match(
    document.querySelector("#case-timeline").textContent,
    /No significant/,
);
click("#investigation-tab-mitre");
assert.match(
    document.querySelector("#case-mitre").textContent,
    /No evidence-backed/,
);
click("#investigation-tab-entities");
assert.match(
    document.querySelector("#case-entities").textContent,
    /No entity relationships/,
);
click("#investigation-tab-evidence");
assert.match(
    document.querySelector("#case-evidence").textContent,
    /No evidence items/,
);
investigationModule.openInvestigationCase("TKT-2026-00125");

click('[data-workflow-stage="parsing"]');
assert.equal(
    document.querySelector("#stageDetailTitle").textContent,
    "Parsing & Normalisation",
);

click("[data-doc-json]");
click('[data-doc-review="default"]');
assert.equal(document.querySelector("#reviewModalOverlay").hidden, false);
document.querySelector("#reviewAmendments").value =
    "Validated during smoke testing.";
click("#reviewSaveBtn");
assert.equal(document.querySelector("#reviewModalOverlay").hidden, true);

click('[data-doc-download][data-doc-format="docx"]');
await new Promise((resolve) => setTimeout(resolve, 0));
click('[data-doc-download][data-doc-format="pdf"]');
await new Promise((resolve) => setTimeout(resolve, 0));

click('[data-workflow-stage="triage"]');
click('[data-decision="approve"]');
assert.equal(document.querySelector("#decisionModalOverlay").hidden, false);
click("#modalConfirm");
assert.equal(document.querySelector("#decisionModalOverlay").hidden, true);

const messageCountBeforePrompt = document.querySelectorAll(
    "#chatMessages .chat-msg",
).length;
const prompt = click("#chatSuggestions [data-ask]");
assert.ok(prompt.dataset.ask);
await new Promise((resolve) => setTimeout(resolve, 700));
assert.ok(
    document.querySelectorAll("#chatMessages .chat-msg").length >
        messageCountBeforePrompt,
);

document.querySelector("#reviewModalOverlay").hidden = false;
document.dispatchEvent(
    new dom.window.KeyboardEvent("keydown", { key: "Escape" }),
);
assert.equal(document.querySelector("#reviewModalOverlay").hidden, true);

click("#backToQueue");
assert.equal(document.querySelector("#pageTitle").textContent, "My Workspace");

console.log("Aegis frontend smoke test passed.");
