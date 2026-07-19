import { getInvestigationCaseData } from "./investigation-data.js";
import { applicationState } from "./state.js";
import { updateInvestigationCopilotContext } from "./copilot.js";
import { renderTimeline, highlightTimelineEvent } from "./timeline.js";
import { renderMitreAttack } from "./mitre-attack.js";
import {
    renderEntityGraph,
    highlightEntity,
    resetEntityGraph,
} from "./entity-graph.js";
import { renderEvidence, highlightEvidence } from "./evidence.js";
import { renderActivity } from "./activity.js";

const tabOrder = [
    "overview",
    "timeline",
    "mitre",
    "entities",
    "evidence",
    "activity",
];

let currentCaseId = null;
let currentData = null;
let platformActivity = [];

function resetInvestigationState() {
    Object.assign(applicationState.investigation, {
        activeTab: "overview",
        previousTab: null,
        selectedTimelineEventId: null,
        selectedMitreMappingId: null,
        selectedEntityId: null,
        selectedRelationshipId: null,
        selectedEvidenceId: null,
        timelineOrder: "oldest",
        mitreTactic: "all",
        validationStatuses: {},
    });
    Object.keys(applicationState.investigation.timelineFilters).forEach(
        (key) => (applicationState.investigation.timelineFilters[key] = "all"),
    );
    Object.assign(applicationState.investigation.entityFilters, {
        type: "all",
        risk: "all",
        query: "",
    });
    Object.assign(applicationState.investigation.graph, {
        scale: 1,
        offsetX: 0,
        offsetY: 0,
    });
    resetEntityGraph();
    platformActivity = [];
}

function updateCountBadges() {
    const counts = {
        mitre: currentData.mitreAttack.length,
        entities: currentData.entities.length,
        evidence: currentData.evidence.length,
    };
    const labels = {
        mitre: "mapped techniques",
        entities: "entities",
        evidence: "evidence items",
    };
    Object.entries(counts).forEach(([key, count]) => {
        const badge = document.querySelector(
            `[data-investigation-count="${key}"]`,
        );
        if (!badge) return;
        badge.textContent = String(count);
        badge.setAttribute("aria-label", `${count} ${labels[key]}`);
        badge.classList.toggle("is-zero", count === 0);
    });
}

function renderOverviewPreviews() {
    const container = document.getElementById("investigationOverviewPreviews");
    if (!container) return;
    container.innerHTML = `
        <article class="investigation-preview-card">
            <div><span class="investigation-preview-card__icon" aria-hidden="true">↕</span><div><h4>Incident Timeline</h4><p>${currentData.timeline.length} significant events</p></div></div>
            <button type="button" data-investigation-open-tab="timeline">View Timeline</button>
        </article>
        <article class="investigation-preview-card">
            <div><span class="investigation-preview-card__icon" aria-hidden="true">⌘</span><div><h4>Entity Relationships</h4><p>${currentData.entities.length} entities · ${currentData.relationships.length} relationships</p></div></div>
            <button type="button" data-investigation-open-tab="entities">Open Entity Graph</button>
        </article>`;
}

function actions() {
    return {
        navigate: crossTabNavigate,
        returnToPreviousTab,
        selectionChanged(tab, label) {
            updateInvestigationCopilotContext(tab, label);
        },
        activity(title, description) {
            platformActivity.unshift({
                id: `ACT-LOCAL-${Date.now()}`,
                time: new Date().toLocaleTimeString("en-SG", {
                    hour: "2-digit",
                    minute: "2-digit",
                }),
                title,
                description,
            });
        },
    };
}

function renderActivePanel(tab) {
    const container = document.getElementById(`case-${tab}`);
    if (!container) return;
    if (tab === "timeline") renderTimeline(container, currentData, actions());
    if (tab === "mitre") renderMitreAttack(container, currentData, actions());
    if (tab === "entities")
        renderEntityGraph(container, currentData, actions());
    if (tab === "evidence") renderEvidence(container, currentData, actions());
    if (tab === "activity")
        renderActivity(container, currentData, platformActivity);
}

export function switchInvestigationTab(tab, options = {}) {
    if (!tabOrder.includes(tab) || !currentData) return;
    if (options.rememberPrevious) {
        applicationState.investigation.previousTab =
            applicationState.investigation.activeTab;
    }
    applicationState.investigation.activeTab = tab;
    document
        .querySelectorAll("#investigationTabs [role='tab']")
        .forEach((button) => {
            const active = button.dataset.caseTab === tab;
            button.classList.toggle("active", active);
            button.setAttribute("aria-selected", String(active));
            button.tabIndex = active ? 0 : -1;
        });
    document.querySelectorAll(".case-tab-page").forEach((panel) => {
        const active = panel.id === `case-${tab}`;
        panel.classList.toggle("active", active);
        panel.hidden = !active;
    });
    renderActivePanel(tab);
    updateInvestigationCopilotContext(tab);
    if (options.focusTab) {
        document.getElementById(`investigation-tab-${tab}`)?.focus();
    }
}

function crossTabNavigate(tab, context = {}) {
    const targetTab = tab === "entities" || tab === "entity" ? "entities" : tab;
    if (targetTab === "evidence" && context.evidenceId)
        highlightEvidence(context.evidenceId);
    if (targetTab === "timeline" && context.eventId)
        highlightTimelineEvent(context.eventId);
    if (targetTab === "entities" && context.entityId)
        highlightEntity(context.entityId);
    if (targetTab === "mitre") {
        const identifier = context.techniqueId || context.mappingId;
        const mapping = currentData.mitreAttack.find(
            (item) => item.techniqueId === identifier || item.id === identifier,
        );
        applicationState.investigation.selectedMitreMappingId =
            mapping?.id ?? null;
        applicationState.investigation.mitreTactic = mapping?.tactic ?? "all";
    }
    switchInvestigationTab(targetTab, { rememberPrevious: true });
}

function returnToPreviousTab() {
    const previous = applicationState.investigation.previousTab;
    applicationState.investigation.previousTab = null;
    if (previous) switchInvestigationTab(previous);
}

function handleTabKeydown(event) {
    const currentIndex = tabOrder.indexOf(event.target.dataset.caseTab);
    if (currentIndex < 0) return;
    let nextIndex = currentIndex;
    if (event.key === "ArrowRight")
        nextIndex = (currentIndex + 1) % tabOrder.length;
    else if (event.key === "ArrowLeft")
        nextIndex = (currentIndex - 1 + tabOrder.length) % tabOrder.length;
    else if (event.key === "Home") nextIndex = 0;
    else if (event.key === "End") nextIndex = tabOrder.length - 1;
    else return;
    event.preventDefault();
    switchInvestigationTab(tabOrder[nextIndex], { focusTab: true });
}

export function openInvestigationCase(caseId) {
    if (!caseId) return;
    const changedCase = currentCaseId !== caseId;
    currentCaseId = caseId;
    currentData = getInvestigationCaseData(caseId);
    if (changedCase) resetInvestigationState();
    updateCountBadges();
    renderOverviewPreviews();
    switchInvestigationTab(applicationState.investigation.activeTab);
}

export function initialiseInvestigationTabs() {
    const tabs = document.getElementById("investigationTabs");
    if (!tabs || tabs.dataset.initialised) return;
    tabs.addEventListener("click", (event) => {
        const button = event.target.closest("button[data-case-tab]");
        if (button) switchInvestigationTab(button.dataset.caseTab);
    });
    tabs.addEventListener("keydown", handleTabKeydown);
    document
        .getElementById("investigationOverviewPreviews")
        ?.addEventListener("click", (event) => {
            const button = event.target.closest(
                "[data-investigation-open-tab]",
            );
            if (button)
                switchInvestigationTab(button.dataset.investigationOpenTab);
        });
    tabs.dataset.initialised = "true";
}
