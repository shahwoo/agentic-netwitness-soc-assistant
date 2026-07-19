import { applicationState } from "./state.js";
import { escapeHtml } from "./utils.js";

let currentData = null;
let currentActions = null;

function renderEvidenceItem(item) {
    const selected =
        item.id === applicationState.investigation.selectedEvidenceId;
    return `
        <article class="evidence-card ${selected ? "is-selected" : ""}" id="evidence-${item.id}" data-evidence-id="${item.id}">
            <button class="evidence-card__summary" type="button" aria-expanded="${selected}">
                <span class="evidence-card__icon" aria-hidden="true">▣</span>
                <span><strong>${escapeHtml(item.id)} · ${escapeHtml(item.type)}</strong><small>${escapeHtml(item.title)}</small></span>
                <span><small>${escapeHtml(item.source)}</small><strong>${escapeHtml(item.collectedAt)}</strong></span>
                <span class="stage-status good">${escapeHtml(item.validationStatus)}</span>
            </button>
            ${
                selected
                    ? `<div class="evidence-card__details">
                        <dl class="investigation-detail-list">
                            <div><dt>Confidence</dt><dd>${escapeHtml(item.confidence)}</dd></div>
                            <div><dt>Related entities</dt><dd>${item.entityIds.length}</dd></div>
                            <div><dt>Timeline event</dt><dd>${escapeHtml(item.timelineEventId || "None")}</dd></div>
                            <div><dt>MITRE mapping</dt><dd>${escapeHtml(item.mitreMappingId || "None")}</dd></div>
                        </dl>
                        <div class="investigation-action-row">
                            ${item.timelineEventId ? '<button type="button" data-evidence-action="timeline">View Timeline Event</button>' : ""}
                            ${item.entityIds.length ? '<button type="button" data-evidence-action="entities">View Related Entities</button>' : ""}
                            ${item.mitreMappingId ? '<button type="button" data-evidence-action="mitre">View MITRE Mapping</button>' : ""}
                        </div>
                    </div>`
                    : ""
            }
        </article>`;
}

function renderEvidenceContent(container) {
    container.innerHTML = `
        <section class="section investigation-panel">
            <div class="investigation-panel__head">
                <div><h3>Evidence Repository</h3><p>Complete technical evidence collected for this case</p></div>
                ${applicationState.investigation.previousTab ? '<button type="button" class="btn-ghost" data-evidence-back>← Return to previous tab</button>' : ""}
            </div>
            <div class="evidence-list">
                ${currentData.evidence.length ? currentData.evidence.map(renderEvidenceItem).join("") : '<div class="investigation-empty">No evidence items are available for this case.</div>'}
            </div>
        </section>`;
    const selected = applicationState.investigation.selectedEvidenceId;
    if (selected) {
        requestAnimationFrame(() =>
            document
                .getElementById(`evidence-${selected}`)
                ?.scrollIntoView({ behavior: "smooth", block: "center" }),
        );
    }
}

function handleEvidenceClick(event, container) {
    if (event.target.closest("[data-evidence-back]")) {
        currentActions.returnToPreviousTab();
        return;
    }
    const card = event.target.closest("[data-evidence-id]");
    if (!card) return;
    const evidence = currentData.evidence.find(
        (item) => item.id === card.dataset.evidenceId,
    );
    const action = event.target.closest("[data-evidence-action]");
    if (action) {
        currentActions.navigate(action.dataset.evidenceAction, {
            eventId: evidence.timelineEventId,
            entityId: evidence.entityIds[0],
            mappingId: evidence.mitreMappingId,
        });
        return;
    }
    applicationState.investigation.selectedEvidenceId =
        applicationState.investigation.selectedEvidenceId === evidence.id
            ? null
            : evidence.id;
    currentActions.selectionChanged("evidence", evidence.title);
    renderEvidenceContent(container);
}

export function renderEvidence(container, data, actions) {
    currentData = data;
    currentActions = actions;
    if (!container.dataset.evidenceInitialised) {
        container.addEventListener("click", (event) =>
            handleEvidenceClick(event, container),
        );
        container.dataset.evidenceInitialised = "true";
    }
    renderEvidenceContent(container);
}

export function highlightEvidence(evidenceId) {
    applicationState.investigation.selectedEvidenceId = evidenceId;
}
