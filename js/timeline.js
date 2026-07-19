import { applicationState } from "./state.js";
import { escapeHtml } from "./utils.js";

let currentData = null;
let currentActions = null;

function formatTimestamp(value) {
    return new Date(value).toLocaleString("en-SG", {
        day: "2-digit",
        month: "short",
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
    });
}

function uniqueValues(items, field) {
    return [...new Set(items.map((item) => item[field]).filter(Boolean))];
}

function matchesTimelineFilters(event) {
    const filters = applicationState.investigation.timelineFilters;
    return (
        (filters.category === "all" || event.category === filters.category) &&
        (filters.source === "all" || event.source === filters.source) &&
        (filters.severity === "all" || event.severity === filters.severity) &&
        (filters.entityType === "all" ||
            event.entityTypes.includes(filters.entityType)) &&
        (filters.tactic === "all" || event.tactic === filters.tactic)
    );
}

function getVisibleEvents() {
    const direction =
        applicationState.investigation.timelineOrder === "oldest" ? 1 : -1;
    return currentData.timeline
        .filter(matchesTimelineFilters)
        .sort(
            (left, right) =>
                (new Date(left.timestamp) - new Date(right.timestamp)) *
                direction,
        );
}

function createOptions(values, selected, allLabel) {
    return [
        `<option value="all">${escapeHtml(allLabel)}</option>`,
        ...values.map(
            (value) =>
                `<option value="${escapeHtml(value)}" ${value === selected ? "selected" : ""}>${escapeHtml(value)}</option>`,
        ),
    ].join("");
}

function renderEvent(event) {
    const selected =
        event.id === applicationState.investigation.selectedTimelineEventId;
    const technique = event.techniqueIds[0];
    return `
        <article class="timeline-event timeline-event--${event.severity.toLowerCase()} ${selected ? "is-selected" : ""}" data-timeline-event="${event.id}">
            <button class="timeline-event__summary" type="button" aria-expanded="${selected}" title="${escapeHtml(event.significance)}">
                <span class="timeline-event__marker" aria-hidden="true">${event.category === "Network" ? "↗" : event.category === "Threat Intelligence" ? "◎" : "▶"}</span>
                <time>${formatTimestamp(event.timestamp)}</time>
                <span class="timeline-event__heading">
                    <strong>${escapeHtml(event.title)}</strong>
                    <span>${escapeHtml(event.summary)}</span>
                </span>
                <span class="timeline-significance">${escapeHtml(event.severity)}</span>
                <span class="timeline-event__chevron" aria-hidden="true">${selected ? "−" : "+"}</span>
            </button>
            ${
                selected
                    ? `<div class="timeline-event__details">
                        <p>${escapeHtml(event.description)}</p>
                        <dl class="investigation-detail-list">
                            <div><dt>Source</dt><dd>${escapeHtml(event.source)}</dd></div>
                            <div><dt>Related entities</dt><dd>${event.entityIds.length}</dd></div>
                            <div><dt>Significance</dt><dd>${escapeHtml(event.significance)}</dd></div>
                            <div><dt>MITRE ATT&amp;CK</dt><dd>${technique ? escapeHtml(technique) : "Not mapped"}</dd></div>
                            <div><dt>Evidence</dt><dd>${event.evidenceIds.length} items</dd></div>
                        </dl>
                        <div class="investigation-raw"><span>Normalised event</span><code>${escapeHtml(event.raw)}</code></div>
                        <div class="investigation-action-row">
                            <button type="button" data-timeline-action="evidence" data-event-id="${event.id}">View Supporting Evidence</button>
                            ${event.entityIds.length ? `<button type="button" data-timeline-action="entities" data-event-id="${event.id}">View in Entity Graph</button>` : ""}
                            ${technique ? `<button type="button" data-timeline-action="mitre" data-event-id="${event.id}">View MITRE Mapping</button>` : ""}
                        </div>
                    </div>`
                    : ""
            }
        </article>`;
}

function renderTimelineContent(container) {
    const events = getVisibleEvents();
    const filters = applicationState.investigation.timelineFilters;
    const categories = uniqueValues(currentData.timeline, "category");
    const sources = uniqueValues(currentData.timeline, "source");
    const severities = uniqueValues(currentData.timeline, "severity");
    const entityTypes = [
        ...new Set(currentData.timeline.flatMap((event) => event.entityTypes)),
    ];
    const tactics = uniqueValues(currentData.timeline, "tactic");

    container.innerHTML = `
        <section class="section investigation-panel">
            <div class="investigation-panel__head">
                <div><h3>Incident Timeline</h3><p>Significant security events in chronological order</p></div>
                <div class="timeline-order" aria-label="Timeline ordering">
                    <button type="button" data-timeline-order="oldest" class="${applicationState.investigation.timelineOrder === "oldest" ? "active" : ""}">Oldest first</button>
                    <button type="button" data-timeline-order="newest" class="${applicationState.investigation.timelineOrder === "newest" ? "active" : ""}">Newest first</button>
                </div>
            </div>
            <div class="timeline-filters" aria-label="Timeline filters">
                <select data-timeline-filter="category" aria-label="Filter timeline by event type">${createOptions(categories, filters.category, "All Events")}</select>
                <select data-timeline-filter="source" aria-label="Filter timeline by source">${createOptions(sources, filters.source, "All Sources")}</select>
                <select data-timeline-filter="severity" aria-label="Filter timeline by severity">${createOptions(severities, filters.severity, "All Severities")}</select>
                <select data-timeline-filter="entityType" aria-label="Filter timeline by entity type">${createOptions(entityTypes, filters.entityType, "All Entity Types")}</select>
                <select data-timeline-filter="tactic" aria-label="Filter timeline by tactic">${createOptions(tactics, filters.tactic, "All Tactics")}</select>
                <button type="button" class="btn-ghost" data-timeline-reset>Reset Filters</button>
            </div>
            <div class="incident-timeline" aria-live="polite">
                ${events.length ? events.map(renderEvent).join("") : '<div class="investigation-empty">No significant investigation events are available for this case.</div>'}
            </div>
        </section>`;
}

function handleTimelineClick(event, container) {
    const orderButton = event.target.closest("[data-timeline-order]");
    if (orderButton) {
        applicationState.investigation.timelineOrder =
            orderButton.dataset.timelineOrder;
        renderTimelineContent(container);
        return;
    }
    if (event.target.closest("[data-timeline-reset]")) {
        Object.keys(applicationState.investigation.timelineFilters).forEach(
            (key) =>
                (applicationState.investigation.timelineFilters[key] = "all"),
        );
        renderTimelineContent(container);
        return;
    }
    const action = event.target.closest("[data-timeline-action]");
    if (action) {
        const timelineEvent = currentData.timeline.find(
            (item) => item.id === action.dataset.eventId,
        );
        currentActions.navigate(action.dataset.timelineAction, {
            eventId: timelineEvent.id,
            evidenceId: timelineEvent.evidenceIds[0],
            entityId: timelineEvent.entityIds[0],
            techniqueId: timelineEvent.techniqueIds[0],
        });
        return;
    }
    const eventElement = event.target.closest("[data-timeline-event]");
    if (eventElement) {
        const id = eventElement.dataset.timelineEvent;
        applicationState.investigation.selectedTimelineEventId =
            applicationState.investigation.selectedTimelineEventId === id
                ? null
                : id;
        currentActions.selectionChanged(
            "timeline",
            currentData.timeline.find((item) => item.id === id)?.title ?? "",
        );
        renderTimelineContent(container);
    }
}

export function renderTimeline(container, data, actions) {
    currentData = data;
    currentActions = actions;
    if (!container.dataset.timelineInitialised) {
        container.addEventListener("click", (event) =>
            handleTimelineClick(event, container),
        );
        container.addEventListener("change", (event) => {
            const filter = event.target.dataset.timelineFilter;
            if (!filter) return;
            applicationState.investigation.timelineFilters[filter] =
                event.target.value;
            renderTimelineContent(container);
        });
        container.dataset.timelineInitialised = "true";
    }
    renderTimelineContent(container);
}

export function highlightTimelineEvent(eventId) {
    applicationState.investigation.selectedTimelineEventId = eventId;
}
