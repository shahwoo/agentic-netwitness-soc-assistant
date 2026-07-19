import { applicationState } from "./state.js";
import { escapeHtml } from "./utils.js";

const defaultPositions = {
    "ENT-USER-001": { x: 95, y: 95 },
    "ENT-ENDPOINT-001": { x: 310, y: 180 },
    "ENT-PROCESS-001": { x: 520, y: 105 },
    "ENT-PROCESS-002": { x: 745, y: 105 },
    "ENT-HASH-001": { x: 735, y: 275 },
    "ENT-IP-001": { x: 310, y: 390 },
    "ENT-DOMAIN-001": { x: 520, y: 390 },
    "ENT-TI-001": { x: 745, y: 430 },
};

let positions = structuredClone(defaultPositions);
let currentData = null;
let currentActions = null;
let dragState = null;
let panState = null;

function entityIcon(type) {
    return (
        {
            Endpoint: "▣",
            User: "●",
            Process: "▶",
            "File Hash": "#",
            "IP Address": "◎",
            Domain: "◇",
            Provider: "✦",
        }[type] ?? "○"
    );
}

function matchesEntityFilters(entity) {
    const filters = applicationState.investigation.entityFilters;
    const query = filters.query.toLowerCase();
    return (
        (filters.type === "all" || entity.type === filters.type) &&
        (filters.risk === "all" || entity.riskLevel === filters.risk) &&
        (!query ||
            entity.label.toLowerCase().includes(query) ||
            entity.value.toLowerCase().includes(query))
    );
}

function selectedConnections() {
    const selectedId = applicationState.investigation.selectedEntityId;
    if (!selectedId) return new Set();
    return new Set(
        currentData.relationships
            .filter(
                (relationship) =>
                    relationship.sourceEntityId === selectedId ||
                    relationship.targetEntityId === selectedId,
            )
            .flatMap((relationship) => [
                relationship.sourceEntityId,
                relationship.targetEntityId,
            ]),
    );
}

function renderRelationship(relationship, visibleEntityIds) {
    if (
        !visibleEntityIds.has(relationship.sourceEntityId) ||
        !visibleEntityIds.has(relationship.targetEntityId)
    ) {
        return "";
    }
    const source = positions[relationship.sourceEntityId];
    const target = positions[relationship.targetEntityId];
    const selected =
        relationship.id ===
        applicationState.investigation.selectedRelationshipId;
    const connected =
        !applicationState.investigation.selectedEntityId ||
        relationship.sourceEntityId ===
            applicationState.investigation.selectedEntityId ||
        relationship.targetEntityId ===
            applicationState.investigation.selectedEntityId;
    const middleX = (source.x + target.x) / 2;
    const middleY = (source.y + target.y) / 2;
    return `
        <g class="entity-edge ${selected ? "is-selected" : ""} ${connected ? "is-connected" : "is-dimmed"}" data-relationship-id="${relationship.id}" tabindex="0" role="button" aria-label="${escapeHtml(relationship.type)} relationship">
            <line x1="${source.x}" y1="${source.y}" x2="${target.x}" y2="${target.y}" marker-end="url(#graph-arrow)" />
            <text x="${middleX}" y="${middleY - 6}" text-anchor="middle">${escapeHtml(relationship.type)}</text>
        </g>`;
}

function renderEntity(entity, connectedIds) {
    const position = positions[entity.id];
    const selected =
        entity.id === applicationState.investigation.selectedEntityId;
    const dimmed = connectedIds.size > 0 && !connectedIds.has(entity.id);
    return `
        <g class="entity-node entity-node--${entity.type.toLowerCase().replaceAll(" ", "-")} entity-node--risk-${entity.riskLevel.toLowerCase()} ${selected ? "is-selected" : ""} ${dimmed ? "is-dimmed" : ""}" transform="translate(${position.x} ${position.y})" data-entity-id="${entity.id}" tabindex="0" role="button" aria-label="${escapeHtml(entity.type)} ${escapeHtml(entity.label)}, ${escapeHtml(entity.riskLevel)} risk">
            <circle r="38" />
            <text class="entity-node__icon" y="-5" text-anchor="middle">${entityIcon(entity.type)}</text>
            <text class="entity-node__label" y="16" text-anchor="middle">${escapeHtml(entity.label)}</text>
            <text class="entity-node__type" y="55" text-anchor="middle">${escapeHtml(entity.type)}</text>
        </g>`;
}

function entityDetails(entity) {
    if (!entity) return "";
    return `
        <div class="entity-details__head"><span class="entity-node-token">${entityIcon(entity.type)}</span><div><small>${escapeHtml(entity.type)}</small><h4>${escapeHtml(entity.label)}</h4></div><button type="button" data-graph-clear aria-label="Close entity details">×</button></div>
        <p class="entity-details__value">${escapeHtml(entity.value)}</p>
        <dl class="investigation-detail-list">
            <div><dt>Risk level</dt><dd>${escapeHtml(entity.riskLevel)}</dd></div>
            <div><dt>Reputation</dt><dd>${entity.riskLevel === "Critical" ? "Malicious" : "Observed"}</dd></div>
            <div><dt>First seen</dt><dd>${new Date(entity.firstSeen).toLocaleString("en-SG")}</dd></div>
            <div><dt>Last seen</dt><dd>${new Date(entity.lastSeen).toLocaleString("en-SG")}</dd></div>
            <div><dt>Supporting evidence</dt><dd>${entity.evidenceIds.length}</dd></div>
            <div><dt>Timeline events</dt><dd>${entity.timelineEventIds.length}</dd></div>
            <div><dt>MITRE techniques</dt><dd>${entity.techniqueIds.length}</dd></div>
            <div><dt>Data source</dt><dd>${escapeHtml(entity.source)}</dd></div>
        </dl>
        <div class="investigation-action-row investigation-action-row--stacked">
            <button type="button" data-entity-action="evidence">View Evidence</button>
            <button type="button" data-entity-action="timeline">View Timeline Events</button>
            ${entity.techniqueIds.length ? '<button type="button" data-entity-action="mitre">View MITRE Techniques</button>' : ""}
            <button type="button" data-entity-copy>Copy Value</button>
        </div>`;
}

function relationshipDetails(relationship) {
    if (!relationship) return "";
    const source = currentData.entities.find(
        (entity) => entity.id === relationship.sourceEntityId,
    );
    const target = currentData.entities.find(
        (entity) => entity.id === relationship.targetEntityId,
    );
    return `
        <div class="entity-details__head"><span class="entity-node-token">↔</span><div><small>Relationship</small><h4>${escapeHtml(source.label)} → ${escapeHtml(target.label)}</h4></div><button type="button" data-graph-clear aria-label="Close relationship details">×</button></div>
        <dl class="investigation-detail-list">
            <div><dt>Relationship</dt><dd>${escapeHtml(relationship.type)}</dd></div>
            <div><dt>Observed</dt><dd>${new Date(relationship.timestamp).toLocaleString("en-SG")}</dd></div>
            <div><dt>Source</dt><dd>NetWitness Endpoint</dd></div>
            <div><dt>Evidence</dt><dd>${relationship.evidenceIds.join(", ")}</dd></div>
        </dl>
        <div class="investigation-action-row investigation-action-row--stacked">
            <button type="button" data-relationship-action="timeline">View Timeline Event</button>
            <button type="button" data-relationship-action="evidence">View Evidence</button>
        </div>`;
}

function renderGraphContent(container) {
    const visibleEntities = currentData.entities.filter(matchesEntityFilters);
    const visibleEntityIds = new Set(
        visibleEntities.map((entity) => entity.id),
    );
    const connectedIds = selectedConnections();
    const graphState = applicationState.investigation.graph;
    const selectedEntity = currentData.entities.find(
        (entity) =>
            entity.id === applicationState.investigation.selectedEntityId,
    );
    const selectedRelationship = currentData.relationships.find(
        (relationship) =>
            relationship.id ===
            applicationState.investigation.selectedRelationshipId,
    );
    const entityTypes = [
        ...new Set(currentData.entities.map((item) => item.type)),
    ];
    const risks = [
        ...new Set(currentData.entities.map((item) => item.riskLevel)),
    ];
    container.innerHTML = `
        <section class="section investigation-panel entity-graph-panel">
            <div class="investigation-panel__head">
                <div><h3>Entity Graph</h3><p>${visibleEntities.length} entities · ${currentData.relationships.length} relationships</p></div>
                <div class="graph-controls" role="toolbar" aria-label="Entity graph controls">
                    <button type="button" data-graph-control="zoom-in" aria-label="Zoom in" title="Zoom In">＋</button>
                    <button type="button" data-graph-control="zoom-out" aria-label="Zoom out" title="Zoom Out">−</button>
                    <button type="button" data-graph-control="fit" aria-label="Fit all nodes into view" title="Fit to View">⊙</button>
                    <button type="button" data-graph-control="reset" aria-label="Reset graph layout" title="Reset Layout">↺</button>
                    <button type="button" data-graph-control="fullscreen" aria-label="Enter full-screen graph mode" title="Full Screen">⛶</button>
                </div>
            </div>
            <div class="entity-graph-filters">
                <label><span class="sr-only">Search entities</span><input data-entity-search value="${escapeHtml(applicationState.investigation.entityFilters.query)}" placeholder="Search endpoint, process, IP, domain or hash" /></label>
                <select data-entity-filter="type" aria-label="Filter graph by entity type"><option value="all">All Entities</option>${entityTypes.map((type) => `<option value="${escapeHtml(type)}" ${applicationState.investigation.entityFilters.type === type ? "selected" : ""}>${escapeHtml(type)}</option>`).join("")}</select>
                <select data-entity-filter="risk" aria-label="Filter graph by risk"><option value="all">Risk: All</option>${risks.map((risk) => `<option value="${escapeHtml(risk)}" ${applicationState.investigation.entityFilters.risk === risk ? "selected" : ""}>${escapeHtml(risk)}</option>`).join("")}</select>
            </div>
            ${
                currentData.relationships.length
                    ? `<div class="entity-graph-layout">
                        <div class="entity-graph-canvas" tabindex="0" aria-label="Interactive entity relationship graph. Use the controls to zoom and select nodes for accessible details.">
                            <svg viewBox="0 0 900 520" role="img" aria-label="Entity relationships">
                                <defs><marker id="graph-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z" /></marker></defs>
                                <g class="entity-graph-viewport" transform="translate(${graphState.offsetX} ${graphState.offsetY}) scale(${graphState.scale})">
                                    <g class="entity-edges">${currentData.relationships.map((relationship) => renderRelationship(relationship, visibleEntityIds)).join("")}</g>
                                    <g class="entity-nodes">${visibleEntities.map((entity) => renderEntity(entity, connectedIds)).join("")}</g>
                                </g>
                            </svg>
                        </div>
                        <aside class="entity-details" aria-live="polite">
                            ${selectedEntity ? entityDetails(selectedEntity) : selectedRelationship ? relationshipDetails(selectedRelationship) : '<div class="entity-details__empty"><span>◎</span><h4>Select an entity or relationship</h4><p>Connected paths and supporting investigation context will appear here.</p></div>'}
                        </aside>
                    </div>`
                    : '<div class="investigation-empty"><strong>No entity relationships are available for this case.</strong></div>'
            }
            <div class="entity-legend" aria-label="Entity type legend">${entityTypes.map((type) => `<span>${entityIcon(type)} ${escapeHtml(type)}</span>`).join("")}</div>
        </section>`;
    attachPointerInteractions(container);
}

function clientToGraph(svg, event) {
    const point = svg.createSVGPoint();
    point.x = event.clientX;
    point.y = event.clientY;
    return point.matrixTransform(svg.getScreenCTM().inverse());
}

function attachPointerInteractions(container) {
    const svg = container.querySelector(".entity-graph-canvas svg");
    if (!svg) return;
    svg.addEventListener("pointerdown", (event) => {
        const node = event.target.closest("[data-entity-id]");
        if (node) {
            dragState = {
                id: node.dataset.entityId,
                start: clientToGraph(svg, event),
                origin: { ...positions[node.dataset.entityId] },
            };
        } else {
            panState = {
                x: event.clientX,
                y: event.clientY,
                offsetX: applicationState.investigation.graph.offsetX,
                offsetY: applicationState.investigation.graph.offsetY,
            };
        }
        svg.setPointerCapture(event.pointerId);
    });
    svg.addEventListener("pointermove", (event) => {
        if (dragState) {
            const point = clientToGraph(svg, event);
            positions[dragState.id] = {
                x: dragState.origin.x + point.x - dragState.start.x,
                y: dragState.origin.y + point.y - dragState.start.y,
            };
            const node = svg.querySelector(
                `[data-entity-id="${dragState.id}"]`,
            );
            node?.setAttribute(
                "transform",
                `translate(${positions[dragState.id].x} ${positions[dragState.id].y})`,
            );
        } else if (panState) {
            applicationState.investigation.graph.offsetX =
                panState.offsetX + event.clientX - panState.x;
            applicationState.investigation.graph.offsetY =
                panState.offsetY + event.clientY - panState.y;
            const viewport = svg.querySelector(".entity-graph-viewport");
            viewport?.setAttribute(
                "transform",
                `translate(${applicationState.investigation.graph.offsetX} ${applicationState.investigation.graph.offsetY}) scale(${applicationState.investigation.graph.scale})`,
            );
        }
    });
    const finish = () => {
        if (dragState) renderGraphContent(container);
        dragState = null;
        panState = null;
    };
    svg.addEventListener("pointerup", finish);
    svg.addEventListener("pointercancel", finish);
    svg.addEventListener(
        "wheel",
        (event) => {
            event.preventDefault();
            applicationState.investigation.graph.scale = Math.min(
                2,
                Math.max(
                    0.55,
                    applicationState.investigation.graph.scale +
                        (event.deltaY < 0 ? 0.1 : -0.1),
                ),
            );
            renderGraphContent(container);
        },
        { passive: false },
    );
}

function handleGraphControl(control, container) {
    const graph = applicationState.investigation.graph;
    if (control === "zoom-in") graph.scale = Math.min(2, graph.scale + 0.15);
    if (control === "zoom-out")
        graph.scale = Math.max(0.55, graph.scale - 0.15);
    if (control === "fit")
        Object.assign(graph, { scale: 0.85, offsetX: 35, offsetY: 18 });
    if (control === "reset") {
        positions = structuredClone(defaultPositions);
        Object.assign(graph, { scale: 1, offsetX: 0, offsetY: 0 });
    }
    if (control === "fullscreen") {
        const panel = container.querySelector(".entity-graph-panel");
        if (document.fullscreenElement) document.exitFullscreen?.();
        else if (panel.requestFullscreen) panel.requestFullscreen();
        else panel.classList.toggle("is-fullscreen-fallback");
        return;
    }
    renderGraphContent(container);
}

function handleGraphClick(event, container) {
    const control = event.target.closest("[data-graph-control]");
    if (control)
        return handleGraphControl(control.dataset.graphControl, container);
    if (event.target.closest("[data-graph-clear]")) {
        applicationState.investigation.selectedEntityId = null;
        applicationState.investigation.selectedRelationshipId = null;
        renderGraphContent(container);
        return;
    }
    const entityElement = event.target.closest("[data-entity-id]");
    if (entityElement && !dragState) {
        applicationState.investigation.selectedEntityId =
            entityElement.dataset.entityId;
        applicationState.investigation.selectedRelationshipId = null;
        const entity = currentData.entities.find(
            (item) => item.id === entityElement.dataset.entityId,
        );
        currentActions.selectionChanged("entities", entity.label);
        renderGraphContent(container);
        return;
    }
    const relationshipElement = event.target.closest("[data-relationship-id]");
    if (relationshipElement) {
        applicationState.investigation.selectedRelationshipId =
            relationshipElement.dataset.relationshipId;
        applicationState.investigation.selectedEntityId = null;
        currentActions.selectionChanged("entities", "Selected relationship");
        renderGraphContent(container);
        return;
    }
    const selectedEntity = currentData.entities.find(
        (entity) =>
            entity.id === applicationState.investigation.selectedEntityId,
    );
    const entityAction = event.target.closest("[data-entity-action]");
    if (entityAction && selectedEntity) {
        currentActions.navigate(entityAction.dataset.entityAction, {
            evidenceId: selectedEntity.evidenceIds[0],
            eventId: selectedEntity.timelineEventIds[0],
            techniqueId: selectedEntity.techniqueIds[0],
            entityId: selectedEntity.id,
        });
        return;
    }
    if (event.target.closest("[data-entity-copy]") && selectedEntity) {
        navigator.clipboard?.writeText(selectedEntity.value);
        return;
    }
    const selectedRelationship = currentData.relationships.find(
        (relationship) =>
            relationship.id ===
            applicationState.investigation.selectedRelationshipId,
    );
    const relationshipAction = event.target.closest(
        "[data-relationship-action]",
    );
    if (relationshipAction && selectedRelationship) {
        currentActions.navigate(relationshipAction.dataset.relationshipAction, {
            evidenceId: selectedRelationship.evidenceIds[0],
            eventId: selectedRelationship.timelineEventIds[0],
        });
    }
}

export function renderEntityGraph(container, data, actions) {
    currentData = data;
    currentActions = actions;
    if (!container.dataset.graphInitialised) {
        container.addEventListener("click", (event) =>
            handleGraphClick(event, container),
        );
        container.addEventListener("change", (event) => {
            const filter = event.target.dataset.entityFilter;
            if (!filter) return;
            applicationState.investigation.entityFilters[filter] =
                event.target.value;
            renderGraphContent(container);
        });
        container.addEventListener("input", (event) => {
            if (!event.target.matches("[data-entity-search]")) return;
            applicationState.investigation.entityFilters.query =
                event.target.value;
            const match = currentData.entities.find(
                (entity) =>
                    entity.label
                        .toLowerCase()
                        .includes(event.target.value.toLowerCase()) ||
                    entity.value
                        .toLowerCase()
                        .includes(event.target.value.toLowerCase()),
            );
            applicationState.investigation.selectedEntityId = match?.id ?? null;
            renderGraphContent(container);
            container.querySelector("[data-entity-search]")?.focus();
        });
        container.addEventListener("keydown", (event) => {
            if (event.key === "Escape") {
                container
                    .querySelector(".entity-graph-panel")
                    ?.classList.remove("is-fullscreen-fallback");
                return;
            }
            if (
                (event.key === "Enter" || event.key === " ") &&
                event.target.closest("[data-entity-id], [data-relationship-id]")
            ) {
                event.preventDefault();
                handleGraphClick(event, container);
            }
        });
        container.dataset.graphInitialised = "true";
    }
    renderGraphContent(container);
}

export function highlightEntity(entityId) {
    applicationState.investigation.selectedEntityId = entityId;
    applicationState.investigation.selectedRelationshipId = null;
    const entity = currentData?.entities.find((item) => item.id === entityId);
    if (entity) {
        applicationState.investigation.entityFilters.query = "";
        applicationState.investigation.entityFilters.type = "all";
        applicationState.investigation.entityFilters.risk = "all";
    }
}

export function resetEntityGraph() {
    positions = structuredClone(defaultPositions);
}
