export const applicationState = {
    activePage: "operations",
    activeCaseId: null,
    activeWorkflowStage: "threat-intelligence",
    selectedQueueFilter: "all",
    currentSort: {
        key: null,
        direction: 1,
    },
    caseDecisions: {},
    generatedDocuments: {},
    documentEdits: {},
    reportSaves: {},
    documentsGenerating: {},
    documentFailures: {},
    investigation: {
        activeTab: "overview",
        previousTab: null,
        selectedTimelineEventId: null,
        selectedMitreMappingId: null,
        selectedEntityId: null,
        selectedRelationshipId: null,
        selectedEvidenceId: null,
        timelineOrder: "oldest",
        timelineFilters: {
            category: "all",
            source: "all",
            severity: "all",
            entityType: "all",
            tactic: "all",
        },
        entityFilters: { type: "all", risk: "all", query: "" },
        mitreTactic: "all",
        validationStatuses: {},
        graph: { scale: 1, offsetX: 0, offsetY: 0 },
    },
};

export const currentUser = {
    name: "Soong Yang",
    initials: "SY",
};
