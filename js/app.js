import { initialiseFilters } from "./filters.js";
import { initialiseNavigation } from "./navigation.js";
import { initialiseWorkflow } from "./workflow.js";
import { initialiseCopilot } from "./copilot.js";
import { initialiseDecisionModals } from "./modals.js";
import { initialiseDocumentEditor } from "./editor.js";
import { initialiseDocumentActions } from "./documents.js";
import { initialiseInvestigationTabs } from "./investigation-tabs.js";

function validateApplicationMarkup() {
    const requiredElementIds = [
        "rows",
        "ticketSearch",
        "global",
        "filterSeverity",
        "filterStage",
        "filterOwner",
        "caseChat",
        "decisionModalOverlay",
        "reviewModalOverlay",
    ];

    const missingIds = requiredElementIds.filter(
        (id) => !document.getElementById(id),
    );

    if (missingIds.length > 0) {
        throw new Error(
            `Aegis startup failed. Missing elements: ${missingIds.join(", ")}`,
        );
    }
}

function initialiseApplication() {
    validateApplicationMarkup();
    initialiseFilters();
    initialiseWorkflow();
    initialiseCopilot();
    initialiseDecisionModals();
    initialiseDocumentActions();
    initialiseDocumentEditor();
    initialiseInvestigationTabs();
    initialiseNavigation();
}

document.addEventListener("DOMContentLoaded", initialiseApplication);
