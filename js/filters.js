import { applicationState } from "./state.js";
import { setText, showToast } from "./utils.js";

let navigationActions = null;
const rowList = [...document.querySelectorAll("#rows tr")],
    ticketSearch = document.getElementById("ticketSearch"),
    globalSearch = document.getElementById("global"),
    toastBox = document.getElementById("toast"),
    filterSeverity = document.getElementById("filterSeverity"),
    filterStage = document.getElementById("filterStage"),
    filterOwner = document.getElementById("filterOwner");
function filterRows() {
    const q = ticketSearch.value.toLowerCase(),
        sev = filterSeverity.value,
        stg = filterStage.value,
        own = filterOwner.value;
    rowList.forEach((row) => {
        const tab =
            applicationState.selectedQueueFilter === "all" ||
            row.dataset.severity === applicationState.selectedQueueFilter ||
            row.dataset.owner === applicationState.selectedQueueFilter ||
            (applicationState.selectedQueueFilter === "action" &&
                row.dataset.action === "true");
        const sevMatch = !sev || row.dataset.severity === sev;
        const stgMatch = !stg || row.dataset.currentStage === stg;
        const ownMatch = !own || row.dataset.owner === own;
        row.classList.toggle(
            "hidden",
            !(
                tab &&
                sevMatch &&
                stgMatch &&
                ownMatch &&
                row.textContent.toLowerCase().includes(q)
            ),
        );
    });
}
ticketSearch.addEventListener("input", filterRows);
[filterSeverity, filterStage, filterOwner].forEach((sel) =>
    sel.addEventListener("change", filterRows),
);
function showAllCasesView() {
    ticketSearch.value = "";
    filterSeverity.value = "";
    filterStage.value = "";
    filterOwner.value = "";
    globalSearch.value = "";
    navigationActions?.setView("operations");
    document.querySelector(".content").classList.add("cases-mode");
    document.getElementById("topOperationsNav").classList.remove("active");
    document.getElementById("topMyQueueNav").classList.remove("active");
    document.getElementById("topAllCasesNav").classList.add("active");
    setText("pageTitle", "All Cases");
    setText("viewTitle", "All Cases");
    setText(
        "viewCopy",
        "Every case across the SOC — searchable, filterable and sortable.",
    );
    setText("queueTitle", "All cases");
    setText("queueCopy", "Every case across the SOC, unfiltered.");
    document.querySelector(".foot").textContent =
        "Showing 26 of 51 open tickets across the SOC.";
    filterRows();
}
document.getElementById("topAllCasesNav").addEventListener("click", () => {
    location.hash = "all-cases";
    showAllCasesView();
});
document
    .querySelectorAll(".pipeline-wrap .stage[data-stage]")
    .forEach((stage) =>
        stage.addEventListener("click", () => {
            const name = stage.dataset.stage;
            filterStage.value = name;
            filterOwner.value = "mine";
            location.hash = "my-queue";
            navigationActions?.setView("mine");
            ticketSearch.scrollIntoView({
                behavior: "smooth",
                block: "center",
            });
            showToast(
                `${name} — my tickets`,
                `Showing your assigned tickets currently in ${name}.`,
            );
        }),
    );
document
    .querySelectorAll("[data-message]")
    .forEach((btn) =>
        btn.addEventListener("click", () => showToast(btn.dataset.message)),
    );
const severityRank = { critical: 3, high: 2, medium: 1, low: 0 },
    stageRank = {
        Parsing: 0,
        Triage: 1,
        "Threat Intelligence Enrichment": 2,
        Investigation: 3,
        Reporting: 4,
    };
const sortKeyGetters = {
    id: (row) => row.querySelector(".id").textContent.trim(),
    case: (row) =>
        row.querySelector(".case b").textContent.trim().toLowerCase(),
    severity: (row) => severityRank[row.dataset.severity] ?? 0,
    stage: (row) => stageRank[row.dataset.currentStage] ?? 0,
    owner: (row) => row.children[4].textContent.trim().toLowerCase(),
    next: (row) => {
        const b = row.querySelector(".next b"),
            s = row.querySelector(".next span");
        return (b ? b.textContent : s ? s.textContent : "")
            .trim()
            .toLowerCase();
    },
};
function sortRows(key) {
    applicationState.currentSort =
        applicationState.currentSort.key === key
            ? {
                  key,
                  direction: applicationState.currentSort.direction * -1,
              }
            : { key, direction: 1 };
    const getter = sortKeyGetters[key],
        sorted = [...rowList].sort((a, b) => {
            const va = getter(a),
                vb = getter(b);
            if (va < vb) return -1 * applicationState.currentSort.direction;
            if (va > vb) return 1 * applicationState.currentSort.direction;
            return 0;
        });
    const tbody = document.getElementById("rows");
    sorted.forEach((row) => tbody.appendChild(row));
    document.querySelectorAll("th.sortable").forEach((th) => {
        const arrow = th.querySelector(".sort-arrow"),
            active = th.dataset.sort === key;
        th.classList.toggle("sort-active", active);
        arrow.textContent = active
            ? applicationState.currentSort.direction === 1
                ? "▲"
                : "▼"
            : "";
    });
}
document
    .querySelectorAll("th.sortable")
    .forEach((th) =>
        th.addEventListener("click", () => sortRows(th.dataset.sort)),
    );
filterRows();
globalSearch.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && e.target.value)
        showToast("Global search", `Searching for “${e.target.value}”`);
});
globalSearch.addEventListener("input", (e) => {
    ticketSearch.value = e.target.value;
    filterRows();
});
const globalFilterToggle = document.getElementById("globalFilterToggle"),
    globalFilterPopover = document.getElementById("globalFilterPopover"),
    globalFilterSeverity = document.getElementById("globalFilterSeverity"),
    globalFilterStage = document.getElementById("globalFilterStage"),
    globalFilterOwner = document.getElementById("globalFilterOwner"),
    globalSortKey = document.getElementById("globalSortKey"),
    globalSortDirBtn = document.getElementById("globalSortDir");
globalFilterToggle.addEventListener("click", (e) => {
    e.stopPropagation();
    if (globalFilterPopover.hidden) {
        globalFilterSeverity.value = filterSeverity.value;
        globalFilterStage.value = filterStage.value;
        globalFilterOwner.value = filterOwner.value;
        globalSortKey.value = applicationState.currentSort.key || "";
        globalSortDirBtn.textContent =
            applicationState.currentSort.direction === 1 ? "▲" : "▼";
    }
    globalFilterPopover.hidden = !globalFilterPopover.hidden;
});
globalFilterSeverity.addEventListener("change", () => {
    filterSeverity.value = globalFilterSeverity.value;
    filterRows();
});
globalFilterStage.addEventListener("change", () => {
    filterStage.value = globalFilterStage.value;
    filterRows();
});
globalFilterOwner.addEventListener("change", () => {
    filterOwner.value = globalFilterOwner.value;
    filterRows();
});
globalSortKey.addEventListener("change", () => {
    const key = globalSortKey.value;
    if (key) {
        sortRows(key);
        globalSortDirBtn.textContent =
            applicationState.currentSort.direction === 1 ? "▲" : "▼";
    }
});
globalSortDirBtn.addEventListener("click", () => {
    const key = globalSortKey.value;
    if (key) {
        sortRows(key);
        globalSortDirBtn.textContent =
            applicationState.currentSort.direction === 1 ? "▲" : "▼";
    }
});
document.addEventListener("click", (e) => {
    if (
        !globalFilterPopover.hidden &&
        !globalFilterPopover.contains(e.target) &&
        e.target !== globalFilterToggle
    )
        globalFilterPopover.hidden = true;
});
document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && !globalFilterPopover.hidden)
        globalFilterPopover.hidden = true;
});

export function initialiseFilters() {
    filterRows();
}

export function configureFilterNavigation(actions) {
    navigationActions = actions;
}

export {
    filterRows,
    sortRows,
    rowList,
    ticketSearch,
    globalSearch,
    filterSeverity,
    filterStage,
    filterOwner,
    showAllCasesView,
};
