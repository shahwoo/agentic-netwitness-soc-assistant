import { escapeHtml } from "./utils.js";

export function renderActivity(container, data, activityLog = []) {
    const items = [...activityLog, ...data.activity];
    container.innerHTML = `
        <section class="section case-panel investigation-panel">
            <div class="investigation-panel__head"><div><h3>Activity</h3><p>Actions performed by analysts and Aegis agents inside the platform</p></div></div>
            <div class="activity-list">
                ${items.length ? items.map((item) => `<div class="activity-item"><i aria-hidden="true">✓</i><div><b>${escapeHtml(item.title)}</b><span>${escapeHtml(item.description)}</span></div><time>${escapeHtml(item.time)}</time></div>`).join("") : '<div class="investigation-empty">No analyst or Aegis activity is available for this case.</div>'}
            </div>
        </section>`;
}
