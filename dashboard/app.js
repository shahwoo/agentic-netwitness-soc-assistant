const state = {
  page: 'dashboard',
  caseData: null,
  triage: null,
  investigation: null,
  reporting: null,
};

const pageMeta = {
  dashboard: ['Main Dashboard', 'Combined view of available agent outputs'],
  agents: ['Agent Panel', 'Readiness status for triage, investigation, and reporting'],
  reports: ['Reports', 'Display final_report.json when available'],
  triage: ['Triage Result', 'Reads outputs/triage_result.json'],
  investigation: ['Investigation Result', 'Reads outputs/investigation_result.json'],
  reporting: ['Reporting Result', 'Reads outputs/final_report.json'],
};

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => Array.from(document.querySelectorAll(selector));

function escapeHtml(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}

function pretty(value) {
  if (value === null || value === undefined || value === '') return 'Not ready yet';
  if (Array.isArray(value)) return value.length ? value.join(', ') : 'Not ready yet';
  if (typeof value === 'object') return JSON.stringify(value, null, 2);
  return String(value);
}

function statusBadge(result) {
  if (!result || !result.ready) {
    return '<span class="badge badge-gray"><i class="ti ti-clock"></i>Not ready yet</span>';
  }
  return '<span class="badge badge-green"><i class="ti ti-check"></i>Ready</span>';
}

function severityBadge(value) {
  const text = pretty(value);
  const lower = text.toLowerCase();
  let type = 'gray';
  if (['critical', 'high'].some((word) => lower.includes(word))) type = lower.includes('critical') ? 'red' : 'orange';
  if (['medium', 'low'].some((word) => lower.includes(word))) type = lower.includes('medium') ? 'blue' : 'green';
  return `<span class="badge badge-${type}"><i class="ti ti-alert-circle"></i>${escapeHtml(text)}</span>`;
}

function toast(message, type = 'blue') {
  const colours = {
    blue: 'var(--blue)',
    green: 'var(--green)',
    red: 'var(--red)',
    orange: 'var(--yellow)',
  };
  const t = $('#toast');
  t.innerHTML = `<strong>${escapeHtml(message)}</strong><div class="tiny muted mono" style="margin-top:3px">${new Date().toLocaleTimeString()}</div>`;
  t.style.borderColor = colours[type] || colours.blue;
  t.style.display = 'block';
  clearTimeout(window.__toastTimer);
  window.__toastTimer = setTimeout(() => { t.style.display = 'none'; }, 3200);
}

function riskRing(value) {
  const number = Number(value);
  const safeValue = Number.isFinite(number) ? Math.max(0, Math.min(100, number)) : 0;
  const size = 76;
  const radius = (size - 12) / 2;
  const centre = size / 2;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (safeValue / 100) * circumference;
  return `
    <svg width="${size}" height="${size}" viewBox="0 0 ${size} ${size}">
      <circle cx="${centre}" cy="${centre}" r="${radius}" fill="none" stroke="var(--border)" stroke-width="6" />
      <circle cx="${centre}" cy="${centre}" r="${radius}" fill="none" stroke="var(--red)" stroke-width="6" stroke-dasharray="${circumference}" stroke-dashoffset="${offset}" stroke-linecap="round" transform="rotate(-90 ${centre} ${centre})" />
      <text x="${centre}" y="${centre - 2}" text-anchor="middle" fill="var(--txt)" font-size="16" font-weight="900">${safeValue || '-'}</text>
      <text x="${centre}" y="${centre + 13}" text-anchor="middle" fill="var(--txt2)" font-size="9">/100</text>
    </svg>
  `;
}

function workflowStep(label, result, iconReady, iconPending) {
  const ready = result && result.ready;
  const cls = ready ? 'wf-done' : 'wf-pending';
  const icon = ready ? iconReady : iconPending;
  return `
    <div class="wf-step">
      <div class="wf-icon ${cls}"><i class="ti ${icon}"></i></div>
      <div class="wf-label">${escapeHtml(label)}</div>
    </div>
  `;
}

async function apiGet(path) {
  const response = await fetch(path, { cache: 'no-store' });
  if (!response.ok) throw new Error(`${path} returned HTTP ${response.status}`);
  return response.json();
}

async function loadData() {
  try {
    const [caseData, triage, investigation, reporting] = await Promise.all([
      apiGet('/api/case'),
      apiGet('/api/triage'),
      apiGet('/api/investigation'),
      apiGet('/api/reporting'),
    ]);

    state.caseData = caseData;
    state.triage = triage;
    state.investigation = investigation;
    state.reporting = reporting;
    updateNavBadges();
    render();
  } catch (error) {
    $('#content').innerHTML = `<div class="empty-state">Could not load API data: ${escapeHtml(error.message)}</div>`;
    toast('Could not load Flask API data', 'red');
  }
}

function updateNavBadges() {
  const items = [
    ['triage-nav-badge', state.triage],
    ['investigation-nav-badge', state.investigation],
    ['reporting-nav-badge', state.reporting],
  ];

  for (const [id, result] of items) {
    const el = $(`#${id}`);
    if (!el) continue;
    el.textContent = result?.ready ? 'Ready' : 'N/A';
    el.classList.toggle('muted-badge', !result?.ready);
  }
}

function setPage(page) {
  state.page = page;
  const [title, sub] = pageMeta[page] || pageMeta.dashboard;
  $('#top-title').textContent = title;
  $('#top-sub').textContent = sub;
  $$('.nav-item').forEach((item) => item.classList.toggle('active', item.dataset.page === page));
  render();
}

function render() {
  const pages = {
    dashboard: renderDashboard,
    agents: renderAgents,
    reports: () => renderAgentDetail('Reporting Agent', state.reporting, 'final_report.json'),
    triage: () => renderAgentDetail('Triage Agent', state.triage, 'triage_result.json'),
    investigation: () => renderAgentDetail('Investigation Agent', state.investigation, 'investigation_result.json'),
    reporting: () => renderAgentDetail('Reporting Agent', state.reporting, 'final_report.json'),
  };
  $('#content').innerHTML = (pages[state.page] || renderDashboard)();
}

function renderDashboard() {
  const c = state.caseData?.case || {};
  const triage = state.triage;
  const investigation = state.investigation;
  const reporting = state.reporting;
  const anyReady = state.caseData?.ready;

  return `
    <div class="card incident-card">
      <div class="threat-icon"><i class="ti ti-virus"></i></div>
      <div style="flex:1">
        <div class="mono tiny muted">${escapeHtml(c.incident_id || 'No incident ID yet')}</div>
        <div class="incident-title">${escapeHtml(c.title || 'SOC case dashboard')}</div>
        <div class="section-sub">This dashboard reads existing JSON files only. Missing agent outputs are shown as Not ready yet.</div>
        <div class="badge-row">
          ${severityBadge(c.severity)}
          <span class="badge badge-blue"><i class="ti ti-percentage"></i>${escapeHtml(pretty(c.confidence))} Confidence</span>
          <span class="badge ${anyReady ? 'badge-green' : 'badge-gray'}"><i class="ti ${anyReady ? 'ti-check' : 'ti-clock'}"></i>${anyReady ? 'At least one output ready' : 'Not ready yet'}</span>
        </div>
      </div>
      <div class="score-ring">
        ${riskRing(c.risk_score)}
        <div class="score-caption">Risk Score</div>
      </div>
    </div>

    <div class="card workflow">
      <div class="section-title"><i class="ti ti-git-branch" style="color:var(--blue)"></i> Agent Output Workflow</div>
      <div class="workflow-steps">
        ${workflowStep('Triage Agent', triage, 'ti-check', 'ti-clock')}
        <div class="connector ${triage?.ready ? 'done' : 'pending'}"></div>
        ${workflowStep('Investigation Agent', investigation, 'ti-check', 'ti-lock')}
        <div class="connector ${investigation?.ready ? 'done' : 'pending'}"></div>
        ${workflowStep('Reporting Agent', reporting, 'ti-check', 'ti-file-report')}
      </div>
    </div>

    <div class="grid grid-3" style="margin-bottom:14px">
      ${agentSummaryCard('Triage Agent', triage, 'ti-alert-triangle')}
      ${agentSummaryCard('Investigation Agent', investigation, 'ti-search')}
      ${agentSummaryCard('Reporting Agent', reporting, 'ti-file-report')}
    </div>

    <div class="grid grid-2">
      <div class="card">
        <div class="section-title"><i class="ti ti-list-details" style="color:var(--teal)"></i> Combined Case Fields</div>
        ${fieldRow('Current Stage', c.current_stage)}
        ${fieldRow('Next Action', c.next_action)}
        ${fieldRow('Severity', c.severity)}
        ${fieldRow('Confidence', c.confidence)}
      </div>
      <div class="card">
        <div class="section-title"><i class="ti ti-code" style="color:var(--blue)"></i> Integration Boundary</div>
        <p class="section-sub">The frontend calls Flask using fetch(). Flask only reads files from outputs/. Agents are not rewritten, imported, or triggered.</p>
        <div class="badge-row">
          <span class="badge badge-blue">GET /api/case</span>
          <span class="badge badge-blue">GET /api/triage</span>
          <span class="badge badge-blue">GET /api/investigation</span>
          <span class="badge badge-blue">GET /api/reporting</span>
        </div>
      </div>
    </div>
  `;
}

function agentSummaryCard(name, result, icon) {
  const source = result?.source_file || 'outputs/not_ready.json';
  const data = result?.data || {};
  const currentStage = data.current_stage || data.report_status || data.status || result?.status || 'Not ready yet';

  return `
    <div class="card agent-card">
      <div style="display:flex;justify-content:space-between;gap:8px;align-items:center">
        <div class="section-title" style="margin-bottom:0"><i class="ti ${icon}" style="color:var(--blue)"></i>${escapeHtml(name)}</div>
        ${statusBadge(result)}
      </div>
      <p class="section-sub" style="margin-top:10px">Source: <span class="mono">${escapeHtml(source)}</span></p>
      <div class="metric-row">
        <div class="metric-mini"><strong>${result?.ready ? 'Yes' : 'No'}</strong><span>Ready</span></div>
        <div class="metric-mini"><strong>${escapeHtml(pretty(currentStage)).slice(0, 12)}</strong><span>Stage</span></div>
        <div class="metric-mini"><strong>${result?.reason ? '1' : '0'}</strong><span>Warnings</span></div>
      </div>
      ${result?.reason ? `<div class="evidence-row" style="margin-top:10px"><span>Reason</span><span class="ev-val warn">${escapeHtml(result.reason)}</span></div>` : ''}
    </div>
  `;
}

function renderAgents() {
  return `
    <div class="page-header">
      <div>
        <div class="page-title">Agent Panel</div>
        <p class="page-desc">This panel shows whether each agent output file is present. It does not run the agents yet.</p>
      </div>
      <button class="btn btn-blue" onclick="loadData()"><i class="ti ti-refresh"></i> Refresh</button>
    </div>
    <div class="grid grid-3">
      ${agentSummaryCard('Triage Agent', state.triage, 'ti-alert-triangle')}
      ${agentSummaryCard('Investigation Agent', state.investigation, 'ti-search')}
      ${agentSummaryCard('Reporting Agent', state.reporting, 'ti-file-report')}
    </div>
  `;
}

function renderAgentDetail(name, result, filename) {
  const ready = result?.ready;
  const data = ready ? result.data : null;

  return `
    <div class="page-header">
      <div>
        <div class="page-title">${escapeHtml(name)}</div>
        <p class="page-desc">Reading <span class="mono">outputs/${escapeHtml(filename)}</span></p>
      </div>
      ${statusBadge(result)}
    </div>

    <div class="grid grid-2" style="margin-bottom:14px">
      <div class="card">
        <div class="section-title"><i class="ti ti-info-circle" style="color:var(--blue)"></i>Status</div>
        ${fieldRow('Ready', ready ? 'Yes' : 'No')}
        ${fieldRow('Status', result?.status)}
        ${fieldRow('Source File', result?.source_file)}
        ${fieldRow('Reason', result?.reason || 'None')}
      </div>
      <div class="card">
        <div class="section-title"><i class="ti ti-database" style="color:var(--teal)"></i>Common Fields</div>
        ${fieldRow('Incident ID', data?.incident_id || data?.case_id || data?.id || data?.alert_id)}
        ${fieldRow('Severity', data?.severity || data?.classification || data?.risk_level)}
        ${fieldRow('Confidence', data?.confidence || data?.confidence_level)}
        ${fieldRow('Next Action', data?.next_action || data?.recommended_action || data?.recommendation)}
      </div>
    </div>

    <div class="card">
      <div class="section-title"><i class="ti ti-code" style="color:var(--blue)"></i>Raw JSON</div>
      <pre class="raw-box">${escapeHtml(ready ? JSON.stringify(data, null, 2) : 'Not ready yet')}</pre>
    </div>
  `;
}

function fieldRow(label, value) {
  return `
    <div class="evidence-row">
      <span>${escapeHtml(label)}</span>
      <span class="ev-val ${value ? '' : 'warn'}">${escapeHtml(pretty(value))}</span>
    </div>
  `;
}

function bindGlobalEvents() {
  $$('.nav-item[data-page], .btn[data-page]').forEach((el) => {
    el.addEventListener('click', () => setPage(el.dataset.page));
  });

  $('#refresh-button').addEventListener('click', () => {
    loadData();
    toast('Dashboard data refreshed', 'blue');
  });

  $('#reload-api').addEventListener('click', () => {
    loadData();
    toast('API data reloaded', 'blue');
  });

  $('#toggle-theme').addEventListener('click', () => {
    document.body.classList.toggle('light');
    toast('Theme toggled', 'blue');
  });
}

bindGlobalEvents();
loadData();
