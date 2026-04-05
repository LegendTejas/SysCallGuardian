/**
 * Main Application logic, Lifecycle, and Data Loading for Unified Dashboard.
 */

// ── State ────────────────────────────────────────────────────────────────────
// selectedRole is also used in auth.js; use var to avoid redeclaration errors
if (typeof selectedRole === 'undefined') { var selectedRole = 'Admin'; }
let livePaused = false;
let liveInterval = null;
let logPage = 1;
const LOGS_PER_PAGE = 8;
let liveCount = { allowed: 0, blocked: 0, susp: 0 };
let liveEventCount = 0;
let chartsInit = false;

// ── Dashboard Lifecycle ───────────────────────────────────────────────────────

async function initDashboard() {
  const role = (localStorage.getItem('sg_role') || 'guest').toLowerCase();
  
  // 1. Initial data fetch (all roles get dashboard stats)
  await refreshDashboard();
  
  // 2. Role-specific initialization
  if (role === 'admin') {
    loadSuspiciousUsers();
    renderPolicies();
    renderLogs();
  } else if (role === 'developer') {
    renderPolicies();  // Will use preview endpoint
    renderLogs();
  }
  // Guest: only overview + live feed (no policies, no logs page, no threats)
  
  startLiveFeed();
}

/**
 * Fetches all necessary data for the unified dashboard and updates charts.
 */
async function refreshDashboard() {
  const statusText = document.getElementById('ov-filter-status-text');
  if (statusText) statusText.textContent = 'Syncing…';

  const filters = {};
  const user  = document.getElementById('ov-filter-user')?.value;
  const stat  = document.getElementById('ov-filter-status')?.value;
  const call  = document.getElementById('ov-filter-call')?.value;
  const role  = document.getElementById('ov-filter-role')?.value;
  
  if (user && user !== 'ALL') filters.user = user;
  if (stat && stat !== 'ALL') filters.status = stat;
  if (call && call !== 'ALL') filters.call_type = call;
  if (role && role !== 'ALL') filters.role = role;

  // 1. Fetch Stats, Activity, and Extended Data with active filters
  const [statsRes, activityRes, extendedRes] = await Promise.all([
    apiGetStats(filters),
    apiGetActivity(filters),
    apiGetExtended(filters)
  ]);

  if (statsRes.ok && activityRes.ok && extendedRes.ok && statsRes.data && activityRes.data && extendedRes.data) {
    const stats = statsRes.data;
    const activity = activityRes.data;
    const extended = extendedRes.data;

    // 2. Update KPI Cards
    setStatCard('stat-total', stats.total_calls, `↑ +${stats.total_calls} total`);
    setStatCard('stat-allowed', stats.allowed, `${((stats.allowed/stats.total_calls)*100 || 0).toFixed(1)}% pass rate`);
    setStatCard('stat-blocked', stats.blocked, `✗ ${stats.blocked} blocked`);
    setStatCard('stat-flagged', stats.suspicious_users, `⚠ ${stats.suspicious_users} high risk`);

    // 3. Update Charts
    updateDashboardCharts(stats, activity, extended);

    // 4. Apply overview filters and update Recent Logs Table
    const filtered = await _applyOverviewFilter(extended.recent_logs || []);
    updateOverviewRecentLogs(filtered);

    // 5. Populate Filter Dropdowns dynamically (only if first time)
    if (document.getElementById('ov-filter-user').children.length <= 1) {
      populateFilterDropdowns(extended);
    }
  } else {
    // API failed, display error state instead of getting stuck on loading
    setStatCard('stat-total', 'Error', `Connection failed`);
    setStatCard('stat-allowed', 'Error', `—`);
    setStatCard('stat-blocked', 'Error', `—`);
    setStatCard('stat-flagged', 'Error', `—`);
    if (statusText) statusText.textContent = 'API Offline';
    return;
  }

  if (statusText) {
    const now = new Date().toLocaleTimeString('en-IN', { hour: '2-digit', minute: '2-digit' });
    statusText.textContent = `Last synced: ${now}`;
  }
}

function resetOverviewFilters() {
  ['ov-filter-user', 'ov-filter-status', 'ov-filter-call', 'ov-filter-role'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.value = 'ALL';
  });
  refreshDashboard();
}

async function _applyOverviewFilter(logs) {
  const statusVal = document.getElementById('ov-filter-status')?.value || 'ALL';
  const callVal   = document.getElementById('ov-filter-call')?.value   || 'ALL';
  const userVal   = document.getElementById('ov-filter-user')?.value   || 'ALL';
  // Note: role filter applies to charts only (recent_logs has no role field)
  if (!logs) return [];
  return logs.filter(l => {
    if (statusVal !== 'ALL' && l.status !== statusVal) return false;
    if (callVal   !== 'ALL' && l.call_type !== callVal) return false;
    if (userVal   !== 'ALL' && l.user !== userVal)      return false;
    return true;
  });
}

function setStatCard(id, value, delta) {
  const card = document.getElementById(id);
  if (!card) return;
  const valEl = card.querySelector('.stat-value');
  if (valEl) valEl.textContent = Number(value).toLocaleString();
  const deltaEl = card.querySelector('.stat-delta');
  if (deltaEl) deltaEl.textContent = delta;
}

function populateFilterDropdowns(data) {
  const userSelect = document.getElementById('ov-filter-user');
  const callSelect = document.getElementById('ov-filter-call');

  // Extract unique users and calls from heatmap/stats
  const users = [...new Set(data.heatmap.map(h => h.username))].sort();
  const calls = [...new Set(data.heatmap.map(h => h.call_type))].sort();

  users.forEach(u => {
    const opt = new Option(u, u);
    userSelect?.add(opt);
  });
  calls.forEach(c => {
    const opt = new Option(c, c);
    callSelect?.add(opt);
  });
}

function updateOverviewRecentLogs(logs) {
  const tbody = document.querySelector('#ov-recent-table tbody');
  if (!tbody) return;

  // If no logs provided in extended, fallback to a standard log fetch
  if (!logs || logs.length === 0) {
    loadRecentLogs(); // existing fallback
    return;
  }

  tbody.innerHTML = logs.slice(0, 6).map(l => `
    <tr onclick="openLogModal('${l.user}','${l.call_type}','${l.status}','${formatTime(l.timestamp)}','${l.target_path || '—'}','—')">
      <td class="mono-text">${l.user}</td>
      <td class="mono-text">${l.call_type}</td>
      <td>${statusBadgeHtml(l.status)}</td>
      <td class="mono-text">${formatTime(l.timestamp)}</td>
    </tr>`).join('');
}

// ── Existing Loaders (Updated for Unified) ───────────────────────────────────

async function loadRecentLogs() {
  const res = await apiGetLogs({ page: 1, per_page: 6 });
  if (res.ok) updateOverviewRecentLogs(res.data.logs);
}

async function loadSuspiciousUsers() {
  const res = await apiGetThreats();
  if (!res.ok) return;

  const count = (res.data || []).length;
  const badge = document.querySelector('#nav-threats .nav-badge');
  if (badge) {
    badge.textContent = count;
    badge.style.display = count > 0 ? 'flex' : 'none';
  }
}

// ── Live Feed (Simulated for Demo) ───────────────────────────────────────────

const MOCK_LIVE = [
  { status: 'allowed', user: 'Tejax', call: 'file_read', path: '/etc/hosts' },
  { status: 'blocked', user: 'Vancika', call: 'exec_process', path: '/bin/sh' },
  { status: 'flagged', user: 'Akael', call: 'net_socket', path: '10.0.0.5:80' },
  { status: 'allowed', user: 'Tejax', call: 'dir_list', path: '/var/log/gateway' },
  { status: 'allowed', user: 'Vancika', call: 'file_write', path: '/home/dev/app.py' },
  { status: 'blocked', user: 'Akael', call: 'file_delete', path: '/etc/config' },
];

function startLiveFeed() {
  if (liveInterval) return;
  const role = (localStorage.getItem('sg_role') || 'guest').toLowerCase();
  const currentUser = localStorage.getItem('sg_username') || '';
  
  liveInterval = setInterval(async () => {
    if (livePaused) return;

    let ev = MOCK_LIVE[Math.floor(Math.random() * MOCK_LIVE.length)];
    
    // Guest: only show their own events
    if (role === 'guest') {
      ev = { ...ev, user: currentUser };
    }
    
    addLiveRow(ev, true);

    liveEventCount++;
    document.getElementById('live-badge').textContent = liveEventCount;

    // Every 10 events, refresh the whole dashboard to sync real stats
    if (liveEventCount % 10 === 0) refreshDashboard();
  }, 3000);
}

function addLiveRow(ev, animate) {
  const feed = document.getElementById('live-feed');
  if (!feed) return;
  const now = new Date().toLocaleTimeString('en-IN', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  const row = document.createElement('div');
  row.className = 'live-entry' + (animate ? ' new-row' : '');
  row.innerHTML = `
    <div class="live-entry-status">${statusBadgeHtml(ev.status)}</div>
    <div class="live-entry-user">${ev.user}</div>
    <div class="live-entry-call">${ev.call} · <span style="color:var(--text3)">${ev.path}</span></div>
    <div class="live-entry-time">${now}</div>`;
  row.onclick = () => openLogModal(ev.user, ev.call, ev.status, now, ev.path, '—');
  feed.insertBefore(row, feed.firstChild);
  if (feed.children.length > 50) feed.removeChild(feed.lastChild);
}

function toggleLiveFeed(btn) {
  livePaused = !livePaused;
  btn.textContent = livePaused ? '▶ Resume' : '⏸ Pause';
}

// ── Policy Management (Visual Editor) ─────────────────────────────────────────

let POLICIES_DATA = [];

/**
 * Renders the visual policy list.
 * Exposed to window so goPage() in ui.js can always find it.
 */
window.renderPolicies = async function() {
  const list = document.getElementById('policy-list');
  if (!list) return;
  
  list.innerHTML = `<div style="padding:20px;color:var(--text3);font-family:var(--mono);font-size:12px;">Syncing policy data…</div>`;

  const result = await api('GET', '/api/policies');
  if (!result.ok) {
    list.innerHTML = `
      <div style="padding:24px;text-align:center;color:var(--danger);font-family:var(--mono);font-size:12px;border:1px dashed var(--border);">
        <div style="margin-bottom:8px;">⚠ Sync Failed</div>
        <div style="opacity:0.7;">${result.data?.error || 'Access Denied or Connection Error'}</div>
        <button class="btn sm" style="margin-top:12px;" onclick="renderPolicies()">Retry Sync</button>
      </div>`;
    return;
  }

  // Handle both array and object responses
  POLICIES_DATA = Array.isArray(result.data) ? result.data : (result.data?.policies || []);
  const active  = POLICIES_DATA.filter(p => p.is_active).length;

  // Update header and stat cards
  const tag = document.querySelector('#page-policies .tag.live');
  if (tag) tag.textContent = `${active} enabled`;
  const countEl = document.querySelector('#page-policies .stat-value');
  if (countEl) countEl.textContent = active;

  if (!POLICIES_DATA.length) {
    list.innerHTML = `
      <div style="padding:48px 24px;text-align:center;color:var(--text3);
                  font-family:var(--mono);font-size:12px;border:1px dashed var(--border);border-radius:var(--radius);">
        <div style="font-size:24px;margin-bottom:12px;opacity:0.3;">🛡</div>
        No active policies found in the gateway.<br>All system calls currently use default RBAC.
        <button class="btn primary sm" style="margin-top:16px;" onclick="openCreatePolicyModal()">+ Create First Policy</button>
      </div>`;
    return;
  }

  list.innerHTML = POLICIES_DATA.map(p => {
    let rule;
    try {
      rule = (typeof p.rule_json === 'string') ? JSON.parse(p.rule_json) : (p.rule_json || {});
    } catch(e) { rule = {}; }
    
    const allowStr    = (rule.allow_roles || []).join(', ') || '—';
    const denyStr     = (rule.deny_roles  || []).join(', ') || '—';
    const condParts   = [];
    if (rule.conditions?.max_risk_score != null)
      condParts.push(`max_risk: ${rule.conditions.max_risk_score}`);
    
    const condStr = condParts.length ? ` · ${condParts.join(' · ')}` : '';
    const safeP   = encodeURIComponent(JSON.stringify(p));

    return `
      <div class="policy-item">
        <div class="policy-status-toggle ${p.is_active ? 'on' : 'off'}"
             onclick="togglePolicy(${p.id}, ${p.is_active}, event)"
             title="${p.is_active ? 'Click to disable' : 'Click to enable'}">
        </div>
        <div class="policy-info" style="cursor:pointer;"
             onclick="openEditPolicyModal('${safeP}')">
          <div class="policy-name">${p.name}</div>
          <div class="policy-desc">
            action: <strong>${rule.action || '—'}</strong> ·
            allow: [${allowStr}] ·
            deny: [${denyStr}]${condStr}
          </div>
        </div>
        <div class="policy-meta">
          <span class="tag ${p.is_active ? 'live' : 'info-tag'}">
            ${p.is_active ? 'ACTIVE' : 'DISABLED'}
          </span>
          <button class="btn sm"
            onclick="event.stopPropagation(); openEditPolicyModal('${safeP}')"
            style="font-size:11px;padding:3px 10px;">
            Edit
          </button>
        </div>
      </div>`;
  }).join('');
}


async function togglePolicy(id, currentState, ev) {
  ev.stopPropagation();

  // Optimistic UI update
  const toggle = ev.currentTarget;
  toggle.classList.toggle('on',  !currentState);
  toggle.classList.toggle('off',  currentState);

  const result = await api('PUT', `/api/policies/${id}`, { is_active: !currentState });

  if (!result.ok) {
    // Revert on failure
    toggle.classList.toggle('on',   currentState);
    toggle.classList.toggle('off',  !currentState);
    showToast('danger', result.data?.error || 'Failed to update policy.');
    return;
  }

  showToast(
    currentState ? 'warn' : 'success',
    `Policy ${currentState ? 'disabled' : 'enabled'}.`
  );
  await renderPolicies();
}

// Format rule JSON for prettier display
function formatRuleJson(rule) {
  try {
    return JSON.stringify(rule, null, 2)
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');
  } catch (e) {
    return JSON.stringify(rule);
  }
}

// Expand/collapse policy details (legacy support for old cards)
function expandPolicyDetails(id) {
  const ruleEl = document.getElementById(`policy-rule-${id}`);
  if (ruleEl) {
    const isHidden = ruleEl.style.display === 'none';
    ruleEl.style.display = isHidden ? 'block' : 'none';
  }
}

// ── Audit Logs ───────────────────────────────────────────────────────────────

async function renderLogs() {
  logPage = 1;
  await drawLogs();
}

async function drawLogs() {
  const tbody = document.getElementById('log-tbody');
  if (!tbody) return;

  const searchVal = (document.getElementById('log-search')?.value || '').toLowerCase().trim();
  const filters = {
    status:    document.getElementById('filter-status')?.value || '',
    user:      document.getElementById('filter-user')?.value  || '',
    call_type: document.getElementById('filter-call')?.value  || '',
    page:      logPage,
    per_page:  LOGS_PER_PAGE,
  };
  // Strip empty params so URLSearchParams doesn't send empty strings
  Object.keys(filters).forEach(k => { if (filters[k] === '') delete filters[k]; });

  const res = await apiGetLogs(filters);
  if (!res.ok) {
    tbody.innerHTML = `<tr><td colspan="7" style="text-align:center;padding:24px;color:var(--danger)">Failed to fetch logs: ${res.data?.error || 'Forbidden'}</td></tr>`;
    return;
  }

  const { logs, total } = res.data;

  // Client-side text search (path/user) after server-side filters
  const filtered = searchVal
    ? logs.filter(l => (l.target_path || '').toLowerCase().includes(searchVal) ||
                       (l.user || '').toLowerCase().includes(searchVal))
    : logs;

  tbody.innerHTML = filtered.map((l) => {
    const hash = l.hash_preview || '—';
    const time = l.timestamp ? new Date(l.timestamp).toLocaleTimeString('en-IN', { hour:'2-digit', minute:'2-digit' }) : '—';
    const safePath = (l.target_path || '—').replace(/'/g, "\\'");
    return `
    <tr class="log-row" onclick="openLogModal('${l.user}','${l.call_type}','${l.status}','${time}','${safePath}','—')">
      <td class="mono-text">#${l.id}</td>
      <td class="mono-text"><strong>${l.user}</strong></td>
      <td class="mono-text">${l.call_type}</td>
      <td class="mono-text" style="max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${l.target_path || '—'}</td>
      <td>${statusBadgeHtml(l.status)}</td>
      <td class="mono-text">${time}</td>
      <td class="hash-cell"><span class="hash-preview">${hash}</span></td>
    </tr>`;
  }).join('') || '<tr><td colspan="7" style="text-align:center;padding:24px;color:var(--text3)">No records found in audit trail</td></tr>';

  buildPagination(total);
  _populateLogFilterDropdowns(logs);
}

/**
 * Populate the filter-user and filter-call dropdowns from current log data.
 * Adds options if they don't already exist to avoid duplicates.
 */
function _populateLogFilterDropdowns(logs) {
  const userSel = document.getElementById('filter-user');
  const callSel = document.getElementById('filter-call');
  if (!userSel || !callSel) return;

  const existingUsers = new Set([...userSel.options].map(o => o.value).filter(Boolean));
  const existingCalls = new Set([...callSel.options].map(o => o.value).filter(Boolean));

  const users = [...new Set(logs.map(l => l.user).filter(Boolean))].sort();
  const calls = [...new Set(logs.map(l => l.call_type).filter(Boolean))].sort();

  users.forEach(u => {
    if (!existingUsers.has(u)) {
      const opt = new Option(u, u);
      userSel.add(opt);
    }
  });
  calls.forEach(c => {
    if (!existingCalls.has(c)) {
      const opt = new Option(c, c);
      callSel.add(opt);
    }
  });
}

function buildPagination(total) {
  const totalPages = Math.ceil(total / LOGS_PER_PAGE) || 1;
  const pag = document.getElementById('pagination');
  if (!pag) return;
  pag.innerHTML = '';

  for (let p = 1; p <= totalPages; p++) {
    const btn = document.createElement('button');
    btn.className = 'btn sm' + (p === logPage ? ' primary' : '');
    btn.textContent = p;
    btn.onclick = async () => { logPage = p; await drawLogs(); };
    pag.appendChild(btn);
  }
}

async function verifyIntegrity() {
  const integrityText = document.getElementById('integrity-text');
  if (!integrityText) return;
  
  integrityText.textContent = '⏳ Verifying SHA-256 hash chain…';
  
  const res = await apiVerifyLogs();
  if (res.ok) {
    const valid = res.data.status === 'valid';
    integrityText.textContent = res.data.message;
    showToast(valid ? 'success' : 'danger', valid ? 'SHA-256 chain verified.' : 'Tampering detected!');
  } else {
    integrityText.textContent = 'Verification failed.';
    showToast('warn', 'Connection error.');
  }
}

// ── System Call Gateway ───────────────────────────────────────────────────────
// NOTE: initSyscallPage, selectOp, updatePreview, executeSyscall,
//       clearSyscallHistory, loadScenario, and currentOp are all defined in
//       the inline <script> block in index.html (the authoritative implementation).
//       They are NOT duplicated here to avoid re-declaration errors and conflicts.

// ── Threats ──────────────────────────────────────────────────────────────────

async function loadThreatsPage() {
  const res = await apiGetThreats();
  if (!res.ok) return;

  const users = res.data;
  const container = document.querySelector('.threat-events');
  if (!container) return;

  container.innerHTML = users.map(u => {
    const level = u.risk_score >= 70 ? 'critical' : u.risk_score >= 40 ? 'warning' : 'low';
    return `
      <div class="threat-event ${level}" onclick="openThreatModal('${u.username}','${level}','Risk score: ${u.risk_score}','${Math.round(u.risk_score)}')">
        <div class="threat-event-body">
          <div class="threat-event-title">${u.username} — ${level.toUpperCase()} Risk</div>
          <div class="threat-event-meta">Score: ${u.risk_score.toFixed(1)} · ${u.role}</div>
        </div>
        <span class="threat-badge ${level}">${level.toUpperCase()}</span>
      </div>`;
  }).join('');
}


// ── Startup ──────────────────────────────────────────────────────────────────

window.addEventListener('DOMContentLoaded', () => {
  if (isLoggedIn()) {
    const role = localStorage.getItem('sg_role') || 'Guest';
    const user = localStorage.getItem('sg_username') || 'User';

    // Restore Nav UI
    const nameEl = document.getElementById('nav-username');
    const roleEl = document.getElementById('nav-role');
    const avatEl = document.getElementById('nav-avatar');
    if (nameEl) nameEl.textContent = user;
    if (roleEl) roleEl.textContent = role.charAt(0).toUpperCase() + role.slice(1);
    if (avatEl) avatEl.textContent = user[0].toUpperCase();

    applyRBAC(role);
    showView('dashboard');
    startClock();
    goPage('overview');
    initDashboard();
  }
});
