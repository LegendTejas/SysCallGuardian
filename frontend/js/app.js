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

    // 5. Populate Filter Dropdowns dynamically
    await populateFilterDropdowns(extended);

    // 6. Sync High-level threats/badges (Admins only)
    const role = (localStorage.getItem('sg_role') || 'guest').toLowerCase();
    if (role === 'admin') {
      loadSuspiciousUsers();
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

async function populateFilterDropdowns(data) {
  const userSelect = document.getElementById('ov-filter-user');
  const callSelect = document.getElementById('ov-filter-call');

  if (!userSelect || !callSelect) return;
  
  const currentUser = userSelect.value;
  const currentCall = callSelect.value;

  // 1. Clear existing options (except "All")
  while (userSelect.options.length > 1) userSelect.remove(1);
  while (callSelect.options.length > 1) callSelect.remove(1);

  // 2. Fetch ALL users from DB for comprehensive filtering (Admin/Dev)
  const userRes = await apiGetUsers();
  const users = userRes.ok ? userRes.data.map(u => u.username).sort() : [];
  
  // 3. Extract unique calls from recent log data
  const calls = [...new Set(data.heatmap.map(h => h.call_type))].sort();

  users.forEach(u => userSelect.add(new Option(u, u)));
  calls.forEach(c => callSelect.add(new Option(c, c)));

  // 4. Restore selection
  userSelect.value = currentUser;
  callSelect.value = currentCall;
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

  const threats = res.data || [];
  const count   = threats.length;

  // 1. Update Navigation Badge
  const badge = document.querySelector('#nav-threats .nav-badge');
  if (badge) {
    badge.textContent = count;
    badge.style.display = count > 0 ? 'flex' : 'none';
  }

  // 2. Update Overview Card (if it exists)
  const list = document.getElementById('suspicious-users-list');
  if (list) {
    if (count === 0) {
      list.innerHTML = `<div style="padding:24px;text-align:center;color:var(--text3);font-family:var(--mono);font-size:11px;opacity:0.6;">✓ No active threats detected.</div>`;
    } else {
      list.innerHTML = threats.slice(0, 4).map(t => `
        <div style="padding:12px 16px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:12px;cursor:pointer;" 
             onclick="openUserModal('${t.username}','${t.role}','Flagged','—','${t.risk_score}')">
          <div class="user-avatar" style="width:32px;height:32px;font-size:12px;">${t.username[0].toUpperCase()}</div>
          <div style="flex:1;">
            <div style="font-size:13px;font-weight:500;">${t.username}</div>
            <div style="font-size:10px;color:var(--danger);font-family:var(--mono);">${t.reason}</div>
          </div>
          <div style="text-align:right;">
            <div style="font-size:11px;font-weight:600;color:var(--danger);">${t.risk_score}</div>
            <div style="font-size:9px;color:var(--text3);font-family:var(--mono);">RISK</div>
          </div>
        </div>`).join('');
    }
  }

  // 3. Update Threats Page Table (if we're on it)
  if (document.getElementById('page-threats').classList.contains('active')) {
    loadThreatsPage();
  }
}

async function loadThreatsPage() {
  const list = document.getElementById('threat-events-list');
  if (!list) return;

  // 1. Fetch data
  const [threatRes, statsRes] = await Promise.all([
    apiGetThreatEvents(),
    apiGetStats()
  ]);
  
  if (!threatRes.ok) return;

  const threats = threatRes.data || [];
  const stats   = statsRes.ok ? statsRes.data : { blocked: 0 };

  // 2. Update Header Tag
  const tag = document.querySelector('#page-threats .tag.danger-tag');
  if (tag) tag.textContent = `${threats.length} events logged`;

  // 3. Update Summary Cards
  const criticalCount = threats.filter(t => t.risk_level === 'critical' || t.risk_score >= 70).length;
  const mediumCount   = threats.filter(t => t.risk_level === 'medium' || t.risk_level === 'high' || (t.risk_score >= 20 && t.risk_score < 70)).length;

  setEl('threat-count-critical', criticalCount);
  setEl('threat-count-medium',   mediumCount);
  setEl('threat-count-blocked',  stats.blocked || 0);
  
  const engineStatus = document.getElementById('threat-status-engine');
  if (engineStatus) engineStatus.textContent = threats.length > 0 ? '● ACTIVE' : '● IDLE';

  // 4. Render Event List (Grid Layout)
  if (threats.length === 0) {
    list.innerHTML = `<div style="padding:60px;text-align:center;color:var(--text3);font-family:var(--mono);font-size:13px;opacity:0.5;">
      <div style="font-size:32px;margin-bottom:12px;">🛡</div>
      All systems clear. No threat events recorded in the current window.
    </div>`;
    return;
  }

  list.innerHTML = threats.map(t => `
    <div style="padding:16px 20px;border-bottom:1px solid var(--border);display:grid;grid-template-columns:100px 140px 1fr 120px;align-items:center;gap:16px;background:var(--surface);">
      <div><span class="threat-badge ${t.risk_level}">${t.risk_level.toUpperCase()}</span></div>
      <div style="font-family:var(--mono);font-size:12px;font-weight:600;color:var(--text);">${t.username}</div>
      <div style="font-size:12px;color:var(--text2);">${t.reason}</div>
      <div style="font-family:var(--mono);font-size:11px;color:var(--text3);text-align:right;">${formatTime(t.time)}</div>
    </div>`).join('');
}

/** Helper to safely set textContent */
function setEl(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
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

  const role = (localStorage.getItem('sg_role') || 'guest').toLowerCase();
  
  // Update header and stat cards
  const tag = document.querySelector('#page-policies .tag.live');
  if (tag) tag.textContent = `${active} enabled`;
  const countEl = document.querySelector('#page-policies .stat-value');
  if (countEl) countEl.textContent = active;

  // READ-ONLY Banner for Developers
  const pageHeader = document.querySelector('#page-policies .page-header p');
  const createBtn = document.querySelector('#page-policies .btn.primary');
  
  if (role === 'developer') {
    if (pageHeader) pageHeader.innerHTML = `<span style="color:var(--accent);font-weight:600;">Policies: Read-only preview</span> · helps in understanding why a script might be getting blocked`;
    if (createBtn) createBtn.style.display = 'none';
  } else {
    if (pageHeader) pageHeader.textContent = 'Visual rule engine for mediated system call access.';
    if (createBtn) createBtn.style.display = '';
  }

  if (!POLICIES_DATA.length) {
    list.innerHTML = `
      <div style="padding:48px 24px;text-align:center;color:var(--text3);
                  font-family:var(--mono);font-size:12px;border:1px dashed var(--border);border-radius:var(--radius);">
        <div style="font-size:24px;margin-bottom:12px;opacity:0.3;">🛡</div>
        No active policies found in the gateway.<br>All system calls currently use default RBAC.
        ${role === 'admin' ? '<button class="btn primary sm" style="margin-top:16px;" onclick="openCreatePolicyModal()">+ Create First Policy</button>' : ''}
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
        ${role === 'admin' ? `
          <div class="policy-status-toggle ${p.is_active ? 'on' : 'off'}"
               onclick="togglePolicy(${p.id}, ${p.is_active}, event)"
               title="${p.is_active ? 'Click to disable' : 'Click to enable'}">
          </div>` : `
          <div class="policy-status-indicator" style="width:12px;height:12px;border-radius:3px;background:${p.is_active ? 'var(--accent)' : 'var(--text3)'};margin:0 14px;"></div>
        `}
        <div class="policy-info" 
             style="${role === 'admin' ? 'cursor:pointer;' : ''}"
             onclick="${role === 'admin' ? `openEditPolicyModal('${safeP}')` : ''}">
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
          ${role === 'admin' ? `
          <button class="btn sm"
            onclick="event.stopPropagation(); openEditPolicyModal('${safeP}')"
            style="font-size:11px;padding:3px 10px;">
            Edit
          </button>` : ''}
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

// ── Advanced Policies (Export/Import) ────────────────────────────────────────

async function exportPolicies() {
  showToast('info', 'Generating rule-set export…');
  const res = await apiExportPolicies();
  if (!res.ok) {
    showToast('danger', 'Failed to export policies.');
    return;
  }

  const data = JSON.stringify(res.data, null, 2);
  const blob = new Blob([data], { type: 'application/json' });
  const url  = window.URL.createObjectURL(blob);
  
  const a = document.createElement('a');
  const date = new Date().toISOString().split('T')[0];
  a.href = url;
  a.download = `syscall_guardian_rules_${date}.json`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  window.URL.revokeObjectURL(url);
  
  showToast('success', 'Security rule-set exported successfully.');
}

function importPolicies(input) {
  const file = input.files[0];
  if (!file) return;

  const reader = new FileReader();
  reader.onload = async (e) => {
    try {
      const data = JSON.parse(e.target.result);
      if (!Array.isArray(data)) {
        showToast('danger', 'Invalid format: Rule-set must be a JSON array.');
        return;
      }

      showToast('info', 'Uploading security rule-set…');
      const res = await apiImportPolicies(data);
      if (res.ok) {
        showToast('success', res.data.message || 'Policies imported successfully.');
        renderPolicies(); // Refresh list
      } else {
        showToast('danger', 'Import failed: ' + (res.data?.error || 'Unknown error'));
      }
    } catch (err) {
      showToast('danger', 'Parse error: Selected file is not valid JSON.');
    }
    // Reset input so it can be used again for the same file
    input.value = '';
  };
  reader.readAsText(file);
}

async function deletePolicyUI(id, name) {
  if (!confirm(`Are you sure you want to PERMANENTLY delete the policy "${name}"?`)) return;

  showToast('info', 'Deleting policy…');
  const res = await apiDeletePolicy(id);
  if (res.ok) {
    showToast('success', `Policy "${name}" removed.`);
    renderPolicies();
  } else {
    showToast('danger', 'Delete failed: ' + (res.data?.error || 'Access restricted'));
  }
}

// ── System Call Gateway ───────────────────────────────────────────────────────
// NOTE: initSyscallPage, selectOp, updatePreview, executeSyscall,
//       clearSyscallHistory, loadScenario, and currentOp are all defined in
//       the inline <script> block in index.html (the authoritative implementation).
// Consolidating startup logic and removing legacy duplicates.


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
    
    // Initial Explorer load
    setTimeout(renderExplorer, 1000);
  }
});

// ── File Explorer Logic ──────────────────────────────────────────────────────

async function renderExplorer() {
  const list = document.getElementById('explorer-list');
  if (!list) return;

  const res = await apiGetExplorer();
  if (!res.ok) {
    list.innerHTML = `<div class="explorer-empty">Access denied or sandbox unreachable.</div>`;
    return;
  }

  const entries = res.data.entries || [];
  if (entries.length === 0) {
    list.innerHTML = `<div class="explorer-empty">Sandbox is empty.<br>Use "Write File" or "Import" to add files.</div>`;
    return;
  }

  list.innerHTML = entries.map(e => `
    <div class="explorer-item" onclick="selectExplorerFile('${e.name}', '${e.type}')">
      <div class="explorer-item-icon">${e.type === 'dir' ? '📁' : '📄'}</div>
      <div class="explorer-item-info">
        <div class="explorer-item-name">${e.name}</div>
        <div class="explorer-item-meta">${e.type.toUpperCase()} ${e.size ? `· ${formatBytes(e.size)}` : ''}</div>
      </div>
    </div>
  `).join('');
}

function selectExplorerFile(name, type) {
  const pathInput = document.getElementById('input-filepath');
  if (pathInput) {
    pathInput.value = name;
    updatePreview();
    showToast('info', `Selected: ${name}`);
  }
}

async function importExternalFile(input) {
  const file = input.files[0];
  if (!file) return;

  if (!file.name.endsWith('.txt')) {
    showToast('danger', 'Only .txt files are allowed for import.');
    return;
  }

  const reader = new FileReader();
  reader.onload = async (e) => {
    const content = e.target.result;
    showToast('info', `Importing ${file.name}…`);
    
    const res = await apiWriteFile(file.name, content);
    if (res.ok) {
      showToast('success', `Successfully imported ${file.name}`);
      renderExplorer();
    } else {
      showToast('danger', `Import failed: ${res.data?.reason || 'Access Denied'}`);
    }
    input.value = ''; // Reset
  };
  reader.readAsText(file);
}

function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}
