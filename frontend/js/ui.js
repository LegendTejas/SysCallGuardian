/**
 * UI Utilities: Navigation, Modals, Toasts, and Clock.
 */

function showView(name) {
  document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
  document.getElementById(name + '-view').classList.add('active');
}

function goPage(name) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  
  const page = document.getElementById('page-' + name);
  if (page) page.classList.add('active');
  
  const nav = document.getElementById('nav-' + name);
  if (nav) nav.classList.add('active');

  // Phase 4: Page-specific initialization & Live reloads
  if (name === 'syscalls' && typeof initSyscallPage === 'function') initSyscallPage();
  if (name === 'threats'  && typeof loadThreatsPage === 'function') loadThreatsPage();
  if (name === 'users'    && typeof loadUsersPage   === 'function') loadUsersPage();
  if (name === 'policies' && typeof renderPolicies  === 'function') renderPolicies();
}

/**
 * Apply Role-Based Access Control to the UI
 */
function applyRBAC(role) {
  const r = role.toLowerCase();
  localStorage.setItem('sg_role', r);

  // ── Step 1: Reset everything to visible ──
  const allNavs = ['overview', 'live', 'users', 'policies', 'syscalls', 'threats', 'logs'];
  allNavs.forEach(id => {
    const el = document.getElementById('nav-' + id);
    if (el) el.style.display = 'flex';
  });
  ['monitor', 'access', 'security'].forEach(id => {
    const el = document.getElementById('label-' + id);
    if (el) el.style.display = 'block';
  });

  // Reset overview title
  const title = document.querySelector('#page-overview h1');
  if (title) title.textContent = 'System Overview';
  const subtitle = document.querySelector('#page-overview p');
  if (subtitle) subtitle.textContent = 'Real-time analytics · unified security monitoring';

  // Show all chart sections by default
  const chartSections = ['chart-heatmap', 'chart-role-dist', 'chart-risk', 'ov-filter-bar'];
  chartSections.forEach(id => {
    const el = document.getElementById(id);
    if (el) el.style.display = '';
  });

  // ── Step 2: Admin — full access, stop here ──
  if (r === 'admin') return;

  // ── Step 3: Developer — hide Users & Roles, Threats. Show Policies read-only ──
  if (r === 'developer') {
    // Hidden pages
    ['users', 'threats'].forEach(id => {
      const el = document.getElementById('nav-' + id);
      if (el) el.style.display = 'none';
    });
    // Hide Access label (Users+Policies section header is misleading when Users is hidden)
    // But show Policies under a different grouping conceptually
    // Keep label-access hidden, policies nav stays visible
    const labelAccess = document.getElementById('label-access');
    if (labelAccess) labelAccess.style.display = 'none';

    // Mark Developer personal view
    if (title && !title.textContent.includes('(Personal View)')) {
      title.textContent += ' (Personal View)';
    }
    if (subtitle) subtitle.textContent = 'Showing activity for your account only.';
    return;
  }

  // ── Step 4: Guest — minimal access ──
  // Hidden: Users, Policies, Threats, Audit Logs
  ['users', 'policies', 'threats', 'logs'].forEach(id => {
    const el = document.getElementById('nav-' + id);
    if (el) el.style.display = 'none';
  });

  // Hide section labels (except Access because Syscalls is there)
  const labelAccess = document.getElementById('label-access');
  if (labelAccess) labelAccess.style.display = 'block'; 
  const labelSecurity = document.getElementById('label-security');
  if (labelSecurity) labelSecurity.style.display = 'none';

  // Personal View indicator
  if (title && !title.textContent.includes('(Personal View)')) {
    title.textContent += ' (Personal View)';
  }
  if (subtitle) subtitle.textContent = 'Showing activity for your account only.';

  // Hide advanced chart sections that don't apply to guests
  chartSections.forEach(id => {
    const el = document.getElementById(id);
    if (el) el.style.display = 'none';
  });
}

function startClock() {
  function tick() {
    const t = new Date().toLocaleTimeString('en-IN', { hour: '2-digit', minute: '2-digit', second: '2-digit' }) + ' IST';
    ['clock', 'clock2'].forEach(id => { 
      const el = document.getElementById(id); 
      if (el) el.textContent = t; 
    });
  }
  tick(); 
  setInterval(tick, 1000);
}

function showToast(type, msg) {
  const wrap = document.getElementById('toasts');
  if (!wrap) return;
  const t = document.createElement('div');
  t.className = 'toast ' + type;
  t.innerHTML = (type === 'success' ? '✓ ' : type === 'danger' ? '⚠ ' : type === 'warn' ? '⚡ ' : 'ℹ ') + msg;
  wrap.appendChild(t);
  setTimeout(() => { 
    t.style.animation = 'toastOut 0.25s ease forwards'; 
    setTimeout(() => t.remove(), 250); 
  }, 3000);
}

// ── Modals ───────────────────────────────────────────────────────────────────

function openLogModal(user, call, status, time, path, pid) {
  document.getElementById('modal-title').textContent = 'Syscall Log Detail';
  document.getElementById('modal-body').innerHTML = `
    <div class="modal-field"><div class="modal-field-label">User</div><div class="modal-field-value">${user}</div></div>
    <div class="modal-field"><div class="modal-field-label">Call Type</div><div class="modal-field-value">${call}</div></div>
    <div class="modal-field"><div class="modal-field-label">Path / Target</div><div class="modal-field-value">${path}</div></div>
    <div class="modal-field"><div class="modal-field-label">Status</div><div style="margin-top:4px">${statusBadgeHtml(status)}</div></div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
      <div class="modal-field"><div class="modal-field-label">PID</div><div class="modal-field-value">${pid}</div></div>
      <div class="modal-field"><div class="modal-field-label">Timestamp</div><div class="modal-field-value">${time}</div></div>
    </div>
    <div class="modal-field">
      <div class="modal-field-label">SHA-256 Hash</div>
      <div class="modal-field-value" style="font-size:11px;word-break:break-all">Fetching from server…</div>
    </div>`;
  const userRole = (localStorage.getItem('sg_role') || 'guest').toLowerCase();
  document.getElementById('modal-footer').innerHTML = `
    <button class="btn sm" onclick="closeModal()">Close</button>
    ${userRole === 'admin' ? '<button class="btn sm primary" onclick="showToast(\'success\',\'Log entry flagged for review!\');closeModal()">Flag Entry</button>' : ''}`;
  document.getElementById('modal-overlay').classList.add('open');
}

function openUserModal(name, role, status, calls, risk) {
  document.getElementById('modal-title').textContent = 'User Detail — ' + name;
  document.getElementById('modal-body').innerHTML = `
    <div style="display:flex;align-items:center;gap:12px;margin-bottom:20px;">
      <div class="user-avatar-lg" style="width:46px;height:46px;font-size:18px">${name[0].toUpperCase()}</div>
      <div><div style="font-size:16px;font-weight:500">${name}</div><div style="font-family:var(--mono);font-size:11px;color:var(--text3)">${role}</div></div>
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
      <div class="modal-field"><div class="modal-field-label">Status</div><div class="modal-field-value">${status}</div></div>
      <div class="modal-field"><div class="modal-field-label">Syscalls</div><div class="modal-field-value">${calls}</div></div>
      <div class="modal-field"><div class="modal-field-label">Risk Score</div><div class="modal-field-value" style="color:${parseInt(risk) > 60 ? 'var(--danger)' : parseInt(risk) > 30 ? 'var(--warning)' : 'var(--accent)'}">${risk}</div></div>
      <div class="modal-field"><div class="modal-field-label">Role</div><div class="modal-field-value">${role}</div></div>
    </div>`;
  const userRole = (localStorage.getItem('sg_role') || 'guest').toLowerCase();
  document.getElementById('modal-footer').innerHTML = `
    <button class="btn sm" onclick="closeModal()">Close</button>
    ${userRole === 'admin' ? `<button class="btn sm" onclick="showToast('warn','Session revoked for ${name}!');closeModal()">Revoke Session</button>` : ''}
    <button class="btn sm primary" onclick="goPage('logs');document.getElementById('filter-user').value='${name}';renderLogs();closeModal()">View Logs →</button>`;
  document.getElementById('modal-overlay').classList.add('open');
}

function openThreatModal(user, level, desc, risk) {
  document.getElementById('modal-title').textContent = 'Threat Detail — ' + user;
  document.getElementById('modal-body').innerHTML = `
    <div class="modal-field"><div class="modal-field-label">User</div><div class="modal-field-value">${user}</div></div>
    <div class="modal-field"><div class="modal-field-label">Threat Level</div><div style="margin-top:4px"><span class="threat-badge ${level.toLowerCase()}">${level.toUpperCase()}</span></div></div>
    <div class="modal-field"><div class="modal-field-label">Risk Score</div><div class="modal-field-value" style="color:var(--danger)">${risk}/100</div></div>
    <div class="modal-field"><div class="modal-field-label">Description</div><div class="modal-field-value" style="font-size:12px;line-height:1.6">${desc}</div></div>`;
  const userRole = (localStorage.getItem('sg_role') || 'guest').toLowerCase();
  document.getElementById('modal-footer').innerHTML = `
    <button class="btn sm" onclick="closeModal()">Dismiss</button>
    ${userRole === 'admin' ? `<button class="btn sm" onclick="showToast('warn','User ${user} blocked!');closeModal()">Block User</button>` : ''}
    <button class="btn sm primary" onclick="goPage('logs');document.getElementById('filter-user').value='${user}';renderLogs();closeModal()">Inspect Logs →</button>`;
  document.getElementById('modal-overlay').classList.add('open');
}

function closeModal(e) {
  if (e && e.target !== document.getElementById('modal-overlay')) return;
  document.getElementById('modal-overlay').classList.remove('open');
}

// ── Helpers ──────────────────────────────────────────────────────────────────

function formatTime(isoString) {
  if (!isoString) return '—';
  return new Date(isoString).toLocaleTimeString('en-IN', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

function getRiskLevel(score) {
  if (score >= 70) return 'critical';
  if (score >= 40) return 'high';
  if (score >= 20) return 'medium';
  return 'low';
}

function statusBadgeHtml(status) {
  const map = {
    allowed: ['allowed', '✓ Allowed'],
    blocked: ['blocked', '✗ Blocked'],
    flagged: ['suspicious', '⚠ Flagged'],
    suspicious: ['suspicious', '⚠ Suspicious'],
  };
  const [cls, label] = map[status] || ['', status];
  return `<span class="status-badge ${cls}">${label}</span>`;
}
