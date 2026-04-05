/**
 * frontend/js/user_management.js
 * Phase 4 — User Management
 *
 * Replaces the static user cards with real data from /api/users.
 * Provides: role change, session revoke, flag clear.
 *
 * Functions exposed globally:
 *   loadUsersPage()
 *   openUserDetailModal(userJson)
 *   changeUserRole(id)
 *   revokeUserSession(id)
 *   unflagUser(id)
 */

// ── Load Users Page ───────────────────────────────────────────────────────────

window.loadUsersPage = async function() {
  const grid = document.getElementById('users-grid');
  if (!grid) return;

  grid.innerHTML = `
    <div style="grid-column:1/-1;padding:28px;text-align:center;
                color:var(--text3);font-family:var(--mono);font-size:12px;">
      Loading users…
    </div>`;

  // GET /api/users — REAL API CALL
  const result = await api('GET', '/api/users');

  if (!result.ok) {
    grid.innerHTML = `
      <div style="grid-column:1/-1;padding:28px;text-align:center;
                  color:var(--danger);font-family:var(--mono);font-size:12px;">
        Failed to load users: ${result.data?.error || 'Server error'}
      </div>`;
    return;
  }

  const users = result.data;

  if (!users.length) {
    grid.innerHTML = `
      <div style="grid-column:1/-1;padding:28px;text-align:center;
                  color:var(--text3);font-family:var(--mono);font-size:12px;">
        No users registered yet.
      </div>`;
    return;
  }

  // Update summary row above the grid if it exists
  _updateUserSummary(users);

  const roleColors = { admin: '',      developer: 'blue', guest: 'blue' };
  const roleIcons  = { admin: '🛡️', developer: '⚙️',   guest: '👤'  };

  grid.innerHTML = users.map(u => {
    const riskLevel  = _riskLevel(u.risk_score);
    const avatarColor = u.is_flagged ? 'red'
                      : u.risk_score >= 40 ? 'amber'
                      : roleColors[u.role] || '';
    const riskColor   = u.is_flagged || u.risk_score >= 70 ? 'var(--danger)'
                      : u.risk_score >= 40                 ? 'var(--warning)'
                      : u.risk_score >= 20                 ? 'var(--info)'
                      : 'var(--accent)';
    const flagBadge   = u.is_flagged
      ? `<span style="font-size:10px;color:var(--danger);font-family:var(--mono);margin-left:4px;">🔴 flagged</span>`
      : '';

    // Safely encode user object for onclick
    const safeJson = encodeURIComponent(JSON.stringify(u));

    return `
      <div class="user-card" onclick="openUserDetailModal('${safeJson}')">
        <div class="user-card-top">
          <div class="user-avatar-lg ${avatarColor}">
            ${u.username[0].toUpperCase()}
          </div>
          <div>
            <div class="user-card-name">${u.username}</div>
            <div class="user-card-role">
              ${roleIcons[u.role] || '👤'} ${u.role}${flagBadge}
            </div>
          </div>
        </div>
        <div class="user-card-stats">
          <div class="user-stat">
            <div class="user-stat-label">Syscalls</div>
            <div class="user-stat-val">${(u.total_calls || 0).toLocaleString()}</div>
          </div>
          <div class="user-stat">
            <div class="user-stat-label">${u.is_flagged || u.risk_score > 0 ? 'Risk' : 'Blocked'}</div>
            <div class="user-stat-val" style="color:${riskColor}">
              ${u.is_flagged || u.risk_score > 0
                ? Math.round(u.risk_score)
                : (u.blocked_calls || 0)}
            </div>
          </div>
        </div>
      </div>`;
  }).join('');
}


// ── User Summary Bar ──────────────────────────────────────────────────────────

function _updateUserSummary(users) {
  const total   = users.length;
  const flagged = users.filter(u => u.is_flagged).length;
  const admins  = users.filter(u => u.role === 'admin').length;

  // Update any summary elements in the page header area if they exist
  const totalEl   = document.getElementById('user-count-total');
  const flaggedEl = document.getElementById('user-count-flagged');
  const adminEl   = document.getElementById('user-count-admin');
  if (totalEl)   totalEl.textContent   = total;
  if (flaggedEl) flaggedEl.textContent = flagged;
  if (adminEl)   adminEl.textContent   = admins;
}


// ── User Detail Modal ─────────────────────────────────────────────────────────

function openUserDetailModal(userJson) {
  const u = typeof userJson === 'string'
    ? JSON.parse(decodeURIComponent(userJson))
    : userJson;

  const riskColor = u.risk_score >= 70 ? 'var(--danger)'
                  : u.risk_score >= 40 ? 'var(--warning)'
                  : u.risk_score >= 20 ? 'var(--info)'
                  : 'var(--accent)';

  document.getElementById('modal-title').textContent = `User — ${u.username}`;

  document.getElementById('modal-body').innerHTML = `
    <!-- Avatar + name -->
    <div style="display:flex;align-items:center;gap:14px;margin-bottom:20px;">
      <div class="user-avatar-lg ${u.is_flagged ? 'red' : ''}"
           style="width:48px;height:48px;font-size:20px;border-radius:12px;">
        ${u.username[0].toUpperCase()}
      </div>
      <div>
        <div style="font-size:17px;font-weight:500;">${u.username}</div>
        <div style="font-size:12px;color:var(--text3);font-family:var(--mono);">
          ${u.role} · joined ${u.created_at ? new Date(u.created_at).toLocaleDateString('en-IN') : '—'}
        </div>
      </div>
    </div>

    <!-- Stats grid -->
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:18px;">
      <div class="modal-field">
        <div class="modal-field-label">Status</div>
        <div class="modal-field-value">
          ${u.is_flagged
            ? '<span style="color:var(--danger);">🔴 Flagged</span>'
            : '<span style="color:var(--accent);">✓ Active</span>'}
        </div>
      </div>
      <div class="modal-field">
        <div class="modal-field-label">Risk Score</div>
        <div class="modal-field-value" style="color:${riskColor};font-size:16px;font-weight:500;">
          ${Math.round(u.risk_score)} <span style="font-size:11px;color:var(--text3);">/ 100</span>
        </div>
      </div>
      <div class="modal-field">
        <div class="modal-field-label">Total Syscalls</div>
        <div class="modal-field-value">${(u.total_calls || 0).toLocaleString()}</div>
      </div>
      <div class="modal-field">
        <div class="modal-field-label">Blocked Calls</div>
        <div class="modal-field-value"
             style="color:${u.blocked_calls > 0 ? 'var(--warning)' : 'var(--text)'}">
          ${(u.blocked_calls || 0)}
        </div>
      </div>
    </div>

    <!-- Risk bar -->
    <div style="margin-bottom:18px;">
      <div style="display:flex;justify-content:space-between;
                  font-size:10px;color:var(--text3);font-family:var(--mono);margin-bottom:5px;">
        <span>Risk Level: ${_riskLevel(u.risk_score).toUpperCase()}</span>
        <span>${Math.round(u.risk_score)}%</span>
      </div>
      <div style="background:var(--surface2);border-radius:100px;height:5px;overflow:hidden;">
        <div style="width:${u.risk_score}%;height:100%;border-radius:100px;
                    background:${riskColor};transition:width 0.4s ease;"></div>
      </div>
    </div>

    <!-- Change role -->
    <div class="modal-field">
      <div class="modal-field-label">Role Assignment</div>
      <select id="um-role-select"
        style="width:100%;padding:9px 12px;border:1.5px solid var(--border);
               border-radius:var(--radius);font-family:var(--mono);font-size:13px;
               background:var(--surface);color:var(--text);outline:none;cursor:pointer;"
        onfocus="this.style.borderColor='var(--accent)'"
        onblur="this.style.borderColor='var(--border)'">
        <option value="admin"     ${u.role === 'admin'     ? 'selected' : ''}>🛡️ admin</option>
        <option value="developer" ${u.role === 'developer' ? 'selected' : ''}>⚙️ developer</option>
        <option value="guest"     ${u.role === 'guest'     ? 'selected' : ''}>👤 guest</option>
      </select>
      <div style="font-size:10px;color:var(--text3);font-family:var(--mono);margin-top:4px;">
        Role change takes effect on next login
      </div>
    </div>`;

  document.getElementById('modal-footer').innerHTML = `
    <button class="btn sm" onclick="closeModal()">Close</button>
    <button class="btn sm"
      onclick="goPage('logs');
               document.getElementById('filter-user').value='${u.username}';
               renderLogs();
               closeModal()">
      View Logs →
    </button>
    ${u.is_flagged ? `
      <button class="btn sm" style="color:var(--accent);border-color:var(--accent);"
        onclick="unflagUser(${u.id})">
        ✓ Clear Flag
      </button>` : ''}
    <button class="btn sm" onclick="revokeUserSession(${u.id})">Revoke Session</button>
    <button class="btn sm primary" onclick="changeUserRole(${u.id})">Save Role →</button>`;

  document.getElementById('modal-overlay').classList.add('open');
}


// ── Actions ───────────────────────────────────────────────────────────────────

async function changeUserRole(id) {
  const role = document.getElementById('um-role-select')?.value;
  if (!role) return;

  // PUT /api/users/:id/role — REAL API CALL
  const result = await api('PUT', `/api/users/${id}/role`, { role });

  if (!result.ok) {
    showToast('danger', result.data?.error || 'Failed to change role.');
    return;
  }
  showToast('success', `Role changed to '${role}'.`);
  closeModal();
  await loadUsersPage();
}


async function revokeUserSession(id) {
  // POST /api/users/:id/revoke — REAL API CALL
  const result = await api('POST', `/api/users/${id}/revoke`);

  if (!result.ok) {
    showToast('danger', result.data?.error || 'Failed to revoke session.');
    return;
  }
  showToast('warn', result.data?.message || 'Session revoked.');
  closeModal();
}


async function unflagUser(id) {
  // POST /api/users/:id/unflag — REAL API CALL
  const result = await api('POST', `/api/users/${id}/unflag`);

  if (!result.ok) {
    showToast('danger', result.data?.error || 'Failed to clear flag.');
    return;
  }
  showToast('success', result.data?.message || 'User cleared.');
  closeModal();
  await loadUsersPage();
}


// ── Utility ───────────────────────────────────────────────────────────────────

function _riskLevel(score) {
  if (score >= 70) return 'critical';
  if (score >= 40) return 'high';
  if (score >= 20) return 'medium';
  return 'low';
}
