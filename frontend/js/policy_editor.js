/**
 * frontend/js/policy_editor.js
 * Phase 4 — Policy Editor
 *
 * Provides visual form-based policy creation and editing.
 * Builds rule_json from form inputs — admins never write raw JSON.
 *
 * Functions exposed to global scope (called from HTML onclick):
 *   openCreatePolicyModal()
 *   openEditPolicyModal(policy)
 *   submitCreatePolicy()
 *   submitEditPolicy(id)
 *   submitDisablePolicy(id)
 */

const PE_VALID_ACTIONS = [
  { value: 'file_read',          label: 'file_read — read a file'              },
  { value: 'file_write',         label: 'file_write — write to a file'         },
  { value: 'file_delete',        label: 'file_delete — delete a file'          },
  { value: 'dir_list',           label: 'dir_list — list directory contents'   },
  { value: 'exec_process',       label: 'exec_process — execute a process'     },
  { value: 'system_dir_access',  label: 'system_dir_access — access /sys /proc'},
];

const PE_ALL_ROLES = ['admin', 'developer', 'guest'];


// ── Open: Create New Policy ───────────────────────────────────────────────────

function openCreatePolicyModal() {
  document.getElementById('modal-title').textContent = '+ New Policy';
  document.getElementById('modal').classList.add('wide');
  document.getElementById('modal-body').innerHTML    = _buildPolicyForm(null);
  document.getElementById('modal-footer').innerHTML  = `
    <button class="btn sm" onclick="closeModal()">Cancel</button>
    <button class="btn sm primary" onclick="submitCreatePolicy()">Create Policy</button>`;
  document.getElementById('modal-overlay').classList.add('open');
}


// ── Open: Edit Existing Policy ────────────────────────────────────────────────

function openEditPolicyModal(policyJson) {
  // If we get an escaped JSON string, parse it. If it's already an object, use it.
  let policy;
  try {
    policy = typeof policyJson === 'string' ? JSON.parse(decodeURIComponent(policyJson)) : policyJson;
  } catch (err) {
    console.error("Failed to parse policy JSON in modal:", err, policyJson);
    return;
  }
  
  document.getElementById('modal-title').textContent = `Edit — ${policy.name}`;
  document.getElementById('modal').classList.add('wide');
  document.getElementById('modal-body').innerHTML    = _buildPolicyForm(policy);
  document.getElementById('modal-footer').innerHTML  = `
    <button class="btn sm" onclick="closeModal()">Cancel</button>
    <button class="btn sm danger" onclick="submitDisablePolicy(${policy.id})">
      ${policy.is_active ? 'Disable' : 'Enable'}
    </button>
    <button class="btn sm primary" onclick="submitEditPolicy(${policy.id})">Save Changes</button>`;
  document.getElementById('modal-overlay').classList.add('open');
}


// ── Form Builder ──────────────────────────────────────────────────────────────

function _buildPolicyForm(existing) {
  const rule     = existing?.rule_json || {};
  const selAct   = rule.action        || '';
  const selAllow = rule.allow_roles   || [];
  const selDeny  = rule.deny_roles    || [];
  const maxRisk  = rule.conditions?.max_risk_score ?? '';
  const timeFrom = rule.conditions?.time_range?.[0] ?? '';
  const timeTo   = rule.conditions?.time_range?.[1] ?? '';

  const inputStyle = `
    width:100%;padding:9px 12px;
    border:1.5px solid var(--border);border-radius:var(--radius);
    font-family:var(--mono);font-size:13px;
    background:var(--surface);color:var(--text);outline:none;`;

  const condInputStyle = `
    width:100%;padding:8px 10px;
    border:1px solid var(--border);border-radius:var(--radius);
    font-family:var(--mono);font-size:12px;
    background:var(--surface);color:var(--text);outline:none;`;

  return `
    <div style="display:grid; grid-template-columns: 1fr 1.2fr; gap: 24px; margin-bottom: 16px;">
      <!-- Column Left: Name & Action -->
      <div style="display:flex; flex-direction:column; gap:16px;">
        <!-- Policy Name -->
        <div class="modal-field" style="margin-bottom:0;">
          <div class="modal-field-label">Policy Name</div>
          <input id="pe-name" type="text"
            value="${existing?.name || ''}"
            placeholder="e.g. block_guest_exec"
            style="${inputStyle}"
            onfocus="this.style.borderColor='var(--accent)'"
            onblur="this.style.borderColor='var(--border)'"
            ${existing ? 'disabled style="' + inputStyle + 'opacity:0.6;cursor:not-allowed;"' : ''}/>
          <div style="font-size:10px;color:var(--text3);font-family:var(--mono);margin-top:4px;">
            Use snake_case · must be unique
          </div>
        </div>

        <!-- Action -->
        <div class="modal-field" style="margin-bottom:0;">
          <div class="modal-field-label">Syscall Action</div>
          <select id="pe-action" style="${inputStyle}cursor:pointer;"
            onfocus="this.style.borderColor='var(--accent)'"
            onblur="this.style.borderColor='var(--border)'">
            <option value="">— select syscall —</option>
            ${PE_VALID_ACTIONS.map(a =>
              `<option value="${a.value}" ${selAct === a.value ? 'selected' : ''}>${a.label}</option>`
            ).join('')}
          </select>
        </div>
      </div>

      <!-- Column Right: Roles -->
      <div style="display:flex; flex-direction:column; gap:16px; padding-left: 24px; border-left: 1px solid var(--border);">
        <!-- Allow Roles -->
        <div class="modal-field" style="margin-bottom:0;">
          <div class="modal-field-label">Allow Roles</div>
          <div style="font-size:10px;color:var(--text3);font-family:var(--mono);margin-bottom:8px;">
            Roles explicitly permitted
          </div>
          <div style="display:flex;gap:14px;">
            ${PE_ALL_ROLES.map(r => `
              <label style="display:flex;align-items:center;gap:6px;cursor:pointer;
                             font-size:13px;font-family:var(--mono);user-select:none;">
                <input type="checkbox" id="pe-allow-${r}" value="${r}"
                  style="accent-color:var(--accent);width:14px;height:14px;"
                  ${selAllow.includes(r) ? 'checked' : ''}
                  onchange="validatePolicyForm()"/>
                ${r}
              </label>`).join('')}
          </div>
        </div>

        <!-- Deny Roles -->
        <div class="modal-field" style="margin-bottom:0;">
          <div class="modal-field-label">Deny Roles</div>
          <div style="font-size:10px;color:var(--text3);font-family:var(--mono);margin-bottom:8px;">
            Roles explicitly blocked (eval first)
          </div>
          <div style="display:flex;gap:14px;">
            ${PE_ALL_ROLES.map(r => `
              <label style="display:flex;align-items:center;gap:6px;cursor:pointer;
                             font-size:13px;font-family:var(--mono);user-select:none;">
                <input type="checkbox" id="pe-deny-${r}" value="${r}"
                  style="accent-color:var(--danger);width:14px;height:14px;"
                  ${selDeny.includes(r) ? 'checked' : ''}
                  onchange="validatePolicyForm()"/>
                ${r}
              </label>`).join('')}
          </div>
        </div>
      </div>
    </div>

    <!-- Conditions -->
    <div style="background:var(--surface2);border:1px solid var(--border);
                border-radius:var(--radius);padding:14px;margin-top:4px;">
      <div class="modal-field-label" style="margin-bottom:10px;">
        Conditions <span style="font-weight:400;color:var(--text3)">(optional)</span>
      </div>
      <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;">
        <div>
          <div style="font-size:10px;color:var(--text3);font-family:var(--mono);
                      text-transform:uppercase;letter-spacing:0.5px;margin-bottom:5px;">
            Max Risk Score
          </div>
          <input id="pe-maxrisk" type="number" min="0" max="100"
            value="${maxRisk}" placeholder="0 – 100"
            style="${condInputStyle}"/>
          <div style="font-size:10px;color:var(--text3);font-family:var(--mono);margin-top:3px;">
            Block if user risk &gt; this value
          </div>
        </div>
        <div>
          <div style="font-size:10px;color:var(--text3);font-family:var(--mono);
                      text-transform:uppercase;letter-spacing:0.5px;margin-bottom:5px;">
            Time From (UTC)
          </div>
          <input id="pe-timefrom" type="time" value="${timeFrom}" style="${condInputStyle}"/>
        </div>
        <div>
          <div style="font-size:10px;color:var(--text3);font-family:var(--mono);
                      text-transform:uppercase;letter-spacing:0.5px;margin-bottom:5px;">
            Time To (UTC)
          </div>
          <input id="pe-timeto" type="time" value="${timeTo}" style="${condInputStyle}"/>
          <div style="font-size:10px;color:var(--text3);font-family:var(--mono);margin-top:3px;">
            Only allow within this window
          </div>
        </div>
      </div>
    </div>

    <!-- Live Preview -->
    <div style="margin-top:12px;">
      <div class="modal-field-label" style="margin-bottom:6px;">Rule Preview (JSON)</div>
      <div id="pe-preview"
        style="background:#0A1A11;border-radius:var(--radius);padding:12px 14px;
               font-family:var(--mono);font-size:11px;color:#A8D8B8;
               white-space:pre-wrap;word-break:break-all;min-height:48px;">
        { }
      </div>
    </div>

    <!-- Error display -->
    <div id="pe-error"
      style="display:none;background:var(--danger-light);border:1px solid rgba(192,57,43,0.2);
             color:var(--danger);padding:8px 12px;border-radius:var(--radius);
             font-size:12px;font-family:var(--mono);margin-top:10px;">
    </div>`;
}


// ── Live Form Validation + Preview ───────────────────────────────────────────

function validatePolicyForm() {
  // Check for role conflict (same role in both allow and deny)
  const conflict = PE_ALL_ROLES.filter(r => {
    const allow = document.getElementById(`pe-allow-${r}`)?.checked;
    const deny  = document.getElementById(`pe-deny-${r}`)?.checked;
    return allow && deny;
  });

  const errEl = document.getElementById('pe-error');
  if (conflict.length) {
    if (errEl) {
      errEl.style.display = 'block';
      errEl.textContent   = `⚠ Role conflict: [${conflict.join(', ')}] cannot be in both Allow and Deny.`;
    }
  } else {
    if (errEl) errEl.style.display = 'none';
  }

  // Update live preview
  const preview = document.getElementById('pe-preview');
  if (preview) {
    const rule = _collectRule();
    preview.textContent = JSON.stringify(rule, null, 2);
  }
}

// Attach listeners after form renders
// Note: We use global listeners or attach them when modal opens
document.addEventListener('change', e => {
  if (e.target.id?.startsWith('pe-')) validatePolicyForm();
});
document.addEventListener('input', e => {
  if (e.target.id?.startsWith('pe-')) validatePolicyForm();
});


// ── Collect rule_json from form ───────────────────────────────────────────────

function _collectRule() {
  const action     = document.getElementById('pe-action')?.value || '';
  const allowRoles = PE_ALL_ROLES.filter(r => document.getElementById(`pe-allow-${r}`)?.checked);
  const denyRoles  = PE_ALL_ROLES.filter(r => document.getElementById(`pe-deny-${r}`)?.checked);
  const maxRisk    = document.getElementById('pe-maxrisk')?.value;
  const timeFrom   = document.getElementById('pe-timefrom')?.value;
  const timeTo     = document.getElementById('pe-timeto')?.value;

  const rule = { action };
  if (allowRoles.length) rule.allow_roles = allowRoles;
  if (denyRoles.length)  rule.deny_roles  = denyRoles;

  const conditions = {};
  if (maxRisk)            conditions.max_risk_score = parseFloat(maxRisk);
  if (timeFrom && timeTo) conditions.time_range     = [timeFrom, timeTo];
  if (Object.keys(conditions).length) rule.conditions = conditions;

  return rule;
}

function _showError(msg) {
  const el = document.getElementById('pe-error');
  if (el) { el.style.display = 'block'; el.textContent = '⚠ ' + msg; }
}


// ── Submit: Create ────────────────────────────────────────────────────────────

async function submitCreatePolicy() {
  const name = document.getElementById('pe-name')?.value?.trim();
  if (!name) { _showError('Policy name is required.'); return; }

  const rule = _collectRule();
  if (!rule.action) { _showError('Please select a syscall action.'); return; }

  const conflict = PE_ALL_ROLES.filter(r =>
    (rule.allow_roles||[]).includes(r) && (rule.deny_roles||[]).includes(r)
  );
  if (conflict.length) {
    _showError(`Role conflict: [${conflict.join(', ')}] in both Allow and Deny.`);
    return;
  }

  const result = await api('POST', '/api/policies', { name, rule_json: rule });

  if (!result.ok) {
    _showError(result.data?.error || 'Failed to create policy.');
    return;
  }

  showToast('success', `Policy '${name}' created.`);
  closeModal();
  await renderPolicies();
}


// ── Submit: Edit ──────────────────────────────────────────────────────────────

async function submitEditPolicy(id) {
  const rule = _collectRule();
  if (!rule.action) { _showError('Please select a syscall action.'); return; }

  const conflict = PE_ALL_ROLES.filter(r =>
    (rule.allow_roles||[]).includes(r) && (rule.deny_roles||[]).includes(r)
  );
  if (conflict.length) {
    _showError(`Role conflict: [${conflict.join(', ')}] in both Allow and Deny.`);
    return;
  }

  const result = await api('PUT', `/api/policies/${id}`, { rule_json: rule });

  if (!result.ok) {
    _showError(result.data?.error || 'Failed to update policy.');
    return;
  }

  showToast('success', 'Policy updated.');
  closeModal();
  await renderPolicies();
}


// ── Submit: Disable / Enable ──────────────────────────────────────────────────

async function submitDisablePolicy(id) {
  const btn      = document.querySelector(`#modal-footer .btn.danger`);
  const enabling = btn?.textContent?.trim() === 'Enable';
  const result   = await api('PUT', `/api/policies/${id}`, { is_active: enabling });

  if (!result.ok) {
    showToast('danger', result.data?.error || 'Failed to update policy.');
    return;
  }

  showToast(enabling ? 'success' : 'warn', `Policy ${enabling ? 'enabled' : 'disabled'}.`);
  closeModal();
  await renderPolicies();
}
