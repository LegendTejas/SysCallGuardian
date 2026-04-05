/**
 * SysCallGuardian System Call Terminal - Real-time syscall execution & monitoring
 */

// State
let currentOp = 'file_read';
let syscallHistory = [];
let historyCount = 0;
let isExecuting = false;
const syscallSpeedMs = 100; // Typing speed for terminal simulation

// Permission map by role
const rolePermissions = {
  admin: ['file_read', 'file_write', 'file_delete', 'dir_list', 'exec_process', 'net_socket', 'system_info'],
  developer: ['file_read', 'file_write', 'dir_list', 'exec_process', 'system_info'],
  guest: ['file_read', 'dir_list', 'system_info'],
};

/**
 * Initialize the syscall page
 */
function initSyscallPage() {
  // Set terminal username
  const username = localStorage.getItem('sg_username') || 'User';
  const terminalUser = document.getElementById('terminal-user');
  if (terminalUser) terminalUser.textContent = username;
  
  // Set role badge
  const role = localStorage.getItem('sg_role') || 'guest';
  const roleBadge = document.getElementById('syscall-role-badge');
  if (roleBadge) {
    roleBadge.textContent = role.toUpperCase();
    roleBadge.className = 'timestamp';
  }
  
  // Clear history on fresh load
  syscallHistory = [];
  updateHistoryCount();
  renderSyscallHistory();
  
  // Set initial terminal output
  const terminalOutput = document.getElementById('terminal-output');
  if (terminalOutput && terminalOutput.childElementCount <= 3) {
    addTerminalLine('Ready for syscall execution. Select operation and parameters above.', 'info');
    addTerminalLine(`Current user: ${username} (${role})`, 'info');
    addTerminalLine('─'.repeat(50), 'dim');
  }
  
  // Render permission chips based on role
  renderRolePermissions();
}

/**
 * Display role-specific permissions
 */
function renderRolePermissions() {
  const permBar = document.getElementById('role-permissions-bar');
  if (!permBar) return;
  
  const role = localStorage.getItem('sg_role') || 'guest';
  const permissions = rolePermissions[role] || [];
  
  // Show possible permissions
  const allPermissions = ['file_read', 'file_write', 'file_delete', 'dir_list', 'exec_process', 'net_socket', 'system_info'];
  
  permBar.innerHTML = allPermissions.map(perm => {
    const hasPermission = permissions.includes(perm);
    return `<div class="perm-chip ${hasPermission ? 'has' : 'no'}">${perm}</div>`;
  }).join('');
  
  // Hide or dim buttons based on role. Guest gets only allowed buttons for a cleaner view.
  allPermissions.forEach(perm => {
    const opBtn = document.querySelector(`.op-btn[data-op="${perm}"]`);
    if (opBtn) {
      if (permissions.includes(perm)) {
        opBtn.classList.remove('blocked-op');
        opBtn.style.display = 'flex';
      } else {
        if (role === 'guest') {
            opBtn.style.display = 'none'; // Keep guest UI limited as requested
        } else {
            opBtn.classList.add('blocked-op');
            opBtn.style.display = 'flex';
        }
      }
    }
  });
}

/**
 * Select operation type
 */
function selectOp(el) {
  const op = el.dataset.op;
  if (!op) return;
  
  // Check if user has permission for this operation
  const role = localStorage.getItem('sg_role') || 'guest';
  const permissions = rolePermissions[role] || [];
  
  if (!permissions.includes(op)) {
    addTerminalLine(`Permission denied: ${role} role cannot perform ${op} operations`, 'blocked');
    showToast('danger', `Permission denied: ${op} not allowed for ${role} role`);
    return;
  }
  
  // Update selected operation
  document.querySelectorAll('.op-btn').forEach(btn => btn.classList.remove('active'));
  el.classList.add('active');
  currentOp = op;
  
  // Update form fields visibility
  document.getElementById('field-filepath').style.display = ['file_read', 'file_write', 'file_delete', 'dir_list'].includes(op) ? 'block' : 'none';
  document.getElementById('field-writedata').style.display = op === 'file_write' ? 'block' : 'none';
  document.getElementById('field-command').style.display = op === 'exec_process' ? 'block' : 'none';
  
  // No fields needed for system_info
  
  // Update form title
  document.getElementById('input-form-title').textContent = getOperationTitle(op);
  
  // Update API preview
  updatePreview();
  
  // Update Execute button text
  document.getElementById('exec-btn').textContent = getExecuteButtonText(op);
}

/**
 * Get operation title for form
 */
function getOperationTitle(op) {
  switch (op) {
    case 'file_read': return 'Read File';
    case 'file_write': return 'Write to File';
    case 'file_delete': return 'Delete File';
    case 'dir_list': return 'List Directory';
    case 'exec_process': return 'Execute Process';
    case 'net_socket': return 'Create Network Socket';
    case 'system_info': return 'System Information';
    default: return 'System Call';
  }
}

/**
 * Get execute button text
 */
function getExecuteButtonText(op) {
  switch (op) {
    case 'file_read': return 'Read File →';
    case 'file_write': return 'Write File →';
    case 'file_delete': return 'Delete File →';
    case 'dir_list': return 'List Directory →';
    case 'exec_process': return 'Execute Process →';
    case 'net_socket': return 'Create Socket →';
    case 'system_info': return 'Fetch Info →';
    default: return 'Execute →';
  }
}

/**
 * Update preview of API call
 */
function updatePreview() {
  const previewEl = document.getElementById('preview-text');
  if (!previewEl) return;
  
  let payload = {};
  
  switch (currentOp) {
    case 'file_read':
    case 'file_delete':
    case 'dir_list':
      payload.file_path = document.getElementById('input-filepath').value || '';
      break;
    case 'file_write':
      payload.file_path = document.getElementById('input-filepath').value || '';
      payload.content = document.getElementById('input-writedata').value || '';
      break;
    case 'exec_process':
      payload.command = document.getElementById('input-command').value || '';
      break;
    case 'net_socket':
      payload.host = document.getElementById('input-filepath').value || '';
      break;
    case 'system_info':
      // no payload
      break;
  }
  
  const endpoint = `/api/syscall/${currentOp}`;
  previewEl.textContent = `{ ${JSON.stringify(payload).slice(1, -1)} }`;
}

/**
 * Execute syscall
 */
async function executeSyscall() {
  if (isExecuting) return; // Prevent multiple executions
  
  // Get parameters
  let params = {};
  let displayPath = '';
  
  switch (currentOp) {
    case 'file_read':
    case 'file_delete':
    case 'dir_list':
      const filepath = document.getElementById('input-filepath').value.trim();
      if (!filepath) {
        showToast('danger', 'Please enter a file path');
        return;
      }
      params.file_path = filepath;
      displayPath = filepath;
      break;
    case 'file_write':
      const writeFilepath = document.getElementById('input-filepath').value.trim();
      const writeContent = document.getElementById('input-writedata').value;
      if (!writeFilepath) {
        showToast('danger', 'Please enter a file path');
        return;
      }
      params.file_path = writeFilepath;
      params.content = writeContent;
      displayPath = writeFilepath;
      break;
    case 'exec_process':
      const command = document.getElementById('input-command').value.trim();
      if (!command) {
        showToast('danger', 'Please enter a command');
        return;
      }
      params.command = command;
      displayPath = command; // Display command as path for history
      break;
    case 'net_socket':
      const host = document.getElementById('input-filepath').value.trim();
      if (!host) {
        showToast('danger', 'Please enter a host:port');
        return;
      }
      params.host = host;
      displayPath = host;
      break;
    case 'system_info':
      displayPath = 'system_info';
      break;
  }
  
  // Start execution animation
  isExecuting = true;
  const terminalThinking = document.getElementById('terminal-thinking');
  if (terminalThinking) terminalThinking.style.display = 'block';
  
  // Update terminal status
  const terminalStatus = document.getElementById('terminal-status');
  if (terminalStatus) terminalStatus.textContent = 'executing syscall...';
  
  // Add executing line to terminal
  addTerminalLine(`Executing: ${getOperationTitle(currentOp)} ${displayPath}`, 'info');
  simulateTerminalTyping('$ ' + getOperationTitle(currentOp) + ' ' + displayPath);
  
  // Simulate network delay
  await new Promise(resolve => setTimeout(resolve, 800 + Math.random() * 600));
  
  // Make API call
  const endpoint = currentOp === 'system_info' ? '/api/syscall/system_info' : `/api/syscall/${currentOp}`;
  const result = await api('POST', endpoint, params);
  
  // Stop execution animation
  isExecuting = false;
  if (terminalThinking) terminalThinking.style.display = 'none';
  if (terminalStatus) terminalStatus.textContent = 'ready';
  
  // Add result to history
  const historyEntry = {
    id: ++historyCount,
    operation: currentOp,
    path: displayPath,
    status: result.ok ? 'allowed' : 'blocked',
    reason: result.data?.reason || (result.ok ? null : 'Access denied'),
    time: new Date().toISOString(),
    result: result.data,
  };
  syscallHistory.unshift(historyEntry);
  
  // Cap history at 20 entries
  if (syscallHistory.length > 20) {
    syscallHistory.pop();
  }
  
  // Update history display
  updateHistoryCount();
  renderSyscallHistory();
  
  // Display result in terminal
  if (result.ok) {
    addTerminalLine(`✓ Operation completed successfully`, 'allowed');
    
    // Display content for read operations
    if (currentOp === 'file_read' && result.data?.content) {
      addTerminalLine(result.data.content, 'output');
    }
    
    // Display output for execute operations
    if (currentOp === 'exec_process' && result.data?.output) {
      addTerminalLine(result.data.output, 'output');
    }
    
    // Display last result card with success
    showLastResult(true, result.data);
    
  } else {
    // Display error
    addTerminalLine(`✗ Operation failed: ${result.data?.reason || 'Access denied'}`, 'blocked');
    
    // Display last result card with error
    showLastResult(false, result.data);
  }
  
  // Add separator
  addTerminalLine('─'.repeat(50), 'dim');
}

/**
 * Show last result card with details
 */
function showLastResult(success, data) {
  const card = document.getElementById('last-result-card');
  const badge = document.getElementById('last-result-badge');
  const body = document.getElementById('last-result-body');
  
  if (!card || !badge || !body) return;
  
  // Display the card
  card.style.display = 'block';
  
  // Set status badge
  badge.className = 'tag ' + (success ? 'live' : 'danger-tag');
  badge.textContent = success ? '✓ SUCCESS' : '✗ FAILED';
  
  // Format content based on operation and result
  let content = '';
  if (success) {
    if (currentOp === 'file_read' && data?.content) {
      content = `<div class="result-section"><div class="result-header">File Content:</div><pre class="result-content">${data.content}</pre></div>`;
    } else if (currentOp === 'exec_process' && data?.output) {
      content = `<div class="result-section"><div class="result-header">Process Output:</div><pre class="result-content">${data.output}</pre></div>`;
    } else if (currentOp === 'dir_list' && data?.files) {
      const fileList = Array.isArray(data.files) ? data.files.join('\n') : data.files;
      content = `<div class="result-section"><div class="result-header">Directory Contents:</div><pre class="result-content">${fileList}</pre></div>`;
    } else {
      content = `<div class="result-message">${data?.message || 'Operation completed successfully'}</div>`;
    }
  } else {
    content = `<div class="result-error">${data?.reason || 'Access denied by security policy'}</div>`;
    if (data?.error_code) {
      content += `<div class="result-error-code">Error code: ${data.error_code}</div>`;
    }
  }
  
  body.innerHTML = content;
}

/**
 * Add a line to the terminal output
 */
function addTerminalLine(text, type = '') {
  const terminal = document.getElementById('terminal-output');
  if (!terminal) return;
  
  const line = document.createElement('div');
  line.className = 'terminal-line' + (type ? ` ${type}` : '');
  line.textContent = text;
  
  terminal.appendChild(line);
  
  // Auto-scroll to bottom
  terminal.scrollTop = terminal.scrollHeight;
  
  return line;
}

/**
 * Simulate typing in the terminal
 */
async function simulateTerminalTyping(text) {
  const terminal = document.getElementById('terminal-output');
  if (!terminal) return;
  
  const line = document.createElement('div');
  line.className = 'terminal-line';
  terminal.appendChild(line);
  
  // Auto-scroll to bottom as typing progresses
  for (let i = 0; i <= text.length; i++) {
    line.textContent = text.substring(0, i) + (i < text.length ? '█' : '');
    terminal.scrollTop = terminal.scrollHeight;
    await new Promise(resolve => setTimeout(resolve, syscallSpeedMs));
  }
}

/**
 * Update history count
 */
function updateHistoryCount() {
  const countEl = document.getElementById('history-count');
  if (countEl) {
    countEl.textContent = `${syscallHistory.length} call${syscallHistory.length !== 1 ? 's' : ''}`;
  }
}

/**
 * Render syscall history table
 */
function renderSyscallHistory() {
  const tableBody = document.getElementById('syscall-history-tbody');
  if (!tableBody) return;
  
  if (syscallHistory.length === 0) {
    tableBody.innerHTML = `<tr><td colspan="6" style="text-align:center;padding:20px;color:var(--text3);font-family:var(--mono);font-size:12px;">No calls made yet this session</td></tr>`;
    return;
  }
  
  tableBody.innerHTML = syscallHistory.map((item, index) => {
    const statusBadge = item.status === 'allowed' 
      ? '<span class="status-badge allowed">✓ Allowed</span>' 
      : '<span class="status-badge blocked">✗ Blocked</span>';
    
    return `
      <tr>
        <td class="mono-text">${item.id}</td>
        <td class="mono-text">${formatOperationName(item.operation)}</td>
        <td class="mono-text" style="max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${item.path}</td>
        <td>${statusBadge}</td>
        <td class="mono-text">${item.reason || '—'}</td>
        <td class="mono-text">${formatTime(item.time)}</td>
      </tr>
    `;
  }).join('');
}

/**
 * Format operation name for display
 */
function formatOperationName(op) {
  switch (op) {
    case 'file_read': return 'READ';
    case 'file_write': return 'WRITE';
    case 'file_delete': return 'DELETE';
    case 'dir_list': return 'LIST';
    case 'exec_process': return 'EXEC';
    case 'net_socket': return 'SOCKET';
    default: return op.toUpperCase();
  }
}

/**
 * Clear syscall history
 */
function clearSyscallHistory() {
  syscallHistory = [];
  updateHistoryCount();
  renderSyscallHistory();
  
  // Hide last result card
  const card = document.getElementById('last-result-card');
  if (card) card.style.display = 'none';
  
  showToast('info', 'Call history cleared');
}

/**
 * Load a test scenario
 */
function loadScenario(type) {
  switch (type) {
    case 'allowed_read':
      selectOpByType('file_read');
      document.getElementById('input-filepath').value = 'test.txt';
      updatePreview();
      break;
    case 'blocked_exec':
      selectOpByType('exec_process');
      document.getElementById('input-command').value = '/bin/sh';
      updatePreview();
      break;
    case 'path_traversal':
      selectOpByType('file_read');
      document.getElementById('input-filepath').value = '../../etc/passwd';
      updatePreview();
      break;
    case 'allowed_exec':
      selectOpByType('exec_process');
      document.getElementById('input-command').value = 'ls -la';
      updatePreview();
      break;
    case 'system_dir':
      selectOpByType('dir_list');
      document.getElementById('input-filepath').value = '/sys/kernel';
      updatePreview();
      break;
  }
}

/**
 * Helper to select operation by type
 */
function selectOpByType(type) {
  const button = document.querySelector(`.op-btn[data-op="${type}"]`);
  if (button) selectOp(button);
}

// Add CSS for the result sections
const resultStyles = document.createElement('style');
resultStyles.textContent = `
  .result-section {
    margin-bottom: 12px;
  }
  .result-header {
    font-size: 11px;
    color: var(--text3);
    font-family: var(--mono);
    margin-bottom: 6px;
  }
  .result-content {
    background: rgba(255,255,255,0.03);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 12px;
    font-family: var(--mono);
    font-size: 12px;
    color: var(--text);
    white-space: pre-wrap;
    overflow-x: auto;
    max-height: 180px;
    line-height: 1.5;
  }
  .result-message {
    color: var(--accent);
    font-size: 13px;
    margin: 8px 0;
  }
  .result-error {
    color: var(--danger);
    font-size: 13px;
    margin: 8px 0;
  }
  .result-error-code {
    color: var(--text3);
    font-family: var(--mono);
    font-size: 11px;
    margin-top: 6px;
  }
`;
document.head.appendChild(resultStyles);
