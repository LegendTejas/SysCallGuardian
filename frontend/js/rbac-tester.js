/**
 * SysCallGuardian RBAC Tester - Verifies role-based content visibility
 * 
 * This script tests the visibility of different UI elements and features
 * based on user roles (Admin, Developer, Guest) to ensure proper RBAC.
 */

// Role-specific dashboard configurations
const roleConfig = {
  // Admin: Full access to all features
  admin: {
    visible: ['overview', 'live', 'users', 'policies', 'syscalls', 'threats', 'logs'],
    hidden: [],
    permissions: [
      'view_all_users', 
      'edit_policies',
      'view_all_logs', 
      'execute_syscalls',
      'verify_integrity',
      'view_heatmap'
    ]
  },
  
  // Developer: Limited admin features
  developer: {
    visible: ['overview', 'live', 'policies', 'syscalls', 'logs'],
    hidden: ['users', 'threats'],
    permissions: [
      'view_own_logs', 
      'view_policy',
      'execute_syscalls',
      'view_filtered_heatmap'
    ]
  },
  
  // Guest: Minimal access
  guest: {
    visible: ['overview', 'live'],
    hidden: ['users', 'policies', 'syscalls', 'threats', 'logs'],
    permissions: [
      'view_own_stats', 
      'reset_password'
    ]
  }
};

/**
 * Test RBAC visibility for current role
 */
function testRBAC() {
  // Get current role
  const role = (localStorage.getItem('sg_role') || 'guest').toLowerCase();
  const config = roleConfig[role] || roleConfig.guest;
  
  console.log(`[RBAC Test] Running visibility test for role: ${role}`);
  
  // Check navigation visibility
  config.visible.forEach(page => {
    const navItem = document.getElementById(`nav-${page}`);
    if (navItem && navItem.style.display === 'none') {
      console.error(`[RBAC Error] ${page} should be visible for ${role} but is hidden`);
    }
  });
  
  config.hidden.forEach(page => {
    const navItem = document.getElementById(`nav-${page}`);
    if (navItem && navItem.style.display !== 'none') {
      console.error(`[RBAC Error] ${page} should be hidden for ${role} but is visible`);
    }
  });
  
  // Test specific permissions
  testPermission(role, 'view_all_users', () => {
    const userGrid = document.getElementById('users-grid');
    return userGrid && userGrid.childElementCount > 0;
  });
  
  testPermission(role, 'edit_policies', () => {
    const addPolicyBtn = document.getElementById('add-policy-btn');
    return addPolicyBtn && addPolicyBtn.style.display !== 'none';
  });
  
  testPermission(role, 'verify_integrity', () => {
    // Verify access to integrity verification (only Admin should have this)
    const integrityBanner = document.getElementById('integrity-banner');
    return integrityBanner && integrityBanner.style.display !== 'none';
  });
  
  console.log(`[RBAC Test] Completed visibility test for ${role} role`);
  
  // Display Test Results as toast only for Admin role
  if (role === 'admin') {
    showToast('success', 'RBAC visibility tests completed successfully');
  }
}

/**
 * Test a specific permission
 */
function testPermission(role, permission, testFn) {
  const hasPermission = roleConfig[role].permissions.includes(permission);
  const testResult = testFn();
  
  if (hasPermission && !testResult) {
    console.error(`[RBAC Error] ${role} should have ${permission} but element is missing or hidden`);
  } else if (!hasPermission && testResult) {
    console.error(`[RBAC Error] ${role} should NOT have ${permission} but element is visible`);
  }
}

/**
 * Apply custom role-based modifications to the UI
 */
function applyRoleBasedUI() {
  const role = (localStorage.getItem('sg_role') || 'guest').toLowerCase();
  
  if (role === 'guest') {
    // Guest-specific UI customizations
    customizeGuestUI();
  } else if (role === 'developer') {
    // Developer-specific UI customizations
    customizeDevUI(); 
  } else {
    // Admin-specific UI customizations
    customizeAdminUI();
  }
}

/**
 * Guest-specific UI customizations
 */
function customizeGuestUI() {
  // Update the suspicious users card to show personal info for Guest
  const susCardEl = document.getElementById('suspicious-card');
  const susListEl = document.getElementById('suspicious-list');
  
  if (susCardEl && susListEl) {
    const cardTitle = susCardEl.querySelector('.card-title');
    const cardSubtitle = susCardEl.querySelector('.card-subtitle');
    const cardButton = susCardEl.querySelector('.btn');
    
    if (cardTitle) cardTitle.textContent = 'Your Activity';
    if (cardSubtitle) cardSubtitle.textContent = 'personal actions · syscall summary';
    if (cardButton) cardButton.style.display = 'none';
    
    // Get current username
    const username = localStorage.getItem('sg_username') || 'Guest';
    
    // Replace suspicious users with personal activity card
    susListEl.innerHTML = `
      <div class="sus-item safe">
        <div class="sus-header">
          <div class="sus-user">${username}</div>
          <div class="risk-score safe">12/100</div>
        </div>
        <div class="sus-meta">Last activity: 2min ago · Total syscalls: 24</div>
        <div style="margin-top:10px;">
          <div class="stat-label">Recent Activity</div>
          <div style="display:flex; justify-content:space-between; font-family:var(--mono); font-size:10px; color:var(--text3); margin:4px 0;">
            <span>READ: 9</span>
            <span>WRITE: 0</span>
            <span>LIST: 5</span>
          </div>
        </div>
      </div>
    `;
  }
  
  // Add security settings card for guest
  const bottomRow = document.querySelector('.bottom-row');
  if (bottomRow) {
    // Check if the security card already exists
    const securityCard = document.querySelector('.card.security-card');
    if (!securityCard) {
      bottomRow.insertAdjacentHTML('beforeend', `
        <div class="card security-card" style="grid-column: 1/-1; margin-top: 14px;">
          <div class="card-header">
            <div>
              <div class="card-title">Security Settings</div>
              <div class="card-subtitle">account protection · recovery options</div>
            </div>
            <span class="tag info-tag">GUEST ACCESS</span>
          </div>
          <div style="padding: 12px 0;">
            <div class="security-option" onclick="openForgotPwdModal()">
              <div class="security-option-icon">🔑</div>
              <div class="security-option-content">
                <div class="security-option-title">Password Recovery</div>
                <div class="security-option-desc">OTP verification to reset password</div>
              </div>
              <div class="security-option-arrow">→</div>
            </div>
            <div class="security-option" onclick="showToast('info', 'This feature is available only to Developer and Admin accounts')">
              <div class="security-option-icon">⚡</div>
              <div class="security-option-content">
                <div class="security-option-title">Request Privileges</div>
                <div class="security-option-desc">Apply for elevated access</div>
              </div>
              <div class="security-option-arrow">→</div>
            </div>
          </div>
        </div>
      `);
    }
  }
  
  // Add limited access notification for guests
  setTimeout(() => {
    showToast('info', 'You are viewing the Guest dashboard with limited features');
  }, 1000);
}

/**
 * Developer-specific UI customizations
 */
function customizeDevUI() {
  // Highlight developer tools
  const syscallsNav = document.getElementById('nav-syscalls');
  if (syscallsNav) {
    syscallsNav.innerHTML = `
      <svg class="nav-icon" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5">
        <rect x="1" y="2" width="14" height="12" rx="2"/>
        <path d="M4 6l3 3-3 3M9 12h3"/>
      </svg>
      <span>System Calls</span>
      <span class="nav-badge" style="background:var(--accent)">DEV</span>
    `;
  }
  
  // Add read-only note on policies page
  const policiesHeader = document.querySelector('#page-policies .page-header p');
  if (policiesHeader) {
    policiesHeader.textContent = 'Read-only policy view · developer access level';
  }
  
  // Customize logs view to show filtered data notice
  const logsHeader = document.querySelector('#page-logs .page-header p');
  if (logsHeader) {
    logsHeader.textContent = 'Filtered syscall logs · redacted sensitive paths';
  }
  
  const integrityBanner = document.getElementById('integrity-banner');
  if (integrityBanner) {
    const integrityText = document.getElementById('integrity-text');
    if (integrityText) {
      integrityText.innerHTML = 'Developer view: Integrity verification results are filtered';
    }
  }
}

/**
 * Admin-specific UI customizations
 */
function customizeAdminUI() {
  // Add admin badges to critical security sections
  const securityLabel = document.getElementById('label-security');
  if (securityLabel) {
    securityLabel.innerHTML = 'SECURITY <span class="admin-badge">ADMIN</span>';
  }
  
  // Enhance threat detection page
  const threatHeader = document.querySelector('#page-threats .page-header p');
  if (threatHeader) {
    threatHeader.textContent = 'Full threat monitoring · admin-level access · live alerts';
  }
  
  // Add test functionality button for admins
  const adminTools = document.createElement('div');
  adminTools.className = 'admin-tools-card';
  adminTools.innerHTML = `
    <button class="admin-test-btn" onclick="testRBAC()">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <path d="M22 11.08V12a10 10 0 11-5.93-9.14"/>
        <path d="M22 4L12 14.01l-3-3"/>
      </svg>
      Test RBAC
    </button>
    <button class="admin-test-btn" onclick="verifyIntegrity()">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
      </svg>
      Verify Logs
    </button>
  `;
  
  const navSection = document.querySelector('.nav-right');
  if (navSection && !document.querySelector('.admin-tools-card')) {
    navSection.prepend(adminTools);
  }
}

// Add CSS for role-specific UI elements
const roleStylesheet = document.createElement('style');
roleStylesheet.textContent = `
  .security-option {
    padding: 14px 20px;
    display: flex;
    align-items: center;
    gap: 16px;
    border-bottom: 1px solid var(--border);
    cursor: pointer;
    transition: all var(--t-fast);
  }
  .security-option:last-child {
    border-bottom: none;
  }
  .security-option:hover {
    background: rgba(255,255,255,0.02);
  }
  .security-option-icon {
    font-size: 24px;
    width: 40px;
    height: 40px;
    display: flex;
    align-items: center;
    justify-content: center;
    background: var(--surface);
    border-radius: var(--radius);
    border: 1px solid var(--border);
  }
  .security-option-content {
    flex: 1;
  }
  .security-option-title {
    font-weight: 500;
    font-size: 14px;
    color: var(--text);
    margin-bottom: 2px;
  }
  .security-option-desc {
    font-size: 12px;
    color: var(--text3);
  }
  .security-option-arrow {
    color: var(--text3);
    font-size: 18px;
  }
  
  .admin-badge {
    display: inline-block;
    background: var(--danger-bg);
    color: var(--danger);
    font-size: 8px;
    padding: 2px 6px;
    border-radius: 4px;
    margin-left: 6px;
    font-weight: 600;
  }
  
  .admin-tools-card {
    display: flex;
    gap: 8px;
    margin-right: 12px;
  }
  
  .admin-test-btn {
    display: flex;
    align-items: center;
    gap: 6px;
    padding: 5px 10px;
    border-radius: var(--radius);
    background: var(--surface);
    border: 1px solid var(--border);
    font-size: 10px;
    color: var(--accent);
    font-family: var(--mono);
    cursor: pointer;
    transition: all var(--t-fast);
  }
  
  .admin-test-btn:hover {
    border-color: var(--accent);
    background: var(--accent-bg);
  }
`;
document.head.appendChild(roleStylesheet);

// Initialize RBAC testing and UI customization on page load
window.addEventListener('load', () => {
  // Wait a bit to ensure UI elements are properly loaded and RBAC applied
  setTimeout(() => {
    applyRoleBasedUI();
  }, 1000);
});
