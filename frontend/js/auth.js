/**
 * Role selector handling and Login/Logout functions.
 */

// Note: selectedRole is shared with app.js; initialized here as default
if (typeof selectedRole === 'undefined') { var selectedRole = 'Admin'; }

function setRole(el, role) {
  document.querySelectorAll('.role-btn').forEach(b => b.classList.remove('active'));
  el.classList.add('active');
  selectedRole = role;
  
  const fp = document.getElementById('fp-link-container');
  const su = document.getElementById('signup-link-container');
  
  if (role === 'Developer') {
      if (fp) fp.style.display = 'none';
      if (su) su.style.display = 'none';
  } else if (role === 'Admin') {
      if (fp) fp.style.display = 'flex';
      if (su) su.style.display = 'none';
  } else {
      // Guest
      if (fp) fp.style.display = 'flex';
      if (su) su.style.display = 'block';
  }
}

function togglePwd() {
  const i = document.getElementById('password');
  i.type = i.type === 'password' ? 'text' : 'password';
}

async function doLogin() {
  const u = document.getElementById('username').value.trim();
  const p = document.getElementById('password').value;
  const err = document.getElementById('error-msg');
  const btn = document.querySelector('.login-btn');

  err.style.display = 'none';
  if (!u || !p) {
    err.style.display = 'block';
    err.textContent = '⚠️ Please fill in all fields.';
    return;
  }

  btn.textContent = 'Authenticating…';
  btn.disabled = true;

  // POST /api/auth/login — REAL API CALL
  const result = await api('POST', '/api/auth/login', { username: u, password: p }, false);

  btn.textContent = 'Access Gateway →';
  btn.disabled = false;

  if (!result.ok) {
    err.style.display = 'block';
    err.textContent = '⚠️ ' + (result.data?.error || 'Invalid credentials.');
    return;
  }

  // Store token and session data
  setToken(result.data.token);
  localStorage.setItem('sg_username', result.data.username);
  localStorage.setItem('sg_role', result.data.role);

  // Update nav
  document.getElementById('nav-username').textContent = result.data.username;
  document.getElementById('nav-role').textContent = result.data.role;
  document.getElementById('nav-avatar').textContent = result.data.username[0].toUpperCase();

  applyRBAC(result.data.role);
  showView('dashboard');
  startClock();
  goPage('overview');
  await initDashboard(); // await so dashboard data loads before returning
}

// Support "Enter" key on login fields
document.addEventListener('DOMContentLoaded', () => {
  const u = document.getElementById('username');
  const p = document.getElementById('password');
  const loginFn = (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      doLogin();
    }
  };
  if (u) u.addEventListener('keydown', loginFn);
  if (p) p.addEventListener('keydown', loginFn);
});

async function doLogout() {
  // POST /api/auth/logout — REAL API CALL
  await api('POST', '/api/auth/logout');
  clearToken();
  if (liveInterval) { clearInterval(liveInterval); liveInterval = null; }
  showView('login');
  document.getElementById('username').value = '';
  document.getElementById('password').value = '';
  document.getElementById('error-msg').style.display = 'none';
}

/* ══ FORGOT PASSWORD UI LOGIC ══ */
function openForgotPwdModal() {
  document.getElementById('fp-modal-overlay').classList.add('open');
  document.getElementById('fp-step-1').style.display = 'block';
  document.getElementById('fp-step-2').style.display = 'none';
  document.getElementById('fp-step-3').style.display = 'none';
  const idInput = document.getElementById('fp-identity');
  idInput.value = '';
  
  // Prevent "Enter" from refreshing page
  idInput.onkeydown = (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      handleForgotPwdIdentity();
    }
  };
}

function closeForgotPwdModal(e) {
  if (e && e.target !== document.getElementById('fp-modal-overlay')) return;
  document.getElementById('fp-modal-overlay').classList.remove('open');
}

async function handleForgotPwdIdentity() {
  const identity = document.getElementById('fp-identity').value.trim();
  if (!identity) return;

  const btn = document.querySelector('#fp-step-1 .fp-btn');
  const errContainer = document.querySelector('#fp-step-1');
  
  if (selectedRole === 'Guest' && !identity.includes('@')) {
      const orig = btn.textContent;
      btn.textContent = "Error: Must use Email address";
      btn.disabled = true;
      setTimeout(() => { btn.textContent = orig; btn.disabled = false; }, 2500);
      return;
  }
  
  btn.textContent = "Checking...";
  btn.disabled = true;

  // Enforce strict UI layout based on selected tab (per user request, no dynamic backend override)
  const safeRole = selectedRole || 'Guest';
  window._tempFpRole = safeRole.toLowerCase();

  btn.textContent = "Continue →";
  btn.disabled = false;

  const contentDiv = document.getElementById('fp-dynamic-content');

  if (window._tempFpRole === 'admin') {
    contentDiv.innerHTML = `
      <button type="button" class="fp-btn" onclick="submitRecovery(event)">Request Admin Reset</button>
      <div class="fp-note">
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
        Security team will be notified
      </div>
    `;
  } else if (window._tempFpRole === 'developer') {
    contentDiv.innerHTML = `
      <button type="button" class="fp-btn" onclick="submitRecovery(event)">Send Secure Reset Link</button>
      <div class="fp-note">
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>
        TOTP required during reset
      </div>
    `;
  } else {
    contentDiv.innerHTML = `
      <button type="button" class="fp-btn" onclick="submitRecovery(event)">Send OTP</button>
    `;
  }

  document.getElementById('fp-step-1').style.display = 'none';
  document.getElementById('fp-step-2').style.display = 'block';
}

async function submitRecovery(e) {
  if (e) e.preventDefault();
  
  const identity = document.getElementById('fp-identity').value.trim();
  const btn = document.querySelector('#fp-step-2 .fp-btn');
  if (btn) {
      btn.textContent = "Sending...";
      btn.disabled = true;
  }

  try {
    // Final dispatch
    await api('POST', '/api/auth/forgot-password', { identity }, false);

    document.getElementById('fp-step-2').style.display = 'none';

    if (window._tempFpRole === 'admin' || window._tempFpRole === 'developer') {
        document.getElementById('fp-step-3-neutral').style.display = 'block';
    } else {
        document.getElementById('fp-step-3').style.display = 'block';
    }
  } catch (err) {
    console.error("Recovery process failed:", err);
    if (btn) btn.textContent = "Error: Please check connection";
  } finally {
    if (btn) btn.disabled = false;
  }
}

function toggleFPPwd(id) {
  const i = document.getElementById(id);
  i.type = i.type === 'password' ? 'text' : 'password';
}

async function saveNewPassword() {
  const otp = document.getElementById('fp-otp').value.trim();
  const pwd1 = document.getElementById('fp-new-pwd').value;
  const pwd2 = document.getElementById('fp-new-pwd-confirm').value;
  const err = document.getElementById('fp-reset-error');
  const btn = document.querySelector('#fp-step-3 .fp-btn');
  
  err.style.display = 'none';
  if (otp.length < 6) {
    err.textContent = '⚠️ Invalid OTP format.';
    err.style.display = 'block';
    return;
  }
  if (pwd1 !== pwd2) {
    err.textContent = '⚠️ Passwords do not match.';
    err.style.display = 'block';
    return;
  }
  if (pwd1.length < 8) {
      err.textContent = '⚠️ Password must be at least 8 characters.';
      err.style.display = 'block';
      return;
  }
  
  btn.textContent = "Resetting...";
  btn.disabled = true;
  
  const res = await api('POST', '/api/auth/reset-password', {
      identity: document.getElementById('fp-identity').value.trim(),
      otp: otp,
      new_password: pwd1
  }, false);
  
  btn.disabled = false;
  btn.textContent = "Reset Password";
  
  if(!res.ok) {
      err.textContent = '⚠️ ' + (res.data?.error || 'Failed to reset password.');
      err.style.display = 'block';
  } else {
      closeForgotPwdModal();
      document.getElementById('username').value = document.getElementById('fp-identity').value.trim();
      const loginErr = document.getElementById('error-msg');
      loginErr.style.display = 'block';
      loginErr.style.color = 'var(--accent)';
      loginErr.textContent = '✅ Password successfully reset. Please log in.';
      setTimeout(()=> { loginErr.style.color = ''; loginErr.style.display = 'none'; }, 6000);
  }
}

/* ══ REGISTRATION UI LOGIC ══ */
function toggleRegister() {
    const lg = document.getElementById('login-card-main');
    const rg = document.getElementById('register-card');
    if (lg.style.display === 'none') {
        lg.style.display = 'block';
        rg.style.display = 'none';
    } else {
        lg.style.display = 'none';
        rg.style.display = 'block';
    }
}

function toggleRegPwd() {
  const i = document.getElementById('reg-password');
  i.type = i.type === 'password' ? 'text' : 'password';
}

async function doRegister() {
    const u = document.getElementById('reg-username').value.trim();
    const e = document.getElementById('reg-email').value.trim();
    const p1 = document.getElementById('reg-password').value;
    const p2 = document.getElementById('reg-password-confirm').value;
    const err = document.getElementById('reg-error-msg');
    
    err.style.display = 'none';
    if (!u || !e || !p1 || !p2) {
        err.textContent = '⚠️ Please fill in all fields.';
        err.style.display = 'block';
        return;
    }
    if (p1 !== p2) {
        err.textContent = '⚠️ Passwords do not match.';
        err.style.display = 'block';
        return;
    }
    
    const btn = document.querySelector('#register-card .login-btn');
    btn.textContent = 'Creating...';
    btn.disabled = true;
    
    const res = await api('POST', '/api/auth/register', { username: u, email: e, password: p1, role: 'guest' }, false);
    
    btn.textContent = 'Create Account';
    btn.disabled = false;
    
    if(!res.ok) {
        err.textContent = '⚠️ ' + (res.data?.error || 'Registration failed.');
        err.style.display = 'block';
    } else {
        toggleRegister();
        document.getElementById('username').value = u;
        const loginErr = document.getElementById('error-msg');
        loginErr.style.display = 'block';
        loginErr.style.color = 'var(--accent)';
        loginErr.textContent = '✅ Account created! Please log in.';
        setTimeout(()=> { loginErr.style.color = ''; loginErr.style.display = 'none'; }, 5000);
    }
}
