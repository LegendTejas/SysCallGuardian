/**
 * frontend/src/services/api.js
 * Akhil — Central API service layer.
 *
 * All backend communication goes through this file.
 * Features:
 *  - Token stored in localStorage (set on login, cleared on logout)
 *  - Every request automatically attaches Authorization: Bearer <token>
 *  - Global 401 handler → redirects to login
 *  - Consistent { data, error, status } response shape
 *  - Base URL from environment variable with localhost fallback
 */

const BASE_URL = window.API_BASE_URL || 'http://localhost:5000';

// ── Token Management ──────────────────────────────────────────────────────────

const TOKEN_KEY   = 'sg_token';
const USERNAME_KEY = 'sg_username';
const ROLE_KEY    = 'sg_role';

export const Auth = {
  setSession(token, username, role) {
    localStorage.setItem(TOKEN_KEY,    token);
    localStorage.setItem(USERNAME_KEY, username);
    localStorage.setItem(ROLE_KEY,     role);
  },
  clearSession() {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(USERNAME_KEY);
    localStorage.removeItem(ROLE_KEY);
  },
  getToken()    { return localStorage.getItem(TOKEN_KEY);    },
  getUsername() { return localStorage.getItem(USERNAME_KEY); },
  getRole()     { return localStorage.getItem(ROLE_KEY);     },
  isLoggedIn()  { return !!localStorage.getItem(TOKEN_KEY);  },
};

// ── Core Fetch Wrapper ────────────────────────────────────────────────────────

/**
 * Central fetch handler.
 * Returns: { data: object|null, error: string|null, status: number }
 */
async function request(method, endpoint, body = null, requiresAuth = true) {
  const headers = { 'Content-Type': 'application/json' };

  if (requiresAuth) {
    const token = Auth.getToken();
    if (!token) {
      handleUnauthorized();
      return { data: null, error: 'No token found.', status: 401 };
    }
    headers['Authorization'] = `Bearer ${token}`;
  }

  const options = { method, headers };
  if (body) options.body = JSON.stringify(body);

  try {
    const response = await fetch(`${BASE_URL}${endpoint}`, options);

    // Global 401 handler — token expired or revoked
    if (response.status === 401) {
      handleUnauthorized();
      return { data: null, error: 'Session expired. Please log in again.', status: 401 };
    }

    let data = null;
    const contentType = response.headers.get('content-type') || '';
    if (contentType.includes('application/json')) {
      data = await response.json();
    }

    if (!response.ok) {
      const error = data?.error || data?.message || `HTTP ${response.status}`;
      return { data: null, error, status: response.status };
    }

    return { data, error: null, status: response.status };

  } catch (err) {
    // Network error (server down, CORS, etc.)
    const error = err.message === 'Failed to fetch'
      ? 'Cannot reach the server. Is the backend running?'
      : err.message;
    return { data: null, error, status: 0 };
  }
}

function handleUnauthorized() {
  Auth.clearSession();
  // Dispatch a custom event so the UI can react (redirect to login)
  window.dispatchEvent(new CustomEvent('sg:unauthorized'));
}

// ── Auth Endpoints ────────────────────────────────────────────────────────────

export const AuthAPI = {
  /**
   * POST /api/auth/login
   * On success, stores token + user info in localStorage.
   */
  async login(username, password) {
    const result = await request('POST', '/api/auth/login', { username, password }, false);
    if (!result.error && result.data?.token) {
      Auth.setSession(result.data.token, result.data.username, result.data.role);
    }
    return result;
  },

  /**
   * POST /api/auth/logout
   * Clears localStorage regardless of server response.
   */
  async logout() {
    const result = await request('POST', '/api/auth/logout');
    Auth.clearSession();
    return result;
  },

  /**
   * GET /api/user/me
   * Returns current user info (username, role, risk_score, is_flagged).
   */
  async me() {
    return request('GET', '/api/user/me');
  },
};

// ── Policy Endpoints ──────────────────────────────────────────────────────────

export const PolicyAPI = {
  /** GET /api/policies */
  async getAll() {
    return request('GET', '/api/policies');
  },

  /** POST /api/policies */
  async create(name, ruleJson) {
    return request('POST', '/api/policies', { name, rule_json: ruleJson });
  },

  /** PUT /api/policies/:id */
  async update(id, ruleJson = null, isActive = null) {
    const body = {};
    if (ruleJson  !== null) body.rule_json  = ruleJson;
    if (isActive  !== null) body.is_active   = isActive;
    return request('PUT', `/api/policies/${id}`, body);
  },
};

// ── Syscall Endpoints ─────────────────────────────────────────────────────────

export const SyscallAPI = {
  /** POST /api/syscall/read */
  async readFile(filePath) {
    return request('POST', '/api/syscall/read', { file_path: filePath });
  },

  /** POST /api/syscall/write */
  async writeFile(filePath, data) {
    return request('POST', '/api/syscall/write', { file_path: filePath, data });
  },

  /** POST /api/syscall/delete */
  async deleteFile(filePath) {
    return request('POST', '/api/syscall/delete', { file_path: filePath });
  },

  /** POST /api/syscall/execute */
  async execute(command) {
    return request('POST', '/api/syscall/execute', { command });
  },
};

// ── Log Endpoints ─────────────────────────────────────────────────────────────

export const LogAPI = {
  /**
   * GET /api/logs
   * All params are optional filters.
   */
  async getLogs({ user, status, call_type, date, from: fromDt, to: toDt, page = 1 } = {}) {
    const params = new URLSearchParams();
    if (user)      params.set('user',      user);
    if (status)    params.set('status',    status);
    if (call_type) params.set('call_type', call_type);
    if (date)      params.set('date',      date);
    if (fromDt)    params.set('from',      fromDt);
    if (toDt)      params.set('to',        toDt);
    params.set('page', page);
    const qs = params.toString();
    return request('GET', `/api/logs${qs ? '?' + qs : ''}`);
  },

  /** GET /api/logs/verify — full chain verification */
  async verifyAll() {
    return request('GET', '/api/logs/verify');
  },

  /** GET /api/logs/verify/:id — single entry verification */
  async verifySingle(id) {
    return request('GET', `/api/logs/verify/${id}`);
  },
};

// ── Dashboard Endpoints ───────────────────────────────────────────────────────

export const DashboardAPI = {
  /** GET /api/dashboard/stats */
  async getStats() {
    return request('GET', '/api/dashboard/stats');
  },

  /** GET /api/dashboard/activity — hourly timeline */
  async getActivity() {
    return request('GET', '/api/dashboard/activity');
  },
};

// ── Threat Endpoints ──────────────────────────────────────────────────────────

export const ThreatAPI = {
  /** GET /api/threats — flagged users with risk scores */
  async getSuspiciousUsers() {
    return request('GET', '/api/threats');
  },
};
