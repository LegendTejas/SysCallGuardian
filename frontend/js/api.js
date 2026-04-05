const BASE_URL = '';
const TOKEN_KEY = 'sg_token';

function getToken() { return localStorage.getItem(TOKEN_KEY); }
function setToken(t) { localStorage.setItem(TOKEN_KEY, t); }
function clearToken() { localStorage.removeItem(TOKEN_KEY); }
function isLoggedIn() { return !!getToken(); }

/**
 * Core API fetch wrapper with simplified error handling and auth support.
 */
async function api(method, endpoint, body = null, auth = true) {
  const headers = { 'Content-Type': 'application/json' };
  if (auth && getToken()) {
    headers['Authorization'] = 'Bearer ' + getToken();
  }

  const opts = { method, headers };
  if (body) opts.body = JSON.stringify(body);

  console.log(`[API Call] ${method} ${BASE_URL}${endpoint}`);
  try {
    const res = await fetch(BASE_URL + endpoint, opts);
    const data = res.headers.get('content-type')?.includes('json') ? await res.json() : null;

    if (res.status === 401) {
      clearToken();
      showView('login');
      showToast('danger', 'Session expired. Please log in again.');
      return { ok: false, data: null, status: 401 };
    }
    return { ok: res.ok, data, status: res.status };
  } catch (e) {
    console.error('[API Error]:', e);
    return { ok: false, data: null, status: 0 };
  }
}

/**
 * Common dashboard endpoints with optional filtering
 */
const apiGetStats = (p = {}) => {
  const q = new URLSearchParams(p).toString();
  return api('GET', `/api/dashboard/stats?${q}`);
};
const apiGetActivity = (p = {}) => {
  const q = new URLSearchParams(p).toString();
  return api('GET', `/api/dashboard/activity?${q}`);
};
const apiGetExtended = (p = {}) => {
  const q = new URLSearchParams(p).toString();
  return api('GET', `/api/dashboard/extended?${q}`);
};
const apiGetLogs = (p = {}) => {
  const q = new URLSearchParams(p).toString();
  return api('GET', `/api/logs?${q}`);
};
const apiGetThreats = () => api('GET', '/api/threats');
const apiVerifyLogs = () => api('GET', '/api/logs/verify');
