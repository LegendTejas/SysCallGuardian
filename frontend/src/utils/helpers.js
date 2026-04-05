/**
 * frontend/src/utils/helpers.js
 * Akhil — Shared utility functions used across all UI components.
 */

// ── Time Formatting ───────────────────────────────────────────────────────────

/**
 * Format an ISO timestamp into a readable local time string.
 * "2026-03-25T14:32:01.000Z" → "14:32:01"
 */
export function formatTime(isoString) {
  if (!isoString) return '—';
  return new Date(isoString).toLocaleTimeString('en-IN', {
    hour:   '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

/**
 * Format an ISO timestamp into date + time.
 * "2026-03-25T14:32:01Z" → "25 Mar, 14:32"
 */
export function formatDateTime(isoString) {
  if (!isoString) return '—';
  return new Date(isoString).toLocaleString('en-IN', {
    day:    '2-digit',
    month:  'short',
    hour:   '2-digit',
    minute: '2-digit',
  });
}

/**
 * Return a human-friendly "time ago" string.
 * "2 minutes ago", "just now", etc.
 */
export function timeAgo(isoString) {
  const diff = Date.now() - new Date(isoString).getTime();
  const secs = Math.floor(diff / 1000);
  if (secs < 10)  return 'just now';
  if (secs < 60)  return `${secs}s ago`;
  const mins = Math.floor(secs / 60);
  if (mins < 60)  return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs  < 24)  return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

// ── Risk Classification ───────────────────────────────────────────────────────

/**
 * Classify a numeric risk score into a level string.
 * Matches Vanshika's backend: risk_scoring.py
 */
export function getRiskLevel(score) {
  if (score >= 70) return 'critical';
  if (score >= 40) return 'high';
  if (score >= 20) return 'medium';
  return 'low';
}

/**
 * Map a risk level string to a CSS color variable.
 */
export function getRiskColor(score) {
  const level = getRiskLevel(score);
  return {
    critical: 'var(--danger)',
    high:     'var(--danger)',
    medium:   'var(--warning)',
    low:      'var(--info)',
  }[level];
}

// ── Status Badge HTML ─────────────────────────────────────────────────────────

/**
 * Return the HTML string for a status badge.
 * status: "allowed" | "blocked" | "flagged" | "suspicious"
 */
export function statusBadge(status) {
  const map = {
    allowed:    ['allowed',    '✓ Allowed'],
    blocked:    ['blocked',    '✗ Blocked'],
    flagged:    ['suspicious', '⚠ Flagged'],
    suspicious: ['suspicious', '⚠ Suspicious'],
  };
  const [cls, label] = map[status] || ['', status];
  return `<span class="status-badge ${cls}">${label}</span>`;
}

// ── Number Formatting ─────────────────────────────────────────────────────────

/** Format a large number with commas: 4821 → "4,821" */
export function formatNumber(n) {
  return (n ?? 0).toLocaleString('en-IN');
}

/** Truncate a SHA-256 hash for display: "a3f2c1d8...e4b7912f" */
export function shortHash(hash) {
  if (!hash || hash.length < 12) return hash || '—';
  return hash.slice(0, 8) + '…' + hash.slice(-4);
}

// ── Error Display ─────────────────────────────────────────────────────────────

/**
 * Extract a user-friendly error message from an API result.
 * Handles network errors, server errors, and validation errors.
 */
export function getErrorMessage(result) {
  if (!result)              return 'An unknown error occurred.';
  if (result.status === 0)  return 'Cannot reach the server. Is the backend running on port 5000?';
  if (result.status === 401) return 'Session expired. Please log in again.';
  if (result.status === 403) return 'You do not have permission to perform this action.';
  if (result.status === 404) return 'Resource not found.';
  if (result.status >= 500)  return 'Server error. Check the Flask console for details.';
  return result.error || 'Something went wrong.';
}

// ── Debounce ──────────────────────────────────────────────────────────────────

/**
 * Debounce a function call.
 * Used for search input → prevents API call on every keystroke.
 *
 * Usage:
 *   const debouncedSearch = debounce(() => fetchLogs(), 300);
 *   searchInput.addEventListener('input', debouncedSearch);
 */
export function debounce(fn, delayMs = 300) {
  let timer;
  return (...args) => {
    clearTimeout(timer);
    timer = setTimeout(() => fn(...args), delayMs);
  };
}

// ── Pagination Helper ─────────────────────────────────────────────────────────

/**
 * Build a pagination config object.
 * Returns: { totalPages, hasPrev, hasNext, currentPage }
 */
export function getPaginationInfo(total, page, perPage) {
  const totalPages = Math.max(1, Math.ceil(total / perPage));
  return {
    totalPages,
    currentPage: page,
    hasPrev:     page > 1,
    hasNext:     page < totalPages,
    startEntry:  (page - 1) * perPage + 1,
    endEntry:    Math.min(page * perPage, total),
  };
}
