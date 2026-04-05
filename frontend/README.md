# 🎨 SysCallGuardian — Frontend & Dashboard

> We built the complete UI layer for SysCallGuardian — a Secure System Call Gateway with Role-Based Access Control and Real-Time Monitoring. This covers everything from the login page to the live dashboard, charts, log viewer, threat panel, and all interactivity.

---

## 📌 Table of Contents

- [What I Built](#-what-i-built)
- [Tech Stack](#-tech-stack)
- [How to Run](#-how-to-run)
- [File Structure](#-file-structure)
- [Design System](#-design-system)
- [Pages & Components](#-pages--components)
  - [Login Page](#1-login-page)
  - [Overview Dashboard](#2-overview-dashboard)
  - [Live Activity Feed](#3-live-activity-feed)
  - [Users & Roles](#4-users--roles)
  - [Policies](#5-policies)
  - [Threat Detection](#6-threat-detection)
  - [Audit Logs](#7-audit-logs)
- [JavaScript Architecture](#-javascript-architecture)
  - [View & Page Router](#view--page-router)
  - [Live Feed Engine](#live-feed-engine)
  - [Log Filter & Paginator](#log-filter--paginator)
  - [Modal System](#modal-system)
  - [Toast Notifications](#toast-notifications)
  - [Chart Initialization](#chart-initialization)
- [Interactivity Map](#-interactivity-map)
- [Key Features](#-key-features)
- [Screenshots](#-screenshots)
- [Future Work](#-future-work)

---

## 🔍 What We Built

The entire frontend for SysCallGuardian is a **single-file SPA** (`index.html`) — no frameworks, no build tools, no bundler. Pure HTML5, CSS3, and Vanilla JavaScript ES6+.

It consists of:
- A **login page** with role-selector (Admin / Developer / Guest), credential validation, and session state. Public registration is disabled and managed via the dashboard.
- A **full dashboard shell** with sticky navbar, sidebar navigation, and 6 inner pages
- **Real-time charts** using Chart.js (syscall activity line chart + call distribution donut)
- A **live activity feed** that streams simulated syscall events with pause/resume
- A **filterable, paginated audit log table** with 4 filters + search
- A **policy toggle interface** to enable/disable security rules
- A **threat detection panel** with risk scores and drill-down
- A **modal system** for log detail, user profiles, and threat events
- A **toast notification system** for all user actions

The frontend is designed to plug directly into the backend APIs (Flask/FastAPI) once integration begins in Phase 3. All data currently comes from in-memory JS arrays that mirror the real database schema.

---

## 🧰 Tech Stack

| Technology | Version | Purpose |
|---|---|---|
| HTML5 | — | Semantic structure, single-file SPA |
| CSS3 | — | Layout, animations, design system via custom properties |
| JavaScript | ES6+ | All interactivity, routing, state, DOM manipulation |
| [Chart.js](https://www.chartjs.org/) | 4.4.1 | Line chart + Donut chart (CDN) |
| [DM Sans](https://fonts.google.com/specimen/DM+Sans) | Variable | Primary UI font — clean, modern sans-serif |
| [JetBrains Mono](https://fonts.google.com/specimen/JetBrains+Mono) | 400/500 | Monospace font for code, hashes, metadata |

**No npm. No React. No build step.** Open the file → it works.

---

## 🚀 How to Run

```bash
# Option 1 — just open it directly
open syscall-gateway-interactive.html

# Option 2 — local server (better for future fetch/API calls)
python3 -m http.server 8080
# → visit http://localhost:8080/syscall-gateway-interactive.html
```

**Demo login:** Refer to root README for Tejax (Admin), Vancika (Dev), or GuestA/B credentials. The frontend is fully integrated with the Flask backend.

---

## 📁 File Structure

Everything lives in one file. Here's the internal layout:

```
index.html
│
├── <head>
│   ├── Google Fonts  (DM Sans + JetBrains Mono)
│   └── Chart.js 4.4.1  (CDN)
│
├── <style>  ── ~500 lines of CSS
│   ├── :root  ── design tokens (colors, spacing, fonts, shadows)
│   ├── Login page styles
│   ├── Dashboard shell  (topnav · sidebar · main-content)
│   ├── Component styles
│   │   ├── Stat cards (.stat-card, .stat-grid)
│   │   ├── Chart cards (.card, .chart-wrap)
│   │   ├── Log table (.log-table, .status-badge)
│   │   ├── Live feed rows (.live-entry, .counter-bar)
│   │   ├── User cards (.user-card, .user-avatar-lg)
│   │   ├── Policy items (.policy-item, .policy-status-toggle)
│   │   ├── Threat events (.threat-event, .threat-badge)
│   │   └── Audit log filters (.filter-select, .search-input, .pagination)
│   ├── Modal overlay + modal card  (.modal-overlay, .modal)
│   ├── Toast notifications  (.toast-wrap, .toast)
│   └── Utility classes  (.btn, .tag, .breadcrumb, .section-header)
│
├── <body>  ── ~400 lines of HTML
│   ├── #login-view
│   └── #dashboard-view
│       ├── .topnav
│       ├── .sidebar  (5 nav items + logout)
│       └── .main-content
│           ├── #page-overview
│           ├── #page-live
│           ├── #page-users
│           ├── #page-policies
│           ├── #page-threats
│           └── #page-logs
│   └── #modal-overlay  (shared modal)
│   └── #toasts  (toast container)
│
└── <script>  ── ~280 lines of JS
    ├── Data  (ALL_LOGS[], POLICIES[], LIVE_EVENTS[])
    ├── State  (selectedRole, livePaused, liveInterval, logPage)
    ├── Login / logout
    ├── Page router  (goPage, showView)
    ├── Clock ticker
    ├── Chart.js init
    ├── Live feed  (startLiveFeed, addLiveRow, toggleLiveFeed)
    ├── Policy renderer  (renderPolicies, togglePolicy)
    ├── Log filter + paginator  (getFilteredLogs, renderLogs, drawLogs)
    ├── Modals  (openLogModal, openUserModal, openThreatModal, closeModal)
    └── Toasts  (showToast)
```

---

## 🎨 Design System

All visual decisions are defined once as CSS custom properties in `:root` and referenced everywhere else. Changing a color, radius, or shadow is a one-line edit.

### Color Tokens

```css
:root {
  /* ── Surfaces ── */
  --bg: #F8F7F4;           /* page background — warm off-white */
  --surface: #FFFFFF;      /* cards, navbar, sidebar */
  --surface2: #F2F1ED;     /* hover states, table row highlights */

  /* ── Borders ── */
  --border: #E4E2DC;       /* default border */
  --border2: #D0CEC6;      /* hover / focus border */

  /* ── Text ── */
  --text: #1A1916;         /* primary — near-black warm */
  --text2: #6B6862;        /* secondary — labels, subtitles */
  --text3: #9E9B95;        /* muted — placeholders, timestamps */

  /* ── Semantic ── */
  --accent: #1A6B4A;         /* green → allowed, primary CTA */
  --accent-light: #E6F4EE;   /* green tint → badge backgrounds */
  --accent-mid: #2D9E6F;     /* green mid → charts, status dot */
  --danger: #C0392B;         /* red → blocked, error states */
  --danger-light: #FDF0EE;   /* red tint → badge backgrounds */
  --warning: #B7600A;        /* amber → suspicious activity */
  --warning-light: #FEF5E7;  /* amber tint */
  --info: #1A5C9C;           /* blue → informational states */
  --info-light: #EBF2FB;     /* blue tint */

  /* ── Typography ── */
  --sans: 'DM Sans', sans-serif;           /* all UI text */
  --mono: 'JetBrains Mono', monospace;     /* code, hashes, labels, metadata */

  /* ── Shape ── */
  --radius: 10px;
  --radius-lg: 16px;

  /* ── Elevation ── */
  --shadow: 0 1px 3px rgba(0,0,0,0.06), 0 1px 2px rgba(0,0,0,0.04);
  --shadow-md: 0 4px 16px rgba(0,0,0,0.08), 0 1px 4px rgba(0,0,0,0.04);
}
```

### Typography Scale

| Use | Size | Weight | Font |
|---|---|---|---|
| Page titles (`h1`) | 22px | 500 | DM Sans |
| Card titles | 14px | 500 | DM Sans |
| Body text | 13–14px | 400 | DM Sans |
| Labels / section headers | 10–11px | 600 | JetBrains Mono + uppercase |
| Code / hashes / paths | 11px | 400 | JetBrains Mono |
| Status badges / pills | 10px | 600 | JetBrains Mono |

### Color → Meaning Mapping

| Color | Meaning | Used in |
|---|---|---|
| `--accent` green | Allowed / success / primary action | Allowed badges, active nav, primary buttons, stat card tops |
| `--danger` red | Blocked / error / critical threat | Blocked badges, danger toasts, critical threat borders |
| `--warning` amber | Suspicious / medium risk | Suspicious badges, medium threat borders, warn toasts |
| `--info` blue | Informational / low risk | Info tags, low threat borders, page-number buttons |

---

## 📄 Pages & Components

### 1. Login Page

**`#login-view`** — full-viewport centered flex layout. Securely restricted to existing users; public signup is disabled.

```
┌─────────────────────────────────┐
│   🛡️ SecureGate                 │
│   SYSTEM CALL GATEWAY v1.0      │
│                                 │
│  ┌───────────────────────────┐  │
│  │  Welcome back             │  │
│  │  Select role + enter creds│  │
│  │                           │  │
│  │  [🛡️ Admin][⚙️ Dev][👤 Guest] │
│  │                           │  │
│  │  Username: [_____________]│  │
│  │  Password: [_________] 👁 │  │
│  │                           │  │
│  │  [  Access Gateway →  ]   │  │
│  │  ⚠ error message (hidden) │  │
│  │  ─── bcrypt · SHA-256 ─── │  │
│  │  🔒 Session expires 4 hours│  │
│  │  [RBAC][bcrypt][SHA-256]   │  │
│  └───────────────────────────┘  │
│  OS Sem 4 · Akhil·Tejas·Vanshika │
└─────────────────────────────────┘
```

**Role selector** — 3 CSS grid cards. Clicking sets `selectedRole` and applies `.active` (green border + tinted background).

**Password toggle** — `👁` icon button. Switches `input.type` between `"password"` and `"text"`.

**Login validation:**
```js
function doLogin() {
  if (!username || !password)   → show error "fill all fields"
  if (password.length < 4)      → show error "invalid credentials"
  // on success:
  //   populate nav avatar, name, role from input
  //   showView('dashboard') → goPage('overview')
  //   initCharts() · startClock() · renderPolicies() · renderLogs() · startLiveFeed()
}
```

**Enter key** on password field triggers `doLogin()` via `keydown` listener.

---

### 2. Overview Dashboard

**`#page-overview`** — the landing page after login.

**Stat cards** (`.stats-grid` — 4-column CSS grid):

| Card | Accent color | Click navigates to |
|---|---|---|
| Total Syscalls | Green top bar | Audit Logs |
| Allowed | Green top bar | Audit Logs |
| Blocked | Red top bar | Audit Logs |
| Flagged Users | Amber top bar | Threat Detection |

Cards have `cursor: pointer` and lift slightly on hover (`transform: translateY(-1px)` + shadow).

**Charts row** (2-column grid, `1.6fr 1fr`):
- Left: **Line chart** — Allowed vs Blocked over 12 hours. Area fill, smooth tension (`0.4`), no point dots, JetBrains Mono tick labels
- Right: **Donut chart** — Allowed / Blocked / Suspicious distribution. `cutout: '72%'`, bottom legend

**Bottom row** (2-column grid, `1.4fr 1fr`):
- Left: Recent logs table — last 6 rows, each row clickable → log modal. "View All →" → Audit Logs
- Right: Suspicious users panel — 3 items with risk bars and color-coded left borders. Clicking any → Threat Detection

---

### 3. Live Activity Feed

**`#page-live`** — real-time syscall stream.

**Counter bar** — running totals for Allowed / Blocked / Suspicious, updating on every tick.

**Feed table columns:** Status badge · User · Call type + path · Timestamp

**How it works:**
```js
// Guarded: only starts once
liveInterval = setInterval(() => {
  if (livePaused) return;
  const ev = LIVE_EVENTS[Math.floor(Math.random() * LIVE_EVENTS.length)];
  addLiveRow(ev);               // inject new row at top of feed
  liveCount[ev.status]++;       // increment the right counter
  // update DOM counter text
}, 1800);  // every 1.8 seconds
```

`addLiveRow` injects a `div` at `feed.firstChild`, applies a `slideIn` CSS keyframe animation, and caps the list at 60 rows to avoid DOM bloat. Every row is clickable → log detail modal.

**Pause/Resume** — toggles `livePaused` boolean, changes button label. Interval keeps running, rows just stop being added.

---

### 4. Users & Roles

**`#page-users`** — 3-column CSS grid of user cards.

**Each `.user-card` shows:**
- Colored avatar (`green` = Admin, `blue` = Dev, `amber` = flagged Dev, `red` = critical Guest)
- Username + role label
- 2-stat mini grid: Syscalls count + Blocked count / Risk score
- **Internal Registration**: Admins and Developers can add new users via a toggleable "Add User" form card.

Clicking a card → `openUserModal(name, role, status, calls, risk)`:
- Header with avatar, name, role
- Status, syscall count, color-coded risk score, role fields
- **"Revoke Session"** → `showToast('warn', ...)`
- **"View Logs →"** → `goPage('logs')` + pre-sets user filter + calls `renderLogs()`

---

### 5. Policies

**`#page-policies`** — 8 security rules with interactive toggles.

**Toggle switch** — pure CSS. The knob is a `::after` pseudo-element:
```css
.policy-status-toggle.on::after  { left: 19px; }   /* knob right */
.policy-status-toggle.off::after { left: 3px;  }   /* knob left */
/* transition: left 0.2s — smooth slide animation */
```

Clicking a toggle:
```js
function togglePolicy(i, ev) {
  ev.stopPropagation();
  POLICIES[i].on = !POLICIES[i].on;
  renderPolicies();   // full list re-render
  showToast(POLICIES[i].on ? 'success' : 'warn', `Policy ${id} enabled/disabled`);
}
```

Policy data:
```js
{ id: 'P-01', name: 'Block /etc write by non-admin',
  desc: 'file_write · /etc/* · Guest, Dev → BLOCK', on: true }
```

---

### 6. Threat Detection

**`#page-threats`** — security-focused summary.

**4-card threat grid** (2×2):
- Critical Threats — red-tinted background card
- Medium Risk count
- Blocked Attempts Today
- Risk Engine Status — live green indicator

**Threat events** — each has a colored left border by severity:
```css
.threat-event.critical { border-left: 3px solid var(--danger);  background: var(--danger-light); }
.threat-event.medium   { border-left: 3px solid #E6960A;        background: var(--warning-light); }
.threat-event.low      { border-left: 3px solid var(--info);    background: var(--info-light); }
```

Clicking → `openThreatModal(user, level, desc, risk)` with user, severity badge, risk score, full description, **"Block User"** and **"Inspect Logs →"** actions.

---

### 7. Audit Logs

**`#page-logs`** — full paginated log viewer with live filtering.

**Filter bar:**
```
[Status ▾] [User ▾] [Call Type ▾] [search input___________] [Clear]
```

All inputs call `renderLogs()` on change/input. Filtering always resets to page 1.

**Filtering logic:**
```js
function getFilteredLogs() {
  const st  = document.getElementById('filter-status').value;
  const usr = document.getElementById('filter-user').value;
  const ct  = document.getElementById('filter-call').value;
  const q   = document.getElementById('log-search').value.toLowerCase();

  return ALL_LOGS.filter(l =>
    (!st  || l.status === st)  &&
    (!usr || l.user === usr)   &&
    (!ct  || l.call === ct)    &&
    (!q   || l.user.includes(q) || l.path.includes(q) || l.call.includes(q))
  );
}
```

**Table columns:** User · Call Type · Path · Status · PID · Time · Hash (truncated SHA-256)

**Pagination:**
```js
const totalPages = Math.ceil(filtered.length / LOGS_PER_PAGE);  // 8 per page
// Dynamically generates: [←] [1] [2] [3] [→]  N entries
// Active page gets .active class (green highlight)
```

Row click → `openLogModal(...)` showing all fields + full SHA-256 hash + "Flag Entry" action.

---

## ⚙️ JavaScript Architecture

### View & Page Router

```js
// Top-level: login ↔ dashboard shell
function showView(name) {
  document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
  document.getElementById(name + '-view').classList.add('active');
}

// Inner pages inside dashboard
// CSS: .page { display: none }  .page.active { display: block }
function goPage(name) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  document.getElementById('page-' + name).classList.add('active');
  document.getElementById('nav-' + name)?.classList.add('active');
  if (name === 'live') startLiveFeed();  // lazy-start on first visit
}
```

No URL changes — purely class toggling. The dashboard shell (nav + sidebar) is always rendered; only the inner `.page` content switches.

---

### Live Feed Engine

```js
let liveInterval = null;
let livePaused = false;
let liveCount = { allowed: 4512, blocked: 309, susp: 14 };

function startLiveFeed() {
  if (liveInterval) return;  // guard: only start once
  liveInterval = setInterval(() => {
    if (livePaused) return;
    const ev = LIVE_EVENTS[Math.floor(Math.random() * LIVE_EVENTS.length)];
    addLiveRow(ev);
    liveCount[ev.status === 'suspicious' ? 'susp' : ev.status]++;
    // update counter bar spans
  }, 1800);
  for (let i = 0; i < 14; i++) addLiveRow(LIVE_EVENTS[i % LIVE_EVENTS.length], false);
}

function addLiveRow(ev, animate = true) {
  const row = document.createElement('div');
  row.className = 'live-entry' + (animate ? ' new-row' : '');
  // innerHTML: status badge · user · call+path · timestamp
  row.onclick = () => openLogModal(...);
  feed.insertBefore(row, feed.firstChild);  // newest at top
  if (feed.children.length > 60) feed.removeChild(feed.lastChild);
}
```

---

### Log Filter & Paginator

```js
const LOGS_PER_PAGE = 8;
let logPage = 1;

function renderLogs() {
  logPage = 1;    // always reset to page 1 when filters change
  drawLogs();
}

function drawLogs() {
  const filtered = getFilteredLogs();
  const slice = filtered.slice((logPage - 1) * LOGS_PER_PAGE, logPage * LOGS_PER_PAGE);
  // render <tr> rows into #log-tbody
  // rebuild [← 1 2 3 →] pagination buttons
  // show total entry count
}
```

---

### Modal System

One shared overlay, three different content openers:

```js
// All three populate the same three DOM targets:
// #modal-title · #modal-body · #modal-footer

openLogModal(user, call, status, time, path, pid)
// → shows syscall details + SHA-256 hash + "Flag Entry" button

openUserModal(name, role, status, calls, risk)
// → shows user profile + "Revoke Session" + "View Logs →"

openThreatModal(user, level, desc, risk)
// → shows threat summary + "Block User" + "Inspect Logs →"

function closeModal(e) {
  // closes on overlay background click OR ✕ button click
  if (e && e.target !== document.getElementById('modal-overlay')) return;
  document.getElementById('modal-overlay').classList.remove('open');
}
```

---

### Toast Notifications

```js
function showToast(type, msg) {
  // type: 'success' | 'danger' | 'warn'
  const t = document.createElement('div');
  t.className = 'toast ' + type;
  t.innerHTML = (type==='success' ? '✓ ' : type==='danger' ? '⚠ ' : '⚡ ') + msg;
  document.getElementById('toasts').appendChild(t);
  setTimeout(() => {
    t.style.animation = 'toastOut 0.25s ease forwards';
    setTimeout(() => t.remove(), 250);
  }, 3000);
}
```

Toasts stack in the bottom-right corner (`position: fixed; bottom: 24px; right: 24px`). Multiple toasts queue independently.

---

### Chart Initialization

```js
let chartsInit = false;

function initCharts() {
  if (chartsInit) return;  // initialize only once per session
  chartsInit = true;

  // Line chart — syscall activity over 12 hours
  new Chart(lineCtx, {
    type: 'line',
    data: {
      labels: ['02:00', '04:00', ... , 'Now'],
      datasets: [
        { label: 'Allowed', data: [...], borderColor: '#2D9E6F',
          backgroundColor: 'rgba(45,158,111,0.08)', fill: true, tension: 0.4,
          pointRadius: 0, borderWidth: 2 },
        { label: 'Blocked',  data: [...], borderColor: '#C0392B',
          backgroundColor: 'rgba(192,57,43,0.06)',  fill: true, tension: 0.4,
          pointRadius: 0, borderWidth: 1.5 }
      ]
    },
    options: { responsive: true, maintainAspectRatio: false, ... }
  });

  // Donut chart — call distribution
  new Chart(donutCtx, {
    type: 'doughnut',
    data: { labels: ['Allowed','Blocked','Suspicious'],
            datasets: [{ data: [4512, 225, 84],
                         backgroundColor: ['#2D9E6F','#C0392B','#E6960A'],
                         borderWidth: 0 }] },
    options: { cutout: '72%', ... }
  });
}
```

---

## 🗺️ Interactivity Map

Complete map of every clickable element and its effect:

```
Login Page
├── Role buttons (Admin / Dev / Guest) ──── sets selectedRole, updates active style
├── 👁 password toggle ─────────────────── toggles input type password ↔ text
├── "Access Gateway →" ─────────────────── validates → transitions to dashboard
└── Enter key on password ──────────────── same as clicking the button

Sidebar
├── Overview ────────────────────────────── goPage('overview')
├── Live Activity ───────────────────────── goPage('live') + starts live feed
├── Users & Roles ───────────────────────── goPage('users')
├── Policies ────────────────────────────── goPage('policies')
├── Threat Detection ────────────────────── goPage('threats')
├── Audit Logs ──────────────────────────── goPage('logs')
└── Logout ──────────────────────────────── showView('login') + clears session token

Overview Page
├── Stat cards (Total / Allowed / Blocked) ── goPage('logs')
├── Stat card (Flagged Users) ──────────────── goPage('threats')
├── Log table rows ──────────────────────────── openLogModal(...)
├── "View All →" on logs ────────────────────── goPage('logs')
├── Suspicious user items ───────────────────── goPage('threats')
└── "View All →" on suspicious ──────────────── goPage('threats')

Live Activity Page
├── Feed rows ────────────────────────────────── openLogModal(...)
└── ⏸ Pause / ▶ Resume ──────────────────────── toggles livePaused boolean

Users & Roles Page
└── User cards ───────────────────────────────── openUserModal(...)
    ├── "Revoke Session" ─────────────────────── showToast('warn', ...)
    └── "View Logs →" ────────────────────────── goPage('logs') + pre-filters by user

Policies Page
└── Toggle switches ──────────────────────────── togglePolicy(i) + re-render + toast

Threat Detection Page
├── Threat event rows ────────────────────────── openThreatModal(...)
│   ├── "Block User" ─────────────────────────── showToast('danger', ...)
│   └── "Inspect Logs →" ─────────────────────── goPage('logs') + pre-filters by user
└── "⚠ Broadcast Alert" ─────────────────────── showToast('danger', ...)

Audit Logs Page
├── Status / User / Call Type dropdowns ──────── re-filters table on change
├── Search input ──────────────────────────────── re-filters on every keystroke
├── Clear button ──────────────────────────────── resets all 4 filters + re-renders
├── Table rows ────────────────────────────────── openLogModal(...)
├── Pagination buttons (← 1 2 3 →) ──────────── switches page + re-renders
└── "↓ Export CSV" ────────────────────────────── showToast('success', ...)
```

---

## ✨ Key Features

- **Zero-dependency SPA** — one HTML file, one CDN script. No npm, no webpack, no React
- **Client-side routing** — 6 navigable pages via CSS class toggling, no URL changes needed
- **Role-aware login** — 3 selectable roles, sets session state displayed throughout the app
- **Real-time live feed** — auto-updating syscall stream via the Flask backend, with pause/resume control
- **CRT Terminal Aesthetic** — high-contrast dashboard with scanline effect and status-driven terminal colors (Green/Red)
- **Animated new rows** — each new feed entry slides in with a `slideIn` CSS keyframe
- **Interactive charts** — Chart.js line chart (activity timeline) + donut chart (distribution)
- **Full filtering system** — 4 independent filters + free-text search, all working simultaneously
- **Paginated log table** — 8 entries per page, dynamic pagination buttons, entry count display
- **Deep-link navigation** — modals can navigate to another page with pre-applied filters (e.g. "View Logs" from user modal pre-sets the user filter)
- **Policy toggles** — pure CSS toggle switches that actually modify in-memory state and re-render the list
- **3-type modal system** — log detail, user detail, threat detail — all share one overlay DOM element
- **Toast stack** — multiple toasts can be queued, each auto-dismisses after 3s with fade-out
- **CSS design token system** — all colors, radii, shadows, and fonts controlled from `:root`
- **Pulsing live indicator** — animated green dot on navbar signals the gateway is active

---

---

## 🔮 Future Work

- [ ] Connect all pages to live backend REST APIs (Flask/FastAPI) via `fetch()`
- [ ] Replace simulated feed with WebSocket for true real-time updates
- [ ] Dark mode toggle — CSS tokens make this a single class swap on `<html>`
- [ ] Export audit logs as real CSV download
- [ ] Responsive mobile layout with sidebar collapse
- [ ] Loading skeletons for API fetch states
- [ ] Persist filter state in `sessionStorage` across page navigations

---

*Frontend built by **Akhil** · SecureGate Project*
