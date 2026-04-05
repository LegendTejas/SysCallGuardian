/**
 * Chart.js initialization and update logic for the Unified Overview dashboard.
 */

let lineChartObj = null;
let donutChartObj = null;
let rolePieObj = null;
let syscallBarObj = null;
let riskBarObj = null;
let timelineChartObj = null;

const COLORS = {
  green: '#2D9E6F',
  red: '#C0392B',
  amber: '#E6960A',
  blue: '#1A5C9C',
  dark: '#0F2D1F',
  text3: '#9E9B95',
  border: '#F0EEE8'
};

/**
 * Main entry point to update all dashboard visualizations.
 * @param {Object} stats - Basic stats (total, allowed, etc)
 * @param {Array} activity - Hourly activity array
 * @param {Object} extended - Extended stats (heatmap, roles, risks, syscalls)
 */
function updateDashboardCharts(stats, activity, extended) {
  renderLineChart(activity);
  renderDonutChart(stats);
  renderRolePie(extended.role_dist);
  renderSyscallBars(extended.syscall_status);
  renderRiskBars(extended.user_risks);
  renderHTMLHeatmap(extended.heatmap);
  renderTimelineMarkers(extended.recent_logs || []); // We'll sample logs for timeline
}

/* ── LINE: ACTIVITY OVER TIME ── */
function renderLineChart(data) {
  const ctx = document.getElementById('lineChart')?.getContext('2d');
  if (!ctx) return;

  const labels = data.map(d => d.hour);
  const allowed = data.map(d => d.allowed);
  const blocked = data.map(d => d.blocked);

  if (lineChartObj) {
    lineChartObj.data.labels = labels;
    lineChartObj.data.datasets[0].data = allowed;
    lineChartObj.data.datasets[1].data = blocked;
    lineChartObj.update();
  } else {
    lineChartObj = new Chart(ctx, {
      type: 'line',
      data: {
        labels,
        datasets: [
          { label: 'Allowed', data: allowed, borderColor: COLORS.green, backgroundColor: 'rgba(45,158,111,0.08)', fill: true, tension: 0.4, pointRadius: 2, borderWidth: 2 },
          { label: 'Blocked', data: blocked, borderColor: COLORS.red, backgroundColor: 'rgba(192,57,43,0.06)', fill: true, tension: 0.4, pointRadius: 2, borderWidth: 1.5 }
        ]
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { display: true, labels: { font: { family: 'JetBrains Mono', size: 10 }, color: COLORS.text3, boxWidth: 10 } } },
        scales: {
          x: { grid: { color: COLORS.border }, ticks: { font: { family: 'JetBrains Mono', size: 9 }, color: COLORS.text3 } },
          y: { grid: { color: COLORS.border }, ticks: { font: { family: 'JetBrains Mono', size: 9 }, color: COLORS.text3 } }
        }
      }
    });
  }
}

/* ── DONUT: CALL DISTRIBUTION ── */
function renderDonutChart(stats) {
  const ctx = document.getElementById('donutChart')?.getContext('2d');
  if (!ctx) return;

  const data = [stats.allowed, stats.blocked, stats.flagged || 0];

  if (donutChartObj) {
    donutChartObj.data.datasets[0].data = data;
    donutChartObj.update();
  } else {
    donutChartObj = new Chart(ctx, {
      type: 'doughnut',
      data: {
        labels: ['Allowed', 'Blocked', 'Flagged'],
        datasets: [{ data, backgroundColor: [COLORS.green, COLORS.red, COLORS.amber], borderWidth: 0, hoverOffset: 4 }]
      },
      options: {
        responsive: true, maintainAspectRatio: false, cutout: '75%',
        plugins: { legend: { position: 'bottom', labels: { font: { family: 'JetBrains Mono', size: 10 }, color: COLORS.text3, boxWidth: 10 } } }
      }
    });
  }
}

/* ── PIE: VOLUME BY ROLE ── */
function renderRolePie(data) {
  const ctx = document.getElementById('rolePieChart')?.getContext('2d');
  if (!ctx) return;

  const labels = data.map(d => d.role.toUpperCase());
  const values = data.map(d => d.count);
  const palette = [COLORS.dark, COLORS.blue, COLORS.green, COLORS.amber];

  if (rolePieObj) {
    rolePieObj.data.labels = labels;
    rolePieObj.data.datasets[0].data = values;
    rolePieObj.update();
  } else {
    rolePieObj = new Chart(ctx, {
      type: 'pie',
      data: {
        labels,
        datasets: [{ data: values, backgroundColor: palette, borderWidth: 2, borderColor: '#fff' }]
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { position: 'right', labels: { font: { family: 'JetBrains Mono', size: 9 }, color: COLORS.text3, boxWidth: 10 } } }
      }
    });
  }
}

/* ── BARS: SYSCALL TYPE BY STATUS ── */
function renderSyscallBars(data) {
  const ctx = document.getElementById('syscallBarChart')?.getContext('2d');
  if (!ctx) return;

  // Pivot data for grouped bars
  const syscalls = [...new Set(data.map(d => d.call_type))].slice(0, 8); // Top 8
  const statuses = ['allowed', 'blocked', 'flagged'];
  
  const datasets = statuses.map((st, i) => ({
    label: st.charAt(0).toUpperCase() + st.slice(1),
    data: syscalls.map(sc => {
      const entry = data.find(d => d.call_type === sc && d.status === st);
      return entry ? entry.count : 0;
    }),
    backgroundColor: [COLORS.green, COLORS.red, COLORS.amber][i],
    borderRadius: 4
  }));

  if (syscallBarObj) {
    syscallBarObj.data.labels = syscalls;
    syscallBarObj.data.datasets = datasets;
    syscallBarObj.update();
  } else {
    syscallBarObj = new Chart(ctx, {
      type: 'bar',
      data: { labels: syscalls, datasets },
      options: {
        responsive: true, maintainAspectRatio: false,
        scales: {
          x: { grid: { display: false }, ticks: { font: { family: 'JetBrains Mono', size: 9 } } },
          y: { grid: { color: COLORS.border }, ticks: { font: { family: 'JetBrains Mono', size: 9 } } }
        },
        plugins: { legend: { labels: { boxWidth: 10, font: { size: 10 } } } }
      }
    });
  }
}

/* ── BARS: USER RISK SCORES (Horizontal) ── */
function renderRiskBars(data) {
  const ctx = document.getElementById('riskBarChart')?.getContext('2d');
  if (!ctx) return;

  const users = data.map(d => d.username).slice(0, 10);
  const scores = data.map(d => d.risk_score).slice(0, 10);
  const barColors = scores.map(s => s > 70 ? COLORS.red : (s > 30 ? COLORS.amber : COLORS.green));

  if (riskBarObj) {
    riskBarObj.data.labels = users;
    riskBarObj.data.datasets[0].data = scores;
    riskBarObj.data.datasets[0].backgroundColor = barColors;
    riskBarObj.update();
  } else {
    riskBarObj = new Chart(ctx, {
      type: 'bar',
      data: {
        labels: users,
        datasets: [{ label: 'Risk Score', data: scores, backgroundColor: barColors, borderRadius: 100, barThickness: 12 }]
      },
      options: {
        indexAxis: 'y',
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { display: false }, tooltip: { intersects: false } },
        scales: {
          x: { max: 100, grid: { color: COLORS.border }, ticks: { font: { family: 'JetBrains Mono', size: 9 } } },
          y: { grid: { display: false }, ticks: { font: { family: 'JetBrains Mono', size: 9 } } }
        }
      }
    });
  }
}

/* ── LINE: SYSCALL TIMELINE (CUMULATIVE) ── */
function renderTimelineMarkers(logs) {
  const ctx = document.getElementById('timelineChart')?.getContext('2d');
  if (!ctx) return;

  // Sort logs by timestamp ascending for cumulative logic
  const sortedLogs = [...logs].sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
  
  const statuses = ['allowed', 'blocked', 'flagged'];
  const datasets = statuses.map((st, i) => {
    let count = 0;
    const data = sortedLogs.map(l => {
      if (l.status === st) count++;
      return { x: new Date(l.timestamp).getTime(), y: count };
    });

    const colors = [COLORS.green, COLORS.red, COLORS.amber];
    return {
      label: st.charAt(0).toUpperCase() + st.slice(1),
      data: data,
      borderColor: colors[i],
      backgroundColor: colors[i] + '15', // subtle fill
      fill: true,
      stepped: true, // Step chart looks better for discrete event growth
      pointRadius: 0,
      borderWidth: 2
    };
  });

  if (timelineChartObj) {
    timelineChartObj.data.datasets = datasets;
    timelineChartObj.update();
  } else {
    timelineChartObj = new Chart(ctx, {
      type: 'line',
      data: { datasets },
      options: {
        responsive: true, maintainAspectRatio: false,
        scales: {
          x: { 
            type: 'linear', 
            position: 'bottom', 
            grid: { color: COLORS.border },
            ticks: { 
               display: false // keep it clean like the scatter was
            }
          },
          y: { 
            beginAtZero: true,
            grid: { color: COLORS.border },
            ticks: { font: { family: 'JetBrains Mono', size: 10 }, color: COLORS.text3 }
          }
        },
        plugins: { 
          legend: { position: 'top', labels: { boxWidth: 8, font: { size: 10 } } },
          tooltip: { mode: 'index', intersect: false }
        }
      }
    });
  }
}

/* ── HEATMAP: PURE HTML/CSS (COMPACT, NO SCROLL) ── */
function renderHTMLHeatmap(data) {
  const container = document.getElementById('heatmap-container');
  if (!container) return;

  // Cap to top 5 users and top 6 syscall types to guarantee no scrolling
  const allUsers    = [...new Set(data.map(d => d.username))].slice(0, 5);
  const allSyscalls = [...new Set(data.map(d => d.call_type))].slice(0, 6);

  if (allUsers.length === 0 || allSyscalls.length === 0) {
    container.innerHTML = '<div style="height:160px; display:flex; align-items:center; justify-content:center; color:var(--text3); font-size:12px; font-family:var(--mono);">No heatmap data</div>';
    return;
  }

  // Truncate long names to keep columns narrow
  const truncate = (s, n) => s.length > n ? s.slice(0, n) + '…' : s;

  let html = `<div class="heatmap-compact">`;

  // X-Axis labels (column headers)
  html += `<div class="heatmap-xaxis-compact">`;
  allSyscalls.forEach(sc => {
    html += `<div class="heatmap-x-label-compact" title="${sc}">${truncate(sc, 8)}</div>`;
  });
  html += `</div>`;

  // Data rows
  allUsers.forEach(u => {
    html += `<div class="heatmap-row-compact">`;
    html += `<div class="heatmap-label-compact" title="${u}">${truncate(u, 7)}</div>`;
    html += `<div class="heatmap-cells-compact">`;
    allSyscalls.forEach(sc => {
      const entry = data.find(d => d.username === u && d.call_type === sc);
      const val   = entry ? entry.count : 0;
      const level = val === 0 ? 0 : (val < 5 ? 1 : (val < 15 ? 2 : (val < 30 ? 3 : 4)));
      html += `<div class="heatmap-cell-compact" data-v="${level}"><div class="heatmap-tip">${u}·${sc}: ${val}</div></div>`;
    });
    html += `</div></div>`;
  });

  html += `</div>`;
  container.innerHTML = html;
}
