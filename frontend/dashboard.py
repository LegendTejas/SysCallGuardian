"""
SysCallGuardian — Plotly Dash Monitoring Dashboard

Run:
    pip install dash plotly pandas
    python dashboard.py
    → open http://127.0.0.1:8050
"""

import random
import datetime
import dash
from dash import dcc, html, Input, Output, dash_table
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
import numpy as np

# ─────────────────────────────────────────────
#  MOCK DATA GENERATION
# ─────────────────────────────────────────────

random.seed(42)
np.random.seed(42)

USERS = [
    "admin",
    "dev_raj",
    "dev_priya",
    "guest_x7",
    "intern_k",
    "tejas",
    "vanshika",
    "Akhil",
]
ROLES = {
    "admin": "Admin",
    "dev_raj": "Developer",
    "dev_priya": "Developer",
    "guest_x7": "Guest",
    "intern_k": "Guest",
    "tejas": "Admin",
    "vanshika": "Developer",
    "Akhil": "Devloper",
}
SYSCALLS = [
    "file_read",
    "file_write",
    "exec_proc",
    "net_socket",
    "dir_list",
    "mmap",
    "fork",
    "chroot",
    "ptrace",
]
STATUSES = ["allowed", "blocked", "suspicious"]
STATUS_PROB = [0.76, 0.15, 0.09]
PATHS = [
    "/var/log/app.log",
    "/etc/passwd",
    "/bin/sh",
    "/home/dev_raj/src",
    "/tmp/cache.db",
    "/sys/kernel",
    "0.0.0.0:4444",
    "/usr/bin/python3",
    "/var/www/html",
    "/etc/shadow",
    "/proc/mem",
    "/usr/local/bin",
]


def make_logs(n=300):
    now = datetime.datetime.now()
    rows = []
    for i in range(n):
        ts = now - datetime.timedelta(hours=11) + datetime.timedelta(seconds=i * 132)
        usr = random.choice(USERS)
        call = random.choice(SYSCALLS)
        # guests are more likely to be blocked
        if ROLES[usr] == "Guest":
            st = random.choices(STATUSES, weights=[0.45, 0.40, 0.15])[0]
        elif usr == "dev_priya":
            st = random.choices(STATUSES, weights=[0.60, 0.20, 0.20])[0]
        else:
            st = random.choices(STATUSES, weights=[0.88, 0.08, 0.04])[0]
        rows.append(
            {
                "timestamp": ts.strftime("%H:%M:%S"),
                "datetime": ts,
                "user": usr,
                "role": ROLES[usr],
                "syscall": call,
                "path": random.choice(PATHS),
                "status": st,
                "pid": random.randint(1000, 9999),
                "risk_delta": random.randint(0, 15) if st != "allowed" else 0,
            }
        )
    return pd.DataFrame(rows)


def make_hourly(df):
    df2 = df.copy()
    df2["hour"] = df2["datetime"].dt.strftime("%H:00")
    grp = df2.groupby(["hour", "status"]).size().reset_index(name="count")
    return grp


def make_risk_scores():
    return {
        "guest_x7": 87,
        "dev_priya": 54,
        "intern_k": 28,
        "dev_raj": 12,
        "vanshika": 8,
        "tejas": 4,
        "Akhil": 1,
        "admin": 0,
    }


df = make_logs(300)
hourly = make_hourly(df)
risks = make_risk_scores()

# ─────────────────────────────────────────────
#  COLOUR PALETTE  (matches SysCallGuardian CSS)
# ─────────────────────────────────────────────
C_GREEN = "#2D9E6F"
C_RED = "#C0392B"
C_AMBER = "#E6960A"
C_BLUE = "#1A5C9C"
C_BG = "#F8F7F4"
C_SURFACE = "#FFFFFF"
C_BORDER = "#E4E2DC"
C_TEXT = "#1A1916"
C_TEXT2 = "#6B6862"
C_TEXT3 = "#9E9B95"
C_DARK = "#0F2D1F"

STATUS_COLORS = {"allowed": C_GREEN, "blocked": C_RED, "suspicious": C_AMBER}

PLOTLY_LAYOUT = dict(
    paper_bgcolor=C_SURFACE,
    plot_bgcolor=C_SURFACE,
    font=dict(family="DM Sans, sans-serif", color=C_TEXT, size=12),
    margin=dict(l=16, r=16, t=40, b=16),
    height=280,  # Reduced from default (~450)
    legend=dict(
        bgcolor="rgba(0,0,0,0)", borderwidth=0, font=dict(size=11, color=C_TEXT2)
    ),
    xaxis=dict(
        gridcolor="#F0EEE8", linecolor=C_BORDER, tickfont=dict(size=10, color=C_TEXT3)
    ),
    yaxis=dict(
        gridcolor="#F0EEE8", linecolor=C_BORDER, tickfont=dict(size=10, color=C_TEXT3)
    ),
)

# ─────────────────────────────────────────────
#  CHART BUILDERS
# ─────────────────────────────────────────────


def chart_line_activity():
    """Line chart — Allowed vs Blocked vs Suspicious over 12 hours."""
    pivot = (
        hourly.pivot(index="hour", columns="status", values="count")
        .fillna(0)
        .reset_index()
    )
    for col in ["allowed", "blocked", "suspicious"]:
        if col not in pivot.columns:
            pivot[col] = 0

    fig = go.Figure()
    fig.add_trace(
        go.Scatter(
            x=pivot["hour"],
            y=pivot["allowed"],
            name="Allowed",
            mode="lines",
            fill="tozeroy",
            line=dict(color=C_GREEN, width=2),
            fillcolor="rgba(45,158,111,0.08)",
        )
    )
    fig.add_trace(
        go.Scatter(
            x=pivot["hour"],
            y=pivot["blocked"],
            name="Blocked",
            mode="lines",
            fill="tozeroy",
            line=dict(color=C_RED, width=2),
            fillcolor="rgba(192,57,43,0.07)",
        )
    )
    fig.add_trace(
        go.Scatter(
            x=pivot["hour"],
            y=pivot["suspicious"],
            name="Suspicious",
            mode="lines",
            fill="tozeroy",
            line=dict(color=C_AMBER, width=2, dash="dot"),
            fillcolor="rgba(230,150,10,0.06)",
        )
    )
    fig.update_layout(**PLOTLY_LAYOUT)
    fig.update_layout(
        title=dict(
            text="Syscall Activity — Last 12 Hours",
            font=dict(size=13, color=C_TEXT),
            x=0,
            xref="paper",
        ),
        hovermode="x unified",
    )
    return fig


def chart_donut_distribution():
    """Donut chart — call decision distribution."""
    counts = df["status"].value_counts()
    fig = go.Figure(
        go.Pie(
            labels=[s.capitalize() for s in counts.index],
            values=counts.values,
            hole=0.70,
            marker=dict(
                colors=[STATUS_COLORS.get(s, C_BLUE) for s in counts.index],
                line=dict(color=C_SURFACE, width=2),
            ),
            textinfo="label+percent",
            textfont=dict(size=11, color=C_TEXT),
            hovertemplate="%{label}: %{value} calls<extra></extra>",
        )
    )
    fig.update_layout(**PLOTLY_LAYOUT)
    fig.update_layout(
        title=dict(
            text="Call Distribution",
            font=dict(size=13, color=C_TEXT),
            x=0,
            xref="paper",
        ),
        showlegend=True,
        legend=dict(orientation="h", x=0.5, xanchor="center", y=-0.08),
    )
    # centre annotation
    total = int(counts.sum())
    fig.add_annotation(
        text=f"<b>{total:,}</b><br><span style='font-size:10px;color:{C_TEXT3}'>total</span>",
        x=0.5,
        y=0.5,
        showarrow=False,
        font=dict(size=15, color=C_TEXT),
        xref="paper",
        yref="paper",
        align="center",
    )
    return fig


def chart_bar_syscalls():
    """Grouped bar chart — syscall types by status."""
    grp = df.groupby(["syscall", "status"]).size().reset_index(name="count")
    fig = go.Figure()
    for status, color in STATUS_COLORS.items():
        sub = grp[grp["status"] == status]
        fig.add_trace(
            go.Bar(
                x=sub["syscall"],
                y=sub["count"],
                name=status.capitalize(),
                marker_color=color,
                marker_line_width=0,
            )
        )
    fig.update_layout(**PLOTLY_LAYOUT)
    fig.update_layout(
        title=dict(
            text="Syscall Types by Decision",
            font=dict(size=13, color=C_TEXT),
            x=0,
            xref="paper",
        ),
        barmode="group",
        bargap=0.25,
        bargroupgap=0.06,
    )
    return fig


def chart_heatmap_user_call():
    """Heatmap — users × syscall types (call count intensity)."""
    pivot = df.groupby(["user", "syscall"]).size().unstack(fill_value=0)
    fig = go.Figure(
        go.Heatmap(
            z=pivot.values,
            x=list(pivot.columns),
            y=list(pivot.index),
            colorscale=[[0, "#F2F1ED"], [0.4, "#A8D5BE"], [1, C_DARK]],
            hovertemplate="User: %{y}<br>Syscall: %{x}<br>Count: %{z}<extra></extra>",
            showscale=True,
            colorbar=dict(thickness=10, tickfont=dict(size=10, color=C_TEXT3)),
        )
    )
    fig.update_layout(**PLOTLY_LAYOUT)
    fig.update_layout(
        title=dict(
            text="User × Syscall Heatmap",
            font=dict(size=13, color=C_TEXT),
            x=0,
            xref="paper",
        ),
        xaxis=dict(tickangle=-30, tickfont=dict(size=10, color=C_TEXT2)),
        yaxis=dict(tickfont=dict(size=10, color=C_TEXT2)),
    )
    return fig


def chart_bar_risk():
    """Horizontal bar chart — risk scores per user."""
    risk_df = pd.DataFrame(list(risks.items()), columns=["user", "score"]).sort_values(
        "score", ascending=True
    )
    colors = [
        C_RED if s >= 70 else C_AMBER if s >= 30 else C_GREEN for s in risk_df["score"]
    ]
    fig = go.Figure(
        go.Bar(
            x=risk_df["score"],
            y=risk_df["user"],
            orientation="h",
            marker=dict(color=colors, line=dict(width=0)),
            text=risk_df["score"],
            textposition="outside",
            textfont=dict(size=11, color=C_TEXT2),
            hovertemplate="<b>%{y}</b><br>Risk Score: %{x}<extra></extra>",
        )
    )
    fig.update_layout(**PLOTLY_LAYOUT)
    fig.update_layout(
        title=dict(
            text="User Risk Scores", font=dict(size=13, color=C_TEXT), x=0, xref="paper"
        ),
        xaxis=dict(range=[0, 110]),
    )
    # threshold line at 80
    fig.add_vline(
        x=80,
        line_dash="dash",
        line_color=C_RED,
        annotation_text="Block threshold (80)",
        annotation_font=dict(size=10, color=C_RED),
        annotation_position="top right",
    )
    return fig


def chart_pie_role():
    """Pie chart — syscall volume by role."""
    grp = df.groupby("role").size().reset_index(name="count")
    fig = go.Figure(
        go.Pie(
            labels=grp["role"],
            values=grp["count"],
            marker=dict(
                colors=[C_DARK, C_BLUE, C_GREEN], line=dict(color=C_SURFACE, width=2)
            ),
            textinfo="label+percent",
            textfont=dict(size=11, color=C_TEXT),
            hovertemplate="%{label}: %{value} calls<extra></extra>",
            pull=[0.04, 0, 0],
        )
    )
    fig.update_layout(**PLOTLY_LAYOUT)
    fig.update_layout(
        title=dict(
            text="Syscall Volume by Role",
            font=dict(size=13, color=C_TEXT),
            x=0,
            xref="paper",
        ),
        showlegend=True,
        legend=dict(orientation="h", x=0.5, xanchor="center", y=-0.08),
    )
    return fig


def chart_scatter_timeline():
    """Scatter plot — individual syscall events on a timeline, coloured by status."""
    sample = df.sample(min(200, len(df)), random_state=1).copy()
    sample["y_jitter"] = [
        USERS.index(u) + random.uniform(-0.3, 0.3) for u in sample["user"]
    ]
    fig = go.Figure()
    for status, color in STATUS_COLORS.items():
        sub = sample[sample["status"] == status]
        fig.add_trace(
            go.Scatter(
                x=sub["datetime"],
                y=sub["y_jitter"],
                mode="markers",
                name=status.capitalize(),
                marker=dict(color=color, size=6, opacity=0.75, line=dict(width=0)),
                text=sub["syscall"] + " · " + sub["user"],
                hovertemplate="<b>%{text}</b><br>%{x}<extra></extra>",
            )
        )
    fig.update_layout(**PLOTLY_LAYOUT)
    fig.update_layout(
        title=dict(
            text="Syscall Timeline by User",
            font=dict(size=13, color=C_TEXT),
            x=0,
            xref="paper",
        ),
        yaxis=dict(
            tickvals=list(range(len(USERS))),
            ticktext=USERS,
            tickfont=dict(size=10, color=C_TEXT2),
            gridcolor="#F0EEE8",
        ),
        xaxis=dict(tickfont=dict(size=10, color=C_TEXT3), gridcolor="#F0EEE8"),
    )
    return fig


# ─────────────────────────────────────────────
#  KPI HELPERS
# ─────────────────────────────────────────────


def kpi_card(
    label, value, sub, color=C_TEXT, bar_color=C_GREEN, pct=None, clickable_id=None
):
    bar = html.Div(
        style={
            "height": "3px",
            "borderRadius": "3px 3px 0 0",
            "background": bar_color,
            "marginBottom": "0",
        }
    )
    prog = []
    if pct is not None:
        prog = [
            html.Div(
                style={
                    "background": "#F0EEE8",
                    "height": "4px",
                    "borderRadius": "2px",
                    "marginTop": "10px",
                },
                children=[
                    html.Div(
                        style={
                            "width": f"{pct}%",
                            "background": bar_color,
                            "height": "100%",
                            "borderRadius": "2px",
                            "transition": "width .5s",
                        }
                    )
                ],
            )
        ]
    return html.Div(
        style={
            "background": C_SURFACE,
            "border": f"1px solid {C_BORDER}",
            "borderRadius": "14px",
            "padding": "18px 20px",
            "position": "relative",
            "overflow": "hidden",
            "cursor": "pointer" if clickable_id else "default",
            "transition": "box-shadow .15s, transform .15s",
            "flex": "1",
        },
        children=[
            bar,
            html.Div(
                label,
                style={
                    "fontSize": "11px",
                    "color": C_TEXT3,
                    "fontFamily": "JetBrains Mono, monospace",
                    "textTransform": "uppercase",
                    "letterSpacing": "0.6px",
                    "marginTop": "14px",
                    "marginBottom": "8px",
                },
            ),
            html.Div(
                str(value),
                style={
                    "fontSize": "30px",
                    "fontWeight": "300",
                    "color": color,
                    "letterSpacing": "-1px",
                    "lineHeight": "1",
                },
            ),
            html.Div(
                sub,
                style={
                    "fontSize": "11px",
                    "fontFamily": "JetBrains Mono, monospace",
                    "color": bar_color,
                    "marginTop": "6px",
                },
            ),
            *prog,
        ],
    )


# ─────────────────────────────────────────────
#  DASH APP
# ─────────────────────────────────────────────

app = dash.Dash(
    __name__,
    title="SysCallGuardian — Analytics Dashboard",
    meta_tags=[{"name": "viewport", "content": "width=device-width, initial-scale=1"}],
)

# ── inline CSS (no external stylesheet needed) ──
FONT_IMPORT = """
@import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@300;400;500;600&family=JetBrains+Mono:wght@400;500&display=swap');
* { box-sizing: border-box; }
body { background: #F8F7F4; margin: 0; font-family: 'DM Sans', sans-serif; color: #1A1916; }
::-webkit-scrollbar { width: 6px; }
::-webkit-scrollbar-thumb { background: #D0CEC6; border-radius: 3px; }
.dash-table-container .dash-spreadsheet-container .dash-spreadsheet-inner table {
    font-family: 'JetBrains Mono', monospace !important; font-size: 11px !important;
}
"""

app.index_string = f"""
<!DOCTYPE html>
<html>
  <head>
    {{%metas%}}
    <title>{{%title%}}</title>
    {{%favicon%}}
    {{%css%}}
    <style>{FONT_IMPORT}</style>
  </head>
  <body>
    {{%app_entry%}}
    <footer>{{%config%}}{{%scripts%}}{{%renderer%}}</footer>
  </body>
</html>
"""

# ─────────────────────────────────────────────
#  LAYOUT
# ─────────────────────────────────────────────

CARD = {
    "background": C_SURFACE,
    "border": f"1px solid {C_BORDER}",
    "borderRadius": "14px",
    "padding": "20px",
}

app.layout = html.Div(
    style={
        "background": C_BG,
        "minHeight": "100vh",
        "fontFamily": "'DM Sans', sans-serif",
    },
    children=[
        # ── TOP NAV ──
        html.Div(
            style={
                "background": C_SURFACE,
                "borderBottom": f"1px solid {C_BORDER}",
                "padding": "0 28px",
                "height": "56px",
                "display": "flex",
                "alignItems": "center",
                "justifyContent": "space-between",
                "position": "sticky",
                "top": "0",
                "zIndex": "100",
            },
            children=[
                html.Div(
                    style={"display": "flex", "alignItems": "center", "gap": "10px"},
                    children=[
                        html.Div(
                            style={
                                "width": "30px",
                                "height": "30px",
                                "background": C_DARK,
                                "borderRadius": "8px",
                                "display": "flex",
                                "alignItems": "center",
                                "justifyContent": "center",
                            },
                            children=html.Span("🛡️", style={"fontSize": "14px"}),
                        ),
                        html.Span(
                            "SysCallGuardian",
                            style={
                                "fontSize": "15px",
                                "fontWeight": "600",
                                "letterSpacing": "-0.3px",
                            },
                        ),
                        html.Span("·", style={"color": C_TEXT3, "margin": "0 4px"}),
                        html.Span(
                            "Analytics Dashboard",
                            style={
                                "fontSize": "12px",
                                "color": C_TEXT3,
                                "fontFamily": "JetBrains Mono, monospace",
                            },
                        ),
                    ],
                ),
                html.Div(
                    style={"display": "flex", "alignItems": "center", "gap": "20px"},
                    children=[
                        html.Div(
                            style={
                                "display": "flex",
                                "alignItems": "center",
                                "gap": "6px",
                                "fontSize": "12px",
                                "color": C_GREEN,
                                "fontFamily": "JetBrains Mono, monospace",
                            },
                            children=[
                                html.Div(
                                    id="live-dot",
                                    style={
                                        "width": "7px",
                                        "height": "7px",
                                        "background": C_GREEN,
                                        "borderRadius": "50%",
                                    },
                                ),
                                "GATEWAY ACTIVE · 3 NODES",
                            ],
                        ),
                        html.Div(
                            id="clock",
                            style={
                                "fontSize": "12px",
                                "color": C_TEXT3,
                                "fontFamily": "JetBrains Mono, monospace",
                                "background": C_BG,
                                "border": f"1px solid {C_BORDER}",
                                "padding": "4px 10px",
                                "borderRadius": "6px",
                            },
                        ),
                    ],
                ),
            ],
        ),
        # ── PAGE BODY ──
        html.Div(
            style={"padding": "28px 32px", "maxWidth": "1600px", "margin": "0 auto"},
            children=[
                # ── PAGE HEADER ──
                html.Div(
                    style={"marginBottom": "24px"},
                    children=[
                        html.H1(
                            "System Overview",
                            style={
                                "fontSize": "22px",
                                "fontWeight": "500",
                                "letterSpacing": "-0.4px",
                                "margin": "0",
                            },
                        ),
                        html.P(
                            "Real-time syscall analytics · RBAC monitoring · Threat analysis",
                            style={
                                "fontSize": "13px",
                                "color": C_TEXT2,
                                "marginTop": "4px",
                            },
                        ),
                    ],
                ),
                # ── FILTER BAR ──
                html.Div(
                    style={
                        **CARD,
                        "marginBottom": "20px",
                        "display": "flex",
                        "alignItems": "center",
                        "gap": "14px",
                        "flexWrap": "wrap",
                    },
                    children=[
                        html.Span(
                            "Filters:",
                            style={
                                "fontSize": "11px",
                                "fontFamily": "JetBrains Mono, monospace",
                                "color": C_TEXT3,
                                "textTransform": "uppercase",
                                "letterSpacing": "0.6px",
                            },
                        ),
                        dcc.Dropdown(
                            id="filter-user",
                            options=[{"label": "All Users", "value": "ALL"}]
                            + [{"label": u, "value": u} for u in USERS],
                            value="ALL",
                            clearable=False,
                            style={"width": "160px", "fontSize": "13px"},
                        ),
                        dcc.Dropdown(
                            id="filter-status",
                            options=[
                                {"label": "All Status", "value": "ALL"},
                                {"label": "Allowed", "value": "allowed"},
                                {"label": "Blocked", "value": "blocked"},
                                {"label": "Suspicious", "value": "suspicious"},
                            ],
                            value="ALL",
                            clearable=False,
                            style={"width": "150px", "fontSize": "13px"},
                        ),
                        dcc.Dropdown(
                            id="filter-syscall",
                            options=[{"label": "All Syscalls", "value": "ALL"}]
                            + [{"label": s, "value": s} for s in SYSCALLS],
                            value="ALL",
                            clearable=False,
                            style={"width": "160px", "fontSize": "13px"},
                        ),
                        dcc.Dropdown(
                            id="filter-role",
                            options=[
                                {"label": "All Roles", "value": "ALL"},
                                {"label": "Admin", "value": "Admin"},
                                {"label": "Developer", "value": "Developer"},
                                {"label": "Guest", "value": "Guest"},
                            ],
                            value="ALL",
                            clearable=False,
                            style={"width": "150px", "fontSize": "13px"},
                        ),
                        html.Div(
                            id="filter-count",
                            style={
                                "marginLeft": "auto",
                                "fontSize": "11px",
                                "fontFamily": "JetBrains Mono, monospace",
                                "color": C_TEXT3,
                            },
                        ),
                    ],
                ),
                # ── KPI ROW ──
                html.Div(
                    id="kpi-row",
                    style={"display": "flex", "gap": "14px", "marginBottom": "20px"},
                ),
                # ── ROW 1: Line + Donut ──
                html.Div(
                    style={
                        "display": "grid",
                        "gridTemplateColumns": "1.6fr 1fr",
                        "gap": "14px",
                        "marginBottom": "14px",
                    },
                    children=[
                        html.Div(
                            style=CARD,
                            children=[
                                dcc.Graph(
                                    id="chart-line", config={"displayModeBar": False}
                                )
                            ],
                        ),
                        html.Div(
                            style=CARD,
                            children=[
                                dcc.Graph(
                                    id="chart-donut", config={"displayModeBar": False}
                                )
                            ],
                        ),
                    ],
                ),
                # ── ROW 2: Bar syscalls + Heatmap ──
                html.Div(
                    style={
                        "display": "grid",
                        "gridTemplateColumns": "1fr 1fr",
                        "gap": "14px",
                        "marginBottom": "14px",
                    },
                    children=[
                        html.Div(
                            style=CARD,
                            children=[
                                dcc.Graph(
                                    id="chart-bar", config={"displayModeBar": False}
                                )
                            ],
                        ),
                        html.Div(
                            style=CARD,
                            children=[
                                dcc.Graph(
                                    id="chart-heatmap", config={"displayModeBar": False}
                                )
                            ],
                        ),
                    ],
                ),
                # ── ROW 3: Risk scores + Role pie ──
                html.Div(
                    style={
                        "display": "grid",
                        "gridTemplateColumns": "1.2fr 1fr",
                        "gap": "14px",
                        "marginBottom": "14px",
                    },
                    children=[
                        html.Div(
                            style=CARD,
                            children=[
                                dcc.Graph(
                                    id="chart-risk", config={"displayModeBar": False}
                                )
                            ],
                        ),
                        html.Div(
                            style=CARD,
                            children=[
                                dcc.Graph(
                                    id="chart-role-pie",
                                    config={"displayModeBar": False},
                                )
                            ],
                        ),
                    ],
                ),
                # ── ROW 4: Timeline scatter (full width) ──
                html.Div(
                    style={**CARD, "marginBottom": "14px"},
                    children=[
                        dcc.Graph(
                            id="chart-timeline", config={"displayModeBar": False}
                        ),
                    ],
                ),
                # ── ROW 5: Log Table ──
                html.Div(
                    style={
                        **CARD,
                        "padding": "0",
                        "overflow": "hidden",
                        "marginBottom": "32px",
                    },
                    children=[
                        html.Div(
                            style={
                                "padding": "16px 20px 12px",
                                "borderBottom": f"1px solid {C_BORDER}",
                                "display": "flex",
                                "justifyContent": "space-between",
                                "alignItems": "center",
                            },
                            children=[
                                html.Div(
                                    children=[
                                        html.Div(
                                            "Recent Syscall Logs",
                                            style={
                                                "fontSize": "14px",
                                                "fontWeight": "500",
                                            },
                                        ),
                                        html.Div(
                                            "latest 50 entries · filtered",
                                            style={
                                                "fontSize": "11px",
                                                "color": C_TEXT3,
                                                "fontFamily": "JetBrains Mono, monospace",
                                            },
                                        ),
                                    ]
                                ),
                                html.Span(
                                    "LIVE",
                                    style={
                                        "fontSize": "11px",
                                        "fontFamily": "JetBrains Mono, monospace",
                                        "padding": "3px 8px",
                                        "borderRadius": "100px",
                                        "background": "#E6F4EE",
                                        "color": C_GREEN,
                                        "fontWeight": "600",
                                    },
                                ),
                            ],
                        ),
                        html.Div(
                            style={"padding": "0 20px 16px"},
                            children=[
                                dash_table.DataTable(
                                    id="log-table",
                                    columns=[
                                        {"name": "User", "id": "user"},
                                        {"name": "Syscall", "id": "syscall"},
                                        {"name": "Path", "id": "path"},
                                        {"name": "Status", "id": "status"},
                                        {"name": "PID", "id": "pid"},
                                        {"name": "Time", "id": "timestamp"},
                                        {"name": "Role", "id": "role"},
                                    ],
                                    page_size=12,
                                    sort_action="native",
                                    filter_action="native",
                                    style_table={"overflowX": "auto"},
                                    style_header={
                                        "background": "#F2F1ED",
                                        "color": C_TEXT3,
                                        "fontFamily": "JetBrains Mono, monospace",
                                        "fontSize": "10px",
                                        "textTransform": "uppercase",
                                        "letterSpacing": "0.6px",
                                        "fontWeight": "600",
                                        "border": "none",
                                        "borderBottom": f"1px solid {C_BORDER}",
                                        "padding": "8px 12px",
                                    },
                                    style_cell={
                                        "fontFamily": "JetBrains Mono, monospace",
                                        "fontSize": "11px",
                                        "color": C_TEXT2,
                                        "padding": "9px 12px",
                                        "border": "none",
                                        "borderBottom": f"1px solid {C_BORDER}",
                                        "backgroundColor": C_SURFACE,
                                        "whiteSpace": "nowrap",
                                        "overflow": "hidden",
                                        "textOverflow": "ellipsis",
                                        "maxWidth": "180px",
                                    },
                                    style_data_conditional=[
                                        {
                                            "if": {
                                                "filter_query": '{status} = "allowed"',
                                                "column_id": "status",
                                            },
                                            "color": C_GREEN,
                                            "fontWeight": "600",
                                        },
                                        {
                                            "if": {
                                                "filter_query": '{status} = "blocked"',
                                                "column_id": "status",
                                            },
                                            "color": C_RED,
                                            "fontWeight": "600",
                                        },
                                        {
                                            "if": {
                                                "filter_query": '{status} = "suspicious"',
                                                "column_id": "status",
                                            },
                                            "color": C_AMBER,
                                            "fontWeight": "600",
                                        },
                                        {
                                            "if": {"row_index": "odd"},
                                            "backgroundColor": "#FAFAF8",
                                        },
                                    ],
                                    style_as_list_view=True,
                                ),
                            ],
                        ),
                    ],
                ),
            ],
        ),
        # interval for clock refresh
        dcc.Interval(id="interval", interval=1000, n_intervals=0),
    ],
)


# ─────────────────────────────────────────────
#  CALLBACKS
# ─────────────────────────────────────────────


def filter_df(user, status, syscall, role):
    """Apply all four dropdown filters to the main dataframe."""
    d = df.copy()
    if user != "ALL":
        d = d[d["user"] == user]
    if status != "ALL":
        d = d[d["status"] == status]
    if syscall != "ALL":
        d = d[d["syscall"] == syscall]
    if role != "ALL":
        d = d[d["role"] == role]
    return d


@app.callback(
    Output("clock", "children"),
    Input("interval", "n_intervals"),
)
def update_clock(_):
    return datetime.datetime.now().strftime("%H:%M:%S IST")


@app.callback(
    Output("kpi-row", "children"),
    Output("filter-count", "children"),
    Output("chart-line", "figure"),
    Output("chart-donut", "figure"),
    Output("chart-bar", "figure"),
    Output("chart-heatmap", "figure"),
    Output("chart-risk", "figure"),
    Output("chart-role-pie", "figure"),
    Output("chart-timeline", "figure"),
    Output("log-table", "data"),
    Input("filter-user", "value"),
    Input("filter-status", "value"),
    Input("filter-syscall", "value"),
    Input("filter-role", "value"),
)
def update_all(user, status, syscall, role):
    d = filter_df(user, status, syscall, role)

    # ── KPIs ──
    total = len(d)
    allowed = int((d["status"] == "allowed").sum())
    blocked = int((d["status"] == "blocked").sum())
    susp = int((d["status"] == "suspicious").sum())
    allow_pct = round(allowed / total * 100) if total else 0
    block_pct = round(blocked / total * 100) if total else 0

    kpis = [
        kpi_card(
            "Total Syscalls", f"{total:,}", f"↑ {total} in window", bar_color=C_BLUE
        ),
        kpi_card(
            "Allowed",
            f"{allowed:,}",
            f"{allow_pct}% pass rate",
            bar_color=C_GREEN,
            pct=allow_pct,
        ),
        kpi_card(
            "Blocked",
            f"{blocked:,}",
            f"{block_pct}% block rate",
            color=C_RED,
            bar_color=C_RED,
            pct=block_pct,
        ),
        kpi_card(
            "Suspicious",
            f"{susp:,}",
            f"{round(susp/total*100) if total else 0}% flagged",
            color=C_AMBER,
            bar_color=C_AMBER,
            pct=round(susp / total * 100) if total else 0,
        ),
    ]
    count_label = f"{total:,} entries matched"

    # ── Chart 1 — Line ──
    h = d.copy()
    h["hour"] = h["datetime"].dt.strftime("%H:00")
    hrly = h.groupby(["hour", "status"]).size().reset_index(name="count")
    pivot = (
        hrly.pivot(index="hour", columns="status", values="count")
        .fillna(0)
        .reset_index()
    )
    for col in ["allowed", "blocked", "suspicious"]:
        if col not in pivot.columns:
            pivot[col] = 0

    fig_line = go.Figure()
    fig_line.add_trace(
        go.Scatter(
            x=pivot["hour"],
            y=pivot["allowed"],
            name="Allowed",
            mode="lines",
            fill="tozeroy",
            line=dict(color=C_GREEN, width=2),
            fillcolor="rgba(45,158,111,0.08)",
        )
    )
    fig_line.add_trace(
        go.Scatter(
            x=pivot["hour"],
            y=pivot["blocked"],
            name="Blocked",
            mode="lines",
            fill="tozeroy",
            line=dict(color=C_RED, width=2),
            fillcolor="rgba(192,57,43,0.07)",
        )
    )
    fig_line.add_trace(
        go.Scatter(
            x=pivot["hour"],
            y=pivot["suspicious"],
            name="Suspicious",
            mode="lines",
            fill="tozeroy",
            line=dict(color=C_AMBER, width=2, dash="dot"),
            fillcolor="rgba(230,150,10,0.06)",
        )
    )
    fig_line.update_layout(**PLOTLY_LAYOUT)
    fig_line.update_layout(
        title=dict(
            text="Syscall Activity — Last 12 Hours",
            font=dict(size=13, color=C_TEXT),
            x=0,
            xref="paper",
        ),
        hovermode="x unified",
    )

    # ── Chart 2 — Donut ──
    counts = d["status"].value_counts()
    fig_donut = go.Figure(
        go.Pie(
            labels=[s.capitalize() for s in counts.index],
            values=counts.values,
            hole=0.70,
            marker=dict(
                colors=[STATUS_COLORS.get(s, C_BLUE) for s in counts.index],
                line=dict(color=C_SURFACE, width=2),
            ),
            textinfo="label+percent",
            textfont=dict(size=11, color=C_TEXT),
            hovertemplate="%{label}: %{value}<extra></extra>",
        )
    )
    fig_donut.update_layout(**PLOTLY_LAYOUT)
    fig_donut.update_layout(
        title=dict(
            text="Call Distribution",
            font=dict(size=13, color=C_TEXT),
            x=0,
            xref="paper",
        ),
        showlegend=True,
        legend=dict(orientation="h", x=0.5, xanchor="center", y=-0.08),
    )
    fig_donut.add_annotation(
        text=f"<b>{total:,}</b><br><span style='font-size:10px;color:{C_TEXT3}'>total</span>",
        x=0.5,
        y=0.5,
        showarrow=False,
        font=dict(size=15, color=C_TEXT),
        xref="paper",
        yref="paper",
        align="center",
    )

    # ── Chart 3 — Grouped Bar ──
    grp = d.groupby(["syscall", "status"]).size().reset_index(name="count")
    fig_bar = go.Figure()
    for st, color in STATUS_COLORS.items():
        sub = grp[grp["status"] == st]
        if not sub.empty:
            fig_bar.add_trace(
                go.Bar(
                    x=sub["syscall"],
                    y=sub["count"],
                    name=st.capitalize(),
                    marker_color=color,
                    marker_line_width=0,
                )
            )
    fig_bar.update_layout(**PLOTLY_LAYOUT)
    fig_bar.update_layout(
        title=dict(
            text="Syscall Types by Decision",
            font=dict(size=13, color=C_TEXT),
            x=0,
            xref="paper",
        ),
        barmode="group",
        bargap=0.25,
        bargroupgap=0.06,
    )

    # ── Chart 4 — Heatmap ──
    if len(d) > 0:
        pv = d.groupby(["user", "syscall"]).size().unstack(fill_value=0)
        fig_heat = go.Figure(
            go.Heatmap(
                z=pv.values,
                x=list(pv.columns),
                y=list(pv.index),
                colorscale=[[0, "#F2F1ED"], [0.4, "#A8D5BE"], [1, C_DARK]],
                hovertemplate="User: %{y}<br>Syscall: %{x}<br>Count: %{z}<extra></extra>",
                showscale=True,
                colorbar=dict(thickness=10, tickfont=dict(size=10, color=C_TEXT3)),
            )
        )
        fig_heat.update_layout(**PLOTLY_LAYOUT)
        fig_heat.update_layout(
            title=dict(
                text="User × Syscall Heatmap",
                font=dict(size=13, color=C_TEXT),
                x=0,
                xref="paper",
            ),
            xaxis=dict(tickangle=-30, tickfont=dict(size=10, color=C_TEXT2)),
            yaxis=dict(tickfont=dict(size=10, color=C_TEXT2)),
        )
    else:
        fig_heat = go.Figure()
        fig_heat.update_layout(
            **PLOTLY_LAYOUT, title=dict(text="User × Syscall Heatmap (no data)")
        )

    # ── Chart 5 — Risk Bars ──
    risk_df = pd.DataFrame(list(risks.items()), columns=["user", "score"])
    # filter to visible users
    if user != "ALL":
        risk_df = risk_df[risk_df["user"] == user]
    risk_df = risk_df.sort_values("score", ascending=True)
    bar_colors = [
        C_RED if s >= 70 else C_AMBER if s >= 30 else C_GREEN for s in risk_df["score"]
    ]
    fig_risk = go.Figure(
        go.Bar(
            x=risk_df["score"],
            y=risk_df["user"],
            orientation="h",
            marker=dict(color=bar_colors, line=dict(width=0)),
            text=risk_df["score"],
            textposition="outside",
            textfont=dict(size=11, color=C_TEXT2),
            hovertemplate="<b>%{y}</b><br>Risk: %{x}<extra></extra>",
        )
    )
    fig_risk.update_layout(**PLOTLY_LAYOUT)
    fig_risk.update_layout(
        title=dict(
            text="User Risk Scores", font=dict(size=13, color=C_TEXT), x=0, xref="paper"
        ),
        xaxis=dict(range=[0, 110]),
    )
    fig_risk.add_vline(
        x=80,
        line_dash="dash",
        line_color=C_RED,
        annotation_text="Block threshold (80)",
        annotation_font=dict(size=10, color=C_RED),
        annotation_position="top right",
    )

    # ── Chart 6 — Role Pie ──
    role_grp = d.groupby("role").size().reset_index(name="count")
    role_colors_map = {"Admin": C_DARK, "Developer": C_BLUE, "Guest": C_GREEN}
    fig_role = go.Figure(
        go.Pie(
            labels=role_grp["role"],
            values=role_grp["count"],
            marker=dict(
                colors=[role_colors_map.get(r, C_AMBER) for r in role_grp["role"]],
                line=dict(color=C_SURFACE, width=2),
            ),
            textinfo="label+percent",
            textfont=dict(size=11, color=C_TEXT),
            hovertemplate="%{label}: %{value}<extra></extra>",
            pull=[0.04 if r == "Guest" else 0 for r in role_grp["role"]],
        )
    )
    fig_role.update_layout(**PLOTLY_LAYOUT)
    fig_role.update_layout(
        title=dict(
            text="Syscall Volume by Role",
            font=dict(size=13, color=C_TEXT),
            x=0,
            xref="paper",
        ),
        showlegend=True,
        legend=dict(orientation="h", x=0.5, xanchor="center", y=-0.08),
    )

    # ── Chart 7 — Scatter Timeline ──
    sample = (
        d.sample(min(200, len(d)), random_state=1).copy() if len(d) > 0 else d.copy()
    )
    sample["y_jitter"] = [
        USERS.index(u) + random.uniform(-0.3, 0.3) for u in sample["user"]
    ]
    fig_scatter = go.Figure()
    for st, color in STATUS_COLORS.items():
        sub = sample[sample["status"] == st]
        if not sub.empty:
            fig_scatter.add_trace(
                go.Scatter(
                    x=sub["datetime"],
                    y=sub["y_jitter"],
                    mode="markers",
                    name=st.capitalize(),
                    marker=dict(color=color, size=6, opacity=0.75, line=dict(width=0)),
                    text=sub["syscall"] + " · " + sub["user"],
                    hovertemplate="<b>%{text}</b><br>%{x}<extra></extra>",
                )
            )
    fig_scatter.update_layout(**PLOTLY_LAYOUT)
    fig_scatter.update_layout(
        title=dict(
            text="Syscall Timeline by User",
            font=dict(size=13, color=C_TEXT),
            x=0,
            xref="paper",
        ),
        yaxis=dict(
            tickvals=list(range(len(USERS))),
            ticktext=USERS,
            tickfont=dict(size=10, color=C_TEXT2),
            gridcolor="#F0EEE8",
        ),
        xaxis=dict(tickfont=dict(size=10, color=C_TEXT3), gridcolor="#F0EEE8"),
    )

    # ── Log Table data ──
    table_data = (
        d.sort_values("datetime", ascending=False)
        .head(50)[["user", "syscall", "path", "status", "pid", "timestamp", "role"]]
        .to_dict("records")
    )

    return (
        kpis,
        count_label,
        fig_line,
        fig_donut,
        fig_bar,
        fig_heat,
        fig_risk,
        fig_role,
        fig_scatter,
        table_data,
    )


# ─────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────

if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=8050)
