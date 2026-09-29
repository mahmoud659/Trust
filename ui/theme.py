"""
ui/theme.py
-----------
Global visual styling for the Streamlit app.

Custom HTML components (cards, verdict banners, pipeline) always set both
their background and text colour, so they stay readable even if a viewer
switches Streamlit to its dark theme.
"""

import streamlit as st

# Design tokens — keep colours in one place so components stay consistent.
COLORS = {
    "ink": "#0F172A",
    "ink_muted": "#475569",
    "ink_subtle": "#64748B",
    "line": "#E2E8F0",
    "surface": "#FFFFFF",
    "surface_alt": "#F8FAFC",
    "brand": "#1E3A8A",
    "brand_soft": "#EEF2FF",
    "pass": "#15803D",
    "pass_soft": "#F0FDF4",
    "warn": "#B45309",
    "warn_soft": "#FFFBEB",
    "fail": "#B91C1C",
    "fail_soft": "#FEF2F2",
    "skip": "#64748B",
    "skip_soft": "#F1F5F9",
    "sidebar": "#0B1220",
}

_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

html, body, [class*="css"], .stApp, .stMarkdown, button, input, textarea {
  font-family: 'Inter', system-ui, -apple-system, 'Segoe UI', sans-serif;
}
code, pre, .tc-mono { font-family: 'JetBrains Mono', ui-monospace, Consolas, monospace !important; }

/* Layout */
.block-container { padding-top: 2rem; padding-bottom: 4rem; max-width: 1240px; }
header[data-testid="stHeader"] { background: transparent; }

/* Sidebar */
section[data-testid="stSidebar"] { background: %(sidebar)s; }
section[data-testid="stSidebar"] * { color: #CBD5E1; }
section[data-testid="stSidebar"] hr { border-color: rgba(148,163,184,.18); }
section[data-testid="stSidebar"] .stButton > button { background: rgba(148,163,184,.10); border:1px solid rgba(148,163,184,.25); }
section[data-testid="stSidebar"] .stButton > button:hover { background: rgba(148,163,184,.18); border-color: rgba(148,163,184,.45); }
section[data-testid="stSidebar"] [role="radiogroup"] label {
  padding: .55rem .75rem; border-radius: 10px; margin-bottom: .25rem; width: 100%%;
  transition: background .15s ease;
}
section[data-testid="stSidebar"] [role="radiogroup"] label:hover { background: rgba(148,163,184,.10); }
section[data-testid="stSidebar"] [role="radiogroup"] label:has(input:checked) { background: rgba(99,102,241,.22); }
section[data-testid="stSidebar"] [role="radiogroup"] label p { font-size: .95rem; font-weight: 500; color: #E2E8F0; }

.tc-brand { display:flex; align-items:center; gap:.7rem; margin:.25rem 0 1.25rem; }
.tc-brand-mark { width:38px; height:38px; border-radius:10px; display:flex; align-items:center; justify-content:center;
  background: linear-gradient(135deg,#6366F1,#1E3A8A); box-shadow: 0 6px 18px rgba(79,70,229,.35); }
.tc-brand-name { font-weight:700; font-size:1.05rem; letter-spacing:.08em; color:#F8FAFC !important; }
.tc-brand-sub { font-size:.72rem; color:#94A3B8 !important; letter-spacing:.04em; }
.tc-side-label { font-size:.68rem; font-weight:600; letter-spacing:.12em; text-transform:uppercase; color:#64748B !important; margin:1rem 0 .5rem; }
.tc-status-row { display:flex; justify-content:space-between; align-items:center; padding:.45rem 0; font-size:.83rem; }
.tc-dot { display:inline-block; width:8px; height:8px; border-radius:50%%; margin-right:.45rem; }
.tc-user { display:flex; align-items:center; gap:.6rem; margin-bottom:.75rem; }
.tc-avatar { width:30px; height:30px; border-radius:50%%; background:#312E81; color:#E0E7FF !important; font-weight:700; font-size:.85rem;
  display:flex; align-items:center; justify-content:center; flex:0 0 30px; }
.tc-user-email { font-size:.83rem; color:#E2E8F0 !important; word-break:break-all; }
.tc-side-note { font-size:.76rem; line-height:1.5; color:#94A3B8 !important; background:rgba(148,163,184,.08);
  border:1px solid rgba(148,163,184,.14); border-radius:10px; padding:.75rem; }

/* Page header */
.tc-eyebrow { font-size:.72rem; font-weight:600; letter-spacing:.14em; text-transform:uppercase; color:%(brand)s; margin-bottom:.35rem; }
.tc-title { font-size:1.9rem; font-weight:700; color:%(ink)s; margin:0 0 .35rem; letter-spacing:-.01em; }
.tc-subtitle { font-size:1rem; color:%(ink_muted)s; max-width:760px; line-height:1.55; margin-bottom:1.5rem; }

.tc-section { display:flex; align-items:center; gap:.6rem; margin:1.75rem 0 .75rem; }
.tc-section-num { width:26px; height:26px; border-radius:8px; background:%(brand_soft)s; color:%(brand)s;
  font-size:.8rem; font-weight:700; display:flex; align-items:center; justify-content:center; }
.tc-section-title { font-size:1.08rem; font-weight:650; color:%(ink)s; }
.tc-section-hint { font-size:.85rem; color:%(ink_subtle)s; margin-left:auto; }

/* Bordered containers (st.container(border=True)) */
div[data-testid="stVerticalBlockBorderWrapper"] { border-radius:14px !important; border-color:%(line)s !important; background:%(surface)s; }

/* Buttons */
.stButton > button, .stDownloadButton > button { border-radius:10px; font-weight:600; padding:.6rem 1rem; }
.stButton > button[kind="primary"] { background:%(brand)s; border-color:%(brand)s; }
.stButton > button[kind="primary"]:hover { background:#1E40AF; border-color:#1E40AF; }

/* Tabs */
.stTabs [data-baseweb="tab-list"] { gap:.25rem; border-bottom:1px solid %(line)s; }
.stTabs [data-baseweb="tab"] { padding:.6rem 1rem; font-weight:500; }

/* Pipeline */
.tc-pipeline { display:grid; grid-template-columns:repeat(5,minmax(0,1fr)); gap:.6rem; margin:.5rem 0 1rem; }
.tc-step { border-radius:12px; padding:.85rem .9rem; border:1px solid %(line)s; background:%(surface)s; position:relative; }
.tc-step-top { display:flex; align-items:center; justify-content:space-between; margin-bottom:.45rem; }
.tc-step-idx { font-size:.68rem; font-weight:600; letter-spacing:.1em; color:%(ink_subtle)s; }
.tc-step-name { font-size:.9rem; font-weight:600; color:%(ink)s; }
.tc-step-state { font-size:.78rem; font-weight:600; margin-top:.2rem; }
.tc-badge { display:inline-flex; align-items:center; justify-content:center; width:22px; height:22px; border-radius:50%%;
  font-size:.75rem; font-weight:700; color:#fff; }
@media (max-width: 900px) { .tc-pipeline { grid-template-columns:repeat(2,minmax(0,1fr)); } }

/* Verdict */
.tc-verdict { border-radius:16px; padding:1.25rem 1.4rem; display:flex; gap:1.1rem; align-items:flex-start; border:1px solid; margin:.25rem 0 1rem; }
.tc-verdict-icon { width:48px; height:48px; flex:0 0 48px; border-radius:12px; display:flex; align-items:center; justify-content:center; color:#fff; font-size:1.4rem; font-weight:700; }
.tc-verdict-kicker { font-size:.72rem; font-weight:600; letter-spacing:.14em; text-transform:uppercase; }
.tc-verdict-title { font-size:1.45rem; font-weight:700; margin:.1rem 0 .35rem; }
.tc-verdict-reason { font-size:.92rem; line-height:1.5; }
.tc-verdict-sub { font-size:.82rem; margin-top:.5rem; opacity:.85; }

/* AI score gauge */
.tc-ai { border:1px solid %(line)s; border-radius:14px; padding:1.1rem 1.2rem; background:%(surface)s; color:%(ink)s; }
.tc-ai-head { display:flex; justify-content:space-between; align-items:baseline; margin-bottom:.9rem; gap:1rem; flex-wrap:wrap; }
.tc-ai-score { font-size:2.1rem; font-weight:700; line-height:1; }
.tc-ai-label { font-size:.8rem; font-weight:600; padding:.25rem .6rem; border-radius:999px; }
.tc-gauge { position:relative; height:12px; border-radius:999px;
  background: linear-gradient(90deg,#22C55E 0%%, #84CC16 35%%, #F59E0B 60%%, #EF4444 100%%); }
.tc-gauge-marker { position:absolute; top:-6px; width:4px; height:24px; background:%(ink)s; border-radius:2px; transform:translateX(-50%%);
  box-shadow:0 0 0 3px #fff; }
.tc-gauge-tick { position:absolute; top:16px; font-size:.7rem; color:%(ink_subtle)s; transform:translateX(-50%%); white-space:nowrap; }
.tc-gauge-tick::before { content:''; position:absolute; left:50%%; top:-18px; width:1px; height:14px; background:rgba(15,23,42,.35); }
.tc-gauge-scale { display:flex; justify-content:space-between; font-size:.72rem; color:%(ink_subtle)s; margin-top:1.6rem; }
.tc-ai-meta { display:flex; gap:1.5rem; flex-wrap:wrap; margin-top:.9rem; font-size:.8rem; color:%(ink_muted)s; }
.tc-ai-meta b { color:%(ink)s; font-weight:600; }

/* Key/value + hash blocks */
.tc-kv { display:grid; grid-template-columns: 150px 1fr; gap:.45rem 1rem; font-size:.86rem; color:%(ink)s; }
.tc-kv dt { color:%(ink_subtle)s; }
.tc-kv dd { margin:0; font-family:'JetBrains Mono',monospace; word-break:break-all; }
.tc-hash { font-family:'JetBrains Mono',monospace; font-size:.8rem; word-break:break-all; background:%(surface_alt)s; color:%(ink)s;
  border:1px solid %(line)s; border-radius:10px; padding:.6rem .75rem; }
.tc-hash-label { font-size:.75rem; font-weight:600; color:%(ink_subtle)s; margin:.2rem 0 .3rem; text-transform:uppercase; letter-spacing:.06em; }

/* Info callouts */
.tc-callout { border-radius:12px; padding:.9rem 1rem; font-size:.88rem; line-height:1.55; border:1px solid; }
.tc-callout-title { font-weight:650; margin-bottom:.25rem; }
.tc-callout code { background:rgba(15,23,42,.06); padding:.05rem .35rem; border-radius:5px; font-size:.8rem; }

/* Steps list (how it works) */
.tc-howto { list-style:none; padding:0; margin:0; counter-reset: step; }
.tc-howto li { counter-increment: step; position:relative; padding:.3rem 0 .6rem 2.2rem; font-size:.88rem; color:%(ink_muted)s; }
.tc-howto li b { color:%(ink)s; font-weight:600; }
.tc-howto li::before { content: counter(step); position:absolute; left:0; top:.25rem; width:1.5rem; height:1.5rem; border-radius:7px;
  background:%(brand_soft)s; color:%(brand)s; font-size:.75rem; font-weight:700; display:flex; align-items:center; justify-content:center; }

.tc-empty { border:1.5px dashed %(line)s; border-radius:14px; padding:2rem; text-align:center; color:%(ink_subtle)s; font-size:.92rem; background:%(surface_alt)s; }
</style>
"""


def inject_global_css() -> None:
    st.markdown(_CSS % COLORS, unsafe_allow_html=True)
