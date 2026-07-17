"""
PhishGuard X — Professional SOC Dashboard
Run with: streamlit run dashboard.py
"""

import sqlite3
import time
import os
import tempfile
import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
from datetime import datetime
from pathlib import Path

try:
    from reporter import ForensicReportGenerator
    REPORTER_ENGINE = ForensicReportGenerator()
    REPORTER_ONLINE = True
except Exception as e:
    REPORTER_ONLINE = False

st.set_page_config(
    page_title="PhishGuard X · SOC Dashboard",
    page_icon="shield",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');
html, body, [class*="css"] { font-family: 'Inter', sans-serif; }
.main .block-container { padding: 1.2rem 2rem 2rem 2rem; max-width: 1400px; }
[data-testid="stSidebar"] { background: linear-gradient(180deg, #0a0f1e 0%, #0d1321 100%); border-right: 1px solid #1e2d45; }
[data-testid="stSidebar"] * { color: #cbd5e1 !important; }
.stApp { background: #070b14; }
.pg-header { background: linear-gradient(135deg, #0d1321 0%, #111827 60%, #0d1a2e 100%); border: 1px solid #1e3a5f; border-radius: 14px; padding: 20px 28px; margin-bottom: 22px; display: flex; align-items: center; justify-content: space-between; }
.pg-title { font-size: 1.55rem; font-weight: 700; color: #f1f5f9; letter-spacing: -0.3px; }
.pg-subtitle { font-size: 0.78rem; color: #64748b; margin-top: 2px; letter-spacing: 0.5px; text-transform: uppercase; }
.pg-badge { background: #0f2744; border: 1px solid #1e4d8c; border-radius: 20px; padding: 5px 14px; font-size: 0.72rem; color: #60a5fa; font-weight: 600; letter-spacing: 0.5px; }
.pg-badge-red { background: #2d0a0a; border: 1px solid #7f1d1d; color: #f87171; }
.stat-card { background: #0d1321; border: 1px solid #1e2d45; border-radius: 12px; padding: 18px 20px; position: relative; overflow: hidden; }
.stat-card::before { content: ''; position: absolute; top: 0; left: 0; right: 0; height: 3px; border-radius: 12px 12px 0 0; }
.stat-card.blue::before  { background: linear-gradient(90deg, #3b82f6, #06b6d4); }
.stat-card.red::before   { background: linear-gradient(90deg, #ef4444, #f97316); }
.stat-card.amber::before { background: linear-gradient(90deg, #f59e0b, #eab308); }
.stat-card.green::before { background: linear-gradient(90deg, #22c55e, #10b981); }
.stat-card.purple::before{ background: linear-gradient(90deg, #8b5cf6, #6366f1); }
.stat-label { font-size: 0.7rem; font-weight: 600; color: #475569; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 6px; }
.stat-value { font-size: 2rem; font-weight: 700; color: #f1f5f9; line-height: 1; }
.stat-delta { font-size: 0.72rem; color: #64748b; margin-top: 5px; }
.stat-icon  { position: absolute; right: 16px; top: 50%; transform: translateY(-50%); font-size: 1.8rem; opacity: 0.12; }
.sec-label { font-size: 0.68rem; font-weight: 700; color: #475569; text-transform: uppercase; letter-spacing: 1.5px; margin-bottom: 10px; margin-top: 4px; display: flex; align-items: center; gap: 8px; }
.sec-label::after { content: ''; flex: 1; height: 1px; background: #1e2d45; }
.vbadge { display: inline-block; padding: 6px 20px; border-radius: 24px; font-size: 1rem; font-weight: 700; letter-spacing: 0.5px; }
.vbadge-PHISHING   { background: #450a0a; color: #fca5a5; border: 1.5px solid #ef4444; }
.vbadge-SUSPICIOUS { background: #431407; color: #fdba74; border: 1.5px solid #f97316; }
.vbadge-SAFE       { background: #052e16; color: #86efac; border: 1.5px solid #22c55e; }
.vbadge-UNKNOWN    { background: #1e2d45; color: #94a3b8; border: 1.5px solid #475569; }
.result-card { background: #0d1321; border: 1px solid #1e2d45; border-radius: 12px; padding: 20px 22px; margin-bottom: 14px; }
.result-card.danger { border-color: #7f1d1d; background: #0f0808; }
.result-card.warn   { border-color: #78350f; background: #0f0a04; }
.result-card.ok     { border-color: #14532d; background: #04100a; }
.log-terminal { background: #050a12; border: 1px solid #1e2d45; border-radius: 10px; padding: 14px 16px; font-family: 'JetBrains Mono', monospace; font-size: 0.75rem; color: #4ade80; max-height: 295px; overflow-y: auto; white-space: pre-wrap; line-height: 1.7; }
.pipeline-wrap { background: #050a12; border: 1px solid #1e2d45; border-radius: 10px; padding: 14px 16px; }
.pipe-step { display: flex; align-items: center; gap: 10px; padding: 5px 0; font-family: 'JetBrains Mono', monospace; font-size: 0.74rem; color: #334155; border-bottom: 1px solid #0d1829; }
.pipe-step:last-child { border-bottom: none; }
.pipe-step.done   { color: #4ade80; }
.pipe-step.active { color: #fbbf24; }
.pipe-dot { width: 7px; height: 7px; border-radius: 50%; flex-shrink: 0; }
.pipe-dot.done   { background: #4ade80; box-shadow: 0 0 6px #4ade8066; }
.pipe-dot.active { background: #fbbf24; box-shadow: 0 0 6px #fbbf2466; }
.pipe-dot.idle   { background: #1e2d45; }
.ftag { display: inline-block; background: #2d0a0a; color: #fca5a5; border: 1px solid #7f1d1d; border-radius: 6px; padding: 3px 10px; font-size: 0.73rem; margin: 3px 3px 3px 0; }
.whois-new { background:#2d0a0a;color:#fca5a5;border:1px solid #ef4444;border-radius:8px;padding:8px 14px;font-size:0.8rem; }
.whois-mid { background:#1c1003;color:#fdba74;border:1px solid #f97316;border-radius:8px;padding:8px 14px;font-size:0.8rem; }
.whois-old { background:#052e16;color:#86efac;border:1px solid #22c55e;border-radius:8px;padding:8px 14px;font-size:0.8rem; }
.camp-alert { background: #150202; border: 1px solid #7f1d1d; border-left: 4px solid #ef4444; border-radius: 10px; padding: 14px 18px; margin-bottom: 12px; }
.camp-domain { font-size: 1rem; font-weight: 700; color: #fca5a5; }
.camp-count  { font-size: 0.78rem; color: #94a3b8; margin-top: 2px; }
.qr-box { background: #0a1628; border: 1px solid #1e3a5f; border-left: 4px solid #3b82f6; border-radius: 10px; padding: 12px 16px; font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; color: #93c5fd; margin-bottom: 14px; }
hr { border-color: #1e2d45 !important; }
::-webkit-scrollbar { width: 5px; height: 5px; }
::-webkit-scrollbar-track { background: #050a12; }
::-webkit-scrollbar-thumb { background: #1e3a5f; border-radius: 4px; }
.stTabs [data-baseweb="tab-list"] { background: #0d1321; border-radius: 10px; border: 1px solid #1e2d45; gap: 4px; padding: 4px; }
.stTabs [data-baseweb="tab"] { background: transparent !important; border-radius: 8px !important; color: #64748b !important; font-size: 0.82rem !important; font-weight: 500 !important; }
.stTabs [aria-selected="true"] { background: #1e3a5f !important; color: #93c5fd !important; }
.stButton > button[kind="primary"] { background: linear-gradient(135deg, #1d4ed8, #1e40af) !important; border: none !important; border-radius: 8px !important; font-weight: 600 !important; font-size: 0.85rem !important; }
</style>
""", unsafe_allow_html=True)

# ── Backend ──
try:
    from analyzer import analyze_url, analyze_email, analyze_sms, analyze_file
    from qr_scanner import scan_qr_for_phishing
    BACKEND_ONLINE = True
    BACKEND_ERROR  = ""
except Exception as e:
    BACKEND_ONLINE = False
    BACKEND_ERROR  = str(e)

DB_NAME = "campaigns.db"

# FIX 1: Override DB_NAME with the absolute path from campaign_detector so that
# dashboard.py, analyzer.py, and campaign_detector.py all open the exact same file,
# regardless of the working directory Streamlit is launched from.
try:
    from campaign_detector import DB_NAME as _CD_DB_NAME
    DB_NAME = _CD_DB_NAME
except Exception:
    pass

# ── Session state init ──
# FIX: Added scan_id to track which scan the stored result belongs to.
# pdf_bytes and pdf_filename are now keyed to scan_id to prevent cross-scan bleed.
if "last_result"  not in st.session_state: st.session_state["last_result"]  = None
if "pdf_bytes"    not in st.session_state: st.session_state["pdf_bytes"]    = None
if "pdf_filename" not in st.session_state: st.session_state["pdf_filename"] = None
if "scan_id"      not in st.session_state: st.session_state["scan_id"]      = None  # FIX
if "pdf_scan_id"  not in st.session_state: st.session_state["pdf_scan_id"]  = None  # FIX

def get_scan_history(limit=300):
    try:
        conn = sqlite3.connect(DB_NAME)
        df = pd.read_sql_query("SELECT domain, url, verdict, timestamp FROM urls ORDER BY id DESC LIMIT ?", conn, params=(limit,))
        conn.close()
        return df
    except:
        return pd.DataFrame(columns=["domain","url","verdict","timestamp"])

def get_campaign_data():
    try:
        conn = sqlite3.connect(DB_NAME)
        df = pd.read_sql_query("""SELECT domain, COUNT(*) as url_count,
            SUM(CASE WHEN verdict='PHISHING' THEN 1 ELSE 0 END) as phishing,
            SUM(CASE WHEN verdict='SUSPICIOUS' THEN 1 ELSE 0 END) as suspicious,
            SUM(CASE WHEN verdict='SAFE' THEN 1 ELSE 0 END) as safe
            FROM urls GROUP BY domain HAVING url_count >= 3 ORDER BY url_count DESC""", conn)
        conn.close()
        return df
    except:
        return pd.DataFrame()

CHART_COLORS = {"PHISHING":"#ef4444","SUSPICIOUS":"#f97316","SAFE":"#22c55e","UNKNOWN":"#64748b"}

def pie_chart(df):
    if df.empty: return None
    c = df["verdict"].value_counts().reset_index(); c.columns = ["verdict","count"]
    colors = [CHART_COLORS.get(v,"#64748b") for v in c["verdict"]]
    fig = go.Figure(go.Pie(labels=c["verdict"], values=c["count"],
        marker=dict(colors=colors, line=dict(color="#070b14",width=2)),
        hole=0.62, textinfo="percent", textfont=dict(size=11,color="#94a3b8"),
        hovertemplate="<b>%{label}</b><br>%{value} scans<extra></extra>"))
    fig.add_annotation(text=f"<b>{len(df)}</b><br><span style='font-size:10px'>Total</span>",
        x=0.5, y=0.5, font=dict(size=18,color="#f1f5f9"), showarrow=False)
    fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font_color="#94a3b8", margin=dict(t=10,b=10,l=10,r=10), height=260,
        legend=dict(font=dict(color="#64748b",size=11), bgcolor="rgba(0,0,0,0)"))
    return fig

def timeline_chart(df):
    if df.empty: return None
    df2 = df.copy(); df2["timestamp"] = pd.to_datetime(df2["timestamp"], errors="coerce")
    df2 = df2.dropna(subset=["timestamp"]); df2["date"] = df2["timestamp"].dt.date
    daily = df2.groupby(["date","verdict"]).size().reset_index(name="count")
    fig = px.bar(daily, x="date", y="count", color="verdict", color_discrete_map=CHART_COLORS, barmode="stack")
    fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font_color="#64748b", xaxis=dict(gridcolor="#0d1829",title=None,tickfont=dict(size=10)),
        yaxis=dict(gridcolor="#0d1829",title=None,tickfont=dict(size=10)),
        margin=dict(t=10,b=10,l=0,r=0), height=240,
        legend=dict(font=dict(color="#64748b",size=10),bgcolor="rgba(0,0,0,0)",orientation="h",x=0,y=1.08), bargap=0.25)
    return fig

def top_domains_chart(df):
    if df.empty: return None
    top = df.groupby("domain").size().reset_index(name="count").sort_values("count",ascending=True).tail(8)
    fig = go.Figure(go.Bar(x=top["count"], y=top["domain"], orientation="h",
        marker=dict(color=top["count"], colorscale=[[0,"#1e3a5f"],[0.5,"#1d4ed8"],[1,"#ef4444"]]),
        text=top["count"], textposition="outside", textfont=dict(color="#64748b",size=10)))
    fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font_color="#64748b", xaxis=dict(gridcolor="#0d1829",title=None,tickfont=dict(size=9)),
        yaxis=dict(title=None,tickfont=dict(size=9,color="#94a3b8")),
        margin=dict(t=10,b=10,l=10,r=30), height=240)
    return fig

def gauge_chart(score):
    color = "#22c55e" if score < 30 else ("#f97316" if score < 70 else "#ef4444")
    label = "SAFE" if score < 30 else ("SUSPICIOUS" if score < 70 else "PHISHING")
    fig = go.Figure(go.Indicator(mode="gauge+number", value=score,
        number=dict(font=dict(color=color,size=42,family="Inter")),
        gauge=dict(axis=dict(range=[0,100],tickcolor="#1e2d45",tickfont=dict(color="#334155",size=9)),
            bar=dict(color=color,thickness=0.22), bgcolor="#050a12",
            borderwidth=1, bordercolor="#1e2d45",
            steps=[dict(range=[0,30],color="#021a0e"),dict(range=[30,70],color="#1a0a00"),dict(range=[70,100],color="#1a0000")],
            threshold=dict(line=dict(color=color,width=2),thickness=0.7,value=score))))
    fig.add_annotation(text=label, x=0.5, y=0.25, font=dict(size=13,color=color,family="Inter"), showarrow=False)
    fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", font_color="#94a3b8", margin=dict(t=20,b=5,l=30,r=30), height=210)
    return fig

PIPELINE_STEPS = ["Input Sanitization","Redirect Chain Trace","Campaign Detection",
    "Trusted Domain Check","Rule-Based Scoring","Redirect Risk Scoring",
    "Content Body Analysis","ML Prediction","WHOIS Domain Age Check",
    "Hybrid Score Calculation","Database Persist","Attack Classification"]

def render_pipeline(done_count=0, active_idx=-1):
    rows = ""
    for i, step in enumerate(PIPELINE_STEPS):
        if i < done_count:   cls,dot,icon = "done","done","+"
        elif i==active_idx:  cls,dot,icon = "active","active","~"
        else:                cls,dot,icon = "","idle","-"
        rows += f'<div class="pipe-step {cls}"><div class="pipe-dot {dot}"></div><span style="color:#334155;margin-right:4px">{i+1:02d}</span>{icon}  {step}</div>'
    return f'<div class="pipeline-wrap">{rows}</div>'

def colorize_logs(logs):
    out = []
    for line in logs:
        if any(x in line for x in ["[!]","Error","Failed"]):
            out.append(f'<span style="color:#f87171">{line}</span>')
        elif any(x in line for x in ["[WHOIS]","[ML]","[Rules]","[Content]","[Redirects]"]):
            out.append(f'<span style="color:#60a5fa">{line}</span>')
        elif any(x in line for x in ["[+]"]):
            out.append(f'<span style="color:#4ade80">{line}</span>')
        elif "WARNING" in line or "SUSPICIOUS" in line:
            out.append(f'<span style="color:#fbbf24">{line}</span>')
        else:
            out.append(f'<span style="color:#475569">{line}</span>')
    return "\n".join(out)

# ── Sidebar ──
with st.sidebar:
    st.markdown('<div style="padding:16px 0 8px 0"><div style="font-size:1.15rem;font-weight:700;color:#f1f5f9">PhishGuard X</div><div style="font-size:0.7rem;color:#475569;margin-top:3px;text-transform:uppercase;letter-spacing:1px">SOC Analysis Platform</div></div>', unsafe_allow_html=True)
    st.divider()
    dot_color = "#4ade80" if BACKEND_ONLINE else "#f87171"
    status    = "Backend Online" if BACKEND_ONLINE else "Backend Offline"
    st.markdown(f'<div style="display:flex;align-items:center;gap:8px;font-size:0.78rem;color:{dot_color}"><div style="width:8px;height:8px;border-radius:50%;background:{dot_color};box-shadow:0 0 6px {dot_color}66"></div>{status}</div>', unsafe_allow_html=True)
    st.divider()
    page = st.radio("Nav", ["Threat Scanner","Analytics","Campaign Monitor"], label_visibility="collapsed")
    st.divider()
    df_s  = get_scan_history()
    total = len(df_s)
    phish = len(df_s[df_s["verdict"]=="PHISHING"])  if not df_s.empty else 0
    susp  = len(df_s[df_s["verdict"]=="SUSPICIOUS"]) if not df_s.empty else 0
    safe  = len(df_s[df_s["verdict"]=="SAFE"])       if not df_s.empty else 0
    threat_rate = round((phish+susp)/total*100,1) if total else 0
    st.markdown('<div style="font-size:0.68rem;font-weight:700;color:#334155;text-transform:uppercase;letter-spacing:1.5px;margin-bottom:10px">Live Stats</div>', unsafe_allow_html=True)
    for lbl, val, col in [("Total Scans",total,"#94a3b8"),("Phishing",phish,"#ef4444"),("Suspicious",susp,"#f97316"),("Safe",safe,"#22c55e"),("Threat Rate",f"{threat_rate}%","#ef4444" if threat_rate>50 else "#f97316" if threat_rate>20 else "#22c55e")]:
        st.markdown(f'<div style="display:flex;justify-content:space-between;padding:5px 0;border-bottom:1px solid #0d1829;font-size:0.8rem"><span style="color:#475569">{lbl}</span><span style="color:{col};font-weight:600">{val}</span></div>', unsafe_allow_html=True)
    st.markdown('<br><div style="font-size:0.65rem;color:#1e2d45;text-align:center">NFSU · Cybersecurity Minor Project<br>PhishGuard X v2.0</div>', unsafe_allow_html=True)

# ══════════ SCAN PAGE ══════════
if "Threat Scanner" in page:
    st.markdown('<div class="pg-header"><div><div class="pg-title">Threat Scanner</div><div class="pg-subtitle">Real-time phishing &amp; malicious URL detection</div></div><div class="pg-badge">Hybrid ML + Rules Engine v2.0</div></div>', unsafe_allow_html=True)
    if not BACKEND_ONLINE:
        st.error(f"Backend offline — {BACKEND_ERROR}"); st.stop()

    col_type, col_main = st.columns([1,3])
    with col_type:
        st.markdown('<div class="sec-label">Input Type</div>', unsafe_allow_html=True)
        scan_type = st.selectbox("Type",["URL","Email","SMS","File Path","QR Code Image"],label_visibility="collapsed")
    with col_main:
        st.markdown('<div class="sec-label">Target</div>', unsafe_allow_html=True)
        if scan_type == "QR Code Image":
            uploaded_qr = st.file_uploader("Upload QR Code Image", type=["png","jpg","jpeg","bmp"], label_visibility="collapsed")
            user_input = None
        else:
            hints = {"URL":"https://example.com","Email":"Paste full email here...","SMS":"Paste SMS message here...","File Path":"/path/to/file.txt"}
            user_input  = st.text_area("Input",placeholder=hints.get(scan_type,""),height=90,label_visibility="collapsed")
            uploaded_qr = None

    run_btn = st.button("Run Analysis", type="primary", use_container_width=True)

    if run_btn:
        has_input = (scan_type=="QR Code Image" and uploaded_qr) or (scan_type!="QR Code Image" and user_input and user_input.strip())
        if not has_input:
            st.warning("Please provide input.")
        else:
            # FIX: Generate a unique scan_id for this run BEFORE analysis.
            # This ID ties the result, the UI display, and the PDF together atomically.
            # Any leftover pdf_bytes from a prior scan is invalidated because pdf_scan_id won't match.
            new_scan_id = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
            st.session_state["scan_id"]      = new_scan_id
            st.session_state["last_result"]  = None   # FIX: Clear stale result immediately
            st.session_state["pdf_bytes"]    = None   # FIX: Clear stale PDF immediately
            st.session_state["pdf_filename"] = None
            st.session_state["pdf_scan_id"]  = None   # FIX: Invalidate any prior PDF

            st.markdown('<div class="sec-label" style="margin-top:18px">Execution Engine</div>', unsafe_allow_html=True)
            pipe_col, log_col = st.columns([1,1])
            with pipe_col: pipe_ph = st.empty()
            with log_col:  log_ph  = st.empty()

            for i in range(len(PIPELINE_STEPS)+1):
                pipe_ph.markdown(render_pipeline(done_count=i,active_idx=i), unsafe_allow_html=True)
                log_ph.markdown(f'<div class="log-terminal"><span style="color:#4ade80">[+] Analysis Started...</span>\n<span style="color:#60a5fa">[*] Running step {i+1}/{len(PIPELINE_STEPS)}...</span></div>', unsafe_allow_html=True)
                time.sleep(0.1)

            tmp_qr_path = None
            try:
                if scan_type == "URL":
                    result = analyze_url(user_input.strip())
                elif scan_type == "Email":
                    result = analyze_email(user_input.strip())
                elif scan_type == "SMS":
                    result = analyze_sms(user_input.strip())
                elif scan_type == "File Path":
                    result = analyze_file(user_input.strip())
                elif scan_type == "QR Code Image":
                    suffix = Path(uploaded_qr.name).suffix or ".png"
                    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp_file:
                        tmp_file.write(uploaded_qr.getvalue())
                        tmp_qr_path = tmp_file.name
                    result = scan_qr_for_phishing(tmp_qr_path)

                # FIX: Stamp the result with the scan_id so downstream rendering
                # can verify it's reading the correct result and not a stale one.
                result["_scan_id"] = new_scan_id

                # FIX: Write to session state ONCE, atomically, after analysis is done.
                # No st.rerun() — Streamlit will naturally re-render the rest of the
                # script in this same run, reading the freshly written session state.
                st.session_state["last_result"] = result

            except Exception as e:
                st.error(f"Analysis failed: {e}")
                st.session_state["last_result"] = None  # FIX: Don't leave stale result on failure
            finally:
                if tmp_qr_path and os.path.exists(tmp_qr_path):
                    try: os.remove(tmp_qr_path)
                    except: pass

    # FIX: Read result ONCE into a local variable for this entire render pass.
    # All downstream UI and PDF logic uses this local var — never re-reads session state mid-render.
    result = st.session_state.get("last_result")

    # FIX: Guard — only render results if the stored result belongs to the current scan_id.
    # This prevents a render race where session_state["last_result"] is from a previous scan
    # but scan_id has already been bumped.
    current_scan_id = st.session_state.get("scan_id")
    if result and result.get("_scan_id") != current_scan_id:
        result = None  # FIX: Mismatch — discard stale result, render nothing

    if result:
        st.markdown('<div class="sec-label" style="margin-top:18px">Execution Engine</div>', unsafe_allow_html=True)
        pipe_col2, log_col2 = st.columns([1,1])
        with pipe_col2:
            st.markdown(render_pipeline(done_count=len(PIPELINE_STEPS)), unsafe_allow_html=True)
        with log_col2:
            logs = result.get("logs",[])
            st.markdown(f'<div class="log-terminal">{colorize_logs(logs)}</div>', unsafe_allow_html=True)

        st.markdown("---")
        st.markdown('<div class="sec-label">Analysis Result</div>', unsafe_allow_html=True)

        verdict  = result.get("verdict","UNKNOWN"); score = result.get("score",0)
        conf     = result.get("confidence",0.0);   attack = result.get("attack_type","Unknown")
        age_days = result.get("domain_age_days");  created = result.get("domain_created","N/A")
        qr_url   = result.get("qr_decoded_url");   findings = result.get("findings",[])
        chain    = result.get("redirect_chain",[]); recs = result.get("recommendation",[])
        campaign = result.get("campaign",{});       simulation = result.get("simulation",[])
        card_cls = {"PHISHING":"danger","SUSPICIOUS":"warn","SAFE":"ok"}.get(verdict,"")

        if qr_url:
            st.markdown(f'<div class="qr-box">QR Decoded → <b>{qr_url}</b></div>', unsafe_allow_html=True)

        res_l, res_r = st.columns([1.4,1])
        with res_l:
            st.markdown(f'<div class="result-card {card_cls}"><div style="margin-bottom:14px"><div style="font-size:0.68rem;color:#475569;text-transform:uppercase;letter-spacing:1px;margin-bottom:6px">Verdict</div><span class="vbadge vbadge-{verdict}">{verdict}</span></div>', unsafe_allow_html=True)
            m1,m2,m3 = st.columns(3)
            m1.metric("Risk Score",f"{score}/100"); m2.metric("ML Confidence",f"{conf}%"); m3.metric("Attack Type",attack)
            if age_days is not None:
                cls2 = "whois-new" if age_days<30 else ("whois-mid" if age_days<180 else "whois-old")
                icon2 = "[HIGH]" if age_days<30 else ("[MED]" if age_days<180 else "[OK]")
                st.markdown(f'<div class="{cls2}" style="margin-top:10px">{icon2} <b>Domain Age:</b> {age_days} days &nbsp;·&nbsp; Registered: {created}</div>', unsafe_allow_html=True)
            if findings:
                st.markdown('<div style="margin-top:14px;font-size:0.68rem;color:#475569;text-transform:uppercase;letter-spacing:1px;margin-bottom:6px">Findings</div>', unsafe_allow_html=True)
                st.markdown("".join(f'<span class="ftag">! {f}</span>' for f in findings), unsafe_allow_html=True)
            if recs:
                st.markdown('<div style="margin-top:14px;font-size:0.68rem;color:#475569;text-transform:uppercase;letter-spacing:1px;margin-bottom:6px">Recommendations</div>', unsafe_allow_html=True)
                for r in recs:
                    st.markdown(f'<div style="font-size:0.8rem;color:#94a3b8;padding:3px 0">→ {r}</div>', unsafe_allow_html=True)
            st.markdown('</div>', unsafe_allow_html=True)

        with res_r:
            st.plotly_chart(gauge_chart(score), use_container_width=True, config={"displayModeBar":False})
            if simulation:
                st.markdown('<div style="font-size:0.68rem;color:#475569;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px">Attack Simulation</div>', unsafe_allow_html=True)
                for i_s,s in enumerate(simulation):
                    st.markdown(f'<div style="font-size:0.75rem;color:#64748b;padding:4px 0;border-bottom:1px solid #0d1829"><span style="color:#1e3a5f;margin-right:6px">{i_s+1}.</span>{s}</div>', unsafe_allow_html=True)

        if campaign.get("campaign_detected"):
            st.markdown(f'<div class="camp-alert"><div class="camp-domain">Coordinated Campaign Detected</div><div class="camp-count">{campaign.get("message","")}</div></div>', unsafe_allow_html=True)

        if chain:
            st.markdown('<div class="sec-label" style="margin-top:16px">Redirect Chain</div>', unsafe_allow_html=True)
            st.dataframe(pd.DataFrame(chain), use_container_width=True, hide_index=True)

        # ── PDF Report ──
        st.markdown("---")
        st.markdown('<div class="sec-label">Forensic Report</div>', unsafe_allow_html=True)

        if REPORTER_ONLINE:
            if st.button("Generate PDF Report", use_container_width=True, type="primary"):
                with st.spinner("Building forensic report..."):
                    try:
                        # FIX: Capture the result into a local variable at button-click time.
                        # Do NOT re-read st.session_state["last_result"] here — use the local
                        # `result` variable already bound at the top of this render pass.
                        # This guarantees the PDF is generated from the exact same data
                        # the UI is currently displaying, with no possibility of drift.
                        pdf_data = result  # already validated and bound above

                        pdf_path = REPORTER_ENGINE.generate(pdf_data)
                        with open(pdf_path, "rb") as f:
                            pdf_bytes = f.read()

                        # FIX: Store pdf_scan_id alongside pdf_bytes so the download button
                        # can verify the PDF matches the currently displayed scan.
                        st.session_state["pdf_bytes"]    = pdf_bytes
                        st.session_state["pdf_scan_id"]  = current_scan_id  # FIX
                        st.session_state["pdf_filename"] = f"PhishGuard_{pdf_data.get('verdict','SCAN')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
                        st.success("Report ready.")
                    except Exception as e:
                        st.error(f"Report generation failed: {e}")

            # FIX: Only show the download button if the stored PDF belongs to the current scan.
            # If the user runs a new scan, pdf_scan_id won't match current_scan_id,
            # so a stale PDF download button from the previous scan will never appear.
            if (st.session_state.get("pdf_bytes")
                    and st.session_state.get("pdf_scan_id") == current_scan_id):  # FIX
                st.download_button(
                    label="Download PDF Report",
                    data=st.session_state["pdf_bytes"],
                    file_name=f"PhishGuard_{datetime.now().strftime('%H%M%S_%f')}.pdf",
                    mime="application/pdf",
                    use_container_width=True,
                )
        else:
            st.warning("Reporter offline — check reporter.py installation.")

# ══════════ ANALYTICS PAGE ══════════
elif "Analytics" in page:
    st.markdown('<div class="pg-header"><div><div class="pg-title">Analytics Dashboard</div><div class="pg-subtitle">Historical scan data · threat trends · domain intelligence</div></div><div class="pg-badge">Live Data</div></div>', unsafe_allow_html=True)
    df = get_scan_history()
    if df.empty:
        st.info("No scan data yet. Run some scans first."); st.stop()
    total = len(df); phish = len(df[df["verdict"]=="PHISHING"]); susp = len(df[df["verdict"]=="SUSPICIOUS"]); safe = len(df[df["verdict"]=="SAFE"])
    threat_rate = round((phish+susp)/total*100,1) if total else 0

    def stat_card(label,value,delta,cls,icon):
        return f'<div class="stat-card {cls}"><div class="stat-label">{label}</div><div class="stat-value">{value}</div><div class="stat-delta">{delta}</div><div class="stat-icon">{icon}</div></div>'

    c1,c2,c3,c4,c5 = st.columns(5)
    with c1: st.markdown(stat_card("Total Scans",total,"All time","blue","[ ]"),unsafe_allow_html=True)
    with c2: st.markdown(stat_card("Phishing",phish,f"{round(phish/total*100,1)}% of scans","red","[!]"),unsafe_allow_html=True)
    with c3: st.markdown(stat_card("Suspicious",susp,f"{round(susp/total*100,1)}% of scans","amber","[~]"),unsafe_allow_html=True)
    with c4: st.markdown(stat_card("Safe",safe,f"{round(safe/total*100,1)}% of scans","green","[+]"),unsafe_allow_html=True)
    with c5: st.markdown(stat_card("Threat Rate",f"{threat_rate}%","Phishing + Suspicious","purple","[%]"),unsafe_allow_html=True)

    st.markdown("<br>",unsafe_allow_html=True)
    ch1,ch2,ch3 = st.columns([1,1.4,1.2])
    with ch1:
        st.markdown('<div class="sec-label">Verdict Distribution</div>',unsafe_allow_html=True)
        pie = pie_chart(df)
        if pie: st.plotly_chart(pie,use_container_width=True,config={"displayModeBar":False})
    with ch2:
        st.markdown('<div class="sec-label">Scan Timeline</div>',unsafe_allow_html=True)
        tl = timeline_chart(df)
        if tl: st.plotly_chart(tl,use_container_width=True,config={"displayModeBar":False})
    with ch3:
        st.markdown('<div class="sec-label">Top Domains Scanned</div>',unsafe_allow_html=True)
        td = top_domains_chart(df)
        if td: st.plotly_chart(td,use_container_width=True,config={"displayModeBar":False})

    st.divider()
    tab1,tab2 = st.tabs(["  Recent Scans  ","  Phishing Only  "])
    with tab1:
        d2 = df.head(100).copy()
        d2["verdict"] = d2["verdict"].map({"PHISHING":"[PHISHING]","SUSPICIOUS":"[SUSPICIOUS]","SAFE":"[SAFE]","UNKNOWN":"[UNKNOWN]"}).fillna(d2["verdict"])
        st.dataframe(d2,use_container_width=True,hide_index=True)
    with tab2:
        pf = df[df["verdict"]=="PHISHING"].copy()
        if pf.empty: st.info("No phishing URLs yet.")
        else: st.dataframe(pf,use_container_width=True,hide_index=True)

    st.divider()
    st.download_button("Export Scan History (CSV)", data=df.to_csv(index=False).encode("utf-8"),
        file_name=f"phishguard_{datetime.now().strftime('%Y%m%d_%H%M')}.csv", mime="text/csv")

# ══════════ CAMPAIGN PAGE ══════════
elif "Campaign Monitor" in page:
    st.markdown('<div class="pg-header"><div><div class="pg-title">Campaign Monitor</div><div class="pg-subtitle">Coordinated phishing campaign detection · domain intelligence</div></div><div class="pg-badge pg-badge-red">Active Threat Intel</div></div>', unsafe_allow_html=True)
    camp_df = get_campaign_data()
    if camp_df.empty:
        st.markdown('<div style="background:#0d1321;border:1px solid #1e2d45;border-radius:12px;padding:40px;text-align:center"><div style="font-size:2rem;margin-bottom:10px">[ ]</div><div style="font-size:0.9rem;color:#64748b">No active campaigns detected.</div><div style="font-size:0.75rem;color:#334155;margin-top:6px">Campaigns appear when the same domain is scanned 3+ times.</div></div>', unsafe_allow_html=True)
    else:
        st.markdown(f'<div class="camp-alert"><div class="camp-domain">{len(camp_df)} Active Phishing Campaign(s) Detected</div><div class="camp-count">These domains have been seen across 3+ different URLs</div></div>', unsafe_allow_html=True)
        for _,row in camp_df.iterrows():
            with st.expander(f"{row['domain']}   —   {row['url_count']} URLs"):
                mc1,mc2,mc3,mc4 = st.columns(4)
                mc1.metric("Total",int(row["url_count"])); mc2.metric("Phishing",int(row["phishing"])); mc3.metric("Suspicious",int(row["suspicious"])); mc4.metric("Safe",int(row["safe"]))
                try:
                    conn = sqlite3.connect(DB_NAME)
                    dom_df = pd.read_sql_query("SELECT url, verdict, timestamp FROM urls WHERE domain=? ORDER BY id DESC", conn, params=(row["domain"],))
                    conn.close()
                    if not dom_df.empty:
                        dom_df["verdict"] = dom_df["verdict"].map({"PHISHING":"[PHISHING]","SUSPICIOUS":"[SUSPICIOUS]","SAFE":"[SAFE]"}).fillna(dom_df["verdict"])
                        st.dataframe(dom_df,use_container_width=True,hide_index=True)
                except: pass
        st.divider()
        st.dataframe(camp_df,use_container_width=True,hide_index=True)