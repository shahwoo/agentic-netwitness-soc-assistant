# chroma db will store brief info produced from agents
# 

"""
SOC Platform v2
───────────────
• NetWitness API token import + automatic daily refresh
• Incidents list pulled from NetWitness REST API
• Chat interface stub (wire up LangChain here)
• ChromaDB integration for incident embeddings & semantic search
"""

import streamlit as st
import requests
import time
import json
import threading
from datetime import datetime, timedelta
from typing import Optional

# ── Optional deps (graceful fallback if not installed) ─────────────────────────
try:
    import chromadb
    from chromadb.config import Settings
    CHROMA_AVAILABLE = True
except ImportError:
    CHROMA_AVAILABLE = False

# ══════════════════════════════════════════════════════════════
# PAGE CONFIG
# ══════════════════════════════════════════════════════════════
st.set_page_config(
    page_title="SOC Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ══════════════════════════════════════════════════════════════
# GLOBAL CSS  — dark military terminal aesthetic
# ══════════════════════════════════════════════════════════════
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Barlow:wght@300;400;600;700&display=swap');

:root {
  --bg:        #04080F;
  --bg1:       #080F1A;
  --bg2:       #0C1624;
  --border:    #162840;
  --accent:    #00D4FF;
  --accent2:   #0AF0A0;
  --warn:      #FFB700;
  --danger:    #FF3B3B;
  --muted:     #3A607A;
  --text:      #B8D4E8;
  --mono:      'Share Tech Mono', monospace;
  --sans:      'Barlow', sans-serif;
}

html, body, [class*="css"] {
  font-family: var(--sans);
  background: var(--bg);
  color: var(--text);
}
.main { background: var(--bg); }

/* ── Sidebar ── */
section[data-testid="stSidebar"] {
  background: linear-gradient(180deg, #05090F 0%, #080F1A 100%);
  border-right: 1px solid var(--border);
}

/* ── Typography ── */
h1,h2,h3 { font-family: var(--mono); color: var(--accent); letter-spacing: 2px; }
h1 { font-size: 1.4rem !important; }
h3 { font-size: 0.95rem !important; }

/* ── Metrics ── */
[data-testid="metric-container"] {
  background: linear-gradient(135deg, var(--bg1) 0%, var(--bg2) 100%);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 12px 16px;
  box-shadow: 0 0 20px rgba(0,212,255,0.04);
}
[data-testid="metric-container"] label { color: var(--muted); font-size: 0.7rem; letter-spacing: 1.5px; font-family: var(--mono); }
[data-testid="metric-container"] [data-testid="stMetricValue"] { color: var(--accent); font-family: var(--mono); font-size: 1.4rem; }

/* ── Buttons ── */
.stButton > button {
  background: linear-gradient(90deg, #003650 0%, #00527A 100%);
  color: var(--accent);
  border: 1px solid #006699;
  border-radius: 4px;
  font-family: var(--mono);
  font-size: 0.75rem;
  letter-spacing: 1px;
  transition: all 0.15s;
}
.stButton > button:hover {
  background: linear-gradient(90deg, #00527A 0%, #006699 100%);
  box-shadow: 0 0 18px rgba(0,212,255,0.25);
  color: #fff;
  border-color: var(--accent);
}

/* ── Inputs ── */
.stTextInput > div > div > input,
.stTextArea textarea,
.stSelectbox > div > div {
  background: var(--bg1) !important;
  border: 1px solid var(--border) !important;
  color: var(--text) !important;
  border-radius: 4px;
  font-family: var(--sans);
}
.stTextInput > div > div > input:focus { border-color: var(--accent) !important; box-shadow: 0 0 8px rgba(0,212,255,0.2) !important; }

/* ── Tabs ── */
.stTabs [data-baseweb="tab-list"] { background: var(--bg1); border-bottom: 1px solid var(--border); }
.stTabs [data-baseweb="tab"] { font-family: var(--mono); font-size: 0.72rem; letter-spacing: 1.5px; color: var(--muted); border: none; }
.stTabs [aria-selected="true"] { color: var(--accent) !important; border-bottom: 2px solid var(--accent) !important; background: var(--bg2) !important; }

/* ── Cards ── */
.card {
  background: var(--bg1);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 14px 18px;
  margin: 6px 0;
  transition: border-color 0.15s;
}
.card:hover { border-color: var(--accent); }
.card-critical { border-left: 3px solid var(--danger) !important; }
.card-high     { border-left: 3px solid #FF7700 !important; }
.card-medium   { border-left: 3px solid var(--warn) !important; }
.card-low      { border-left: 3px solid var(--accent2) !important; }

/* ── Badges ── */
.badge { padding: 2px 9px; border-radius: 3px; font-family: var(--mono); font-size: 0.65rem; display:inline-block; }
.badge-critical { background:#2A0808; color:var(--danger); border:1px solid var(--danger); }
.badge-high     { background:#2A1500; color:#FF7700;       border:1px solid #FF7700; }
.badge-medium   { background:#1A1500; color:var(--warn);   border:1px solid var(--warn); }
.badge-low      { background:#001A10; color:var(--accent2);border:1px solid var(--accent2); }
.badge-info     { background:#001A2A; color:var(--accent); border:1px solid var(--accent); }

/* ── Chat bubbles ── */
.bubble-user {
  background: #0A1E30;
  border-left: 3px solid #005C8A;
  padding: 10px 14px; border-radius: 0 6px 6px 0;
  margin: 5px 0; font-size: 0.88rem;
}
.bubble-agent {
  background: #060F1A;
  border-left: 3px solid var(--accent);
  padding: 10px 14px; border-radius: 0 6px 6px 0;
  margin: 5px 0; font-size: 0.88rem;
}
.bubble-label { font-family: var(--mono); font-size: 0.6rem; letter-spacing: 2px; margin-bottom: 4px; color: var(--accent); }

/* ── Status indicators ── */
.dot { display:inline-block; width:7px; height:7px; border-radius:50%; margin-right:5px; }
.dot-green  { background: var(--accent2); box-shadow: 0 0 6px var(--accent2); animation: blink 2s infinite; }
.dot-red    { background: var(--danger);  box-shadow: 0 0 6px var(--danger); }
.dot-yellow { background: var(--warn);    box-shadow: 0 0 6px var(--warn); animation: blink 1s infinite; }
@keyframes blink { 0%,100%{opacity:1} 50%{opacity:.3} }

/* ── Token timer bar ── */
.timer-bar-wrap { background: var(--bg2); border-radius: 3px; height: 6px; width: 100%; margin: 6px 0; border: 1px solid var(--border); }
.timer-bar-fill { height: 100%; border-radius: 3px; transition: width 0.5s; }

/* ── Scrollbar ── */
::-webkit-scrollbar { width: 4px; }
::-webkit-scrollbar-track { background: var(--bg); }
::-webkit-scrollbar-thumb { background: #1A3A5C; border-radius: 2px; }

/* ── Section labels ── */
.sec-label {
  font-family: var(--mono); font-size: 0.6rem; color: var(--muted);
  letter-spacing: 3px; text-transform: uppercase; margin: 14px 0 6px;
}
hr { border-color: var(--border); margin: 1rem 0; }

/* ── ChromaDB panel ── */
.chroma-row {
  background: var(--bg2); border: 1px solid var(--border);
  border-radius: 4px; padding: 8px 12px; margin: 4px 0;
  font-family: var(--mono); font-size: 0.72rem;
}
</style>
""", unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════
# SESSION STATE
# ══════════════════════════════════════════════════════════════
DEFAULTS = {
    "nw_host":          "192.168.20.11",
    "nw_username":      "admin",
    "nw_password":      "NetWitness456$",
    "nw_token":         "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3Nzg2MDI5NDE5ODIsImlzcyI6InNlY3VyaXR5LXNlcnZlci02N2E0ZmZhMy1iYTYxLTRlMmEtYjY1Yi1mZjBiNzhjN2RhZWYiLCJpYXQiOjE3Nzg1NjY2NDE5ODIsImF1dGhvcml0aWVzIjpbIkFkbWluaXN0cmF0b3JzIl0sInVzZXJfbmFtZSI6ImFkbWluIn0.OTOMh2wx9FA5V2LTRry59cSqL3iy_lg1Lrn0FgKyWrytpn2R6R5xhm49cFsVfdu8OEgH502C1rC-xZiZAGC5zX5rP0OkOd2vSctruWEdDG9mVw5WyZd3YTPi4nU4ufkQJHFqh1yPgrLHeW5yrEKmBQLqoeY086tji9J0brQeso0pmwOE45TdxopPWu9yziSAFOxhqDrYvlBAeTtDX54LTRlkqJHtGvBpZAV6TrdkiB-fuIODLEAXMwcFXlK4zzc5a8k9KURSRMX8o0hkkPiHMrcyL1pXbaomEgESVP_UlDkPcmAPUeJbYvl-hXizZ55igqhV6fOcNIfFahuc66QsNA",
    "nw_token_expires": None,   # datetime
    "nw_connected":     False,
    "nw_status_msg":    "",
    "incidents":        [],
    "incidents_loaded": False,
    "chat_history":     [],     # [{role, content, ts}]
    "active_tab":       0,
    "chroma_client":    None,
    "chroma_collection":None,
    "chroma_status":    "",
    "search_results":   [],
}
for k, v in DEFAULTS.items():
    if k not in st.session_state:
        st.session_state[k] = v


# ══════════════════════════════════════════════════════════════
# NETWITNESS TOKEN HELPERS
# ══════════════════════════════════════════════════════════════
def nw_headers(token: str) -> dict:
    return {
        "NetWitness-Token": token,
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

def nw_authenticate() -> tuple[bool, str]:
    """
    Authenticate with username/password → get a fresh token.
    NetWitness REST: POST /rest/api/auth/userpass
    """
    host = st.session_state.nw_host.rstrip("/")
    if not host or not st.session_state.nw_username or not st.session_state.nw_password:
        return False, "Host, username and password are all required."
    try:
        resp = requests.post(
            f"{host}/rest/api/auth/userpass",
            json={
                "username": st.session_state.nw_username,
                "password": st.session_state.nw_password,
            },
            timeout=10,
            verify=False,
        )
        if resp.status_code in (200, 201):
            data = resp.json()
            token = data.get("accessToken") or data.get("token") or data.get("data", {}).get("token", "")
            if not token:
                return False, f"Auth succeeded but no token in response: {str(data)[:200]}"
            st.session_state.nw_token = token
            # Tokens expire in 24 h — store expiry with a 5-min safety buffer
            st.session_state.nw_token_expires = datetime.now() + timedelta(hours=23, minutes=55)
            st.session_state.nw_connected = True
            return True, "Authenticated — token valid for ~24 h"
        else:
            return False, f"HTTP {resp.status_code}: {resp.text[:200]}"
    except Exception as e:
        return False, f"Connection error: {e}"

def nw_import_token(raw_token: str) -> tuple[bool, str]:
    """
    Accept a manually pasted token; verify it with a lightweight call.
    """
    host = st.session_state.nw_host.rstrip("/")
    if not host or not raw_token.strip():
        return False, "Host and token are required."
    try:
        resp = requests.get(
            f"{host}/rest/api/version",
            headers=nw_headers(raw_token.strip()),
            timeout=8,
            verify=False,
        )
        if resp.status_code == 200:
            st.session_state.nw_token = raw_token.strip()
            st.session_state.nw_token_expires = datetime.now() + timedelta(hours=23, minutes=55)
            st.session_state.nw_connected = True
            ver = resp.json().get("version", "?")
            return True, f"Token valid — NetWitness v{ver}"
        else:
            return False, f"Token rejected — HTTP {resp.status_code}"
    except Exception as e:
        return False, f"Connection error: {e}"

def nw_refresh_if_needed():
    """Auto-refresh token if it's expired or about to expire."""
    exp = st.session_state.nw_token_expires
    if exp and datetime.now() >= exp:
        st.session_state.nw_connected = False
        # If we have credentials, re-authenticate automatically
        if st.session_state.nw_username and st.session_state.nw_password:
            ok, msg = nw_authenticate()
            st.session_state.nw_status_msg = f"[AUTO-REFRESH] {msg}"
        else:
            st.session_state.nw_status_msg = "Token expired — re-import or enter credentials to refresh."

def token_time_left() -> Optional[timedelta]:
    if st.session_state.nw_token_expires:
        delta = st.session_state.nw_token_expires - datetime.now()
        return max(delta, timedelta(0))
    return None

def token_pct() -> float:
    """Return 0-1 fraction of token lifetime remaining (24h total)."""
    tl = token_time_left()
    if tl is None:
        return 0.0
    return min(tl.total_seconds() / (24 * 3600), 1.0)


# ══════════════════════════════════════════════════════════════
# NETWITNESS INCIDENTS
# ══════════════════════════════════════════════════════════════
def nw_fetch_incidents(limit: int = 50) -> tuple[bool, str, list]:
    """
    Fetch incidents from NetWitness Respond module.
    GET /rest/api/incidents?limit=N
    """
    nw_refresh_if_needed()
    if not st.session_state.nw_connected or not st.session_state.nw_token:
        return False, "Not connected to NetWitness.", []
    host = st.session_state.nw_host.rstrip("/")
    try:
        resp = requests.get(
            f"{host}/rest/api/incidents",
            headers=nw_headers(st.session_state.nw_token),
            params={"limit": limit, "pageSize": limit},
            timeout=15,
            verify=False,
        )
        if resp.status_code == 200:
            data = resp.json()
            incidents = data.get("items") or data.get("data") or data if isinstance(data, list) else []
            return True, f"Loaded {len(incidents)} incidents.", incidents
        elif resp.status_code == 401:
            st.session_state.nw_connected = False
            return False, "Unauthorized — token may have expired. Re-authenticate.", []
        else:
            return False, f"HTTP {resp.status_code}: {resp.text[:300]}", []
    except Exception as e:
        return False, f"Request failed: {e}", []


# ══════════════════════════════════════════════════════════════
# CHROMADB HELPERS
# ══════════════════════════════════════════════════════════════
def chroma_init(persist_path: str = "./chroma_db") -> tuple[bool, str]:
    if not CHROMA_AVAILABLE:
        return False, "chromadb not installed. Run: pip install chromadb"
    try:
        client = chromadb.PersistentClient(path=persist_path)
        collection = client.get_or_create_collection(
            name="soc_incidents",
            metadata={"hnsw:space": "cosine"},
        )
        st.session_state.chroma_client = client
        st.session_state.chroma_collection = collection
        count = collection.count()
        return True, f"ChromaDB ready — {count} vectors in 'soc_incidents'"
    except Exception as e:
        return False, f"ChromaDB error: {e}"

def chroma_upsert_incidents(incidents: list) -> tuple[int, str]:
    col = st.session_state.chroma_collection
    if col is None:
        return 0, "ChromaDB not initialised."
    docs, ids, metas = [], [], []
    for inc in incidents:
        inc_id = str(inc.get("id") or inc.get("incidentId") or inc.get("_id", ""))
        if not inc_id:
            continue
        title   = inc.get("title") or inc.get("name") or ""
        summary = inc.get("summary") or inc.get("description") or ""
        text    = f"{title}\n{summary}".strip() or "no content"
        docs.append(text)
        ids.append(inc_id)
        metas.append({
            "severity": str(inc.get("riskScore") or inc.get("severity") or ""),
            "status":   str(inc.get("status") or ""),
            "created":  str(inc.get("created") or inc.get("createdDate") or ""),
        })
    if not docs:
        return 0, "No valid incidents to store."
    try:
        col.upsert(documents=docs, ids=ids, metadatas=metas)
        return len(docs), f"Upserted {len(docs)} incidents into ChromaDB."
    except Exception as e:
        return 0, f"Upsert error: {e}"

def chroma_search(query: str, n: int = 5) -> list:
    col = st.session_state.chroma_collection
    if col is None or not query.strip():
        return []
    try:
        res = col.query(query_texts=[query], n_results=min(n, col.count() or 1))
        results = []
        for i, doc in enumerate(res["documents"][0]):
            results.append({
                "id":       res["ids"][0][i],
                "text":     doc,
                "distance": round(res["distances"][0][i], 4),
                "meta":     res["metadatas"][0][i],
            })
        return results
    except Exception as e:
        return [{"id": "error", "text": str(e), "distance": 0, "meta": {}}]


# ══════════════════════════════════════════════════════════════
# CHAT HELPERS  (stub — wire LangChain here)
# ══════════════════════════════════════════════════════════════
def chat_respond(user_msg: str, incident_context: Optional[dict] = None) -> str:
    """
    ─────────────────────────────────────────────────────
    LANGCHAIN INTEGRATION POINT
    Replace the body of this function with your LangChain
    chain / agent / RAG pipeline.

    Available context you can pass to the chain:
      • user_msg          — the analyst's message
      • incident_context  — currently selected incident dict
      • st.session_state.chroma_collection — live ChromaDB collection
      • st.session_state.nw_token / nw_host — for live NW API calls
    ─────────────────────────────────────────────────────
    """
    # ── Stub response ──────────────────────────────────
    ctx = ""
    if incident_context:
        ctx = f" (incident #{incident_context.get('id','?')}: {incident_context.get('title','?')})"
    return (
        f"[LANGCHAIN STUB] Received: \"{user_msg}\"{ctx}.\n\n"
        f"Wire up your LangChain chain inside `chat_respond()` in app.py. "
        f"The ChromaDB collection is available via `st.session_state.chroma_collection`."
    )


# ══════════════════════════════════════════════════════════════
# SIDEBAR
# ══════════════════════════════════════════════════════════════
with st.sidebar:
    st.markdown("## 🛡️ SOC PLATFORM")

    # ── Connection status banner ───────────────────────
    if st.session_state.nw_connected:
        tl = token_time_left()
        tl_str = f"{int(tl.total_seconds()//3600)}h {int((tl.total_seconds()%3600)//60)}m" if tl else "?"
        pct = token_pct()
        bar_color = "#00D4FF" if pct > 0.2 else "#FFB700" if pct > 0.05 else "#FF3B3B"
        st.markdown(
            f'<div class="sec-label">■ NETWITNESS STATUS</div>'
            f'<div style="font-family:var(--mono);font-size:0.7rem">'
            f'<span class="dot dot-green"></span>CONNECTED</div>'
            f'<div style="font-family:var(--mono);font-size:0.62rem;color:var(--muted);margin-top:2px">'
            f'Token expires in {tl_str}</div>'
            f'<div class="timer-bar-wrap"><div class="timer-bar-fill" style="width:{pct*100:.1f}%;background:{bar_color}"></div></div>',
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            '<div class="sec-label">■ NETWITNESS STATUS</div>'
            '<div style="font-family:var(--mono);font-size:0.7rem">'
            '<span class="dot dot-red"></span>DISCONNECTED</div>',
            unsafe_allow_html=True,
        )
    if st.session_state.nw_status_msg:
        st.caption(st.session_state.nw_status_msg)

    st.markdown("---")

    # ── NetWitness config ──────────────────────────────
    st.markdown('<div class="sec-label">■ NETWITNESS CONFIG</div>', unsafe_allow_html=True)
    st.session_state.nw_host = st.text_input(
        "Host URL", value=st.session_state.nw_host,
        placeholder="https://nw-server:50103",
    )

    with st.expander("🔐 Authenticate with credentials"):
        st.session_state.nw_username = st.text_input("Username", value=st.session_state.nw_username)
        st.session_state.nw_password = st.text_input("Password", value=st.session_state.nw_password, type="password")
        if st.button("🔑 Login & Get Token", use_container_width=True):
            with st.spinner("Authenticating…"):
                ok, msg = nw_authenticate()
            st.session_state.nw_status_msg = msg
            if ok:
                st.success(msg)
            else:
                st.error(msg)
            st.rerun()

    with st.expander("📋 Import token manually"):
        raw = st.text_area("Paste access token", height=80, placeholder="eyJ… or long token string")
        if st.button("✅ Import & Verify Token", use_container_width=True):
            with st.spinner("Verifying token…"):
                ok, msg = nw_import_token(raw)
            st.session_state.nw_status_msg = msg
            if ok:
                st.success(msg)
            else:
                st.error(msg)
            st.rerun()

    if st.session_state.nw_connected:
        if st.button("🔄 Force Refresh Token", use_container_width=True):
            if st.session_state.nw_username:
                ok, msg = nw_authenticate()
                st.session_state.nw_status_msg = msg
            else:
                st.session_state.nw_status_msg = "No credentials stored — re-import token manually."
            st.rerun()

    st.markdown("---")

    # ── ChromaDB config ────────────────────────────────
    st.markdown('<div class="sec-label">■ CHROMADB</div>', unsafe_allow_html=True)
    chroma_path = st.text_input("Persist path", value="./chroma_db", label_visibility="visible")
    col_ca, col_cb = st.columns(2)
    if col_ca.button("🗄️ Connect", use_container_width=True):
        ok, msg = chroma_init(chroma_path)
        st.session_state.chroma_status = msg
        if ok: st.success(msg)
        else:  st.error(msg)
    if st.session_state.chroma_collection is not None:
        st.markdown(
            f'<div style="font-family:var(--mono);font-size:0.65rem;color:#00D4A0">'
            f'<span class="dot dot-green"></span>{st.session_state.chroma_status}</div>',
            unsafe_allow_html=True,
        )

    st.markdown("---")
    st.markdown(
        '<div style="font-family:var(--mono);font-size:0.6rem;color:var(--muted);text-align:center">'
        'SOC PLATFORM v2 · RESTRICTED</div>',
        unsafe_allow_html=True,
    )


# ══════════════════════════════════════════════════════════════
# MAIN HEADER
# ══════════════════════════════════════════════════════════════
st.markdown("# 🛡️ SOC PLATFORM")
c1, c2, c3, c4 = st.columns(4)
active_incidents = [i for i in st.session_state.incidents if str(i.get("status","")).upper() not in ("CLOSED","RESOLVED","REMEDIATED")]
critical = [i for i in st.session_state.incidents if str(i.get("riskScore") or i.get("severity","")).upper() in ("CRITICAL","HIGH","90","100")]
c1.metric("📋 Total Incidents",   len(st.session_state.incidents))
c2.metric("🔴 Active",           len(active_incidents))
c3.metric("⚠️ High / Critical",  len(critical))
chroma_count = st.session_state.chroma_collection.count() if st.session_state.chroma_collection else 0
c4.metric("🗄️ ChromaDB Vectors", chroma_count)

# auto-check token expiry on every render
nw_refresh_if_needed()

st.markdown("---")

# ══════════════════════════════════════════════════════════════
# TABS
# ══════════════════════════════════════════════════════════════
tab_incidents, tab_chat, tab_chroma = st.tabs([
    "📋  INCIDENTS",
    "💬  CHAT",
    "🗄️  CHROMADB",
])


# ─────────────────────────────────────────────────────────────
# TAB 1 — INCIDENTS
# ─────────────────────────────────────────────────────────────
with tab_incidents:
    col_ctl1, col_ctl2, col_ctl3, col_ctl4 = st.columns([1, 1, 1, 3])

    if col_ctl1.button("🔄 Fetch Incidents", use_container_width=True):
        with st.spinner("Fetching from NetWitness…"):
            ok, msg, data = nw_fetch_incidents(limit=100)
        st.session_state.nw_status_msg = msg
        if ok:
            st.session_state.incidents = data
            st.session_state.incidents_loaded = True
            st.success(msg)
        else:
            st.error(msg)
        st.rerun()

    if col_ctl2.button("⬆️ Sync → ChromaDB", use_container_width=True):
        if st.session_state.chroma_collection is None:
            st.error("Connect ChromaDB first (sidebar).")
        elif not st.session_state.incidents:
            st.warning("Fetch incidents first.")
        else:
            n, msg = chroma_upsert_incidents(st.session_state.incidents)
            st.success(msg) if n else st.error(msg)

    sev_filter = col_ctl3.selectbox(
        "Severity", ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"],
        label_visibility="collapsed",
    )

    # ── Incident cards ───────────────────────────────────────
    if not st.session_state.incidents_loaded:
        st.markdown(
            '<div style="text-align:center;padding:60px;font-family:var(--mono);'
            'font-size:0.8rem;color:var(--muted)">'
            '● AWAITING DATA FEED<br><span style="font-size:0.65rem">'
            'Connect to NetWitness and click Fetch Incidents</span></div>',
            unsafe_allow_html=True,
        )
    else:
        shown = 0
        for inc in st.session_state.incidents:
            sev_raw = str(inc.get("riskScore") or inc.get("severity") or "LOW").upper()
            # Map numeric risk scores to labels
            try:
                score = int(sev_raw)
                sev_label = "CRITICAL" if score >= 90 else "HIGH" if score >= 70 else "MEDIUM" if score >= 40 else "LOW"
            except ValueError:
                sev_label = sev_raw if sev_raw in ("CRITICAL","HIGH","MEDIUM","LOW") else "LOW"

            if sev_filter != "ALL" and sev_label != sev_filter:
                continue
            shown += 1

            inc_id    = inc.get("id") or inc.get("incidentId") or "—"
            title     = inc.get("title") or inc.get("name") or "Untitled Incident"
            status    = inc.get("status") or "UNKNOWN"
            created   = str(inc.get("created") or inc.get("createdDate") or "—")[:16]
            assignee  = inc.get("assignee") or inc.get("assigned") or "Unassigned"
            alert_cnt = inc.get("alertCount") or inc.get("numAlerts") or "—"

            badge_cls = f"badge-{sev_label.lower()}"
            card_cls  = f"card card-{sev_label.lower()}"

            with st.container():
                st.markdown(
                    f'<div class="{card_cls}">'
                    f'<div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">'
                    f'<span class="badge {badge_cls}">{sev_label}</span>'
                    f'<strong style="flex:1;font-size:0.9rem">{title}</strong>'
                    f'<code style="color:var(--muted);font-size:0.7rem">{inc_id}</code>'
                    f'</div>'
                    f'<div style="margin-top:6px;font-size:0.76rem;color:var(--muted);display:flex;gap:20px;flex-wrap:wrap">'
                    f'<span>🕐 {created}</span>'
                    f'<span>📌 {status}</span>'
                    f'<span>👤 {assignee}</span>'
                    f'<span>🚨 {alert_cnt} alerts</span>'
                    f'</div>'
                    f'</div>',
                    unsafe_allow_html=True,
                )
                col_chat_btn, col_detail_btn, _ = st.columns([1, 1, 5])
                if col_chat_btn.button("💬 Chat", key=f"chat_{inc_id}"):
                    st.session_state["chat_incident"] = inc
                    st.session_state.active_tab = 1
                    st.rerun()
                if col_detail_btn.button("🔍 Detail", key=f"detail_{inc_id}"):
                    with st.expander(f"Incident {inc_id} — Full JSON", expanded=True):
                        st.json(inc)

        if shown == 0:
            st.info(f"No incidents match severity filter: {sev_filter}")


# ─────────────────────────────────────────────────────────────
# TAB 2 — CHAT
# ─────────────────────────────────────────────────────────────
with tab_chat:
    # Active incident context banner
    active_inc = st.session_state.get("chat_incident")
    if active_inc:
        inc_sev = str(active_inc.get("riskScore") or active_inc.get("severity") or "").upper()
        st.markdown(
            f'<div style="background:#050F1A;border:1px solid var(--accent);border-radius:5px;'
            f'padding:10px 16px;font-family:var(--mono);font-size:0.72rem;margin-bottom:12px">'
            f'<span class="badge badge-info">CONTEXT</span>&nbsp; '
            f'Incident <strong>{active_inc.get("id","?")}</strong> — '
            f'{active_inc.get("title","?")}'
            f'<span style="float:right;cursor:pointer;color:var(--muted)" '
            f'title="Clear context">· severity {inc_sev}</span>'
            f'</div>',
            unsafe_allow_html=True,
        )
        if st.button("✕ Clear incident context", key="clear_ctx"):
            st.session_state["chat_incident"] = None
            st.rerun()
    else:
        st.markdown(
            '<div style="font-family:var(--mono);font-size:0.7rem;color:var(--muted);'
            'padding:6px 0;margin-bottom:8px">'
            '● No incident context — chatting generally. '
            'Click 💬 Chat on any incident to attach context.</div>',
            unsafe_allow_html=True,
        )

    # ── Chat history ─────────────────────────────────────────
    chat_box = st.container()
    with chat_box:
        if not st.session_state.chat_history:
            st.markdown(
                '<div style="text-align:center;padding:50px;font-family:var(--mono);'
                'font-size:0.78rem;color:var(--muted)">'
                '💬 SOC CHAT READY<br>'
                '<span style="font-size:0.62rem">LangChain integration point — see chat_respond() in app.py</span>'
                '</div>',
                unsafe_allow_html=True,
            )
        for msg in st.session_state.chat_history:
            role = msg["role"]
            ts   = msg.get("ts", "")
            if role == "user":
                st.markdown(
                    f'<div class="bubble-user">'
                    f'<div class="bubble-label" style="color:var(--muted)">ANALYST · {ts}</div>'
                    f'{msg["content"]}</div>',
                    unsafe_allow_html=True,
                )
            else:
                st.markdown(
                    f'<div class="bubble-agent">'
                    f'<div class="bubble-label">SOC AGENT · {ts}</div>'
                    f'{msg["content"]}</div>',
                    unsafe_allow_html=True,
                )

    # ── Input row ─────────────────────────────────────────────
    st.markdown("---")
    user_input = st.chat_input("Ask the SOC agent…")
    if user_input:
        ts_now = datetime.now().strftime("%H:%M:%S")
        st.session_state.chat_history.append({"role": "user", "content": user_input, "ts": ts_now})
        with st.spinner("Agent thinking…"):
            reply = chat_respond(user_input, incident_context=active_inc)
        st.session_state.chat_history.append({"role": "assistant", "content": reply, "ts": datetime.now().strftime("%H:%M:%S")})
        st.rerun()

    col_cc1, col_cc2 = st.columns([1, 5])
    if col_cc1.button("🗑️ Clear Chat", use_container_width=True):
        st.session_state.chat_history = []
        st.rerun()


# ─────────────────────────────────────────────────────────────
# TAB 3 — CHROMADB
# ─────────────────────────────────────────────────────────────
with tab_chroma:
    col_db1, col_db2 = st.columns([2, 1])
    with col_db1:
        st.markdown("### CHROMADB — soc_incidents")
        if st.session_state.chroma_collection is None:
            st.warning("ChromaDB not connected. Use the sidebar to connect.")
        else:
            col = st.session_state.chroma_collection
            count = col.count()
            st.markdown(f'<span class="badge badge-info">{count} vectors stored</span>', unsafe_allow_html=True)
            st.markdown("---")

            # Semantic search
            st.markdown('<div class="sec-label">■ SEMANTIC SEARCH</div>', unsafe_allow_html=True)
            q_col, n_col = st.columns([4, 1])
            search_q = q_col.text_input("Search query", placeholder="e.g. ransomware lateral movement", label_visibility="collapsed")
            n_results = n_col.number_input("Top N", min_value=1, max_value=20, value=5, label_visibility="collapsed")
            if st.button("🔍 Search ChromaDB", use_container_width=False):
                with st.spinner("Querying vectors…"):
                    st.session_state.search_results = chroma_search(search_q, n=n_results)

            for r in st.session_state.search_results:
                dist_pct = round((1 - r["distance"]) * 100, 1)
                meta = r["meta"]
                st.markdown(
                    f'<div class="chroma-row">'
                    f'<span class="badge badge-info">{dist_pct}% match</span>'
                    f'&nbsp;<strong>{r["id"]}</strong>&nbsp;'
                    f'<span style="color:var(--muted)">sev:{meta.get("severity","?")} '
                    f'status:{meta.get("status","?")}</span><br>'
                    f'<span style="font-size:0.68rem;color:var(--text)">{r["text"][:180]}…</span>'
                    f'</div>',
                    unsafe_allow_html=True,
                )

            st.markdown("---")
            st.markdown('<div class="sec-label">■ COLLECTION ACTIONS</div>', unsafe_allow_html=True)
            act1, act2, act3 = st.columns(3)
            if act1.button("⬆️ Sync Incidents", use_container_width=True):
                if not st.session_state.incidents:
                    st.warning("Fetch incidents first from the Incidents tab.")
                else:
                    n, msg = chroma_upsert_incidents(st.session_state.incidents)
                    st.success(msg) if n else st.error(msg)
                    st.rerun()
            if act2.button("🗑️ Wipe Collection", use_container_width=True):
                try:
                    st.session_state.chroma_client.delete_collection("soc_incidents")
                    ok, msg = chroma_init()
                    st.session_state.chroma_status = msg
                    st.success("Collection wiped and recreated.")
                    st.rerun()
                except Exception as e:
                    st.error(str(e))
            if act3.button("📤 Export IDs", use_container_width=True):
                try:
                    all_ids = col.get()["ids"]
                    st.download_button("Download IDs", data="\n".join(all_ids), file_name="chroma_ids.txt")
                except Exception as e:
                    st.error(str(e))

    with col_db2:
        st.markdown("### HOW TO WIRE LANGCHAIN")
        st.markdown("""
```python
# In chat_respond() → app.py

from langchain_community.vectorstores import Chroma
from langchain_anthropic import ChatAnthropic
from langchain.chains import RetrievalQA

vectorstore = Chroma(
    client=st.session_state.chroma_client,
    collection_name="soc_incidents",
    embedding_function=your_embedder,
)

llm = ChatAnthropic(model="claude-sonnet-4-20250514")

chain = RetrievalQA.from_chain_type(
    llm=llm,
    retriever=vectorstore.as_retriever(
        search_kwargs={"k": 5}
    ),
)

return chain.invoke(user_msg)["result"]
```
        """)