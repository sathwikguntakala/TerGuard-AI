"""
🛡️ TerGuard AI – Real-Time Threat Intelligence & Social Engineering Gateway

SOC analyst dashboard with telemetry HUD, visual token heatmap,
URL ledger, and incident export capabilities.
"""
from __future__ import annotations

import json
import sys
import os
import time
from datetime import datetime, timezone
from pathlib import Path

# Ensure project root is importable
_project_root = str(Path(__file__).resolve().parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

import streamlit as st

from src.gateway import TerGuardGateway, ThreatEvaluationResult
from src.utils.samples import PRESET_ATTACK_VECTORS, THREAT_SAMPLES

# ---------------------------------------------------------------------------
# Page configuration & dark-theme CSS
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="TerGuard AI – Threat Intelligence Gateway",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

_DARK_CSS = """
<style>
    /* Dark cybersecurity theme overrides */
    .stApp {
        background-color: #0d1117;
        color: #c9d1d9;
    }
    [data-testid="stSidebar"] {
        background-color: #161b22;
    }
    .metric-card {
        background: linear-gradient(135deg, #161b22 0%, #1c2333 100%);
        border: 1px solid #30363d;
        border-radius: 12px;
        padding: 20px;
        text-align: center;
    }
    .metric-value {
        font-size: 2rem;
        font-weight: 700;
        margin: 4px 0;
    }
    .metric-label {
        font-size: 0.85rem;
        color: #8b949e;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }
    .threat-critical { color: #f85149; }
    .threat-high { color: #ff7b72; }
    .threat-medium { color: #d29922; }
    .threat-low { color: #3fb950; }
    .threat-safe { color: #58a6ff; }
    .heatmap-container {
        background: #161b22;
        border: 1px solid #30363d;
        border-radius: 8px;
        padding: 16px;
        line-height: 2.2;
        font-size: 0.95rem;
    }
    .url-table {
        width: 100%;
        border-collapse: collapse;
    }
    .url-table th {
        background: #21262d;
        color: #c9d1d9;
        padding: 10px 12px;
        text-align: left;
        border-bottom: 2px solid #30363d;
        font-size: 0.85rem;
        text-transform: uppercase;
    }
    .url-table td {
        padding: 8px 12px;
        border-bottom: 1px solid #21262d;
        font-family: 'Cascadia Code', 'Fira Code', monospace;
        font-size: 0.85rem;
    }
    .badge {
        display: inline-block;
        padding: 3px 10px;
        border-radius: 20px;
        font-size: 0.75rem;
        font-weight: 600;
        text-transform: uppercase;
    }
    .badge-critical { background: #f8514933; color: #f85149; border: 1px solid #f85149; }
    .badge-high { background: #ff7b7233; color: #ff7b72; border: 1px solid #ff7b72; }
    .badge-medium { background: #d2992233; color: #d29922; border: 1px solid #d29922; }
    .badge-low { background: #3fb95033; color: #3fb950; border: 1px solid #3fb950; }
    .badge-safe { background: #58a6ff33; color: #58a6ff; border: 1px solid #58a6ff; }
    .rule-tag {
        display: inline-block;
        background: #21262d;
        border: 1px solid #30363d;
        border-radius: 4px;
        padding: 2px 8px;
        margin: 2px;
        font-size: 0.8rem;
        color: #ff7b72;
    }
</style>
"""
st.markdown(_DARK_CSS, unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Gateway singleton (cached so model loads once)
# ---------------------------------------------------------------------------

@st.cache_resource(show_spinner="🔄 Loading TerGuard AI engine …")
def _load_gateway() -> TerGuardGateway:
    """Initialise the gateway once and cache across reruns."""
    return TerGuardGateway()


def _threat_badge(level: str) -> str:
    """Return an HTML badge span for a threat level."""
    css_class = f"badge-{level.lower()}"
    return f'<span class="badge {css_class}">{level}</span>'


def _threat_color_class(level: str) -> str:
    return f"threat-{level.lower()}"


def _score_bar_html(score: float, max_val: float = 100.0) -> str:
    """Render a compact horizontal progress bar."""
    pct = min(score / max_val * 100, 100)
    if pct >= 80:
        color = "#f85149"
    elif pct >= 60:
        color = "#ff7b72"
    elif pct >= 40:
        color = "#d29922"
    elif pct >= 20:
        color = "#3fb950"
    else:
        color = "#58a6ff"
    return (
        f'<div style="background:#21262d;border-radius:6px;height:10px;width:100%;">'
        f'<div style="width:{pct:.1f}%;background:{color};height:10px;border-radius:6px;"></div>'
        f'</div>'
    )


# ---------------------------------------------------------------------------
# Sidebar – Input controls
# ---------------------------------------------------------------------------
st.sidebar.markdown("## 🛡️ TerGuard AI")
st.sidebar.markdown("---")

input_mode = st.sidebar.radio(
    "Input source",
    ["📋 Preset Attack Vectors", "✏️ Manual Text Entry"],
    index=0,
)

raw_text = ""
if input_mode == "📋 Preset Attack Vectors":
    preset_names = list(PRESET_ATTACK_VECTORS.keys())
    selected = st.sidebar.selectbox("Select scenario", preset_names)
    raw_text = PRESET_ATTACK_VECTORS[selected]
    st.sidebar.text_area("Preview", raw_text, height=180, disabled=True)
else:
    raw_text = st.sidebar.text_area(
        "Paste email / SMS / message",
        height=220,
        placeholder="Enter suspicious communication text here …",
    )

analyse_btn = st.sidebar.button("🔍 Analyse Message", type="primary", use_container_width=True)

st.sidebar.markdown("---")
st.sidebar.caption("TerGuard AI v1.0 · Offline Mode · All inference local")

# ---------------------------------------------------------------------------
# Main content
# ---------------------------------------------------------------------------
st.markdown(
    "# 🛡️ TerGuard AI – Real-Time Threat Intelligence & Social Engineering Gateway"
)

if not analyse_btn or not raw_text.strip():
    st.info("Select or enter a message in the sidebar and click **Analyse Message** to begin inspection.")
    st.stop()

# Run analysis
with st.spinner("⚡ Running multi-layer threat analysis …"):
    gateway = _load_gateway()
    result: ThreatEvaluationResult = gateway.evaluate_message(raw_text)

# ── Telemetry cards ────────────────────────────────────────────────────────
st.markdown("## 📊 Telemetry Dashboard")
c1, c2, c3, c4 = st.columns(4)

with c1:
    color_cls = _threat_color_class(result.threat_level)
    st.markdown(
        f"""<div class="metric-card">
        <div class="metric-label">Threat Level</div>
        <div class="metric-value {color_cls}">{result.threat_level}</div>
        {_threat_badge(result.threat_level)}
        </div>""",
        unsafe_allow_html=True,
    )

with c2:
    st.markdown(
        f"""<div class="metric-card">
        <div class="metric-label">Composite Risk Score</div>
        <div class="metric-value">{result.composite_score:.1f}<span style="font-size:1rem;color:#8b949e">/100</span></div>
        {_score_bar_html(result.composite_score)}
        </div>""",
        unsafe_allow_html=True,
    )

with c3:
    latency_color = "#3fb950" if result.total_latency_ms < 30 else "#d29922" if result.total_latency_ms < 100 else "#f85149"
    st.markdown(
        f"""<div class="metric-card">
        <div class="metric-label">Total Latency</div>
        <div class="metric-value" style="color:{latency_color}">{result.total_latency_ms:.1f}<span style="font-size:1rem;color:#8b949e">ms</span></div>
        <div class="metric-label">{"✅ Under 30ms" if result.total_latency_ms < 30 else "⚠️ Above target"}</div>
        </div>""",
        unsafe_allow_html=True,
    )

with c4:
    st.markdown(
        f"""<div class="metric-card">
        <div class="metric-label">NLP Confidence</div>
        <div class="metric-value">{result.classification.confidence * 100:.0f}%</div>
        <div class="metric-label">Model: {result.classification.model_name}</div>
        </div>""",
        unsafe_allow_html=True,
    )

# ── Remediation banner ────────────────────────────────────────────────────
level_icon = {"CRITICAL": "🚨", "HIGH": "⚠️", "MEDIUM": "⚡", "LOW": "ℹ️", "SAFE": "✅"}
icon = level_icon.get(result.threat_level, "🔍")
st.markdown(f"### {icon} Remediation Guidance")
st.info(result.remediation)

# ── Explainability heatmap ─────────────────────────────────────────────────
st.markdown("## 🔬 Explainability Canvas – Token Risk Attribution")
st.markdown(
    f'<div class="heatmap-container">{result.explainability.html_heatmap}</div>',
    unsafe_allow_html=True,
)

# Legend
st.markdown(
    """<div style="margin-top:8px;font-size:0.8rem;color:#8b949e;">
    <span style="background:#c8e6c9;color:black;padding:2px 8px;border-radius:3px;">Safe</span>
    <span style="background:#fff9c4;color:black;padding:2px 8px;border-radius:3px;">Low</span>
    <span style="background:#ffe0b2;color:black;padding:2px 8px;border-radius:3px;">Medium</span>
    <span style="background:#ff8a65;color:black;padding:2px 8px;border-radius:3px;">High</span>
    <span style="background:#ef5350;color:white;padding:2px 8px;border-radius:3px;">Critical</span>
    </div>""",
    unsafe_allow_html=True,
)

# Top risk tokens table
if result.explainability.top_risk_tokens:
    st.markdown("### 🎯 Top Risk Tokens")
    token_data = [
        {"Token": t.token, "Raw Score": f"{t.score:.4f}", "Normalised": f"{t.normalized_score:.4f}"}
        for t in result.explainability.top_risk_tokens
    ]
    st.dataframe(token_data, use_container_width=True, hide_index=True)

# ── URL Inspection ─────────────────────────────────────────────────────────
st.markdown("## 🔗 Deep URL Inspection")
if result.url_reports:
    rows = []
    for rpt in result.url_reports:
        flags_html = " ".join(f'<span class="rule-tag">{f}</span>' for f in rpt.flags) if rpt.flags else "—"
        rows.append(
            f"<tr>"
            f"<td>{rpt.url}</td>"
            f"<td>{rpt.domain}</td>"
            f"<td>{rpt.entropy:.2f}</td>"
            f"<td>{'🚨 Yes' if rpt.has_homoglyphs else '✅ No'}</td>"
            f"<td>{'⚠️ Yes' if rpt.suspicious_tld else '✅ No'}</td>"
            f"<td>{rpt.risk_score:.2f}</td>"
            f"<td>{flags_html}</td>"
            f"</tr>"
        )
    table_html = (
        '<table class="url-table"><thead><tr>'
        "<th>URL</th><th>Domain</th><th>Entropy</th>"
        "<th>Homoglyphs</th><th>Suspicious TLD</th><th>Risk</th><th>Flags</th>"
        "</tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table>"
    )
    st.markdown(table_html, unsafe_allow_html=True)
else:
    st.success("No URLs detected in this message.")

# ── Heuristic Rules ────────────────────────────────────────────────────────
st.markdown("## 📏 Heuristic Rule Analysis")
hr = result.heuristic_result
hcols = st.columns(4)
labels = ["Urgency", "Credential Theft", "Financial", "Authority"]
scores = [hr.urgency_score, hr.credential_theft_score, hr.financial_score, hr.authority_score]
for col, label, score in zip(hcols, labels, scores):
    with col:
        st.markdown(
            f"""<div class="metric-card">
            <div class="metric-label">{label}</div>
            <div class="metric-value">{score:.2f}</div>
            {_score_bar_html(score, 1.0)}
            </div>""",
            unsafe_allow_html=True,
        )

if hr.triggered_rules:
    st.markdown("### Triggered Rules")
    for rule in hr.triggered_rules:
        st.markdown(f"- 🔴 {rule}")

# ── Classification breakdown ──────────────────────────────────────────────
st.markdown("## 🧠 NLP Classification Breakdown")
prob_cols = st.columns(3)
for col, (lbl, prob) in zip(prob_cols, result.classification.probabilities.items()):
    with col:
        st.metric(lbl, f"{prob * 100:.1f}%")

st.caption(
    f"Inference latency: {result.classification.latency_ms:.2f} ms  ·  "
    f"ONNX: {'Yes' if result.classification.used_onnx else 'No'}  ·  "
    f"Model: `{result.classification.model_name}`"
)

# ── Export ─────────────────────────────────────────────────────────────────
st.markdown("## 📤 Incident Export")
export_col1, export_col2 = st.columns(2)

# Build export payload
export_payload = {
    "timestamp": datetime.now(timezone.utc).isoformat(),
    "threat_level": result.threat_level,
    "composite_score": round(result.composite_score, 2),
    "total_latency_ms": round(result.total_latency_ms, 2),
    "classification": {
        "label": result.classification.label,
        "confidence": result.classification.confidence,
        "probabilities": result.classification.probabilities,
        "model": result.classification.model_name,
    },
    "urls_analysed": len(result.url_reports),
    "url_details": [
        {
            "url": r.url,
            "domain": r.domain,
            "entropy": round(r.entropy, 4),
            "homoglyphs": r.has_homoglyphs,
            "suspicious_tld": r.suspicious_tld,
            "risk_score": round(r.risk_score, 4),
            "flags": r.flags,
        }
        for r in result.url_reports
    ],
    "heuristics": {
        "composite": round(hr.composite_heuristic_score, 4),
        "urgency": round(hr.urgency_score, 4),
        "credential_theft": round(hr.credential_theft_score, 4),
        "financial": round(hr.financial_score, 4),
        "authority": round(hr.authority_score, 4),
        "triggered_rules": hr.triggered_rules,
    },
    "top_risk_tokens": [
        {"token": t.token, "score": round(t.normalized_score, 4)}
        for t in result.explainability.top_risk_tokens
    ],
    "remediation": result.remediation,
    "summary": result.summary,
    "input_text": raw_text,
}

with export_col1:
    st.download_button(
        "⬇️ Export JSON Report",
        data=json.dumps(export_payload, indent=2),
        file_name=f"terguard_incident_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
        mime="application/json",
        use_container_width=True,
    )

with export_col2:
    md_lines = [
        f"# TerGuard AI Incident Report",
        f"**Generated:** {datetime.now(timezone.utc).isoformat()}",
        f"",
        f"## Summary",
        f"- **Threat Level:** {result.threat_level}",
        f"- **Composite Score:** {result.composite_score:.1f}/100",
        f"- **Latency:** {result.total_latency_ms:.1f}ms",
        f"- **Classification:** {result.classification.label} ({result.classification.confidence:.0%})",
        f"",
        f"## Remediation",
        f"{result.remediation}",
        f"",
        f"## URLs Analysed ({len(result.url_reports)})",
    ]
    for r in result.url_reports:
        md_lines.append(f"- `{r.url}` — Entropy: {r.entropy:.2f}, Risk: {r.risk_score:.2f}")
    md_lines += [
        f"",
        f"## Heuristics",
        f"- Urgency: {hr.urgency_score:.2f}",
        f"- Credential Theft: {hr.credential_theft_score:.2f}",
        f"- Financial: {hr.financial_score:.2f}",
        f"- Authority: {hr.authority_score:.2f}",
    ]
    if hr.triggered_rules:
        md_lines.append("")
        for rule in hr.triggered_rules:
            md_lines.append(f"- {rule}")

    st.download_button(
        "⬇️ Export Markdown Report",
        data="\n".join(md_lines),
        file_name=f"terguard_incident_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md",
        mime="text/markdown",
        use_container_width=True,
    )

# ── Raw JSON expander ─────────────────────────────────────────────────────
with st.expander("📋 Raw Analysis JSON"):
    st.json(export_payload)

st.markdown("---")
st.caption("🛡️ TerGuard AI v1.0 · All analysis performed locally · Zero external API dependencies")
