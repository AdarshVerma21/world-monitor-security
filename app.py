
import time
from datetime import datetime
from typing import Any, Dict, List
from urllib.parse import urlparse

import streamlit as st

# ============================================================
# PROJECT IMPORTS
# ============================================================

try:
    from engine import run_assessment
    ENGINE_AVAILABLE = True
    ENGINE_ERROR = None
except Exception as exc:
    ENGINE_AVAILABLE = False
    ENGINE_ERROR = str(exc)
    try:
        from scanner.headers import scan_headers
        from scanner.cors import scan_cors
        from scanner.cookies import scan_cookies
        from scanner.tls import scan_tls
        from scanner.security import scan_security
        FALLBACK_SCANNERS_AVAILABLE = True
    except Exception as scanner_exc:
        FALLBACK_SCANNERS_AVAILABLE = False
        ENGINE_ERROR = f"{exc}\nScanner fallback error: {scanner_exc}"

try:
    from database import (
        init_database,
        save_scan,
        get_scan_history,
        get_scan,
        delete_scan,
        clear_history,
        get_history_statistics,
    )
    DATABASE_AVAILABLE = True
    DATABASE_ERROR = None
except Exception as exc:
    DATABASE_AVAILABLE = False
    DATABASE_ERROR = str(exc)

# ============================================================
# PAGE CONFIG
# ============================================================

st.set_page_config(
    page_title="VIGIL Security",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ============================================================
# CSS
# ============================================================

st.markdown(
    """
<style>
.stApp {
    background:
        radial-gradient(circle at top left, rgba(33,255,135,.06), transparent 35%),
        #020706;
    color: #f4f7f6;
}
.block-container {
    max-width: 1450px;
    padding-top: 2rem;
    padding-bottom: 4rem;
}
.vigil-hero {
    padding: 38px 42px;
    border: 1px solid #19352c;
    border-radius: 22px;
    background: linear-gradient(135deg,#07140f,#030b08);
    margin-bottom: 35px;
}
.vigil-title {
    font-size: 42px;
    font-weight: 900;
    letter-spacing: 6px;
}
.green { color: #21ff87; }
.vigil-subtitle {
    margin-top: 12px;
    color: #87a99d;
    letter-spacing: 3px;
    font-size: 13px;
    font-weight: 700;
}
.vigil-ready {
    margin-top: 22px;
    color: #21ff87;
    font-weight: 800;
}
.vigil-section {
    margin-top: 34px;
    margin-bottom: 18px;
    font-size: 21px;
    font-weight: 900;
    letter-spacing: 4px;
}
.metric-card {
    min-height: 135px;
    padding: 24px;
    border: 1px solid #19382e;
    border-radius: 16px;
    background: #06100d;
}
.metric-label {
    color: #769e91;
    font-size: 11px;
    letter-spacing: 3px;
    font-weight: 800;
}
.metric-value {
    margin-top: 22px;
    font-size: 34px;
    font-weight: 900;
}
.metric-green { color: #21ff87; }
.metric-red { color: #ff4757; }
.metric-orange { color: #ff9b4a; }
.metric-blue { color: #55adff; }
.command-card {
    text-align: center;
    padding: 22px 10px;
    min-height: 130px;
    border: 1px solid #19382e;
    border-radius: 14px;
    background: #06100d;
}
.command-icon { font-size: 32px; }
.command-name {
    margin-top: 10px;
    font-weight: 900;
    font-size: 13px;
}
.status-ok { color: #21ff87; font-weight: 800; }
.status-bad { color: #ff4757; font-weight: 800; }
.finding {
    border: 1px solid #263932;
    border-radius: 12px;
    background: #040a08;
    padding: 15px 18px;
    margin-bottom: 10px;
}
.sev-critical { color:#ff4056; font-weight:800; }
.sev-high { color:#ff5260; font-weight:800; }
.sev-medium { color:#ff9b4a; font-weight:800; }
.sev-low { color:#ffd45c; font-weight:800; }
.sev-info { color:#55adff; font-weight:800; }
.recommendation {
    background: #0a2030;
    border: 1px solid #163e56;
    border-radius: 10px;
    padding: 14px 18px;
    margin-bottom: 9px;
    color: #45a7ff;
}
.monitor-good {
    border: 1px solid #1b6a43;
    background: rgba(20,100,55,.18);
    border-radius: 14px;
    padding: 20px;
}
.monitor-bad {
    border: 1px solid #7b2631;
    background: rgba(120,20,30,.18);
    border-radius: 14px;
    padding: 20px;
}
.monitor-neutral {
    border: 1px solid #625a20;
    background: rgba(100,90,20,.14);
    border-radius: 14px;
    padding: 20px;
}
.vigil-footer {
    margin-top: 55px;
    padding: 28px;
    border-top: 1px solid #19352c;
    text-align: center;
    color: #62877b;
    letter-spacing: 1px;
}
</style>
""",
    unsafe_allow_html=True,
)

# ============================================================
# DATABASE
# ============================================================

if DATABASE_AVAILABLE:
    try:
        init_database()
    except Exception:
        pass

# ============================================================
# SESSION STATE
# ============================================================

defaults = {
    "result": None,
    "last_target": "",
    "last_scan_time": None,
    "scan_started": False,
}

for key, value in defaults.items():
    if key not in st.session_state:
        st.session_state[key] = value

# ============================================================
# HELPERS
# ============================================================

def safe_dict(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}

def safe_list(value: Any) -> List[Any]:
    return value if isinstance(value, list) else []

def normalize_url(value: str) -> str:
    value = (value or "").strip()
    if not value:
        return ""
    if not value.startswith(("http://", "https://")):
        value = "https://" + value
    try:
        parsed = urlparse(value)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            return ""
        return value.rstrip("/")
    except Exception:
        return ""

def get_findings(result: Any) -> List[Dict[str, Any]]:
    if not isinstance(result, dict):
        return []
    return [x for x in safe_list(result.get("findings")) if isinstance(x, dict)]

def severity_of(finding: Any) -> str:
    if not isinstance(finding, dict):
        return "Informational"
    return str(finding.get("severity", "Informational")).strip().title()

def finding_name(finding: Any) -> str:
    finding = safe_dict(finding)
    return str(
        finding.get("title")
        or finding.get("name")
        or finding.get("header")
        or finding.get("type")
        or finding.get("check")
        or "Security Finding"
    )

def finding_description(finding: Any) -> str:
    finding = safe_dict(finding)
    return str(
        finding.get("description")
        or finding.get("message")
        or finding.get("detail")
        or "Security configuration issue detected."
    )

def finding_recommendation(finding: Any) -> str:
    finding = safe_dict(finding)
    return str(
        finding.get("recommendation")
        or finding.get("remediation")
        or finding.get("solution")
        or "Review and harden the affected configuration."
    )

def severity_class(severity: str) -> str:
    return {
        "Critical": "sev-critical",
        "High": "sev-high",
        "Medium": "sev-medium",
        "Low": "sev-low",
    }.get(severity, "sev-info")

def severity_counts(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    for finding in findings:
        sev = severity_of(finding)
        counts[sev if sev in counts else "Informational"] += 1
    return counts

def get_risk(result: Any) -> Dict[str, Any]:
    result = safe_dict(result)
    risk = safe_dict(result.get("risk"))
    return {
        "score": risk.get("score", 0),
        "rating": risk.get("rating", "Informational"),
    }

def get_status_code(result: Any) -> Any:
    result = safe_dict(result)
    status = result.get("status_code")
    if status is None:
        status = safe_dict(result.get("checks")).get("headers", {})
        status = safe_dict(status).get("status_code")
    return status

def get_response_time(result: Any) -> Any:
    result = safe_dict(result)
    value = result.get("response_time")
    if value is None:
        value = result.get("response_time_ms")
    if value is None:
        value = safe_dict(result.get("checks")).get("headers", {})
        value = safe_dict(value).get("response_time_ms")
    return value

def get_final_url(result: Any) -> str:
    result = safe_dict(result)
    headers = safe_dict(result.get("checks")).get("headers", {})
    return str(
        result.get("final_url")
        or safe_dict(headers).get("final_url")
        or result.get("target", "Unknown")
    )

def calculate_fallback_risk(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    weights = {"Critical": 10, "High": 7, "Medium": 4, "Low": 1}
    score = sum(weights.get(severity_of(x), 0) for x in findings)
    if score >= 15:
        rating = "Critical"
    elif score >= 8:
        rating = "High"
    elif score >= 4:
        rating = "Medium"
    elif score > 0:
        rating = "Low"
    else:
        rating = "Informational"
    return {"score": score, "rating": rating}

def fallback_assessment(target_url: str) -> Dict[str, Any]:
    scanners = [
        ("headers", scan_headers),
        ("cors", scan_cors),
        ("cookies", scan_cookies),
        ("tls", scan_tls),
        ("security", scan_security),
    ]
    checks = {}
    findings = []
    start = time.perf_counter()
    for name, scanner in scanners:
        try:
            value = scanner(target_url)
            if not isinstance(value, dict):
                value = {"findings": []}
        except Exception as exc:
            value = {"findings": [], "error": str(exc)}
        if not isinstance(value.get("findings"), list):
            value["findings"] = []
        checks[name] = value
        findings.extend(value["findings"])
    elapsed = round((time.perf_counter() - start) * 1000, 2)
    status = None
    final_url = target_url
    for check in checks.values():
        if isinstance(check, dict):
            status = status if status is not None else check.get("status_code", check.get("status"))
            final_url = check.get("final_url") or final_url
    return {
        "target": target_url,
        "final_url": final_url,
        "status_code": status,
        "response_time": elapsed,
        "risk": calculate_fallback_risk(findings),
        "findings": findings,
        "checks": checks,
    }

def perform_assessment(target_url: str) -> Dict[str, Any]:
    if ENGINE_AVAILABLE:
        result = run_assessment(target_url)
        if not isinstance(result, dict):
            raise RuntimeError("Assessment engine returned invalid data.")
        return result
    if FALLBACK_SCANNERS_AVAILABLE:
        return fallback_assessment(target_url)
    raise RuntimeError("No assessment engine is available.\n" + str(ENGINE_ERROR))

def make_json_bytes(result: Dict[str, Any]) -> bytes:
    return json.dumps(result, indent=2, ensure_ascii=False, default=str).encode("utf-8")

def html_escape(value: Any) -> str:
    import html
    return html.escape(str(value))

def generate_html_report(result: Dict[str, Any]) -> str:
    result = safe_dict(result)
    findings = get_findings(result)
    risk = get_risk(result)
    rows = ""
    for i, finding in enumerate(findings, 1):
        rows += f"""
<tr>
<td>{i}</td>
<td>{html_escape(finding_name(finding))}</td>
<td>{html_escape(severity_of(finding))}</td>
<td>{html_escape(finding_description(finding))}</td>
<td>{html_escape(finding_recommendation(finding))}</td>
</tr>
"""
    if not rows:
        rows = '<tr><td colspan="5">No security findings detected.</td></tr>'
    return f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>VIGIL Security Report</title>
<style>
body{{font-family:Arial;background:#06100d;color:#f4f7f6;padding:40px}}
.container{{max-width:1200px;margin:auto}}
.card{{background:#0b1713;border:1px solid #24463b;border-radius:15px;padding:22px;margin:20px 0}}
h1{{letter-spacing:5px}} .green{{color:#21ff87}}
table{{width:100%;border-collapse:collapse}}th,td{{border:1px solid #29463d;padding:10px;text-align:left;vertical-align:top}}th{{background:#10251f}}
</style></head><body><div class="container">
<h1>🔐 WORLD <span class="green">MONITOR</span> SECURITY</h1>
<div class="card">
<p><b>Target:</b> {html_escape(result.get("target","Unknown"))}</p>
<p><b>HTTP Status:</b> {html_escape(get_status_code(result))}</p>
<p><b>Response Time:</b> {html_escape(get_response_time(result))} ms</p>
<p><b>Risk Score:</b> {html_escape(risk["score"])}</p>
<p><b>Risk Rating:</b> {html_escape(risk["rating"])}</p>
<p><b>Generated:</b> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
</div>
<div class="card"><h2>Security Findings</h2>
<table><thead><tr><th>#</th><th>Finding</th><th>Severity</th><th>Description</th><th>Recommendation</th></tr></thead>
<tbody>{rows}</tbody></table></div>
</div></body></html>"""

def create_pdf_report(result: Dict[str, Any]) -> bytes:
    from io import BytesIO
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

    result = safe_dict(result)
    findings = get_findings(result)
    risk = get_risk(result)
    counts = severity_counts(findings)
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=A4,
        leftMargin=12*mm, rightMargin=12*mm,
        topMargin=12*mm, bottomMargin=12*mm
    )
    styles = getSampleStyleSheet()
    story = [
        Paragraph("VIGIL SECURITY", styles["Title"]),
        Paragraph("VIGIL Security Assessment Report", styles["Heading2"]),
        Spacer(1, 8),
        Paragraph(f"<b>Target:</b> {html_escape(result.get('target','Unknown'))}", styles["BodyText"]),
        Paragraph(f"<b>Generated:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles["BodyText"]),
        Spacer(1, 12),
    ]
    summary = Table([
        ["Risk Score","Risk Rating","Findings","HTTP Status"],
        [str(risk["score"]),str(risk["rating"]),str(len(findings)),str(get_status_code(result) or "N/A")]
    ])
    summary.setStyle(TableStyle([
        ("BACKGROUND",(0,0),(-1,0),colors.HexColor("#16352a")),
        ("TEXTCOLOR",(0,0),(-1,0),colors.white),
        ("GRID",(0,0),(-1,-1),.5,colors.grey),
        ("PADDING",(0,0),(-1,-1),7),
    ]))
    story += [summary, Spacer(1,12), Paragraph("Severity Summary", styles["Heading2"])]
    sev = Table([
        ["Critical","High","Medium","Low"],
        [str(counts["Critical"]),str(counts["High"]),str(counts["Medium"]),str(counts["Low"])]
    ])
    sev.setStyle(TableStyle([
        ("BACKGROUND",(0,0),(-1,0),colors.HexColor("#16352a")),
        ("TEXTCOLOR",(0,0),(-1,0),colors.white),
        ("GRID",(0,0),(-1,-1),.5,colors.grey),
        ("PADDING",(0,0),(-1,-1),7),
    ]))
    story += [sev, Spacer(1,12), Paragraph("Security Findings", styles["Heading2"])]
    data = [["#","Finding","Severity","Description","Recommendation"]]
    for i, finding in enumerate(findings,1):
        data.append([
            str(i),
            Paragraph(html_escape(finding_name(finding)), styles["BodyText"]),
            html_escape(severity_of(finding)),
            Paragraph(html_escape(finding_description(finding)), styles["BodyText"]),
            Paragraph(html_escape(finding_recommendation(finding)), styles["BodyText"]),
        ])
    if len(data) == 1:
        data.append(["-","No findings","Informational","No security findings detected.","Continue secure configuration practices."])
    table = Table(data, repeatRows=1, colWidths=[8*mm,32*mm,20*mm,55*mm,55*mm])
    table.setStyle(TableStyle([
        ("BACKGROUND",(0,0),(-1,0),colors.HexColor("#16352a")),
        ("TEXTCOLOR",(0,0),(-1,0),colors.white),
        ("GRID",(0,0),(-1,-1),.4,colors.grey),
        ("VALIGN",(0,0),(-1,-1),"TOP"),
        ("FONTSIZE",(0,0),(-1,-1),7),
        ("PADDING",(0,0),(-1,-1),5),
    ]))
    story += [table, Spacer(1,12), Paragraph(
        f"<b>Response Time:</b> {html_escape(get_response_time(result) or 'N/A')} ms",
        styles["BodyText"]
    )]
    doc.build(story)
    return buffer.getvalue()

def compare_results(previous: Dict[str, Any], current: Dict[str, Any]) -> Dict[str, Any]:
    pf = get_findings(previous)
    cf = get_findings(current)
    pr = get_risk(previous)
    cr = get_risk(current)
    pc = severity_counts(pf)
    cc = severity_counts(cf)
    score_change = int(cr["score"] or 0) - int(pr["score"] or 0)
    if score_change < 0:
        status = "Improved"
    elif score_change > 0:
        status = "Worsened"
    else:
        status = "Unchanged"
    return {
        "status": status,
        "previous_score": pr["score"],
        "current_score": cr["score"],
        "score_change": score_change,
        "previous_rating": pr["rating"],
        "current_rating": cr["rating"],
        "previous_findings": len(pf),
        "current_findings": len(cf),
        "severity_changes": {
            sev: cc[sev] - pc[sev]
            for sev in pc
        },
    }

def find_previous_scan(target: str) -> Any:
    if not DATABASE_AVAILABLE:
        return None
    try:
        normalized = normalize_url(target)
        for item in get_scan_history(100):
            saved_target = normalize_url(item.get("target",""))
            if saved_target != normalized:
                continue
            saved = get_scan(int(item["id"]))
            if saved and isinstance(saved.get("result"), dict):
                return saved
    except Exception:
        pass
    return None

# ============================================================
# SIDEBAR
# ============================================================

with st.sidebar:
    st.markdown("## 🔐 VIGIL")
    st.markdown("### SECURITY")
    st.divider()
    st.markdown(
        """
**VIGIL Control Center**

- 🔎 Run security assessments
- 📊 Review risk posture
- 🛡️ Inspect vulnerabilities
- 📜 Scan history
- 📈 Security analytics
- 🔄 Monitor security posture
- 📄 Export security reports
"""
    )
    st.divider()
    st.success("Database connected" if DATABASE_AVAILABLE else "Database unavailable")
    if ENGINE_AVAILABLE:
        st.success("Assessment engine ready")
    elif FALLBACK_SCANNERS_AVAILABLE:
        st.warning("Using scanner fallback")
    else:
        st.error("Assessment engine unavailable")
    st.divider()
    st.caption("Only scan systems you own or have explicit authorization to test.")

# ============================================================
# HERO
# ============================================================

st.markdown(
    """
<div class="vigil-hero">
<div class="vigil-title">🔐 WORLD <span class="green">MONITOR</span> SECURITY</div>
<div class="vigil-subtitle">UNIFIED WEB SECURITY ASSESSMENT & THREAT INTELLIGENCE</div>
<div class="vigil-ready">● SYSTEM READY</div>
</div>
""",
    unsafe_allow_html=True,
)

# ============================================================
# TARGET CONFIGURATION
# ============================================================

st.markdown('<div class="vigil-section">TARGET CONFIGURATION</div>', unsafe_allow_html=True)

target_url = st.text_input(
    "Target URL",
    value=st.session_state.last_target or "http://localhost:3000",
    placeholder="https://example.com",
    help="Enter a URL for a system you own or have explicit authorization to test.",
)

scan_col, warning_col = st.columns([1, 2.5], gap="medium")

with scan_col:
    scan_button = st.button("🚀 SCAN", type="primary", use_container_width=True)

with warning_col:
    st.warning("⚠️ Only scan systems you own or have explicit authorization to test.")

# ============================================================
# RUN SCAN
# ============================================================

if scan_button:
    cleaned = normalize_url(target_url)
    if not cleaned:
        st.error("Please enter a valid HTTP or HTTPS URL.")
    else:
        st.session_state.scan_started = True
        st.session_state.last_target = cleaned
        previous_scan = find_previous_scan(cleaned)
        with st.spinner("Running security assessment..."):
            try:
                started = time.perf_counter()
                scan_result = perform_assessment(cleaned)
                elapsed = round((time.perf_counter() - started) * 1000, 2)
                if get_response_time(scan_result) is None:
                    scan_result["response_time"] = elapsed
                st.session_state.result = scan_result
                st.session_state.last_scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                if DATABASE_AVAILABLE:
                    try:
                        save_scan(scan_result)
                    except Exception as exc:
                        st.warning(f"Scan completed but could not be saved: {exc}")
                if previous_scan:
                    comparison = compare_results(previous_scan["result"], scan_result)
                    if comparison["status"] == "Improved":
                        st.success(f"🟢 Security improved by {abs(comparison['score_change'])} risk points.")
                    elif comparison["status"] == "Worsened":
                        st.error(f"🔴 Risk increased by {comparison['score_change']} points.")
                    else:
                        st.info("🟡 Security posture is unchanged.")
            except Exception as exc:
                st.session_state.result = None
                st.error("Unable to complete the security assessment.")
                with st.expander("Technical error details"):
                    st.code(str(exc))

# ============================================================
# RESULT
# ============================================================

result = st.session_state.result

if not isinstance(result, dict):
    st.markdown(
        """
<div style="margin-top:35px;padding:30px;background:#08100d;border:1px solid #17382d;border-radius:15px;text-align:center">
<div style="font-size:40px">🛡️</div>
<h3>READY FOR SECURITY ASSESSMENT</h3>
<p style="color:#7e9c92">Enter an authorized target above and click SCAN to begin.</p>
</div>
""",
        unsafe_allow_html=True,
    )
else:
    findings = get_findings(result)
    risk = get_risk(result)
    counts = severity_counts(findings)
    status = get_status_code(result)
    response = get_response_time(result)
    final_url = get_final_url(result)
    target = result.get("target", target_url)

    # ========================================================
    # SECURITY OVERVIEW
    # ========================================================

    st.markdown('<div class="vigil-section">SECURITY OVERVIEW</div>', unsafe_allow_html=True)
    cols = st.columns(4, gap="medium")
    values = [
        ("RISK SCORE", risk["score"], "metric-red"),
        ("RISK RATING", risk["rating"], "metric-orange" if risk["rating"] == "Medium" else "metric-red" if risk["rating"] in ("Critical","High") else "metric-green"),
        ("FINDINGS", len(findings), "metric-blue"),
        ("HTTP STATUS", status if status is not None else "N/A", "metric-green" if isinstance(status,int) and status < 400 else "metric-red"),
    ]
    for col, (label, value, cls) in zip(cols, values):
        with col:
            st.markdown(
                f'<div class="metric-card"><div class="metric-label">{label}</div><div class="metric-value {cls}">{value}</div></div>',
                unsafe_allow_html=True,
            )

    # ========================================================
    # SEVERITY
    # ========================================================

    st.markdown('<div class="vigil-section">SEVERITY SUMMARY</div>', unsafe_allow_html=True)
    s_cols = st.columns(4)
    for col, label in zip(s_cols, ["Critical","High","Medium","Low"]):
        with col:
            st.metric(label, counts[label])

    # ========================================================
    # COMMAND CENTER
    # ========================================================

    st.markdown('<div class="vigil-section">SECURITY COMMAND CENTER</div>', unsafe_allow_html=True)
    checks = safe_dict(result.get("checks"))
    command_cols = st.columns(5)
    for col, (icon, name, key) in zip(
        command_cols,
        [("🛡️","HTTP HEADERS","headers"),("🌐","CORS","cors"),("🍪","COOKIES","cookies"),("🔐","TLS / HTTPS","tls"),("⚙️","SECURITY","security")]
    ):
        issue_count = len(get_findings(safe_dict(checks.get(key))))
        with col:
            st.markdown(
                f'<div class="command-card"><div class="command-icon">{icon}</div><div class="command-name">{name}</div><div class="{"status-bad" if issue_count else "status-ok"}">{"🔴 " + str(issue_count) + " ISSUE(S)" if issue_count else "🟢 OK"}</div></div>',
                unsafe_allow_html=True,
            )

    # ========================================================
    # TARGET INTELLIGENCE
    # ========================================================

    st.markdown('<div class="vigil-section">TARGET INTELLIGENCE</div>', unsafe_allow_html=True)
    i1, i2 = st.columns(2)
    with i1:
        st.info(f"**Target:** {target}\n\n**Final URL:** {final_url}\n\n**HTTP Status:** {status or 'N/A'}")
    with i2:
        st.info(f"**Response Time:** {response if response is not None else 'N/A'} ms\n\n**HTTPS:** {'Enabled' if final_url.lower().startswith('https://') else 'Not Enabled'}\n\n**Last Scan:** {st.session_state.last_scan_time or 'N/A'}")

    # ========================================================
    # MONITORING
    # ========================================================

    st.markdown('<div class="vigil-section">SECURITY CHANGE MONITORING</div>', unsafe_allow_html=True)
    previous = find_previous_scan(target)
    if previous:
        previous_result = previous.get("result", {})
        comparison = compare_results(previous_result, result)
        delta = comparison["score_change"]
        if comparison["status"] == "Improved":
            box = "monitor-good"
            title = "🟢 SECURITY IMPROVED"
            text = f"Risk score decreased by {abs(delta)} points."
        elif comparison["status"] == "Worsened":
            box = "monitor-bad"
            title = "🔴 SECURITY WORSENED"
            text = f"Risk score increased by {delta} points."
        else:
            box = "monitor-neutral"
            title = "🟡 SECURITY UNCHANGED"
            text = "Risk score has not changed."
        st.markdown(
            f'<div class="{box}"><h3>{title}</h3><p>{text}</p><b>Previous:</b> {comparison["previous_score"]} ({comparison["previous_rating"]}) &nbsp; → &nbsp; <b>Current:</b> {comparison["current_score"]} ({comparison["current_rating"]})</div>',
            unsafe_allow_html=True,
        )
        st.write("Severity changes:", comparison["severity_changes"])
        if st.button("🔄 Re-scan Current Target", use_container_width=True):
            st.session_state.result = None
            st.rerun()
    else:
        st.info("No previous scan for this target. Run another scan later to track security changes.")

    # ========================================================
    # FINDINGS
    # ========================================================

    st.markdown('<div class="vigil-section">SECURITY FINDINGS</div>', unsafe_allow_html=True)
    if not findings:
        st.success("🎉 No security findings detected.")
    else:
        for index, finding in enumerate(findings, 1):
            sev = severity_of(finding)
            with st.expander(f"{index}. {finding_name(finding)} — {sev}"):
                st.markdown(f"**Severity:** {sev}")
                st.write(finding_description(finding))
                st.info(finding_recommendation(finding))

    # ========================================================
    # RECOMMENDATIONS
    # ========================================================

    st.markdown('<div class="vigil-section">RECOMMENDATIONS</div>', unsafe_allow_html=True)
    recommendations = []
    for finding in findings:
        rec = finding_recommendation(finding)
        if rec not in recommendations:
            recommendations.append(rec)
    if recommendations:
        for rec in recommendations:
            st.markdown(f'<div class="recommendation">🛡️ {html_escape(rec)}</div>', unsafe_allow_html=True)
    else:
        st.success("No immediate remediation recommendations.")

    # ========================================================
    # REPORTS
    # ========================================================

    st.markdown('<div class="vigil-section">REPORTS</div>', unsafe_allow_html=True)
    r1, r2, r3 = st.columns(3)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    with r1:
        st.download_button(
            "📄 Download JSON Report",
            data=make_json_bytes(result),
            file_name=f"vigil_security_{timestamp}.json",
            mime="application/json",
            use_container_width=True,
        )
    with r2:
        try:
            html_report = generate_html_report(result)
            st.download_button(
                "🌐 Download HTML Report",
                data=html_report.encode("utf-8"),
                file_name=f"vigil_security_{timestamp}.html",
                mime="text/html",
                use_container_width=True,
            )
        except Exception as exc:
            st.warning(f"HTML report unavailable: {exc}")
    with r3:
        try:
            pdf = create_pdf_report(result)
            st.download_button(
                "📑 Download PDF Report",
                data=pdf,
                file_name=f"vigil_security_{timestamp}.pdf",
                mime="application/pdf",
                use_container_width=True,
            )
        except Exception as exc:
            st.warning(f"PDF report unavailable: {exc}")

    # ========================================================
    # TECHNICAL DETAILS
    # ========================================================

    st.markdown('<div class="vigil-section">TECHNICAL DETAILS</div>', unsafe_allow_html=True)
    tabs = st.tabs(["🛡️ HTTP Headers","🌐 CORS","🍪 Cookies","🔐 TLS / HTTPS","⚙️ Security"])
    for tab, key in zip(tabs, ["headers","cors","cookies","tls","security"]):
        with tab:
            module = safe_dict(checks.get(key))
            st.subheader(key.upper())
            module_findings = get_findings(module)
            if module_findings:
                for finding in module_findings:
                    st.markdown(f"**{finding_name(finding)}** — {severity_of(finding)}")
                    st.write(finding_description(finding))
            else:
                st.success("No findings in this module.")
            with st.expander("View raw module data"):
                st.json(module)

    # ========================================================
    # RAW DATA
    # ========================================================

    st.markdown('<div class="vigil-section">RAW ASSESSMENT DATA</div>', unsafe_allow_html=True)
    with st.expander("📦 View Complete Assessment JSON"):
        st.json(result)

    if st.button("🔄 Clear Current Result", use_container_width=True):
        st.session_state.result = None
        st.rerun()

# ============================================================
# SCAN HISTORY
# ============================================================

st.markdown('<div class="vigil-section">SCAN HISTORY</div>', unsafe_allow_html=True)
history = []
if DATABASE_AVAILABLE:
    try:
        history = get_scan_history(50)
    except Exception as exc:
        st.warning(f"Unable to load scan history: {exc}")

if history:
    table = []
    for item in history:
        table.append({
            "ID": item.get("id"),
            "Target": item.get("target","Unknown"),
            "Risk Score": item.get("risk_score",0),
            "Risk Rating": item.get("risk_rating","Informational"),
            "Findings": item.get("findings_count",0),
            "HTTP": item.get("http_status","N/A"),
            "Response": item.get("response_time","N/A"),
            "Scan Time": item.get("scan_time",""),
        })
    st.dataframe(table, use_container_width=True, hide_index=True)
    ids = [x.get("id") for x in history if x.get("id") is not None]
    c1, c2, c3 = st.columns(3)
    with c1:
        selected_id = st.selectbox("Saved scan", ids, key="load_scan")
        if st.button("📂 Load Saved Scan", use_container_width=True):
            saved = get_scan(int(selected_id))
            if saved and isinstance(saved.get("result"), dict):
                st.session_state.result = saved["result"]
                st.session_state.last_target = saved["result"].get("target","")
                st.rerun()
    with c2:
        delete_id = st.selectbox("Delete scan", ids, key="delete_scan")
        if st.button("🗑️ Delete Selected Scan", use_container_width=True):
            if delete_scan(int(delete_id)):
                st.rerun()
    with c3:
        if st.button("🧹 Clear All History", use_container_width=True):
            clear_history()
            st.rerun()
else:
    st.info("No saved scans yet.")

# ============================================================
# ANALYTICS
# ============================================================

st.markdown('<div class="vigil-section">SECURITY ANALYTICS</div>', unsafe_allow_html=True)
if DATABASE_AVAILABLE:
    try:
        stats = get_history_statistics()
        a = st.columns(6)
        metrics = [
            ("TOTAL SCANS", stats.get("total_scans",0)),
            ("AVERAGE RISK", stats.get("average_risk",0)),
            ("CRITICAL", stats.get("critical",0)),
            ("HIGH", stats.get("high",0)),
            ("MEDIUM", stats.get("medium",0)),
            ("LOW", stats.get("low",0)),
        ]
        for col, (label, value) in zip(a, metrics):
            with col:
                st.metric(label, value)

        if history:
            oldest_first = list(reversed(history))
            risk_rows = [{"Scan": str(x.get("id")), "Risk Score": x.get("risk_score",0)} for x in oldest_first]
            finding_rows = [{"Scan": str(x.get("id")), "Findings": x.get("findings_count",0)} for x in oldest_first]
            st.markdown("### 📈 Risk Score Trend")
            st.line_chart(risk_rows, x="Scan", y="Risk Score")
            st.markdown("### 🔎 Findings Trend")
            st.line_chart(finding_rows, x="Scan", y="Findings")
            st.markdown("### 📊 Risk Distribution")
            st.bar_chart({
                "Critical": stats.get("critical",0),
                "High": stats.get("high",0),
                "Medium": stats.get("medium",0),
                "Low": stats.get("low",0),
            })
    except Exception as exc:
        st.info(f"Analytics unavailable: {exc}")
else:
    st.info("Database unavailable.")

# ============================================================
# SCAN COMPARISON
# ============================================================

st.markdown('<div class="vigil-section">SCAN COMPARISON</div>', unsafe_allow_html=True)
if DATABASE_AVAILABLE and len(history) >= 2:
    ids = [x.get("id") for x in history if x.get("id") is not None]
    ca, cb = st.columns(2)
    with ca:
        scan_a_id = st.selectbox("Select Scan A", ids, index=0, key="compare_a")
    with cb:
        scan_b_id = st.selectbox("Select Scan B", ids, index=1, key="compare_b")
    scan_a = get_scan(int(scan_a_id))
    scan_b = get_scan(int(scan_b_id))
    if scan_a and scan_b:
        ra = safe_dict(scan_a.get("result"))
        rb = safe_dict(scan_b.get("result"))
        comparison = compare_results(ra, rb)
        rows = []
        changes = comparison["severity_changes"]
        for metric, va, vb in [
            ("Risk Score", comparison["previous_score"], comparison["current_score"]),
            ("Critical", severity_counts(get_findings(ra))["Critical"], severity_counts(get_findings(rb))["Critical"]),
            ("High", severity_counts(get_findings(ra))["High"], severity_counts(get_findings(rb))["High"]),
            ("Medium", severity_counts(get_findings(ra))["Medium"], severity_counts(get_findings(rb))["Medium"]),
            ("Low", severity_counts(get_findings(ra))["Low"], severity_counts(get_findings(rb))["Low"]),
            ("Findings", comparison["previous_findings"], comparison["current_findings"]),
        ]:
            d = vb - va
            rows.append({"Metric": metric, f"Scan {scan_a_id}": va, f"Scan {scan_b_id}": vb, "Change": d})
        st.dataframe(rows, use_container_width=True, hide_index=True)
        if comparison["status"] == "Improved":
            st.success("🟢 Security posture improved between the selected scans.")
        elif comparison["status"] == "Worsened":
            st.error("🔴 Security posture worsened between the selected scans.")
        else:
            st.info("🟡 Security posture is unchanged.")
else:
    st.info("Run at least two scans to compare security posture.")

# ============================================================
# SYSTEM STATUS
# ============================================================

st.markdown('<div class="vigil-section">SYSTEM STATUS</div>', unsafe_allow_html=True)
s1, s2, s3 = st.columns(3)
with s1:
    st.success("🟢 Assessment Engine: READY" if ENGINE_AVAILABLE else ("🟡 Scanner Fallback: READY" if FALLBACK_SCANNERS_AVAILABLE else "🔴 Assessment Engine: UNAVAILABLE"))
with s2:
    st.success("🟢 Database: READY" if DATABASE_AVAILABLE else "🟡 Database: UNAVAILABLE")
with s3:
    try:
        import reportlab
        st.success("🟢 PDF Reports: READY")
    except Exception:
        st.warning("🟡 PDF Reports: INSTALL REPORTLAB")

# ============================================================
# FOOTER
# ============================================================

st.markdown(
    """
<div class="vigil-footer">
🔐 VIGIL SECURITY
<br><br>
Unified Web Security Assessment & Threat Intelligence
<br><br>
Scan only systems you own or have explicit authorization to test.
</div>
""",
    unsafe_allow_html=True,
)
