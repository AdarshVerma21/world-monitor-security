import json
from datetime import datetime


def generate_json_report(result):
    """
    Convert the complete assessment result into
    downloadable JSON.
    """
    return json.dumps(
        result,
        indent=2,
        ensure_ascii=False
    )


def generate_html_report(result):
    """
    Generate a standalone HTML security assessment report.
    """

    target = result.get("target", "Unknown")
    risk = result.get("risk", {})

    score = risk.get("score", 0)
    rating = risk.get("rating", "Unknown")

    findings = result.get("findings", [])

    checks = result.get("checks", {})

    headers = checks.get("headers", {})
    cors = checks.get("cors", {})
    cookies = checks.get("cookies", {})
    tls = checks.get("tls", {})
    security = checks.get("security", {})

    generated_at = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    finding_rows = ""

    for index, finding in enumerate(findings, start=1):

        severity = finding.get(
            "severity",
            "Unknown"
        )

        title = (
            finding.get("title")
            or finding.get("header")
            or finding.get("type")
            or "Security Finding"
        )

        description = finding.get(
            "description",
            "No description available."
        )

        evidence = finding.get(
            "evidence",
            "No evidence available."
        )

        finding_rows += f"""
        <div class="finding">
            <h3>{index}. {title}</h3>

            <p>
                <strong>Severity:</strong>
                <span class="severity">
                    {severity}
                </span>
            </p>

            <p>
                <strong>Description:</strong>
                {description}
            </p>

            <p>
                <strong>Evidence:</strong>
            </p>

            <pre>{evidence}</pre>
        </div>
        """

    def module_status(module):
        if not module:
            return "UNKNOWN"

        module_findings = module.get(
            "findings",
            []
        )

        if module_findings:
            return f"{len(module_findings)} ISSUE(S)"

        return "OK"

    return f"""
<!DOCTYPE html>

<html lang="en">

<head>

<meta charset="UTF-8">

<meta name="viewport"
      content="width=device-width, initial-scale=1.0">

<title>
World Monitor Security Report
</title>

<style>

* {{
    box-sizing: border-box;
}}

body {{
    margin: 0;
    padding: 40px;

    background: #050807;
    color: #e8eeee;

    font-family:
        Arial,
        Helvetica,
        sans-serif;
}}

.container {{
    max-width: 1100px;
    margin: auto;
}}

.header {{
    padding: 35px;

    border: 1px solid #17382d;
    border-radius: 18px;

    background: #09130f;
}}

.logo {{
    font-size: 32px;
    font-weight: 800;
    letter-spacing: 5px;
}}

.logo span {{
    color: #20f477;
}}

.subtitle {{
    margin-top: 12px;
    color: #8da69d;
    letter-spacing: 2px;
}}

.section {{
    margin-top: 35px;
}}

.section-title {{
    font-size: 22px;
    letter-spacing: 3px;
    margin-bottom: 18px;
}}

.grid {{
    display: grid;
    grid-template-columns:
        repeat(4, 1fr);

    gap: 15px;
}}

.card {{
    padding: 25px;

    border: 1px solid #17382d;
    border-radius: 14px;

    background: #08100d;
}}

.label {{
    color: #75938a;
    font-size: 12px;
    letter-spacing: 2px;
}}

.value {{
    margin-top: 10px;

    font-size: 30px;
    font-weight: 700;
}}

.critical {{
    color: #ff4757;
}}

.high {{
    color: #ff7043;
}}

.medium {{
    color: #ffb52e;
}}

.low {{
    color: #ffd84d;
}}

.ok {{
    color: #20f477;
}}

.target {{
    padding: 20px;

    border-radius: 12px;

    background: #0b1511;

    font-family: monospace;

    word-break: break-all;
}}

.modules {{
    display: grid;

    grid-template-columns:
        repeat(5, 1fr);

    gap: 12px;
}}

.module {{
    padding: 20px;

    border: 1px solid #17382d;
    border-radius: 12px;

    background: #08100d;

    text-align: center;
}}

.finding {{
    margin-top: 15px;

    padding: 22px;

    border: 1px solid #26342f;
    border-radius: 12px;

    background: #0a100e;
}}

.finding h3 {{
    margin-top: 0;
}}

.severity {{
    font-weight: 700;
}}

pre {{
    padding: 15px;

    overflow-x: auto;

    border-radius: 8px;

    background: #11161c;

    color: #d5ddd9;
}}

.footer {{
    margin-top: 50px;

    padding-top: 20px;

    border-top: 1px solid #17382d;

    color: #687d76;

    text-align: center;
}}

@media(max-width: 800px) {{

    body {{
        padding: 15px;
    }}

    .grid {{
        grid-template-columns:
            repeat(2, 1fr);
    }}

    .modules {{
        grid-template-columns:
            repeat(2, 1fr);
    }}

}}

</style>

</head>

<body>

<div class="container">

<div class="header">

<div class="logo">
🔐 WORLD <span>MONITOR</span> SECURITY
</div>

<div class="subtitle">
AUTHORIZED SECURITY ASSESSMENT REPORT
</div>

<p>
Generated: {generated_at}
</p>

</div>


<div class="section">

<div class="section-title">
TARGET
</div>

<div class="target">
{target}
</div>

</div>


<div class="section">

<div class="section-title">
SECURITY OVERVIEW
</div>

<div class="grid">

<div class="card">

<div class="label">
RISK SCORE
</div>

<div class="value">
{score}
</div>

</div>


<div class="card">

<div class="label">
RISK RATING
</div>

<div class="value critical">
{rating}
</div>

</div>


<div class="card">

<div class="label">
FINDINGS
</div>

<div class="value">
{len(findings)}
</div>

</div>


<div class="card">

<div class="label">
HTTP STATUS
</div>

<div class="value">
{headers.get("status_code", "N/A")}
</div>

</div>

</div>

</div>


<div class="section">

<div class="section-title">
SECURITY MODULES
</div>

<div class="modules">

<div class="module">
🛡️
<br><br>
HTTP HEADERS
<br><br>
<strong>
{module_status(headers)}
</strong>
</div>

<div class="module">
🌐
<br><br>
CORS
<br><br>
<strong>
{module_status(cors)}
</strong>
</div>

<div class="module">
🍪
<br><br>
COOKIES
<br><br>
<strong>
{module_status(cookies)}
</strong>
</div>

<div class="module">
🔐
<br><br>
TLS / HTTPS
<br><br>
<strong>
{module_status(tls)}
</strong>
</div>

<div class="module">
⚙️
<br><br>
SECURITY
<br><br>
<strong>
{module_status(security)}
</strong>
</div>

</div>

</div>


<div class="section">

<div class="section-title">
SECURITY FINDINGS
</div>

{finding_rows if finding_rows else
"<p>No security findings detected.</p>"}

</div>


<div class="footer">

WORLD MONITOR SECURITY<br>

Authorized security assessment only.

</div>

</div>

</body>

</html>
"""