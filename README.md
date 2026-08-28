# 🔐 World Monitor Security

> A web security assessment and monitoring platform built with Python and Streamlit.

World Monitor Security is a defensive cybersecurity application designed to perform **authorized web security assessments**, identify common security configuration weaknesses, calculate an overall risk score, generate detailed reports, and track security posture over time.

The platform provides a centralized dashboard for analyzing HTTP security headers, CORS, cookies, TLS/HTTPS configuration, and additional security checks.

---

## ⚠️ Responsible Use

**Only scan systems that you own or have explicit authorization to test.**

This project is intended for:

- Security education
- Defensive security analysis
- Authorized penetration testing
- Web application configuration auditing
- Security monitoring
- Cybersecurity portfolio demonstrations

Do not use this application to scan systems without permission.

---

# 🚀 Features

## 🔎 Web Security Assessment

Enter an authorized target URL and run a security assessment from a single dashboard.

The application analyzes:

- HTTP security headers
- CORS configuration
- Cookie security
- TLS / HTTPS
- Additional security configuration checks

---

## 🛡️ HTTP Security Headers

The application checks for important HTTP security headers and identifies missing or insecure configurations.

Examples include:

- Content-Security-Policy
- X-Content-Type-Options
- X-Frame-Options
- Referrer-Policy

The dashboard displays:

- Severity
- Finding description
- Security impact
- Recommended remediation

---

## 🌐 CORS Analysis

The CORS module analyzes Cross-Origin Resource Sharing configuration and identifies potentially unsafe configurations.

It helps identify situations such as overly permissive cross-origin policies.

---

## 🍪 Cookie Security Analysis

The cookie scanner analyzes cookie security attributes and helps identify configuration weaknesses.

Relevant security attributes include:

- Secure
- HttpOnly
- SameSite

---

## 🔐 TLS / HTTPS Analysis

The TLS module checks transport security and reports whether HTTPS is enabled.

The dashboard can display:

- HTTPS status
- TLS information
- Transport security findings
- Response timing

---

# 📊 Risk Scoring

World Monitor Security calculates an overall risk score from discovered findings.

Severity weights:

| Severity | Weight |
|----------|-------:|
| Critical | 10 |
| High | 7 |
| Medium | 4 |
| Low | 1 |

Risk ratings are calculated from the resulting score:

| Score | Rating |
|------:|--------|
| 15+ | Critical |
| 8–14 | High |
| 4–7 | Medium |
| 1–3 | Low |
| 0 | Informational |

The dashboard provides a quick security posture overview using:

- Risk score
- Risk rating
- Total findings
- HTTP status

---

# 🎯 Security Dashboard

The dashboard provides a centralized security overview containing:

### Security Overview

- Risk Score
- Risk Rating
- Findings
- HTTP Status

### Severity Summary

- Critical findings
- High findings
- Medium findings
- Low findings

### Security Command Center

Dedicated modules for:

- HTTP Headers
- CORS
- Cookies
- TLS / HTTPS
- Security

---

# 🚨 Security Findings

Every detected issue is presented as a security finding.

Findings include information such as:

- Finding name
- Severity
- Description
- Security impact
- Recommended remediation

This makes the application useful not only for detection but also for understanding how security configurations can be improved.

---

# 💡 Security Recommendations

The application provides actionable recommendations for detected issues.

Examples include:

- Configure Content-Security-Policy
- Add X-Content-Type-Options
- Add X-Frame-Options
- Configure Referrer-Policy
- Enable HTTPS

Recommendations are displayed directly in the dashboard so users can quickly understand the next security improvement.

---

# 📄 Report Generation

World Monitor Security supports multiple report formats.

## JSON Report

Useful for:

- Automation
- Data processing
- Security pipelines
- Machine-readable results

## HTML Report

Useful for:

- Browser-based review
- Sharing assessment results
- Security documentation

## PDF Report

Useful for:

- Security documentation
- Client reports
- Project demonstrations
- Offline review

---

# 🗃️ Scan History

Scan results are stored using SQLite.

The application records information including:

- Target
- Risk score
- Risk rating
- Findings count
- HTTP status
- Response time
- Scan timestamp
- Complete assessment result

This allows previous assessments to be reviewed later.

---

# 📈 Security Trends

The application provides historical security analysis.

Available analytics include:

- Risk-score trends
- Findings trends
- Risk distribution
- Historical scan information

This makes it possible to observe how a target's security posture changes over time.

---

# 🔄 Scan Comparison

Multiple scans of the same authorized target can be compared.

The comparison can show:

- Previous risk score
- Current risk score
- Risk-score difference
- Previous risk rating
- Current risk rating
- Previous findings count
- Current findings count
- Security posture change

This helps determine whether security configuration has improved or degraded.

---

# 🚨 Security Change Monitoring

World Monitor Security can monitor changes between assessments.

It can identify whether the security posture has:

- 🟢 Improved
- 🔴 Worsened
- ⚪ Remained unchanged

This is useful for tracking security configuration changes after deployments or infrastructure updates.

---

# 🧰 Error Handling

The application includes defensive error handling to prevent common runtime failures.

Examples include:

- Empty scan results
- Invalid assessment results
- Missing result dictionaries
- Report generation failures
- Scanner failures
- Missing optional fields

The application safely handles cases where an assessment does not return a valid result.

---

# 🏗️ Architecture

The project uses a modular architecture.

```text
                         ┌─────────────────────┐
                         │     Streamlit UI    │
                         │       app.py        │
                         └──────────┬──────────┘
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │   Assessment Engine │
                         │      engine.py      │
                         └──────────┬──────────┘
                                    │
             ┌──────────────────────┼──────────────────────┐
             │                      │                      │
             ▼                      ▼                      ▼
      ┌────────────┐         ┌────────────┐         ┌────────────┐
      │   Headers  │         │    CORS    │         │  Cookies   │
      │   Scanner  │         │   Scanner  │         │   Scanner  │
      └────────────┘         └────────────┘         └────────────┘
             │                      │                      │
             └──────────────────────┼──────────────────────┘
                                    │
                           ┌────────▼────────┐
                           │   TLS Scanner   │
                           │  Security Scan  │
                           └────────┬────────┘
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │   Risk Calculation  │
                         └──────────┬──────────┘
                                    │
                  ┌─────────────────┼─────────────────┐
                  │                 │                 │
                  ▼                 ▼                 ▼
           ┌────────────┐    ┌────────────┐    ┌────────────┐
           │  Reports   │    │  Database  │    │  Analytics │
           │ JSON/HTML/ │    │   SQLite   │    │   Trends   │
           │    PDF     │    │            │    │ Comparison │
           └────────────┘    └────────────┘    └────────────┘
