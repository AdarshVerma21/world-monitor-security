from typing import Dict, Any, List
from urllib.parse import urlparse

from scanner.headers import scan_headers
from scanner.cors import scan_cors
from scanner.cookies import scan_cookies
from scanner.tls import scan_tls
from scanner.security import scan_security


# ============================================================
# CONSTANTS
# ============================================================

RISK_WEIGHTS = {
    "Critical": 10,
    "High": 7,
    "Medium": 4,
    "Low": 1,
    "Informational": 0,
    "Info": 0,
}


# ============================================================
# URL VALIDATION
# ============================================================

def validate_target_url(target_url: str) -> bool:
    """
    Validate that the target is a usable HTTP/HTTPS URL.
    """

    if not isinstance(target_url, str):
        return False

    target_url = target_url.strip()

    if not target_url:
        return False

    try:
        parsed = urlparse(target_url)

        return (
            parsed.scheme in ("http", "https")
            and bool(parsed.netloc)
        )

    except Exception:
        return False


# ============================================================
# RISK CALCULATION
# ============================================================

def calculate_risk(
    findings: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """
    Calculate the overall security risk from all findings.

    Severity weights:

        Critical       = 10
        High           = 7
        Medium         = 4
        Low            = 1
        Informational  = 0
    """

    if not isinstance(findings, list):
        findings = []

    score = 0

    severity_counts = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Informational": 0,
    }

    for finding in findings:

        if not isinstance(finding, dict):
            continue

        severity = str(
            finding.get(
                "severity",
                "Low",
            )
        ).strip()

        # Normalize severity names
        normalized = severity.capitalize()

        if normalized == "Info":
            normalized = "Informational"

        weight = RISK_WEIGHTS.get(
            normalized,
            0,
        )

        score += weight

        if normalized in severity_counts:

            severity_counts[
                normalized
            ] += 1

    # --------------------------------------------------------
    # RISK RATING
    # --------------------------------------------------------

    if score >= 20:

        rating = "Critical"

    elif score >= 12:

        rating = "High"

    elif score >= 5:

        rating = "Medium"

    elif score > 0:

        rating = "Low"

    else:

        rating = "Informational"

    return {
        "score": score,
        "rating": rating,
        "severity_counts": severity_counts,
    }


# ============================================================
# RESULT NORMALIZATION
# ============================================================

def normalize_result(
    result: Any,
    module_name: str,
) -> Dict[str, Any]:
    """
    Make sure every scanner always returns a dictionary.

    This prevents errors when a scanner unexpectedly returns
    None or another invalid value.
    """

    if result is None:

        return {
            "module": module_name,
            "status": "error",
            "findings": [],
            "error": (
                f"{module_name} scanner returned no result."
            ),
        }

    if not isinstance(result, dict):

        return {
            "module": module_name,
            "status": "error",
            "findings": [],
            "error": (
                f"{module_name} scanner returned "
                f"an invalid result."
            ),
        }

    # Make sure findings always exists
    findings = result.get(
        "findings",
        [],
    )

    if not isinstance(
        findings,
        list,
    ):

        result["findings"] = []

    return result


# ============================================================
# SAFE SCANNER EXECUTION
# ============================================================

def run_scanner(
    scanner,
    target_url: str,
    module_name: str,
) -> Dict[str, Any]:
    """
    Execute an individual scanner safely.

    If a scanner crashes, the remaining scanners can still run.
    """

    try:

        result = scanner(
            target_url
        )

        return normalize_result(
            result,
            module_name,
        )

    except Exception as exc:

        return {
            "module": module_name,
            "status": "error",
            "findings": [],
            "error": str(exc),
        }


# ============================================================
# FINDING NORMALIZATION
# ============================================================

def normalize_findings(
    findings: Any,
) -> List[Dict[str, Any]]:
    """
    Normalize scanner findings into a consistent format.
    """

    if not isinstance(
        findings,
        list,
    ):

        return []

    normalized = []

    for finding in findings:

        if not isinstance(
            finding,
            dict,
        ):

            continue

        item = dict(
            finding
        )

        # ----------------------------------------------------
        # Severity
        # ----------------------------------------------------

        severity = str(
            item.get(
                "severity",
                "Low",
            )
        ).strip()

        normalized_severity = (
            severity.capitalize()
        )

        if normalized_severity == "Info":

            normalized_severity = (
                "Informational"
            )

        if normalized_severity not in (
            "Critical",
            "High",
            "Medium",
            "Low",
            "Informational",
        ):

            normalized_severity = "Low"

        item["severity"] = (
            normalized_severity
        )

        # ----------------------------------------------------
        # Common fields
        # ----------------------------------------------------

        if "title" not in item:

            item["title"] = (
                item.get(
                    "header"
                )
                or item.get(
                    "type"
                )
                or "Security Finding"
            )

        if "description" not in item:

            item["description"] = (
                item.get(
                    "message"
                )
                or "No description available."
            )

        if "evidence" not in item:

            item["evidence"] = (
                item.get(
                    "details"
                )
                or "No evidence available."
            )

        normalized.append(
            item
        )

    return normalized


# ============================================================
# RUN COMPLETE ASSESSMENT
# ============================================================

def run_assessment(
    target_url: str,
) -> Dict[str, Any]:
    """
    Run the complete World Monitor Security assessment.

    The assessment includes:

        1. HTTP Headers
        2. CORS
        3. Cookies
        4. TLS / HTTPS
        5. Security configuration

    Each scanner is executed independently so that one failed
    module does not stop the complete assessment.
    """

    # ========================================================
    # VALIDATE TARGET
    # ========================================================

    target_url = (
        target_url.strip()
        if isinstance(
            target_url,
            str,
        )
        else ""
    )

    if not validate_target_url(
        target_url
    ):

        return {
            "target": target_url,
            "risk": {
                "score": 0,
                "rating": "Informational",
                "severity_counts": {
                    "Critical": 0,
                    "High": 0,
                    "Medium": 0,
                    "Low": 0,
                    "Informational": 0,
                },
            },
            "findings": [
                {
                    "title": "Invalid Target URL",
                    "severity": "Low",
                    "description": (
                        "The supplied target URL is not "
                        "a valid HTTP or HTTPS URL."
                    ),
                    "evidence": target_url,
                }
            ],
            "checks": {},
            "assessment_status": "invalid_target",
        }

    # ========================================================
    # RUN SCANNERS
    # ========================================================

    header_result = run_scanner(
        scan_headers,
        target_url,
        "headers",
    )

    cors_result = run_scanner(
        scan_cors,
        target_url,
        "cors",
    )

    cookie_result = run_scanner(
        scan_cookies,
        target_url,
        "cookies",
    )

    tls_result = run_scanner(
        scan_tls,
        target_url,
        "tls",
    )

    security_result = run_scanner(
        scan_security,
        target_url,
        "security",
    )

    # ========================================================
    # NORMALIZE FINDINGS
    # ========================================================

    header_findings = normalize_findings(
        header_result.get(
            "findings",
            [],
        )
    )

    cors_findings = normalize_findings(
        cors_result.get(
            "findings",
            [],
        )
    )

    cookie_findings = normalize_findings(
        cookie_result.get(
            "findings",
            [],
        )
    )

    tls_findings = normalize_findings(
        tls_result.get(
            "findings",
            [],
        )
    )

    security_findings = normalize_findings(
        security_result.get(
            "findings",
            [],
        )
    )

    # ========================================================
    # COMBINE FINDINGS
    # ========================================================

    findings = (
        header_findings
        + cors_findings
        + cookie_findings
        + tls_findings
        + security_findings
    )

    # ========================================================
    # CALCULATE RISK
    # ========================================================

    risk = calculate_risk(
        findings
    )

    # ========================================================
    # MODULE STATUS
    # ========================================================

    module_errors = []

    scanner_results = {
        "headers": header_result,
        "cors": cors_result,
        "cookies": cookie_result,
        "tls": tls_result,
        "security": security_result,
    }

    for module_name, module_result in (
        scanner_results.items()
    ):

        if (
            module_result.get(
                "status"
            )
            == "error"
        ):

            module_errors.append(
                module_name
            )

    # ========================================================
    # ASSESSMENT STATUS
    # ========================================================

    if module_errors:

        assessment_status = (
            "completed_with_errors"
        )

    else:

        assessment_status = "completed"

    # ========================================================
    # RETURN COMPLETE ASSESSMENT
    # ========================================================

    return {
        "target": target_url,

        "risk": risk,

        "findings": findings,

        "checks": scanner_results,

        "assessment_status": (
            assessment_status
        ),

        "scanner_errors": module_errors,
    }