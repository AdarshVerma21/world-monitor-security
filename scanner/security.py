import requests
from typing import Dict, Any, List


def scan_security(target_url: str) -> Dict[str, Any]:
    """
    Perform additional passive security configuration checks.

    Checks:
    - HSTS
    - Server information disclosure
    - HTTP methods
    - Redirect behavior

    Only use this scanner against systems you own
    or are authorized to assess.
    """

    result: Dict[str, Any] = {
        "target": target_url,
        "status_code": None,
        "findings": [],
        "error": None,
    }

    try:
        response = requests.get(
            target_url,
            timeout=10,
            allow_redirects=True,
        )

        result["status_code"] = response.status_code
        result["final_url"] = response.url

        headers = {
            key.lower(): value
            for key, value in response.headers.items()
        }

        findings: List[Dict[str, Any]] = []

        # ====================================================
        # HSTS
        # ====================================================

        if target_url.lower().startswith("https://"):

            if "strict-transport-security" not in headers:

                findings.append(
                    {
                        "type": "missing_hsts",
                        "severity": "Medium",
                        "title": "Missing HSTS",
                        "description": (
                            "The HTTPS target does not send a "
                            "Strict-Transport-Security header."
                        ),
                        "evidence": (
                            "Strict-Transport-Security header "
                            "was not present."
                        ),
                    }
                )

        # ====================================================
        # SERVER INFORMATION DISCLOSURE
        # ====================================================

        server_header = headers.get("server")

        if server_header:

            findings.append(
                {
                    "type": "server_information_disclosure",
                    "severity": "Low",
                    "title": "Server Information Disclosure",
                    "description": (
                        "The response exposes server information "
                        "through the Server HTTP header."
                    ),
                    "evidence": (
                        f"Server: {server_header}"
                    ),
                }
            )

        # ====================================================
        # X-POWERED-BY INFORMATION DISCLOSURE
        # ====================================================

        powered_by = headers.get("x-powered-by")

        if powered_by:

            findings.append(
                {
                    "type": "technology_information_disclosure",
                    "severity": "Low",
                    "title": "Technology Information Disclosure",
                    "description": (
                        "The application exposes technology "
                        "information through the X-Powered-By header."
                    ),
                    "evidence": (
                        f"X-Powered-By: {powered_by}"
                    ),
                }
            )

        # ====================================================
        # HTTP METHODS
        # ====================================================

        allow_header = headers.get("allow")

        if allow_header:

            methods = [
                method.strip().upper()
                for method in allow_header.split(",")
            ]

            dangerous_methods = [
                method
                for method in methods
                if method in {"PUT", "DELETE", "TRACE", "CONNECT"}
            ]

            if dangerous_methods:

                findings.append(
                    {
                        "type": "potentially_risky_http_methods",
                        "severity": "Medium",
                        "title": "Potentially Risky HTTP Methods",
                        "description": (
                            "The server advertises HTTP methods "
                            "that may require additional security review."
                        ),
                        "evidence": (
                            f"Allowed methods: {', '.join(methods)}"
                        ),
                    }
                )

        # ====================================================
        # REDIRECT ANALYSIS
        # ====================================================

        if response.history:

            redirect_chain = []

            for redirect in response.history:

                redirect_chain.append(
                    {
                        "status_code": redirect.status_code,
                        "url": redirect.url,
                        "location": redirect.headers.get(
                            "Location"
                        ),
                    }
                )

            result["redirect_chain"] = redirect_chain

            if len(response.history) > 3:

                findings.append(
                    {
                        "type": "long_redirect_chain",
                        "severity": "Low",
                        "title": "Long Redirect Chain",
                        "description": (
                            "The target uses multiple HTTP redirects "
                            "before reaching the final URL."
                        ),
                        "evidence": (
                            f"{len(response.history)} redirects detected."
                        ),
                    }
                )

        else:

            result["redirect_chain"] = []

        # ====================================================
        # FINAL RESULT
        # ====================================================

        result["findings"] = findings

    except requests.exceptions.Timeout:

        result["error"] = (
            "Connection timed out while scanning the target."
        )

    except requests.exceptions.RequestException as error:

        result["error"] = str(error)

    except Exception as error:

        result["error"] = str(error)

    return result