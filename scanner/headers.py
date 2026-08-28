import requests
from typing import Dict, Any


SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "severity": "Medium",
        "description": "Helps prevent XSS and other code-injection attacks.",
    },
    "X-Content-Type-Options": {
        "severity": "Low",
        "description": "Prevents MIME-type sniffing.",
    },
    "X-Frame-Options": {
        "severity": "Medium",
        "description": "Helps prevent clickjacking attacks.",
    },
    "Referrer-Policy": {
        "severity": "Low",
        "description": "Controls how much referrer information is sent.",
    },
    "Permissions-Policy": {
        "severity": "Low",
        "description": "Controls access to browser features.",
    },
}


def scan_headers(target_url: str) -> Dict[str, Any]:
    """
    Perform a safe HTTP GET request and analyze security headers.
    Intended for authorized/local security testing.
    """

    try:
        response = requests.get(
            target_url,
            timeout=10,
            allow_redirects=True,
        )

        headers = dict(response.headers)

        findings = []

        for header, metadata in SECURITY_HEADERS.items():
            if header not in headers:
                findings.append(
                    {
                        "type": "missing_security_header",
                        "header": header,
                        "severity": metadata["severity"],
                        "description": metadata["description"],
                        "evidence": f"{header} was not present in the response.",
                    }
                )

        return {
            "target": target_url,
            "status_code": response.status_code,
            "final_url": response.url,
            "response_time_ms": round(response.elapsed.total_seconds() * 1000, 2),
            "headers": headers,
            "findings": findings,
            "error": None,
        }

    except requests.RequestException as exc:
        return {
            "target": target_url,
            "status_code": None,
            "final_url": None,
            "response_time_ms": None,
            "headers": {},
            "findings": [],
            "error": str(exc),
        }