import requests
from typing import Dict, Any


def scan_cookies(target_url: str) -> Dict[str, Any]:
    """Check cookies for common security attributes."""

    try:
        response = requests.get(
            target_url,
            timeout=10,
            allow_redirects=True,
        )

        findings = []

        for cookie in response.cookies:

            if not cookie.secure:
                findings.append({
                    "type": "insecure_cookie",
                    "cookie": cookie.name,
                    "severity": "Medium",
                    "description": "Cookie does not use the Secure attribute.",
                    "evidence": (
                        f"Cookie '{cookie.name}' was set without Secure."
                    ),
                })

            if not cookie.has_nonstandard_attr("HttpOnly"):
                findings.append({
                    "type": "missing_httponly",
                    "cookie": cookie.name,
                    "severity": "Medium",
                    "description": "Cookie does not use HttpOnly.",
                    "evidence": (
                        f"Cookie '{cookie.name}' was set without HttpOnly."
                    ),
                })

        return {
            "target": target_url,
            "cookies": [
                {
                    "name": cookie.name,
                    "secure": cookie.secure,
                    "httponly": cookie.has_nonstandard_attr("HttpOnly"),
                }
                for cookie in response.cookies
            ],
            "findings": findings,
            "error": None,
        }

    except requests.RequestException as exc:
        return {
            "target": target_url,
            "cookies": [],
            "findings": [],
            "error": str(exc),
        }