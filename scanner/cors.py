import requests
from typing import Dict, Any


def scan_cors(target_url: str) -> Dict[str, Any]:
    """Safely inspect CORS response behavior."""

    try:
        response = requests.get(
            target_url,
            headers={
                "Origin": "https://security-test.invalid"
            },
            timeout=10,
            allow_redirects=True,
        )

        allow_origin = response.headers.get(
            "Access-Control-Allow-Origin"
        )

        allow_credentials = response.headers.get(
            "Access-Control-Allow-Credentials"
        )

        findings = []

        if allow_origin == "*":
            findings.append({
                "type": "cors_wildcard",
                "severity": "Medium",
                "title": "Wildcard CORS policy",
                "description": (
                    "The server allows requests from any origin."
                ),
                "evidence": (
                    "Access-Control-Allow-Origin: *"
                ),
            })

        if (
            allow_origin == "*"
            and allow_credentials
            and allow_credentials.lower() == "true"
        ):
            findings.append({
                "type": "cors_wildcard_credentials",
                "severity": "High",
                "title": "Wildcard CORS with credentials",
                "description": (
                    "Wildcard CORS combined with credentials "
                    "requires security review."
                ),
                "evidence": (
                    "Access-Control-Allow-Origin: * and "
                    "Access-Control-Allow-Credentials: true"
                ),
            })

        return {
            "target": target_url,
            "status_code": response.status_code,
            "allow_origin": allow_origin,
            "allow_credentials": allow_credentials,
            "findings": findings,
            "error": None,
        }

    except requests.RequestException as exc:
        return {
            "target": target_url,
            "status_code": None,
            "allow_origin": None,
            "allow_credentials": None,
            "findings": [],
            "error": str(exc),
        }