import socket
import ssl
from typing import Dict, Any
from urllib.parse import urlparse


def scan_tls(target_url: str) -> Dict[str, Any]:
    """Safely inspect TLS configuration for HTTPS targets."""

    parsed = urlparse(target_url)

    if parsed.scheme != "https":
        return {
            "target": target_url,
            "is_https": False,
            "tls_version": None,
            "certificate_valid": None,
            "findings": [
                {
                    "type": "no_https",
                    "severity": "High",
                    "description": "The target is not using HTTPS.",
                    "evidence": f"Target scheme is '{parsed.scheme}'.",
                }
            ],
            "error": None,
        }

    hostname = parsed.hostname
    port = parsed.port or 443

    try:
        context = ssl.create_default_context()

        with socket.create_connection(
            (hostname, port),
            timeout=10,
        ) as sock:

            with context.wrap_socket(
                sock,
                server_hostname=hostname,
            ) as tls_socket:

                certificate = tls_socket.getpeercert()

                return {
                    "target": target_url,
                    "is_https": True,
                    "tls_version": tls_socket.version(),
                    "cipher": tls_socket.cipher()[0]
                    if tls_socket.cipher()
                    else None,
                    "certificate_valid": bool(certificate),
                    "findings": [],
                    "error": None,
                }

    except (socket.error, ssl.SSLError, ValueError) as exc:
        return {
            "target": target_url,
            "is_https": True,
            "tls_version": None,
            "cipher": None,
            "certificate_valid": False,
            "findings": [
                {
                    "type": "tls_error",
                    "severity": "High",
                    "description": "Unable to establish a valid TLS connection.",
                    "evidence": str(exc),
                }
            ],
            "error": str(exc),
        }