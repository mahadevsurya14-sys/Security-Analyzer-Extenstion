"""
Security Analyzer - SSRF Guard & Target URL Validator
Strictly enforces IP filtering and network boundaries to prevent
Server-Side Request Forgery (SSRF) vulnerabilities.
"""

import ipaddress
import socket
from urllib.parse import urlparse
from typing import Tuple


BLOCKED_HOSTNAMES = {
    "localhost",
    "metadata.google.internal",
    "instance-data",
    "169.254.169.254",
}


class SSRFValidationError(Exception):
    """Raised when a target URL fails SSRF security validation."""
    pass


def validate_target_url(target_url: str) -> Tuple[bool, str, str]:
    """
    Validates a target URL against SSRF threats.
    
    Verifies:
    1. Scheme is strictly http or https.
    2. Hostname does not match known cloud metadata endpoints.
    3. Resolved IP addresses are strictly public routable IPs
       (rejects loopback, private RFC 1918, link-local, multicast, reserved).

    Returns:
        Tuple of (is_valid: bool, resolved_ip: str, message: str)
    Raises:
        SSRFValidationError if target fails validation.
    """
    if not target_url or not isinstance(target_url, str):
        raise SSRFValidationError("Target URL must be a non-empty string.")

    target_url = target_url.strip()
    try:
        parsed = urlparse(target_url)
    except Exception as e:
        raise SSRFValidationError(f"Invalid URL structure: {e}")

    scheme = (parsed.scheme or "").lower()
    if scheme not in ("http", "https"):
        raise SSRFValidationError(f"Forbidden URL scheme '{scheme}'. Only HTTP and HTTPS are permitted.")

    hostname = (parsed.hostname or "").lower()
    if not hostname:
        raise SSRFValidationError("Missing hostname in target URL.")

    # 1. Check blocked hostnames
    if hostname in BLOCKED_HOSTNAMES or hostname.endswith(".internal") or hostname.endswith(".local"):
        raise SSRFValidationError(f"Target host '{hostname}' is blocked by SSRF policy.")

    # 2. Resolve DNS to check all underlying IP addresses
    port = parsed.port or (443 if scheme == "https" else 80)
    try:
        addr_info = socket.getaddrinfo(hostname, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise SSRFValidationError(f"Unable to resolve host '{hostname}': {e}")
    except Exception as e:
        raise SSRFValidationError(f"DNS resolution failure: {e}")

    resolved_ips = []
    for family, socktype, proto, canonname, sockaddr in addr_info:
        ip_str = sockaddr[0]
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            raise SSRFValidationError(f"Invalid resolved IP format: {ip_str}")

        # Check against private, loopback, link-local, and reserved ranges
        if ip_obj.is_loopback:
            raise SSRFValidationError(f"Resolved IP {ip_str} is a loopback address.")
        if ip_obj.is_private:
            raise SSRFValidationError(f"Resolved IP {ip_str} belongs to a private network (RFC 1918).")
        if ip_obj.is_link_local:
            raise SSRFValidationError(f"Resolved IP {ip_str} is a link-local address.")
        if ip_obj.is_multicast:
            raise SSRFValidationError(f"Resolved IP {ip_str} is a multicast address.")
        if ip_obj.is_reserved:
            raise SSRFValidationError(f"Resolved IP {ip_str} is an IETF reserved address.")

        # Specific AWS / cloud link-local metadata range (169.254.0.0/16)
        if isinstance(ip_obj, ipaddress.IPv4Address) and ip_str.startswith("169.254."):
            raise SSRFValidationError(f"Resolved IP {ip_str} is in cloud metadata link-local range.")

        resolved_ips.append(ip_str)

    if not resolved_ips:
        raise SSRFValidationError(f"No routable IP found for hostname '{hostname}'.")

    primary_ip = resolved_ips[0]
    return True, primary_ip, f"Target {hostname} ({primary_ip}) verified safe."
