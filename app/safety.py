from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit

from fastapi import HTTPException


RFC1918_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8")
)


def validate_private_target(ip_text: str) -> str:
    """Accept only IPv4 literals in loopback/RFC1918; never resolve hostnames."""
    try:
        address = ipaddress.ip_address(ip_text)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="Target must be an IPv4 address literal; DNS names are not accepted.") from exc

    if not isinstance(address, ipaddress.IPv4Address):
        raise HTTPException(status_code=422, detail="Only IPv4 targets are supported in this lab profile.")

    allowed = any(address in network for network in RFC1918_NETWORKS)
    if not allowed or address.is_multicast or address.is_unspecified or address.is_link_local:
        raise HTTPException(status_code=403, detail="Target is outside the permitted loopback/RFC1918 scope.")

    return str(address)


def validate_target_url(url: str) -> None:
    """Defense-in-depth check for persisted targets before each run."""
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise HTTPException(status_code=400, detail="Invalid target URL.")
    if parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in {"", "/"}:
        raise HTTPException(status_code=400, detail="Target URL may not contain credentials, query, fragment, or custom path.")
    validate_private_target(parsed.hostname)
    if parsed.port is None or not 1024 <= parsed.port <= 65535:
        raise HTTPException(status_code=400, detail="Target port is outside the permitted range.")
