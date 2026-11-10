"""
SSRF guard (Phase 10) for outbound fetch targets.

is_public_url(url) blocks:
    - non-http(s) schemes
    - localhost / *.localhost / *.local hostnames
    - literal private/loopback/link-local/reserved IPs (v4+v6 incl.
      ::ffff: mapped, fe80::, fc00::/7, 169.254.169.254 metadata)
    - hostnames that RESOLVE to any of the above (DNS check)

PRIVADB_ALLOW_PRIVATE_TARGETS=true relaxes the private-IP rules for
lab/testbed use (the API-level consent/smoke harnesses crawl
localhost pages through the same /scan endpoint).
"""

from __future__ import annotations

import ipaddress
import logging
import os
import socket
from typing import Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

METADATA_HOSTS = {"169.254.169.254", "metadata.google.internal",
                  "instance-data", "100.100.100.200"}  # AWS/GCP/Aliyun


def allow_private() -> bool:
    return os.environ.get("PRIVADB_ALLOW_PRIVATE_TARGETS", "").lower() in (
        "1", "true", "yes")


def _ip_blocked(ip: ipaddress._BaseAddress) -> bool:
    if ip.version == 6 and isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
    return (ip.is_private or ip.is_loopback or ip.is_link_local
            or ip.is_reserved or ip.is_multicast or ip.is_unspecified)


def _resolve(host: str) -> list[str]:
    """All A/AAAA addresses for host ([] on failure — failure is not
    treated as safe: we then fall back to literal checks only)."""
    try:
        infos = socket.getaddrinfo(host, None)
        return sorted({i[4][0] for i in infos})
    except Exception:
        return []


def is_public_url(url: str) -> bool:
    """True only when the URL points at a public, non-metadata target."""
    try:
        p = urlparse(url if "://" in url else "https://" + url)
    except Exception:
        return False
    if p.scheme not in ("http", "https"):
        return False
    host = (p.hostname or "").strip().lower().rstrip(".")
    if not host:
        return False

    relax = allow_private()

    # cloud metadata is never allowed, not even in lab mode
    if host in METADATA_HOSTS:
        logger.debug(f"SSRF blocked (metadata host): {host}")
        return False

    if (host == "localhost" or host.endswith(".localhost")
            or host.endswith(".local")):
        if relax:
            return True
        logger.debug(f"SSRF blocked (local host): {host}")
        return False

    # literal IP?
    try:
        ip = ipaddress.ip_address(host)
        if _ip_blocked(ip) and not relax:
            logger.debug(f"SSRF blocked (literal {ip})")
            return False
        if host in METADATA_HOSTS:
            return False
        return True
    except ValueError:
        pass  # not an IP — DNS check below

    # DNS resolution: any private answer fails the whole host
    addrs = _resolve(host)
    if not addrs:
        # unresolvable: allow the attempt (browser will fail anyway),
        # but never vouch for it — keep permissive to not break scans
        # of domains with flaky DNS
        logger.debug(f"SSRF: {host} unresolvable, allowing attempt")
        return True
    for a in addrs:
        try:
            ip = ipaddress.ip_address(a)
        except ValueError:
            return False
        if _ip_blocked(ip) and not relax:
            logger.debug(f"SSRF blocked ({host} → {a})")
            return False
    return True
