"""
Attribution layer (Phase 5).

- Public Suffix List based same-party checks (fixes the last-two-labels
  bug on .co.uk / .com.pk and private suffixes like blogspot.com).
- Disconnect entity resolution: domain → owning company + category
  (Advertising, Analytics, Fingerprinting, Social, …).
- CNAME cloaking detection: subdomains that resolve to tracker
  infrastructure instead of their owner's.

Lists:
    data/disconnect_services.json — Disconnect Tracking Protection list
    (categories → company → url pattern → domains), vendored offline.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
from typing import Optional

logger = logging.getLogger(__name__)

# ─── PSL extraction (offline bundled snapshot, no network on first use) ─
try:
    import tldextract
    _extract = tldextract.TLDExtract(suffix_list_urls=())  # bundled PSL
    _HAS_TLD = True
except Exception:  # pragma: no cover - tldextract optional at runtime
    _extract = None
    _HAS_TLD = False
    logger.warning("tldextract unavailable — falling back to naive "
                   "registrable-domain logic (fixes .co.uk only partially)")

_DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
_DISCONNECT_FILE = os.path.join(_DATA_DIR, "disconnect_services.json")

# Categories whose domains count as "tracking" for is_tracker_domain().
# Entity attribution (entity_for) loads ALL categories — company
# attribution is wanted even for Content/Email/Consent managers.
# Anti-fraud excluded (ambiguous); ConsentManagers excluded (they ARE
# the consent machinery, not trackers).
TRACKER_CATEGORIES = {
    "Advertising", "Analytics", "FingerprintingGeneral",
    "FingerprintingInvasive", "Social", "Cryptomining",
    "Email", "EmailAggressive",
}

# domain → {"company": str, "category": str}
_DOMAIN_ENTITY: dict[str, dict] = {}
_disconnect_loaded = False

# CNAME cache: host → Optional[cname_target]
_CNAME_CACHE: dict[str, Optional[str]] = {}


def _load_disconnect():
    global _disconnect_loaded
    if _disconnect_loaded:
        return
    _disconnect_loaded = True
    try:
        with open(_DISCONNECT_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        logger.warning(f"Disconnect list not loaded: {e}")
        return
    n = 0
    for category, companies in (data.get("categories") or {}).items():
        # Load ALL categories — attribution wants companies regardless
        # of category; is_tracker_domain filters by TRACKER_CATEGORIES.
        # Format: category → [ {company: {url_pattern: [domains]}}, ... ]
        entries = companies if isinstance(companies, list) else []
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            for company, patterns in entry.items():
                if not isinstance(patterns, dict):
                    continue
                for _pattern, domains in patterns.items():
                    if not isinstance(domains, list):
                        continue
                    for dom in domains:
                        d = str(dom).lower().lstrip(".")
                        if not d:
                            continue
                        # first-writer wins (category order: Advertising
                        # before Content, so primary purpose sticks)
                        if d not in _DOMAIN_ENTITY:
                            _DOMAIN_ENTITY[d] = {"company": company,
                                                 "category": category}
                            n += 1
    logger.info(f"Disconnect entity list loaded: {n} domains, "
                f"{len(_DOMAIN_ENTITY)} unique")


def registrable(host: str) -> str:
    """Registrable (eTLD+1) domain for a host; '' when none (IPs,
    'localhost'). Strips port first."""
    h = _strip_host(host)
    if not h:
        return ""
    if _HAS_TLD:
        try:
            ext = _extract(h)
            reg = ext.top_domain_under_public_suffix
            # IPs / localhost / bare unknown TLDs → no registrable domain
            if not reg or reg == h and not ext.suffix:
                return "" if _looks_like_ip(h) or h == "localhost" else h
            return reg
        except Exception:
            pass
    # naive fallback (original behavior)
    parts = h.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return ""


def _strip_host(host: str) -> str:
    """Strip port / scheme / trailing dot from a netloc or URL-ish host."""
    h = (host or "").strip().lower()
    if "://" in h:
        from urllib.parse import urlparse
        h = urlparse(h).netloc or h
    # strip port (careful with IPv6 brackets)
    if h.startswith("["):
        end = h.find("]")
        if end != -1:
            return h[:end + 1]
    if h.count(":") == 1:
        h = h.split(":", 1)[0]
    return h.rstrip(".")


def _looks_like_ip(h: str) -> bool:
    if h.count(".") == 3:
        parts = h.split(".")
        if all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
            return True
    return h.endswith(".ip6.arpa") or h == "::1"


def is_same_party(a: str, b: str) -> bool:
    """
    PSL-based party check. Hosts with a registrable domain compare on
    eTLD+1; IPs/localhost compare on exact (port-stripped) host — so
    localhost and 127.0.0.1 are *different* parties, matching how the
    testbed models cross-host sink servers.
    """
    ha, hb = _strip_host(a), _strip_host(b)
    if not ha or not hb:
        return False
    if ha == hb:
        return True
    ra, rb = registrable(ha), registrable(hb)
    if ra and rb:
        return ra == rb
    # one/both lack a registrable domain (IP, localhost, single-label)
    # → exact host comparison (port already stripped)
    return ha == hb


def entity_for(host: str) -> Optional[dict]:
    """Disconnect entity {company, category} for a host, or None."""
    _load_disconnect()
    h = _strip_host(host)
    if not h:
        return None
    if h in _DOMAIN_ENTITY:
        return dict(_DOMAIN_ENTITY[h])
    reg = registrable(h)
    if reg and reg in _DOMAIN_ENTITY:
        return dict(_DOMAIN_ENTITY[reg])
    # walk parent domains (cdn.x.example.com)
    parts = h.split(".")
    for i in range(1, max(0, len(parts) - 1)):
        cand = ".".join(parts[i:])
        if cand in _DOMAIN_ENTITY:
            return dict(_DOMAIN_ENTITY[cand])
    return None


def is_tracker_domain(host: str) -> bool:
    """True when the host appears in a tracking category of the
    Disconnect list (entity check, not just exact-domain membership)."""
    ent = entity_for(host)
    return bool(ent and ent.get("category") in TRACKER_CATEGORIES)


def resolve_cname(host: str, timeout: float = 1.5) -> Optional[str]:
    """
    Resolve the CNAME target of a host (for cloaking detection).
    Returns the canonical hostname or None (no CNAME / DNS failure /
    dig unavailable). Cached per process.
    """
    h = _strip_host(host)
    if not h or _looks_like_ip(h) or h == "localhost":
        return None
    if h in _CNAME_CACHE:
        return _CNAME_CACHE[h]
    target = None
    dig = shutil.which("dig")
    if dig:
        try:
            out = subprocess.run(
                [dig, "+short", "+time=1", "+tries=1", "CNAME", h],
                capture_output=True, text=True, timeout=timeout,
            ).stdout.strip()
            # dig may return a chain "a.example. b.example."
            if out:
                target = out.splitlines()[0].strip().rstrip(".")
                # skip degenerate self-references
                if target.lower() == h:
                    target = None
        except Exception:
            target = None
    _CNAME_CACHE[h] = target
    return target


def classify_cloaking(site_host: str, request_host: str) -> dict:
    """
    CNAME cloaking check: does request_host resolve via CNAME to
    infrastructure outside the site's registrable domain (optionally a
    known tracker)? Only meaningful for same-party-looking subdomains —
    callers decide when to spend the DNS lookup.
    """
    from app_config import DNS_CNAME_CHECKS
    out = {"cname": None, "cloaked": False, "cname_entity": None}
    if not DNS_CNAME_CHECKS:
        return out
    tgt = resolve_cname(request_host)
    if not tgt:
        return out
    out["cname"] = tgt
    # Cloaked when the CNAME leaves the site's registrable domain
    site_reg = registrable(site_host)
    tgt_reg = registrable(tgt) or tgt
    leaves_site = bool(site_reg) and tgt_reg != site_reg
    ent = entity_for(tgt)
    out["cname_entity"] = ent
    out["cloaked"] = bool(leaves_site and (ent or not is_same_party(site_host, tgt)))
    if out["cloaked"]:
        logger.info(f"  CNAME cloaking: {request_host} → {tgt} "
                    f"entity={ent}")
    return out
