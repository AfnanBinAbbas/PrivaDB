"""
Tracking detection engine for IndexedDB dynamic taint analysis.

Analyzes crawled data to find:
1. Potential tracking identifiers in IndexedDB
2. Exfiltration of those identifiers via network requests
3. First-party vs third-party classification
"""

import json
import math
import os
import re
import logging
from collections import Counter
from urllib.parse import urlparse, parse_qs, unquote

import app_config as config

logger = logging.getLogger(__name__)


# ─── Entropy Calculation ─────────────────────────────────────────────
def shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string. Higher = more random."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


# ─── Identifier Detection ───────────────────────────────────────────
def extract_potential_ids(value, path: str = "") -> list[dict]:
    """
    Recursively extract potential tracking identifiers from an IndexedDB value.

    Logic: any string value with length >= MIN_ID_LENGTH (8) is flagged
    as a potential identifier (length gate), then classified by pattern
    (UUID / hex / base64 / high-entropy) when possible.

    Returns list of dicts: {value, path, reason, entropy}
    """
    results = []
    if isinstance(value, str):
        if len(value) >= config.MIN_ID_LENGTH and not _is_common_value(value):
            results.append({
                "value": value,
                "path": path,
                "reason": _classify_string_reason(value) or "idb_value",
                "entropy": shannon_entropy(value),
            })
    elif isinstance(value, dict):
        for k, v in value.items():
            child_path = f"{path}.{k}" if path else k
            # Check ANY key with a string value >= MIN_ID_LENGTH
            if isinstance(v, str) and len(v) >= config.MIN_ID_LENGTH and not _is_common_value(v):
                results.append({
                    "value": v,
                    "path": child_path,
                    "reason": f"idb_key:{k}",
                    "entropy": shannon_entropy(v),
                })
            # Continue recursing into nested structures
            results.extend(extract_potential_ids(v, child_path))
    elif isinstance(value, list):
        for i, item in enumerate(value):
            results.extend(extract_potential_ids(item, f"{path}[{i}]"))

    return results


def _classify_string_reason(value: str) -> str | None:
    """Classify a candidate string by tracking-identifier pattern.

    Returns one of: uuid_v4, hex_string, base64_blob, high_entropy —
    or None when no pattern matches. Used by extract_potential_ids to
    label the length-gated candidates with their shape.
    """
    if len(value) < config.MIN_ID_LENGTH:
        return None

    # UUID v4 (search: UUID may be embedded in a longer string)
    if config.UUID_V4_RE.search(value):
        return "uuid_v4"

    # Hex string (≥16 chars)
    if config.HEX_STRING_RE.match(value):
        return "hex_string"

    # Base64 blob
    if config.BASE64_RE.match(value) and len(value) >= 20:
        return "base64_blob"

    # High-entropy string (likely random identifier)
    entropy = shannon_entropy(value)
    if entropy >= config.ENTROPY_THRESHOLD and 12 <= len(value) <= 128:
        if not _is_common_value(value):
            return "high_entropy"

    return None


def _is_common_value(value: str) -> bool:
    """Filter out strings that are placeholders, versions, or non-tracking identifiers."""
    lower = value.lower().strip()
    
    # 0. Placeholders and nulls
    if lower in ["undefined", "null", "[object object]", "nan", "none"]:
        return True

    # 1. URLs, file paths, common protocols
    if lower.startswith(("http://", "https://", "/", "data:", "blob:", "wss://", "ws://")):
        return True
    if any(ext in lower for ext in [".js", ".css", ".html", ".png", ".jpg", ".svg", ".json", ".map"]):
        return True
        
    # 2. Domain patterns
    if re.search(r'[a-z0-9-]+\.[a-z]{2,}', lower):
        return True
        
    # 3. Dates, Timestamps, and Timezones
    if re.search(r'^[a-z]+/[a-z_]+$', lower) or lower.upper() in ["UTC", "GMT", "PST", "EST", "CET", "IST", "JST"]:
        return True
    
    if re.search(r'^\d{4}-\d{2}-\d{2}', lower) or re.search(r'\d{2}/\d{2}/\d{4}', lower):
        return True
        
    if re.match(r'^(16|17|18)\d{8}(\d{3})?$', lower):
        return True
        
    # 4. Locations: Latitude and Longitude
    if re.search(r'^[+-]?\d{1,3}\.\d{4,}$', lower) or re.search(r'^-?\d+\.\d+,-?\d+\.\d+$', lower.replace(" ", "")):
        return True
        
    # 5. Version-like patterns (e.g., 1.2.3, v5.0, 15.0)
    if re.match(r'^[vV]?\d+(\.\d+)+$', lower) or re.match(r'^\d+\.\d+$', lower):
        if len(lower) < 10: # Long digit-dot strings might be IDs
            return True
        
    return False


# ─── Network Request Matching ────────────────────────────────────────
def find_exfiltrations(identifiers: list[dict], network_requests: list[dict],
                       site_domain: str) -> list[dict]:
    """
    Search all network requests for occurrences of extracted identifiers.

    Returns list of exfiltration events.
    """
    events = []

    for identifier in identifiers:
        id_value = str(identifier["value"])
        if len(id_value) < config.MIN_ID_LENGTH:
            continue
            
        # Filter: skip if it's a common non-ID value (domain, date, timestamp, timezone, location)
        if _is_common_value(id_value):
            continue
            
        # Filter: skip if the reason or path explicitly mentions location/timezone/coordinates
        reason = str(identifier.get("reason", "")).lower()
        path = str(identifier.get("path", "")).lower()
        location_keywords = ["location", "latitude", "longitude", "timezone", "tz", "lat", "lng", "coord"]
        if any(key in reason or key in path for key in location_keywords):
            continue

        for req in network_requests:
            req_url = req.get("url", "")
            if not req_url:
                continue

            match_location = _find_value_in_request(id_value, req)
            if match_location:
                req_domain = urlparse(req_url).netloc
                is_third_party = not _is_same_party(site_domain, req_domain)
                is_known_tracker = _is_known_tracker(req_domain)

                confidence = _calculate_confidence(
                    identifier, is_third_party, is_known_tracker
                )

                events.append({
                    "identifier_value": id_value,
                    "identifier_path": identifier["path"],
                    "identifier_reason": identifier["reason"],
                    "identifier_entropy": identifier["entropy"],
                    "database": identifier.get("database", ""),
                    "store": identifier.get("store", ""),
                    "record_key": identifier.get("record_key", ""),
                    "request_url": req_url,
                    "request_method": req.get("method", ""),
                    "request_domain": req_domain,
                    "request_status": (req.get("response") or {}).get("status", 0),
                    "match_location": match_location,
                    "is_third_party": is_third_party,
                    "is_known_tracker": is_known_tracker,
                    "confidence": confidence,
                })

    # Deduplicate and filter false positives
    seen = {}
    conf_map = {config.CONFIDENCE_HIGH: 3, config.CONFIDENCE_MEDIUM: 2, config.CONFIDENCE_LOW: 1, "": 0}
    
    for evt in events:
        # Deduplicate: only show 1 instance per unique tracker domain
        domain = evt["request_domain"]
        if domain not in seen:
            seen[domain] = evt
        else:
            # Keep the one with higher confidence
            if conf_map.get(evt["confidence"], 0) > conf_map.get(seen[domain]["confidence"], 0):
                seen[domain] = evt
                
    unique_events = []
    for domain, evt in seen.items():
        # Filter: skip if the identifier value is just the site domain
        id_val = evt["identifier_value"].lower().strip()
        site_lower = site_domain.lower().strip()
        base_site = site_lower.replace("www.", "")
        if id_val == site_lower or id_val == base_site or id_val == f"www.{base_site}":
            continue  # Domain self-match → false positive
        unique_events.append(evt)

    return unique_events


def _find_value_in_request(value: str, request: dict) -> str | None:
    """Check if a value appears in any part of a network request."""
    url = request.get("url") or ""

    # Check URL (query params and path)
    if value in url:
        return "url"

    # Check URL-decoded version
    if value in unquote(url):
        return "url_decoded"

    # Check POST data
    post_data = request.get("post_data")
    if post_data and isinstance(post_data, str):
        if value in post_data:
            return "post_body"
        if value in unquote(post_data):
            return "post_body_decoded"

    # Check specific headers
    headers = request.get("headers") or {}
    for header_name in ("cookie", "authorization", "x-client-id", "x-request-id"):
        header_val = headers.get(header_name) or ""
        if value in header_val:
            return f"header:{header_name}"

    return None


def _is_same_party(site_domain: str, request_domain: str) -> bool:
    """Check if two domains are the same party (same registrable domain)."""
    # Simple heuristic: compare last two domain parts
    def get_base(domain):
        parts = domain.lower().split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return domain.lower()

    return get_base(site_domain) == get_base(request_domain)


def _is_known_tracker(domain: str) -> bool:
    """Check if a domain is in any tracker list (hardcoded + blacklists)."""
    domain_lower = domain.lower()
    for tracker in config.ALL_TRACKER_DOMAINS:
        if domain_lower == tracker or domain_lower.endswith("." + tracker):
            return True
    return False


def _calculate_confidence(identifier: dict, is_third_party: bool,
                          is_known_tracker: bool) -> str:
    """Assign a confidence level to an exfiltration event."""
    score = 0

    # Third-party is the strongest signal
    if is_third_party:
        score += 3

    # Known tracker domain
    if is_known_tracker:
        score += 2

    # High-entropy identifier
    if identifier.get("entropy", 0) >= config.ENTROPY_THRESHOLD:
        score += 1

    # UUID or hex are strong ID patterns
    if identifier.get("reason") in ("uuid_v4", "hex_string"):
        score += 1

    # Key name matches tracking pattern
    if "tracking_key_name" in identifier.get("reason", ""):
        score += 1

    if score >= 5:
        return config.CONFIDENCE_HIGH
    elif score >= 3:
        return config.CONFIDENCE_MEDIUM
    else:
        return config.CONFIDENCE_LOW


# ─── Paper-Aligned Flow Classification ──────────────────────────────
def classify_flow_direction(event: dict) -> str:
    """
    Classify an exfiltration event as outflow or inflow.

    Outflow: IDB data → network/cookie sink (data leaving storage)
    Inflow:  external source → IDB (data entering storage)

    Since our detector captures IDB→network flows, all current events
    are outflow flows. We label them and also heuristically
    detect inflow-like patterns (e.g., URL/cookie data stored in IDB).
    """
    # All detected exfiltrations are IDB→sink = outflow
    return config.FLOW_OUTFLOW


def classify_confinement(site_domain: str, request_domain: str) -> str:
    """
    Classify whether a flow is internal (same origin) or external.

    Paper definition: internal = same origin as the page.
    Web storage is origin-scoped, so confinement = stays within origin.
    """
    site_origin = _get_origin(site_domain)
    req_origin = _get_origin(request_domain)

    if site_origin == req_origin:
        return config.CONFINEMENT_INTERNAL
    return config.CONFINEMENT_EXTERNAL


def classify_cross_origin(site_domain: str, request_domain: str) -> str:
    """
    For external flows, classify as same-site or cross-site.

    Same-site:  same registrable domain, different origin
    Cross-site: different registrable domain entirely
    """
    if _is_same_party(site_domain, request_domain):
        return config.CROSS_SAME_SITE
    return config.CROSS_CROSS_SITE


def _get_origin(domain: str) -> str:
    """Extract the origin (scheme-independent) from a domain."""
    # Normalize: strip www. and lowercase for origin comparison
    d = domain.lower().strip()
    if d.startswith("www."):
        d = d[4:]
    return d


def detect_integrity_flows(site_data: dict) -> list[dict]:
    """
    Heuristically detect integrity flows: external data → IDB.

    Checks if any IndexedDB values contain data that likely originated from
    cookies, URL parameters, or navigator properties (i.e., source → storage).
    """
    domain = site_data.get("domain") or "unknown"
    url = site_data.get("url") or ""
    integrity_flows = []

    # Collect source data from the page
    parsed = urlparse(url)
    url_params = parse_qs(parsed.query)
    url_param_values = set()
    for vals in url_params.values():
        url_param_values.update(v for v in vals if len(v) >= config.MIN_ID_LENGTH)

    # Scan IDB records for values matching external source patterns
    idb = site_data.get("indexeddb") or {}
    for db in idb.get("databases") or []:
        db_name = db.get("name") or ""
        for store in db.get("stores") or []:
            store_name = store.get("name") or ""
            for record in store.get("records") or []:
                value = record.get("value")
                key = record.get("key") or ""
                base_path = f"{db_name}/{store_name}/{key}"

                # Check if any IDB value contains URL-sourced data
                _check_integrity_sources(
                    value, base_path, db_name, store_name, str(key),
                    domain, url_param_values, integrity_flows
                )

    return integrity_flows


def _check_integrity_sources(value, path: str, db_name: str,
                             store_name: str, record_key: str,
                             domain: str, url_params: set,
                             results: list):
    """Check if an IDB value contains data from known sources."""
    if isinstance(value, str) and len(value) >= config.MIN_ID_LENGTH:
        source_class = None

        # Check if value matches a URL parameter
        for param_val in url_params:
            if param_val in value:
                source_class = "url_parameter"
                break

        # Check if value looks like it contains navigator data
        nav_patterns = ["mozilla", "chrome", "safari", "webkit", "gecko",
                        "windows nt", "linux", "macintosh"]
        if not source_class:
            val_lower = value.lower()
            if any(p in val_lower for p in nav_patterns) and len(value) > 20:
                source_class = "navigator_prop"

        if source_class:
            results.append({
                "flow_direction": config.FLOW_INFLOW,
                "source_class": source_class,
                "sink_class": "IDBObjectStore.put",  # Written to IDB store
                "value": value[:64],  # Truncate for privacy
                "path": path,
                "database": db_name,
                "store": store_name,
                "record_key": record_key,
                "confinement": config.CONFINEMENT_INTERNAL,
                "cross_origin": None,
                "is_third_party": False,
                "is_known_tracker": False,
            })
    elif isinstance(value, dict):
        for k, v in value.items():
            child_path = f"{path}.{k}" if path else k
            _check_integrity_sources(
                v, child_path, db_name, store_name, record_key,
                domain, url_params, results
            )
    elif isinstance(value, list):
        for i, item in enumerate(value):
            _check_integrity_sources(
                item, f"{path}[{i}]", db_name, store_name, record_key,
                domain, url_params, results
            )


# ─── Paper Metrics Calculator ────────────────────────────────────────
def compute_paper_metrics(all_results: list[dict]) -> dict:
    """
    Compute all quantitative metrics from the "What Storage" paper.

    Returns a dict with Tables II, III, IV equivalents and derived metrics.
    """
    total_sites = len(all_results)
    sites_with_idb = sum(
        1 for r in all_results
        if (r.get("indexeddb_summary") or {}).get("database_count", 0) > 0
    )

    # Gather all flows
    all_confid = []    # outflow flows
    all_integrity = [] # inflow flows

    for r in all_results:
        for evt in r.get("exfiltration_events", []):
            all_confid.append(evt)
        for iflow in r.get("integrity_flows", []):
            all_integrity.append(iflow)

    total_confid = len(all_confid)
    total_integrity = len(all_integrity)
    total_flows = total_confid + total_integrity

    # ── Table III: Internal vs External × Outflow/Inflow ──
    confid_internal = sum(
        1 for e in all_confid
        if e.get("confinement") == config.CONFINEMENT_INTERNAL
    )
    confid_external = sum(
        1 for e in all_confid
        if e.get("confinement") == config.CONFINEMENT_EXTERNAL
    )
    # Inflow flows are all internal by nature (source → local IDB)
    integ_internal = total_integrity
    integ_external = 0

    total_internal = confid_internal + integ_internal
    total_external = confid_external + integ_external

    # ── Table IV: Same-site vs Cross-site (external flows only) ──────
    confid_same_site = sum(
        1 for e in all_confid
        if e.get("confinement") == config.CONFINEMENT_EXTERNAL
        and e.get("cross_origin") == config.CROSS_SAME_SITE
    )
    confid_cross_site = sum(
        1 for e in all_confid
        if e.get("confinement") == config.CONFINEMENT_EXTERNAL
        and e.get("cross_origin") == config.CROSS_CROSS_SITE
    )

    # ── Tracking vs Non-tracking ─────────────────────────────────────
    confid_tracking = sum(
        1 for e in all_confid if e.get("is_known_tracker")
    )
    confid_non_tracking = total_confid - confid_tracking
    integ_tracking = sum(
        1 for e in all_integrity if e.get("is_known_tracker")
    )
    integ_non_tracking = total_integrity - integ_tracking

    # ── Tracking within external flows ───────────────────────────────
    external_tracking = sum(
        1 for e in all_confid
        if e.get("confinement") == config.CONFINEMENT_EXTERNAL
        and e.get("is_known_tracker")
    )
    external_non_tracking = confid_external - external_tracking

    # Cross-site tracking breakdown
    cross_site_tracking = sum(
        1 for e in all_confid
        if e.get("cross_origin") == config.CROSS_CROSS_SITE
        and e.get("is_known_tracker")
    )
    cross_site_non_tracking = confid_cross_site - cross_site_tracking
    same_site_tracking = sum(
        1 for e in all_confid
        if e.get("cross_origin") == config.CROSS_SAME_SITE
        and e.get("is_known_tracker")
    )
    same_site_non_tracking = confid_same_site - same_site_tracking

    # ── Per-database flow distribution ───────────────────────────────
    db_flow_counts = Counter()
    for e in all_confid:
        db_name = e.get("identifier_path", "").split("/")[0] if "/" in e.get("identifier_path", "") else "unknown"
        db_flow_counts[db_name] += 1

    # ── Sink class distribution for outflow flows ────────────
    sink_distribution = Counter()
    for e in all_confid:
        loc = e.get("match_location", "")
        if "header:cookie" in loc:
            sink_distribution["cookies"] += 1
        else:
            sink_distribution["network"] += 1

    # ── Source class distribution for inflow flows ────────────────
    source_distribution = Counter(
        e.get("source_class", "unknown") for e in all_integrity
    )

    # ── Derived percentages ──────────────────────────────────────────
    def pct(num, denom):
        return round(num / denom * 100, 1) if denom > 0 else 0.0

    return {
        "overview": {
            "total_sites": total_sites,
            "sites_with_idb": sites_with_idb,
            "pct_sites_with_idb": pct(sites_with_idb, total_sites),
            "total_flows": total_flows,
            "outflow_flows": total_confid,
            "inflow_flows": total_integrity,
        },
        "table_iii_confinement": {
            "internal": {
                "outflow": confid_internal,
                "inflow": integ_internal,
                "total": total_internal,
                "pct_of_total": pct(total_internal, total_flows),
            },
            "external": {
                "outflow": confid_external,
                "inflow": integ_external,
                "total": total_external,
                "pct_of_total": pct(total_external, total_flows),
            },
        },
        "table_iv_external_breakdown": {
            "same_site": {
                "outflow": confid_same_site,
                "tracking": same_site_tracking,
                "non_tracking": same_site_non_tracking,
                "pct_of_external": pct(confid_same_site, confid_external),
            },
            "cross_site": {
                "outflow": confid_cross_site,
                "tracking": cross_site_tracking,
                "non_tracking": cross_site_non_tracking,
                "pct_of_external": pct(confid_cross_site, confid_external),
            },
        },
        "tracking_classification": {
            "outflow_tracking": confid_tracking,
            "outflow_non_tracking": confid_non_tracking,
            "inflow_tracking": integ_tracking,
            "inflow_non_tracking": integ_non_tracking,
            "pct_outflow_tracking": pct(confid_tracking, total_confid),
            "pct_external_tracking": pct(external_tracking, confid_external),
        },
        "sink_distribution": dict(sink_distribution),
        "source_distribution": dict(source_distribution),
        "top_databases": dict(db_flow_counts.most_common(10)),
    }


# ─── Main Detection Pipeline ────────────────────────────────────────
def _extract_idb_kv_map(idb_data: dict) -> dict:
    """
    Build a flat map of db/store/key → serialized_value from IDB data.

    Returns dict: { "dbName/storeName/recordKey" : str(value) }
    """
    kv_map = {}
    idb_data = idb_data or {}
    for db in idb_data.get("databases") or []:
        db_name = db.get("name") or ""
        for store in db.get("stores") or []:
            store_name = store.get("name") or ""
            for record in store.get("records") or []:
                key = str(record.get("key") or "")
                value = str(record.get("value") or "")
                path = f"{db_name}/{store_name}/{key}"
                kv_map[path] = value
    return kv_map


def diff_iterations(site_data: dict) -> dict:
    """
    Compare IDB records across crawl iterations.

    Returns:
        {
            "changed_keys":  { path: [val_iter1, val_iter2, ...] },
            "static_keys":   { path: value },
            "changed_count": int,
            "static_count":  int,
        }
    """
    iterations = site_data.get("iterations", [])
    if len(iterations) < 2:
        # No diff possible with < 2 iterations
        return {"changed_keys": {}, "static_keys": {}, "changed_count": 0,
                "static_count": 0}

    # Extract KV maps from each iteration
    kv_maps = []
    for it in iterations:
        idb = it.get("indexeddb") or {}
        kv_maps.append(_extract_idb_kv_map(idb))

    # Get union of all keys across all iterations
    all_keys = set()
    for m in kv_maps:
        all_keys.update(m.keys())

    changed_keys = {}
    static_keys = {}

    for key in sorted(all_keys):
        values = [m.get(key) for m in kv_maps]
        # Remove None (key missing in some iterations) → treat as changed
        non_none = [v for v in values if v is not None]
        if len(non_none) < 2:
            # Key only appeared in one iteration → changed (unique per session)
            changed_keys[key] = values
        elif len(set(non_none)) > 1:
            # Different values across iterations → changed (tracking candidate)
            changed_keys[key] = values
        else:
            # Same value across all iterations → static (config/cache)
            static_keys[key] = non_none[0]

    return {
        "changed_keys": changed_keys,
        "static_keys": static_keys,
        "changed_count": len(changed_keys),
        "static_count": len(static_keys),
    }


# ─── Foxhound Taint Flow Parsing ──────────────────────────────────
# Foxhound tags strings at taint sources and reports full CFG flows when
# a tainted string reaches a sink. Each taint[] entry is a flow: flow[0]
# is the sink operation, the last op with source:true is the source read.
# The tainted substring is detail["str"][begin:end].
#
# IMPORTANT (verified empirically): IndexedDB reads are a *taint blackout* —
# Foxhound does not tag IDB reads as sources, and taint round-tripped
# through IDB comes back clean. So IDB-specific exfiltration is recovered
# by the FLOW_HOOKS_INIT_SCRIPT instrumentation (analyze_idb_hook_flows)
# rather than by taint flows. Taint covers localStorage/sessionStorage/
# cookie/location/MessageEvent sources; the IDB hooks cover IDB reads.
_TAINT_SINK_SOURCE_MAP = {
    "fetch.url": ("fetch.url", "EXTERNAL"),
    "fetch.body": ("fetch.body", "EXTERNAL"),
    "XMLHttpRequest.open": ("xhr_url", "EXTERNAL"),
    "XMLHttpRequest.send": ("xhr_body", "EXTERNAL"),
    "XMLHttpRequest.setRequestHeader": ("header", "EXTERNAL"),
    "navigator.sendBeacon": ("sendbeacon", "EXTERNAL"),
    "img.src": ("img_src", "EXTERNAL"),
    "script.src": ("script_src", "EXTERNAL"),
    "localStorage.setItem": ("localStorage", "LOCALSTORAGE"),
    "sessionStorage.setItem": ("sessionStorage", "SESSIONSTORAGE"),
    "document.write": ("document.write", "LEGACY"),
    "eval": ("eval", "EXEC"),
    "Function.closure": ("Function.ctor", "EXEC"),
}


def _safe_urljoin(base: str, part: str) -> str:
    from urllib.parse import urljoin
    try:
        return urljoin(base or "", part or "")
    except Exception:
        return part or ""


def _sink_target(sink: str, loc: str, part: str) -> str:
    """Resolve a sink's tainted operand to the absolute URL where relevant."""
    if not part:
        return ""
    if sink in ("fetch.url", "XMLHttpRequest.open", "navigator.sendBeacon",
                 "img.src", "script.src"):
        return _safe_urljoin(loc, part)
    if sink == "fetch.body":
        return part
    return part


def _taint_confidence(conf_level: str) -> str:
    mapping = {"HIGH": config.CONFIDENCE_HIGH,
               "MEDIUM": config.CONFIDENCE_MEDIUM,
               "LOW": config.CONFIDENCE_LOW}
    return mapping.get((conf_level or "").upper(), config.CONFIDENCE_MEDIUM)


def parse_taint_flows(events: list, site_domain: str,
                      network_requests: list[dict] = None,
                      idb_data: dict = None) -> list[dict]:
    """
    Convert raw Foxhound taint events into analysis flows.

    Each event -> one or more flows (one per taint[] entry). A flow records
    the sink, the source JS function, the tainted value, whether the source
    was a Web Storage read (localStorage/sessionStorage) versus an
    IDB-related context, and the 1P/3P classification of the sink target.

    IDB data is threaded through so flows that originate from a storage
    read can be cross-referenced (even though Foxhound itself doesn't taint
    IDB reads, the IDB hook layer can fill that gap).
    """
    flows = []
    observed = set()

    for ev in events or []:
        detail = ev.get("detail", {}) or {}
        sink = detail.get("sink", "")
        sink_str = detail.get("str", "") or ""
        loc = detail.get("loc", "") or ""
        subframe = detail.get("subframe", False)
        event_ts = detail.get("timestamp")

        for taint_ent in (ev.get("taint") or []):
            begin = taint_ent.get("begin", 0)
            end = taint_ent.get("end", begin)
            flow_ops = taint_ent.get("flow", []) or []

            source_op = None
            source_loc = None
            for op in flow_ops:
                if op.get("source"):
                    source_op = op
                    source_loc = op.get("location", {}) or {}
                    break

            if source_op is None:
                continue

            source_js_func = (source_loc.get("function") or "").strip()
            source_js_file = (source_loc.get("filename") or "").split("?")[0].rsplit("/", 1)[-1]
            source_js_line = source_loc.get("line")
            source_operation = source_op.get("operation", "")
            source_hint = source_operation.split(".")[-1]

            tainted_value = sink_str[begin:end] if sink_str else sink_str
            target = _sink_target(sink, loc, tainted_value)

            sink_class, sink_kind = _TAINT_SINK_SOURCE_MAP.get(
                sink, (sink, "EXTERNAL")
            )

            # 1P/3P classification of the sink target
            req_domain = urlparse(target).netloc if target else ""
            is_3p = bool(req_domain) and not _is_same_party(site_domain, req_domain)
            is_tracker = _is_known_tracker(req_domain) if req_domain else False

            confidence = config.CONFIDENCE_MEDIUM
            if sink_kind == "EXTERNAL" and is_3p:
                confidence = config.CONFIDENCE_HIGH if is_tracker else config.CONFIDENCE_MEDIUM
            elif sink_kind == "EXTERNAL" and not req_domain:
                confidence = config.CONFIDENCE_MEDIUM
            elif sink_kind in ("LOCALSTORAGE", "SESSIONSTORAGE"):
                confidence = config.CONFIDENCE_LOW  # stays on-device

            # Storage-source flag for report UI
            storage_source = "storage" if source_operation in (
                "localStorage.getItem", "sessionStorage.getItem"
            ) else ("url_like" if source_operation in (
                "location.search", "location.href", "location.hash"
            ) else ("cookie" if source_operation == "document.cookie"
                    else "other"))

            dedupe_key = (
                sink, source_operation, source_loc.get("line"),
                source_loc.get("scripthash"), target
            )
            if dedupe_key in observed:
                continue
            observed.add(dedupe_key)

            flows.append({
                "mechanism": "taint",
                "sink": sink_class,
                "sink_kind": sink_kind,
                "source_operation": source_operation,
                "source_function": source_js_func or None,
                "source_file": source_js_file or None,
                "source_line": source_js_line,
                "source_hint": source_hint,
                "tainted_value": tainted_value,
                "target": target or None,
                "request_domain": req_domain or None,
                "is_third_party": bool(is_3p),
                "is_known_tracker": bool(is_tracker),
                "subframe": subframe,
                "timestamp": event_ts,
                "storage_source": storage_source,
                "flow_direction": config.FLOW_OUTFLOW if sink_kind == "EXTERNAL"
                                  else "storage_egress",
                "confinement": classify_confinement(
                    site_domain, req_domain) if req_domain else config.CONFINEMENT_INTERNAL,
                "cross_origin": classify_cross_origin(
                    site_domain, req_domain) if req_domain else None,
                "confidence": confidence,
            })

    return flows


# ─── IDB Hook Flow Matching ───────────────────────────────────────
def _norm_url(u: str) -> str:
    return (u or "").strip().rstrip("/")


def analyze_idb_hook_flows(hooks: dict, network_requests: list[dict],
                           site_domain: str, loc: str = "") -> list[dict]:
    """
    Match IDB reads (recorded by the flow-hook init script) to external
    network sends (same init script), closing the Foxhound IDB taint
    blackout. Returns flows of the form:
        source: IDB read (store/op + caller JS fn)
        sink:   network send (url + caller JS fn)
    """
    if not hooks:
        return []

    reads = hooks.get("reads", []) or []
    sends = hooks.get("sends", []) or []
    if not reads or not sends:
        return []

    flows = []

    for read in reads:
        read_val = read.get("value", "") or ""
        if not read_val or len(read_val) < config.MIN_ID_LENGTH:
            continue

        # Try to JSON-parse the read value; if it's an object, extract
        # leaf strings to match against send URLs (IDB records often store
        # nested objects where individual fields appear in network params).
        try:
            parsed = json.loads(read_val) if read_val.startswith(("{", "[")) else None
        except Exception:
            parsed = None

        needles = set()
        needles.add(read_val)
        needles.add(unquote(read_val))
        if isinstance(parsed, dict):
            for v in parsed.values():
                if isinstance(v, str) and v:
                    needles.add(v)
                    needles.add(unquote(v))
        elif isinstance(parsed, list):
            for v in parsed:
                if isinstance(v, str) and v:
                    needles.add(v)
                    needles.add(unquote(v))

        # Also add re-encoded forms
        from urllib.parse import quote as _quote
        encoded_needles = set()
        for n in needles:
            if n and n not in ("null", "undefined"):
                try:
                    encoded_needles.add(_quote(n, safe=""))
                except Exception:
                    pass

        matched_sends = []
        for snd in sends:
            s_url = snd.get("url", "") or ""
            s_body = snd.get("body", "") or ""
            decoded_url = unquote(s_url)
            decoded_body = unquote(s_body)
            for needle in needles:
                if (needle and (needle in s_url or needle in decoded_url
                                or needle in s_body or needle in decoded_body)):
                    matched_sends.append(snd)
                    break
            else:
                for enc in encoded_needles:
                    if enc and (enc in s_url or enc in s_body):
                        matched_sends.append(snd)
                        break

        if not matched_sends:
            continue

        sink_doms = set()
        for snd in matched_sends:
            try:
                sink_doms.add(urlparse(snd.get("url", "")).netloc)
            except Exception:
                pass

        for snd in matched_sends:
            s_url = snd.get("url", "") or ""
            req_domain = urlparse(s_url).netloc
            is_3p = bool(req_domain) and not _is_same_party(site_domain, req_domain)
            is_tracker = _is_known_tracker(req_domain) if req_domain else False

            read_store = read.get("store", "")
            read_op = read.get("op", "get")

            flows.append({
                "mechanism": "idb_hook",
                "sink": snd.get("op", "network"),
                "sink_kind": "EXTERNAL",
                "source_operation": f"IDB.{read_op}",
                "source_function": read.get("fn") or None,
                "source_file": None,
                "source_line": None,
                "source_hint": read_op,
                "source_store": read_store,
                "idb_value": read_val,
                "target": s_url,
                "request_domain": req_domain or None,
                "is_third_party": bool(is_3p),
                "is_known_tracker": bool(is_tracker),
                "sink_function": snd.get("fn") or None,
                "sink_hook": snd.get("op", ""),
                "subframe": False,
                "timestamp": snd.get("ts") or read.get("ts"),
                "storage_source": "idb",
                "flow_direction": config.FLOW_OUTFLOW,
                "confinement": classify_confinement(
                    site_domain, req_domain) if req_domain else config.CONFINEMENT_INTERNAL,
                "cross_origin": classify_cross_origin(
                    site_domain, req_domain) if req_domain else None,
                "confidence": config.CONFIDENCE_HIGH if (is_3p and is_tracker)
                              else (config.CONFIDENCE_MEDIUM if is_3p
                                    else config.CONFIDENCE_LOW),
            })

    return flows


def analyze_site(site_data: dict) -> dict:
    """
    Run the full detection pipeline on a single site's crawled data.

    Returns analysis results with identifiers, exfiltration events,
    and paper-aligned flow classifications.
    """
    domain = site_data.get("domain", "unknown")
    logger.info(f"🔍 Analyzing: {domain}")

    # Step 0: Cross-iteration diff analysis
    iteration_diff = diff_iterations(site_data)
    changed_paths = set(iteration_diff["changed_keys"].keys())
    if iteration_diff["changed_count"] > 0 or iteration_diff["static_count"] > 0:
        logger.info(
            f"  Iteration diff: {iteration_diff['changed_count']} changed, "
            f"{iteration_diff['static_count']} static records"
        )

    # Step 1: Extract potential identifiers from IndexedDB
    all_identifiers = []
    idb = site_data.get("indexeddb") or {}

    for db in idb.get("databases") or []:
        db_name = db.get("name") or ""
        for store in db.get("stores") or []:
            store_name = store.get("name") or ""
            for record in store.get("records") or []:
                key = record.get("key") or ""
                value = record.get("value")
                base_path = f"{db_name}/{store_name}/{key}"

                ids = extract_potential_ids(value, base_path)
                for ident in ids:
                    ident["database"] = db_name
                    ident["store"] = store_name
                    ident["record_key"] = str(key)
                    # Mark whether this record changed across iterations
                    ident["changed_across_iterations"] = base_path in changed_paths
                all_identifiers.append(ids)

    # Flatten
    flat_ids = [item for sublist in all_identifiers for item in sublist]

    # Filter: if we have diff data, keep identifiers from CHANGED records,
    # OR static records that have very high entropy (likely persistent IDs)
    if changed_paths:
        # Keep if it changed OR if it's very high entropy (> 4.5)
        changed_ids = [
            i for i in flat_ids 
            if i.get("changed_across_iterations") or i.get("entropy", 0) > 4.5
        ]
        static_ids = [i for i in flat_ids if i not in changed_ids]
        logger.info(
            f"  Identifiers: {len(flat_ids)} total → "
            f"{len(changed_ids)} kept ({len(static_ids)} filtered out)"
        )
        flat_ids = changed_ids
    else:
        logger.info(f"  Found {len(flat_ids)} potential identifiers")

    # Step 1b: Aggregate Foxhound taint flows + IDB hook flows across
    # iterations (these live under each iteration's crawl result).
    iterations = site_data.get("iterations", []) or []
    taint_flows = []
    idb_hook_flows = []
    seen_taint = set()
    seen_hook = set()
    site_loc = site_data.get("url", "") or ""
    for it in iterations:
        it_network = it.get("network_requests", []) or []
        for tf in parse_taint_flows(it.get("taint_events", []), domain,
                                    it_network, it.get("indexeddb")):
            k = (tf.get("sink"), tf.get("source_operation"),
                 tf.get("source_line"), tf.get("target"))
            if k in seen_taint:
                continue
            seen_taint.add(k)
            taint_flows.append(tf)
        for hf in analyze_idb_hook_flows(it.get("flow_hooks", {}), it_network,
                                         domain, site_loc):
            k = (hf.get("source_function"), hf.get("source_store"),
                 hf.get("target"))
            if k in seen_hook:
                continue
            seen_hook.add(k)
            idb_hook_flows.append(hf)

    logger.info(
        f"  Taint flows: {len(taint_flows)} | IDB hook flows: {len(idb_hook_flows)}"
    )

    # Step 2: Find exfiltrations (outflow flows)
    network = site_data.get("network_requests") or []
    exfiltrations = find_exfiltrations(flat_ids, network, domain)

    # Step 3: Classify each exfiltration with paper-aligned labels
    for evt in exfiltrations:
        req_domain = evt.get("request_domain", "")
        evt["flow_direction"] = classify_flow_direction(evt)
        evt["confinement"] = classify_confinement(domain, req_domain)
        if evt["confinement"] == config.CONFINEMENT_EXTERNAL:
            evt["cross_origin"] = classify_cross_origin(domain, req_domain)
        else:
            evt["cross_origin"] = None
        # Sink classification (IDB data → external sink)
        loc = evt.get("match_location", "")
        if "header:cookie" in loc:
            evt["sink_class"] = "header_cookie"
        elif "post_data" in loc:
            method = evt.get("request_method", "GET").upper()
            evt["sink_class"] = "xhr_body" if method != "GET" else "fetch_body"
        else:
            evt["sink_class"] = "fetch_url"  # URL parameter match
        # Source is always IDB read for outflow flows
        evt["source_class"] = "IDBObjectStore.get"

    logger.info(f"  Found {len(exfiltrations)} exfiltration events")

    # Step 4: Detect integrity flows (source → IDB)
    integrity_flows = detect_integrity_flows(site_data)
    logger.info(f"  Found {len(integrity_flows)} integrity flows")

    # Classify confidence
    high = sum(1 for e in exfiltrations if e["confidence"] == config.CONFIDENCE_HIGH)
    med = sum(1 for e in exfiltrations if e["confidence"] == config.CONFIDENCE_MEDIUM)
    low = sum(1 for e in exfiltrations if e["confidence"] == config.CONFIDENCE_LOW)

    # Confinement summary
    internal_count = sum(
        1 for e in exfiltrations
        if e.get("confinement") == config.CONFINEMENT_INTERNAL
    )
    external_count = sum(
        1 for e in exfiltrations
        if e.get("confinement") == config.CONFINEMENT_EXTERNAL
    )

    logger.info(
        f"  Confidence: {high} HIGH, {med} MEDIUM, {low} LOW | "
        f"Confinement: {internal_count} internal, {external_count} external"
    )

    return {
        "domain": domain,
        "url": site_data.get("url", ""),
        "timestamp": site_data.get("timestamp", ""),
        "indexeddb_summary": {
            "database_count": len(idb.get("databases", [])),
            "total_records": sum(
                s.get("recordCount", 0)
                for d in idb.get("databases", [])
                for s in d.get("stores", [])
            ),
        },
        # ── Actual IDB key:value records ─────────────────────────────
        "indexeddb_records": [
            {
                "database": db.get("name", ""),
                "store": store.get("name", ""),
                "key": str(record.get("key", "")),
                "value": record.get("value"),
            }
            for db in idb.get("databases", [])
            for store in db.get("stores", [])
            for record in store.get("records", [])
        ],
        "network_summary": {
            "total_requests": len(network),
            "third_party_requests": sum(
                1 for r in network
                if not _is_same_party(domain, urlparse(r.get("url", "")).netloc)
            ),
        },
        # ── Actual network request details ───────────────────────────
        "network_requests": [
            {
                "url": r.get("url", ""),
                "method": r.get("method", ""),
                "domain": urlparse(r.get("url", "")).netloc,
                "is_third_party": not _is_same_party(
                    domain, urlparse(r.get("url", "")).netloc
                ),
                "has_post_data": bool(r.get("post_data")),
                "response": r.get("response"),
            }
            for r in network
        ],
        "identifiers_found": len(flat_ids),
        "identifiers": flat_ids,
        "exfiltration_events": exfiltrations,
        "exfiltration_summary": {
            "total": len(exfiltrations),
            "high_confidence": high,
            "medium_confidence": med,
            "low_confidence": low,
        },
        "taint_flows": taint_flows,
        "idb_hook_flows": idb_hook_flows,
        "dynamic_flows": {
            "total": len(taint_flows) + len(idb_hook_flows),
            "taint": len(taint_flows),
            "idb_hook": len(idb_hook_flows),
            "high_confidence": sum(
                1 for f in taint_flows + idb_hook_flows
                if f.get("confidence") == config.CONFIDENCE_HIGH
            ),
            "medium_confidence": sum(
                1 for f in taint_flows + idb_hook_flows
                if f.get("confidence") == config.CONFIDENCE_MEDIUM
            ),
            "low_confidence": sum(
                1 for f in taint_flows + idb_hook_flows
                if f.get("confidence") == config.CONFIDENCE_LOW
            ),
            "external": sum(
                1 for f in taint_flows + idb_hook_flows
                if f.get("confinement") == config.CONFINEMENT_EXTERNAL
            ),
            "tracker_targets": sum(
                1 for f in taint_flows + idb_hook_flows if f.get("is_known_tracker")
            ),
        },
        "inflow_flows": integrity_flows,
        "flow_classification": {
            "outflow_flows": len(exfiltrations) + len(taint_flows) + len(idb_hook_flows),
            "inflow_flows": len(integrity_flows),
            "internal_flows": internal_count,
            "external_flows": external_count,
        },
        "iteration_diff": {
            "changed_count": iteration_diff["changed_count"],
            "static_count": iteration_diff["static_count"],
            "changed_keys": list(iteration_diff["changed_keys"].keys()),
        },
    }


from typing import List, Dict, Optional, Callable

def analyze_all_sites(raw_data_dir: str = None,
                      site_limit: int = None,
                      only_files: List[str] = None,
                      on_progress: Optional[Callable[[float, str], None]] = None) -> List[dict]:
    """
    Analyze all crawled site data in the raw data directory.

    Args:
        raw_data_dir: Directory containing crawled JSON files.
        site_limit:   Max number of sites to analyze (None = all).
        only_files:   If provided, only analyze these specific filenames.

    Returns list of per-site analysis results.
    """
    raw_dir = raw_data_dir or config.RAW_DATA_DIR
    results = []

    if not os.path.exists(raw_dir):
        logger.error(f"Raw data directory not found: {raw_dir}")
        return results

    if only_files:
        # Analyze only the specified files (from a just-completed crawl)
        json_files = [f for f in only_files if os.path.exists(os.path.join(raw_dir, f))]
    else:
        json_files = sorted(f for f in os.listdir(raw_dir) if f.endswith(".json"))
        if site_limit:
            json_files = json_files[:site_limit]
    logger.info(f"Analyzing {len(json_files)} crawled sites from {raw_dir}")

    total_sites = len(json_files)
    for i, filename in enumerate(json_files, 1):
        if on_progress:
            progress_pct = (i / total_sites) * 100
            on_progress(progress_pct, f"Analyzing {filename} ({i}/{total_sites})")
            
        filepath = os.path.join(raw_dir, filename)
        with open(filepath, "r", encoding="utf-8") as f:
            site_data = json.load(f)
        analysis = analyze_site(site_data)
        results.append(analysis)

    return results


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )
    results = analyze_all_sites()
    print(f"\nTotal sites analyzed: {len(results)}")
    for r in results:
        fc = r.get('flow_classification', {})
        print(
            f"  {r['domain']}: "
            f"{r['exfiltration_summary']} | "
            f"outflow={fc.get('outflow_flows',0)} "
            f"inflow={fc.get('inflow_flows',0)} "
            f"int={fc.get('internal_flows',0)} "
            f"ext={fc.get('external_flows',0)}"
        )
