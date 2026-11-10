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
import transforms as tf
import entities
import uid as paper_uid

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
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        # Phase 3: numeric identifiers (long ids, epoch-ms timestamps used
        # as ids) enter the pool too — matched as their decimal string.
        num_s = str(value)
        if len(num_s) >= config.MIN_ID_LENGTH and not _is_common_value(num_s):
            results.append({
                "value": num_s,
                "path": path,
                "reason": "numeric_id",
                "entropy": shannon_entropy(num_s),
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

    Matching is transform-aware (Phase 3): every identifier is expanded
    into its encoded/hashed variants (urlencode, base64, hex, md5/sha1/
    sha256, JSON-escaped, truncated prefixes) and searched across URL,
    POST bodies (raw/JSON/form), ALL headers and WebSocket frames.
    Each event records its transform_chain so reports can quantify how
    much exfiltration plain substring matching would miss.

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

        # Expand into transform variants once per identifier
        needles = tf.generate_variants(id_value)
        needles.update(tf.truncated_prefixes(id_value))
        if not needles:
            continue

        for req in network_requests:
            req_url = req.get("url", "")
            if not req_url:
                continue

            hit = tf.search_request(req, needles)
            if not hit:
                continue
            match_location = hit["location"]
            all_hits = hit.get("all_hits") or [
                {"location": hit["location"], "variant": hit["variant"],
                 "transform_chain": hit["transform_chain"]}]
            # Union of every chain observed in this request (a URL may
            # carry md5(uid) AND base64(uid) simultaneously)
            chains = []
            for h in all_hits:
                for c in h.get("transform_chain") or ["raw"]:
                    if c not in chains:
                        chains.append(c)
            chain = hit["transform_chain"]
            is_transformed = any(c != "raw" for c in chains)
            req_domain = urlparse(req_url).netloc
            is_third_party = not _is_same_party(site_domain, req_domain)
            is_known_tracker = _is_known_tracker(req_domain)

            # Phase 5: entity attribution (Disconnect) + CNAME cloaking.
            # Cloaking check only for apparent first-party hosts (bounded
            # DNS: one dig per unique host, cached in entities module).
            entity = _entity_for(req_domain)
            cloaking = {"cname": None, "cloaked": False}
            if not is_third_party:
                try:
                    cloaking = entities.classify_cloaking(site_domain,
                                                          req_domain)
                except Exception:
                    cloaking = {"cname": None, "cloaked": False}
                if cloaking.get("cloaked"):
                    # Apparent 1P subdomain actually points at 3P infra
                    is_third_party = True
                    if cloaking.get("cname_entity"):
                        is_known_tracker = True
                        entity = dict(cloaking["cname_entity"])
            if is_known_tracker and entity is None:
                # elevating without a Disconnect record: mark categoryless
                entity = entity or {"company": None, "category": "known_list"}

            confidence = _calculate_confidence(
                identifier, is_third_party, is_known_tracker
            )

            events.append({
                "identifier_value": id_value,
                "identifier_path": identifier["path"],
                "identifier_reason": identifier["reason"],
                "identifier_entropy": identifier["entropy"],
                "identifier_score": identifier.get("score", 0.0),
                "database": identifier.get("database", ""),
                "store": identifier.get("store", ""),
                "record_key": identifier.get("record_key", ""),
                "request_url": req_url,
                "request_method": req.get("method", ""),
                "request_domain": req_domain,
                "request_status": (req.get("response") or {}).get("status", 0),
                "match_location": match_location,
                "matched_variant": hit["variant"],
                "transform_chain": chain,
                "all_transform_chains": chains,
                "mechanism": ("transform" if is_transformed else "substring"),
                "storage_type": identifier.get("storage_type", "indexeddb"),
                "is_third_party": is_third_party,
                "is_known_tracker": is_known_tracker,
                "tracker_entity": entity,
                "cname_target": cloaking.get("cname"),
                "cname_cloaked": bool(cloaking.get("cloaked")),
                "confidence": confidence,
            })

    # Dedup (Phase 3 fix): keep every distinct (identifier, destination,
    # match_location) flow. The old rule collapsed everything to one event
    # per domain, understating flow counts. Display-side aggregation is
    # the reporter's job, not the detector's.
    seen = {}
    for evt in events:
        key = (evt["identifier_value"], evt["request_domain"],
               evt["match_location"], evt["request_url"])
        prev = seen.get(key)
        if prev is None:
            seen[key] = evt
            continue
        # Same flow seen twice: keep the higher-confidence record
        conf_map = {config.CONFIDENCE_HIGH: 3, config.CONFIDENCE_MEDIUM: 2,
                    config.CONFIDENCE_LOW: 1, "": 0}
        if conf_map.get(evt["confidence"], 0) > conf_map.get(prev["confidence"], 0):
            seen[key] = evt

    unique_events = []
    site_lower = site_domain.lower().strip()
    base_site = site_lower.replace("www.", "")
    for evt in seen.values():
        # Filter: skip if the identifier value is just the site domain
        id_val = evt["identifier_value"].lower().strip()
        if id_val in (site_lower, base_site, f"www.{base_site}"):
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
    """Same party? PSL-based (entities.is_same_party) — fixes the
    last-two-labels bug on .co.uk/.com.pk and handles ports, IPs and
    localhost correctly. Falls back to the naive heuristic if the PSL
    layer is unavailable."""
    try:
        return entities.is_same_party(site_domain, request_domain)
    except Exception:
        def get_base(domain):
            parts = domain.lower().split(".")
            if len(parts) >= 2:
                return ".".join(parts[-2:])
            return domain.lower()
        return get_base(site_domain) == get_base(request_domain)


def _is_known_tracker(domain: str) -> bool:
    """Tracker membership: legacy hardcoded/blacklist lists PLUS the
    Disconnect entity list (category-aware)."""
    domain_lower = (domain or "").lower()
    for tracker in config.ALL_TRACKER_DOMAINS:
        if domain_lower == tracker or domain_lower.endswith("." + tracker):
            return True
    try:
        return entities.is_tracker_domain(domain_lower)
    except Exception:
        return False


def _entity_for(domain: str) -> dict | None:
    """Disconnect {company, category} attribution for a host (or None)."""
    try:
        return entities.entity_for(domain)
    except Exception:
        return None


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
    # network egress
    "fetch.url": ("fetch.url", "EXTERNAL"),
    "fetch.body": ("fetch.body", "EXTERNAL"),
    "XMLHttpRequest.open": ("xhr_url", "EXTERNAL"),
    "XMLHttpRequest.send": ("xhr_body", "EXTERNAL"),
    "XMLHttpRequest.setRequestHeader": ("header", "EXTERNAL"),
    "navigator.sendBeacon": ("sendbeacon", "EXTERNAL"),
    "img.src": ("img_src", "EXTERNAL"),
    "script.src": ("script_src", "EXTERNAL"),
    "iframe.src": ("iframe_src", "EXTERNAL"),
    "a.href": ("a_href", "EXTERNAL"),
    "WebSocket.send": ("websocket_send", "EXTERNAL"),
    "WebSocket": ("websocket", "EXTERNAL"),
    # storage sinks (stay on-device)
    "localStorage.setItem": ("localStorage", "LOCALSTORAGE"),
    "sessionStorage.setItem": ("sessionStorage", "SESSIONSTORAGE"),
    # DOM / legacy / execution sinks
    "document.write": ("document.write", "LEGACY"),
    "innerHTML": ("innerHTML", "DOM"),
    "element.style": ("element.style", "DOM"),
    "element.append": ("element.append", "DOM"),
    "script.text": ("script.text", "DOM"),
    "document.cookie": ("document.cookie", "COOKIE"),
    "Range.createContextualFragment": ("createContextualFragment", "DOM"),
    "eval": ("eval", "EXEC"),
    "Function.closure": ("Function.ctor", "EXEC"),
}


def _norm_taint_sink(sink: str) -> str:
    """Normalize Foxhound sink labels: 'XMLHttpRequest.open(url)' →
    'XMLHttpRequest.open', 'localStorage.setItem(key)' → 'localStorage.setItem'."""
    s = (sink or "").strip()
    if "(" in s:
        s = s.split("(", 1)[0]
    return s


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
                 "img.src", "script.src", "iframe.src", "a.href",
                 "WebSocket"):
        return _safe_urljoin(loc, part)
    if sink in ("fetch.body", "XMLHttpRequest.send", "WebSocket.send"):
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
        sink = _norm_taint_sink(detail.get("sink", ""))
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


# ─── Write-Side Instrumentation (Phase 2) ───────────────────────────
# WHO creates identifiers, and is it really "inflow" (network → IDB)?
# The flow-hook init script records every IDBObjectStore.put/add/cursor
# update with the calling script's stack location, plus captured network
# response bodies. A write is classified as inflow only when a leaf string
# of the written value is observed in a prior response — replacing the
# old URL-param/navigator heuristic guess.

def _leaf_strings(value, min_len: int = 1, max_leaves: int = 64) -> list[str]:
    """Flatten a (possibly nested) JSON-parsed value into leaf strings."""
    out = []

    def walk(v, depth=0):
        if len(out) >= max_leaves or depth > 6:
            return
        if isinstance(v, str):
            if len(v) >= min_len:
                out.append(v)
        elif isinstance(v, dict):
            for item in v.values():
                walk(item, depth + 1)
        elif isinstance(v, (list, tuple)):
            for item in v:
                walk(item, depth + 1)
        elif isinstance(v, (int, float)) and v is not None:
            s = str(v)
            if len(s) >= min_len:
                out.append(s)

    walk(value)
    return out


def _parse_write_value(raw: str):
    """Parse a recorded write value (string or JSON string) → leaf strings."""
    if not raw:
        return []
    txt = raw
    if txt.startswith(("{", "[")):
        try:
            return _leaf_strings(json.loads(txt), min_len=config.MIN_ID_LENGTH)
        except Exception:
            pass
    return _leaf_strings(txt, min_len=config.MIN_ID_LENGTH)


def _script_origin(stack_loc: str) -> str:
    """Extract the script origin from a JS stack location string.

    Formats seen: 'https://host/path.js:1:2', 'https://host/x.js:1:2',
    'inline script', 'https://host/' (page itself), or ''.
    """
    loc = (stack_loc or "").strip()
    if not loc or loc in ("inline script", "eval code", "native"):
        return ""
    # Strip trailing ":line:col" (greedy → preserves ports in the URL)
    m = re.match(r"^(.*):\d+:\d+$", loc)
    candidate = m.group(1) if m else loc
    if candidate.startswith(("http://", "https://", "ws://", "wss://", "//")):
        try:
            return urlparse(candidate).netloc
        except Exception:
            return ""
    return ""


def analyze_idb_writes(hooks: dict, site_domain: str,
                       network_requests: list[dict] = None) -> dict:
    """
    Analyze recorded IDB writes.

    Returns:
      {
        "writes": [...attribution records...],
        "inflow_flows": [...network → IDB proven by response match...],
        "writer_stats": {"first_party": n, "third_party": n, "unknown": n},
        "pre_consent_candidates": n,   # writes within 3s of page load
      }
    """
    writes = (hooks or {}).get("writes", []) or []
    responses = (hooks or {}).get("responses", []) or []

    # Precompute response leaf index: leaf → response url
    resp_leaves: list[tuple[str, str]] = []
    for r in responses:
        body = r.get("body", "") or ""
        rurl = r.get("url", "") or ""
        for leaf in _leaf_strings(body, min_len=config.MIN_ID_LENGTH, max_leaves=128):
            resp_leaves.append((leaf, rurl))
        # Also raw-URL search fallback below via decoded body

    writer_stats = {"first_party": 0, "third_party": 0, "unknown": 0}
    attribution = []
    inflow = []
    pre_consent = 0

    site_base = site_domain.lower().replace("www.", "")
    POST_LOAD_WINDOW_MS = 3000  # writes within 3s of load → pre-consent candidates

    for w in writes:
        w_db = w.get("db", "") or ""
        w_store = w.get("store", "") or ""
        w_key = w.get("key", "") or ""
        w_op = w.get("op", "put")
        w_fn = w.get("fn") or None
        w_loc = w.get("loc") or ""
        w_trel = w.get("t_rel")

        writer_dom = _script_origin(w_loc)
        if not writer_dom:
            writer_role = "unknown"
            writer_stats["unknown"] += 1
            is_3p_writer = False
        else:
            is_3p_writer = not _is_same_party(site_domain, writer_dom)
            writer_role = "third_party" if is_3p_writer else "first_party"
            writer_stats[writer_role] += 1

        if isinstance(w_trel, (int, float)) and w_trel <= POST_LOAD_WINDOW_MS:
            pre_consent += 1

        leaves = _parse_write_value(w.get("value", "") or "")

        # Proven inflow: a leaf of the written value appeared in a response
        matched_url = ""
        matched_leaf = ""
        for leaf in leaves:
            for rleaf, rurl in resp_leaves:
                if leaf == rleaf or (len(leaf) >= config.MIN_ID_LENGTH
                                     and leaf in rleaf):
                    matched_url, matched_leaf = rurl, leaf
                    break
            if matched_url:
                break

        attribution.append({
            "op": w_op,
            "database": w_db,
            "store": w_store,
            "key": w_key,
            "writer_origin": writer_dom or None,
            "writer_role": writer_role,
            "writer_function": w_fn,
            "writer_stack": w_loc or None,
            "t_rel_ms": w_trel,
            "leaf_count": len(leaves),
            "value_preview": (leaves[0][:64] if leaves else ""),
        })

        if matched_url:
            req_dom = urlparse(matched_url).netloc if matched_url else ""
            # Response may be same-origin (API call) — still inflow if data
            # physically arrived from the network.
            is_3p_resp = bool(req_dom) and not _is_same_party(site_domain, req_dom)
            inflow.append({
                "flow_direction": config.FLOW_INFLOW,
                "source_class": "network_response",
                "sink_class": f"IDBObjectStore.{w_op}",
                "value": matched_leaf,
                "value_hash": __import__("hashlib").sha256(
                    matched_leaf.encode("utf-8", "ignore")).hexdigest()[:16],
                "path": f"{w_db}/{w_store}/{w_key}".strip("/"),
                "database": w_db,
                "store": w_store,
                "record_key": w_key,
                "response_url": matched_url,
                "request_domain": req_dom or None,
                "writer_origin": writer_dom or None,
                "writer_role": writer_role,
                "writer_function": w_fn,
                "mechanism": "response_match",
                "confidence": (config.CONFIDENCE_HIGH if is_3p_resp
                               else config.CONFIDENCE_MEDIUM),
                "is_third_party": is_3p_resp,
                "is_known_tracker": _is_known_tracker(req_dom) if req_dom else False,
                "confinement": classify_confinement(site_domain, req_dom)
                               if req_dom else config.CONFINEMENT_INTERNAL,
                "cross_origin": classify_cross_origin(site_domain, req_dom)
                                if req_dom else None,
                "t_rel_ms": w_trel,
            })

    return {
        "writes": attribution,
        "inflow_flows": inflow,
        "writer_stats": writer_stats,
        "pre_consent_candidates": pre_consent,
        "write_count": len(writes),
        "response_count": len(responses),
    }


def analyze_other_storage(site_data: dict, site_domain: str) -> dict:
    """
    Phase 6: run the SAME identifier extraction + transform-aware
    matching over localStorage, sessionStorage, cookies, Cache Storage
    and service workers — so IDB can be compared to every other store
    on one axis.

    Returns:
      {
        "comparison": {storage_type: {identifiers, exfil_events,
                                      third_party_exfils}},
        "storage_exfiltrations": [events…],   # all non-IDB exfil events
        "respawn_candidates": [{value_hash, stores:[...]}…],  # same value
                                                  # in cookie AND idb
        "captured": {storage_type: counts…},
      }
    """
    other = site_data.get("other_storage") or {}
    network = site_data.get("network_requests") or []

    # ── build identifier pools per storage type ──
    pools: dict[str, list[dict]] = {
        "localStorage": [], "sessionStorage": [], "cookies": [],
        "caches": [], "service_workers": [],
    }

    def _tag(idents, storage_type):
        for i in idents:
            i["storage_type"] = storage_type
        return idents

    for store_name in ("localStorage", "sessionStorage"):
        blob = other.get(store_name) or {}
        # include frame copies (iframes may hold third-party storage)
        sources = [(None, blob)]
        for fr in other.get("frames") or []:
            fblob = fr.get(store_name) or {}
            if fblob:
                sources.append((fr.get("frame_url", ""), fblob))
        seen_keys = set()
        for frame_url, fb in sources:
            for k, v in fb.items():
                key = (frame_url or "", k)
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                path = f"{store_name}/{k}"
                idents = extract_potential_ids(v, path)
                for i in idents:
                    i["record_key"] = k
                    i["store"] = store_name
                    i["database"] = frame_url or ""
                pools[store_name].extend(_tag(idents, store_name))

    for ck in other.get("cookies") or []:
        val = str(ck.get("value", ""))
        idents = extract_potential_ids(val, f"cookies/{ck.get('name','')}")
        for i in idents:
            i["record_key"] = ck.get("name", "")
            i["store"] = "cookies"
        pools["cookies"].extend(_tag(idents, "cookies"))

    # Cache request URLs: the URL itself may carry identifiers
    for cname, urls in (other.get("caches") or {}).items():
        for u in urls or []:
            fake_idents = extract_potential_ids(
                u, f"caches/{cname}")
            # also treat full URL as candidate (query strings embedded)
            fake_idents.extend(extract_potential_ids(
                str(u), f"caches/{cname}/url"))
            for i in fake_idents:
                i["store"] = f"caches/{cname}"
            pools["caches"].extend(_tag(fake_idents, "caches"))

    for sw_url in other.get("service_workers") or []:
        idents = extract_potential_ids(str(sw_url), "service_workers")
        for i in idents:
            i["store"] = "service_workers"
        pools["service_workers"].extend(_tag(idents, "service_workers"))

    # ── same matching on each pool ──
    storage_exfils: list[dict] = []
    comparison: dict[str, dict] = {}
    idb_ident_values = set()

    # IDB pool (from first-iteration extraction, same as main pass)
    idb = site_data.get("indexeddb") or {}
    for db in idb.get("databases") or []:
        for store in db.get("stores") or []:
            for record in store.get("records") or []:
                for ident in extract_potential_ids(
                        record.get("value"),
                        f"{db.get('name','')}/{store.get('name','')}/"
                        f"{record.get('key','')}"):
                    idb_ident_values.add(str(ident.get("value", "")))

    for stype, idents in pools.items():
        # dedupe identifiers within pool by value (frames may duplicate)
        dedup = {}
        for i in idents:
            dedup.setdefault(str(i.get("value", "")), i)
        idents = list(dedup.values())
        exfils = find_exfiltrations(idents, network, site_domain)
        for e in exfils:
            e["storage_type"] = stype
        storage_exfils.extend(exfils)
        comparison[stype] = {
            "identifiers": len(idents),
            "exfil_events": len(exfils),
            "third_party_exfils": sum(1 for e in exfils
                                      if e.get("is_third_party")),
        }

    # IDB row is filled by analyze_site (it owns the main-pass counts);
    # placeholder keeps the axis shape stable when called standalone.
    comparison.setdefault("indexeddb", {
        "identifiers": 0, "exfil_events": 0, "third_party_exfils": 0,
    })

    # ── respawn candidates: value present in BOTH cookies and IDB ──
    cookie_names_by_val: dict[str, list[str]] = {}
    for c in other.get("cookies") or []:
        cookie_names_by_val.setdefault(str(c.get("value", "")), []).append(
            str(c.get("name", "")))
    import hashlib
    respawn = []
    for v in idb_ident_values & set(cookie_names_by_val):
        if len(v) >= config.MIN_ID_LENGTH:
            respawn.append({
                "value_hash": hashlib.sha256(
                    v.encode("utf-8", "ignore")).hexdigest()[:16],
                "stores": ["indexeddb", "cookies"],
                "cookie_names": cookie_names_by_val.get(v, []),
            })

    captured = {
        "localStorage": len(other.get("localStorage") or {}),
        "sessionStorage": len(other.get("sessionStorage") or {}),
        "cookies": len(other.get("cookies") or []),
        "caches": len(other.get("caches") or {}),
        "service_workers": len(other.get("service_workers") or []),
        "frames": len(other.get("frames") or []),
    }
    logger.info(
        f"  Storage comparison: "
        + ", ".join(f"{k}={v['identifiers']}ids/{v['exfil_events']}exfil"
                    for k, v in comparison.items())
        + f" | respawn candidates: {len(respawn)}"
    )
    return {
        "comparison": comparison,
        "storage_exfiltrations": storage_exfils,
        "respawn_candidates": respawn,
        "captured": captured,
    }


def _analyze_consent(iterations: list[dict], site_domain: str) -> dict | None:
    """
    Phase 4: compare consent conditions for one site.

    Returns None when no consent-study iterations are present (normal
    scans). Otherwise a dict:

      {
        "conditions": {
          "none":   {banner_detected, state, writes, pre_click_writes,
                     idb_records_post_load, idb_records_post_consent, ...},
          "accept": {...},
          "reject": {...},
        },
        "headline": {
          "writes_after_reject": int,       # tracking persisted post-reject
          "writes_before_consent": int,     # activity before any click
          "banner_detected": bool,
          "banner_failures": [str],         # never silently "no banner"
          "tracking_without_consent": bool,
        }
      }
    """
    consent_iters = [it for it in iterations if it.get("consent")]
    if not consent_iters:
        return None

    conditions = {}
    banner_failures = []
    total_pre_click = 0
    total_post_reject_writes = 0

    for it in consent_iters:
        rec = it["consent"]
        action = rec.get("action", "none")
        banner = rec.get("banner") or {}
        outcome = rec.get("outcome") or {}
        state = outcome.get("state", "unknown")
        hooks = it.get("flow_hooks", {}) or {}
        writes = hooks.get("writes", []) or []
        t_click = rec.get("t_rel_click")
        snaps = rec.get("snapshots") or {}

        pre_click = [w for w in writes
                     if isinstance(w.get("t_rel"), (int, float))
                     and t_click is not None
                     and w["t_rel"] <= t_click]
        # When no click happened (action=none), every write is "pre-consent"
        if not outcome.get("clicked") and action == "none":
            pre_click = list(writes)

        if outcome.get("error"):
            banner_failures.append(f"{action}: {outcome['error']}")

        snap_load = snaps.get("post_load") or {}
        snap_after = snaps.get("post_consent") or {}

        cond = conditions.setdefault(action, {
            "runs": 0, "banner_detected": False, "states": [],
            "writes": 0, "pre_click_writes": 0,
            "post_click_writes": 0,
            "idb_records_post_load": 0, "idb_records_post_consent": 0,
            "idb_growth": 0, "errors": [],
        })
        cond["runs"] += 1
        cond["banner_detected"] = cond["banner_detected"] or bool(
            banner.get("detected"))
        cond["states"].append(state)
        cond["writes"] += len(writes)
        cond["pre_click_writes"] += len(pre_click)
        cond["post_click_writes"] += len(writes) - len(pre_click)
        cond["idb_records_post_load"] = max(
            cond["idb_records_post_load"],
            snap_load.get("record_count", 0))
        cond["idb_records_post_consent"] = max(
            cond["idb_records_post_consent"],
            snap_after.get("record_count", 0))
        cond["idb_growth"] = max(
            0, snap_after.get("record_count", 0)
            - snap_load.get("record_count", 0))
        if outcome.get("error"):
            cond["errors"].append(str(outcome["error"]))

        # Per-condition exfiltration: identifiers from THIS run's IDB
        # matched against THIS run's network (fresh context per condition,
        # so the comparison is apples-to-apples).
        it_idb = it.get("indexeddb") or {}
        it_ids = []
        for db in it_idb.get("databases") or []:
            for store in db.get("stores") or []:
                for record in store.get("records") or []:
                    for ident in extract_potential_ids(
                            record.get("value"),
                            f"{db.get('name','')}/{store.get('name','')}/"
                            f"{record.get('key','')}"):
                        ident["database"] = db.get("name", "")
                        ident["store"] = store.get("name", "")
                        ident["record_key"] = str(record.get("key", ""))
                        it_ids.append(ident)
        it_exfils = find_exfiltrations(
            it_ids, it.get("network_requests") or [], site_domain)
        third_party_exfils = [e for e in it_exfils if e.get("is_third_party")]
        cond["exfil_events"] = cond.get("exfil_events", 0) + len(it_exfils)
        cond["third_party_exfils"] = (cond.get("third_party_exfils", 0)
                                      + len(third_party_exfils))
        cond["identifiers"] = cond.get("identifiers", 0) + len(it_ids)

        total_pre_click += len(pre_click)
        if action == "reject" and outcome.get("clicked"):
            total_post_reject_writes += len(writes) - len(pre_click)

    banner_detected = any(c["banner_detected"] for c in conditions.values())
    headline = {
        "writes_after_reject": total_post_reject_writes,
        "writes_before_consent": total_pre_click,
        "banner_detected": banner_detected,
        "banner_failures": banner_failures,
        "third_party_exfils": {
            action: c.get("third_party_exfils", 0)
            for action, c in sorted(conditions.items())
        },
        "tracking_without_consent": bool(
            total_post_reject_writes > 0 or total_pre_click > 0),
    }
    logger.info(
        f"  Consent study: conditions={sorted(conditions)} "
        f"pre-consent writes={total_pre_click} "
        f"post-reject writes={total_post_reject_writes} "
        f"banner={banner_detected} failures={len(banner_failures)}"
    )
    return {"conditions": conditions, "headline": headline}


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

    # Phase 3: attach a scored-identifier rating (entropy + key-name shape
    # + pattern + persistence). Threshold is a tunable knob (Phase 7
    # ablation decides its final value; 0.0 = scoring recorded but the
    # legacy length/diff gates remain the only filters).
    for ident in flat_ids:
        key_name = ""
        if ident.get("reason", "").startswith("idb_key:"):
            key_name = ident["reason"].split(":", 1)[1]
        ident.update(tf.score_identifier(
            str(ident.get("value", "")),
            key_name=key_name,
            entropy=float(ident.get("entropy", -1)),
            changed_across_iterations=bool(
                ident.get("changed_across_iterations")),
            reasons=str(ident.get("reason", "")),
        ))
    score_thr = float(getattr(config, "ID_SCORE_THRESHOLD", 0.0) or 0.0)
    if score_thr > 0.0:
        before = len(flat_ids)
        flat_ids = [i for i in flat_ids
                    if float(i.get("score", 0)) >= score_thr]
        logger.info(f"  Score gate ≥{score_thr}: {before} → {len(flat_ids)}")

    # Filter: if we have diff data, keep identifiers from CHANGED records,
    # OR static records that have very high entropy (likely persistent IDs)
    if changed_paths:
        if getattr(config, "LEGACY_DIFF_FILTER", False):
            # Legacy behavior (kept measurable for ablation): changed OR
            # very-high-entropy static records only — drops most real IDs
            # whenever ANY record in the store changes (e.g. timestamps).
            changed_ids = [
                i for i in flat_ids
                if i.get("changed_across_iterations")
                or i.get("entropy", 0) > 4.5
            ]
        else:
            # Fixed filter: a static identifier survives when it scores
            # as a strong identifier (score ≥ 0.4 — Phase 3 model), so a
            # single volatile record no longer wipes the ID pool.
            changed_ids = [
                i for i in flat_ids
                if i.get("changed_across_iterations")
                or i.get("entropy", 0) > 4.5
                or float(i.get("score", 0)) >= 0.4
            ]
        static_ids = [i for i in flat_ids if i not in changed_ids]
        logger.info(
            f"  Identifiers: {len(flat_ids)} total → "
            f"{len(changed_ids)} kept ({len(static_ids)} filtered out)"
            + (" [legacy diff filter]"
               if getattr(config, "LEGACY_DIFF_FILTER", False) else "")
        )
        flat_ids = changed_ids
    else:
        logger.info(f"  Found {len(flat_ids)} potential identifiers")

    # Paper §4.1 client-identifier classification (IndexedDB only,
    # Chen-et-al. heuristic per the methodology paper). Needs the
    # iteration list — hoisted here ahead of Step 1b.
    iterations = site_data.get("iterations", []) or []
    uid_report = paper_uid.classify_site(
        iterations, min_len=config.MIN_ID_LENGTH)
    paper_uid.attach_to_identifiers(flat_ids, uid_report)
    logger.info(
        f"  Paper client identifiers (§4.1, IDB-only): "
        f"{uid_report['confirmed_count']} confirmed, "
        f"{uid_report['candidate_count']} candidates "
        f"(evaluated={uid_report['evaluated']})")

    # Step 1b: Aggregate Foxhound taint flows + IDB hook flows across
    # iterations (these live under each iteration's crawl result).
    taint_flows = []
    idb_hook_flows = []
    seen_taint = set()
    seen_hook = set()
    site_loc = site_data.get("url", "") or ""
    # Phase 2: write-side aggregation (attribution + proven inflow)
    write_analysis = {"writes": [], "inflow_flows": [],
                      "writer_stats": {"first_party": 0, "third_party": 0,
                                       "unknown": 0},
                      "pre_consent_candidates": 0, "write_count": 0,
                      "response_count": 0}
    seen_inflow = set()
    for it in iterations:
        it_network = it.get("network_requests", []) or []
        # Consent state of this run (Phase 4) — tag every flow it yields
        it_consent = ((it.get("consent") or {}).get("outcome") or {}
                      ).get("state") or None
        for tf_ev in parse_taint_flows(it.get("taint_events", []), domain,
                                       it_network, it.get("indexeddb")):
            k = (tf_ev.get("sink"), tf_ev.get("source_operation"),
                 tf_ev.get("source_line"), tf_ev.get("target"))
            if k in seen_taint:
                continue
            seen_taint.add(k)
            if it_consent:
                tf_ev["consent_state"] = it_consent
            taint_flows.append(tf_ev)
        it_hooks = it.get("flow_hooks", {})
        for hf in analyze_idb_hook_flows(it_hooks, it_network,
                                         domain, site_loc):
            k = (hf.get("source_function"), hf.get("source_store"),
                 hf.get("target"))
            if k in seen_hook:
                continue
            seen_hook.add(k)
            if it_consent:
                hf["consent_state"] = it_consent
            idb_hook_flows.append(hf)

        # Write-side: attribution for every write + response-proven inflow
        wa = analyze_idb_writes(it_hooks, domain, it_network)
        write_analysis["writes"].extend(wa["writes"])
        for role, n in wa["writer_stats"].items():
            write_analysis["writer_stats"][role] += n
        write_analysis["pre_consent_candidates"] += wa["pre_consent_candidates"]
        write_analysis["write_count"] += wa["write_count"]
        write_analysis["response_count"] += wa["response_count"]
        for inf in wa["inflow_flows"]:
            k = (inf.get("database"), inf.get("store"),
                 inf.get("record_key"), inf.get("value_hash"))
            if k in seen_inflow:
                continue
            seen_inflow.add(k)
            write_analysis["inflow_flows"].append(inf)

    logger.info(
        f"  Taint flows: {len(taint_flows)} | IDB hook flows: {len(idb_hook_flows)}"
    )

    # Step 1c: Phase 4 — consent-condition comparison. Each consent-study
    # iteration carries result["consent"] (action, banner, outcome,
    # snapshots). Headline: writes/flows under reject and pre-click
    # activity = tracking without consent.
    consent_analysis = _analyze_consent(iterations, domain)

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
        # Source provenance: the IDB record this identifier was extracted
        # from (db/store/key are attached by the extractor pass). The exact
        # JS read op is unknown for substring matches — that is what the
        # taint/hook mechanisms provide.
        db = evt.get("database", "")
        st = evt.get("store", "")
        evt["source_class"] = (
            f"IDBObjectStore.get:{db}/{st}" if db or st else "IDBObjectStore.get"
        )

    # ── Merge mechanism tags: substring ↔ taint/hook corroboration ──
    # An identifier observed by more than one mechanism is tagged "both";
    # this disagreement/agreement is a research result, not noise.
    taint_values = {str(f.get("tainted_value")) for f in taint_flows
                    if f.get("tainted_value")}
    hook_values = {str(f.get("idb_value")) for f in idb_hook_flows
                   if f.get("idb_value")}

    uid_verdict_by_value = {
        str(i.get("value")): i.get("client_identifier")
        for i in flat_ids
        if i.get("client_identifier") is not None}

    for evt in exfiltrations:
        val = str(evt.get("identifier_value", ""))
        # Paper §4.1: is this value a confirmed client identifier?
        evt["client_identifier"] = uid_verdict_by_value.get(val)
        # Base mechanism from Phase 3 matching: "transform" when a
        # non-raw variant matched, else "substring".
        base_mech = evt.get("mechanism") or "substring"
        if base_mech == "both":
            base_mech = "substring"
        mech = [base_mech]
        if val in taint_values:
            mech.append("taint")
        if val in hook_values:
            mech.append("idb_hook")
        evt["mechanism"] = "both" if len(mech) > 1 else base_mech
        evt["taint_confirmed"] = len(mech) > 1
        evt["corroborating_mechanisms"] = mech

    logger.info(
        f"  Found {len(exfiltrations)} exfiltration events "
        f"({sum(1 for e in exfiltrations if e.get('taint_confirmed'))} taint-corroborated)"
    )

    # Step 3b: Phase 6 — same matching over every other store, so IDB
    # can be compared against localStorage/cookies/caches on one axis.
    storage_analysis = analyze_other_storage(site_data, domain)
    storage_analysis["comparison"]["indexeddb"] = {
        "identifiers": len(flat_ids),
        "exfil_events": len(exfiltrations),
        "third_party_exfils": sum(1 for e in exfiltrations
                                  if e.get("is_third_party")),
    }

    # Step 4: Inflow (source → IDB).
    # Response-proven inflow (Phase 2 hooks) takes precedence; the legacy
    # URL-param/navigator heuristic still runs as a fallback for crawls
    # collected without hooks — tagged so the two are distinguishable.
    integrity_flows = list(write_analysis["inflow_flows"])
    seen_iv = {(f.get("database"), f.get("store"), f.get("record_key"),
                f.get("value", "")[:64]) for f in integrity_flows}
    for f in detect_integrity_flows(site_data):
        k = (f.get("database"), f.get("store"), f.get("record_key"),
             f.get("value", "")[:64])
        if k in seen_iv:
            continue
        f["mechanism"] = "heuristic"
        integrity_flows.append(f)
    logger.info(
        f"  Found {len(integrity_flows)} inflow flows "
        f"({len(write_analysis['inflow_flows'])} response-proven, "
        f"{write_analysis['write_count']} writes observed, "
        f"writer split: {write_analysis['writer_stats']})"
    )

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
            # Phase 3: report extractor truncation instead of hiding it
            "truncated_stores": sum(
                1
                for d in idb.get("databases", [])
                for s in d.get("stores", [])
                if s.get("truncated")
            ),
            "truncated_records": sum(
                s.get("truncatedCount", 0)
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
        "consent_analysis": consent_analysis,
        "storage_analysis": storage_analysis,
        # Paper §4.1 client identifiers (IndexedDB records only)
        "client_identifiers": [
            i for i in uid_report.get("identifiers", [])
            if i.get("confirmed")],
        "client_identifiers_found": uid_report.get(
            "confirmed_count", 0),
        "uid_candidates": uid_report.get("candidate_count", 0),
        "uid_summary": uid_report,
        "write_attribution": {
            "total_writes": write_analysis["write_count"],
            "responses_captured": write_analysis["response_count"],
            "writer_stats": write_analysis["writer_stats"],
            "pre_consent_candidates": write_analysis["pre_consent_candidates"],
            "writes": write_analysis["writes"][:200],
        },
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
