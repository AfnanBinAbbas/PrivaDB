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

import config

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
    as a potential identifier. No pattern matching — purely length-based.

    Returns list of dicts: {value, path, reason, entropy}
    """
    results = []
#(Sir ko dikhana)
    if isinstance(value, str):
        if len(value) >= config.MIN_ID_LENGTH:
            results.append({
                "value": value,
                "path": path,
                "reason": "idb_value",
                "entropy": shannon_entropy(value),
            })
    elif isinstance(value, dict):
        for k, v in value.items():
            child_path = f"{path}.{k}" if path else k
            # Check ANY key with a string value >= MIN_ID_LENGTH
            if isinstance(v, str) and len(v) >= config.MIN_ID_LENGTH:
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


def _check_string_value(value: str, path: str, results: list):
    """Check a string value for tracking identifier patterns."""
    if len(value) < config.MIN_ID_LENGTH:
        return

    # UUID v4
    if config.UUID_V4_RE.search(value):
        for match in config.UUID_V4_RE.finditer(value):
            results.append({
                "value": match.group(),
                "path": path,
                "reason": "uuid_v4",
                "entropy": shannon_entropy(match.group()),
            })
        return

    # Hex string (≥16 chars)
    if config.HEX_STRING_RE.match(value):
        results.append({
            "value": value,
            "path": path,
            "reason": "hex_string",
            "entropy": shannon_entropy(value),
        })
        return

    # Base64 blob
    if config.BASE64_RE.match(value) and len(value) >= 20:
        results.append({
            "value": value,
            "path": path,
            "reason": "base64_blob",
            "entropy": shannon_entropy(value),
        })
        return

    # High-entropy string (likely random identifier)
    entropy = shannon_entropy(value)
    if entropy >= config.ENTROPY_THRESHOLD and len(value) >= 12 and len(value) <= 128:
        # Exclude common non-tracking high-entropy strings
        if not _is_common_value(value):
            results.append({
                "value": value,
                "path": path,
                "reason": "high_entropy",
                "entropy": entropy,
            })


def _is_common_value(value: str) -> bool:
    """Filter out strings that are high-entropy but clearly not tracking IDs."""
    lower = value.lower()
    # URLs, file paths, common words
    if lower.startswith(("http://", "https://", "/", "data:", "blob:")):
        return True
    if any(ext in lower for ext in [".js", ".css", ".html", ".png", ".jpg", ".svg"]):
        return True
    # Dates
    if re.match(r'^\d{4}-\d{2}-\d{2}', value):
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
                    "match_location": match_location,
                    "is_third_party": is_third_party,
                    "is_known_tracker": is_known_tracker,
                    "confidence": confidence,
                })

    # Deduplicate and filter false positives
    seen = set()
    unique_events = []
    for evt in events:
        key = (evt["identifier_value"], evt["request_url"], evt["match_location"])
        if key not in seen:
            seen.add(key)
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
    url = request.get("url", "")

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
    headers = request.get("headers", {})
    for header_name in ("cookie", "authorization", "x-client-id", "x-request-id"):
        header_val = headers.get(header_name, "")
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
    domain = site_data.get("domain", "unknown")
    url = site_data.get("url", "")
    integrity_flows = []

    # Collect source data from the page
    parsed = urlparse(url)
    url_params = parse_qs(parsed.query)
    url_param_values = set()
    for vals in url_params.values():
        url_param_values.update(v for v in vals if len(v) >= config.MIN_ID_LENGTH)

    # Scan IDB records for values matching external source patterns
    idb = site_data.get("indexeddb", {})
    for db in idb.get("databases", []):
        db_name = db.get("name", "")
        for store in db.get("stores", []):
            store_name = store.get("name", "")
            for record in store.get("records", []):
                value = record.get("value")
                key = record.get("key", "")
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
        if r.get("indexeddb_summary", {}).get("database_count", 0) > 0
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
    for db in idb_data.get("databases", []):
        db_name = db.get("name", "")
        for store in db.get("stores", []):
            store_name = store.get("name", "")
            for record in store.get("records", []):
                key = str(record.get("key", ""))
                value = str(record.get("value", ""))
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
        idb = it.get("indexeddb", {})
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
    idb = site_data.get("indexeddb", {})

    for db in idb.get("databases", []):
        db_name = db.get("name", "")
        for store in db.get("stores", []):
            store_name = store.get("name", "")
            for record in store.get("records", []):
                key = record.get("key", "")
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

    # Step 2: Find exfiltrations (outflow flows)
    network = site_data.get("network_requests", [])
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
        "inflow_flows": integrity_flows,
        "flow_classification": {
            "outflow_flows": len(exfiltrations),
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


def analyze_all_sites(raw_data_dir: str = None,
                      site_limit: int = None,
                      only_files: list[str] = None) -> list[dict]:
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

    for filename in json_files:
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
