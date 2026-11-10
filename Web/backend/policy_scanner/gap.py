"""
Policy-vs-behavior gap analysis (Phase 9).

Compares what the privacy policy DISCLOSES (disclosure.py) against what
the measurement actually OBSERVED (detector events → entities via the
shared Disconnect vocabulary):

    received  = companies behind domains that received identifiers
    disclosed = companies the policy names
    gap       = received − undisclosed entities, storage claims vs
                observed IndexedDB activity, purpose claims vs observed
                advertising/analytics sinks

Both ends intentionally share the same entity lexicon, so a company
counted as "received" can only be absent from "disclosed" when the
policy genuinely never names it.

find_behavior_entities() reads the detector's combined_results.json
(or a summary entry) for one site.
"""

from __future__ import annotations

import datetime
import glob
import json
import logging
import os
import sys
from typing import Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

_ENGINE_DIR = os.path.abspath(os.path.join(
    os.path.dirname(__file__), "..", "..", "src", "engine"))
if _ENGINE_DIR not in sys.path:
    sys.path.insert(0, _ENGINE_DIR)


def _analysis_dir(engine: Optional[str] = None) -> list[str]:
    base = os.path.join(_ENGINE_DIR, "results")
    dirs = []
    if engine:
        dirs.append(os.path.join(base, engine.capitalize(), "analysis"))
    else:
        dirs.extend(os.path.join(base, e, "analysis")
                    for e in ("Chrome", "Foxhound"))
    return [d for d in dirs if os.path.isdir(d)]


def find_behavior(domain: str,
                  engine: Optional[str] = None) -> Optional[dict]:
    """
    Collect observed-behavior facts for one site from the detector
    output (combined_results.json entries).

    Returns {entities: [{company, category, count, urls[]}],
             domains: [...], mechanisms: {...}, observed_storage: [...],
             source_files: [...]} or None when no analysis exists.
    """
    import entities as eng_entities

    rows: list[dict] = []
    source_files: list[str] = []
    needle = domain.lower().replace(".", "_").replace(":", "_")
    for d in _analysis_dir(engine):
        # per-site files first
        candidates = glob.glob(os.path.join(d, "*.json"))
        for path in candidates:
            fname = os.path.basename(path)
            if fname in ("combined_results.json", "summary.json",
                         "statistics.json", "sites.json",
                         "global_report.json"):
                continue
            key = fname[:-5].lower()
            if needle not in key and key not in domain.lower().replace(
                    ".", "_"):
                continue
            try:
                with open(path, encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, list):
                    rows.extend(data)
                    source_files.append(path)
            except Exception:
                continue

    if not rows:
        # fall back: search combined_results.json
        for d in _analysis_dir(engine):
            path = os.path.join(d, "combined_results.json")
            if not os.path.exists(path):
                continue
            try:
                with open(path, encoding="utf-8") as f:
                    combined = json.load(f)
            except Exception:
                continue
            for site_key, entries in combined.items():
                if domain.lower() in site_key.lower() or \
                        site_key.lower() in domain.lower():
                    rows.extend(entries if isinstance(entries, list) else [])
                    source_files.append(path)

    if not rows:
        return None

    from collections import defaultdict
    ent_map: dict[str, dict] = {}
    domains: set[str] = set()
    mechanisms: dict[str, int] = defaultdict(int)
    observed_storage: set[str] = set()

    for row in rows:
        url = str(row.get("requestUrl") or row.get("request_url") or "")
        mech = str(row.get("mechanism", "unknown"))
        mechanisms[mech] += 1
        src = str(row.get("source", ""))
        if src.startswith("storage:"):
            observed_storage.add(src.split(":", 1)[1])
        if row.get("databaseName", "").startswith(("localStorage",
                                                   "cookies", "sessionStorage",
                                                   "caches")):
            observed_storage.add(
                str(row.get("databaseName", "")).split(":", 1)[0])
        host = urlparse(url).netloc if url else str(
            row.get("domain", ""))
        if not host:
            continue
        domains.add(host)
        ent = eng_entities.entity_for(host)
        company = (ent or {}).get("company") or host
        category = (ent or {}).get("category") or (
            "unknown" if not ent else ent.get("category"))
        bucket = ent_map.setdefault(company, {
            "company": company, "category": category, "count": 0,
            "urls": []})
        bucket["count"] += 1
        if url and len(bucket["urls"]) < 5:
            bucket["urls"].append(url[:200])

    return {
        "entities": sorted(ent_map.values(),
                           key=lambda x: -x["count"]),
        "domains": sorted(domains),
        "mechanisms": dict(mechanisms),
        "observed_storage": sorted(observed_storage),
        "source_files": source_files,
    }


def gap_report(disclosures: dict, behavior: Optional[dict]) -> dict:
    """The compliance-gap finding: received-but-not-disclosed."""
    disclosed_names = {
        t["name"].lower() for t in disclosures.get("third_parties", [])}
    # a disclosed domain implies its registrable company is disclosed
    from entities import registrable, entity_for
    disclosed_regs = {registrable(n) for n in disclosed_names if n}
    disclosed_companies = set()
    for n in disclosed_names:
        ent = entity_for(n)
        if ent and ent.get("company"):
            disclosed_companies.add(ent["company"].lower())
        else:
            disclosed_companies.add(n)

    behavior = behavior or {"entities": [], "observed_storage": [],
                            "mechanisms": {}}
    undisclosed = []
    received_names = []
    for ent in behavior.get("entities", []):
        name = ent.get("company") or ""
        received_names.append(name)
        if not name:
            continue
        # never count first-party / self references as gaps
        nl = name.lower()
        if nl in disclosed_companies or nl in disclosed_names:
            continue
        reg = registrable(name)
        if reg and reg in disclosed_regs:
            continue
        # registrable-name equality: disclosed "Google" vs received
        # "Google Analytics" handled by company lexicon on both sides
        if any(nl in dn or dn in nl for dn in disclosed_companies
               if len(dn) >= 4):
            continue
        undisclosed.append(ent)

    disclosed_storage = {s["tech"]
                         for s in disclosures.get("storage", [])}
    observed_storage = set(behavior.get("observed_storage") or [])
    # IndexedDB is THE project's focus: called out explicitly
    idb_disclosed = "indexeddb" in disclosed_storage
    idb_observed = "idb" in " ".join(observed_storage).lower() or \
        bool(behavior.get("mechanisms", {}).get("idb_hook")) or \
        bool(behavior.get("mechanisms", {}).get("taint"))

    disclosed_purposes = {p["purpose"]
                          for p in disclosures.get("purposes", [])}
    received_categories = {e.get("category")
                           for e in behavior.get("entities", [])
                           if e.get("category") and e.get("category")
                           != "unknown"}
    # which disclosed purpose should cover each received category
    category_purpose = {
        "Advertising": "advertising",
        "Analytics": "analytics",
        "Social": "social_media",
        "FingerprintingInvasive": "advertising",
        "FingerprintingGeneral": "advertising",
        "Email": "email_marketing",
        "EmailAggressive": "email_marketing",
    }
    purpose_gap = sorted(
        cat for cat in received_categories
        if cat in category_purpose
        and category_purpose[cat] not in disclosed_purposes
    )

    verdict_bits = []
    if undisclosed:
        verdict_bits.append(
            f"{len(undisclosed)} recipient compan(ies) never named in "
            f"the policy")
    if idb_observed and not idb_disclosed:
        verdict_bits.append("IndexedDB observed but not disclosed")
    if purpose_gap:
        verdict_bits.append(
            f"received categories without matching purpose: "
            f"{', '.join(purpose_gap)}")

    return {
        "received_companies": received_names,
        "disclosed_companies": sorted(disclosed_companies),
        "undisclosed_recipients": undisclosed,
        "storage": {
            "disclosed": sorted(disclosed_storage),
            "observed": sorted(observed_storage),
            "indexeddb_disclosed": idb_disclosed,
            "indexeddb_observed": bool(idb_observed),
        },
        "purposes": {
            "disclosed": sorted(disclosed_purposes),
            "received_categories": sorted(received_categories),
            "gap": purpose_gap,
        },
        "verdict": ("; ".join(verdict_bits) if verdict_bits
                    else "no material gap found"),
        "gap_found": bool(verdict_bits),
        "generated_at": datetime.datetime.now(datetime.timezone.utc)
                        .isoformat(),
    }


def full_gap(domain: str, policy_text: str, policy_url: str,
             engine: Optional[str] = None) -> dict:
    """One-shot: extract disclosures, load behavior, compute gap, save
    snapshot. Returns the whole report."""
    from disclosure import extract_disclosures, save_snapshot
    disclosures = extract_disclosures(policy_text)
    snapshot_path = save_snapshot(domain, policy_url, policy_text,
                                  disclosures)
    behavior = find_behavior(domain, engine)
    gap = gap_report(disclosures, behavior)
    return {
        "domain": domain,
        "policy_url": policy_url,
        "snapshot_path": snapshot_path,
        "disclosures": disclosures,
        "behavior": behavior,
        "gap": gap,
    }
