"""
Test Cases — Live Crawl & Detection Report for Manual Verification

Crawls a small set of curated websites, runs the detection pipeline,
and produces a human-readable JSON report with:
  - IndexedDB key:value pairs
  - Tracker domains with request URLs and status codes
  - All third-party requests
  - Inflow flows (external data → IDB)
  - Pass/Fail verdict per site

Usage:
    python test_cases.py                              # Default test sites
    python test_cases.py --url https://example.com    # Custom URL(s)
    python test_cases.py --no-headless                # Show browser
    python test_cases.py --iterations 2               # Multiple crawls
"""

import argparse
import asyncio
import json
import os
import logging
import sys
from datetime import datetime
from urllib.parse import urlparse

from playwright.async_api import async_playwright

import config
from crawler import SiteCrawler, EXTRACT_INDEXEDDB_SCRIPT
from detector import (
    analyze_site,
    _is_same_party,
    _is_known_tracker,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)

# ─── Default Test Sites ─────────────────────────────────────────────
# Hand-picked from sites.json — diverse tracker types for coverage.
DEFAULT_TEST_SITES = [
    {
        "url": "https://firearmsdepot.com/",
        "expected_tracker": "Klaviyo",
        "reason": "Third-party Klaviyo tracking script using IndexedDB",
    },
    {
        "url": "https://calculojuridico.com.br/",
        "expected_tracker": "CrazyEgg",
        "reason": "Third-party CrazyEgg tracking script using IndexedDB",
    },
    {
        "url": "https://omtechlaser.com/",
        "expected_tracker": "PushOwl",
        "reason": "Third-party PushOwl push notification script using IndexedDB",
    },
    {
        "url": "https://www.billabong.com/",
        "expected_tracker": "Shopify",
        "reason": "Shopify web pixel script using IndexedDB",
    },
    {
        "url": "https://chem25.aparsclassroom.com/",
        "expected_tracker": "Firebase",
        "reason": "Firebase Analytics third-party script using IndexedDB",
    },
]

# ─── Output Directory ───────────────────────────────────────────────
TEST_REPORTS_DIR = os.path.join(config.RESULTS_DIR, "test_reports")


# ─── Crawl a Single Site (simplified, single-pass) ──────────────────
async def _crawl_single(url: str, headless: bool, iterations: int) -> dict:
    """
    Crawl a URL with fresh browser instances and return raw crawl data.

    Unlike the main pipeline, this stores full response status codes
    for every network request to aid manual verification.
    """
    all_iterations = []

    for i in range(1, iterations + 1):
        logger.info(f"  Iteration {i}/{iterations} — fresh browser")
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=headless)
            crawler = SiteCrawler()
            result = await crawler.crawl_site(browser, url)
            result["iteration"] = i
            all_iterations.append(result)
            await browser.close()
        if i < iterations:
            await asyncio.sleep(2)

    # Combine iterations (same structure as crawler.crawl_all_sites)
    first = all_iterations[0]
    combined = {
        "url": url,
        "domain": first["domain"],
        "timestamp": first["timestamp"],
        "iterations": all_iterations,
        "indexeddb": first.get("indexeddb", {"databases": []}),
        "network_requests": first.get("network_requests", []),
        "errors": [],
    }
    for it in all_iterations:
        for err in it.get("errors", []):
            combined["errors"].append(f"iter{it['iteration']}: {err}")

    return combined


# ─── Build the Human-Readable Report ────────────────────────────────
def _build_site_report(site_info: dict, raw_data: dict, analysis: dict) -> dict:
    """
    Build a flat, human-readable report dict for a single test site.
    """
    domain = raw_data.get("domain", "unknown")
    url = raw_data.get("url", "")

    # ── IDB Records (raw key:value pairs) ────────────────────────────
    idb_data = raw_data.get("indexeddb", {})
    idb_report = {
        "database_count": len(idb_data.get("databases", [])),
        "databases": [],
    }
    for db in idb_data.get("databases", []):
        db_entry = {
            "name": db.get("name", ""),
            "version": db.get("version"),
            "stores": [],
        }
        for store in db.get("stores", []):
            store_entry = {
                "name": store.get("name", ""),
                "record_count": store.get("recordCount", 0),
                "records": [],
            }
            for record in store.get("records", [])[:50]:  # Cap for readability
                store_entry["records"].append({
                    "key": record.get("key"),
                    "value": record.get("value"),
                })
            db_entry["stores"].append(store_entry)
        idb_report["databases"].append(db_entry)

    # ── Tracker-related exfiltration events ──────────────────────────
    trackers_detected = []
    for evt in analysis.get("exfiltration_events", []):
        # Find the matching network request to get status code
        status_code = _find_status_code(
            evt.get("request_url", ""),
            raw_data.get("network_requests", []),
        )
        trackers_detected.append({
            "tracker_domain": evt.get("request_domain", ""),
            "request_url": evt.get("request_url", ""),
            "method": evt.get("request_method", ""),
            "status_code": status_code,
            "is_known_tracker": evt.get("is_known_tracker", False),
            "is_third_party": evt.get("is_third_party", False),
            "identifier_exfiltrated": evt.get("identifier_value", ""),
            "identifier_path": evt.get("identifier_path", ""),
            "exfil_location": evt.get("match_location", ""),
            "confidence": evt.get("confidence", ""),
            "flow_direction": evt.get("flow_direction", ""),
            "confinement": evt.get("confinement", ""),
            "cross_origin": evt.get("cross_origin"),
            "sink_class": evt.get("sink_class", ""),
        })

    # ── All third-party requests (with status codes) ─────────────────
    all_third_party = []
    seen_urls = set()
    for req in raw_data.get("network_requests", []):
        req_url = req.get("url", "")
        if not req_url or req_url in seen_urls:
            continue
        req_domain = urlparse(req_url).netloc
        if _is_same_party(domain, req_domain):
            continue
        seen_urls.add(req_url)
        status = req.get("response", {})
        all_third_party.append({
            "domain": req_domain,
            "url": req_url[:200],  # Truncate very long URLs
            "method": req.get("method", ""),
            "status_code": status.get("status") if isinstance(status, dict) else None,
            "resource_type": req.get("resource_type", ""),
            "is_known_tracker": _is_known_tracker(req_domain),
        })

    # ── Inflow flows ─────────────────────────────────────────────────
    inflow_report = []
    for iflow in analysis.get("inflow_flows", []):
        inflow_report.append({
            "source": iflow.get("source_class", ""),
            "value_snippet": str(iflow.get("value", ""))[:80],
            "stored_in": iflow.get("path", ""),
            "database": iflow.get("database", ""),
            "store": iflow.get("store", ""),
        })

    # ── Pass/Fail verdict ────────────────────────────────────────────
    expected = site_info.get("expected_tracker", "").lower()
    verdict = "NO_EXPECTATION"
    if expected:
        # Check if any tracker domain or exfiltration event matches
        found = False
        for t in trackers_detected:
            if expected in t["tracker_domain"].lower():
                found = True
                break
        if not found:
            for tp in all_third_party:
                if expected in tp["domain"].lower() and tp["is_known_tracker"]:
                    found = True
                    break
        if not found:
            # Also check if the keyword appears in any third-party domain
            for tp in all_third_party:
                if expected in tp["domain"].lower():
                    found = True
                    break

        if found:
            verdict = "PASS" if trackers_detected else "PARTIAL"
        else:
            verdict = "FAIL"

    # ── Summary ──────────────────────────────────────────────────────
    exfil_summary = analysis.get("exfiltration_summary", {})
    summary = {
        "total_idb_databases": idb_report["database_count"],
        "total_idb_records": sum(
            s["record_count"]
            for db in idb_report["databases"]
            for s in db["stores"]
        ),
        "total_network_requests": len(raw_data.get("network_requests", [])),
        "third_party_requests": len(all_third_party),
        "identifiers_found": analysis.get("identifiers_found", 0),
        "exfiltration_events": exfil_summary.get("total", 0),
        "high_confidence": exfil_summary.get("high_confidence", 0),
        "medium_confidence": exfil_summary.get("medium_confidence", 0),
        "low_confidence": exfil_summary.get("low_confidence", 0),
        "inflow_flows": len(inflow_report),
    }

    return {
        "url": url,
        "domain": domain,
        "expected_tracker": site_info.get("expected_tracker", ""),
        "reason": site_info.get("reason", ""),
        "verdict": verdict,
        "crawl_timestamp": raw_data.get("timestamp", ""),
        "errors": raw_data.get("errors", []),
        "indexeddb": idb_report,
        "trackers_detected": trackers_detected,
        "all_third_party_requests": all_third_party,
        "inflow_flows": inflow_report,
        "summary": summary,
    }


def _find_status_code(target_url: str, network_requests: list) -> int | None:
    """Find the HTTP status code for a given URL from captured requests."""
    for req in network_requests:
        if req.get("url") == target_url:
            resp = req.get("response")
            if isinstance(resp, dict):
                return resp.get("status")
    return None


# ─── Main Runner ─────────────────────────────────────────────────────
async def run_tests(
    sites: list[dict],
    headless: bool = True,
    iterations: int = 1,
) -> dict:
    """
    Run the full test suite: crawl → detect → report.

    Returns the complete test report dict.
    """
    report = {
        "test_run": datetime.utcnow().isoformat() + "Z",
        "settings": {
            "headless": headless,
            "iterations": iterations,
            "sites_count": len(sites),
        },
        "sites": [],
    }

    for i, site in enumerate(sites, 1):
        url = site["url"]
        print(f"\n{'═' * 60}")
        print(f"  TEST {i}/{len(sites)}: {url}")
        print(f"  Expected: {site.get('expected_tracker', 'N/A')}")
        print(f"{'═' * 60}")

        # Step 1: Crawl
        print("  ⏳ Crawling...")
        raw_data = await _crawl_single(url, headless, iterations)

        # Step 2: Detect
        print("  🔍 Analyzing...")
        analysis = analyze_site(raw_data)

        # Step 3: Build report
        site_report = _build_site_report(site, raw_data, analysis)
        report["sites"].append(site_report)

        verdict = site_report["verdict"]
        emoji = {"PASS": "✅", "PARTIAL": "🟡", "FAIL": "❌"}.get(verdict, "ℹ️")
        print(f"  {emoji} Verdict: {verdict}")
        s = site_report["summary"]
        print(
            f"     IDB: {s['total_idb_databases']} dbs, "
            f"{s['total_idb_records']} records | "
            f"Net: {s['total_network_requests']} reqs | "
            f"Exfil: {s['exfiltration_events']} "
            f"(H:{s['high_confidence']} M:{s['medium_confidence']} "
            f"L:{s['low_confidence']}) | "
            f"Inflow: {s['inflow_flows']}"
        )

        if i < len(sites):
            await asyncio.sleep(2)

    # ── Save report ──────────────────────────────────────────────────
    os.makedirs(TEST_REPORTS_DIR, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path = os.path.join(TEST_REPORTS_DIR, f"test_report_{timestamp}.json")

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False, default=str)

    print(f"\n{'═' * 60}")
    print(f"  📋 TEST REPORT SAVED")
    print(f"     {out_path}")
    print(f"{'═' * 60}")

    # ── Print summary table ──────────────────────────────────────────
    print(f"\n  {'Site':<35} {'Expected':<12} {'Verdict':<10} "
          f"{'DBs':>4} {'Recs':>5} {'Exfil':>5} {'HIGH':>4}")
    print("  " + "─" * 90)
    for sr in report["sites"]:
        s = sr["summary"]
        v_emoji = {"PASS": "✅", "PARTIAL": "🟡", "FAIL": "❌"}.get(
            sr["verdict"], "ℹ️"
        )
        print(
            f"  {sr['domain']:<35} {sr['expected_tracker']:<12} "
            f"{v_emoji} {sr['verdict']:<7} "
            f"{s['total_idb_databases']:>4} {s['total_idb_records']:>5} "
            f"{s['exfiltration_events']:>5} {s['high_confidence']:>4}"
        )

    passed = sum(1 for sr in report["sites"] if sr["verdict"] == "PASS")
    partial = sum(1 for sr in report["sites"] if sr["verdict"] == "PARTIAL")
    failed = sum(1 for sr in report["sites"] if sr["verdict"] == "FAIL")
    print(f"\n  Results: {passed} PASS  |  {partial} PARTIAL  |  {failed} FAIL")
    print()

    return report


# ─── CLI ─────────────────────────────────────────────────────────────
def parse_args():
    parser = argparse.ArgumentParser(
        prog="python test_cases.py",
        description="Run test cases with live crawling and produce verification reports.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python test_cases.py                           # Default test sites
  python test_cases.py --url https://example.com # Custom URL
  python test_cases.py --no-headless             # Show browser
  python test_cases.py --iterations 2            # 2 crawl iterations
  python test_cases.py --url https://a.com --url https://b.com
        """,
    )
    parser.add_argument(
        "--url",
        action="append",
        metavar="URL",
        help="Custom URL to test (can be repeated). Overrides default sites.",
    )
    parser.add_argument(
        "--no-headless",
        action="store_true",
        help="Show browser window for debugging",
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=1,
        metavar="N",
        help="Number of crawl iterations per site (default: 1)",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    headless = not args.no_headless

    # Build site list
    if args.url:
        sites = []
        for u in args.url:
            if not u.startswith(("http://", "https://")):
                u = "https://" + u
            if not u.endswith("/"):
                u += "/"
            sites.append({
                "url": u,
                "expected_tracker": "",
                "reason": "custom test URL",
            })
    else:
        sites = DEFAULT_TEST_SITES

    print("\n" + "═" * 60)
    print("  IndexedDB TEST CASES — Live Crawl & Verification Report")
    print("═" * 60)
    print(f"  Sites: {len(sites)} | Iterations: {args.iterations} | "
          f"Headless: {headless}")

    asyncio.run(run_tests(sites, headless=headless, iterations=args.iterations))


if __name__ == "__main__":
    main()
