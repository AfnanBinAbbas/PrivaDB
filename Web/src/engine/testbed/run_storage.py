#!/usr/bin/env python3
"""
Phase 6 storage study — ground-truth verification.

Serves testbed/pages/storage.html (localStorage exfil, sessionStorage
control, IDB→cookie respawn cycle) and asserts:

  S1 other_storage captured (localStorage, cookies at minimum)
  S2 localStorage value exfiltrated → storage_exfiltrations with
     mechanism=localStorage (transform-aware, third-party sink)
  S3 RESPAWN: value restored into 'respawn_restored' cookie from IDB
     after deletion → respawn_candidates entry names that cookie
  S4 comparison covers all five non-IDB stores + the IDB row
  S5 sessionStorage control captured

Usage:
    python testbed/run_storage.py [--engine foxhound|chrome] [--headless]
"""
import argparse
import asyncio
import json
import os
import sys
import threading
from http.server import ThreadingHTTPServer

ENGINE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ENGINE_DIR)

import app_config as config  # noqa: E402

from testbed.run_smoke import (  # noqa: E402
    PAGE_PORT, SINK_PORT, PageHandler, SinkHandler, CHECK_LOG, _check,
)

PAGE_PATH = f"http://localhost:{PAGE_PORT}/storage.html"
KNOWN_LSVAL = "ls-value-fedcba98765432101122334455667788"
KNOWN_SSVAL = "ss-value-887766554433221100ffeeddccbbaa99"


async def _crawl(engine: str, headless: bool) -> dict:
    from crawler import crawl_all_sites
    from detector import analyze_site

    config.set_engine(engine)
    config.HEADLESS = headless
    config.CRAWL_ITERATIONS = 1
    results = await crawl_all_sites(
        custom_sites=[{"url": PAGE_PATH, "reason": "phase6 storage study"}],
    )
    return analyze_site(results[0]) if results else {}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--engine", default="foxhound",
                        choices=["foxhound", "chrome"])
    parser.add_argument("--headless", action="store_true")
    args = parser.parse_args()

    sink = ThreadingHTTPServer(("127.0.0.1", SINK_PORT), SinkHandler)
    page = ThreadingHTTPServer(("127.0.0.1", PAGE_PORT), PageHandler)
    for srv in (sink, page):
        threading.Thread(target=srv.serve_forever, daemon=True).start()
    print(f"  page: {PAGE_PATH}")
    print(f"  sink: http://127.0.0.1:{SINK_PORT}/")

    try:
        analysis = asyncio.run(_crawl(args.engine, args.headless))
        if not analysis:
            print("FATAL: crawl returned no data")
            return 2

        sa = analysis.get("storage_analysis") or {}
        comp = sa.get("comparison") or {}
        exfils = sa.get("storage_exfiltrations") or []
        respawn = sa.get("respawn_candidates") or []
        captured = sa.get("captured") or {}

        print("\n=== Storage-study assertions ===")
        results = []

        # S1: capture happened
        results.append(_check(
            "S1 other_storage captured (ls + cookies)",
            captured.get("localStorage", 0) >= 1
            and captured.get("cookies", 0) >= 1,
            f"captured={json.dumps(captured)}"))

        # S2: localStorage exfil, third-party sink, mechanism correct
        ls_hits = [e for e in exfils
                   if KNOWN_LSVAL in str(e.get("identifier_value", ""))
                   and e.get("storage_type") == "localStorage"]
        results.append(_check(
            "S2 localStorage value exfiltrated (storage_exfiltrations)",
            bool(ls_hits),
            f"{len(ls_hits)} hit(s), chains="
            f"{sorted({tuple(e.get('transform_chain') or []) for e in ls_hits})}"))
        if ls_hits:
            results.append(_check(
                "S2b classified third-party (localhost page → 127.0.0.1 sink)",
                any(e.get("is_third_party") for e in ls_hits)))

        # S3: respawn — restored cookie named 'respawn_restored' present
        respawn_named = [r for r in respawn
                         if "respawn_restored" in (r.get("cookie_names") or [])]
        results.append(_check(
            "S3 respawn: IDB-restored 'respawn_restored' cookie detected",
            bool(respawn_named),
            f"candidates={len(respawn)}, names="
            f"{[r.get('cookie_names') for r in respawn]}"))

        # S4: comparison covers all stores + IDB row
        expected_keys = {"indexeddb", "localStorage", "sessionStorage",
                         "cookies", "caches", "service_workers"}
        results.append(_check(
            "S4 comparison covers IDB + 5 other stores",
            expected_keys <= set(comp.keys()),
            f"keys={sorted(comp.keys())}"))
        results.append(_check(
            "S4b IDB row populated by main pass",
            comp.get("indexeddb", {}).get("identifiers", 0) >= 1,
            f"idb={comp.get('indexeddb')}"))

        # S5: sessionStorage control captured
        results.append(_check(
            "S5 sessionStorage control value captured",
            captured.get("sessionStorage", 0) >= 1,
            f"ss count={captured.get('sessionStorage')}"))

        print("\n=== Comparison table (Phase 6 axis) ===")
        for st, row in sorted(comp.items()):
            print(f"  {st:16} identifiers={row.get('identifiers', 0):<4} "
                  f"exfil={row.get('exfil_events', 0):<4} "
                  f"3p={row.get('third_party_exfils', 0)}")

        out = os.path.join(os.path.dirname(__file__), "storage_report.json")
        with open(out, "w") as f:
            json.dump({
                "engine": args.engine,
                "page": PAGE_PATH,
                "passed": all(results),
                "n_pass": sum(results),
                "n_total": len(results),
                "checks": CHECK_LOG,
                "storage_analysis": {
                    "comparison": comp,
                    "captured": captured,
                    "respawn_candidates": respawn,
                    "storage_exfil_count": len(exfils),
                },
            }, f, indent=2, default=str)
        print(f"\n  report → {out}")
        n_pass, n_total = sum(results), len(results)
        print(f"\n  RESULT: {n_pass}/{n_total} checks passed")
        return 0 if n_pass == n_total else 1
    finally:
        sink.shutdown()
        page.shutdown()


if __name__ == "__main__":
    sys.exit(main())
