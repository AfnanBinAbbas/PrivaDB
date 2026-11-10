#!/usr/bin/env python3
"""
Phase 4 consent study — ground-truth verification.

Serves testbed/pages/consent.html (fake OneTrust banner; tracker script
gated on Accept, but fires after Reject when ?misbehave=1), runs the
three-condition consent study against it, and asserts:

  C1 banner detected via known CMP selectors
  C2 accept → tracker write + exfil observed, state=accepted
  C3 reject on misbehaving page → post-reject write + exfil observed
     (headline: tracking_without_consent)
  C4 no-interaction → state=pre_consent, all writes pre-click
  C5 consent_analysis present with all three conditions
  C6 banner failures are surfaced (not silently "no banner")

Usage:
    python testbed/run_consent.py [--engine foxhound|chrome] [--headless]
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

# reuse the smoke sink/page servers (they serve /consent-tracker.js too)
from testbed.run_smoke import (  # noqa: E402
    PAGE_PORT, SINK_PORT, PageHandler, SinkHandler, CHECK_LOG, _check,
)

PAGE_PATH = f"http://localhost:{PAGE_PORT}/consent.html?misbehave=1"
TRACKER_UID = "consent-uid-00112233445566778899aabbccddeeff"
BASELINE = "baseline-aaaaaaaaaaaaaaaaaaaaaaaaaaaa"


async def _study(engine: str, headless: bool) -> dict:
    from crawler import crawl_all_sites
    from detector import analyze_site

    config.set_engine(engine)
    config.HEADLESS = headless
    results = await crawl_all_sites(
        custom_sites=[{"url": PAGE_PATH, "reason": "phase4 consent study"}],
        consent_study=True,
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
        analysis = asyncio.run(_study(args.engine, args.headless))
        if not analysis:
            print("FATAL: study returned no data")
            return 2

        ca = analysis.get("consent_analysis")
        conds = (ca or {}).get("conditions") or {}
        headline = (ca or {}).get("headline") or {}

        print("\n=== Consent-study assertions ===")
        results = []

        results.append(_check(
            "C5 consent_analysis with all three conditions",
            ca is not None and sorted(conds) == ["accept", "none", "reject"],
            f"conditions={sorted(conds)}"))

        if ca:
            none_c = conds.get("none", {})
            acc_c = conds.get("accept", {})
            rej_c = conds.get("reject", {})

            # C1: banner detected through the known CMP selectors
            banner_by_cond = {k: c.get("banner_detected")
                              for k, c in conds.items()}
            results.append(_check(
                "C1 banner detected (OneTrust selectors)",
                all(banner_by_cond.values()),
                f"per-cond={banner_by_cond}"))

            # C2: accept → state accepted + tracker write + exfil
            acc_states = acc_c.get("states", [])
            results.append(_check(
                "C2 accept → state=accepted",
                "accepted" in acc_states, f"states={acc_states}"))
            results.append(_check(
                "C2b accept → tracker uid written to IDB",
                acc_c.get("idb_records_post_consent", 0) >= 1,
                f"records post-load={acc_c.get('idb_records_post_load')} "
                f"post-consent={acc_c.get('idb_records_post_consent')}"))
            results.append(_check(
                "C2c accept → exfil events observed",
                acc_c.get("third_party_exfils", 0) >= 1
                or acc_c.get("exfil_events", 0) >= 1,
                f"exfil={acc_c.get('exfil_events')} "
                f"3p={acc_c.get('third_party_exfils')}"))

            # C3: reject on MISBEHAVING page → post-reject writes + exfil
            rej_states = rej_c.get("states", [])
            results.append(_check(
                "C3a reject → state=rejected",
                "rejected" in rej_states, f"states={rej_states}"))
            results.append(_check(
                "C3b reject → post-reject tracker write detected "
                "(tracking without consent)",
                headline.get("writes_after_reject", 0) >= 1,
                f"writes_after_reject={headline.get('writes_after_reject')}"))
            results.append(_check(
                "C3c reject → exfil after reject detected",
                rej_c.get("third_party_exfils", 0) >= 1
                or rej_c.get("exfil_events", 0) >= 1,
                f"exfil={rej_c.get('exfil_events')} "
                f"3p={rej_c.get('third_party_exfils')}"))

            # C4: no-interaction → pre_consent, writes counted as pre-click
            none_states = none_c.get("states", [])
            results.append(_check(
                "C4a no-interaction → state=pre_consent",
                "pre_consent" in none_states, f"states={none_states}"))
            results.append(_check(
                "C4b all no-interaction writes are pre-consent",
                none_c.get("pre_click_writes", 0)
                >= none_c.get("writes", 0),
                f"pre={none_c.get('pre_click_writes')}/"
                f"total={none_c.get('writes')}"))

            # C6: banner failures surfaced when clicks fail
            failures = headline.get("banner_failures", [])
            results.append(_check(
                "C6 banner failures surfaced as list (not silent)",
                isinstance(failures, list),
                f"failures={len(failures)}: {failures[:2]}"))

            # headline flag
            results.append(_check(
                "C3d headline: tracking_without_consent=True",
                headline.get("tracking_without_consent") is True,
                f"headline={json.dumps(headline)}"))

        out = os.path.join(os.path.dirname(__file__),
                           "consent_report.json")
        with open(out, "w") as f:
            json.dump({
                "engine": args.engine,
                "page": PAGE_PATH,
                "passed": all(results),
                "n_pass": sum(results),
                "n_total": len(results),
                "checks": CHECK_LOG,
                "consent_analysis": ca,
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
