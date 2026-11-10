#!/usr/bin/env python3
"""
Phase 8 scale study — verification of the parallel/resumable crawler.

    T1 batch: 4 testbed pages, 2 workers → all jobs done
    T2 results: one analysis JSON per site in data/scale/results/
    T3 resume: second run skips everything (queue drained, no re-crawl)
    T4 retry logic: _fail requeues below --attempts, permanent after
    T5 store backend: reports sqlite-vs-jsonl for this interpreter

Usage:
    python testbed/run_scale.py [--engine chrome|foxhound]
"""
import argparse
import json
import os
import shutil
import sys
import threading
from collections import deque
from http.server import ThreadingHTTPServer

ENGINE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ENGINE_DIR)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import app_config as config  # noqa: E402

from testbed.run_smoke import (  # noqa: E402
    PAGE_PORT, SINK_PORT, PageHandler, SinkHandler, CHECK_LOG, _check,
)

SCALE_DIR = os.path.join(ENGINE_DIR, "data", "scale")
RESULTS = os.path.join(SCALE_DIR, "results")
DB = os.path.join(SCALE_DIR, "scale_test.sqlite")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--engine", default="chrome",
                    choices=["chrome", "foxhound"])
    ap.add_argument("--headed", action="store_true")
    args = ap.parse_args()

    # clean slate
    shutil.rmtree(SCALE_DIR, ignore_errors=True)
    os.makedirs(RESULTS, exist_ok=True)

    sink = ThreadingHTTPServer(("127.0.0.1", SINK_PORT), SinkHandler)
    page = ThreadingHTTPServer(("127.0.0.1", PAGE_PORT), PageHandler)
    for srv in (sink, page):
        threading.Thread(target=srv.serve_forever, daemon=True).start()

    urls = [f"http://localhost:{PAGE_PORT}/{p}"
            for p in ("transforms.html", "smoke.html", "storage.html",
                      "consent.html")]
    print("  pages:", *[u.rsplit('/', 1)[-1] for u in urls])

    try:
        from scale import ScaleRunner, RESULTS_DIR
        from store import SiteStore

        results = []
        store = SiteStore(DB)
        print(f"  store mode: {store.mode}")

        # ── T1: batch run ──
        runner = ScaleRunner(urls, store, workers=2, engine=args.engine,
                             headless=not args.headed, iterations=1,
                             timeout=240.0, attempts=2)
        outcome = runner.run()
        counts = store.counts()
        results.append(_check(
            "T1 batch completes with all sites done",
            counts.get("done", 0) == len(urls),
            f"counts={counts}"))

        # ── T2: one analysis per site ──
        files = [f for f in os.listdir(RESULTS_DIR)
                 if f.endswith(".json")]
        results.append(_check(
            "T2 analysis JSON per site in data/scale/results",
            len(files) == len(urls), f"files={len(files)}"))

        # spot-check one analysis is real
        ok_shape = False
        if files:
            with open(os.path.join(RESULTS_DIR, files[0])) as f:
                a = json.load(f)
            ok_shape = "identifiers_found" in a and "exfiltration_events" in a
        results.append(_check("T2b analyses carry detector schema",
                              ok_shape))

        # ── T3: resume skips everything ──
        done_before = len(store.completed())
        runner2 = ScaleRunner(urls, store, workers=2, engine=args.engine,
                              headless=not args.headed, iterations=1,
                              timeout=240.0, attempts=2)
        pending_before = list(store.pending())
        runner2.run()
        results.append(_check(
            "T3 resume: pending queue empty, completed preserved",
            pending_before == [] and len(store.completed()) == done_before,
            f"pending={len(pending_before)} done={len(store.completed())}"))

        # ── T4: retry logic (no processes — direct state machine) ──
        from store import SiteStore as SS
        t4_path = os.path.join(SCALE_DIR, "t4.sqlite")
        s4 = SS(t4_path)
        u = "https://t4.example"
        s4.ensure(u)

        class _R(ScaleRunner):
            def __init__(self, st):
                # bypass heavy init
                self.store = st
                self.attempts = 2
        r4 = _R(s4)
        q = deque()
        s4.mark(u, "running", bump_attempt=True)      # attempt 1
        r4._fail(u, "boom", q)
        retry_ok = u in q and s4.pending() == [u]
        s4.mark(u, "running", bump_attempt=True)      # attempt 2
        r4._fail(u, "boom2", q)
        perm = s4.pending() == [] and "permanent_failed" in s4.counts()
        results.append(_check(
            "T4 retry requeues below attempts, permanent-fails after",
            retry_ok and perm,
            f"retry_ok={retry_ok} permanent={perm} counts={s4.counts()}"))

        # ── T5: backend recorded ──
        results.append(_check(
            "T5 store backend identified (sqlite or jsonl fallback)",
            store.mode in ("sqlite", "jsonl"), f"mode={store.mode}"))

        # ── T6: batch report generation glue ──
        from scale import _generate_reports
        config.set_engine(args.engine)
        summary_path = _generate_reports(RESULTS, args.engine)
        results.append(_check(
            "T6 combined report generated from batch analyses",
            bool(summary_path) and os.path.exists(summary_path),
            f"path={summary_path}"))

        out = os.path.join(os.path.dirname(__file__), "scale_report.json")
        with open(out, "w") as f:
            json.dump({"engine": args.engine, "passed": all(results),
                       "n_pass": sum(results), "n_total": len(results),
                       "store_mode": store.mode, "counts": counts,
                       "checks": CHECK_LOG,
                       "batch": outcome}, f, indent=2, default=str)
        print(f"\n  report → {out}")
        n_pass, n_total = sum(results), len(results)
        print(f"  RESULT: {n_pass}/{n_total} checks passed")
        return 0 if n_pass == n_total else 1
    finally:
        sink.shutdown()
        page.shutdown()


if __name__ == "__main__":
    sys.exit(main())
