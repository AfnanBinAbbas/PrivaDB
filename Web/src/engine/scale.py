"""
Scale crawling (Phase 8): parallel, resumable, retrying batch scans.

    python scale.py --sample 20 --workers 3 --engine chrome --headless
    python scale.py --list data/tranco_5000.csv --workers 4 \
                    --engine foxhound --timeout 180 --attempts 2

Design:
    - jobs + status live in a SiteStore (SQLite or JSONL fallback)
    - each site is crawled+analyzed in a SPAWNED process (isolated
      global config; raw crawl lands in the engine's crawled/ dir,
      analysis JSON in data/scale/results/<slug>.json)
    - per-site timeout kills the worker process (terminate) and the
      job goes back to pending up to --attempts times
    - --resume is implicit: completed urls are skipped
    - after the batch, generate_reports() runs ONCE in the main
      process over every analysis (no cross-worker file races)
"""
from __future__ import annotations

import argparse
import json
import multiprocessing as mp
import os
import sys
import time
from collections import deque
from typing import Optional

ENGINE_DIR = os.path.dirname(os.path.abspath(__file__))
if ENGINE_DIR not in sys.path:
    sys.path.insert(0, ENGINE_DIR)

DEFAULT_SCALE_DIR = os.path.join(ENGINE_DIR, "data", "scale")
RESULTS_DIR = os.path.join(DEFAULT_SCALE_DIR, "results")


def _slug(url: str) -> str:
    import hashlib
    safe = "".join(c if c.isalnum() else "_" for c in url)[:80]
    return f"{safe}_{hashlib.sha1(url.encode()).hexdigest()[:8]}"


def _worker(url: str, engine: str, headless: bool, iterations: int,
            consent_study: bool, conn):
    """Runs in a spawned process. Sends {"status", "summary"} on conn."""
    try:
        import asyncio
        sys.path.insert(0, ENGINE_DIR)
        import app_config as config
        from crawler import crawl_all_sites
        from detector import analyze_site

        config.set_engine(engine)
        config.HEADLESS = headless
        config.CRAWL_ITERATIONS = iterations
        os.makedirs(RESULTS_DIR, exist_ok=True)

        async def _one():
            res = await crawl_all_sites(
                custom_sites=[{"url": url, "reason": "scale batch"}],
                consent_study=consent_study)
            return res[0] if res else None

        site_data = asyncio.run(_one())
        if not site_data:
            conn.send({"status": "failed", "error": "empty crawl"})
            return
        analysis = analyze_site(site_data)

        out_path = os.path.join(RESULTS_DIR, f"{_slug(url)}.json")
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(analysis, f, indent=1, default=str)

        small = {
            "domain": analysis.get("domain"),
            "identifiers": analysis.get("identifiers_found"),
            "exfil": len(analysis.get("exfiltration_events") or []),
            "taint": len(analysis.get("taint_flows") or []),
            "idb_hook": len(analysis.get("idb_hook_flows") or []),
            "storage_exfil": len(
                (analysis.get("storage_analysis") or {}).get(
                    "storage_exfiltrations") or []),
            "result_path": out_path,
        }
        conn.send({"status": "done", "summary": small})
    except Exception as e:
        try:
            import traceback
            conn.send({"status": "failed",
                       "error": f"{e}\n{traceback.format_exc()[-500:]}"})
        except Exception:
            pass
    finally:
        try:
            conn.close()
        except Exception:
            pass


class ScaleRunner:
    def __init__(self, urls: list[str], store, workers: int = 3,
                 engine: str = "chrome", headless: bool = True,
                 iterations: int = 1, timeout: float = 180.0,
                 attempts: int = 2, consent_study: bool = False):
        self.urls = urls
        self.store = store
        self.workers = max(1, workers)
        self.engine = engine
        self.headless = headless
        self.iterations = iterations
        self.timeout = timeout
        self.attempts = max(1, attempts)
        self.consent_study = consent_study
        self.ctx = mp.get_context("spawn")

    def run(self) -> dict:
        for u in self.urls:
            self.store.ensure(u)
        queue = deque(self.store.pending())
        done_before = len(self.store.completed())
        print(f"  queue={len(queue)} (resume skipped {done_before} done)")

        running: dict[mp.process.BaseProcess, dict] = {}
        results_log: list[dict] = []
        t0 = time.time()

        def launch(url: str):
            parent_conn, child_conn = self.ctx.Pipe(duplex=False)
            p = self.ctx.Process(
                target=_worker,
                args=(url, self.engine, self.headless, self.iterations,
                      self.consent_study, child_conn),
                daemon=True)
            p.start()
            child_conn.close()
            self.store.mark(url, "running", bump_attempt=True)
            running[p] = {"url": url, "conn": parent_conn,
                          "start": time.time(), "attempts": int(
                              (self.store.summary(url) or {}).get(
                                  "attempts", 0))}

        while queue or running:
            while queue and len(running) < self.workers:
                launch(queue.popleft())

            # harvest
            for p in list(running):
                meta = running[p]
                expired = time.time() - meta["start"] > self.timeout
                got = None
                if meta["conn"].poll(0.2):
                    try:
                        got = meta["conn"].recv()
                    except Exception:
                        got = None
                if got:
                    p.join(timeout=5)
                    if p.is_alive():
                        p.terminate()
                    url = meta["url"]
                    if got.get("status") == "done":
                        self.store.mark(url, "done",
                                        summary=got.get("summary"))
                        results_log.append({"url": url, **got["summary"]})
                        print(f"  ✓ {url}  {got['summary']}")
                    else:
                        self._fail(url, got.get("error", "worker error"),
                                   queue)
                    del running[p]
                elif expired:
                    url = meta["url"]
                    p.terminate()
                    p.join(timeout=5)
                    self._fail(url, f"timeout >{self.timeout}s", queue)
                    print(f"  ⏱ {url} timed out")
                    del running[p]
                elif not p.is_alive():
                    # died without sending (hard crash)
                    url = meta["url"]
                    self._fail(url, "worker exited without result", queue)
                    del running[p]

        stats = self.store.counts()
        print(f"  batch finished in {time.time() - t0:.0f}s → {stats}")
        return {"stats": stats, "results": results_log}

    def _fail(self, url: str, error: str, queue: deque):
        rows_attempts = self._attempts_for(url)
        if rows_attempts < self.attempts:
            self.store.mark(url, "pending", error=error,
                            bump_attempt=False)
            queue.append(url)
        else:
            self.store.mark(url, "permanent_failed", error=error,
                            bump_attempt=True)

    def _attempts_for(self, url: str) -> int:
        # attempts were bumped at launch; read store row
        for r in self.store._rows():
            if r["url"] == url:
                return int(r.get("attempts", 0))
        return 0


def _generate_reports(results_dir: str, engine: str) -> Optional[str]:
    """Single-threaded report generation over every scale analysis."""
    try:
        import app_config as config
        from reporter import generate_reports
        import json as _json

        config.set_engine(engine)
        analyses = []
        for fname in sorted(os.listdir(results_dir)):
            if not fname.endswith(".json"):
                continue
            with open(os.path.join(results_dir, fname)) as f:
                analyses.append(_json.load(f))
        if not analyses:
            return None
        generate_reports(analyses)
        return os.path.join(config.ANALYSIS_DIR, "summary.json")
    except Exception as e:
        print(f"  report generation failed: {e}")
        return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--list", default=None,
                    help="ranked list file; default = vendored tranco-1000")
    ap.add_argument("--sample", type=int, default=10,
                    help="how many domains from the head of the list")
    ap.add_argument("--urls", nargs="*", default=None,
                    help="explicit urls (overrides --list/--sample)")
    ap.add_argument("--workers", type=int, default=3)
    ap.add_argument("--engine", default="chrome",
                    choices=["chrome", "foxhound"])
    ap.add_argument("--headed", action="store_true")
    ap.add_argument("--iterations", type=int, default=1)
    ap.add_argument("--timeout", type=float, default=180.0)
    ap.add_argument("--attempts", type=int, default=2)
    ap.add_argument("--consent-study", action="store_true")
    ap.add_argument("--db", default=os.path.join(DEFAULT_SCALE_DIR,
                                                  "scale.sqlite"))
    ap.add_argument("--no-reports", action="store_true")
    args = ap.parse_args()

    if args.urls:
        urls = [u if u.startswith("http") else f"https://{u}"
                for u in args.urls]
    else:
        import tranco
        rows = tranco.load_list(args.list, sample=args.sample)
        urls = [f"https://{d}" for _r, d in rows]

    from store import SiteStore
    store = SiteStore(args.db)
    print(f"  store: {args.db} ({store.mode})")

    runner = ScaleRunner(
        urls, store, workers=args.workers, engine=args.engine,
        headless=not args.headed, iterations=args.iterations,
        timeout=args.timeout, attempts=args.attempts,
        consent_study=args.consent_study)
    outcome = runner.run()

    if not args.no_reports:
        path = _generate_reports(RESULTS_DIR, args.engine)
        if path:
            print(f"  combined report → {path}")

    print(f"  final store state: {store.counts()}")
    return 0 if store.counts().get("failed", 0) == 0 else 1


if __name__ == "__main__":
    mp.freeze_support()
    sys.exit(main())
