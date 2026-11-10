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
            consent_study: bool, prune_raw: bool, conn):
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
        # provenance rides with the analysis so raw crawls can be pruned
        # without losing run_meta (browser/foxhound build versions)
        if not analysis.get("run_meta"):
            analysis["run_meta"] = site_data.get("run_meta") or {}

        out_path = os.path.join(RESULTS_DIR, f"{_slug(url)}.json")
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(analysis, f, indent=1, default=str)

        if prune_raw:
            try:
                dom = str(site_data.get("domain", "")).replace(
                    ".", "_").replace("/", "_")
                rawp = os.path.join(config.RAW_DATA_DIR, f"{dom}.json")
                if os.path.exists(rawp):
                    os.remove(rawp)
            except Exception:
                pass

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
            # IDB fields for campaign results sync (results_sync)
            "idb_dbs": (analysis.get("indexeddb_summary") or {}).get(
                "database_count", 0),
            "idb_records": (analysis.get("indexeddb_summary") or {}).get(
                "total_records", 0),
            "client_ids": analysis.get("client_identifiers_found", 0),
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
                 attempts: int = 2, consent_study: bool = False,
                 max_cpu: Optional[float] = None,
                 prune_raw: bool = False):
        self.urls = urls
        self.store = store
        self.workers = max(1, workers)
        self.engine = engine
        self.headless = headless
        self.iterations = iterations
        self.timeout = timeout
        self.attempts = max(1, attempts)
        self.consent_study = consent_study
        # CPU governor: when system CPU exceeds max_cpu (%), no NEW
        # simultaneous scan is started — in-flight scans drain first
        # (floor of 1 keeps progress when the host baseline is already
        # above the cap from other apps).
        self.max_cpu = max_cpu
        self.prune_raw = prune_raw
        self.throttle_events = 0
        self._last_cpu_log = 0.0
        if max_cpu is not None:
            try:
                import psutil
                psutil.cpu_percent(interval=None)   # prime the counter
            except Exception:
                pass
        self.ctx = mp.get_context("spawn")

    def _cpu_pct(self, sample: float = 0.5) -> Optional[float]:
        """Current aggregate CPU % (0-100 across all cores); loadavg
        approximation when psutil is unavailable."""
        if self.max_cpu is None:
            return None
        try:
            import psutil
            return float(psutil.cpu_percent(interval=sample))
        except Exception:
            try:
                return min(100.0, os.getloadavg()[0]
                           / (os.cpu_count() or 1) * 100)
            except Exception:
                return None

    def run(self) -> dict:
        if hasattr(self.store, "ensure_many"):
            self.store.ensure_many(self.urls)
        else:
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
                      self.consent_study, self.prune_raw, child_conn),
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
                # CPU governor (user cap): above max_cpu → hold new
                # launches while ≥1 scan is already in flight; floor of
                # 1 guarantees progress even if the host baseline sits
                # above the cap because of other apps.
                cpu = self._cpu_pct()
                if (cpu is not None and cpu > (self.max_cpu or 0)
                        and len(running) >= 1):
                    self.throttle_events += 1
                    now = time.time()
                    if now - self._last_cpu_log > 60:
                        print(f"  ⏳ CPU {cpu:.0f}% > cap "
                              f"{self.max_cpu:.0f}% — throttled: "
                              f"{len(running)} in flight, "
                              f"{len(queue)} queued (waiting for drain)")
                        self._last_cpu_log = now
                    break
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
        if self.max_cpu is not None:
            print(f"  CPU governor: cap {self.max_cpu:.0f}% — "
                  f"throttled launch waves: {self.throttle_events}")
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
    """Single-threaded report generation over every scale analysis —
    detector reports (CSV/JSON/charts) + Phase 12 HTML: one standalone
    report per site plus a bulk executive report."""
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
        summary_path = os.path.join(config.ANALYSIS_DIR, "summary.json")

        # Phase 12: HTML reports for the batch
        try:
            html_paths = _html_reports(analyses, engine)
            print(f"  HTML reports: {len(html_paths)} per-site + bulk")
        except Exception as e:
            print(f"  HTML report generation skipped: {e}")
        return summary_path
    except Exception as e:
        print(f"  report generation failed: {e}")
        return None


def _html_reports(analyses: list[dict], engine: str) -> list[str]:
    """Render Phase-12 HTML (per-site + bulk) for scale results.
    GRC uses analysis evidence only (headers/policy stay off so batch
    runs remain offline-friendly); evidence_inputs record that."""
    import grc as grc_mod
    import report_html
    import re as _re

    out_dir = os.path.join(ENGINE_DIR, "results",
                           "Chrome" if engine.lower() == "chrome"
                           else "Foxhound", "reports")
    os.makedirs(out_dir, exist_ok=True)
    paths = []
    sites = []
    for a in analyses:
        domain = a.get("domain") or a.get("url") or "unknown"
        url = a.get("url") or f"https://{domain}"
        grc_report = grc_mod.run_grc_checks(
            a, url, policy_info=None, header_info=None)
        sites.append({"domain": domain, "url": url, "engine": engine,
                      "analysis": a, "grc": grc_report})
        # provenance: run_meta lives on the raw crawl, not the analysis
        run_meta = a.get("run_meta") or {}
        if not run_meta:
            try:
                import app_config as _cfg
                _cfg.set_engine(engine)
                raw = os.path.join(
                    _cfg.RAW_DATA_DIR,
                    f"{str(domain).replace('.', '_')}.json")
                with open(raw, encoding="utf-8") as f:
                    run_meta = (json.load(f).get("run_meta") or {})
            except Exception:
                run_meta = {}
        html_doc = report_html.render_scan_report(
            a, url, grc_report,
            run_meta=run_meta,
            scan_meta={"started_at": a.get("timestamp", ""),
                       "status": "completed"},
            sources=[f"data/scale/results/{_slug(url)}.json"])
        safe = _re.sub(r"[^A-Za-z0-9._-]", "_", str(domain))[:60]
        path = os.path.join(out_dir, f"scale_{safe}.html")
        with open(path, "w", encoding="utf-8") as f:
            f.write(html_doc)
        paths.append(path)

    if sites:
        bulk = report_html.render_bulk_report(sites)
        bpath = os.path.join(out_dir, "bulk_latest.html")
        with open(bpath, "w", encoding="utf-8") as f:
            f.write(bulk)
        paths.append(bpath)
    return paths


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
    ap.add_argument("--max-cpu", type=float, default=None, metavar="PCT",
                    help="CPU cap in %% (0-100): above it no NEW "
                         "simultaneous scan starts (in-flight drains; "
                         "floor of 1 always allowed). e.g. 50")
    ap.add_argument("--prune-raw", action="store_true",
                    help="delete each site's raw crawl JSON after its "
                         "analysis is written (run_meta is embedded in "
                         "the analysis first) — required for 10k-scale "
                         "disk budgets")
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
        consent_study=args.consent_study,
        max_cpu=args.max_cpu, prune_raw=args.prune_raw)
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
