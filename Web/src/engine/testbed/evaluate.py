#!/usr/bin/env python3
"""
Phase 7 evaluation — precision/recall of the three matching methods
against declarative ground truth, plus ablations and run-to-run noise.

Methods scored on the SAME crawl of testbed/pages/transforms.html:
    substring   — raw-only needle matching (the pre-Phase-3 baseline;
                  isolated: same dedup, no transforms, no storage pools)
    transforms  — full detector: variant expansion + all stores
                  (exfiltration_events + storage_exfiltrations)
    dynamic     — Foxhound taint flows + idb_hook flows (provenance
                  methods; taint only covers non-IDB sources by design)

Ablations (re-analyze the saved crawl under config variants):
    ID_SCORE_THRESHOLD  0 / 0.5 / 0.7
    MIN_ID_LENGTH       4 / 8 / 12
    iteration diff      off (1 iteration) / on (2 iterations, legacy
                        changed-records filter)

Noise: two extra independent crawls → event-count variance.

Usage:
    python testbed/evaluate.py [--engine foxhound|chrome] [--headless]
                               [--skip-crawl]   # reuse saved crawl
"""
import argparse
import asyncio
import copy
import json
import os
import sys
import threading
import time
from http.server import ThreadingHTTPServer

ENGINE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ENGINE_DIR)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import app_config as config  # noqa: E402
import ground_truth as gt  # noqa: E402

from testbed.run_smoke import (  # noqa: E402
    PAGE_PORT, SINK_PORT, PageHandler, SinkHandler,
)

PAGE_PATH = f"http://localhost:{PAGE_PORT}/transforms.html"
REPORT = os.path.join(os.path.dirname(__file__), "evaluate_report.json")


# ─── Crawl helpers ──────────────────────────────────────────────────

async def _crawl(iterations: int) -> dict:
    from crawler import crawl_all_sites
    config.CRAWL_ITERATIONS = iterations
    results = await crawl_all_sites(
        custom_sites=[{"url": PAGE_PATH, "reason": "phase7 evaluation"}],
    )
    return results[0] if results else {}


# ─── Method extractors ──────────────────────────────────────────────

def _idb_idents(site_data: dict) -> list[dict]:
    from detector import extract_potential_ids
    out = []
    for db in (site_data.get("indexeddb") or {}).get("databases") or []:
        for store in db.get("stores") or []:
            for record in store.get("records") or []:
                for ident in extract_potential_ids(
                        record.get("value"),
                        f"{db.get('name','')}/{store.get('name','')}/"
                        f"{record.get('key','')}"):
                    ident["database"] = db.get("name", "")
                    ident["store"] = store.get("name", "")
                    ident["record_key"] = str(record.get("key", ""))
                    out.append(ident)
    return out


def baseline_events(site_data: dict, domain: str) -> list[dict]:
    """Pre-Phase-3 behavior: raw substring over IDB identifiers only
    (transforms + truncated prefixes disabled; new dedup kept, so the
    measured delta is the transform capability, not the dedup fix)."""
    import detector
    import transforms
    orig_gen = transforms.generate_variants
    orig_tr = transforms.truncated_prefixes
    transforms.generate_variants = lambda v: {v: ["raw"]} if v else {}
    transforms.truncated_prefixes = lambda v: {}
    try:
        return detector.find_exfiltrations(
            _idb_idents(site_data), site_data.get("network_requests") or [],
            domain)
    finally:
        transforms.generate_variants = orig_gen
        transforms.truncated_prefixes = orig_tr


def dynamic_events(analysis: dict) -> list[dict]:
    """Taint + idb-hook flows as (value, url) pairs."""
    out = []
    for tf in analysis.get("taint_flows") or []:
        out.append({"identifier_value": str(tf.get("tainted_value", "")),
                    "request_url": str(tf.get("target", "")),
                    "method": "taint"})
    for hf in analysis.get("idb_hook_flows") or []:
        out.append({"identifier_value": str(hf.get("idb_value", "")),
                    "request_url": str(hf.get("target", "")),
                    "method": "idb_hook"})
    return out


def full_events(analysis: dict) -> list[dict]:
    sa = analysis.get("storage_analysis") or {}
    return (list(analysis.get("exfiltration_events") or [])
            + list(sa.get("storage_exfiltrations") or []))


# ─── Scoring ────────────────────────────────────────────────────────

def _event_matches_flow(ev: dict, flow: tuple) -> bool:
    gv, sub, _chain = flow
    val = str(ev.get("identifier_value", ""))
    url = str(ev.get("request_url", ""))
    if val != gv:
        # dynamic flows carry JSON-blob idb values — substring fallback
        if gv not in val:
            return False
    return sub in url


def score(events: list[dict], flows: list[tuple],
          non_ids: list[str]) -> dict:
    tp_ev, fp_ev = [], []
    for ev in events:
        if any(_event_matches_flow(ev, f) for f in flows):
            tp_ev.append(ev)
        else:
            fp_ev.append(ev)   # includes events on NON_IDENTIFIERS
    fn_flows = [f for f in flows
                if not any(_event_matches_flow(ev, f) for ev in events)]
    # NON_IDENTIFIERS detection rate (are benign controls flagged at all?)
    flagged_benign = sorted({
        str(ev.get("identifier_value", "")) for ev in events
        if str(ev.get("identifier_value", "")) in non_ids})
    precision = (len(tp_ev) / len(events)) if events else None
    recall = (len(flows) - len(fn_flows)) / len(flows) if flows else None
    return {
        "predicted": len(events),
        "tp": len(tp_ev), "fp": len(fp_ev), "fn": len(fn_flows),
        "precision": round(precision, 4) if precision is not None else None,
        "recall": round(recall, 4) if recall is not None else None,
        "fn_flow_substrings": [f[1][:60] for f in fn_flows],
        "flagged_benign_controls": flagged_benign,
    }


# ─── Ablations ──────────────────────────────────────────────────────

def run_analysis(site_data: dict) -> dict:
    from detector import analyze_site
    return analyze_site(site_data)


def ablations(site_data: dict) -> dict:
    out = {}
    one_view = dict(site_data)
    one_view["iterations"] = (site_data.get("iterations") or [])[:1]

    def evaluate_current(label: str, data: dict):
        analysis = run_analysis(data)
        evs = full_events(analysis)
        out[label] = score(evs, gt.FLOWS, gt.NON_IDENTIFIERS)

    # score-gate ablation (diff neutral)
    orig_score = config.ID_SCORE_THRESHOLD
    for thr in (0.0, 0.5, 0.7):
        config.ID_SCORE_THRESHOLD = thr
        evaluate_current(f"ID_SCORE_THRESHOLD={thr}", one_view)
    config.ID_SCORE_THRESHOLD = orig_score

    # length-gate ablation (diff neutral)
    orig_len = config.MIN_ID_LENGTH
    for ln in (4, 8, 12):
        config.MIN_ID_LENGTH = ln
        evaluate_current(f"MIN_ID_LENGTH={ln}", one_view)
    config.MIN_ID_LENGTH = orig_len

    # iteration-diff ablation: the legacy changed-records filter only
    # activates when a record changed between visits (the transforms page
    # writes a volatile record for exactly this test).
    evaluate_current("diff=off(1it)", one_view)
    evaluate_current("diff=fixed(2it)", site_data)
    orig_legacy = getattr(config, "LEGACY_DIFF_FILTER", False)
    config.LEGACY_DIFF_FILTER = True
    evaluate_current("diff=legacy(2it)", site_data)
    config.LEGACY_DIFF_FILTER = orig_legacy
    return out


# ─── Main ───────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--engine", default="foxhound",
                        choices=["foxhound", "chrome"])
    parser.add_argument("--headless", action="store_true")
    parser.add_argument("--skip-crawl", action="store_true",
                        help="reuse testbed/evaluate_crawl.json")
    args = parser.parse_args()

    # GT self-check
    vecs = gt.verify_js_md5_vectors()
    assert all(vecs.values()), f"ground-truth md5 vectors drifted: {vecs}"
    print(f"  ground-truth vectors OK: {vecs}")

    sink = ThreadingHTTPServer(("127.0.0.1", SINK_PORT), SinkHandler)
    page = ThreadingHTTPServer(("127.0.0.1", PAGE_PORT), PageHandler)
    for srv in (sink, page):
        threading.Thread(target=srv.serve_forever, daemon=True).start()

    crawl_path = os.path.join(os.path.dirname(__file__),
                              "evaluate_crawl.json")
    try:
        config.set_engine(args.engine)
        config.HEADLESS = args.headless
        orig_score = config.ID_SCORE_THRESHOLD
        orig_len = config.MIN_ID_LENGTH
        config.ID_SCORE_THRESHOLD = 0.0
        config.MIN_ID_LENGTH = 8

        if args.skip_crawl and os.path.exists(crawl_path):
            with open(crawl_path) as f:
                site_data = json.load(f)
            print(f"  reusing crawl: {crawl_path}")
        else:
            print(f"  crawling {PAGE_PATH} (2 iterations) …")
            site_data = asyncio.run(_crawl(2))
            if not site_data:
                print("FATAL: crawl empty")
                return 2
            with open(crawl_path, "w") as f:
                json.dump(site_data, f, default=str)
            print(f"  crawl saved → {crawl_path}")

        domain = site_data.get("domain", "")

        # Method comparison runs on a DIFF-NEUTRAL view (1 iteration) so
        # the legacy changed-records filter doesn't confound substring vs
        # transforms vs dynamic — that filter is measured separately as
        # its own ablation below.
        one_view = dict(site_data)
        one_view["iterations"] = (site_data.get("iterations") or [])[:1]
        analysis = run_analysis(one_view)

        # ── methods (identical data for all three) ──
        base_ev = baseline_events(one_view, domain)
        full_ev = full_events(analysis)
        dyn_ev = dynamic_events(analysis)

        methods = {
            "substring (baseline)": score(base_ev, gt.FLOWS,
                                          gt.NON_IDENTIFIERS),
            "transforms (full)": score(full_ev, gt.FLOWS,
                                       gt.NON_IDENTIFIERS),
            "dynamic (taint+hooks)": score(dyn_ev, gt.FLOWS,
                                           gt.NON_IDENTIFIERS),
        }

        print("\n=== Method comparison (ground truth: "
              f"{len(gt.FLOWS)} flows, {len(gt.NON_IDENTIFIERS)} benign) ===")
        print(f"  {'method':26} {'pred':>5} {'TP':>4} {'FP':>4} {'FN':>4} "
              f"{'prec':>7} {'recall':>7}")
        for name, s in methods.items():
            prec = f"{s['precision']:.3f}" if s["precision"] is not None else "  n/a"
            rec = f"{s['recall']:.3f}" if s["recall"] is not None else "  n/a"
            print(f"  {name:26} {s['predicted']:>5} {s['tp']:>4} "
                  f"{s['fp']:>4} {s['fn']:>4} {prec:>7} {rec:>7}")

        # ── ablations ──
        abl = ablations(site_data)
        print("\n=== Ablations (full method) ===")
        print(f"  {'variant':24} {'pred':>5} {'FP':>4} {'FN':>4} "
              f"{'prec':>7} {'recall':>7}")
        for label, s in abl.items():
            prec = f"{s['precision']:.3f}" if s["precision"] is not None else "  n/a"
            print(f"  {label:24} {s['predicted']:>5} {s['fp']:>4} "
                  f"{s['fn']:>4} {prec:>7} {s['recall']:.3f}")

        # ── Paper §4.1 client-identifier classification (IDB only) ──
        # Classify from the FULL 2-iteration crawl — the methods table
        # above deliberately uses the diff-neutral 1-iteration view,
        # which can never satisfy paper conditions C4/C5.
        import uid as paper_uid
        uid_report_full = paper_uid.classify_site(
            site_data.get("iterations") or [])
        uid_sum = uid_report_full
        uid_confirmed = [i for i in uid_report_full.get("identifiers", [])
                         if i.get("confirmed")]
        uid_checks = []
        def _uid(name, ok, detail=""):
            uid_checks.append({"name": name, "passed": bool(ok),
                               "detail": detail})
            print(f"  [{'PASS' if ok else 'FAIL'}] UID: {name}"
                  + (f" — {detail}" if detail else ""))
        _uid("§4.1 evaluated (≥2 fresh iterations)",
             uid_sum.get("evaluated") is True,
             f"reason={uid_sum.get('reason', 'ok')}")
        conf_keys = [i.get("key", "") for i in uid_confirmed]
        _uid("instance-unique UID confirmed (C4/C5 + reload)",
             any(k.endswith("/instance_uid") for k in conf_keys),
             f"confirmed keys={conf_keys}")
        tid_key = [i.get("key", "") for i in (uid_sum.get("identifiers") or [])
                   if i.get("key", "").endswith("/tid")]
        tid_ok = (not tid_key) or all(
            not i.get("confirmed")
            for i in (uid_sum.get("identifiers") or [])
            if i.get("key", "").endswith("/tid"))
        _uid("static value NOT misclassified as UID",
             tid_ok, f"tid keys={tid_key}")
        print(f"  paper scope: {uid_sum.get('scope')} · "
              f"{uid_sum.get('paper')}")

        # ── noise: two extra independent crawls ──
        counts = [len(full_ev)]
        for run_idx in (2, 3):
            try:
                extra = asyncio.run(_crawl(1))
                if extra:
                    a = run_analysis(extra)
                    counts.append(len(full_events(a)))
            except Exception as e:
                print(f"  variance crawl {run_idx} failed: {e}")
        mean = sum(counts) / len(counts)
        var = sum((c - mean) ** 2 for c in counts) / len(counts)
        noise = {"counts": counts, "mean": round(mean, 2),
                 "stdev": round(var ** 0.5, 2)}
        print(f"\n=== Run-to-run variance (event counts) ===  "
              f"{counts} → mean={mean:.1f} stdev={var**0.5:.2f}")

        # restore config
        config.ID_SCORE_THRESHOLD = orig_score
        config.MIN_ID_LENGTH = orig_len

        report = {
            "engine": args.engine,
            "page": PAGE_PATH,
            "ground_truth": {
                "flows": len(gt.FLOWS),
                "non_identifiers": len(gt.NON_IDENTIFIERS),
                "md5_vectors_ok": vecs,
            },
            "methods": methods,
            "ablations": abl,
            "paper_uid": {
                "summary": {k: uid_sum.get(k) for k in (
                    "evaluated", "confirmed_count", "candidate_count",
                    "reload_checked", "scope", "paper", "reason")},
                "confirmed_keys": conf_keys,
                "checks": uid_checks,
            },
            "noise": noise,
            "flow_coverage": {
                "transforms_fn": methods["transforms (full)"][
                    "fn_flow_substrings"],
                "baseline_fn": methods["substring (baseline)"][
                    "fn_flow_substrings"],
            },
        }
        with open(REPORT, "w") as f:
            json.dump(report, f, indent=2, default=str)
        uid_ok = all(c["passed"] for c in uid_checks)
        print(f"\n  UID checks: {sum(c['passed'] for c in uid_checks)}"
              f"/{len(uid_checks)}")
        print(f"  report → {REPORT}")
        return 0 if uid_ok else 1
    finally:
        sink.shutdown()
        page.shutdown()


if __name__ == "__main__":
    sys.exit(main())
