#!/usr/bin/env python3
"""
Phase 7 + worker-context evaluation — precision/recall of the three
matching methods against declarative ground truth, plus ablations,
run-to-run noise, per-mechanism attribution and worker-hook coverage.

Pages crawled (each with 2 fresh-profile iterations):
    transforms.html  — classic 12-flow ground truth (window context)
    idb_workers.html — IDB→network from window / dedicated worker /
                       shared worker (16 scored flows) + service-worker
                       flows proven browser-side via the sink only
                       (environment-dark on Playwright+Firefox:
                       probe1 Q2 / probe3 Q17 — see ground_truth.py)

Methods scored on the SAME union of both crawls:
    substring   — raw-only needle matching over captured network only
                  (the pre-Phase-3 baseline; no hooks, no synthesis)
    transforms  — full detector: variant expansion + all stores +
                  hook-synthesized network (worker-class sends)
    dynamic     — Foxhound taint flows + idb_hook flows (hook layer
                  now includes worker contexts when enabled)

Flags:
    --no-hooks   disable the flow-hook layer (taint stays on) — the
                 BEFORE condition for the worker-coverage delta
    --skip-crawl reuse saved evaluate_crawl.json + evaluate_workers_crawl.json

Usage:
    python testbed/evaluate.py [--engine foxhound|chrome] [--headless]
                               [--skip-crawl] [--no-hooks]
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
    PAGE_PORT, SINK_PORT, PageHandler, SinkHandler, sink_received,
)

PAGE_PATH = f"http://localhost:{PAGE_PORT}/transforms.html"
WORKER_PATH = f"http://localhost:{PAGE_PORT}/idb_workers.html"
REPORT = os.path.join(os.path.dirname(__file__), "evaluate_report.json")

PAGES = [
    ("transforms", "transforms.html", "evaluate_crawl.json"),
    ("workers", "idb_workers.html", "evaluate_workers_crawl.json"),
]


# ─── Crawl helpers ──────────────────────────────────────────────────

async def _crawl_page(page_name: str, iterations: int) -> dict:
    from crawler import crawl_all_sites
    config.CRAWL_ITERATIONS = iterations
    results = await crawl_all_sites(
        custom_sites=[{"url": f"http://localhost:{PAGE_PORT}/{page_name}",
                       "reason": "phase7 evaluation"}],
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
    measured delta is the transform capability, not the dedup fix).
    Deliberately uses RAW network_requests (no hook synthesis): the
    baseline method does not use the hook layer."""
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
                    "method": "taint",
                    "mechanism": "taint"})
    for hf in analysis.get("idb_hook_flows") or []:
        out.append({"identifier_value": str(hf.get("idb_value", "")),
                    "request_url": str(hf.get("target", "")),
                    "method": "idb_hook",
                    "mechanism": "idb_hook",
                    "context": hf.get("context") or "window"})
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


def _print_method_table(methods: dict, flows, label: str):
    print(f"\n=== Method comparison {label} (ground truth: "
          f"{len(flows)} flows, {len(gt.NON_IDENTIFIERS)} benign) ===")
    print(f"  {'method':26} {'pred':>5} {'TP':>4} {'FP':>4} {'FN':>4} "
          f"{'prec':>7} {'recall':>7}")
    for name, s in methods.items():
        prec = (f"{s['precision']:.3f}" if s["precision"] is not None
                else "  n/a")
        rec = f"{s['recall']:.3f}" if s["recall"] is not None else "  n/a"
        print(f"  {name:26} {s['predicted']:>5} {s['tp']:>4} "
              f"{s['fp']:>4} {s['fn']:>4} {prec:>7} {rec:>7}")


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


# ─── Per-mechanism attribution (Phase 13) ───────────────────────────

def mechanism_breakdown(views: dict, flows: list[tuple]) -> dict:
    """Group every predicted event by the mechanism that produced it.

    views: {"transforms": analysis, "workers": analysis}
    Reports per-mechanism event counts (TP/FP against the union GT) and
    a flow→mechanisms catch matrix (which mechanisms observed each flow).
    """
    by_mech: dict = {}
    catch: dict = {}
    for page, analysis in views.items():
        for ev in full_events(analysis):
            m = str(ev.get("mechanism") or "unknown")
            d = by_mech.setdefault(
                m, {"count": 0, "tp": 0, "fp": 0, "pages": {}})
            d["count"] += 1
            d["pages"][page] = d["pages"].get(page, 0) + 1
            if any(_event_matches_flow(ev, f) for f in flows):
                d["tp"] += 1
            else:
                d["fp"] += 1
        for ev in dynamic_events(analysis):
            m = str(ev.get("mechanism") or ev.get("method") or "unknown")
            d = by_mech.setdefault(
                m, {"count": 0, "tp": 0, "fp": 0, "pages": {}})
            d["count"] += 1
            d["pages"][page] = d["pages"].get(page, 0) + 1
            if any(_event_matches_flow(ev, f) for f in flows):
                d["tp"] += 1
            else:
                d["fp"] += 1
    # flow catch matrix: for each flow, which mechanisms produced a
    # matching event (union across pages and both event families)
    all_events = []
    for analysis in views.values():
        all_events.extend(full_events(analysis))
        all_events.extend(dynamic_events(analysis))
    for f in flows:
        subs = f[1][:60]
        mech_set = sorted({
            str(ev.get("mechanism") or ev.get("method") or "unknown")
            for ev in all_events if _event_matches_flow(ev, f)})
        catch[subs] = mech_set
    return {"by_mechanism": by_mech, "flow_catch_matrix": catch}


# ─── Worker-hook coverage (Phase 13) ────────────────────────────────

def worker_coverage(wk_view: dict, wk_analysis: dict,
                    enabled: bool, sink_paths: list) -> dict:
    """Coverage accounting for the worker injection layer.

    Asserts (when injection is on): dedicated + shared workers spawned
    through the blob bootstrap and their hook core reported in (hello),
    the service worker is spawn-accounted but intentionally left
    unmarked (environment-dark: no injection on either engine — FF
    route bypass, Chromium route-fulfillment breaks SW cross-origin
    fetches), no frame reported tampering, every worker-context send is
    observable (Playwright capture or hook synthesis), and the SW exfil
    reached the sink browser-side.
    """
    import detector
    cov = {"worker_injection_enabled": bool(enabled), "checks": []}

    def check(name, ok, detail=""):
        cov["checks"].append({"name": name, "passed": bool(ok),
                              "detail": detail})
        print(f"  [{'PASS' if ok else 'FAIL'}] WC: {name}"
              + (f" — {detail}" if detail else ""))
        return ok

    # flow_hooks live PER ITERATION (site-level key is only populated
    # for older artifacts) — aggregate across iterations.
    fh_list = [it.get("flow_hooks") or {}
               for it in (wk_view.get("iterations") or [])]
    if not fh_list and wk_view.get("flow_hooks"):
        fh_list = [wk_view.get("flow_hooks") or {}]

    metas: list = []
    spawned: dict = {}
    seen: dict = {}
    gaps: list = []
    tampered = []
    for fh in fh_list:
        metas.extend(fh.get("meta") or [])
    for m in metas:
        spawned.update(m.get("spawned") or {})
        seen.update(m.get("seen") or {})
        gaps.extend(m.get("gaps") or [])
        if m.get("tampered"):
            tampered.append((m.get("frame_url"), m.get("tampered")))
    cov["spawned"] = spawned
    cov["seen"] = {k: v for k, v in seen.items()}
    cov["gaps"] = gaps
    cov["tampered"] = tampered
    cov["route_injections"] = 0  # route machinery removed (blob path)
    synth = [r for r in detector.synthesize_network_from_hooks(wk_view)
             if r.get("synthetic")]
    cov["synthetic_network_entries"] = len(synth)
    cov["synthetic_contexts"] = sorted({
        c for r in synth for c in (r.get("source_contexts") or [])})

    # browser-side ground truth: the sink actually received the SW exfil
    # (proves the SW ran + exfiltrated even though every detector is
    # blind to it on this browser stack). sink_paths comes from the live
    # SinkHandler log (fresh crawl) or evaluate_sink_log.json (skip-crawl
    # runs in a new process where the in-memory log is empty).
    cov["sw_sink_paths"] = sorted(
        p for p in sink_paths if "/v/sv" in p)[:6]
    cov["sw_sink_seen"] = any("/v/svraw" in p for p in sink_paths)

    if not enabled:
        print("  [SKIP] WC: worker injection disabled "
              "(--no-worker-injection / --no-hooks before-run) — "
              "coverage asserts not applicable")
        cov["expected_off"] = True
        return cov

    # kind-based matching: hello keys are "kind\0location"; spawned
    # values are the same blob: URLs the hellos report as location.
    seen_pairs = [(k.split("\u0000", 1)[0], k.split("\u0000", 1)[1])
                  for k in seen if "\u0000" in k]
    ded_spawn = [u for u, k in spawned.items() if k == "dedicated"]
    ded_seen = [loc for kind, loc in seen_pairs if kind == "dedicated"]
    check("dedicated worker: blob bootstrap spawned (hello received)",
          bool(ded_spawn) and all(u in ded_seen for u in ded_spawn),
          f"spawned={len(ded_spawn)} seen={len(ded_seen)}")
    sh_spawn = [u for u, k in spawned.items() if k == "shared"]
    sh_seen = [loc for kind, loc in seen_pairs if kind == "shared"]
    check("shared worker: blob bootstrap spawned (hello received)",
          bool(sh_spawn) and all(u in sh_seen for u in sh_spawn),
          f"spawned={len(sh_spawn)} seen={len(sh_seen)}")
    sw_spawn = [u for u, k in spawned.items() if k == "service"]
    check("service worker spawn recorded (left unmarked by design)",
          bool(sw_spawn) and all("wk-sw" in u for u in sw_spawn),
          f"spawned={sw_spawn}")
    unexpected = [g for g in gaps if "wk-sw" not in g]
    check("gaps limited to the environment-dark service worker",
          not unexpected, f"gaps={gaps}")
    check("no frame reported hook tampering",
          not tampered, f"tampered={tampered}")
    # Every worker-context send must be observable somewhere: either
    # Playwright captured the request (dedicated-worker fetches usually
    # are) or the detector synthesized it from the hook send (shared
    # worker fetches are never reported — probe3 Q17 / Chromium).
    worker_send_urls = set()
    for fh in fh_list:
        for s in fh.get("sends") or []:
            if (s.get("ctx") or "window") != "window":
                worker_send_urls.add(str(s.get("url") or ""))
    raw_urls = {r.get("url") for r in
                (wk_view.get("network_requests") or [])}
    synth_urls = {r.get("url") for r in synth}
    missing = sorted(u for u in worker_send_urls
                     if u and u not in raw_urls and u not in synth_urls)
    check("worker sends observable (capture or synthesis)",
          bool(worker_send_urls) and not missing,
          f"worker_sends={len(worker_send_urls)} missing={missing[:3]}")
    check("service worker exfil reached the sink (browser ground truth)",
          cov["sw_sink_seen"],
          f"sw_sink_paths={cov['sw_sink_paths']}")
    cov["passed"] = all(c["passed"] for c in cov["checks"])
    return cov


# ─── Main ───────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--engine", default="foxhound",
                        choices=["foxhound", "chrome"])
    parser.add_argument("--headless", action="store_true")
    parser.add_argument("--skip-crawl", action="store_true",
                        help="reuse saved per-page crawl JSONs")
    parser.add_argument("--no-hooks", action="store_true",
                        help="disable flow hooks entirely (taint stays "
                             "on) — full instrumentation-off reference")
    parser.add_argument("--no-worker-injection", action="store_true",
                        help="window hooks + taint on, worker injection "
                             "off — the true BEFORE condition for the "
                             "worker-coverage delta")
    args = parser.parse_args()

    # GT self-check
    vecs = gt.verify_js_md5_vectors()
    assert all(vecs.values()), f"ground-truth md5 vectors drifted: {vecs}"
    print(f"  ground-truth vectors OK: {vecs}")

    # Worker-variant capability: every scored worker flow's transform
    # chain must be generable by the matcher, or the flow is undetectable
    # by construction (page/GT drift bug, not a detector result).
    import transforms as tf
    tid_variants = tf.generate_variants(gt.TID)
    tid_prefixes = tf.truncated_prefixes(gt.TID)
    needed_variant = {
        gt.TID, __import__("urllib.parse", fromlist=["quote"]).quote(
            gt.TID, safe=""),
        __import__("base64").b64encode(gt.TID.encode()).decode(),
        gt.TID.encode().hex(),
        __import__("hashlib").md5(gt.TID.encode()).hexdigest(),
        __import__("hashlib").sha1(gt.TID.encode()).hexdigest(),
        __import__("hashlib").sha256(gt.TID.encode()).hexdigest(),
        __import__("urllib.parse", fromlist=["quote"]).quote(
            __import__("urllib.parse", fromlist=["quote"]).quote(
                gt.TID, safe=""), safe=""),
    }
    missing = sorted(v for v in needed_variant
                     if v not in tid_variants)
    cap_ok = (not missing) and (gt.TID[:16] in tid_prefixes)
    assert cap_ok, f"worker GT chains not generable: missing={missing}"
    print(f"  worker variant capability OK "
          f"({len(gt.WORKER_FLOWS)} flows, {len(gt.NON_IDENTIFIERS)} benign)")

    sink = ThreadingHTTPServer(("127.0.0.1", SINK_PORT), SinkHandler)
    page = ThreadingHTTPServer(("127.0.0.1", PAGE_PORT), PageHandler)
    for srv in (sink, page):
        threading.Thread(target=srv.serve_forever, daemon=True).start()

    crawl_dir = os.path.dirname(__file__)
    try:
        config.set_engine(args.engine)
        config.HEADLESS = args.headless
        orig_hooks = getattr(config, "FLOW_HOOKS_ENABLED", True)
        orig_inject = getattr(config, "FLOW_WORKER_INJECTION_ENABLED", True)
        if args.no_hooks:
            config.FLOW_HOOKS_ENABLED = False
        if args.no_worker_injection:
            config.FLOW_WORKER_INJECTION_ENABLED = False
        worker_injection_on = (not args.no_hooks
                               and not args.no_worker_injection)
        hooks_on = not args.no_hooks
        orig_score = config.ID_SCORE_THRESHOLD
        orig_len = config.MIN_ID_LENGTH
        config.ID_SCORE_THRESHOLD = 0.0
        config.MIN_ID_LENGTH = 8

        crawls: dict = {}
        for name, page_name, fname in PAGES:
            path = os.path.join(crawl_dir, fname)
            if args.skip_crawl and os.path.exists(path):
                with open(path) as f:
                    crawls[name] = json.load(f)
                print(f"  reusing crawl: {path}")
            else:
                print(f"  crawling {page_name} (2 iterations, "
                      f"hooks={'on' if hooks_on else 'off'}, "
                      f"worker_injection="
                      f"{'on' if worker_injection_on else 'off'}) …")
                data = asyncio.run(_crawl_page(page_name, 2))
                if not data:
                    print(f"FATAL: {name} crawl empty")
                    return 2
                with open(path, "w") as f:
                    json.dump(data, f, default=str)
                print(f"  crawl saved → {path}")
                crawls[name] = data

        # Persist the sink log right after the crawls so --skip-crawl
        # runs (fresh process, empty in-memory log) can still prove the
        # service-worker exfil browser-side.
        sink_log_path = os.path.join(crawl_dir, "evaluate_sink_log.json")
        if not args.skip_crawl:
            with open(sink_log_path, "w") as f:
                json.dump([{"path": r.get("path", ""),
                            "method": r.get("method", "")}
                           for r in sink_received], f, indent=1)
        try:
            with open(sink_log_path) as f:
                sink_paths = [e.get("path", "") for e in json.load(f)]
        except Exception:
            sink_paths = [r.get("path", "") for r in sink_received]

        tf_data = crawls["transforms"]
        wk_data = crawls["workers"]
        tf_domain = tf_data.get("domain", "")
        wk_domain = wk_data.get("domain", "")

        ALL_FLOWS = list(gt.FLOWS) + list(gt.WORKER_FLOWS)

        # Method comparison runs on a DIFF-NEUTRAL view (1 iteration) so
        # the legacy changed-records filter doesn't confound substring vs
        # transforms vs dynamic — that filter is measured separately as
        # its own ablation below.
        views = {}
        for name, data in (("transforms", tf_data), ("workers", wk_data)):
            v = dict(data)
            v["iterations"] = (data.get("iterations") or [])[:1]
            views[name] = v
        analyses = {name: run_analysis(v) for name, v in views.items()}

        # ── methods: per-page (page-specific GT) + union (all flows) ──
        page_flows = {"transforms": list(gt.FLOWS),
                      "workers": list(gt.WORKER_FLOWS)}
        methods_by_page = {}
        for name, v in views.items():
            domain = tf_domain if name == "transforms" else wk_domain
            methods_by_page[name] = {
                "substring (baseline)": score(
                    baseline_events(v, domain), page_flows[name],
                    gt.NON_IDENTIFIERS),
                "transforms (full)": score(
                    full_events(analyses[name]), page_flows[name],
                    gt.NON_IDENTIFIERS),
                "dynamic (taint+hooks)": score(
                    dynamic_events(analyses[name]), page_flows[name],
                    gt.NON_IDENTIFIERS),
            }
        union_events = {
            "substring (baseline)": (
                baseline_events(views["transforms"], tf_domain)
                + baseline_events(views["workers"], wk_domain)),
            "transforms (full)": (
                full_events(analyses["transforms"])
                + full_events(analyses["workers"])),
            "dynamic (taint+hooks)": (
                dynamic_events(analyses["transforms"])
                + dynamic_events(analyses["workers"])),
        }
        methods = {k: score(v, ALL_FLOWS, gt.NON_IDENTIFIERS)
                   for k, v in union_events.items()}

        _print_method_table(methods, ALL_FLOWS, "(union of both pages)")
        _print_method_table(methods_by_page["transforms"], ALL_FLOWS,
                            "(transforms page only)")
        _print_method_table(methods_by_page["workers"], ALL_FLOWS,
                            "(worker page only)")

        # ── per-mechanism attribution ──
        mech = mechanism_breakdown(analyses, ALL_FLOWS)
        print("\n=== Per-mechanism (union events) ===")
        print(f"  {'mechanism':14} {'count':>6} {'TP':>5} {'FP':>5}  pages")
        for m, d in sorted(mech["by_mechanism"].items(),
                           key=lambda kv: -kv[1]["count"]):
            print(f"  {m:14} {d['count']:>6} {d['tp']:>5} {d['fp']:>5}  "
                  f"{d['pages']}")
        caught_by_multi = sum(
            1 for ms in mech["flow_catch_matrix"].values() if len(ms) > 1)
        print(f"  flows caught by >1 mechanism: {caught_by_multi}"
              f"/{len(ALL_FLOWS)}")

        # ── ablations (transforms page, classic GT) ──
        abl = ablations(tf_data)
        print("\n=== Ablations (full method, transforms page) ===")
        print(f"  {'variant':24} {'pred':>5} {'FP':>4} {'FN':>4} "
              f"{'prec':>7} {'recall':>7}")
        for label, s in abl.items():
            prec = (f"{s['precision']:.3f}" if s["precision"] is not None
                    else "  n/a")
            print(f"  {label:24} {s['predicted']:>5} {s['fp']:>4} "
                  f"{s['fn']:>4} {prec:>7} {s['recall']:.3f}")

        # ── Paper §4.1 client-identifier classification (IDB only) ──
        import uid as paper_uid
        uid_report_full = paper_uid.classify_site(
            tf_data.get("iterations") or [])
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

        # ── worker-hook coverage ──
        print("\n=== Worker-hook coverage (worker page) ===")
        cov = worker_coverage(views["workers"], analyses["workers"],
                              enabled=worker_injection_on,
                              sink_paths=sink_paths)

        # ── noise: two extra independent crawls (transforms page) ──
        counts = [len(full_events(analyses["transforms"]))]
        for run_idx in (2, 3):
            try:
                extra = asyncio.run(_crawl_page("transforms.html", 1))
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
        config.FLOW_HOOKS_ENABLED = orig_hooks
        config.FLOW_WORKER_INJECTION_ENABLED = orig_inject

        report = {
            "engine": args.engine,
            "headless": bool(args.headless),
            "hooks_enabled": hooks_on,
            "worker_injection": worker_injection_on,
            "page": PAGE_PATH,
            "worker_page": WORKER_PATH,
            "ground_truth": {
                "flows": len(ALL_FLOWS),
                "classic_flows": len(gt.FLOWS),
                "worker_flows": len(gt.WORKER_FLOWS),
                "worker_sw_unscored": len(gt.WORKER_SW_UNSCORED),
                "non_identifiers": len(gt.NON_IDENTIFIERS),
                "md5_vectors_ok": vecs,
                "worker_variant_capability_ok": cap_ok,
            },
            "methods": methods,
            "methods_by_page": methods_by_page,
            "mechanisms": mech,
            "worker_coverage": cov,
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
        cov_ok = (not report["worker_injection"]) or cov.get("passed", False)
        print(f"\n  UID checks: {sum(c['passed'] for c in uid_checks)}"
              f"/{len(uid_checks)}")
        if report["worker_injection"]:
            print(f"  WC checks: {sum(c['passed'] for c in cov['checks'])}"
                  f"/{len(cov['checks'])}")
        print(f"  report → {REPORT}")
        return 0 if (uid_ok and cov_ok) else 1
    finally:
        config.FLOW_HOOKS_ENABLED = True
        config.FLOW_WORKER_INJECTION_ENABLED = True
        sink.shutdown()
        page.shutdown()


if __name__ == "__main__":
    sys.exit(main())
