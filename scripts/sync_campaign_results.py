#!/usr/bin/env python3
"""
Campaign results sync (Stage A → repo), one-shot & idempotent.

Regenerates campaign_results/stageA/ from the live scale store +
analyses, commits what changed, and pushes it to
origin/buildout/full-plan — designed to run repeatedly from a loop
(see scripts/run_results_sync_loop.sh).

Artifacts per run (all counts-only; per-site reports rendered only for
sites with IDB records):
    site_results.csv    rank,domain,status + IDB/taint/exfil counts
    summary_table.md    progress, totals, top sites, failures
    store_stageA.jsonl  snapshot of the resumable job store
    reports/<site>.html standalone report (values+sinks) for sites with
                        IDB records — mission-relevant subset only
    bulk_stageA.html    aggregate executive report, re-rendered every
                        --bulk-every completions (and once at the end)

Exit codes: 0 synced (or nothing to do) · 1 error · 99 campaign complete
            (sync + final push already done)
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import re
import shutil
import subprocess
import sys
from collections import Counter
from urllib.parse import urlparse

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
ENGINE = os.path.join(REPO, "Web", "src", "engine")
sys.path.insert(0, ENGINE)


def _git(*args, env=None):
    e = os.environ.copy()
    if env:
        e.update(env)
    return subprocess.run(["git", "-C", REPO, *args],
                          capture_output=True, text=True, env=e)


def _askpass() -> dict:
    for cand in (os.path.expanduser("~/privadb-askpass.sh"),
                 "/tmp/opencode/gitaskpass.sh"):
        if os.path.exists(cand) and os.access(cand, os.X_OK):
            return {"GIT_ASKPASS": cand, "GIT_TERMINAL_PROMPT": "0"}
    return None


def load_ranks(path: str) -> dict[str, str]:
    ranks: dict[str, str] = {}
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or "," not in line:
                    continue
                r, _, d = line.partition(",")
                d = d.strip().lower()
                if d and d not in ranks:
                    ranks[d] = r.strip()
    except FileNotFoundError:
        pass
    return ranks


def backfill(row: dict) -> dict:
    """Older store rows lack IDB fields — read them from the analysis."""
    summ = row.get("summary") or {}
    if "idb_dbs" in summ:
        return summ
    rp = summ.get("result_path")
    if rp and os.path.exists(rp):
        try:
            with open(rp, encoding="utf-8") as f:
                a = json.load(f)
            summ["idb_dbs"] = (a.get("indexeddb_summary") or {}).get(
                "database_count", 0)
            summ["idb_records"] = (a.get("indexeddb_summary") or {}).get(
                "total_records", 0)
            summ["client_ids"] = a.get("client_identifiers_found", 0)
        except Exception:
            pass
    summ.setdefault("idb_dbs", "")
    summ.setdefault("idb_records", "")
    summ.setdefault("client_ids", "")
    return summ


def domain_of(url: str) -> str:
    return (urlparse(url).netloc or url).lower().strip("/")


def write_csv(rows, ranks, out_path):
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["rank", "domain", "status", "attempts", "idb_dbs",
                    "idb_records", "identifiers", "client_ids_4_1",
                    "exfil", "taint", "idb_hook", "storage_exfil"])
        for r in sorted(rows, key=lambda x: domain_of(x["url"])):
            dom = domain_of(r["url"])
            s = backfill(r)
            rank = ranks.get(dom) or ranks.get(dom.removeprefix("www.")) \
                or ranks.get(f"www.{dom}") or ""
            w.writerow([rank, dom, r.get("status", ""),
                        r.get("attempts", 0),
                        s.get("idb_dbs", ""), s.get("idb_records", ""),
                        s.get("identifiers", ""), s.get("client_ids", ""),
                        s.get("exfil", ""), s.get("taint", ""),
                        s.get("idb_hook", ""), s.get("storage_exfil", "")])


def write_summary(rows, out_path, extra):
    terminal = [r for r in rows
                if r.get("status") in ("done", "permanent_failed")]
    done = [r for r in rows if r.get("status") == "done"]
    fails = [r for r in rows if r.get("status") == "permanent_failed"]
    agg = Counter()
    for r in done:
        s = backfill(r)
        for k in ("idb_dbs", "idb_records", "identifiers", "client_ids",
                  "exfil", "taint", "idb_hook", "storage_exfil"):
            v = s.get(k)
            if isinstance(v, int):
                agg[k] += v
    by_taint = sorted(
        ((backfill(r).get("taint") or 0), domain_of(r["url"]))
        for r in done)[-15:][::-1]
    idb_sites = sorted(
        ((backfill(r).get("idb_records") or 0), domain_of(r["url"]))
        for r in done if (backfill(r).get("idb_records") or 0) > 0
    )[::-1][:15]

    L = []
    L.append("# Stage A — Tranco Top 10k × Foxhound dynamic taint "
             "analysis\n")
    L.append(f"Progress: **{len(terminal)}/10000** terminal "
             f"({len(done)} done, {len(fails)} failed) · "
             f"running/pending: {10000 - len(terminal)}\n")
    L.append(f"Run: foxhound · iterations=1 (leak pass — §4.1 identity "
             f"confirmation deferred to Stage B) · workers=2 · "
             f"--max-cpu 50 (CPU governor) · --prune-raw · "
             f"headless · last sync {extra.get('synced_at')}\n")
    L.append("| metric | total |")
    L.append("|---|---:|")
    for k, label in [("taint", "taint flows"),
                     ("storage_exfil", "storage exfils"),
                     ("idb_dbs", "IndexedDB databases"),
                     ("idb_records", "IndexedDB records"),
                     ("exfil", "exfil events"),
                     ("idb_hook", "idb-hook flows"),
                     ("client_ids", "§4.1 confirmed identities "
                                    "(Stage B only)")]:
        L.append(f"| {label} | {agg.get(k, 0)} |")
    L.append("")
    if by_taint:
        L.append("Top sites by taint flows:\n")
        L.append("| site | taint flows |")
        L.append("|---|---:|")
        for v, d in by_taint:
            L.append(f"| {d} | {v} |")
        L.append("")
    if idb_sites:
        L.append("Sites with IndexedDB records (mission scope):\n")
        L.append("| site | IDB records |")
        L.append("|---|---:|")
        for v, d in idb_sites:
            L.append(f"| {d} | {v} |")
        L.append("")
    if fails:
        L.append(f"Failed sites ({len(fails)}): "
                 + ", ".join(domain_of(r["url"]) for r in fails[:25])
                 + ("…" if len(fails) > 25 else "") + "\n")
    L.append("Full per-site counts: `site_results.csv` · "
             "job store: `store_stageA.jsonl` (resumable) · "
             "per-site reports (IDB-active sites): `reports/` · "
             "aggregate: `bulk_stageA.html` (every "
             f"{extra.get('bulk_every')} completions).\n")
    L.append("Stage B plan: `tranco.py --select-idb <results dir> "
             "--out stageB.csv` then `scale.py --list stageB.csv "
             "--iterations 2` for paper §4.1 identity confirmation.\n")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(L))


def render_idb_reports(rows, reports_dir):
    """Render missing standalone reports for sites with IDB records."""
    import grc as grc_mod
    import report_html
    os.makedirs(reports_dir, exist_ok=True)
    made = 0
    for r in rows:
        if r.get("status") != "done":
            continue
        s = backfill(r)
        if not (s.get("idb_records") or 0):
            continue
        rp = s.get("result_path")
        dom = domain_of(r["url"])
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", dom)[:80]
        out = os.path.join(reports_dir, f"{safe}.html")
        if os.path.exists(out) or not rp or not os.path.exists(rp):
            continue
        try:
            with open(rp, encoding="utf-8") as f:
                analysis = json.load(f)
            url = analysis.get("url") or f"https://{dom}"
            g = grc_mod.run_grc_checks(analysis, url, None, None)
            doc = report_html.render_scan_report(
                analysis, url, g,
                run_meta=analysis.get("run_meta") or {},
                scan_meta={"started_at": analysis.get("timestamp", ""),
                           "status": "completed"},
                sources=[os.path.relpath(rp, REPO)])
            with open(out, "w", encoding="utf-8") as f:
                f.write(doc)
            made += 1
        except Exception as e:
            print(f"  report failed for {dom}: {e}")
    return made


def render_milestone_bulk(rows, out_path):
    import grc as grc_mod
    import report_html
    sites = []
    for r in rows:
        if r.get("status") != "done":
            continue
        rp = (r.get("summary") or {}).get("result_path")
        if not rp or not os.path.exists(rp):
            continue
        try:
            with open(rp, encoding="utf-8") as f:
                a = json.load(f)
        except Exception:
            continue
        dom = a.get("domain") or domain_of(r["url"])
        url = a.get("url") or f"https://{dom}"
        sites.append({"domain": dom, "url": url, "engine": "foxhound",
                      "analysis": a,
                      "grc": grc_mod.run_grc_checks(a, url, None, None)})
    if not sites:
        return False
    doc = report_html.render_bulk_report(sites)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(doc)
    return True


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--store", default=os.path.join(
        ENGINE, "data", "scale", "stageA_10k.jsonl"))
    ap.add_argument("--tranco", default=os.path.join(
        ENGINE, "data", "tranco_10000.csv"))
    ap.add_argument("--out-dir", default=os.path.join(
        REPO, "campaign_results", "stageA"))
    ap.add_argument("--bulk-every", type=int, default=1000)
    args = ap.parse_args()

    if not os.path.exists(args.store):
        print("store not found — campaign not started?")
        return 1

    rows = [json.loads(line) for line in open(args.store, encoding="utf-8")
            if line.strip()]
    total = len(rows)
    counts = Counter(r.get("status") for r in rows)
    done_n = counts.get("done", 0)
    terminal = counts.get("done", 0) + counts.get("permanent_failed", 0)
    complete = (counts.get("pending", 0) == 0
                and counts.get("running", 0) == 0 and total > 0)

    os.makedirs(args.out_dir, exist_ok=True)
    ranks = load_ranks(args.tranco)

    # 1) CSV + store snapshot + summary
    csv_path = os.path.join(args.out_dir, "site_results.csv")
    write_csv(rows, ranks, csv_path)
    shutil.copyfile(args.store,
                    os.path.join(args.out_dir, "store_stageA.jsonl"))
    from datetime import datetime, timezone
    write_summary(rows, os.path.join(args.out_dir, "summary_table.md"),
                  {"synced_at": datetime.now(timezone.utc).isoformat(
                       timespec="seconds"),
                   "bulk_every": args.bulk_every})
    print(f"csv+summary+store snapshot updated "
          f"({done_n} done / {total})")

    # 2) per-site reports for IDB-active sites (incremental)
    made = render_idb_reports(rows, os.path.join(args.out_dir, "reports"))
    if made:
        print(f"rendered {made} new IDB-site report(s)")

    # 3) milestone bulk report
    state_path = os.path.join(args.out_dir, "bulk_state.json")
    state = {}
    if os.path.exists(state_path):
        try:
            state = json.load(open(state_path))
        except Exception:
            state = {}
    last = int(state.get("generated_at_done", 0))
    if done_n >= last + args.bulk_every or (complete and done_n != last):
        if render_milestone_bulk(rows,
                                 os.path.join(args.out_dir,
                                              "bulk_stageA.html")):
            json.dump({"generated_at_done": done_n},
                      open(state_path, "w"))
            print(f"bulk report re-rendered at {done_n} done")

    # 4) commit + push
    dirty = _git("status", "--porcelain", "--", args.out_dir).stdout.strip()
    pushed = False
    if dirty:
        _git("add", "--", args.out_dir)
        msg = (f"results(stageA): {done_n}/{total} sites — "
               f"taint/IDB/exfil counts, IDB-site reports, "
               f"summary+store snapshot")
        c = _git("commit", "-m", msg)
        if c.returncode == 0:
            sha = _git("rev-parse", "--short", "HEAD").stdout.strip()
            print(f"committed {sha}: {msg}")
            ask = _askpass()
            if ask:
                p = _git("push", "origin", "buildout/full-plan", env=ask)
                if p.returncode == 0:
                    pushed = True
                    print("pushed → origin/buildout/full-plan")
                else:
                    print("PUSH FAILED (commit kept locally):\n"
                          + (p.stderr or p.stdout)[-400:])
            else:
                print("no askpass helper found — commit kept, "
                      "not pushed (create ~/privadb-askpass.sh)")
        else:
            print("nothing to commit (race-clean)")
    else:
        print("no result changes since last sync")

    print(f"state: {dict(counts)} · complete={complete}")
    if complete:
        print("CAMPAIGN COMPLETE — final sync done")
        return 99
    return 0


if __name__ == "__main__":
    sys.exit(main())
