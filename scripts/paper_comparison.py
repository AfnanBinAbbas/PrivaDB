#!/usr/bin/env python3
"""Paper comparison — PrivaDB Stage A vs "What Storage?" (Ahmad et al.).

Renders campaign_results/stageA/paper_comparison.md with:
  A. count-level totals for EVERY completed site (from the store —
     survives analysis pruning), vs the paper's headline numbers;
  B. event-level classification tables (confinement / tracking /
     cross-site — paper Tables II–IV) computed with
     detector.compute_paper_metrics over whatever per-site ANALYSES
     currently exist (grows as the campaign (re)produces them);
  C. the IndexedDB-specific numbers the paper does NOT cover (its
     scope ends at localStorage/sessionStorage getItem/setItem).

Re-run any time during/after the campaign:
    venv/bin/python scripts/paper_comparison.py
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
ENGINE = os.path.join(REPO, "Web", "src", "engine")
sys.path.insert(0, ENGINE)

# ── Published numbers: What Storage? An Empirical Analysis of Web
# Storage in the Wild (Ahmad, Casarin, Calzavara) — Tranco Top 5k
# (list 2021-12-14), Jalangi dynamic taint, 60 s render. Verbatim from
# the paper's Section IV.B / Tables II–IV.
PAPER = {
    "list": "Tranco Top 5k (2021-12-14)",
    "instrumented_sites": 3324,
    "raw_flows": 5187,
    "raw_flow_domains": 837,
    "raw_flow_domain_pct": 25,
    "filtered_flows": 3207,
    "filtered_domains": 651,
    "confidentiality": 531,
    "integrity": 2676,
    "external": 1053,
    "external_pct": 33,
    "tracking": 2276,
    "tracking_pct": 71,
    "external_tracker_pct": 78,
    "cross_site_range": "84–98% of external (per class)",
    "local_only": 2487,
    "session_only": 708,
    "confid_tracker_pct": 65,
    "integrity_tracker_pct": 72,
}


def load_store(path: str) -> list[dict]:
    rows = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def count_level(rows: list[dict]) -> dict:
    """Count-level totals.

    Prefers the curated site_results.csv (sync backfills IDB fields
    from analyses into it; raw store rows can lack them) and falls
    back to the store snapshot.
    """
    import csv as csv_mod
    csv_path = os.path.join(REPO, "campaign_results", "stageA",
                            "site_results.csv")

    def i(v):
        try:
            return int(str(v or 0).replace(",", ""))
        except (TypeError, ValueError):
            return 0

    if os.path.exists(csv_path):
        with open(csv_path) as f:
            srows = list(csv_mod.DictReader(f))
        done = [r for r in srows if r.get("status") == "done"]
        summ = done
        listed = len(srows)
    else:
        done = [r for r in rows if r.get("status") == "done"]
        summ = [r.get("summary") or {} for r in done]
        listed = len(rows)

    idb_sites = sum(1 for s in summ
                    if i(s.get("idb_dbs")) or i(s.get("idb_records")))
    tot = lambda k: sum(i(s.get(k)) for s in summ)  # noqa: E731
    return {
        "listed": listed,
        "done": len(done),
        "idb_sites": idb_sites,
        "idb_site_pct": round(100 * idb_sites / max(len(done), 1), 1),
        "idb_dbs": tot("idb_dbs"),
        "idb_records": tot("idb_records"),
        "identifiers": tot("identifiers"),
        "exfil_events": tot("exfil"),
        "taint_flows": tot("taint"),
        "idb_hook_flows": tot("idb_hook"),
        "storage_exfil": tot("storage_exfil"),
        "client_ids_4_1": tot("client_ids_4_1"),
        "sites_with_exfil": sum(1 for s in summ if i(s.get("exfil"))),
        "sites_with_storage_exfil": sum(
            1 for s in summ if i(s.get("storage_exfil"))),
        "sites_with_taint": sum(1 for s in summ if i(s.get("taint"))),
    }


def event_level(rows: list[dict]) -> tuple[dict | None, int]:
    """compute_paper_metrics over analyses that still exist on disk."""
    from detector import compute_paper_metrics
    analyses = []
    for r in rows:
        if r.get("status") != "done":
            continue
        rp = (r.get("summary") or {}).get("result_path")
        if not rp or not os.path.exists(rp):
            continue
        try:
            with open(rp) as f:
                analyses.append(json.load(f))
        except Exception:
            continue
    if not analyses:
        return None, 0
    return compute_paper_metrics(analyses), len(analyses)


def pct(num, den):
    return f"{100 * num / den:.1f}%" if den else "n/a"


def render(cl: dict, pm: dict | None, pm_n: int, out_path: str):
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    L = []
    L.append("# Paper comparison — PrivaDB vs *What Storage?* "
             "(IndexedDB context)\n")
    L.append(f"Generated: `{now}` · regenerate: "
             "`venv/bin/python scripts/paper_comparison.py`\n")
    L.append("Paper: Zubair Ahmad, Samuele Casarin, Stefano Calzavara — "
             "*What Storage? An Empirical Analysis of Web Storage in the "
             "Wild* (Tranco Top 5k, Jalangi dynamic taint). "
             "Source: `References/What Storage An Empirical Analysis of.pdf` "
             "§IV.B + Tables II–IV.\n")

    L.append("## 0. Instrument differences (read before comparing)\n")
    L.append("| axis | paper | PrivaDB Stage A |")
    L.append("|---|---|---|")
    L.append(f"| list | {PAPER['list']} | Tranco Top 10k (current) |")
    L.append("| client | Puppeteer + Jalangi JS instrumentation | "
             "Foxhound (Firefox 137) taint + in-page flow hooks |")
    L.append("| render budget | 60 s | 8 s idle (IDLE_WAIT) |")
    L.append("| storage scope | localStorage/sessionStorage "
             "`getItem`/`setItem` flows | **IndexedDB** + all other stores "
             "(cookies, LS/SS, caches, SW) |")
    L.append("| flow unit | one taint flow | identifier-matched exfil "
             "event `(id, destination, location, url)` + dynamic flows |")
    L.append("| tracker lists | EasyList/EasyPrivacy script URL | "
             "Disconnect entity list + CNAME-cloaking checks |")
    L.append("")
    L.append("Counts are therefore *framework-aligned* (same "
             "confinement/tracking/cross-site taxonomy), not 1:1 "
             "reproductions of the paper's taint-flow unit.\n")

    L.append("## A. Headline comparison (count level, all completed "
             "sites)\n")
    L.append(f"*Source: `data/scale/stageA_10k.jsonl` store summaries "
             f"({cl['done']}/{cl['listed']} sites done)*\n")
    L.append("| metric | paper (Top 5k) | PrivaDB (Top 10k, "
             f"{cl['done']} done) |")
    L.append("|---|---:|---:|")
    L.append(f"| sites with usable data | {PAPER['instrumented_sites']} "
             f"({pct(PAPER['instrumented_sites'], 5000)} of 5k) | "
             f"{cl['done']} ({pct(cl['done'], 10000)} of 10k, in "
             "progress) |")
    L.append(f"| sites with storage/IDB activity | {PAPER['raw_flow_domains']} "
             f"({PAPER['raw_flow_domain_pct']}%) LS/SS | "
             f"{cl['sites_with_storage_exfil']} "
             f"({pct(cl['sites_with_storage_exfil'], cl['done'])}) "
             "other-store exfil · "
             f"**{cl['idb_sites']} ({cl['idb_site_pct']}%) IndexedDB** |")
    L.append(f"| total flows (paper unit ≈ our exfil events) | "
             f"{PAPER['filtered_flows']} filtered | "
             f"{cl['exfil_events']:,} exfil events + "
             f"{cl['storage_exfil']:,} storage exfils |")
    L.append(f"| dynamic (taint) flows | n/a (their taint IS the flow) | "
             f"{cl['taint_flows']:,} taint + {cl['idb_hook_flows']:,} "
             "idb_hook |")
    L.append(f"| §4.1 confirmed IDB client identifiers | n/a (not in "
             f"paper) | {cl['client_ids_4_1']} (Stage B pending) |")
    L.append("")

    L.append("## B. Classification tables (paper Tables II–IV "
             "equivalents)\n")
    if pm:
        ov = pm.get("overview", {})
        t3 = pm.get("table_iii_confinement", {})
        t4 = pm.get("table_iv_external_breakdown", {})
        L.append(f"*Source: `compute_paper_metrics` over {pm_n} per-site "
                 "analyses (grows as the campaign (re)produces them)*\n")
        L.append("| metric | paper | PrivaDB |")
        L.append("|---|---:|---:|")
        tf = ov.get("total_flows", 0)
        L.append(f"| total flows analysed | {PAPER['filtered_flows']} | "
                 f"{tf} |")
        L.append(f"| confidentiality (outflow) | {PAPER['confidentiality']} "
                 f"| {ov.get('outflow_flows', 0)} |")
        L.append(f"| integrity (inflow) | {PAPER['integrity']} | "
                 f"{ov.get('inflow_flows', 0)} |")
        ext = t3.get("external", {}).get("count",
                                         t3.get("external", {}).get("total", 0))
        L.append(f"| external | {PAPER['external']} "
                 f"({PAPER['external_pct']}%) | {ext} "
                 f"({t3.get('external', {}).get('pct_of_total', 'n/a')}%) |")
        L.append(f"| external = tracking | {PAPER['external_tracker_pct']}% | "
                 f"{pm.get('tracking', {}).get('pct_external_tracking', 'n/a')}%"
                 " |")
        L.append(f"| cross-site (of external) | {PAPER['cross_site_range']} | "
                 f"{t4.get('cross_site', {}).get('pct_of_external', 'n/a')}% |")
        L.append("")
    else:
        L.append("_No per-site analyses currently on disk (the 4,121 "
                 "pre-existing analyses were destroyed by the run_scale "
                 "clean-slate bug — REPORT Phase 13.2; counts survived in "
                 "the store). This section fills in automatically as the "
                 "resumed campaign writes new analyses; full Tables for "
                 "all 10k need the re-crawl phase (see §D)._\n")

    L.append("## C. IndexedDB context — what the paper does NOT cover\n")
    L.append("*Source: store summaries (same as §A)*\n")
    L.append("| IDB metric | value |")
    L.append("|---|---:|")
    L.append(f"| sites using IndexedDB | {cl['idb_sites']} / "
             f"{cl['done']} ({cl['idb_site_pct']}%) |")
    L.append(f"| IDB databases observed | {cl['idb_dbs']:,} |")
    L.append(f"| IDB records observed | {cl['idb_records']:,} |")
    L.append(f"| candidate identifiers extracted | {cl['identifiers']:,} |")
    L.append(f"| IDB→network exfil events | {cl['exfil_events']:,} "
             f"on {cl['sites_with_exfil']} sites |")
    L.append(f"| idb_hook provenance flows | {cl['idb_hook_flows']:,} |")
    L.append(f"| §4.1 confirmed client identifiers | "
             f"{cl['client_ids_4_1']} (needs Stage B: 2 fresh profiles) |")
    L.append("")
    L.append("The paper's sources/sinks table ends at "
             "`localStorage.getItem`/`setItem` — **no IndexedDB "
             "measurement exists in it**; these rows are PrivaDB's "
             "extension, instrument-validated at P/R 0.875/1.000 on the "
             "28-flow ground truth (`evaluate_report.json`).\n")

    L.append("## D. Gaps before paper-grade completeness\n")
    L.append("1. **Campaign completion** — Stage A running "
             f"({cl['done']}/{cl['listed']}); event tables in §B only "
             "cover analyses on disk.")
    L.append("2. **Re-crawl phase** — the 4,121 pre-campaign sites need "
             "re-crawling (store says `done` but analyses were lost to "
             "the run_scale rmtree bug) so Tables II–IV span the full "
             "Top-10k sample: build `missing.csv` from dead "
             "result_paths + a fresh store, run `scale.py --list "
             "missing.csv --db stageA_recrawl.jsonl …`.")
    L.append("3. **Stage B** — `iterations=2` over IDB-active sites for "
             "paper §4.1 client-identifier confirmation "
             "(`tranco.py --select-idb` → `scale.py --list stageB.csv "
             "--iterations 2`).")
    L.append("4. **Human labels** — two-annotator κ on a sample of "
             "exfil events (`export_labeling.py`/`score_labels.py`) for "
             "real-world precision (testbed P/R is not site precision).")
    L.append("5. **Render budget** — paper used 60 s; ours is 8 s. "
             "Late-loading trackers are under-sampled vs the paper.")
    L.append("")

    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w") as f:
        f.write("\n".join(L) + "\n")
    print(f"wrote {out_path} "
          f"(done={cl['done']}, analyses_on_disk={pm_n})")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--store", default=os.path.join(
        ENGINE, "data", "scale", "stageA_10k.jsonl"))
    ap.add_argument("--out", default=os.path.join(
        REPO, "campaign_results", "stageA", "paper_comparison.md"))
    args = ap.parse_args()
    rows = load_store(args.store)
    cl = count_level(rows)
    pm, n = event_level(rows)
    render(cl, pm, n, args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
