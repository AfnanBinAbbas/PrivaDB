#!/usr/bin/env python3
"""
Phase 11 — paper report generator.

Reads the measured artifacts (testbed reports + detector summary) and
emits a single Markdown document with headline numbers, the method
comparison, consent/storage findings, and the limitations section.

    python paper_report.py [--out ../../PAPER_REPORT.md]

Every number in the output traces to a JSON file named in its section —
no hand-typed statistics.
"""
from __future__ import annotations

import argparse
import glob
import json
import os
from datetime import datetime, timezone

ENGINE_DIR = os.path.dirname(os.path.abspath(__file__))
TESTBED = os.path.join(ENGINE_DIR, "testbed")


def _load(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def _pct(x):
    return f"{x * 100:.1f}%" if isinstance(x, (int, float)) else "n/a"


def _fmt(x, nd=3):
    if x is None:
        return "n/a"
    if isinstance(x, float):
        return f"{x:.{nd}f}"
    return str(x)


def collect() -> dict:
    data = {}
    for name in ("evaluate", "consent", "storage", "smoke", "scale"):
        data[name] = _load(os.path.join(TESTBED, f"{name}_report.json"))
    for eng in ("chrome", "foxhound"):
        data[f"partition_{eng}"] = _load(
            os.path.join(TESTBED, f"partition_report_{eng}.json"))
    for eng in ("Chrome", "Foxhound"):
        s = _load(os.path.join(ENGINE_DIR, "results", eng, "analysis",
                               "summary.json"))
        if s:
            data[f"summary_{eng.lower()}"] = s
    crawls = sorted(
        glob.glob(os.path.join(ENGINE_DIR, "results", "*", "crawled",
                               "*.json")),
        key=os.path.getmtime)
    if crawls:
        c = _load(crawls[-1])
        if c and c.get("run_meta"):
            data["run_meta"] = c["run_meta"]
            data["run_meta"]["source"] = os.path.relpath(crawls[-1],
                                                         ENGINE_DIR)
    return data


def headline_metrics(data: dict) -> list[str]:
    lines = []
    for key in ("summary_chrome", "summary_foxhound"):
        summary = data.get(key)
        if not summary:
            continue
        total = len(summary)
        sites = [r for r in summary
                 if (r.get("indexeddb_summary") or {}).get(
                     "database_count", 0) > 0]
        with_exfil = [
            r for r in summary
            if ((r.get("exfiltration_summary") or {}).get("total", 0)
                or len(r.get("taint_flows") or [])
                or len(r.get("idb_hook_flows") or []))]
        third_party_sites = [
            r for r in summary
            if any(e.get("is_third_party")
                   for e in (r.get("exfiltration_events") or []))]
        dyn = sum((r.get("dynamic_flows") or {}).get("total", 0)
                  for r in summary)
        client_ids = sum(int(r.get("client_identifiers_found") or 0)
                         for r in summary)
        lines.append(
            f"- **{key.split('_')[1]}**: {total} site analyses — "
            f"{len(sites)} ({_pct(len(sites) / total if total else 0)}) "
            f"with IndexedDB data; {len(with_exfil)} with exfiltration "
            f"flows; {len(third_party_sites)} sending identifiers to "
            f"third parties; {dyn} dynamic (taint/hook) flows total; "
            f"**{client_ids} paper-confirmed IndexedDB client "
            f"identifiers (§4.1)**")
    return lines or ["_no detector summary found — run a scan first._"]


def method_comparison(data: dict) -> list[str]:
    ev = data.get("evaluate")
    if not ev:
        return ["_evaluate_report.json missing — rerun "
                "`testbed/evaluate.py`._"]
    gt = ev.get("ground_truth", {})
    pages = ("transforms.html + idb_workers.html"
             if gt.get("worker_flows") else "testbed/pages/transforms.html")
    lines = [f"Ground truth: **{gt.get('flows')} must-detect flows** "
             f"({gt.get('classic_flows', gt.get('flows'))} window-context"
             + (f" + {gt.get('worker_flows')} worker-context"
                if gt.get("worker_flows") else "")
             + f"; {pages}), "
             f"**{gt.get('non_identifiers')} benign controls**.", "",
             "| method | predicted | TP | FP | FN | precision | recall |",
             "|---|---:|---:|---:|---:|---:|---:|"]
    for name, s in (ev.get("methods") or {}).items():
        lines.append(
            f"| {name} | {s['predicted']} | {s['tp']} | {s['fp']} | "
            f"{s['fn']} | {_fmt(s['precision'])} | {_fmt(s['recall'])} |")
    cov = ev.get("worker_coverage") or {}
    if cov:
        n_ok = sum(1 for c in (cov.get("checks") or []) if c.get("passed"))
        n_all = len(cov.get("checks") or [])
        lines += ["",
                  f"Worker-context coverage (Phase 13): injection="
                  f"{cov.get('worker_injection_enabled')} · "
                  f"checks {n_ok}/{n_all} · blob bootstrap path · "
                  f"synthetic network entries="
                  f"{cov.get('synthetic_network_entries')} "
                  f"· service-worker sink proof="
                  f"{cov.get('sw_sink_seen')} · gaps="
                  f"{len(cov.get('gaps') or [])} (environment-dark SW)."]
    lines += ["", "Ablations:", "",
              "| variant | predicted | FP | FN | precision | recall |",
              "|---|---:|---:|---:|---:|---:|---:|"]
    for label, s in (ev.get("ablations") or {}).items():
        lines.append(
            f"| {label} | {s['predicted']} | {s['fp']} | {s['fn']} | "
            f"{_fmt(s['precision'])} | {_fmt(s['recall'])} |")
    noise = ev.get("noise") or {}
    lines += ["",
              f"Run-to-run noise: counts={noise.get('counts')} "
              f"mean={noise.get('mean')} σ={noise.get('stdev')}"]
    return lines


def consent_section(data: dict) -> list[str]:
    c = data.get("consent")
    if not c:
        return ["_consent_report.json missing — rerun "
                "`testbed/run_consent.py`._"]
    ca = c.get("consent_analysis") or {}
    h = ca.get("headline") or {}
    conds = ca.get("conditions") or {}
    exf = h.get("third_party_exfils") or {}
    lines = [f"Banner detected: **{h.get('banner_detected')}** · "
             f"pre-consent writes: **{h.get('writes_before_consent')}** · "
             f"post-reject writes: **{h.get('writes_after_reject')}** · "
             f"tracking-without-consent: "
             f"**{h.get('tracking_without_consent')}**", "",
             "| condition | 3rd-party exfils | writes | pre-click |",
             "|---|---:|---:|---:|"]
    for action in sorted(conds):
        row = conds[action]
        lines.append(f"| {action} | {exf.get(action, 0)} | "
                     f"{row.get('writes', 0)} | "
                     f"{row.get('pre_click_writes', 0)} |")
    lines += ["", f"Banner failures surfaced (never silently downgraded): "
              f"{h.get('banner_failures')}"]
    return lines


def storage_section(data: dict) -> list[str]:
    s = data.get("storage")
    if not s:
        return ["_storage_report.json missing._"]
    sa = s.get("storage_analysis") or {}
    comp = sa.get("comparison") or {}
    lines = ["| store | identifiers | exfil events | third-party |",
             "|---|---:|---:|---:|"]
    for st in sorted(comp):
        row = comp[st]
        lines.append(f"| {st} | {row.get('identifiers', 0)} | "
                     f"{row.get('exfil_events', 0)} | "
                     f"{row.get('third_party_exfils', 0)} |")
    resp = sa.get("respawn_candidates") or []
    lines += ["",
              f"Respawn candidates (value present in cookie ∩ IDB): "
              f"**{len(resp)}** — "
              f"{[r.get('cookie_names') for r in resp]}"]
    return lines


def partition_section(data: dict) -> list[str]:
    lines = []
    for eng in ("chrome", "foxhound"):
        p = data.get(f"partition_{eng}")
        if not p:
            continue
        lines.append(f"- **{eng}**: {p.get('verdict', 'inconclusive')}")
    return lines or ["_partition reports missing._"]


def scale_section(data: dict) -> list[str]:
    s = data.get("scale")
    if not s:
        return ["_scale_report.json missing — rerun "
                "`testbed/run_scale.py`._"]
    return [f"Batch verification: **{s.get('n_pass')}/"
            f"{s.get('n_total')}** checks · store backend: "
            f"`{s.get('store_mode')}` · final counts: "
            f"{s.get('counts')}"]


def smoke_section(data: dict) -> list[str]:
    s = data.get("smoke")
    if not s:
        return ["_smoke_report.json missing._"]
    return [f"Ground-truth smoke suite: **{s.get('n_pass')}/"
            f"{s.get('n_total')}** checks passed "
            f"(engine={s.get('engine')})"]


def provenance(data: dict) -> list[str]:
    rm = data.get("run_meta") or {}
    if not rm:
        return ["_run_meta unavailable (no crawl yet)._"]
    keys = ["source", "engine", "browser_version", "foxhound_build_id",
            "playwright_version", "python_version", "platform",
            "user_agent", "captured_at"]
    return [f"- **{k}**: `{rm[k]}`" for k in keys if k in rm]


def limitations() -> list[str]:
    return [
        "- **Automation fingerprint.** Sites may serve different content "
        "to Playwright-driven browsers (bot detection); headless-vs-"
        "headed effects are not quantified.",
        "- **Single vantage point.** All measurements ran from one host/"
        "region; regional (GDPR vs non-GDPR) comparisons require "
        "repeat runs from tagged vantage points.",
        "- **HttpOnly cookies are invisible** to in-page capture "
        "(document.cookie) — cookie-side numbers are lower bounds.",
        "- **IDB is a taint blackout** in Foxhound (reads are not taint "
        "sources); IDB→network provenance therefore comes from the "
        "in-page hook layer, whose matching is substring-based unless "
        "the transform matcher corroborates it.",
        "- **Real-site precision is pending human labels.** Automatic "
        "ground truth covers the testbed only; real-site flows are "
        "exported via `testbed/export_labeling.py` for two-annotator "
        "scoring (`testbed/score_labels.py`, Cohen's κ).",
        "- **Docker images were not build-verified on the authoring "
        "host** (no docker-group access); Dockerfiles carry fixes "
        "(sys.path, PRIVADB_HOST, pinned requirements) but need a "
        "`docker build` run by a privileged user.",
        "- **License.** The repository is currently proprietary; an "
        "open license for the paper artifact is an owner decision and "
        "has NOT been changed by this work.",
    ]


def build() -> str:
    data = collect()
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    out = [
        "# PrivaDB — Measurement Report (generated)",
        "",
        f"Generated: `{now}` · generator: "
        f"`Web/src/engine/paper_report.py`",
        "",
        "Every figure below is read from the JSON artifacts produced by "
        "the testbed suites and detector runs; the source file is named "
        "in each section.",
        "",
        "## 0. Provenance (run_meta)",
        "",
        "*Source: newest crawl's `run_meta`*",
        "",
        *provenance(data),
        "",
        "## 1. Headline metrics (site-level)",
        "",
        "*Source: `results/<engine>/analysis/summary.json`*",
        "",
        *headline_metrics(data),
        "",
        "## 2. Method comparison — the core contribution",
        "",
        "*Source: `testbed/evaluate_report.json`*",
        "",
        *method_comparison(data),
        "",
        "## 3. Consent state (tracking without consent)",
        "",
        "*Source: `testbed/consent_report.json`*",
        "",
        *consent_section(data),
        "",
        "## 4. Storage comparison (IDB vs everything else)",
        "",
        "*Source: `testbed/storage_report.json`*",
        "",
        *storage_section(data),
        "",
        "## 5. Cross-site storage partitioning (per engine)",
        "",
        "*Source: `testbed/partition_report_<engine>.json`*",
        "",
        *partition_section(data),
        "",
        "## 6. Scale readiness",
        "",
        "*Source: `testbed/scale_report.json`*",
        "",
        *scale_section(data),
        "",
        "## 7. Ground-truth suite status",
        "",
        "*Source: `testbed/smoke_report.json`*",
        "",
        *smoke_section(data),
        "",
        "## 8. Limitations",
        "",
        *limitations(),
        "",
        "## 9. Reproducing",
        "",
        "```bash",
        "cd Web/src/engine",
        "python testbed/run_smoke.py --engine foxhound",
        "python testbed/run_consent.py --engine foxhound",
        "python testbed/run_storage.py --engine chrome --headless",
        "python testbed/run_partition.py --engine chrome --headless",
        "python testbed/run_scale.py --engine chrome --headed",
        "python testbed/evaluate.py --engine foxhound",
        "python paper_report.py --out ../../PAPER_REPORT.md",
        "```",
        "",
    ]
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=os.path.abspath(os.path.join(
        ENGINE_DIR, "..", "..", "..", "PAPER_REPORT.md")))
    args = ap.parse_args()
    text = build()
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(text)
    print(f"report → {args.out} ({len(text)} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
