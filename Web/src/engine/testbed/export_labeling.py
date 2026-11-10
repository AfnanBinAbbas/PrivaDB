#!/usr/bin/env python3
"""
Phase 7 labeling tooling — export REAL-SITE flows for manual annotation.

The testbed supplies automatic ground truth; real-site precision needs
human labels (with a second annotator on a subset for agreement).
This script exports recent detector events as JSONL, one flow per line,
ready for two independent annotators:

    {"id": "<sha1>", "site": ..., "value_hash": ..., "value_sample": ...,
     "request_url": ..., "mechanism": ..., "confidence": ...,
     "label": null, "annotator": null}

Annotator instructions (also written into the export header):
    label = "tracking"        value plausibly a tracking identifier
                               sent to a third party / tracker
    label = "benign"          functional value (CSRF, session nonce,
                               version, preference) or first-party only
    label = "unsure"          cannot tell from the flow

Scoring: score_labels.py merges two annotator files, reports Cohen's
kappa on the overlap, and precision per method:

    python testbed/export_labeling.py [--analysis-dir DIR]
    python testbed/score_labels.py a.jsonl b.jsonl
"""
import argparse
import hashlib
import json
import os
import sys

ENGINE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ENGINE_DIR)

import app_config as config  # noqa: E402


def _flow_id(site: str, value: str, url: str, mech: str) -> str:
    return hashlib.sha1(f"{site}|{value}|{url}|{mech}".encode()).hexdigest()[:16]


def export(analysis_dir: str, out_path: str) -> int:
    import re

    def irrelevant(value: str, key: str) -> bool:
        # mirror of server._is_irrelevant_value (kept local to avoid
        # importing the FastAPI app)
        v = (value or "").lower().strip()
        if v in ["undefined", "null", "[object object]", "nan", "none"]:
            return True
        if re.search(r'[a-z0-9-]+\.[a-z]{2,}', v):
            return True
        if len(v) >= 10 and v.isdigit():
            return True
        return False

    rows = []
    for fname in sorted(os.listdir(analysis_dir)):
        if not fname.endswith(".json") or fname in (
                "combined_results.json", "global_report.json",
                "summary.json", "statistics.json", "sites.json"):
            continue
        try:
            with open(os.path.join(analysis_dir, fname)) as f:
                entries = json.load(f)
        except Exception:
            continue
        site = fname.replace(".json", "").replace("_", ".")
        if not isinstance(entries, list):
            continue
        for e in entries:
            value = str(e.get("value", "") or e.get("identifier_value", ""))
            url = str(e.get("requestUrl") or e.get("request_url") or "")
            mech = str(e.get("mechanism", "unknown"))
            if not value or irrelevant(value, ""):
                continue
            rows.append({
                "id": _flow_id(site, value, url, mech),
                "site": site,
                "value_hash": hashlib.sha256(
                    value.encode()).hexdigest()[:16],
                "value_sample": value[:24] + ("…" if len(value) > 24 else ""),
                "request_url": url[:300],
                "mechanism": mech,
                "confidence": e.get("confidence", ""),
                "is_third_party": e.get("is_third_party",
                                        e.get("isThirdParty", None)),
                "label": None,
                "annotator": None,
            })

    # dedupe by flow id
    seen = set()
    uniq = []
    for r in rows:
        if r["id"] in seen:
            continue
        seen.add(r["id"])
        uniq.append(r)

    with open(out_path, "w") as f:
        for r in uniq:
            f.write(json.dumps(r) + "\n")
    return len(uniq)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--analysis-dir", default=None)
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    analysis_dir = args.analysis_dir or os.path.join(
        config.RESULTS_DIR, "analysis")
    out = args.out or os.path.join(os.path.dirname(__file__),
                                   "label_export.jsonl")
    n = export(analysis_dir, out)
    print(f"exported {n} flows → {out}")
    print("instructions: label each line 'tracking' | 'benign' | 'unsure'; "
          "copy the file once per annotator before labeling")
    return 0 if n else 1


if __name__ == "__main__":
    sys.exit(main())
