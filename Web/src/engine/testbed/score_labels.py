#!/usr/bin/env python3
"""
Phase 7 label scoring — precision from human annotations + inter-annotator
agreement (Cohen's kappa on the shared subset).

    python testbed/score_labels.py annotator_a.jsonl annotator_b.jsonl
    python testbed/score_labels.py annotator_a.jsonl   # single annotator

Agreement is computed on flows both files label (excluding 'unsure').
Precision per mechanism: tracking-labeled flows / all labeled flows,
for each method tag (substring/transform/taint/idb_hook/…).
"""
import json
import sys
from collections import Counter


def load(path: str) -> dict:
    out = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)
            out[r["id"]] = r
    return out


def cohen_kappa(pairs: list[tuple[str, str]]) -> float:
    n = len(pairs)
    if n == 0:
        return float("nan")
    labels = sorted({a for a, _ in pairs} | {b for _, b in pairs})
    po = sum(1 for a, b in pairs if a == b) / n
    ca = Counter(a for a, _ in pairs)
    cb = Counter(b for _, b in pairs)
    pe = sum((ca[l] / n) * (cb[l] / n) for l in labels)
    if pe == 1.0:
        return 1.0
    return (po - pe) / (1 - pe)


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    a = load(sys.argv[1])
    b = load(sys.argv[2]) if len(sys.argv) > 2 else None

    def precision(rows: dict):
        per_mech = {}
        labeled = [r for r in rows.values() if r.get("label")]
        for r in labeled:
            m = r.get("mechanism") or "unknown"
            per_mech.setdefault(m, []).append(
                1 if r["label"] == "tracking" else 0)
        overall = ([1 if r["label"] == "tracking" else 0
                    for r in labeled if r["label"] != "unsure"])
        return {
            "labeled": len(labeled),
            "tracking": sum(overall),
            "benign": len(overall) - sum(overall),
            "precision": (round(sum(overall) / len(overall), 4)
                          if overall else None),
            "per_mechanism": {
                m: {"n": len(v), "tracking": sum(v),
                    "precision": round(sum(v) / len(v), 4)}
                for m, v in sorted(per_mech.items())
            },
        }

    print(f"annotator A: {sys.argv[1]}")
    print(json.dumps(precision(a), indent=2))
    if b:
        print(f"annotator B: {sys.argv[2]}")
        print(json.dumps(precision(b), indent=2))
        shared = [(a[i]["label"], b[i]["label"]) for i in a
                  if i in b and a[i].get("label") and b[i].get("label")
                  and a[i]["label"] != "unsure" and b[i]["label"] != "unsure"]
        kappa = cohen_kappa(shared)
        agree = sum(1 for x, y in shared if x == y)
        print(f"\nagreement on {len(shared)} shared non-unsure labels: "
              f"{agree}/{len(shared)} "
              f"({agree / len(shared) * 100:.1f}%)  Cohen's κ = {kappa:.3f}"
              if shared else "\nno shared labels to score")
    return 0


if __name__ == "__main__":
    sys.exit(main())
