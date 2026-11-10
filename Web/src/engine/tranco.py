"""
Tranco ranked-list loading and sampling (Phase 8).

Supports:
    - the vendored data/tranco_top1000.csv (offline reproducibility)
    - local rank,domain CSV files
    - plain domain lists (one per line)
    - downloading the current Tranco top-1m zip (follows redirects)

Usage:
    python tranco.py --sample 100            # print 100 domains
    python tranco.py --download --sample 5000 --out data/tranco_5000.csv
"""

from __future__ import annotations

import argparse
import csv
import io
import os
import sys
import zipfile
from typing import Optional
from urllib.request import Request, urlopen

_DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
VENDORED_TOP = os.path.join(_DATA_DIR, "tranco_top1000.csv")
TRANCO_ZIP_URL = "https://tranco-list.eu/top-1m.csv.zip"

USER_AGENT = "PrivaDB-research/1.0 (measurement study; local tool)"


def parse_list(text: str) -> list[tuple[int, str]]:
    """Parse rank,domain CSV or plain domain list → [(rank, domain)]."""
    out: list[tuple[int, str]] = []
    for i, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        if "," in line:
            rank_s, _, dom = line.partition(",")
            rank = int(rank_s) if rank_s.isdigit() else i
            dom = dom.strip().lower()
        else:
            rank, dom = i, line.lower()
        if dom and "." in dom:
            out.append((rank, dom))
    return out


def load_list(path: Optional[str] = None,
              sample: Optional[int] = None) -> list[tuple[int, str]]:
    """
    Load a ranked list. path None → vendored top-1000. A .zip path is
    the Tranco download format (first CSV entry). Returns [(rank, dom)].
    """
    src = path or VENDORED_TOP
    if not os.path.exists(src):
        raise FileNotFoundError(src)
    if src.endswith(".zip"):
        with zipfile.ZipFile(src) as z:
            name = z.namelist()[0]
            text = z.read(name).decode("utf-8", "ignore")
    else:
        with open(src, encoding="utf-8", errors="ignore") as f:
            text = f.read()
    rows = parse_list(text)
    if sample:
        rows = rows[:sample]
    return rows


def download(dest: Optional[str] = None,
             timeout: float = 30.0) -> str:
    """Download the current Tranco top-1m zip to dest (follows 3xx)."""
    dest = dest or os.path.join(_DATA_DIR, "tranco_top1m.zip")
    req = Request(TRANCO_ZIP_URL, headers={"User-Agent": USER_AGENT})
    with urlopen(req, timeout=timeout) as resp:
        data = resp.read()
    if not data[:2] == b"PK":
        raise ValueError("download is not a zip (got %r…)" % data[:20])
    with open(dest, "wb") as f:
        f.write(data)
    return dest


def sample_domains(limit: int, path: Optional[str] = None) -> list[str]:
    return [d for _r, d in load_list(path, sample=limit)]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--list", default=None,
                    help="ranked list file (.csv/.zip/plain); "
                         "default = vendored top-1000")
    ap.add_argument("--sample", type=int, default=None)
    ap.add_argument("--download", action="store_true",
                    help="fetch current Tranco top-1m first")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    src = args.list
    if args.download:
        src = download()
        print(f"downloaded → {src}")
    rows = load_list(src, sample=args.sample)
    if args.out:
        with open(args.out, "w", newline="") as f:
            w = csv.writer(f)
            for rank, dom in rows:
                w.writerow([rank, dom])
        print(f"wrote {len(rows)} domains → {args.out}")
    else:
        for rank, dom in rows:
            print(f"{rank},{dom}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
