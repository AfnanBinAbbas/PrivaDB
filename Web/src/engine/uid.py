"""
Client-identifier (unique user identifier) detection per the repo's
methodology paper:

    Ahmad, Casarin, Calzavara — "Information flow control for
    comparative privacy analyses", Int. J. Information Security
    (2024) 23:3199–3216  (References/s10207-024-00886-0.pdf), §4.1.

The paper applies the Chen et al. heuristic — "originally proposed
**for cookies**" in the paper's own words — to client-side state
information (CSSI). This module adapts it to **IndexedDB only**
(this repo's scope): cookie/localStorage values appear in the storage
comparison but are NEVER labelled client identifiers here.

A CSSI (k, v) — an IndexedDB record — is a client identifier iff ALL
paper conditions hold:

  C1  the item is not deleted when the browser closes
      → inherent to IndexedDB (persistent storage): recorded True
  C2  the item persists with the SAME value when the page is RELOADED
      → verified by the crawler's reload pass (crawl result key
        "reload_check"); "unverified" when that pass is absent
  C3  len(unquoted(v)) >= 8
  C4  the same key k is set when visiting from a FRESH browser instance
      → key present in ≥2 iterations (each iteration = fresh profile)
  C5  values across fresh instances are "significantly different":
      timestamps stripped → longest common subsequence recursively
      stripped until ≤2 chars → Ratcliff–Obershelp similarity < 66%

"confirmed" requires all five literally True; "candidate" = C3+C4+C5
(C2 missing/unverified) so partially-evaluated crawls still surface
plausible identifiers without overclaiming.
"""

from __future__ import annotations

import difflib
import json
import logging
import re
from itertools import combinations
from typing import Optional
from urllib.parse import unquote

logger = logging.getLogger(__name__)

# paper: Ratcliff–Obershelp threshold 66% — below ⇒ significantly different
SIMILARITY_THRESHOLD = 0.66
MIN_LEN = 8

# value noise the paper strips before comparing
_TS_PATTERNS = [
    re.compile(r"\d{13}"),            # epoch milliseconds
    re.compile(r"\d{10}"),            # epoch seconds
    re.compile(r"\d{4}-\d{2}-\d{2}"),  # ISO date
    re.compile(r"\d{2}/\d{2}/\d{4}"),  # US date
]


def strip_timestamps(v: str) -> str:
    out = v
    for pat in _TS_PATTERNS:
        out = pat.sub("", out)
    return out


def _lcs(a: str, b: str) -> str:
    """Longest common subsequence (DP; identifier values are short).
    Falls back to difflib's longest common block above 512 chars."""
    if not a or not b:
        return ""
    if len(a) > 512 or len(b) > 512:
        m = difflib.SequenceMatcher(None, a, b).find_longest_match(
            0, len(a), 0, len(b))
        return a[m.a:m.a + m.size]
    # full matrix for exact backtracking (≤513×513 ints — fine)
    dp = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(1, len(a) + 1):
        row, prev = dp[i], dp[i - 1]
        ai = a[i - 1]
        for j in range(1, len(b) + 1):
            if ai == b[j - 1]:
                row[j] = prev[j - 1] + 1
            else:
                row[j] = row[j - 1] if row[j - 1] >= prev[j] else prev[j]
    out = []
    i, j = len(a), len(b)
    while i > 0 and j > 0:
        if a[i - 1] == b[j - 1]:
            out.append(a[i - 1])
            i -= 1
            j -= 1
        elif dp[i - 1][j] >= dp[i][j - 1]:
            i -= 1
        else:
            j -= 1
    return "".join(reversed(out))


def strip_common(a: str, b: str) -> tuple[str, str]:
    """Recursively strip the LCS from both values until ≤2 chars."""
    for _ in range(64):
        lcs = _lcs(a, b)
        if not lcs or len(lcs) <= 2:
            break
        a = a.replace(lcs, "")
        b = b.replace(lcs, "")
    return a, b


def significantly_different(v1: str, v2: str) -> tuple[bool, float]:
    """Paper C5: True when similarity of preprocessed residuals < 0.66.
    Returns (is_different, similarity_of_residuals)."""
    a = strip_timestamps(unquote(v1 or ""))
    b = strip_timestamps(unquote(v2 or ""))
    a, b = strip_common(a, b)
    if not a and not b:
        return False, 1.0
    ratio = difflib.SequenceMatcher(None, a, b).ratio()
    return ratio < SIMILARITY_THRESHOLD, round(ratio, 4)


# ─── record extraction ──────────────────────────────────────────────

def _record_map(indexeddb: Optional[dict]) -> dict[str, str]:
    """{db/store/key: canonical-string(value)} for one iteration."""
    out: dict[str, str] = {}
    for db in (indexeddb or {}).get("databases") or []:
        dbn = db.get("name", "") or ""
        for st in db.get("stores") or []:
            stn = st.get("name", "") or ""
            for rec in st.get("records") or []:
                k = str(rec.get("key", ""))
                val = rec.get("value")
                try:
                    canon = json.dumps(val, sort_keys=True, default=str) \
                        if not isinstance(val, str) else val
                except Exception:
                    canon = str(val)
                out[f"{dbn}/{stn}/{k}"] = canon
    return out


def _reload_map(iteration: dict) -> Optional[dict[str, str]]:
    """{key: value} captured after the same-session reload pass, or
    None when the crawler's reload pass did not run for this
    iteration."""
    rc = iteration.get("reload_check")
    if not isinstance(rc, dict):
        return None
    after = rc.get("after_indexeddb")
    if not isinstance(after, dict):
        return None
    return _record_map(after)


# ─── classification ─────────────────────────────────────────────────

def classify_site(iterations: list[dict],
                  min_len: int = MIN_LEN) -> dict:
    """
    Paper §4.1 client-identifier classification over one site's crawl
    iterations (each iteration must come from a FRESH browser profile).
    """
    iterations = [it for it in (iterations or [])]
    n = len(iterations)
    rec_maps = [_record_map(it.get("indexeddb")) for it in iterations]

    if n < 2:
        return {
            "evaluated": False,
            "reason": "paper C4/C5 need ≥2 fresh-profile iterations "
                      f"(got {n}) — rerun with iterations ≥2",
            "identifiers": [],
            "confirmed_count": 0,
            "candidate_count": 0,
            "scope": "indexeddb-only",
            "paper": "Ahmad et al. IJIS 2024 §4.1 (Chen et al. "
                     "heuristic adapted from cookies to IndexedDB)",
        }

    all_keys: set[str] = set()
    for m in rec_maps:
        all_keys |= set(m)

    identifiers = []
    for key in sorted(all_keys):
        present = [(i, m[key]) for i, m in enumerate(rec_maps) if key in m]
        # C4: same key set from a fresh browser instance → ≥2 visits
        c4 = len(present) >= 2
        if not c4:
            continue  # key only in one instance — static/local, not UID

        values = [v for _, v in present]
        # C3: every observed value unquoted-length ≥8
        c3 = all(len(unquote(v)) >= min_len for v in values)

        # C5: cross-instance values significantly different (ALL pairs)
        pairs = list(combinations(range(len(values)), 2))
        diffs = [significantly_different(values[i], values[j])
                 for i, j in pairs]
        c5 = bool(diffs) and all(d for d, _ in diffs)
        worst_sim = max((r for _, r in diffs), default=1.0)

        # C2: same value across a SAME-SESSION reload (crawler pass)
        # (checked against the iteration's OWN reload snapshot)
        c2: object = "unverified"
        for i_iter, v_iter in present:
            rmap = _reload_map(iterations[i_iter])
            if rmap is None:
                continue
            if key not in rmap or rmap[key] != v_iter:
                c2 = False
                break
            c2 = True

        # C1: IndexedDB is persistent storage by spec
        c1 = True

        conditions = {"c1_persistent": c1, "c2_reload_same_value": c2,
                      "c3_length": c3, "c4_fresh_key": c4,
                      "c5_values_differ": c5}
        confirmed = (c1 is True and c2 is True and c3 and c4 and c5)
        candidate = (c3 and c4 and c5)
        identifiers.append({
            "key": key,
            "values": values,
            "iterations_present": [i for i, _ in present],
            "residual_similarity": worst_sim,
            "conditions": conditions,
            "confirmed": confirmed,
            "candidate": candidate and not confirmed,
        })

    confirmed = [i for i in identifiers if i["confirmed"]]
    candidates = [i for i in identifiers if i["candidate"]]
    return {
        "evaluated": True,
        "identifiers": identifiers,
        "confirmed_count": len(confirmed),
        "candidate_count": len(candidates),
        "iterations": n,
        "reload_checked": any(
            i["conditions"]["c2_reload_same_value"] in (True, False)
            for i in identifiers),
        "scope": "indexeddb-only",
        "paper": "Ahmad et al. IJIS 2024 §4.1 (Chen et al. heuristic "
                 "adapted from cookies to IndexedDB)",
        "thresholds": {"min_length": min_len,
                       "similarity_below": SIMILARITY_THRESHOLD},
    }


def attach_to_identifiers(identifiers: list[dict],
                          report: dict) -> None:
    """Stamp every IDB identifier with its record's paper verdict.

    Identifiers whose path starts with a classified record key inherit
    that key's verdict; anything else stays unlabelled (never claimed
    as a client identifier).
    """
    verdict_by_key = {i["key"]: i for i in report.get("identifiers", [])}
    for ident in identifiers:
        path = str(ident.get("path", "") or "")
        ident["client_identifier"] = None
        ident["uid_conditions"] = None
        for key, verdict in verdict_by_key.items():
            if path == key or path.startswith(key + "."):
                ident["client_identifier"] = bool(verdict["confirmed"])
                ident["uid_candidate"] = bool(verdict["candidate"])
                ident["uid_conditions"] = verdict["conditions"]
                break
