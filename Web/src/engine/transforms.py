"""
Transform-aware matching (Phase 3).

Generates the encoded/hashed variants a tracker might send instead of the
raw identifier, and provides the matcher that checks every place a value
can travel (URL, decoded URL, POST bodies incl. JSON/form/multipart, all
headers, WebSocket frames).

Observed real-world transformations of stored identifiers:
    raw, url-encoded (×1/×2), base64, base64url, hex, md5, sha1, sha256,
    sha256(lowercase), JSON-escaped, truncated prefixes.

Every match records its transform_chain so reports can state how much of
the exfiltration would be invisible to plain substring matching.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import math
from typing import Optional
from urllib.parse import quote, unquote

# Maximum variants generated per identifier (bounded to keep the
# |identifiers| × |requests| × |variants| search tractable).
MAX_VARIANTS = 16

# Prefix length used for truncation detection (trackers often send the
# first 16/32 hex chars of an id).
PREFIX_LEN = 16


def _b64(data: bytes, urlsafe: bool = False) -> str:
    if urlsafe:
        return base64.urlsafe_b64encode(data).decode("ascii")
    return base64.b64encode(data).decode("ascii")


def generate_variants(value: str) -> dict[str, list[str]]:
    """
    Returns {variant_string: transform_chain} — chain is the ordered list
    of transforms applied to reach the variant (['raw'] for the original).
    """
    if not isinstance(value, str) or not value:
        return {}

    variants: dict[str, list[str]] = {}

    def add(v: str, chain: list[str]):
        if not v or v in variants:
            return
        if len(variants) >= MAX_VARIANTS:
            return
        variants[v] = chain

    raw_bytes = value.encode("utf-8", "ignore")

    # raw
    add(value, ["raw"])

    # URL encoding (single, double)
    once = quote(value, safe="")
    add(once, ["urlencode"])
    twice = quote(once, safe="")
    add(twice, ["urlencode", "urlencode"])

    # JSON-escaped (only meaningful when value has JSON-special chars;
    # json.dumps also escapes non-ASCII which some payloads mirror)
    dumped = json.dumps(value)[1:-1]  # strip surrounding quotes
    if dumped != value:
        add(dumped, ["json_escape"])

    # base64 / base64url (with and without padding stripped)
    b64 = _b64(raw_bytes)
    add(b64, ["base64"])
    add(b64.rstrip("="), ["base64", "strip_padding"])
    b64u = _b64(raw_bytes, urlsafe=True)
    add(b64u, ["base64url"])
    add(b64u.rstrip("="), ["base64url", "strip_padding"])

    # hex (utf-8 bytes)
    hx = binascii.hexlify(raw_bytes).decode("ascii")
    add(hx, ["hex"])

    # case variants (search engines / case-insensitive contexts)
    lower = value.lower()
    if lower != value:
        add(lower, ["lowercase"])
    upper = value.upper()
    if upper != value:
        add(upper, ["uppercase"])

    # hashes — hex digests (these are one-way: we can only match them
    # because we hash the candidate and compare, not decode)
    def add_hash(alg_name: str, data: bytes, chain: list[str]):
        h = hashlib.new(alg_name, data).hexdigest()
        add(h, chain)
        add(h.upper(), chain + ["uppercase"])

    add_hash("md5", raw_bytes, ["md5"])
    add_hash("sha1", raw_bytes, ["sha1"])
    add_hash("sha256", raw_bytes, ["sha256"])
    if lower != value:
        add_hash("sha256", lower.encode("utf-8", "ignore"), ["lowercase", "sha256"])
        add_hash("md5", lower.encode("utf-8", "ignore"), ["lowercase", "md5"])
    add_hash("sha256", quote(value, safe="").encode("utf-8", "ignore"),
             ["urlencode", "sha256"])

    return variants


def truncated_prefixes(value: str) -> dict[str, list[str]]:
    """First-N-char prefixes (common for truncated ids in short params)."""
    out = {}
    if len(value) > PREFIX_LEN:
        out[value[:PREFIX_LEN]] = ["truncate16"]
    if len(value) > 32 and len(value) % 2 == 0:
        out[value[:32]] = ["truncate32"]
    return out


# ─── Request-side extraction ────────────────────────────────────────

def _search_needles_in_text(text: str, needles: dict[str, list[str]],
                            location: str) -> list[tuple[str, str, list[str]]]:
    """Return ALL (variant, location, chain) hits for needles in text.

    Also searches the URL-decoded text once, tagged with '_decoded'.
    """
    hits: list[tuple[str, str, list[str]]] = []
    if not text:
        return hits
    for variant, chain in needles.items():
        if variant and variant in text:
            hits.append((variant, location, chain))
    # decoded pass (only if something url-encoded exists)
    if not hits and any("%" in v for v in needles):
        decoded = unquote(text)
        if decoded != text:
            for variant, chain in needles.items():
                if variant and variant in decoded:
                    hits.append((variant, location + "_decoded", chain))
    return hits


def _json_leaf_strings(obj, out: list[str], depth: int = 0):
    if depth > 6 or len(out) > 500:
        return
    if isinstance(obj, str):
        out.append(obj)
    elif isinstance(obj, (int, float)) and not isinstance(obj, bool):
        out.append(str(obj))
    elif isinstance(obj, dict):
        for v in obj.values():
            _json_leaf_strings(v, out, depth + 1)
    elif isinstance(obj, list):
        for v in obj:
            _json_leaf_strings(v, out, depth + 1)


def search_request(request: dict,
                   needles: dict[str, list[str]]) -> Optional[dict]:
    """
    Search every place a value can travel in one captured request.

    needles: {variant: transform_chain}
    Returns dict {location, variant, transform_chain, all_hits} or None.
    all_hits = every (variant, location, chain) match found, so a single
    request carrying both md5(uid) and base64(uid) reports both chains.
    """
    all_hits: list[dict] = []
    url = request.get("url") or ""

    def collect(text, location):
        for variant, loc, chain in _search_needles_in_text(text, needles,
                                                           location):
            all_hits.append({"location": loc, "variant": variant,
                             "transform_chain": chain})

    collect(url, "url")

    # POST/PUT body
    post_data = request.get("post_data")
    if post_data and isinstance(post_data, str):
        collect(post_data, "post_body")
        stripped = post_data.lstrip()
        if stripped.startswith("{"):
            try:
                leaves: list[str] = []
                _json_leaf_strings(json.loads(post_data), leaves)
                for leaf in leaves:
                    collect(leaf, "post_json")
            except Exception:
                pass
        # form-encoded: split on & so each value is isolated
        if "=" in post_data and not stripped.startswith("{"):
            for part in post_data.replace("&", "\n").split("\n"):
                val = part.split("=", 1)[-1] if "=" in part else part
                collect(val, "post_form")

    # ALL headers (previously only 4 were checked)
    headers = request.get("headers") or {}
    for name, hval in headers.items():
        if isinstance(hval, str):
            collect(hval, f"header:{name}")

    # WebSocket frames (captured separately by the crawler)
    for frame in request.get("ws_frames") or []:
        payload = frame.get("payload") or ""
        direction = frame.get("direction", "send")
        collect(payload, f"ws_{direction}")

    if not all_hits:
        return None

    # Dedupe hits by (variant, location)
    seen_keys = set()
    uniq = []
    for h in all_hits:
        k = (h["variant"], h["location"])
        if k in seen_keys:
            continue
        seen_keys.add(k)
        uniq.append(h)

    primary = uniq[0]
    return {
        "location": primary["location"],
        "variant": primary["variant"],
        "transform_chain": primary["transform_chain"],
        "all_hits": uniq,
    }


def score_identifier(value: str, key_name: str = "",
                     entropy: float = -1.0,
                     changed_across_iterations: bool = False,
                     reasons: str = "") -> dict:
    """
    Scored identifier model (Phase 3): replaces 'length ≥ 8' as the
    decision rule with a weighted score. Signals:

      - entropy (Shannon bits/char, normalized to [0,1] at 6.0)
      - key-name patterns (uid/device/visitor/fp/… in the storage key)
      - pattern shape (uuid/hex/base64 from the extractor's reason)
      - persistence/drift across crawl iterations

    Returns {score, signals: {...}} in [0, 1].
    """
    signals = {}

    # entropy signal: 0 at ≤2.0 bits, 1 at ≥5.0 bits
    if entropy < 0:
        entropy = _shannon(value)
    signals["entropy"] = max(0.0, min(1.0, (entropy - 2.0) / 3.0))

    # key-name signal
    key_l = (key_name or "").lower()
    key_patterns = {
        "strong": ["uid", "uuid", "device", "visitor", "fingerprint", "fp_",
                   "_fp", "clientid", "client_id", "anonymous", "sessionid",
                   "session_id", "tracker", "did", "machineid"],
        "weak": ["id", "user", "token", "key", "hash", "guid", "distinct", "eid"],
    }
    if any(p in key_l for p in key_patterns["strong"]):
        signals["key_name"] = 1.0
    elif any(p in key_l for p in key_patterns["weak"]):
        signals["key_name"] = 0.6
    else:
        signals["key_name"] = 0.0

    # shape signal from extractor reason
    shape = {"uuid_v4": 1.0, "hex_string": 0.9, "base64_blob": 0.8,
             "high_entropy": 0.7, "tracking_key_name": 0.6}
    signals["shape"] = shape.get(reasons, 0.3 if reasons.startswith("idb_key")
                                 else 0.2)

    # persistence/drift: changed across visits is a strong tracking signal
    signals["persistence"] = 0.8 if changed_across_iterations else (
        0.5 if entropy >= config_entropy_threshold() else 0.2)

    score = (0.35 * signals["entropy"]
             + 0.25 * signals["key_name"]
             + 0.25 * signals["shape"]
             + 0.15 * signals["persistence"])
    return {"score": round(score, 4), "signals": signals}


def _shannon(s: str) -> float:
    if not s:
        return 0.0
    probs = [float(s.count(c)) / len(s) for c in dict.fromkeys(s)]
    return -sum(p * math.log(p, 2.0) for p in probs)


def config_entropy_threshold() -> float:
    # local import to avoid circulars at module load
    try:
        from app_config import ENTROPY_THRESHOLD
        return ENTROPY_THRESHOLD
    except Exception:
        return 3.0
