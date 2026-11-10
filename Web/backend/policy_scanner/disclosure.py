"""
Disclosure extraction (Phase 9): WHAT does the privacy policy actually
say it stores and shares — structured and evaluable, replacing pure
keyword-presence scoring.

Outputs:
    {
      "storage":     [{"tech": "indexeddb", "evidence": "..."} …],
      "third_parties": [{"name": "Klaviyo", "how": "name|domain", …}],
      "purposes":    [{"purpose": "advertising", "evidence": …} …],
      "cookies_disclosed": bool,
      "excerpt_count": int,
      "policy_words": int,
    }

Lexicons:
    storage techs     — fixed term list with variants
    third parties     — Disconnect company names + domains (shared with
                        the behavior side, so both ends of the gap
                        comparison use the SAME entity vocabulary) plus
                        a small cloud/processor supplement
    purposes          — GDPR/CCPA-style purpose categories

Snapshots: save_snapshot() stores {url, fetched_at, sha256, text} so
every gap finding is reproducible against the exact policy wording.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import logging
import os
import re
from typing import Optional

logger = logging.getLogger(__name__)

_ENGINE_DATA = os.path.abspath(os.path.join(
    os.path.dirname(__file__), "..", "..", "src", "engine", "data"))
SNAPSHOT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "snapshots")

# ─── Storage technologies ───────────────────────────────────────────
STORAGE_TERMS = {
    "cookies": ["cookie"],
    "indexeddb": ["indexeddb", "indexed db", "indexed database"],
    "localstorage": ["localstorage", "local storage", "web storage"],
    "sessionstorage": ["sessionstorage", "session storage"],
    "cache_storage": ["cache storage", "caches api", "cache api"],
    "service_workers": ["service worker"],
    "pixels": ["web beacon", "web beacon", "pixel", "tracking pixel",
               "clear gif"],
    "device_ids": ["device identifier", "device id", "advertising id",
                   "identifier for advertisers", "ifa", "idfa", "gaid"],
    "fingerprints": ["fingerprint", "browser fingerprint",
                     "device fingerprint"],
    "ip_address": ["ip address"],
    "headers": ["http header"],
}

# ─── Purpose categories ─────────────────────────────────────────────
PURPOSE_TERMS = {
    "advertising": ["advertising", "advertise", "ad personalisation",
                    "ad personalization", "targeted ad", "our advertising",
                    "marketing partners"],
    "analytics": ["analytics", "analyse usage", "analyze usage",
                  "statistics", "measure performance", "audience measure"],
    "personalization": ["personalis", "personaliz", "customise content",
                        "customize content", "recommend"],
    "security": ["security", "fraud", "abuse prevention", "bot "],
    "essential": ["essential", "strictly necessary", "operation of the",
                  "core service"],
    "email_marketing": ["email market", "newsletter", "marketing email",
                        "promotional"],
    "social_media": ["social media", "social network"],
}

# ─── Supplemental processors (not always in Disconnect) ─────────────
SUPPLEMENTAL_VENDORS = [
    "Amazon Web Services", "AWS", "Google Cloud", "Microsoft Azure",
    "Azure", "Cloudflare", "Fastly", "Akamai", "Stripe", "PayPal",
    "Zendesk", "Intercom", "Freshdesk", "Mailchimp", "SendGrid",
    "Twilio", "Segment", "Amplitude", "Mixpanel", "Hotjar",
    "FullStory", "Sentry", "Datadog", "New Relic", "Vercel", "Netlify",
    "GitHub", "Braze", "Iterable", "Customer.io", "Optimizely",
    "Contentful", "Algolia", "Elastic", "Snowflake", "HubSpot",
    "Salesforce", "Shopify", "WooCommerce", "Atlassian",
]

_lexicon_cache: dict = {}


def _vendor_lexicon() -> dict:
    """{lower_name: canonical_name} from Disconnect companies + supplement."""
    if _lexicon_cache:
        return _lexicon_cache
    names: dict[str, str] = {}
    # Disconnect list: data/disconnect_services.json (engine data dir)
    path = os.path.join(_ENGINE_DATA, "disconnect_services.json")
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        for companies in (data.get("categories") or {}).values():
            entries = companies if isinstance(companies, list) else []
            for entry in entries:
                if isinstance(entry, dict):
                    for company in entry:
                        names.setdefault(str(company).lower(),
                                         str(company))
    except Exception as e:
        logger.warning(f"Disconnect lexicon unavailable for disclosure "
                       f"extraction: {e}")
    for v in SUPPLEMENTAL_VENDORS:
        names.setdefault(v.lower(), v)
    _lexicon_cache.update(names)
    return _lexicon_cache


def _evidence(text: str, match: re.Match, width: int = 70) -> str:
    s = max(0, match.start() - width)
    e = min(len(text), match.end() + width)
    return re.sub(r"\s+", " ", text[s:e]).strip()


def extract_disclosures(text: str) -> dict:
    """Structured disclosure extraction from policy text."""
    low = (text or "").lower()
    out: dict = {
        "storage": [],
        "third_parties": [],
        "purposes": [],
        "cookies_disclosed": "cookie" in low,
        "policy_words": len((text or "").split()),
        "policy_sha256": hashlib.sha256(
            (text or "").encode("utf-8", "ignore")).hexdigest()[:16],
    }

    # storage technologies (term-level evidence)
    for tech, variants in STORAGE_TERMS.items():
        for v in variants:
            m = re.search(re.escape(v), low)
            if m:
                out["storage"].append({
                    "tech": tech, "term": v,
                    "evidence": _evidence(text or "", m)})
                break

    # purposes
    for purpose, variants in PURPOSE_TERMS.items():
        for v in variants:
            m = re.search(re.escape(v), low)
            if m:
                out["purposes"].append({
                    "purpose": purpose,
                    "evidence": _evidence(text or "", m)})
                break

    # third parties: lexicon name matches (word-ish boundaries).
    # Policies wrap names across newlines ("Amazon\nWeb Services") —
    # match against a whitespace-normalized copy.
    lex = _vendor_lexicon()
    src = text or ""
    norm = re.sub(r"\s+", " ", src)
    seen: set[str] = set()
    for lname, canonical in lex.items():
        if len(lname) < 4:      # skip 2-3 letter noise ("aws" ok len3? keep ≥4)
            continue
        pat = re.compile(r"(?<![a-z0-9])" + re.escape(lname)
                         + r"(?![a-z0-9])", re.IGNORECASE)
        m = pat.search(norm)
        if m and canonical.lower() not in seen:
            seen.add(canonical.lower())
            out["third_parties"].append({
                "name": canonical, "how": "lexicon",
                "evidence": _evidence(norm, m)})
        if len(out["third_parties"]) >= 100:
            break

    # domains mentioned directly (e.g. "klaviyo.com" in a cookie list)
    for m in re.finditer(r"\b([a-z0-9-]+(?:\.[a-z0-9-]+)+"
                         r"\.(?:com|net|org|io|co|uk|de|fr|jp|in|br))\b",
                         low):
        dom = m.group(1)
        if any(dom == t["name"].lower() for t in out["third_parties"]):
            continue
        out["third_parties"].append({"name": dom, "how": "domain"})
        if len(out["third_parties"]) >= 100:
            break

    return out


def save_snapshot(domain: str, policy_url: str, text: str,
                  disclosures: dict) -> str:
    """Persist the exact policy wording + extraction for reproducibility."""
    os.makedirs(SNAPSHOT_DIR, exist_ok=True)
    safe = re.sub(r"[^a-zA-Z0-9._-]", "_", domain)[:80]
    rec = {
        "domain": domain,
        "policy_url": policy_url,
        "fetched_at": datetime.datetime.now(datetime.timezone.utc)
                      .isoformat(),
        "sha256": hashlib.sha256(
            (text or "").encode("utf-8", "ignore")).hexdigest(),
        "words": len((text or "").split()),
        "disclosures": disclosures,
        "text": (text or "")[:200_000],
    }
    path = os.path.join(SNAPSHOT_DIR, f"{safe}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(rec, f, indent=1, ensure_ascii=False)
    logger.info(f"policy snapshot → {path}")
    return path


def load_snapshot(domain: str) -> Optional[dict]:
    safe = re.sub(r"[^a-zA-Z0-9._-]", "_", domain)[:80]
    path = os.path.join(SNAPSHOT_DIR, f"{safe}.json")
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None
