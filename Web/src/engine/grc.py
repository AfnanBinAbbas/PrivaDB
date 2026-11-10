"""
GRC compliance checks (Phase 12) — evidence-driven screening of a
scan target against GDPR, ePrivacy, CCPA and ISO/IEC 27001:2022.

Every check is computed from MEASUREMENT artifacts (detector analysis,
consent study, policy disclosures, live response headers) — never from
self-declared text alone. Statuses:

    PASS  evidence satisfies the control
    FAIL  evidence contradicts the control        → counts to risk score
    WARN  partial / needs human review            → counts at half weight
    N/A   evidence unavailable (e.g. no consent study, no policy fetch)
    INFO  contextual observation (no pass/fail)

Severity weights for risk_score (0–100, higher = worse):
    high=10, medium=6, low=3 (WARN halves), capped at 100.

DISCLAIMER carried into every report: this is an indicative technical
screening, not a legal certification or DPO opinion.
"""

from __future__ import annotations

import logging
import os
import re
import sys
from typing import Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

ENGINE_DIR = os.path.dirname(os.path.abspath(__file__))
_BACKEND_DIR = os.path.abspath(os.path.join(ENGINE_DIR, "..", "..",
                                            "backend"))
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)

GENERATOR = "PrivaDB grc.py"
GRC_VERSION = "1.0"

# framework → clause label used in rollups
FRAMEWORKS = ("GDPR", "ePrivacy", "CCPA", "ISO27001")

SEVERITY_WEIGHT = {"high": 10, "medium": 6, "low": 3}

# check_id → [(framework, clause), …]
FRAMEWORK_MAP: dict[str, list[tuple[str, str]]] = {
    "GRC-01": [("GDPR", "Art. 32 — security of processing"),
               ("ISO27001", "A.8.24 — use of cryptography")],
    "GRC-02": [("GDPR", "Art. 32 — security of processing"),
               ("ISO27001", "A.8.9 — configuration management")],
    "GRC-03": [("ePrivacy", "Art. 5(3) — storage/access equipment"),
               ("GDPR", "Art. 32 — security of processing"),
               ("ISO27001", "A.8.24 — use of cryptography")],
    "GRC-04": [("ePrivacy", "Art. 5(3) — consent for storage/access"),
               ("GDPR", "Art. 7 — conditions for consent")],
    "GRC-05": [("ePrivacy", "Art. 5(3) — prior consent"),
               ("GDPR", "Art. 6(1)(a) — lawfulness of processing")],
    "GRC-06": [("ePrivacy", "Art. 5(3) — respect of refusal"),
               ("GDPR", "Art. 7(1) — demonstrable consent")],
    "GRC-07": [("GDPR", "Art. 5(1)(f) — integrity and confidentiality"),
               ("GDPR", "Art. 28 — processors / contracts"),
               ("CCPA", "§1798.120 — sale/share of personal info")],
    "GRC-08": [("GDPR", "Art. 13 — information provided"),
               ("CCPA", "§1798.100 — notice at collection")],
    "GRC-09": [("GDPR", "Art. 13 — information provided")],
    "GRC-10": [("GDPR", "Art. 5(1)(e) — storage limitation"),
               ("ISO27001", "A.8.10 — information deletion")],
    "GRC-11": [("GDPR", "Art. 5(1)(a) — fairness and transparency"),
               ("GDPR", "Art. 13 — information provided")],
    "GRC-12": [("GDPR", "Art. 32 — security of processing"),
               ("ISO27001", "A.8.24 — use of cryptography")],
    "GRC-13": [("GDPR", "Art. 13 — information provided"),
               ("CCPA", "§1798.100 — notice at collection")],
    "GRC-14": [("CCPA", "§1798.120 — sharing for cross-context ads"),
               ("GDPR", "Art. 5(1)(b) — purpose limitation")],
}


# ─── helpers ────────────────────────────────────────────────────────

def _is_public(url: str) -> bool:
    try:
        from security import is_public_url
        return is_public_url(url)
    except Exception:
        try:
            p = urlparse(url)
            return p.scheme in ("http", "https") and (
                p.hostname not in ("localhost", "127.0.0.1", "0.0.0.0"))
        except Exception:
            return False


def fetch_headers(url: str, timeout: float = 8.0) -> Optional[dict]:
    """Best-effort response headers of the target's first page.
    Returns {final_url, status, headers} or None (offline/blocked/
    unsafe target). Follows redirects; SSRF-guarded."""
    if not _is_public(url):
        return None
    try:
        import httpx
        with httpx.Client(timeout=timeout, follow_redirects=True,
                          headers={"User-Agent":
                                   "PrivaDB-research/1.0 (GRC header "
                                   "check; local tool)"},
                          verify=False) as client:
            r = client.get(url)
        return {
            "final_url": str(r.url),
            "status": r.status,
            "headers": {k.lower(): v for k, v in r.headers.items()},
        }
    except Exception as e:
        logger.info(f"header fetch skipped for {url}: {e}")
        return None


def load_policy_info(url: str) -> Optional[dict]:
    """Fetch + extract the site's privacy policy (Phase 9 stack).
    Returns {policy_url, disclosures, gap} or None."""
    if not _is_public(url):
        return None
    try:
        from policy_scanner.fetcher import PolicyFetcher
        from policy_scanner.disclosure import extract_disclosures
        from policy_scanner.gap import gap_report
        f = PolicyFetcher()
        policy_url = f.find_policy_url(url)
        if not policy_url:
            return None
        text = f.fetch_policy_text(policy_url)
        if not text:
            return None
        disc = extract_disclosures(text)
        # gap without behavior (behavior is merged by caller if present)
        return {"policy_url": policy_url, "disclosures": disc,
                "gap": None, "text_words": len(text.split())}
    except Exception as e:
        logger.info(f"policy fetch skipped for {url}: {e}")
        return None


def _mk(check_id: str, status: str, severity: str, title: str,
        evidence: str, recommendation: str,
        detail: str = "") -> dict:
    return {
        "id": check_id,
        "title": title,
        "status": status,
        "severity": severity if status in ("FAIL", "WARN") else None,
        "evidence": evidence,
        "recommendation": recommendation,
        "detail": detail,
        "frameworks": [{"framework": f, "clause": c}
                       for f, c in FRAMEWORK_MAP.get(check_id, [])],
    }


# ─── the checks ─────────────────────────────────────────────────────

def run_grc_checks(analysis: Optional[dict],
                   target_url: str,
                   policy_info: Optional[dict] = None,
                   header_info: Optional[dict] = None,
                   consent_available: bool = True) -> dict:
    """
    Compute all GRC checks from measurement evidence.

    analysis: detector output of analyze_site() (may be None for
    header-only screening); policy_info from load_policy_info();
    header_info from fetch_headers().
    """
    analysis = analysis or {}
    exfils = list(analysis.get("exfiltration_events") or [])
    storage_exfils = list(
        (analysis.get("storage_analysis") or {}).get(
            "storage_exfiltrations") or [])
    all_events = exfils + storage_exfils
    taint = analysis.get("taint_flows") or []
    hooks = analysis.get("idb_hook_flows") or []
    consent = analysis.get("consent_analysis") or {}
    headline = consent.get("headline") or {}
    storage = analysis.get("storage_analysis") or {}
    respawn = storage.get("respawn_candidates") or []
    writes = analysis.get("write_attribution") or {}
    disc = (policy_info or {}).get("disclosures")
    gap = (policy_info or {}).get("gap")

    third_party = [e for e in all_events if e.get("is_third_party")]
    cloaked = [e for e in all_events if e.get("cname_cloaked")]
    cleartext = [e for e in all_events
                 if str(e.get("request_url", "")).startswith("http://")]
    cross_site = [e for e in all_events if e.get("cross_origin")
                  == "cross_site"]
    ad_receivers = [e for e in third_party
                    if ((e.get("tracker_entity") or {}).get("category")
                        in ("Advertising", "FingerprintingInvasive",
                            "FingerprintingGeneral"))]

    checks: list[dict] = []

    # GRC-01 transport security
    hdr = (header_info or {}).get("headers") or {}
    final_url = (header_info or {}).get("final_url") or target_url
    if not header_info:
        checks.append(_mk(
            "GRC-01", "N/A", "low", "Transport security (HTTPS/HSTS)",
            "response headers unavailable (offline fetch skipped)",
            "Verify the site enforces HTTPS with HSTS before "
            "deploying."))
    else:
        https = str(final_url).startswith("https://")
        hsts = "strict-transport-security" in hdr
        ok = https and hsts
        checks.append(_mk(
            "GRC-01", "PASS" if ok else "FAIL", "high",
            "Transport security (HTTPS/HSTS)",
            f"final_url={final_url} · HSTS="
            f"{'present' if hsts else 'absent'}",
            "Enforce HTTPS redirects site-wide and send a "
            "`Strict-Transport-Security` header (≥ 15552000s).",
            detail="HSTS missing" if https and not hsts else ""))

    # GRC-02 header hardening
    if not header_info:
        checks.append(_mk(
            "GRC-02", "N/A", "medium", "Response header hardening",
            "response headers unavailable",
            "Deploy CSP, X-Content-Type-Options, Referrer-Policy and "
            "Permissions-Policy."))
    else:
        want = {
            "content-security-policy": "CSP",
            "x-content-type-options": "X-Content-Type-Options",
            "referrer-policy": "Referrer-Policy",
            "permissions-policy": "Permissions-Policy",
        }
        missing = [label for h, label in want.items() if h not in hdr]
        checks.append(_mk(
            "GRC-02", "PASS" if not missing else "FAIL", "medium",
            "Response header hardening",
            "present=" + ", ".join(sorted(set(want.values())
                                          - set(missing))) +
            (" · missing=" + ", ".join(missing) if missing else ""),
            "Add the missing security headers via your web server or "
            "CDN (CSP first — it also constrains third-party scripts)."))

    # GRC-03 cookie flags
    set_cookies = hdr.get("set-cookie", "")
    if not header_info:
        checks.append(_mk(
            "GRC-03", "N/A", "medium", "Cookie flag hygiene",
            "no response headers",
            "Set Secure; HttpOnly; SameSite on all non-essential "
            "cookies."))
    elif not set_cookies:
        checks.append(_mk(
            "GRC-03", "INFO", "low", "Cookie flag hygiene",
            "no Set-Cookie header on the landing response",
            "Re-check after a consent interaction; first-party session "
            "cookies should still carry Secure/HttpOnly/SameSite."))
    else:
        cookies = [c.strip() for c in re.split(r",(?=[^;]+=)", set_cookies)
                   if "=" in c]
        bad = []
        for c in cookies:
            low = c.lower()
            name = c.split("=", 1)[0].strip().lower()
            flags = []
            if "httponly" not in low:
                flags.append("HttpOnly")
            if "secure" not in low:
                flags.append("Secure")
            if "samesite" not in low:
                flags.append("SameSite")
            if flags:
                bad.append(f"{name}({'+'.join(flags)})")
        checks.append(_mk(
            "GRC-03", "PASS" if not bad else "FAIL", "medium",
            "Cookie flag hygiene",
            f"{len(cookies)} cookie(s) on landing response"
            + (f"; non-compliant: {', '.join(bad[:6])}" if bad else
               " — all carry Secure/HttpOnly/SameSite"),
            "Set Secure, HttpOnly and SameSite=Lax/Strict on every "
            "cookie; reserve SameSite=None for strictly necessary "
            "cross-site cases over HTTPS."))

    # GRC-04 consent banner
    if not consent:
        checks.append(_mk(
            "GRC-04", "N/A", "medium", "Consent banner present",
            "no consent study in this scan (run with consent_study=true)",
            "Run the three-condition consent study to verify banner "
            "behaviour."))
    else:
        detected = bool(headline.get("banner_detected"))
        failures = headline.get("banner_failures") or []
        status = "PASS" if detected and not failures else (
            "WARN" if detected else "FAIL")
        checks.append(_mk(
            "GRC-04", status, "medium", "Consent banner present",
            f"banner_detected={detected} · interaction failures="
            f"{failures or 'none'}",
            "Provide a reachable, functional consent mechanism before "
            "any non-essential storage or access."))

    # GRC-05 pre-consent tracking
    if not consent:
        checks.append(_mk(
            "GRC-05", "N/A", "high", "No processing before consent",
            "no consent study in this scan",
            "Run the consent study (no-interaction condition) to "
            "measure pre-consent writes."))
    else:
        pre = int(headline.get("writes_before_consent") or 0)
        checks.append(_mk(
            "GRC-05", "PASS" if pre == 0 else "FAIL", "high",
            "No processing before consent",
            f"IDB writes recorded before any consent interaction: "
            f"{pre}",
            "Defer all non-essential storage (IDB writes, trackers, "
            "pixels) until consent is granted — gate script loading, "
            "not just banner dismissal."))

    # GRC-06 tracking after reject
    if not consent:
        checks.append(_mk(
            "GRC-06", "N/A", "high", "Refusal is respected",
            "no consent study in this scan",
            "Run the consent study (reject condition) to verify."))
    else:
        post_reject = int(headline.get("writes_after_reject") or 0)
        rej_exfil = (headline.get("third_party_exfils") or {}).get(
            "reject", 0)
        ok = post_reject == 0 and rej_exfil == 0
        checks.append(_mk(
            "GRC-06", "PASS" if ok else "FAIL", "high",
            "Refusal is respected",
            f"post-reject writes={post_reject} · third-party exfils "
            f"after reject={rej_exfil}",
            "Stop all non-essential network/storage activity when the "
            "user rejects; enforce it server-side as well as in the "
            "banner."))

    # GRC-07 third-party identifier transmission
    if not analysis:
        checks.append(_mk(
            "GRC-07", "N/A", "high", "Third-party identifier flows",
            "no measurement analysis attached",
            "Run a measurement scan first."))
    elif not third_party:
        checks.append(_mk(
            "GRC-07", "PASS", "high", "Third-party identifier flows",
            "no identifier observed leaving to a third party in this "
            "scan",
            "Keep first-party-only storage; review any future vendor "
            "additions against Art. 28 contracts."))
    else:
        companies = sorted({
            (e.get("tracker_entity") or {}).get("company")
            or e.get("request_domain", "?")
            for e in third_party})
        checks.append(_mk(
            "GRC-07", "FAIL", "high", "Third-party identifier flows",
            f"{len(third_party)} flow(s) of stored identifiers to "
            f"third parties: {', '.join(companies[:8])}"
            + ("…" if len(companies) > 8 else ""),
            "Establish Art. 28 processor agreements (Art. 44 for "
            "transfers), document a DPIA, and reduce identifiers sent "
            "to the strict minimum."))

    # GRC-08 transparency: undisclosed recipients
    if policy_info is None:
        checks.append(_mk(
            "GRC-08", "N/A", "high", "Recipients disclosed in policy",
            "policy not fetched for this report",
            "Re-run with policy fetching enabled or run "
            "POST /api/v1/policy/gap."))
    elif gap is None and disc is not None and third_party:
        checks.append(_mk(
            "GRC-08", "WARN", "high", "Recipients disclosed in policy",
            f"policy names {len(disc.get('third_parties', []))} "
            f"parties; behaviour comparison not computed",
            "Compute the disclosure-vs-behaviour gap "
            "(POST /api/v1/policy/gap) and name every processor."))
    elif gap is not None and gap.get("undisclosed_recipients"):
        names = [e.get("company") for e in
                 gap["undisclosed_recipients"]]
        checks.append(_mk(
            "GRC-08", "FAIL", "high", "Recipients disclosed in policy",
            f"received but never named: {', '.join(map(str, names[:8]))}",
            "Add every recipient company (and its purpose) to the "
            "privacy policy's recipient list before further "
            "transmission."))
    elif gap is not None:
        checks.append(_mk(
            "GRC-08", "PASS", "high", "Recipients disclosed in policy",
            "every measured recipient appears in the policy",
            "Keep the recipient list in sync when adding vendors."))
    else:
        checks.append(_mk(
            "GRC-08", "N/A", "high", "Recipients disclosed in policy",
            "no policy or no measured flows to compare",
            "Fetch the policy and run a scan to enable this check."))

    # GRC-09 storage-technology disclosure (IndexedDB focus)
    if disc is None:
        checks.append(_mk(
            "GRC-09", "N/A", "medium", "Storage technologies disclosed",
            "policy not analysed",
            "Analyse the policy for storage-tech disclosures."))
    else:
        disclosed = {s["tech"] for s in disc.get("storage", [])}
        idb_used = bool(analysis) and bool(
            (analysis.get("indexeddb_summary") or {}).get(
                "database_count", 0))
        ls_used = bool((storage.get("captured") or {}).get(
            "localStorage", 0))
        undisc = []
        if idb_used and "indexeddb" not in disclosed:
            undisc.append("IndexedDB")
        if ls_used and "localstorage" not in disclosed:
            undisc.append("localStorage")
        if undisc and (idb_used or ls_used):
            checks.append(_mk(
                "GRC-09", "FAIL", "medium",
                "Storage technologies disclosed",
                f"observed storage not named in policy: "
                f"{', '.join(undisc)}",
                "Name every storage technology (IndexedDB, local "
                "storage, caches) in the privacy policy's purposes/"
                "retention section."))
        elif idb_used or ls_used:
            checks.append(_mk(
                "GRC-09", "PASS", "medium",
                "Storage technologies disclosed",
                "observed storage technologies are named in the policy",
                "Keep disclosures aligned with new storage APIs."))
        else:
            checks.append(_mk(
                "GRC-09", "INFO", "medium",
                "Storage technologies disclosed",
                "no web storage observed in this scan",
                "n/a — re-run on a deeper crawl."))

    # GRC-10 storage limitation / respawn
    if not analysis:
        checks.append(_mk(
            "GRC-10", "N/A", "medium", "Storage limitation (no respawn)",
            "no measurement analysis attached", "Run a scan first."))
    elif not respawn:
        checks.append(_mk(
            "GRC-10", "PASS", "medium", "Storage limitation (no respawn)",
            "no identifier found in both cookies and IndexedDB",
            "Continue monitoring respawn patterns after cookie "
            "clearance."))
    else:
        names = sorted({n for r in respawn
                        for n in (r.get("cookie_names") or [])})
        checks.append(_mk(
            "GRC-10", "FAIL", "medium",
            "Storage limitation (no respawn)",
            f"{len(respawn)} identifier(s) present in cookie ∩ IDB "
            f"(cookie(s): {', '.join(names) or 'n/a'}) — storage "
            f"survives cookie deletion",
            "Honour cookie-clearance by also deleting the IDB "
            "equivalent (evercookie-style respawning undermines "
            "erasure requests)."))

    # GRC-11 CNAME cloaking
    if not analysis:
        checks.append(_mk(
            "GRC-11", "N/A", "medium", "No first-party cloaking",
            "no measurement analysis attached", "Run a scan first."))
    elif not cloaked:
        checks.append(_mk(
            "GRC-11", "PASS", "medium", "No first-party cloaking",
            "no CNAME cloaking observed on measured flows",
            "Keep DNS changes reviewable; cloaked subdomains must be "
            "disclosed."))
    else:
        pairs = sorted({f"{e.get('request_domain')} → "
                        f"{e.get('cname_target')}" for e in cloaked})
        checks.append(_mk(
            "GRC-11", "FAIL", "medium", "No first-party cloaking",
            f"{len(cloaked)} flow(s) via cloaked CNAMEs: "
            f"{'; '.join(pairs[:4])}",
            "Disclose CNAME-cloaked vendor endpoints or stop using "
            "them; cloaking defeats user expectations of first-party "
            "scope."))

    # GRC-12 identifier transport encryption
    if not all_events:
        checks.append(_mk(
            "GRC-12", "N/A", "high", "Identifiers sent over TLS",
            "no identifier flows measured", "Run a scan first."))
    elif not cleartext:
        checks.append(_mk(
            "GRC-12", "PASS", "high", "Identifiers sent over TLS",
            f"all {len(all_events)} measured identifier flow(s) use "
            f"https://",
            "Maintain TLS everywhere; HSTS (GRC-01) prevents downgrade."))
    else:
        hosts = sorted({urlparse(e.get("request_url", "")).netloc
                        for e in cleartext})
        checks.append(_mk(
            "GRC-12", "FAIL", "high", "Identifiers sent over TLS",
            f"{len(cleartext)} flow(s) in cleartext to: "
            f"{', '.join(hosts[:6])}",
            "Redirect all identifier-bearing requests to HTTPS and "
            "re-issue any tokens that crossed the wire in cleartext."))

    # GRC-13 privacy policy availability
    if policy_info is None:
        checks.append(_mk(
            "GRC-13", "WARN", "low", "Privacy policy available",
            "policy not fetched (or not found) for this report",
            "Publish a reachable privacy policy at /privacy and "
            "re-run the report."))
    else:
        checks.append(_mk(
            "GRC-13", "PASS", "low", "Privacy policy available",
            f"policy at {policy_info.get('policy_url')} "
            f"({policy_info.get('text_words', '?')} words)",
            "Keep the policy dated and version-controlled."))

    # GRC-14 cross-site sharing context (INFO)
    if not analysis:
        checks.append(_mk(
            "GRC-14", "N/A", "low",
            "Cross-context sharing review", "no analysis attached",
            "Run a scan first."))
    elif not cross_site:
        checks.append(_mk(
            "GRC-14", "INFO", "low", "Cross-context sharing review",
            "no cross-site identifier flows observed on this scan",
            "If cross-context sharing is added later, CCPA "
            "‘sharing’ disclosure may apply."))
    else:
        checks.append(_mk(
            "GRC-14", "INFO", "low", "Cross-context sharing review",
            f"{len(cross_site)} cross-site flow(s); "
            f"{len(ad_receivers)} to advertising-category receivers",
            "Assess whether CCPA ‘sharing for cross-context "
            "behavioral advertising’ opt-out and GDPR Art. 5(1)(b) "
            "purpose compatibility apply."))

    # ── rollups ──
    by_framework: dict[str, dict] = {f: {"pass": 0, "fail": 0,
                                         "warn": 0, "na": 0, "info": 0,
                                         "clauses": []}
                                     for f in FRAMEWORKS}
    risk = 0
    for c in checks:
        for fmap in c["frameworks"]:
            fw = fmap["framework"]
            if fw not in by_framework:
                continue
            bucket = {"PASS": "pass", "FAIL": "fail", "WARN": "warn",
                      "N/A": "na", "INFO": "info"}[c["status"]]
            by_framework[fw][bucket] += 1
            by_framework[fw]["clauses"].append(
                {"clause": fmap["clause"], "check": c["id"],
                 "status": c["status"]})
        if c["status"] in ("FAIL", "WARN"):
            w = SEVERITY_WEIGHT.get(c["severity"] or "low", 3)
            risk += w if c["status"] == "FAIL" else w / 2
    risk_score = min(100, round(risk))

    for fw, roll in by_framework.items():
        evaluated = roll["pass"] + roll["fail"] + roll["warn"]
        roll["pass_rate"] = (round(
            (roll["pass"] + 0.5 * roll["warn"]) / evaluated * 100, 1)
            if evaluated else None)
        roll.pop("clauses")  # clauses already on checks

    counts = {"pass": 0, "fail": 0, "warn": 0, "na": 0, "info": 0}
    for c in checks:
        counts[{"PASS": "pass", "FAIL": "fail", "WARN": "warn",
                "N/A": "na", "INFO": "info"}[c["status"]]] += 1

    return {
        "generator": GENERATOR,
        "version": GRC_VERSION,
        "target": target_url,
        "checks": checks,
        "summary": {**counts, "risk_score": risk_score},
        "frameworks": by_framework,
        "disclaimer": (
            "Indicative technical screening based on measured "
            "behaviour and best-effort policy/header collection. Not "
            "a legal certification, audit opinion, or DPO advice."),
        "evidence_inputs": {
            "analysis": bool(analysis),
            "consent_study": bool(consent),
            "policy": policy_info is not None,
            "response_headers": header_info is not None,
        },
    }
