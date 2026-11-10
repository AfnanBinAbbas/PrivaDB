"""
Phase 12 tests — GRC check engine + standards-compliant HTML reports.
No network: checks are fed synthetic evidence; renderers are pure.
"""
import os
import sys

_BACKEND = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
_ENGINE = os.path.abspath(os.path.join(_BACKEND, "..", "src", "engine"))
for p in (_BACKEND, _ENGINE):
    if p not in sys.path:
        sys.path.insert(0, p)

RAW_SECRET = "rawsecret-0123456789abcdef0123456789abcdef"


def _analysis_with_findings():
    """Synthetic analysis exercising every FAIL-capable check."""
    return {
        "domain": "shop.example",
        "url": "https://shop.example/",
        "indexeddb_summary": {"database_count": 2, "total_records": 9},
        "exfiltration_summary": {"total": 2, "high_confidence": 1,
                                 "medium_confidence": 1, "low_confidence": 0},
        "exfiltration_events": [
            {"identifier_value": RAW_SECRET,
             "request_url": "http://tracker.example.net/collect?d="
                            + RAW_SECRET,
             "request_domain": "tracker.example.net",
             "mechanism": "substring", "match_location": "url",
             "confidence": "HIGH", "is_third_party": True,
             "is_known_tracker": True,
             "tracker_entity": {"company": "Klaviyo",
                                "category": "Advertising"},
             "cname_cloaked": False, "cross_origin": "cross_site",
             "confinement": "external"},
            {"identifier_value": RAW_SECRET,
             "request_url": "https://shop.example/api/echo",
             "request_domain": "shop.example",
             "mechanism": "transform", "match_location": "post_body",
             "confidence": "LOW", "is_third_party": False,
             "is_known_tracker": False, "tracker_entity": None,
             "cname_cloaked": True, "cname_target": "safe.shop.example",
             "cross_origin": "same_site", "confinement": "internal"},
        ],
        "taint_flows": [],
        "idb_hook_flows": [{
            "idb_value": RAW_SECRET, "sink": "fetch.url",
            "target": "https://tracker.example.net/fetch?u=" + RAW_SECRET,
            "source_store": "ids", "source_function": "sendUid",
            "sink_function": "window.fetch",
            "confidence": "HIGH", "is_third_party": True,
            "is_known_tracker": True,
            "tracker_entity": {"company": "Klaviyo",
                               "category": "Advertising"}}],
        "inflow_flows": [{
            "flow_direction": "inflow", "source_class": "network_response",
            "sink_class": "IDBObjectStore.put",
            "value": RAW_SECRET,
            "response_url": "https://api.shop.example/session?sid="
                            + RAW_SECRET,
            "database": "shop_db", "store": "session", "record_key": "s1",
            "mechanism": "response_match", "confidence": "MEDIUM",
            "is_third_party": False, "is_known_tracker": False,
            "confinement": "internal", "cross_origin": "same_site"}],
        "dynamic_flows": {"total": 0},
        "consent_analysis": {
            "headline": {
                "writes_before_consent": 3, "writes_after_reject": 2,
                "banner_detected": True, "banner_failures": [],
                "third_party_exfils": {"accept": 1, "none": 0, "reject": 1},
                "tracking_without_consent": True,
            },
            "conditions": {
                "none": {"writes": 3, "pre_click_writes": 3,
                         "states": ["pre_consent"],
                         "third_party_exfils": 0},
                "accept": {"writes": 2, "pre_click_writes": 1,
                           "states": ["accepted"],
                           "third_party_exfils": 1},
                "reject": {"writes": 2, "pre_click_writes": 1,
                           "states": ["rejected"],
                           "third_party_exfils": 1},
            },
        },
        "storage_analysis": {
            "comparison": {
                "indexeddb": {"identifiers": 4, "exfil_events": 2,
                              "third_party_exfils": 1},
                "localStorage": {"identifiers": 1, "exfil_events": 0,
                                 "third_party_exfils": 0}},
            "storage_exfiltrations": [],
            "respawn_candidates": [
                {"value_hash": "deadbeef", "stores": ["indexeddb",
                                                      "cookies"],
                 "cookie_names": ["session_resurrected"]}],
            "captured": {"localStorage": 1, "cookies": 1},
        },
        "write_attribution": {"write_count": 5,
                              "writer_stats": {"first_party": 3,
                                               "third_party": 2,
                                               "unknown": 0},
                              "pre_consent_candidates": 3,
                              "response_count": 4},
    }


def _policy_gap_info():
    return {
        "policy_url": "https://shop.example/privacy",
        "text_words": 400,
        "disclosures": {
            "storage": [{"tech": "cookies", "term": "cookie",
                         "evidence": "we use cookies"}],
            "third_parties": [{"name": "Cloudflare", "how": "lexicon"}],
            "purposes": [{"purpose": "essential", "evidence": "essential"}],
            "cookies_disclosed": True,
        },
        "gap": {"undisclosed_recipients": [
            {"company": "Klaviyo", "category": "Advertising"}],
            "storage": {"indexeddb_disclosed": False},
            "gap_found": True},
    }


def test_grc_fail_paths_and_risk_score():
    from grc import run_grc_checks
    analysis = _analysis_with_findings()
    headers = {"final_url": "https://shop.example/",
               "status": 200,
               "headers": {"strict-transport-security": "max-age=1",
                           "content-security-policy": "default-src 'self'",
                           "x-content-type-options": "nosniff",
                           "referrer-policy": "no-referrer",
                           "permissions-policy": "camera=()",
                           "set-cookie": "sid=abc; Path=/; Secure; "
                                         "HttpOnly; SameSite=Lax"}}
    grc = run_grc_checks(analysis, "https://shop.example/",
                         policy_info=_policy_gap_info(),
                         header_info=headers)
    by_id = {c["id"]: c for c in grc["checks"]}

    # header checks → all PASS with the hardened fixture
    assert by_id["GRC-01"]["status"] == "PASS"
    assert by_id["GRC-02"]["status"] == "PASS"
    assert by_id["GRC-03"]["status"] == "PASS"
    # consent evidence → FAILs (pre-consent + post-reject tracking)
    assert by_id["GRC-04"]["status"] in ("PASS", "WARN")
    assert by_id["GRC-05"]["status"] == "FAIL"
    assert by_id["GRC-06"]["status"] == "FAIL"
    # measured third-party transmission → FAIL with entity evidence
    assert by_id["GRC-07"]["status"] == "FAIL"
    assert "Klaviyo" in by_id["GRC-07"]["evidence"]
    # undisclosed recipient → FAIL; IndexedDB undisclosed → FAIL
    assert by_id["GRC-08"]["status"] == "FAIL"
    assert by_id["GRC-09"]["status"] == "FAIL"
    # respawn → FAIL; cloaking → FAIL; cleartext → FAIL
    assert by_id["GRC-10"]["status"] == "FAIL"
    assert by_id["GRC-11"]["status"] == "FAIL"
    assert by_id["GRC-12"]["status"] == "FAIL"
    assert by_id["GRC-13"]["status"] == "PASS"

    s = grc["summary"]
    assert s["fail"] >= 6
    assert 40 <= s["risk_score"] <= 100, s
    # every check carries framework mappings
    assert all(c["frameworks"] for c in grc["checks"])
    assert grc["frameworks"]["GDPR"]["fail"] >= 5
    assert grc["frameworks"]["ePrivacy"]["fail"] >= 1
    # disclaimer present
    assert "legal certification" in grc["disclaimer"].lower()
    print("test_grc_fail_paths_and_risk_score OK")


def test_grc_na_and_clean_paths():
    from grc import run_grc_checks
    # no analysis + no extras → everything N/A; only GRC-13 can WARN
    # (policy not fetched), giving a tiny risk score
    grc = run_grc_checks(None, "https://clean.example/",
                         policy_info=None, header_info=None)
    assert grc["summary"]["fail"] == 0
    assert grc["summary"]["risk_score"] <= 5, grc["summary"]
    assert grc["summary"]["na"] >= 10

    # clean analysis (no third-party, no respawn, no consent issues
    # recorded because consent study exists and is clean)
    clean = {
        "domain": "clean.example", "url": "https://clean.example/",
        "indexeddb_summary": {"database_count": 1, "total_records": 2},
        "exfiltration_events": [], "taint_flows": [],
        "idb_hook_flows": [], "inflow_flows": [],
        "dynamic_flows": {"total": 0},
        "consent_analysis": {
            "headline": {"writes_before_consent": 0,
                         "writes_after_reject": 0,
                         "banner_detected": True, "banner_failures": [],
                         "third_party_exfils": {"accept": 0, "none": 0,
                                                "reject": 0},
                         "tracking_without_consent": False},
            "conditions": {"none": {"writes": 0, "pre_click_writes": 0,
                                    "states": ["pre_consent"],
                                    "third_party_exfils": 0},
                           "accept": {"writes": 0, "pre_click_writes": 0,
                                      "states": ["accepted"],
                                      "third_party_exfils": 0},
                           "reject": {"writes": 0, "pre_click_writes": 0,
                                      "states": ["rejected"],
                                      "third_party_exfils": 0}}},
        "storage_analysis": {"comparison": {}, "storage_exfiltrations": [],
                             "respawn_candidates": [],
                             "captured": {}},
        "write_attribution": {"write_count": 0,
                              "writer_stats": {"first_party": 0,
                                               "third_party": 0,
                                               "unknown": 0},
                              "pre_consent_candidates": 0,
                              "response_count": 0},
    }
    headers = {"final_url": "https://clean.example/", "status": 200,
               "headers": {"strict-transport-security": "x",
                           "content-security-policy": "x",
                           "x-content-type-options": "nosniff",
                           "referrer-policy": "no-referrer",
                           "permissions-policy": "x",
                           "set-cookie": "a=b; Secure; HttpOnly; "
                                         "SameSite=Strict"}}
    grc2 = run_grc_checks(clean, "https://clean.example/",
                          policy_info=None, header_info=headers)
    by_id = {c["id"]: c for c in grc2["checks"]}
    assert by_id["GRC-05"]["status"] == "PASS"
    assert by_id["GRC-06"]["status"] == "PASS"
    assert by_id["GRC-07"]["status"] == "PASS"
    assert by_id["GRC-10"]["status"] == "PASS"
    # no measured flows → nothing to check over TLS (N/A by design)
    assert by_id["GRC-12"]["status"] == "N/A"
    assert grc2["summary"]["fail"] == 0
    # only the policy-not-fetched WARN contributes (≤5 risk)
    assert grc2["summary"]["risk_score"] <= 5, grc2["summary"]
    print("test_grc_na_and_clean_paths OK")


def test_single_report_html_standards():
    from grc import run_grc_checks
    from report_html import render_scan_report
    analysis = _analysis_with_findings()
    grc = run_grc_checks(analysis, "https://shop.example/",
                         policy_info=_policy_gap_info(),
                         header_info=None)
    doc = render_scan_report(
        analysis, "https://shop.example/", grc,
        run_meta={"engine": "foxhound", "browser_version": "137.0",
                  "foxhound_build_id": "20251126175156",
                  "playwright_version": "1.62.0"},
        scan_meta={"started_at": "2026-11-10T00:00:00",
                   "status": "completed"},
        sources=["results/Foxhound/crawled/shop_example.json"])

    # structural standards
    assert doc.startswith("<!DOCTYPE html>")
    assert '<html lang="en">' in doc
    assert '<meta charset="utf-8">' in doc
    assert 'name="viewport"' in doc
    assert 'name="generator"' in doc
    assert '<title>' in doc
    assert 'class="skip" href="#main"' in doc
    for landmark in ("<header", 'aria-label="Report contents"',
                     '<main id="main"', "<footer", "<section"):
        assert landmark in doc, landmark
    assert "<caption>" in doc
    assert 'scope="col"' in doc and 'scope="row"' in doc
    assert "@media print" in doc
    assert "not a legal certification" in doc
    # GRC rendered
    assert "GRC compliance screening" in doc
    assert "Framework rollup" in doc
    assert "GRC-07" in doc and "Recommendations" in doc
    assert "GDPR" in doc and "ePrivacy" in doc and "CCPA" in doc
    # evidence: RAW leaked values shown with hash + source/sink columns
    assert "sha256:" in doc
    assert RAW_SECRET in doc                      # value visible
    assert "Leaked value (+ hash)" in doc
    assert ">Source<" in doc and ">Sink<" in doc
    # source provenance rendered per mechanism
    assert "IDB " in doc and "IDB read ids" in doc
    assert "sendUid" in doc and "window.fetch" in doc     # hook src/sink fns
    assert "network https://api.shop.example/session" in doc  # inflow source
    assert "response_match" in doc                            # inflow mech
    assert "IDBObjectStore.put" in doc                        # inflow sink
    assert 'class="leak"' in doc                          # value styling
    # sensitivity marking present
    assert "raw leaked values" in doc.lower() or \
        "contains raw leaked values" in doc
    # provenance
    assert "foxhound_build_id" in doc
    assert "Limitations" in doc
    # consent + storage sections present
    assert "Consent study" in doc and "Storage comparison" in doc
    print("test_single_report_html_standards OK")


def test_bulk_report_html():
    from grc import run_grc_checks
    from report_html import render_bulk_report
    a1 = _analysis_with_findings()
    a2 = {"domain": "clean.example", "url": "https://clean.example/",
          "indexeddb_summary": {"database_count": 0, "total_records": 0},
          "exfiltration_events": [], "taint_flows": [],
          "idb_hook_flows": [], "inflow_flows": [],
          "dynamic_flows": {"total": 0}}
    sites = []
    for a in (a1, a2):
        url = a["url"]
        sites.append({"domain": a["domain"], "url": url,
                      "engine": "foxhound", "analysis": a,
                      "grc": run_grc_checks(a, url)})
    doc = render_bulk_report(sites)
    assert doc.startswith("<!DOCTYPE html>")
    assert '<html lang="en">' in doc
    assert "One row per analysed site" in doc
    assert "shop.example" in doc and "clean.example" in doc
    assert "GRC aggregates across the batch" in doc
    assert "Most frequent control failures" in doc
    assert "not a legal certification" in doc
    assert "@media print" in doc
    # bulk stays aggregates-only — raw identifiers never rendered there
    assert RAW_SECRET not in doc
    assert "aggregates only" in doc
    # no external asset references
    assert 'src="' not in doc and "<link " not in doc
    print("test_bulk_report_html OK")


def test_no_javascript_required():
    """Reports must work with JS disabled: zero <script> tags."""
    from grc import run_grc_checks
    from report_html import render_scan_report, render_bulk_report
    a = _analysis_with_findings()
    grc = run_grc_checks(a, "https://shop.example/")
    single = render_scan_report(a, "https://shop.example/", grc)
    bulk = render_bulk_report([{"domain": "x", "url": "https://x/",
                                "engine": "chrome", "analysis": a,
                                "grc": grc}])
    assert "<script" not in single
    assert "<script" not in bulk
    print("test_no_javascript_required OK")


if __name__ == "__main__":
    test_grc_fail_paths_and_risk_score()
    test_grc_na_and_clean_paths()
    test_single_report_html_standards()
    test_bulk_report_html()
    test_no_javascript_required()
    print("ALL PHASE-12 TESTS PASSED")
