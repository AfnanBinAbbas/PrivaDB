"""
Phase 9 tests — disclosure extraction + gap analysis (evaluable, no
network). Run:  python -m pytest tests/ -q   (or python tests/test_disclosure.py)
"""
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(
    os.path.dirname(__file__), "..")))

# fixture: a policy that discloses SOME things and omits others
FIXTURE_POLICY = """
Acme Shop Privacy Policy

We use cookies and local storage to operate this website. Analytics data
is collected to measure performance and improve our services. We do not
sell your personal information for advertising purposes.

Service providers: we share information with Google Analytics, Amazon
Web Services and Zendesk to provide customer support.

We may send marketing emails if you subscribe to our newsletter.
Last updated: 2026-01-01.
"""

FIXTURE_BEHAVIOR = {
    "entities": [
        {"company": "Google", "category": "Analytics", "count": 4,
         "urls": ["https://www.google-analytics.com/collect"]},
        # Klaviyo received identifiers but the policy never names it
        {"company": "Klaviyo", "category": "Content", "count": 2,
         "urls": ["https://a.klaviyo.com/api/track"]},
        {"company": "Amazon Web Services", "category": "unknown",
         "count": 1, "urls": ["https://d123.cloudfront.net/x"]},
    ],
    "domains": ["www.google-analytics.com", "a.klaviyo.com"],
    "mechanisms": {"substring": 5, "idb_hook": 2},
    "observed_storage": ["localStorage", "cookies"],
    "source_files": ["fake.json"],
}


def test_disclosure_extraction():
    from policy_scanner.disclosure import extract_disclosures
    d = extract_disclosures(FIXTURE_POLICY)

    techs = {s["tech"] for s in d["storage"]}
    assert "cookies" in techs, techs
    assert "localstorage" in techs, techs
    assert "indexeddb" not in techs          # genuinely absent
    assert d["cookies_disclosed"] is True

    names = {t["name"].lower() for t in d["third_parties"]}
    assert "google analytics" in names or any("google" in n for n in names), names
    assert any("zendesk" in n for n in names), names
    assert any("amazon web services" in n or "aws" == n for n in names), names
    # NOT in the policy:
    assert not any("klaviyo" in n for n in names), names
    assert not any("facebook" in n or "meta" == n for n in names), names

    purposes = {p["purpose"] for p in d["purposes"]}
    assert "analytics" in purposes, purposes
    assert "email_marketing" in purposes, purposes
    print("test_disclosure_extraction OK")


def test_gap_undisclosed_recipient():
    from policy_scanner.gap import gap_report
    from policy_scanner.disclosure import extract_disclosures
    d = extract_disclosures(FIXTURE_POLICY)
    gap = gap_report(d, FIXTURE_BEHAVIOR)

    undisclosed = {e["company"] for e in gap["undisclosed_recipients"]}
    assert "Klaviyo" in undisclosed, undisclosed      # observed, unnamed
    assert "Google" not in undisclosed, undisclosed   # disclosed
    assert "Amazon Web Services" not in undisclosed, undisclosed
    assert gap["gap_found"] is True
    assert "Klaviyo" in gap["verdict"] or "never named" in gap["verdict"]
    print("test_gap_undisclosed_recipient OK")


def test_gap_storage_claim():
    from policy_scanner.gap import gap_report
    from policy_scanner.disclosure import extract_disclosures
    d = extract_disclosures(FIXTURE_POLICY)
    gap = gap_report(d, FIXTURE_BEHAVIOR)

    # policy never mentions IndexedDB, behavior has idb_hook mechanism
    assert gap["storage"]["indexeddb_disclosed"] is False
    assert gap["storage"]["indexeddb_observed"] is True
    assert "IndexedDB observed but not disclosed" in gap["verdict"]
    print("test_gap_storage_claim OK")


def test_clean_policy_no_gap():
    """A full-disclosure policy + matching behavior → no material gap."""
    from policy_scanner.disclosure import extract_disclosures
    from policy_scanner.gap import gap_report
    full_policy = (
        "We use cookies, local storage and IndexedDB. "
        "For advertising and analytics we work with Google Analytics "
        "and Klaviyo. Social media widgets from Meta are embedded."
    )
    behavior = {
        "entities": [
            {"company": "Google", "category": "Analytics", "count": 3},
            {"company": "Klaviyo", "category": "Advertising", "count": 2},
        ],
        "observed_storage": ["localStorage", "cookies"],
        "mechanisms": {"idb_hook": 4},
        "domains": [],
        "source_files": [],
    }
    d = extract_disclosures(full_policy)
    gap = gap_report(d, behavior)
    names = {e["company"] for e in gap["undisclosed_recipients"]}
    assert not names, names
    assert gap["storage"]["indexeddb_disclosed"] is True
    assert gap["storage"]["indexeddb_observed"] is True
    print("test_clean_policy_no_gap OK")


def test_snapshot_roundtrip(tmp_path=None):
    import policy_scanner.disclosure as disc
    import tempfile
    old = disc.SNAPSHOT_DIR
    try:
        disc.SNAPSHOT_DIR = tempfile.mkdtemp()
        d = disc.extract_disclosures(FIXTURE_POLICY)
        p = disc.save_snapshot("example.com", "https://example.com/privacy",
                               FIXTURE_POLICY, d)
        back = disc.load_snapshot("example.com")
        assert back and back["domain"] == "example.com"
        assert back["sha256"]
        assert back["disclosures"]["policy_sha256"] == d["policy_sha256"]
        assert os.path.exists(p)
    finally:
        disc.SNAPSHOT_DIR = old
    print("test_snapshot_roundtrip OK")


if __name__ == "__main__":
    test_disclosure_extraction()
    test_gap_undisclosed_recipient()
    test_gap_storage_claim()
    test_clean_policy_no_gap()
    test_snapshot_roundtrip()
    print("ALL PHASE-9 TESTS PASSED")
