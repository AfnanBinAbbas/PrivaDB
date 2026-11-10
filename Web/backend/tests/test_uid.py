"""
Phase UID tests — paper §4.1 client-identifier heuristic (uid.py).
Source: Ahmad et al., IJIS 2024 §4.1 (References/s10207-024-00886-0).
No network, pure functions.
"""
import os
import sys

_ENGINE = os.path.abspath(os.path.join(
    os.path.dirname(__file__), "..", "..", "src", "engine"))
if _ENGINE not in sys.path:
    sys.path.insert(0, _ENGINE)


def _it(uid_val, static_val="same-value-12345678", reload_val=None,
        key="uid"):
    recs = [{"key": key, "value": uid_val},
            {"key": "static", "value": static_val}]
    after = [{"key": key, "value": uid_val if reload_val is None
              else reload_val},
             {"key": "static", "value": static_val}]
    return {
        "indexeddb": {"databases": [{"name": "db", "stores": [
            {"name": "s", "records": recs}]}]},
        "reload_check": {"after_indexeddb": {"databases": [
            {"name": "db", "stores": [{"name": "s", "records": after}]}]}},
    }


def test_lcs_and_strips():
    import uid
    assert len(uid._lcs("abcdef", "azced")) == 3
    assert uid.strip_timestamps("x1700000000000y") == "xy"
    # timestamp-only difference → NOT significantly different
    d, r = uid.significantly_different("1700000000000-aaa",
                                       "1700000060000-aaa")
    assert d is False and r == 1.0
    # instance-random values → different
    d2, r2 = uid.significantly_different("a3f9c1d7e5b2846f",
                                         "77aa33bb88cc55dd")
    assert d2 is True and r2 < 0.66
    print("test_lcs_and_strips OK")


def test_confirmed_and_rejected():
    import uid
    its = [_it("inst-aaaa111122223333"),
           _it("inst-bbbb444455556666")]
    rep = uid.classify_site(its)
    assert rep["evaluated"] is True
    assert rep["scope"] == "indexeddb-only"
    by = {i["key"]: i for i in rep["identifiers"]}
    # instance-unique key: all five paper conditions hold
    conf = by["db/s/uid"]
    assert conf["confirmed"] is True, conf
    assert all(v is True for v in conf["conditions"].values())
    # static key fails C5 → neither confirmed nor candidate
    stat = by["db/s/static"]
    assert stat["confirmed"] is False and stat["candidate"] is False
    assert stat["conditions"]["c5_values_differ"] is False
    assert rep["confirmed_count"] == 1
    print("test_confirmed_and_rejected OK")


def test_c2_reload_violation_blocks_confirmation():
    import uid
    its = [_it("inst-aaaa111122223333"),
           _it("inst-bbbb444455556666",
               reload_val="CHANGED-on-reload-9999")]
    rep = uid.classify_site(its)
    v = {i["key"]: i for i in rep["identifiers"]}["db/s/uid"]
    assert v["conditions"]["c2_reload_same_value"] is False
    assert v["confirmed"] is False
    print("test_c2_reload_violation_blocks_confirmation OK")


def test_no_reload_data_yields_candidate_not_confirmed():
    import uid
    its = [{k: v for k, v in it.items() if k != "reload_check"}
           for it in [_it("inst-aaaa111122223333"),
                      _it("inst-bbbb444455556666")]]
    rep = uid.classify_site(its)
    v = {i["key"]: i for i in rep["identifiers"]}["db/s/uid"]
    assert v["conditions"]["c2_reload_same_value"] == "unverified"
    assert v["candidate"] is True and v["confirmed"] is False
    assert rep["reload_checked"] is False
    print("test_no_reload_data_yields_candidate_not_confirmed OK")


def test_needs_two_iterations():
    import uid
    rep = uid.classify_site([_it("inst-aaaa111122223333")])
    assert rep["evaluated"] is False
    assert "≥2" in rep["reason"]
    assert rep["confirmed_count"] == 0
    print("test_needs_two_iterations OK")


def test_short_value_fails_c3():
    import uid
    its = [_it("abc", static_val="x"), _it("xyz", static_val="x")]
    rep = uid.classify_site(its)
    v = {i["key"]: i for i in rep["identifiers"]}.get("db/s/uid")
    # present in 2 instances but <8 chars → C3 fails
    if v:  # key path may be built only for present keys — verify gate
        assert v["confirmed"] is False
        assert v["conditions"]["c3_length"] is False
    # and no confirmation anywhere
    assert rep["confirmed_count"] == 0
    print("test_short_value_fails_c3 OK")


def test_attach_to_identifiers():
    import uid
    rep = uid.classify_site([_it("inst-aaaa111122223333"),
                             _it("inst-bbbb444455556666")])
    idents = [{"path": "db/s/uid.leaf", "reason": "idb_key:uid"},
              {"path": "db/s/other"},
              {"path": "cookie-ish/value"}]
    uid.attach_to_identifiers(idents, rep)
    assert idents[0]["client_identifier"] is True
    assert idents[0]["uid_conditions"]["c4_fresh_key"] is True
    assert idents[1]["client_identifier"] is None   # never claimed
    assert idents[2]["client_identifier"] is None   # out of IDB scope
    print("test_attach_to_identifiers OK")


if __name__ == "__main__":
    test_lcs_and_strips()
    test_confirmed_and_rejected()
    test_c2_reload_violation_blocks_confirmation()
    test_no_reload_data_yields_candidate_not_confirmed()
    test_needs_two_iterations()
    test_short_value_fails_c3()
    test_attach_to_identifiers()
    print("ALL UID PAPER TESTS PASSED")
