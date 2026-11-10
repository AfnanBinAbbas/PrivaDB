"""
Phase 10 tests — SSRF guard. No network beyond local DNS.
"""
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(
    os.path.dirname(__file__), "..")))


def _guard():
    from security import is_public_url
    return is_public_url


def test_blocks_private_and_loopback():
    f = _guard()
    old = os.environ.pop("PRIVADB_ALLOW_PRIVATE_TARGETS", None)
    try:
        assert not f("http://127.0.0.1:8000/scan")
        assert not f("http://localhost:8080/")
        assert not f("https://10.0.0.5/admin")
        assert not f("https://192.168.1.1/")
        assert not f("https://172.16.0.1/")
        assert not f("http://[::1]/")
        assert not f("http://0.0.0.0/")
        assert not f("https://foo.localhost/")
    finally:
        if old is not None:
            os.environ["PRIVADB_ALLOW_PRIVATE_TARGETS"] = old


def test_blocks_metadata_and_schemes():
    f = _guard()
    assert not f("http://169.254.169.254/latest/meta-data/")
    assert not f("http://metadata.google.internal/computeMetadata/")
    assert not f("ftp://example.com/x")
    assert not f("file:///etc/passwd")
    assert not f("gopher://x/")
    # link-local
    assert not f("http://169.254.1.1/")


def test_allows_public():
    f = _guard()
    assert f("https://example.com/")
    assert f("https://www.google-analytics.com/collect")
    assert f("http://93.184.216.34/")   # public IP (example.com)


def test_lab_override(monkeypatch=None):
    f = _guard()
    old = os.environ.get("PRIVADB_ALLOW_PRIVATE_TARGETS")
    try:
        os.environ["PRIVADB_ALLOW_PRIVATE_TARGETS"] = "true"
        assert f("http://localhost:18765/smoke.html")
        assert f("http://127.0.0.1:18766/")
    finally:
        if old is None:
            os.environ.pop("PRIVADB_ALLOW_PRIVATE_TARGETS", None)
        else:
            os.environ["PRIVADB_ALLOW_PRIVATE_TARGETS"] = old


def test_mapped_ipv6():
    f = _guard()
    assert not f("http://[::ffff:127.0.0.1]/")


if __name__ == "__main__":
    test_blocks_private_and_loopback()
    test_blocks_metadata_and_schemes()
    test_allows_public()
    test_lab_override()
    test_mapped_ipv6()
    print("ALL PHASE-10 SECURITY TESTS PASSED")
