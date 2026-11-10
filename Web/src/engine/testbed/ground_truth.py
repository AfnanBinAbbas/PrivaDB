"""
Phase 7 ground truth — declarative expected behavior of testbed pages.

Every page under testbed/pages/ embeds the literal constants below;
evaluate.py scores detector output against FLOWS / NON_IDENTIFIERS.
Changing a value here requires changing it in the page too.

Scoring definitions (see evaluate.py):
    predicted positive = one exfil event raised by the method
    TP  = event whose (identifier_value, request_url) matches a FLOW
    FP  = any other event (incl. events on NON_IDENTIFIERS)
    FN  = FLOW with no matching event
"""

from __future__ import annotations

import hashlib
from urllib.parse import quote

# ── identifiers (stored in IDB on the transforms page) ──
TID = "tid-0f3e2d1c4b5a69788796a5b4c3d2e1f0"
TENC = "id with spaces+plus/slash?chars=and&more 1234567890"
LSBEACON = "lsbeacon-99887766554433221100ffeeddccbbaa"

# ── benign controls (stored in IDB but NOT tracking identifiers) ──
CSRF = "csrf-11223344556677889900aabbccddeeff"
VERSION = "v1.2.3-build.987654321"

# expected md5 of TID — also validates the page's pure-JS md5: if the
# page's digest is wrong, the md5 FLOW below can never be detected.
TID_MD5 = hashlib.md5(TID.encode()).hexdigest()

# ── must-detect flows: (value, url_substring, transform_chain) ──
FLOWS = [
    # raw in query
    (TID, "/v/raw?x=", ["raw"]),
    # transform variants of TID
    (TID, "/v/b64?x=" + __import__("base64").b64encode(TID.encode()).decode(),
     ["base64"]),
    (TID, "/v/hex?x=" + TID.encode().hex(), ["hex"]),
    (TID, "/v/md5?x=" + TID_MD5, ["md5"]),
    (TID, "/v/sha1x?x=" + TID[:16], ["truncate16"]),
    (TID, "/v/sha256?x=" + hashlib.sha256(TID.encode()).hexdigest(),
     ["sha256"]),
    # url-encoded TENC (raw form never appears on the wire)
    (TENC, "/v/enc?x=" + quote(TENC, safe=""), ["urlencode"]),
    # sink diversity on raw TID
    (TID, "/v/xhr", ["raw"]),
    (TID, "/v/beacon", ["raw"]),
    (TID, "/v/pixel?u=", ["raw"]),
    (TID, "/v/form", ["raw"]),
    # localStorage → sendBeacon (taint source; detected via storage pool,
    # taint (foxhound), or substring — all count as detecting the flow)
    (LSBEACON, "/v/lsbeacon", ["raw"]),
]

# any event on these values = false positive of the identifier model
NON_IDENTIFIERS = [CSRF, VERSION]

# smoke page ground truth (used when the smoke crawl is evaluated)
SMOKE_UID = "a3f9c1d7e5b2846f0913a7c5d8e2f6b4"
SMOKE_LS = "ls-taint-9f8e7d6c5b4a3210ffeeddccbbaa9988"


def verify_js_md5_vectors() -> dict:
    """
    Self-check of the md5 constants used by the page ground truth.
    (The page's JS md5 was verified against these vectors with node at
    authoring time; this confirms the Python side didn't drift.)
    """
    return {
        "abc": hashlib.md5(b"abc").hexdigest() == "900150983cd24fb0d6963f7d28e17f72",
        "empty": hashlib.md5(b"").hexdigest() == "d41d8cd98f00b204e9800998ecf8427e",
        "tid": hashlib.md5(TID.encode()).hexdigest() == TID_MD5,
    }
