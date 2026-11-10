#!/usr/bin/env python3
"""
Phase 1 smoke test — verifies the detection pipeline against ground truth.

Serves a controlled page (pages/smoke.html) that performs KNOWN IndexedDB
exfiltration flows through KNOWN sinks, crawls it with the Foxhound engine,
runs the detector, and asserts every ground-truth flow is caught while the
benign control is not flagged.

Ground truth (see pages/smoke.html):
  G1  IDB uid → fetch URL query      → expect substring exfil + idb_hook flow
  G2  IDB uid → XHR POST body        → expect substring exfil (post_data)
  G3  localStorage → sendBeacon      → expect taint flow (localStorage.getItem)
  G4  IDB uid → img.src pixel        → expect idb_hook / substring exfil
  G5  benign constant (not in IDB)   → expect NOT flagged as identifier

Usage:
    python testbed/run_smoke.py                 # foxhound (full assertions)
    python testbed/run_smoke.py --engine chrome # substring-only assertions
    python testbed/run_smoke.py --headless
"""
import argparse
import asyncio
import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ENGINE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ENGINE_DIR)

import app_config as config  # noqa: E402

PAGE_PORT = 18765
SINK_PORT = 18766

KNOWN_UID = "a3f9c1d7e5b2846f0913a7c5d8e2f6b4"
KNOWN_LS = "ls-taint-9f8e7d6c5b4a3210ffeeddccbbaa9988"
BENIGN = "benign-constant-string"
# [6] inflow: value served by the network that the page writes to IDB
KNOWN_INFLOW = "net-inflow-fedcba98765432101122334455667788"
# [7] third-party writer script: writes KNOWN_TPWRITER to IDB from
#     the sink origin (different port → different party)
KNOWN_TPWRITER = "tp-writer-887766554433221100ffeeddccbbaa99"

_page_dir = os.path.join(os.path.dirname(__file__), "pages")
sink_received = []
_sink_lock = threading.Lock()


class _CorsMixin:
    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "*")


class SinkHandler(BaseHTTPRequestHandler, _CorsMixin):
    """Receives exfiltrated values; logs them as ground truth."""

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        # Inflow payload: known value the page must write to IDB
        if self.path.startswith("/payload"):
            payload = json.dumps(
                {"ok": True, "inbound_value": KNOWN_INFLOW}).encode()
            self.send_response(200)
            self._cors()
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            self._record("GET")
            return
        # Third-party writer script: writes KNOWN_TPWRITER into page IDB
        if self.path.startswith("/tracker.js"):
            js = f"""
(function () {{
  try {{
    var req = indexedDB.open("smoke_db", 1);
    req.onupgradeneeded = function (e) {{
      var db = e.target.result;
      if (!db.objectStoreNames.contains("ids")) db.createObjectStore("ids");
    }};
    req.onsuccess = function (e) {{
      var db = e.target.result;
      if (!db.objectStoreNames.contains("ids")) return;
      var tx = db.transaction("ids", "readwrite");
      tx.objectStore("ids").put({{ fp: "{KNOWN_TPWRITER}" }}, "tp1");
    }};
  }} catch (e) {{}}
}})();
""".encode()
            self.send_response(200)
            self._cors()
            self.send_header("Content-Type", "application/javascript")
            self.send_header("Content-Length", str(len(js)))
            self.end_headers()
            self.wfile.write(js)
            self._record("GET")
            return
        self._record("GET")
        self._reply()

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length else b""
        self._record("POST", body.decode("utf-8", "ignore"))
        self._reply()

    def _record(self, method, body=""):
        entry = {"method": method, "path": self.path, "body": body,
                 "ts": time.time()}
        with _sink_lock:
            sink_received.append(entry)

    def _reply(self):
        payload = b'{"ok":true}'
        self.send_response(200)
        self._cors()
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *a):
        pass


class PageHandler(BaseHTTPRequestHandler):
    """Serves the smoke page (with injected sink base) and the FP-control sink."""

    def do_GET(self):
        if self.path.startswith("/smoke-sink"):
            with _sink_lock:
                sink_received.append({"method": "GET", "path": self.path,
                                      "body": "", "ts": time.time()})
            body = b"ok"
            self.send_response(200)
        elif self.path.startswith("/smoke"):
            with open(os.path.join(_page_dir, "smoke.html"), "rb") as f:
                # Sink on 127.0.0.1 while the page is on localhost: the two
                # names are distinct parties under both the naive heuristic
                # and PSL-based checks (Phase 5).
                html = f.read().replace(b"__SINK_BASE__",
                                        f"http://127.0.0.1:{SINK_PORT}".encode())
            body = html
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
        else:
            body = b"not found"
            self.send_response(404)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def _start_servers():
    sink = ThreadingHTTPServer(("127.0.0.1", SINK_PORT), SinkHandler)
    page = ThreadingHTTPServer(("127.0.0.1", PAGE_PORT), PageHandler)
    for srv in (sink, page):
        threading.Thread(target=srv.serve_forever, daemon=True).start()
    return sink, page


CHECK_LOG = []

def _check(name, ok, detail=""):
    ok = bool(ok)
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f" — {detail}" if detail else ""))
    CHECK_LOG.append({"name": name, "passed": ok, "detail": detail})
    return ok


async def _crawl(engine: str, headless: bool) -> dict:
    from crawler import crawl_all_sites

    config.set_engine(engine)
    config.HEADLESS = headless
    config.CRAWL_ITERATIONS = 1
    results = await crawl_all_sites(
        custom_sites=[{"url": f"http://localhost:{PAGE_PORT}/smoke.html",
                       "reason": "phase1 smoke test"}]
    )
    return results[0] if results else {}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--engine", default="foxhound",
                        choices=["foxhound", "chrome"])
    parser.add_argument("--headless", action="store_true")
    args = parser.parse_args()

    sink_srv, page_srv = _start_servers()
    print(f"  page server: http://localhost:{PAGE_PORT}/smoke.html")
    print(f"  sink server: http://localhost:{SINK_PORT}/")

    try:
        site_data = asyncio.run(_crawl(args.engine, args.headless))
        if not site_data:
            print("FATAL: crawl returned no data")
            return 2

        from detector import analyze_site
        analysis = analyze_site(site_data)

        exfils = analysis.get("exfiltration_events", [])
        taints = analysis.get("taint_flows", [])
        hooks = analysis.get("idb_hook_flows", [])
        idents = analysis.get("identifiers", [])

        with _sink_lock:
            received = list(sink_received)

        print("\n=== Ground-truth assertions ===")
        results = []

        # G0: the browser really exfiltrated (sink observed the flows)
        got_uid_net = any(KNOWN_UID in (r["path"] + r["body"]) for r in received)
        got_ls_net = any(KNOWN_LS in (r["path"] + r["body"]) for r in received)
        results.append(_check(
            "G0a sink received IDB uid (browser-side ground truth)",
            got_uid_net, f"{len(received)} sink requests total"))
        results.append(_check(
            "G0b sink received localStorage value (browser-side ground truth)",
            got_ls_net))

        # G1/G2/G4: substring exfil of KNOWN_UID
        uid_exfils = [e for e in exfils
                      if str(e.get("identifier_value", "")) == KNOWN_UID]
        results.append(_check(
            "G1 substring exfil: IDB uid found in network request",
            bool(uid_exfils),
            f"{len(uid_exfils)} event(s), mechanisms="
            f"{sorted({e.get('mechanism') for e in uid_exfils})}"))
        if uid_exfils:
            results.append(_check(
                "G1b classified third-party",
                any(e.get("is_third_party") for e in uid_exfils)))
            results.append(_check(
                "G1c match covers URL and/or POST body",
                any(e.get("match_location") in ("url", "url_decoded",
                                                 "post_data")
                    for e in uid_exfils),
                ",".join(sorted({e.get("match_location", "")
                                 for e in uid_exfils}))))

        # G1d: idb_hook flow ties the IDB read to the network send
        # (flow hooks now run on both engines)
        uid_hook = [f for f in hooks
                    if KNOWN_UID in str(f.get("idb_value", ""))]
        results.append(_check(
            "G1d idb_hook flow: IDB read → network send",
            bool(uid_hook),
            f"{len(uid_hook)} flow(s), targets="
            f"{sorted({(f.get('target') or '')[:60] for f in uid_hook})}"))

        # G3: taint flow with localStorage source (foxhound only)
        if args.engine == "foxhound":
            ls_taint = [f for f in taints
                        if KNOWN_LS in str(f.get("tainted_value", ""))
                        or KNOWN_LS in str(f.get("target", ""))]
            src_taint = [f for f in taints
                         if f.get("source_operation") == "localStorage.getItem"]
            results.append(_check(
                "G3 taint flow: localStorage.getItem → sink",
                bool(ls_taint or src_taint),
                f"known-value={len(ls_taint)} any-localStorage-src={len(src_taint)}"
                f" (total taint flows: {len(taints)})"))

        # G5: FP control — benign constant must NOT be an identifier
        fp = [e for e in exfils
              if BENIGN in str(e.get("identifier_value", ""))]
        fp_id = [i for i in idents if str(i.get("value", "")) == BENIGN]
        results.append(_check(
            "G5 no false positive on non-IDB constant",
            not fp and not fp_id,
            f"exfils={len(fp)} idents={len(fp_id)}"))

        # Phase 2 ground truth (requires flow hooks — both engines now)
        wa = analysis.get("write_attribution", {}) or {}
        inflows = analysis.get("inflow_flows", []) or []

        # G6: response-proven inflow — network value written to IDB
        inflow_hits = [f for f in inflows
                       if KNOWN_INFLOW in str(f.get("value", ""))]
        heuristic_only = [f for f in inflows
                          if f.get("mechanism") == "heuristic"]
        results.append(_check(
            "G6 inflow: network response value written to IDB (response-proven)",
            bool(inflow_hits),
            f"proven={len(inflow_hits)} heuristic_fallback={len(heuristic_only)}"))
        if inflow_hits:
            results.append(_check(
                "G6b inflow tagged mechanism=response_match + direction=inflow",
                all(f.get("mechanism") == "response_match"
                    and f.get("flow_direction") == "inflow"
                    for f in inflow_hits)))

        # G7: third-party script writer attribution
        tp_writes = [w for w in wa.get("writes", [])
                     if KNOWN_TPWRITER in str(w.get("value_preview", ""))]
        # value_preview is a leaf of the {fp: ...} object → may be the value
        tp_writes += [w for w in wa.get("writes", [])
                      if w.get("store") == "tp1"]
        # dedupe
        tp_writes = list({id(w): w for w in tp_writes}.values())
        results.append(_check(
            "G7 attribution: third-party script write recorded",
            bool(tp_writes),
            f"{len(tp_writes)} matching write(s)"))
        if tp_writes:
            roles = {w.get("writer_role") for w in tp_writes}
            results.append(_check(
                "G7b writer_role == third_party",
                "third_party" in roles,
                f"roles={sorted(roles)} origins="
                f"{sorted({str(w.get('writer_origin')) for w in tp_writes})}"))

        # G8: first-party writes from the inline smoke script are attributed
        fp_writes = [w for w in wa.get("writes", [])
                     if w.get("store") == "ids" and w.get("key") in
                     ("user1", "inflow1")]
        if fp_writes:
            fp_roles = {w.get("writer_role") for w in fp_writes}
            results.append(_check(
                "G8 attribution: first-party (inline) writes classified",
                "first_party" in fp_roles or "unknown" in fp_roles,
                f"roles={sorted(fp_roles)}"))

        # G9 (Phase 3): transformed exfil — sha256(uid) and base64(uid)
        # sent in a query param must match via transform chains, not raw.
        tf_events = [e for e in exfils
                     if str(e.get("identifier_value", "")) == KNOWN_UID
                     and e.get("mechanism") in ("transform", "both")]
        all_chains = {c for e in tf_events
                      for c in (e.get("all_transform_chains")
                                or e.get("transform_chain") or [])}
        has_sha = "sha256" in all_chains
        has_b64 = "base64" in all_chains
        results.append(_check(
            "G9 transform-aware match: sha256(uid) + base64(uid) in query",
            has_sha and has_b64,
            f"chains seen={sorted(all_chains)}"))

        # G9b: WS/headers — via unit-level check (page doesn't use WS);
        # header matching is exercised by transforms.search_request
        # against all headers (smoke sends no custom headers → skip).

        # G10: dedup fix — flows counted per (id, sink, location), so the
        # uid appears in multiple distinct events (get/pixel/track URLs)
        uid_events = [e for e in exfils
                      if str(e.get("identifier_value", "")) == KNOWN_UID]
        distinct_urls = {e.get("request_url") for e in uid_events}
        results.append(_check(
            "G10 dedup keeps distinct (id,destination) flows",
            len(distinct_urls) >= 2,
            f"{len(uid_events)} events across {len(distinct_urls)} URLs"))

        # Coverage summary
        print("\n=== Pipeline coverage ===")
        print(f"  identifiers:        {analysis.get('identifiers_found')}")
        print(f"  exfiltration events:{len(exfils)}")
        print(f"  taint flows:        {len(taints)}")
        print(f"  idb_hook flows:     {len(hooks)}")
        print(f"  dynamic_flows:      {analysis.get('dynamic_flows')}")

        # Persist evidence
        out = os.path.join(os.path.dirname(__file__), "smoke_report.json")
        with open(out, "w") as f:
            json.dump({
                "engine": args.engine,
                "checks": CHECK_LOG,
                "passed": all(results),
                "n_pass": sum(results),
                "n_total": len(results),
                "sink_received": received,
                "analysis_snapshot": {
                    "identifiers_found": analysis.get("identifiers_found"),
                    "exfiltrations": len(exfils),
                    "taint_flows": len(taints),
                    "idb_hook_flows": len(hooks),
                    "dynamic_flows": analysis.get("dynamic_flows"),
                },
            }, f, indent=2, default=str)
        print(f"\n  report → {out}")

        n_pass, n_total = sum(results), len(results)
        print(f"\n  RESULT: {n_pass}/{n_total} checks passed")
        return 0 if n_pass == n_total else 1
    finally:
        sink_srv.shutdown()
        page_srv.shutdown()


if __name__ == "__main__":
    sys.exit(main())
