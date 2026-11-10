#!/usr/bin/env python3
"""
Phase 6 partitioning probe — cross-site storage visibility, per engine.

Drives a browser through two different top-level sites that embed the
SAME third-party iframe origin:

  1. parent A = http://localhost:18765/partition.html?seed=<shared>
       → iframe http://127.0.0.1:18766/probe.html?seed=<shared>
         stores the seed in the iframe origin's localStorage
  2. parent B = http://127.0.0.1:18765/partition.html   (no seed)
       → same iframe (no seed) reads localStorage and reports what it
         sees back to the sink

Verdict per engine:
  seen=<seed>  → iframe storage is NOT partitioned by top-level site
                 (cross-site tracking vector)
  seen=none    → storage partitioning active (state isolation works)

Run once per engine and compare Chrome vs Foxhound(Firefox):

    python testbed/run_partition.py --engine chrome --headless
    python testbed/run_partition.py --engine foxhound
"""
import argparse
import asyncio
import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs, unquote

ENGINE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ENGINE_DIR)

import app_config as config  # noqa: E402

PAGE_PORT = 18765
SINK_PORT = 18766
SEED = "partition-seed-aabbccddeeff001122334455667788"

partition_results = []
_plock = threading.Lock()

PARENT_HTML = b"""<!DOCTYPE html><html><body><script>
const seed = new URLSearchParams(location.search).get('seed');
const src = 'http://127.0.0.1:__SINK__/probe.html'
  + (seed ? ('?seed=' + encodeURIComponent(seed)) : '');
const f = document.createElement('iframe');
f.src = src; f.style.display = 'none';
document.body.appendChild(f);
</script></body></html>"""

PROBE_HTML = b"""<!DOCTYPE html><html><body><script>
const q = new URLSearchParams(location.search);
function report(state, val) {
  try {
    navigator.sendBeacon('http://127.0.0.1:__SINK__/partition-result?state='
      + state + '&v=' + encodeURIComponent(val || ''));
  } catch (e) {
    new Image().src = 'http://127.0.0.1:__SINK__/partition-result?state='
      + state + '&v=' + encodeURIComponent(val || '');
  }
}
const seed = q.get('seed');
if (seed) {
  try { localStorage.setItem('pid', seed); } catch (e) {}
  report('stored', seed);
} else {
  let v = null;
  try { v = localStorage.getItem('pid'); } catch (e) {}
  report('seen', v || 'none');
}
</script></body></html>"""


class _Cors:
    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "*")


class SinkHandler(BaseHTTPRequestHandler, _Cors):
    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self):
        # sendBeacon posts — same result endpoint as GET
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length:
            self.rfile.read(length)
        self._handle_partition_result(self.path)
        body = b"ok"
        self.send_response(200)
        self._cors()
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _handle_partition_result(self, raw_path: str):
        parsed = urlparse(raw_path)
        if parsed.path != "/partition-result":
            return False
        qs = parse_qs(parsed.query)
        rec = {"state": (qs.get("state") or [""])[0],
               "v": unquote((qs.get("v") or [""])[0]),
               "ts": time.time()}
        with _plock:
            partition_results.append(rec)
        print(f"    [sink] partition-result: {rec['state']}={rec['v'][:60]}")
        return True

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/probe.html":
            body = PROBE_HTML.replace(b"__SINK__",
                                      str(SINK_PORT).encode())
            ctype = "text/html; charset=utf-8"
        elif parsed.path == "/partition-result":
            self._handle_partition_result(self.path)
            body = b"ok"
            ctype = "text/plain"
        else:
            body = b"not found"
            self.send_response(404)
            ctype = "text/plain"
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(200)
        self._cors()
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class PageHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = PARENT_HTML.replace(b"__SINK__", str(SINK_PORT).encode())
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


async def _probe(engine: str, headless: bool) -> list[dict]:
    from playwright.async_api import async_playwright

    async with async_playwright() as pw:
        if engine == "foxhound":
            browser = await pw.firefox.launch(
                headless=headless,
                executable_path=config.FOXHOUND_BIN,
                args=["-new-instance"],
                env=_env(),
                timeout=60000,
            )
        else:
            browser = await pw.chromium.launch(
                headless=headless,
                args=["--disable-gpu", "--no-sandbox",
                      "--disable-setuid-sandbox", "--disable-dev-shm-usage"],
            )
        # no_viewport: Foxhound's Juggler rejects setDefaultViewport's
        # isMobile property (same workaround as the main crawler)
        context = await browser.new_context(no_viewport=True)
        page = await context.new_page()

        # Parent A (site = localhost) seeds the iframe storage
        await page.goto(
            f"http://localhost:{PAGE_PORT}/partition.html?seed={SEED}",
            wait_until="domcontentloaded", timeout=30000)
        await page.wait_for_timeout(3000)

        # Parent B (site = 127.0.0.1) — different top-level site
        await page.goto(
            f"http://127.0.0.1:{PAGE_PORT}/partition.html",
            wait_until="domcontentloaded", timeout=30000)
        await page.wait_for_timeout(3000)

        await context.close()
        await browser.close()

    with _plock:
        return list(partition_results)


def _env():
    env = os.environ.copy()
    env["DBUS_SYSTEM_BUS_ADDRESS"] = "unix:path=/dev/null"
    env["DBUS_SESSION_BUS_ADDRESS"] = "unix:path=/dev/null"
    env["MOZ_NO_REMOTE"] = "1"
    env.setdefault("DISPLAY", ":0")
    return env


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--engine", default="chrome",
                        choices=["chrome", "foxhound"])
    parser.add_argument("--headless", action="store_true")
    args = parser.parse_args()

    sink = ThreadingHTTPServer(("127.0.0.1", SINK_PORT), SinkHandler)
    page = ThreadingHTTPServer(("127.0.0.1", PAGE_PORT), PageHandler)
    for srv in (sink, page):
        threading.Thread(target=srv.serve_forever, daemon=True).start()

    try:
        recs = asyncio.run(_probe(args.engine, args.headless))
        stored = [r for r in recs if r["state"] == "stored"]
        seen = [r for r in recs if r["state"] == "seen"]

        print(f"\n=== Partition probe ({args.engine}) ===")
        print(f"  stored events: {len(stored)} (expect 1, value=seed)")
        print(f"  seen events:   {len(seen)} "
              f"→ {[r['v'][:40] for r in seen]}")

        if not seen:
            verdict = "inconclusive"
            partitioned = None
        elif seen[-1]["v"] == SEED:
            verdict = "NOT partitioned — iframe localStorage visible across " \
                      "different top-level sites (cross-site tracking vector)"
            partitioned = False
        elif seen[-1]["v"] == "none":
            verdict = "partitioned — iframe storage isolated per top-level site"
            partitioned = True
        else:
            verdict = f"unexpected value: {seen[-1]['v']}"
            partitioned = None

        print(f"  VERDICT: {verdict}")
        out = os.path.join(os.path.dirname(__file__),
                           f"partition_report_{args.engine}.json")
        with open(out, "w") as f:
            json.dump({"engine": args.engine, "headless": args.headless,
                       "seed": SEED, "events": recs,
                       "partitioned": partitioned, "verdict": verdict},
                      f, indent=2)
        print(f"  report → {out}")
        # exit 0 either way: the measurement IS the result; exit 3 only
        # when the probe produced no data
        return 0 if seen else 3
    finally:
        sink.shutdown()
        page.shutdown()


if __name__ == "__main__":
    sys.exit(main())
