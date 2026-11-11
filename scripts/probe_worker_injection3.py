#!/usr/bin/env python3
"""Probe 3: remaining fallback paths.

Q14 blob-URL DedicatedWorker + importScripts(ABSOLUTE url) works?
Q15 blob-URL SharedWorker allowed in Firefox 137?
Q16 importScripts(absolute) inside blob SharedWorker works?
Q17 are SharedWorker-initiated fetches visible to context.on('request')?
Q18 are DedicatedWorker fetches visible AFTER route injection (re-check)?
Q19 what does self.location look like with route+marker (contamination check)?
"""
import asyncio
import json
import os
import re
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = 18793
FOXHOUND = os.path.abspath(os.path.join(
    os.path.dirname(__file__), "..", "Web", "foxhound", "foxhound"))

hits = []
lock = threading.Lock()

INDEX = r"""<!DOCTYPE html><html><head><meta charset="utf-8"><title>probe3</title></head>
<body><h1>probe3</h1>
<script>
window.__probe = {errors: [], events: [], blobw: null, blobsh: null,
                  shfetch: null, loc: null};
const ABS_W2 = location.origin + "/w2.js";
const ABS_SHARED = location.origin + "/shared3.js";

// Q14: blob dedicated worker + absolute importScripts
(async () => {
  try {
    const blob = new Blob(
      ['self.__P = "blobok"; importScripts("' + ABS_W2 + '");'],
      {type: "text/javascript"});
    const w = new Worker(URL.createObjectURL(blob));
    w.onmessage = (e) => {
      window.__probe.events.push("blobw:" + e.data);
      if (String(e.data).indexOf("w2-ran") === 0) window.__probe.blobw = String(e.data);
    };
    w.onerror = (e) => window.__probe.errors.push("blobw: " + (e.message || e));
  } catch (e) { window.__probe.errors.push("blobw-throw: " + e); }

  // Q19: route+marker dedicated worker location check
  try {
    const rw = new Worker("/loc.js?__privadb_tok=P3");
    rw.onmessage = (e) => { window.__probe.loc = String(e.data); };
  } catch (e) { window.__probe.errors.push("locw: " + e); }

  // Q15/Q16: blob shared worker + absolute importScripts inside it
  try {
    const blob = new Blob(
      ['self.__P = "shblobok"; importScripts("' + ABS_SHARED + '");'],
      {type: "text/javascript"});
    const sw = new SharedWorker(URL.createObjectURL(blob));
    sw.port.onmessage = (e) => {
      window.__probe.events.push("blobsh:" + e.data);
      if (String(e.data).indexOf("shared3-ran") === 0) window.__probe.blobsh = String(e.data);
    };
    sw.port.start();
    setTimeout(() => sw.port.postMessage({cmd: "ping"}), 300);
  } catch (e) { window.__probe.errors.push("blobsh: " + e); }

  // Q17: shared worker fetch visibility (plain, marked-but-unroutable)
  try {
    const sw2 = new SharedWorker("/shared4.js?__privadb_tok=P3");
    sw2.port.onmessage = (e) => window.__probe.events.push("sh4:" + e.data);
    sw2.port.start();
    setTimeout(() => sw2.port.postMessage({cmd: "ping"}), 600);
  } catch (e) { window.__probe.errors.push("sh4: " + e); }

  setTimeout(() => { document.title = "probe3-done"; }, 2500);
})();
</script></body></html>
"""

W2JS = r"""
postMessage("w2-ran pre=" + (self.__P || "none"));
"""

LOCJS = r"""
postMessage("loc=" + self.location.href);
"""

SHARED3JS = r"""
self.onconnect = (e) => {
  const port = e.ports[0];
  port.onmessage = (ev) => {
    if (ev.data && ev.data.cmd === "ping")
      port.postMessage("shared3-ran pre=" + (self.__P || "none"));
  };
  port.start();
};
"""

SHARED4JS = r"""
self.onconnect = (e) => {
  const port = e.ports[0];
  port.onmessage = (ev) => {
    if (ev.data && ev.data.cmd === "ping") {
      fetch("/shfetch4?x=1").then(() => port.postMessage("shfetch=ok"))
        .catch((err) => port.postMessage("shfetch=err:" + err));
    }
  };
  port.start();
};
"""


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        with lock:
            hits.append(self.path)
        table = {
            "/index": (INDEX, "text/html; charset=utf-8"),
            "/w2.js": (W2JS, "application/javascript"),
            "/loc.js": (LOCJS, "application/javascript"),
            "/shared3.js": (SHARED3JS, "application/javascript"),
            "/shared4.js": (SHARED4JS, "application/javascript"),
        }
        body, ctype = None, "application/json"
        for p, (b, c) in table.items():
            if self.path.startswith(p):
                body, ctype = b.encode(), c
                break
        if body is None:
            body = b'{"ok":true}'
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


async def main():
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    from playwright.async_api import async_playwright
    route_log, reqs = [], []
    env = os.environ.copy()
    env["DBUS_SYSTEM_BUS_ADDRESS"] = "unix:path=/dev/null"
    env["DBUS_SESSION_BUS_ADDRESS"] = "unix:path=/dev/null"
    env["MOZ_NO_REMOTE"] = "1"
    env.setdefault("DISPLAY", ":99")

    async with async_playwright() as pw:
        browser = await pw.firefox.launch(
            headless=True, executable_path=FOXHOUND,
            args=["-new-instance"], env=env,
            firefox_user_prefs={"security.csp.enable": False}, timeout=60000)
        ctx = await browser.new_context(ignore_https_errors=True, no_viewport=True)

        async def route_handler(route):
            entry = {"url": route.request.url}
            try:
                resp = await route.fetch()
                body = await resp.body()
                prelude = b"/*P3PRELUDE*/\nself.__PRIVADB_PRELUDE='ROUTE_OK';\n"
                headers = {k: v for k, v in resp.headers.items()
                           if k.lower() not in ("content-length", "content-encoding")}
                entry["injected"] = True
                route_log.append(entry)
                await route.fulfill(status=resp.status, headers=headers,
                                    body=prelude + body)
            except Exception as e:
                entry["error"] = str(e)
                route_log.append(entry)
                try:
                    await route.continue_()
                except Exception:
                    pass

        await ctx.route(re.compile(r"[?&]__privadb_tok="), route_handler)
        ctx.on("request", lambda r: reqs.append(r.url))
        ctx.on("requestfailed", lambda r: reqs.append("FAILED:" + r.url))
        page = await ctx.new_page()
        await page.goto(f"http://localhost:{PORT}/index.html",
                        wait_until="domcontentloaded", timeout=30000)
        for _ in range(40):
            if await page.title() == "probe3-done":
                break
            await page.wait_for_timeout(250)
        await page.wait_for_timeout(1200)
        probe = await page.evaluate("window.__probe")
        await browser.close()
    srv.shutdown()

    v = {
        "Q14_blob_dedicated_import_abs": str(probe.get("blobw") or "").startswith("w2-ran pre=blobok"),
        "Q15_blob_shared_allowed": any(e.startswith("blobsh:shared3-ran") for e in probe.get("events", [])),
        "Q17_shared_fetch_seen_by_context": any("shfetch4" in u for u in reqs),
        "Q17b_shared_fetch_reached_server": any(h.startswith("/shfetch4") for h in hits),
        "Q18_dedicated_worker_route_still_works": any("loc.js" in e.get("url", "") for e in route_log),
        "Q19_marker_in_worker_location": "__privadb_tok=P3" in str(probe.get("loc") or ""),
    }
    result = {"verdicts": v, "probe": probe, "route_log": route_log,
              "requests": reqs, "hits": sorted(set(hits))}
    out = os.path.join(os.path.dirname(__file__), "..", "raw", "05-probe3.json")
    with open(out, "w") as f:
        json.dump(result, f, indent=2, default=str)
    print(json.dumps(v, indent=2))
    print("loc:", probe.get("loc"))
    print("events:", probe.get("events"))
    print("errors:", probe.get("errors"))
    print("hits:", sorted(set(hits)))
    failed = [k for k, val in v.items() if not val]
    print("FAILED:", failed if failed else "none")
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
