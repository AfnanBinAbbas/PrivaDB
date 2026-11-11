#!/usr/bin/env python3
"""Probe 2: shared-worker route injection + blob-URL service-worker registration.

Q9  does context.route see shared-worker script fetches (marked URL)?
Q10 does the prelude run inside a SharedWorker?
Q11 can Firefox register a blob:-URL service worker (instrumented copy)?
Q12 if blob SW fails: exact rejection error (logged for the record)?
Q13 does BroadcastChannel work from SharedWorker -> page?
"""
import asyncio
import json
import os
import re
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = 18792
FOXHOUND = os.path.abspath(os.path.join(
    os.path.dirname(__file__), "..", "Web", "foxhound", "foxhound"))

hits = []
lock = threading.Lock()

INDEX = r"""<!DOCTYPE html><html><head><meta charset="utf-8"><title>probe2</title></head>
<body><h1>probe2</h1>
<script>
window.__probe = {errors: [], events: [], shared_msg: null, blob_sw: null, bc: []};
try {
  const bc = new BroadcastChannel("__privadb_probe2__");
  bc.onmessage = (e) => window.__probe.bc.push(String(e.data));
} catch (e) { window.__probe.errors.push("bc: " + e); }

// Q9/Q10/Q13: shared worker with route marker
try {
  const sw = new SharedWorker("/shared.js?__privadb_tok=P2");
  sw.port.onmessage = (e) => {
    window.__probe.events.push("shared:" + String(e.data));
    if (String(e.data).indexOf("sh-prelude") === 0)
      window.__probe.shared_msg = String(e.data);
  };
  sw.port.start();
  setTimeout(() => sw.port.postMessage({cmd: "ping"}), 500);
  window.__probe.events.push("shared_spawned");
} catch (e) { window.__probe.errors.push("shared: " + e); }

// Q11/Q12: blob-URL service worker registration
(async () => {
  try {
    const txt = await (await fetch("/sw2.js")).text();
    const blob = new Blob(["/*p2*/\nself.__BLOB_SW = 1;\n" + txt],
                          {type: "text/javascript"});
    const burl = URL.createObjectURL(blob);
    try {
      const reg = await navigator.serviceWorker.register(burl, {scope: "/"});
      for (let i = 0; i < 30 && !(reg && (reg.active || reg.installing || reg.waiting)); i++)
        await new Promise(r => setTimeout(r, 100));
      const st = reg && (reg.active || reg.installing || reg.waiting);
      window.__probe.blob_sw = "registered:" + (st ? st.state : "?");
    } catch (e) { window.__probe.blob_sw = "rejected: " + e; }
  } catch (e) { window.__probe.blob_sw = "fetch-failed: " + e; }
  document.title = "probe2-done";
})();
</script></body></html>
"""

SHAREDJS = r"""
self.onconnect = (e) => {
  const port = e.ports[0];
  port.onmessage = (ev) => {
    if (ev.data && ev.data.cmd === "ping") {
      try { new BroadcastChannel("__privadb_probe2__").postMessage("shared-bc-hello"); }
      catch (err) {}
      port.postMessage("sh-prelude=" + (self.__PRIVADB_PRELUDE || "none"));
    }
  };
  port.start();
};
"""

SW2JS = r"""
self.addEventListener("install", (e) => self.skipWaiting());
self.addEventListener("activate", () => {
  try { new BroadcastChannel("__privadb_probe2__").postMessage("blob-sw-activated"); } catch (e) {}
});
"""


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        with lock:
            hits.append(self.path)
        if self.path.startswith("/index"):
            body, ctype = INDEX.encode(), "text/html; charset=utf-8"
        elif self.path.startswith("/shared.js"):
            body, ctype = SHAREDJS.encode(), "application/javascript"
        elif self.path.startswith("/sw2.js"):
            body, ctype = SW2JS.encode(), "application/javascript"
        else:
            body, ctype = b'{"ok":true}', "application/json"
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
    route_log, consoles = [], []
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
                prelude = b"/*P2PRELUDE*/\nself.__PRIVADB_PRELUDE = 'ROUTE_OK';\n"
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
        page = await ctx.new_page()
        page.on("console", lambda m: consoles.append(f"{m.type}: {m.text}"))
        await page.goto(f"http://localhost:{PORT}/index.html",
                        wait_until="domcontentloaded", timeout=30000)
        for _ in range(40):
            if await page.title() == "probe2-done":
                break
            await page.wait_for_timeout(250)
        await page.wait_for_timeout(1500)
        probe = await page.evaluate("window.__probe")
        await browser.close()
    srv.shutdown()

    v = {}
    v["Q9_route_saw_shared_script"] = any("shared.js" in e.get("url", "") for e in route_log)
    v["Q10_prelude_ran_in_shared"] = str(probe.get("shared_msg") or "").startswith("sh-prelude=ROUTE_OK")
    v["Q11_blob_sw_registered"] = str(probe.get("blob_sw") or "").startswith("registered")
    v["Q13_bc_shared_to_page"] = any("shared-bc-hello" in x for x in probe.get("bc", []))
    result = {"verdicts": v, "probe": probe, "route_log": route_log,
              "hits": sorted(set(hits)), "consoles": consoles[:30]}
    out = os.path.join(os.path.dirname(__file__), "..", "raw", "04-probe2.json")
    with open(out, "w") as f:
        json.dump(result, f, indent=2, default=str)
    print(json.dumps(v, indent=2))
    print("blob_sw:", probe.get("blob_sw"))
    print("events:", probe.get("events"))
    print("errors:", probe.get("errors"))
    print("route:", route_log)
    print("hits:", sorted(set(hits)))
    failed = [k for k, val in v.items() if not val]
    print("FAILED:", failed if failed else "none")
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
