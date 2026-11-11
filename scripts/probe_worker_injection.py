#!/usr/bin/env python3
"""Headless probe: which injection paths work in Foxhound (Firefox 137)?

Questions answered (logged by evaluate + server hits):
  Q1 does context.route see dedicated-worker script fetches (marked URL)?
  Q2 does context.route see service-worker script fetches (marked URL)?
  Q3 does route-prepended prelude run inside worker / SW?
  Q4 are worker-initiated network requests visible to context.on('request')?
  Q5 does BroadcastChannel worker->page work (the event bridge)?
  Q6 does blob-URL worker + importScripts (fallback path) work?
  Q7 does SW activate + clients.claim + message round-trip work headless?
  Q8 does crypto.subtle work inside a worker (SHA-256 in testbed)?

Run: venv/bin/python scripts/probe_worker_injection.py
"""
import asyncio
import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ENGINE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "Web", "src", "engine"))
sys.path.insert(0, ENGINE_DIR)

PORT = 18791
FOXHOUND = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "Web", "foxhound", "foxhound"))

hits = []          # server-side ground truth of what the browser actually fetched
lock = threading.Lock()

INDEX = r"""<!DOCTYPE html><html><head><meta charset="utf-8"><title>probe</title></head>
<body><h1>probe</h1>
<script>
window.__probe = {errors: [], events: [], bc_page: [], sw_state: null,
                  worker_msg: null, blob_msg: null, subtle: null, tok: "PROBE1"};
function ev(k, v) { window.__probe.events.push(k + "=" + v); }
try {
  const bc = new BroadcastChannel("__privadb_probe__");
  bc.onmessage = (e) => {
    window.__probe.bc_page.push(String(e.data));
    if (window.__probe.worker_msg === null) window.__probe.worker_msg = String(e.data);
  };
  ev("bc_listener", "ok");
} catch (e) { window.__probe.errors.push("bc: " + e); }

// Q1/Q3: dedicated worker with route marker
try {
  const w = new Worker("/w.js?__privadb_tok=PROBE1");
  w.onmessage = (e) => {
    window.__probe.events.push("worker_msg:" + String(e.data));
    if (String(e.data).indexOf("w-prelude") === 0)
      window.__probe.worker_msg = String(e.data);
  };
  w.onerror = (e) => window.__probe.errors.push("worker error: " + (e.message || e));
  ev("worker_spawned", "ok");
} catch (e) { window.__probe.errors.push("worker: " + e); }

// Q6: blob bootstrap + importScripts fallback
try {
  const blob = new Blob(
    ['self.__BLOBPRE = "yes"; importScripts("/w2.js?x=" + Date.now());'],
    {type: "text/javascript"});
  const burl = URL.createObjectURL(blob);
  const w2 = new Worker(burl);
  w2.onmessage = (e) => {
    window.__probe.events.push("blob_msg:" + String(e.data));
    window.__probe.blob_msg = String(e.data);
  };
  w2.onerror = (e) => window.__probe.errors.push("blobworker error: " + (e.message || e));
  ev("blob_worker_spawned", "ok");
} catch (e) { window.__probe.errors.push("blobworker: " + e); }

// Q2/Q3/Q7: service worker with route marker
(async () => {
  try {
    const reg = await navigator.serviceWorker.register("/sw.js?__privadb_tok=PROBE1");
    ev("sw_registered", "ok");
    for (let i = 0; i < 40 && !(reg && reg.active); i++) await new Promise(r => setTimeout(r, 100));
    window.__probe.sw_state = reg && reg.active ? reg.active.state : "none";
    ev("sw_active", window.__probe.sw_state);
    if (reg && reg.active) {
      const done = new Promise((res) => {
        const bc2 = new BroadcastChannel("__privadb_probe__");
        bc2.onmessage = (e) => { if (String(e.data).indexOf("sw-") === 0) res(String(e.data)); };
        setTimeout(() => res("sw-timeout"), 3000);
      });
      reg.active.postMessage({cmd: "probe-exfil"});
      const r = await done;
      window.__probe.events.push("sw_reply:" + r);
    }
  } catch (e) { window.__probe.errors.push("sw: " + e); }
  // Q8: crypto.subtle in window (baseline) — worker variant checked in w.js
  try {
    const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode("abc"));
    window.__probe.subtle = Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, "0")).join("").slice(0, 8);
  } catch (e) { window.__probe.subtle = "err:" + e; }
  document.title = "probe-done";
})();
</script></body></html>
"""

WJS = r"""
self.onmessage = () => {};
postMessage("w-prelude=" + (self.__PRIVADB_PRELUDE || "none"));
postMessage("w-bc=" + (self.__PRIVADB_BC || "none"));
try { new BroadcastChannel("__privadb_probe__").postMessage("worker-bc-hello"); }
catch (e) { postMessage("w-bcerr=" + e); }
try {
  fetch("/wfetch?x=1").then(r => r.text()).then(() => postMessage("w-fetch=ok"))
      .catch(e => postMessage("w-fetch=err:" + e));
} catch (e) { postMessage("w-fetch=throw:" + e); }
try {
  crypto.subtle.digest("SHA-256", new TextEncoder().encode("abc")).then(b => {
    const h = Array.from(new Uint8Array(b)).map(x => x.toString(16).padStart(2, "0")).join("");
    postMessage("w-subtle=" + h.slice(0, 8));
  }).catch(e => postMessage("w-subtle=err:" + e));
} catch (e) { postMessage("w-subtle=throw:" + e); }
"""

W2JS = r"""
postMessage("w2-ran pre=" + (self.__BLOBPRE || "none"));
"""

SWJS = r"""
self.addEventListener("install", (e) => { self.skipWaiting(); });
self.addEventListener("activate", (e) => {
  e.waitUntil((async () => {
    try { await self.clients.claim(); } catch (e) {}
    try {
      await fetch("/swact?prelude=" + encodeURIComponent(self.__PRIVADB_PRELUDE || "none"));
    } catch (e) {}
    try { new BroadcastChannel("__privadb_probe__").postMessage("sw-activated prelude=" + (self.__PRIVADB_PRELUDE || "none")); }
    catch (e) {}
  })());
});
self.addEventListener("message", (e) => {
  const bc = new BroadcastChannel("__privadb_probe__");
  if (e.data && e.data.cmd === "probe-exfil") {
    bc.postMessage("sw-msg-received");
    fetch("/svfetch?x=1").then(() => bc.postMessage("sw-fetch=ok"))
      .catch((err) => bc.postMessage("sw-fetch=err:" + err));
  }
});
"""


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        with lock:
            hits.append(self.path)
        body, ctype = None, "text/plain"
        if self.path.startswith("/index"):
            body, ctype = INDEX.encode(), "text/html; charset=utf-8"
        elif self.path.startswith("/w.js"):
            body, ctype = WJS.encode(), "application/javascript"
        elif self.path.startswith("/w2.js"):
            body, ctype = W2JS.encode(), "application/javascript"
        elif self.path.startswith("/sw.js"):
            body, ctype = SWJS.encode(), "application/javascript"
        else:
            body = b'{"ok":true}'
            ctype = "application/json"
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

    route_log = []
    all_requests = []
    consoles = []

    env = os.environ.copy()
    env["DBUS_SYSTEM_BUS_ADDRESS"] = "unix:path=/dev/null"
    env["DBUS_SESSION_BUS_ADDRESS"] = "unix:path=/dev/null"
    env["MOZ_NO_REMOTE"] = "1"
    env.setdefault("DISPLAY", ":99")

    print(f"### STEP 03 | PURPOSE | worker/SW injection probe (headless foxhound) | port={PORT}")
    print(f"foxhound bin: {FOXHOUND}")

    async with async_playwright() as pw:
        browser = await pw.firefox.launch(
            headless=True,
            executable_path=FOXHOUND,
            args=["-new-instance", "-width", "1920", "-height", "1080"],
            env=env,
            firefox_user_prefs={"security.csp.enable": False},
            timeout=60000,
        )
        ctx = await browser.new_context(ignore_https_errors=True, no_viewport=True)

        async def route_handler(route):
            req = route.request
            entry = {"url": req.url, "method": req.method, "resource": req.resource_type}
            try:
                resp = await route.fetch()
                body = await resp.body()
                entry["status"] = resp.status
                entry["orig_len"] = len(body)
                prelude = (
                    "/*__PRIVADB_PRELUDE*/\n"
                    "self.__PRIVADB_PRELUDE = 'ROUTE_OK';\n"
                    "try { self.__PRIVADB_BC = 'yes'; } catch (e) {}\n"
                ).encode()
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

        import re
        await ctx.route(re.compile(r"[?&]__privadb_tok="), route_handler)
        ctx.on("request", lambda r: all_requests.append(
            {"url": r.url, "type": r.resource_type,
             "frame": (r.frame.url if r.frame else None)}))
        ctx.on("requestfailed", lambda r: all_requests.append(
            {"url": r.url, "type": r.resource_type, "failed": r.failure}))

        page = await ctx.new_page()
        page.on("console", lambda m: consoles.append(f"{m.type}: {m.text}"))

        await page.goto(f"http://localhost:{PORT}/index.html",
                        wait_until="domcontentloaded", timeout=30000)
        for _ in range(30):
            t = await page.title()
            if t == "probe-done":
                break
            await page.wait_for_timeout(300)
        await page.wait_for_timeout(2500)

        probe = await page.evaluate("window.__probe")
        await browser.close()

    srv.shutdown()

    result = {
        "probe": probe,
        "route_log": route_log,
        "server_hits": sorted(set(hits)),
        "requests": all_requests,
        "consoles": consoles[:50],
        "verdicts": {},
    }
    # verdicts
    def has(prefix):
        return any(h.startswith(prefix) for h in hits)
    v = result["verdicts"]
    v["Q1_route_saw_worker_script"] = any(
        "w.js" in (e.get("url") or "") for e in route_log)
    v["Q2_route_saw_sw_script"] = any(
        "sw.js" in (e.get("url") or "") for e in route_log)
    worker_ev = (probe or {}).get("worker_msg") or ""
    v["Q3a_prelude_ran_in_worker"] = worker_ev.startswith("w-prelude=ROUTE_OK")
    v["Q3b_prelude_ran_in_sw"] = any("prelude=ROUTE_OK" in h for h in hits)
    v["Q4_worker_request_seen_by_context"] = any(
        "wfetch" in (r.get("url") or "") for r in all_requests)
    v["Q4b_worker_request_reached_server"] = has("/wfetch")
    bc = (probe or {}).get("bc_page") or []
    v["Q5_bc_worker_to_page"] = any("worker-bc-hello" in str(x) for x in bc)
    v["Q5b_bc_sw_to_page"] = any("sw-activated" in str(x) for x in bc)
    v["Q6_blob_importscripts_worker"] = str((probe or {}).get("blob_msg") or "").startswith("w2-ran")
    v["Q7_sw_activated"] = (probe or {}).get("sw_state") == "active"
    v["Q7b_sw_message_roundtrip"] = any("sw_reply:sw-msg-received" == e for e in (probe or {}).get("events", []))
    v["Q7c_sw_fetch_reached_server"] = has("/svfetch")
    v["Q8_subtle_in_window"] = str((probe or {}).get("subtle") or "").startswith(("8", "a", "b", "c", "d", "e", "f")) and "err" not in str((probe or {}).get("subtle"))

    out = os.path.join(os.path.dirname(__file__), "..", "raw", "03-worker-injection-probe.json")
    with open(out, "w") as f:
        json.dump(result, f, indent=2, default=str)
    print(json.dumps(result["verdicts"], indent=2))
    print("\nprobe events:", json.dumps((probe or {}).get("events"), indent=1))
    print("errors:", json.dumps((probe or {}).get("errors"), indent=1))
    print("route_log:", json.dumps(route_log, indent=1))
    print("server hits:", sorted(set(hits)))
    print(f"\nfull → {os.path.abspath(out)}")
    srv_ok = all(v.values()) if False else None
    failed = [k for k, val in v.items() if not val]
    print(f"FAILED verdicts: {failed if failed else 'none'}")
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
