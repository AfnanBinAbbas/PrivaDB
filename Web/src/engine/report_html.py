#!/usr/bin/env python3
"""
HTML report rendering (Phase 12) — standalone, standards-compliant
single-scan and bulk reports with embedded GRC compliance results.

Standards followed:
  * HTML5 semantics: DOCTYPE, lang, charset+viewport meta, header/nav/
    main/section/article/footer landmarks, heading hierarchy
  * WCAG-oriented: skip-link, table <caption> + <th scope>, status
    conveyed by TEXT (not colour alone), high-contrast palette,
    works with JavaScript disabled (zero JS; native <details>)
  * Print: @media print styles, forced page-breaks before sections
  * Evidence: per-site reports show the LEAKED VALUES in clear (clipped
    to 140 chars) next to their SHA-256:16 hash, each row carrying its
    source (IDB record / taint source / storage) and sink (destination
    URL / write target). Treat per-site reports as SENSITIVE. The bulk
    report stays aggregate-only (counts, no values).
  * Provenance: generator + version + generated-at + source run_meta
    + input artifact paths on every report
  * Portability: single self-contained file, no external requests

    render_scan_report(...)   → str (one target)
    render_bulk_report(...)   → str (executive summary of many)
"""

from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

GENERATOR = "PrivaDB report_html.py"
REPORT_VERSION = "1.0"

# ─── styling (embedded; screen + print) ─────────────────────────────
_CSS = """
:root{--bg:#ffffff;--fg:#1a1d21;--muted:#5b6470;--line:#d7dce2;
--accent:#0b5fff;--pass:#0a6b34;--fail:#a4171b;--warn:#8a5a00;
--info:#37506b;--na:#5b6470;--chip:#f2f4f7}
*{box-sizing:border-box}
body{margin:0;font:16px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,
Arial,sans-serif;color:var(--fg);background:var(--bg)}
.skip{position:absolute;left:-9999px}
.skip:focus{left:8px;top:8px;background:#fff;padding:8px 12px;
z-index:9;border:2px solid var(--accent)}
header.masthead{border-bottom:3px solid var(--fg);padding:24px 4vw 16px}
header.masthead h1{margin:0 0 4px;font-size:1.6rem}
header.masthead .sub{color:var(--muted);font-size:.92rem}
.classification{display:inline-block;margin-top:8px;padding:2px 10px;
border:1px solid var(--fg);font-size:.8rem;letter-spacing:.04em;
text-transform:uppercase}
nav.toc{padding:12px 4vw;border-bottom:1px solid var(--line);
background:var(--chip)}
nav.toc a{margin-right:16px;color:var(--accent);font-size:.9rem}
main{padding:8px 4vw 40px;max-width:1100px}
section{margin-top:28px}
h2{font-size:1.25rem;border-bottom:1px solid var(--line);
padding-bottom:6px;margin-top:8px}
h3{font-size:1.02rem;margin-bottom:6px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,
minmax(150px,1fr));gap:10px;padding:0;list-style:none}
.cards li{border:1px solid var(--line);border-radius:8px;padding:10px;
background:var(--chip)}
.cards .num{font-size:1.4rem;font-weight:700}
.cards .lbl{font-size:.78rem;color:var(--muted);text-transform:
uppercase;letter-spacing:.04em}
table{border-collapse:collapse;width:100%;margin:10px 0;font-size:.9rem}
caption{text-align:left;font-weight:600;padding:6px 0;
caption-side:top}
th,td{border:1px solid var(--line);padding:6px 8px;text-align:left;
vertical-align:top}
thead th{background:var(--chip)}
th[scope=row]{font-weight:600;background:#fafbfc}
.status{font-weight:700;white-space:nowrap}
.status.PASS{color:var(--pass)}
.status.FAIL{color:var(--fail)}
.status.WARN{color:var(--warn)}
.status.INFO{color:var(--info)}
.status.NA{color:var(--na)}
.sev{font-size:.8rem;color:var(--muted)}
.hash{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
font-size:.85em}
.leak{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
font-size:.85em;background:#fff7e6;padding:1px 4px;border-radius:3px;
word-break:break-all}
details{margin:8px 0;border:1px solid var(--line);border-radius:6px;
padding:8px 10px}
summary{cursor:pointer;font-weight:600}
pre{white-space:pre-wrap;word-break:break-word;font-size:.78rem;
background:var(--chip);padding:8px;border-radius:6px;overflow:auto}
.gauge{font-size:2rem;font-weight:800}
.gauge.high{color:var(--fail)}.gauge.mid{color:var(--warn)}
.gauge.low{color:var(--pass)}
footer{border-top:3px solid var(--fg);padding:16px 4vw;
color:var(--muted);font-size:.85rem}
footer .disc{border:1px solid var(--line);padding:10px;background:
var(--chip);margin-top:8px;color:var(--fg)}
a{color:var(--accent)}
ul.tight{margin:6px 0;padding-left:20px}
@media print{
 nav.toc,.skip{display:none}
 body{font-size:11pt}
 section{page-break-inside:auto}
 h2{page-break-after:avoid}
 table{page-break-inside:auto}
 tr{page-break-inside:avoid}
 details{border:none}
 details>summary{display:none}
 details[open]{display:block}
 a[href]:after{content:""}
}
"""


def _e(x) -> str:
    return html.escape(str(x if x is not None else ""), quote=True)


def _h(v) -> str:
    """Render an identifier ONLY as a hash (evidence hygiene)."""
    import hashlib
    if v is None or v == "":
        return ""
    return "sha256:" + hashlib.sha256(
        str(v).encode("utf-8", "ignore")).hexdigest()[:16]


def _status_span(status: str) -> str:
    cls = {"N/A": "NA"}.get(status, status)
    return f'<span class="status {cls}">{_e(status)}</span>'


def _fmt_dt(ts=None) -> str:
    if ts is None:
        return datetime.now(timezone.utc).isoformat(timespec="seconds")
    return str(ts)


def _head(title: str, subtitle: str, classification: str) -> str:
    gen = datetime.now(timezone.utc).isoformat(timespec="seconds")
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="generator" content="{_e(GENERATOR)} {_e(REPORT_VERSION)}">
<meta name="description" content="{_e(subtitle)}">
<title>{_e(title)}</title>
<style>{_CSS}</style>
</head>
<body>
<a class="skip" href="#main">Skip to main content</a>
<header class="masthead">
  <h1>{_e(title)}</h1>
  <div class="sub">{_e(subtitle)}</div>
  <div class="sub">Generated {_e(gen)} · {_e(GENERATOR)} v{_e(REPORT_VERSION)}</div>
  <span class="classification">{_e(classification)}</span>
</header>"""


def _toc(items: list[tuple[str, str]]) -> str:
    links = "".join(f'<a href="#{_e(i)}">{_e(t)}</a>' for i, t in items)
    return f'<nav class="toc" aria-label="Report contents">{links}</nav>'


def _footer(extra: str = "") -> str:
    return f"""<footer>
<div>Report version {_e(REPORT_VERSION)} · generator {_e(GENERATOR)} ·
 <strong>sensitive:</strong> this per-site report contains raw leaked
 values (clipped to 140 chars) with their SHA-256:16 hashes and
 source/sink provenance — store and share it accordingly.</div>
{extra}
<div class="disc"><strong>Disclaimer.</strong> This document is an
indicative technical screening produced by an automated measurement
tool. It is not a legal certification, audit opinion, or advice from a
Data Protection Officer. Compliance conclusions must be validated by a
qualified reviewer.</div>
</footer>
</body>
</html>"""


def _analysis_view(analysis: dict) -> dict:
    """Extract the view-model for the measurement sections."""
    exfils = list(analysis.get("exfiltration_events") or [])
    taint = list(analysis.get("taint_flows") or [])
    hooks = list(analysis.get("idb_hook_flows") or [])
    inflow = list(analysis.get("inflow_flows") or [])
    storage = analysis.get("storage_analysis") or {}
    consent = analysis.get("consent_analysis")
    writes = analysis.get("write_attribution") or {}
    idb_sum = analysis.get("indexeddb_summary") or {}
    third_party = [e for e in (exfils + list(
        storage.get("storage_exfiltrations") or []))
        if e.get("is_third_party")]
    all_flow_events = exfils + list(
        storage.get("storage_exfiltrations") or [])
    return {
        "exfils": exfils, "taint": taint, "hooks": hooks,
        "inflow": inflow, "storage": storage, "consent": consent,
        "writes": writes, "idb_sum": idb_sum,
        "third_party": third_party, "all_flow_events": all_flow_events,
        "dynamic": analysis.get("dynamic_flows") or {},
    }


def _cards(view: dict, grc: dict) -> str:
    s = grc.get("summary", {})
    risk = s.get("risk_score", 0)
    gcls = "high" if risk >= 40 else ("mid" if risk >= 15 else "low")
    cards = [
        (str(risk), f"GRC risk /100 ({gcls})"),
        (str(view["idb_sum"].get("database_count", 0)),
         "IndexedDB databases"),
        (str(view["idb_sum"].get("total_records", 0)), "IDB records"),
        (str(len(view["third_party"])), "3rd-party identifier flows"),
        (str(view["dynamic"].get("total", 0)), "Dynamic taint/hook flows"),
        (str(len(view["inflow"])), "Inflow (network→IDB) flows"),
        (str(len(view["storage"].get("respawn_candidates") or [])),
         "Respawn candidates"),
        (f"{s.get('fail', 0)}F/{s.get('warn', 0)}W/{s.get('pass', 0)}P",
         "GRC checks"),
    ]
    items = "".join(
        f'<li><div class="num">{_e(n)}</div>'
        f'<div class="lbl">{_e(l)}</div></li>' for n, l in cards)
    return (f'<ul class="cards" aria-label="Summary metrics">{items}</ul>')


def _grc_section(grc: dict) -> str:
    out = ['<section id="grc" aria-labelledby="grc-h">',
           '<h2 id="grc-h">GRC compliance screening</h2>']
    s = grc.get("summary", {})
    risk = s.get("risk_score", 0)
    gcls = "high" if risk >= 40 else ("mid" if risk >= 15 else "low")
    out.append(
        f'<p><span class="gauge {gcls}">{risk}/100</span> '
        f'&nbsp; risk score (higher = worse) — '
        f'{s.get("pass", 0)} pass · {s.get("fail", 0)} fail · '
        f'{s.get("warn", 0)} warn · {s.get("na", 0)} n/a · '
        f'{s.get("info", 0)} info</p>')

    # framework rollup
    out.append('<table><caption>Framework rollup '
               '(indicative pass rate over evaluated checks)</caption>'
               '<thead><tr><th scope="col">Framework</th>'
               '<th scope="col">Pass</th><th scope="col">Fail</th>'
               '<th scope="col">Warn</th><th scope="col">N/A</th>'
               '<th scope="col">Pass rate</th></tr></thead><tbody>')
    for fw in ("GDPR", "ePrivacy", "CCPA", "ISO27001"):
        roll = (grc.get("frameworks") or {}).get(fw) or {}
        pr = roll.get("pass_rate")
        out.append(
            f'<tr><th scope="row">{_e(fw)}</th>'
            f'<td>{roll.get("pass", 0)}</td>'
            f'<td>{roll.get("fail", 0)}</td>'
            f'<td>{roll.get("warn", 0)}</td>'
            f'<td>{roll.get("na", 0)}</td>'
            f'<td>{"n/a" if pr is None else str(pr) + "%"}</td></tr>')
    out.append('</tbody></table>')

    # checks table
    out.append('<table><caption>Control checks with measured evidence'
               '</caption><thead><tr>'
               '<th scope="col">ID</th><th scope="col">Control</th>'
               '<th scope="col">Status</th>'
               '<th scope="col">Severity</th>'
               '<th scope="col">Evidence (measured)</th>'
               '<th scope="col">Frameworks</th></tr></thead><tbody>')
    for c in grc.get("checks", []):
        fws = "; ".join(f'{f["framework"]}: {f["clause"]}'
                        for f in c.get("frameworks", []))
        sev = (f'<span class="sev">{_e(c["severity"])}</span>'
               if c.get("severity") else '<span class="sev">—</span>')
        out.append(
            f'<tr><th scope="row">{_e(c["id"])}</th>'
            f'<td>{_e(c["title"])}</td>'
            f'<td>{_status_span(c["status"])}</td>'
            f'<td>{sev}</td><td>{_e(c.get("evidence", ""))}</td>'
            f'<td>{_e(fws)}</td></tr>')
    out.append('</tbody></table>')

    # recommendations for non-passing checks
    recs = [c for c in grc.get("checks", [])
            if c["status"] in ("FAIL", "WARN")]
    if recs:
        out.append('<h3>Recommendations</h3><ul class="tight">')
        for c in recs:
            out.append(f'<li><strong>{_e(c["id"])} '
                       f'{_e(c["title"])}:</strong> '
                       f'{_e(c.get("recommendation", ""))}</li>')
        out.append('</ul>')

    ev = grc.get("evidence_inputs") or {}
    out.append(
        '<p class="sev">Evidence inputs: '
        + ", ".join(f'{k}={"yes" if v else "no"}'
                    for k, v in ev.items())
        + ".</p>")
    out.append('</section>')
    return "\n".join(out)


def _val(v) -> str:
    """Leaked value: raw (clipped) + hash side-by-side."""
    s = "" if v is None else str(v)
    clipped = s if len(s) <= 140 else s[:140] + "…"
    return (f'<span class="leak">{_e(clipped)}</span> '
            f'<span class="hash">{_h(s)}</span>')


def _entity_cell(e: dict) -> str:
    ent = e.get("tracker_entity") or {}
    name = ent.get("company") or "—"
    cat = f' {_e("(" + ent["category"] + ")")}' if ent.get("category") else ""
    return f"{_e(name)}{cat}"


def _flow_rows(view: dict) -> list[dict]:
    """Normalise every flow mechanism into one source→value→sink row
    set: exfiltration events, storage exfils, taint flows, IDB-hook
    flows, and inflow (network → storage) flows."""
    rows: list[dict] = []

    for e in view["exfils"]:
        db = e.get("database") or ""
        st = e.get("store") or ""
        rk = e.get("record_key") or ""
        src = (f"IDB {_e(db)}/{_e(st)}/{_e(rk)}".rstrip("/")
               if (db or st or rk)
               else f"IDB {_e(e.get('identifier_path', 'record'))}")
        rows.append({
            "dir": "outflow", "source": src,
            "value": e.get("identifier_value"),
            "sink": f"{_e(e.get('match_location', ''))} → "
                    f"{_e(e.get('request_url', ''))}",
            "mech": _e(e.get("mechanism", "substring")),
            "entity": _entity_cell(e), "tp": e.get("is_third_party"),
            "conf": _e(e.get("confidence", "")),
        })

    for e in (view["storage"].get("storage_exfiltrations") or []):
        stype = e.get("storage_type", "storage")
        rows.append({
            "dir": "outflow",
            "source": f"{_e(stype)} {_e(e.get('store', ''))}"
                      f"/{_e(e.get('record_key', ''))}".rstrip("/"),
            "value": e.get("identifier_value"),
            "sink": f"{_e(e.get('match_location', ''))} → "
                    f"{_e(e.get('request_url', ''))}",
            "mech": _e(stype), "entity": _entity_cell(e),
            "tp": e.get("is_third_party"),
            "conf": _e(e.get("confidence", "")),
        })

    for t in view["taint"]:
        fn = t.get("source_function") or ""
        line = t.get("source_line")
        src = _e(t.get("source_operation", "taint source"))
        if fn:
            src += f' <span class="hash">{_e(fn)}' + (
                f":{_e(line)}</span>" if line is not None else "</span>")
        rows.append({
            "dir": "outflow", "source": src,
            "value": t.get("tainted_value"),
            "sink": f"{_e(t.get('sink', ''))} → {_e(t.get('target', ''))}",
            "mech": "taint", "entity": _entity_cell(t),
            "tp": t.get("is_third_party"),
            "conf": _e(t.get("confidence", "")),
        })

    for h in view["hooks"]:
        fn = h.get("source_function") or ""
        src = f"IDB read {_e(h.get('source_store', ''))}"
        if fn:
            src += f' <span class="hash">via {_e(fn)}</span>'
        sink_fn = h.get("sink_function") or ""
        sink = f"{_e(h.get('sink', ''))} → {_e(h.get('target', ''))}"
        if sink_fn:
            sink += f' <span class="hash">by {_e(sink_fn)}</span>'
        rows.append({
            "dir": "outflow", "source": src,
            "value": h.get("idb_value"), "sink": sink,
            "mech": "idb_hook", "entity": _entity_cell(h),
            "tp": h.get("is_third_party"),
            "conf": _e(h.get("confidence", "")),
        })

    for i in view["inflow"]:
        resp = i.get("response_url") or i.get("request_domain") or ""
        rows.append({
            "dir": "inflow",
            "source": f"network {_e(resp)}",
            "value": i.get("value"),
            "sink": f"{_e(i.get('sink_class', 'IDB write'))} → "
                    f"{_e(i.get('database', ''))}"
                    f"/{_e(i.get('store', ''))}"
                    f"/{_e(i.get('record_key', ''))}".rstrip("/"),
            "mech": _e(i.get("mechanism", "response_match")),
            "entity": _entity_cell(i), "tp": i.get("is_third_party"),
            "conf": _e(i.get("confidence", "")),
        })
    return rows


def _flows_table(view: dict) -> str:
    """Leaked-values table: every flow with its source, raw value
    (clipped + hash) and sink — outflow and inflow side by side."""
    rows = _flow_rows(view)
    if not rows:
        return ('<p>No identifier flows measured in this scan.</p>')
    shown = rows[:150]
    body = "".join(
        "<tr>"
        f'<td>{r["dir"]}</td><td>{r["source"]}</td>'
        f'<td>{_val(r["value"])}</td><td>{r["sink"]}</td>'
        f'<td>{r["mech"]}</td><td>{r["entity"]}</td>'
        f'{"<td>yes</td>" if r["tp"] else "<td>no</td>"}'
        f'<td>{r["conf"]}</td>'
        "</tr>" for r in shown)
    return (
        '<table><caption>Leaked values with source → sink provenance '
        '(raw values clipped to 140 chars + SHA-256:16; '
        f'showing {len(shown)} of {len(rows)})</caption><thead><tr>'
        '<th scope="col">Direction</th>'
        '<th scope="col">Source</th>'
        '<th scope="col">Leaked value (+ hash)</th>'
        '<th scope="col">Sink</th>'
        '<th scope="col">Mechanism</th>'
        '<th scope="col">Entity</th>'
        '<th scope="col">Third party</th>'
        '<th scope="col">Confidence</th></tr></thead><tbody>'
        + body + "</tbody></table>")


def _consent_section(view: dict) -> str:
    ca = view["consent"]
    if not ca:
        return ""
    h = ca.get("headline") or {}
    conds = ca.get("conditions") or {}
    rows = []
    exf = h.get("third_party_exfils") or {}
    for action in sorted(conds):
        c = conds[action]
        rows.append(
            f'<tr><th scope="row">{_e(action)}</th>'
            f'<td>{exf.get(action, 0)}</td>'
            f'<td>{c.get("writes", 0)}</td>'
            f'<td>{c.get("pre_click_writes", 0)}</td>'
            f'<td>{_e(", ".join(map(str, c.get("states", []))))}</td>'
            "</tr>")
    return (
        '<section id="consent" aria-labelledby="consent-h">'
        '<h2 id="consent-h">Consent study</h2>'
        f'<p>Tracking-without-consent verdict: '
        f'<strong>{"YES — observed" if h.get("tracking_without_consent") else "not observed"}</strong> · '
        f'banner detected: <strong>{_e(h.get("banner_detected"))}</strong> '
        f'· pre-consent writes: <strong>{h.get("writes_before_consent", 0)}</strong>'
        f' · post-reject writes: '
        f'<strong>{h.get("writes_after_reject", 0)}</strong></p>'
        '<table><caption>Per-condition measurements</caption><thead><tr>'
        '<th scope="col">Condition</th>'
        '<th scope="col">3rd-party exfils</th>'
        '<th scope="col">IDB writes</th>'
        '<th scope="col">Pre-click writes</th>'
        '<th scope="col">Outcome states</th></tr></thead><tbody>'
        + "".join(rows) + "</tbody></table></section>")


def _storage_section(view: dict) -> str:
    st = view["storage"]
    if not st:
        return ""
    comp = st.get("comparison") or {}
    rows = "".join(
        f'<tr><th scope="row">{_e(k)}</th>'
        f'<td>{v.get("identifiers", 0)}</td>'
        f'<td>{v.get("exfil_events", 0)}</td>'
        f'<td>{v.get("third_party_exfils", 0)}</td></tr>'
        for k, v in sorted(comp.items()))
    resp = st.get("respawn_candidates") or []
    resp_line = ("<p><strong>Respawn candidates:</strong> "
                 f'{len(resp)}'
                 + (f' (cookies: '
                   f'{_e(", ".join(sorted({n for r in resp for n in r.get("cookie_names", [])})))})'
                   if resp else "") + "</p>")
    return (
        '<section id="storage" aria-labelledby="storage-h">'
        '<h2 id="storage-h">Storage comparison (IDB vs other stores)'
        '</h2>'
        '<table><caption>Identifiers and exfiltration per store'
        '</caption><thead><tr><th scope="col">Store</th>'
        '<th scope="col">Identifiers</th>'
        '<th scope="col">Exfil events</th>'
        '<th scope="col">Third-party</th></tr></thead><tbody>'
        + rows + "</tbody></table>" + resp_line + "</section>")


def _writes_section(view: dict) -> str:
    w = view["writes"]
    if not w or not w.get("write_count"):
        return ""
    ws = w.get("writer_stats") or {}
    return (
        '<section id="writes" aria-labelledby="writes-h">'
        '<h2 id="writes-h">Write-side attribution</h2>'
        f'<p>{w.get("write_count", 0)} IDB write(s) observed · '
        f'first-party writers: {ws.get("first_party", 0)} · '
        f'third-party writers: {ws.get("third_party", 0)} · '
        f'unknown: {ws.get("unknown", 0)} · '
        f'pre-consent candidates (≤3s): '
        f'{w.get("pre_consent_candidates", 0)} · '
        f'{w.get("response_count", 0)} response(s) captured for '
        f'inflow provenance.</p></section>')


def render_scan_report(analysis: dict,
                       target_url: str,
                       grc: dict,
                       run_meta: Optional[dict] = None,
                       scan_meta: Optional[dict] = None,
                       sources: Optional[list[str]] = None) -> str:
    """One standalone HTML report for a single scan target."""
    run_meta = run_meta or {}
    scan_meta = scan_meta or {}
    sources = sources or []
    view = _analysis_view(analysis or {})
    domain = urlparse(target_url).netloc or target_url

    toc_items = [
        ("summary", "1. Executive summary"),
        ("grc", "2. GRC compliance"),
        ("findings", "3. Measurement findings"),
        ("consent", "4. Consent study"),
        ("storage", "5. Storage comparison"),
        ("writes", "6. Write attribution"),
        ("method", "7. Methodology & provenance"),
        ("limits", "8. Limitations"),
    ]
    parts = [_head(
        f"PrivaDB scan report — {domain}",
        f"IndexedDB tracking measurement + GRC screening for "
        f"{target_url}",
        "Confidential — contains raw leaked values (sensitive)"),
        _toc(toc_items)]

    # 1 summary
    parts.append(f'<main id="main">')
    parts.append(
        '<section id="summary" aria-labelledby="sum-h">'
        '<h2 id="sum-h">1. Executive summary</h2>'
        f'<p><strong>Target:</strong> {_e(target_url)}<br>'
        f'<strong>Engine:</strong> {_e(run_meta.get("engine", "—"))} '
        f'{_e(run_meta.get("browser_version", ""))}<br>'
        f'<strong>Scan started:</strong> '
        f'{_e(scan_meta.get("started_at", "—"))} · '
        f'<strong>Status:</strong> {_e(scan_meta.get("status", "—"))}'
        '</p>'
        + _cards(view, grc) + "</section>")

    # 2 GRC
    parts.append(_grc_section(grc))

    # 3 findings
    parts.append(
        '<section id="findings" aria-labelledby="find-h">'
        '<h2 id="find-h">3. Measurement findings</h2>'
        f'<p>Exfiltration events: {len(view["exfils"])} · '
        f'third-party flows: {len(view["third_party"])} · '
        f'taint flows: {len(view["taint"])} · '
        f'IDB-hook flows: {len(view["hooks"])} · '
        f'inflow flows: {len(view["inflow"])}.</p>'
        + _flows_table(view) + "</section>")

    # 4 consent / 5 storage / 6 writes (conditional)
    c_sec = _consent_section(view)
    if c_sec:
        parts.append(c_sec)
    else:
        parts.append(
            '<section id="consent"><h2>4. Consent study</h2>'
            '<p>No consent study in this scan — run with '
            '<code>consent_study=true</code> to measure pre-consent/'
            'post-reject behaviour.</p></section>')
    s_sec = _storage_section(view)
    if s_sec:
        # storage section already numbered 5 in heading text? keep ids
        parts.append(s_sec)
    else:
        parts.append(
            '<section id="storage"><h2>5. Storage comparison</h2>'
            '<p>No multi-store capture in this scan.</p></section>')
    w_sec = _writes_section(view)
    if w_sec:
        parts.append(w_sec)
    else:
        parts.append(
            '<section id="writes"><h2>6. Write attribution</h2>'
            '<p>No write-side instrumentation data in this scan.'
            '</p></section>')

    # 7 methodology & provenance
    rm_rows = "".join(
        f'<tr><th scope="row">{_e(k)}</th><td>{_e(v)}</td></tr>'
        for k, v in run_meta.items())
    src_items = "".join(f'<li><span class="hash">{_e(p)}</span></li>'
                        for p in sources)
    parts.append(
        '<section id="method" aria-labelledby="mth-h">'
        '<h2 id="mth-h">7. Methodology &amp; provenance</h2>'
        '<p>Dynamic measurement: fresh browser context per iteration; '
        'IndexedDB/other-store extraction; in-page flow hooks (reads, '
        'writes, network sends, responses); Foxhound taint-export '
        'capture; transform-aware matching (raw/encode/hash variants) '
        'against URL, bodies, all headers and WebSocket frames; PSL + '
        'Disconnect entity attribution; best-effort policy and response '
        'header collection for GRC checks. Confidence labels and '
        'confinement follow the What-Storage paper taxonomy.</p>'
        '<table><caption>Run metadata (run_meta)</caption><tbody>'
        + (rm_rows or '<tr><td>—</td></tr>') +
        '</tbody></table>'
        '<details><summary>Source artifacts</summary><ul class="tight">'
        + (src_items or "<li>—</li>") +
        '</ul></details>'
        '<details><summary>Analysis snapshot (JSON, raw values may appear)'
        '</summary><pre>'
        + _e(json.dumps(
            {k: analysis.get(k) for k in (
                "domain", "url", "timestamp", "indexeddb_summary",
                "dynamic_flows", "flow_classification",
                "exfiltration_summary") if analysis},
            indent=1, default=str)[:20000]) +
        '</pre></details>'
        '</section>')

    # 8 limitations
    parts.append(
        '<section id="limits" aria-labelledby="lim-h">'
        '<h2 id="lim-h">8. Limitations</h2>'
        '<ul class="tight">'
        '<li>Automation fingerprint: sites may behave differently '
        'under Playwright-driven browsers.</li>'
        '<li>Single vantage point (one host/region) — regional '
        'comparisons require tagged repeat runs.</li>'
        '<li>HttpOnly cookies are invisible to in-page capture; '
        'cookie figures are lower bounds.</li>'
        '<li>Foxhound does not taint IndexedDB reads; IDB→network '
        'provenance comes from the in-page hook layer.</li>'
        '<li>Policy- and header-based checks are best-effort and may '
        'be N/A when the target blocks collection.</li>'
        '<li>Per-site reports display raw leaked values (clipped) with '
        'source/sink provenance — treat them as sensitive personal '
        'data; the bulk report contains aggregates only.</li>'
        '</ul></section>')

    parts.append("</main>")
    parts.append(_footer(
        f'<div class="sev">Target: {_e(target_url)} · checks: '
        f'{_e(json.dumps(grc.get("summary", {})))}</div>'))
    return "\n".join(parts)


def render_bulk_report(sites: list[dict]) -> str:
    """
    Executive HTML for many scans.
    sites: [{domain, url, engine, analysis, grc, run_meta}] — grc may
    be None (analysis-only rows still render).
    """
    rows = []
    total_risk = []
    fail_histogram: dict[str, int] = {}
    fw_totals: dict[str, dict] = {f: {"pass": 0, "fail": 0, "warn": 0,
                                      "na": 0, "info": 0}
                                  for f in ("GDPR", "ePrivacy", "CCPA",
                                            "ISO27001")}
    for s in sites:
        analysis = s.get("analysis") or {}
        grc = s.get("grc") or {}
        summ = grc.get("summary") or {}
        risk = summ.get("risk_score")
        if risk is not None:
            total_risk.append(risk)
        for c in grc.get("checks", []):
            if c["status"] == "FAIL":
                fail_histogram[c["id"]] = (
                    fail_histogram.get(c["id"], 0) + 1)
        for fw, roll in (grc.get("frameworks") or {}).items():
            if fw in fw_totals:
                for k in fw_totals[fw]:
                    fw_totals[fw][k] += roll.get(k, 0)
        view = _analysis_view(analysis)
        idb_ok = bool((analysis.get("indexeddb_summary") or {}).get(
            "database_count", 0))
        rows.append(
            "<tr>"
            f'<th scope="row">{_e(s.get("domain") or s.get("url"))}</th>'
            f'<td>{_e(s.get("engine", "—"))}</td>'
            f'<td>{"yes" if idb_ok else "no"}</td>'
            f'<td>{len(view["all_flow_events"])}</td>'
            f'<td>{len(view["third_party"])}</td>'
            f'<td>{len(view["taint"]) + len(view["hooks"])}</td>'
            f'<td>{_e(risk if risk is not None else "n/a")}</td>'
            f'<td>{summ.get("fail", 0)}F/{summ.get("warn", 0)}W</td>'
            "</tr>")

    n = len(sites)
    avg_risk = (round(sum(total_risk) / len(total_risk), 1)
                if total_risk else "n/a")
    worst = max(total_risk) if total_risk else "n/a"
    top_fails = sorted(fail_histogram.items(),
                       key=lambda kv: -kv[1])[:10]
    hist_rows = "".join(
        f'<tr><th scope="row">{_e(cid)}</th><td>{cnt}</td></tr>'
        for cid, cnt in top_fails) or '<tr><td>—</td></tr>'

    toc = [("summary", "1. Executive summary"),
           ("sites", "2. Per-site results"),
           ("grc", "3. GRC aggregates"),
           ("fails", "4. Most frequent failures"),
           ("method", "5. Methodology"),
           ("limits", "6. Limitations")]
    parts = [_head(
        "PrivaDB bulk scan report",
        f"{n} site(s) — IndexedDB tracking measurement + GRC screening",
        "Confidential — research measurement"),
        _toc(toc)]

    total_3p = sum(len(_analysis_view(s.get("analysis") or {}
                                      )["third_party"]) for s in sites)
    with_idb = sum(1 for s in sites if (
        (s.get("analysis") or {}).get("indexeddb_summary") or {}
    ).get("database_count", 0))
    parts.append('<main id="main">')
    parts.append(
        '<section id="summary" aria-labelledby="sum-h">'
        '<h2 id="sum-h">1. Executive summary</h2>'
        f'<p><strong>{n}</strong> site(s) analysed · '
        f'<strong>{with_idb}</strong> with IndexedDB data · '
        f'<strong>{total_3p}</strong> third-party identifier flows '
        f'across the batch · average GRC risk '
        f'<strong>{avg_risk}</strong>/100 (worst <strong>{worst}'
        f'</strong>).</p>'
        '<ul class="cards">'
        f'<li><div class="num">{n}</div><div class="lbl">Sites</div></li>'
        f'<li><div class="num">{with_idb}</div>'
        f'<div class="lbl">With IndexedDB</div></li>'
        f'<li><div class="num">{total_3p}</div>'
        f'<div class="lbl">3rd-party flows</div></li>'
        f'<li><div class="num">{avg_risk}</div>'
        f'<div class="lbl">Avg risk /100</div></li>'
        '</ul></section>')

    parts.append(
        '<section id="sites" aria-labelledby="st-h">'
        '<h2 id="st-h">2. Per-site results</h2>'
        '<table><caption>One row per analysed site (aggregates only — '
        'raw values live in the per-site reports)</caption><thead><tr>'
        '<th scope="col">Domain</th><th scope="col">Engine</th>'
        '<th scope="col">IDB seen</th>'
        '<th scope="col">Identifier flows</th>'
        '<th scope="col">3rd-party</th>'
        '<th scope="col">Dynamic</th>'
        '<th scope="col">Risk /100</th>'
        '<th scope="col">GRC F/W</th></tr></thead><tbody>'
        + ("".join(rows) or '<tr><td colspan="8">—</td></tr>')
        + "</tbody></table></section>")

    fw_rows = "".join(
        f'<tr><th scope="row">{_e(fw)}</th>'
        f'<td>{t["pass"]}</td><td>{t["fail"]}</td>'
        f'<td>{t["warn"]}</td><td>{t["na"]}</td><td>{t["info"]}</td>'
        '</tr>' for fw, t in fw_totals.items())
    parts.append(
        '<section id="grc" aria-labelledby="gr-h">'
        '<h2 id="gr-h">3. GRC aggregates across the batch</h2>'
        '<table><caption>Check outcomes per framework (all sites)'
        '</caption><thead><tr><th scope="col">Framework</th>'
        '<th scope="col">Pass</th><th scope="col">Fail</th>'
        '<th scope="col">Warn</th><th scope="col">N/A</th>'
        '<th scope="col">Info</th></tr></thead><tbody>'
        + fw_rows + "</tbody></table></section>")

    parts.append(
        '<section id="fails" aria-labelledby="fl-h">'
        '<h2 id="fl-h">4. Most frequent control failures</h2>'
        '<table><caption>FAIL count per check id</caption><thead><tr>'
        '<th scope="col">Check</th><th scope="col">Sites failing'
        '</th></tr></thead><tbody>'
        + hist_rows + "</tbody></table></section>")

    parts.append(
        '<section id="method"><h2>5. Methodology</h2>'
        '<p>Each site: fresh browser context, IDB + multi-store '
        'extraction, in-page flow hooks, Foxhound taint capture, '
        'transform-aware matching, entity attribution; GRC checks '
        'computed from the same evidence (headers/policy fetched '
        'best-effort unless stated otherwise). Per-site standalone '
        'reports contain full evidence tables.</p></section>')

    parts.append(
        '<section id="limits"><h2>6. Limitations</h2>'
        '<ul class="tight">'
        '<li>Indicative screening — not legal certification.</li>'
        '<li>Automation fingerprint and single vantage point bound '
        'external validity.</li>'
        '<li>HttpOnly cookies invisible to in-page capture.</li>'
        '<li>N/A outcomes reflect unavailable evidence (policy/'
        'headers/consent study), not compliance.</li>'
        '</ul></section>')

    parts.append("</main>")
    parts.append(_footer(
        f'<div class="sev">{n} site rows · '
        f'{sum(fail_histogram.values())} total FAIL outcomes</div>'))
    return "\n".join(parts)
