"""
Report generator for IndexedDB dynamic taint analysis.

Produces structured JSON, CSV, and numpy tabular console output
suitable for academic research papers.
"""

import csv
import json
import os
import logging
from collections import Counter

import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")  # Non-interactive backend for server/headless
import matplotlib.pyplot as plt

import app_config as config
from detector import compute_paper_metrics

logger = logging.getLogger(__name__)


# ─── Table formatting helpers ────────────────────────────────────────
def count_crawled_sites(results_dir: str = None) -> int:
    """Count unique domains from crawled directories of both engines."""
    if results_dir is None:
        results_dir = config.RESULTS_DIR
    chrome_crawled = os.path.join(results_dir, "Chrome", "crawled")
    foxhound_crawled = os.path.join(results_dir, "Foxhound", "crawled")
    domains = set()
    
    def extract_domain(filename: str) -> str:
        if filename.endswith('.json'):
            filename = filename[:-5]
        return filename.replace('_', '.')
    
    if os.path.isdir(chrome_crawled):
        for f in os.listdir(chrome_crawled):
            if f.endswith('.json'):
                domains.add(extract_domain(f))
    if os.path.isdir(foxhound_crawled):
        for f in os.listdir(foxhound_crawled):
            if f.endswith('.json'):
                domains.add(extract_domain(f))
    return len(domains)
    
def _print_table(title: str, headers: list[str], rows: list[list],
                 col_aligns: list[str] = None):
    """
    Print a formatted table using numpy arrays.

    Args:
        title:      Table title
        headers:    Column header names
        rows:       List of rows (each row is a list of values)
        col_aligns: Per-column alignment: 'l' (left), 'r' (right), 'c' (center)
                    Defaults to left for first column, right for rest.
    """
    if not rows:
        print(f"\n  {title}")
        print("  (no data)\n")
        return

    num_cols = len(headers)
    if col_aligns is None:
        col_aligns = ['l'] + ['r'] * (num_cols - 1)

    # Convert all values to strings via numpy for uniform processing
    str_rows = [[str(v) for v in row] for row in rows]
    all_rows = [headers] + str_rows
    data = np.array(all_rows, dtype=object)

    # Calculate column widths (max length per column)
    col_widths = np.array([
        max(len(str(data[r, c])) for r in range(data.shape[0]))
        for c in range(num_cols)
    ])
    # Add padding
    col_widths = col_widths + 2

    total_width = int(np.sum(col_widths)) + num_cols + 1

    # Format a single row
    def fmt_row(values, aligns):
        cells = []
        for val, w, align in zip(values, col_widths, aligns):
            w = int(w)
            s = str(val)
            if align == 'r':
                cells.append(s.rjust(w))
            elif align == 'c':
                cells.append(s.center(w))
            else:
                cells.append(s.ljust(w))
        return "|" + "|".join(cells) + "|"

    # Print
    separator = "+" + "+".join("-" * int(w) for w in col_widths) + "+"
    print(f"\n  {title}")
    print("  " + separator)
    print("  " + fmt_row(headers, ['c'] * num_cols))  # headers centered
    print("  " + separator)
    for row in str_rows:
        print("  " + fmt_row(row, col_aligns))
    print("  " + separator)


def generate_reports(analysis_results: list[dict]):
    """
    Generate all report formats from analysis results.

    Outputs:
    - results/summary.json      — full structured results
    - results/tracking_events.csv — one row per exfiltration event
    - results/statistics.json    — aggregate counts + paper metrics
    - Console tables (numpy)
    """
    os.makedirs(config.RESULTS_DIR, exist_ok=True)
    os.makedirs(config.ANALYSIS_DIR, exist_ok=True)
    os.makedirs(config.CHARTS_DIR, exist_ok=True)

    _write_summary_json(analysis_results)
    _write_tracking_csv(analysis_results)
    _write_per_site_json(analysis_results)
    paper_metrics = compute_paper_metrics(analysis_results)
    total_crawled_sites = count_crawled_sites()  # new
    stats = _write_statistics_json(analysis_results, paper_metrics, total_crawled_sites)
    _generate_charts(analysis_results, stats, paper_metrics)
    _print_console_summary(analysis_results, stats, paper_metrics, total_crawled_sites)

def _write_summary_json(results: list[dict]):
    """Write the full structured results to JSON."""
    path = os.path.join(config.ANALYSIS_DIR, "summary.json")

    # Strip the full identifier lists for the summary (keep exfiltrations)
    summary = []
    for r in results:
        entry = {k: v for k, v in r.items() if k != "identifiers"}
        entry["identifiers_found"] = r.get("identifiers_found", 0)
        summary.append(entry)

    with open(path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False, default=str)
    logger.info(f"📄 Summary JSON → {path}")


def _write_tracking_csv(results: list[dict]):
    """Write one row per exfiltration event to CSV."""
    path = os.path.join(config.ANALYSIS_DIR, "tracking_events.csv")

    fieldnames = [
        "site_domain",
        "site_url",
        "flow_direction",
        "confinement",
        "cross_origin",
        "source_class",
        "sink_class",
        "database",
        "store",
        "record_key",
        "identifier_key",
        "identifier_value",
        "identifier_value_hash",
        "identifier_reason",
        "identifier_entropy",
        "changed_across_iterations",
        "tracker_domain",
        "request_url",
        "request_method",
        "request_domain",
        "match_location",
        "is_third_party",
        "is_known_tracker",
        "confidence",
    ]

    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for r in results:
            domain = r.get("domain", "")
            url = r.get("url", "")

            # Outflow flows (exfiltrations)
            for evt in r.get("exfiltration_events", []):
                import hashlib
                val = evt.get("identifier_value", "")
                val_hash = hashlib.sha256(val.encode()).hexdigest()[:16]
                # Extract the IDB key name from the reason (e.g. "idb_key:userId")
                reason = evt.get("identifier_reason", "")
                idb_key = reason.split(":", 1)[1] if ":" in reason else reason
                # Tracker domain = request domain if it's a known tracker
                req_domain = evt.get("request_domain", "")
                tracker = req_domain if evt.get("is_known_tracker") else ""

                writer.writerow({
                    "site_domain": domain,
                    "site_url": url,
                    "flow_direction": evt.get("flow_direction", "outflow"),
                    "confinement": evt.get("confinement", ""),
                    "cross_origin": evt.get("cross_origin", ""),
                    "source_class": evt.get("source_class", ""),
                    "sink_class": evt.get("sink_class", ""),
                    "database": evt.get("database", ""),
                    "store": evt.get("store", ""),
                    "record_key": evt.get("record_key", ""),
                    "identifier_key": idb_key,
                    "identifier_value": val,
                    "identifier_value_hash": val_hash,
                    "identifier_reason": reason,
                    "identifier_entropy": round(evt.get("identifier_entropy", 0), 2),
                    "changed_across_iterations": evt.get("changed_across_iterations", ""),
                    "tracker_domain": tracker,
                    "request_url": evt.get("request_url", ""),
                    "request_method": evt.get("request_method", ""),
                    "request_domain": req_domain,
                    "match_location": evt.get("match_location", ""),
                    "is_third_party": evt.get("is_third_party", False),
                    "is_known_tracker": evt.get("is_known_tracker", False),
                    "confidence": evt.get("confidence", ""),
                })

            # Inflow flows
            for iflow in r.get("inflow_flows", []):
                import hashlib
                val = iflow.get("value", "")
                val_hash = hashlib.sha256(val.encode()).hexdigest()[:16]

                writer.writerow({
                    "site_domain": domain,
                    "site_url": url,
                    "flow_direction": "inflow",
                    "confinement": iflow.get("confinement", "internal"),
                    "cross_origin": iflow.get("cross_origin", ""),
                    "source_class": iflow.get("source_class", ""),
                    "sink_class": iflow.get("sink_class", "IDBObjectStore.put"),
                    "database": iflow.get("database", ""),
                    "store": iflow.get("store", ""),
                    "record_key": iflow.get("record_key", ""),
                    "identifier_key": "",
                    "identifier_value": val,
                    "identifier_value_hash": val_hash,
                    "identifier_reason": "inflow_source",
                    "identifier_entropy": 0,
                    "changed_across_iterations": "",
                    "tracker_domain": "",
                    "request_url": "",
                    "request_method": "",
                    "request_domain": "",
                    "match_location": iflow.get("source_class", ""),
                    "is_third_party": False,
                    "is_known_tracker": False,
                    "confidence": "",
                })

    logger.info(f"📊 Tracking events CSV → {path}")


# ─── Per-Site JSON Output (TS pipeline format) ──────────────────────
def _find_status_code(target_url: str, network_requests: list) -> int | None:
    """Find the HTTP status code for a given URL from captured requests."""
    for req in network_requests:
        if req.get("url") == target_url:
            resp = req.get("response")
            if isinstance(resp, dict):
                return resp.get("status")
    return None


def _map_sink_name(evt: dict) -> str:
    """
    Map internal match_location / sink_class to Foxhound-style sink names.

    Examples: "fetch.url", "script.src", "document.cookie", "XMLHttpRequest.send"
    """
    loc = evt.get("match_location", "")
    sink_class = evt.get("sink_class", "")

    # Taint-confirmed events carry the real sink name already
    if loc.startswith("taint:"):
        return loc.replace("taint:", "")

    # Map from match_location
    if loc in ("url", "url_decoded"):
        method = evt.get("request_method", "GET").upper()
        if method in ("POST", "PUT", "PATCH"):
            return "XMLHttpRequest.open(url)"
        return "fetch.url"
    if loc in ("post_body", "post_body_decoded"):
        return "fetch.body"
    if "header:cookie" in loc:
        return "document.cookie"

    # Fallback to sink_class
    sink_map = {
        "fetch_url": "fetch.url",
        "fetch_body": "fetch.body",
        "xhr_url": "XMLHttpRequest.open(url)",
        "xhr_body": "XMLHttpRequest.send",
        "header_cookie": "document.cookie",
        "sendbeacon": "navigator.sendBeacon(url)",
        "img_src": "img.src",
        "script_src": "script.src",
    }
    return sink_map.get(sink_class, evt.get("request_method", "GET"))


def _write_per_site_json(results: list[dict]):
    """
    Write per-site JSON files and combined_results.json matching the TS pipeline format.

    Each exfiltration event is transformed to:
        {databaseName, key, value, source, sink, statusCode, domain, requestUrl}
    """
    combined: dict[str, list[dict]] = {}

    for r in results:
        domain = r.get("domain", "unknown")
        network = r.get("network_requests", [])
        entries = []

        for evt in r.get("exfiltration_events", []):
            db_name = evt.get("database", "")
            if not db_name:
                # Fallback: extract from identifier_path  "db/store/key"
                path_parts = evt.get("identifier_path", "").split("/")
                db_name = path_parts[0] if path_parts else ""

            # Build the IDB key in "db/store/record_key" format
            store = evt.get("store", "")
            record_key = evt.get("record_key", "")
            if store or record_key:
                idb_key = f"{db_name}/{store}/{record_key}"
            else:
                idb_key = evt.get("identifier_path", "")

            status_code = _find_status_code(evt.get("request_url", ""), network)

            entries.append({
                "databaseName": db_name,
                "key": idb_key,
                "value": evt.get("identifier_value", ""),
                "source": "IndexedDB",
                "sink": _map_sink_name(evt),
                "statusCode": status_code if status_code is not None else 200,
                "domain": domain,
                "requestUrl": evt.get("request_url", ""),
            })

        if entries:
            combined[domain] = entries

            # Write individual site JSON
            safe_domain = domain.replace(".", "_").replace("/", "_")
            site_path = os.path.join(config.ANALYSIS_DIR, f"{safe_domain}.json")
            with open(site_path, "w", encoding="utf-8") as f:
                json.dump(entries, f, indent=2, ensure_ascii=False, default=str)

    # Write combined results
    combined_path = os.path.join(config.ANALYSIS_DIR, "combined_results.json")
    with open(combined_path, "w", encoding="utf-8") as f:
        json.dump(combined, f, indent=2, ensure_ascii=False, default=str)

    logger.info(
        f"📁 Per-site JSON → {config.ANALYSIS_DIR}/ "
        f"({len(combined)} sites with data)"
    )
    logger.info(f"📁 Combined results → {combined_path}")


def _write_statistics_json(results: list[dict],
                           paper_metrics: dict,
                           total_crawled_sites: int) -> dict:
    """Write aggregate statistics + paper metrics to JSON. Returns stats."""
    path = os.path.join(config.ANALYSIS_DIR, "statistics.json")

    total_sites = len(results)
    total_identifiers = sum(r.get("identifiers_found", 0) for r in results)

    # Exfiltration stats
    all_events = [e for r in results for e in r.get("exfiltration_events", [])]
    total_exfils = len(all_events)
    high = sum(1 for e in all_events if e.get("confidence") == config.CONFIDENCE_HIGH)
    med = sum(1 for e in all_events if e.get("confidence") == config.CONFIDENCE_MEDIUM)
    low = sum(1 for e in all_events if e.get("confidence") == config.CONFIDENCE_LOW)

    third_party_exfils = sum(1 for e in all_events if e.get("is_third_party"))
    known_tracker_exfils = sum(1 for e in all_events if e.get("is_known_tracker"))

    # Top tracker domains
    tracker_domains = Counter(
        e.get("request_domain", "")
        for e in all_events
        if e.get("is_third_party")
    )

    # Identifier type distribution
    id_reasons = Counter(e.get("identifier_reason", "") for e in all_events)

    # Sites with exfiltrations
    sites_with_exfils = sum(
        1 for r in results
        if r.get("exfiltration_summary", {}).get("total", 0) > 0
    )
    sites_with_high_conf = sum(
        1 for r in results
        if r.get("exfiltration_summary", {}).get("high_confidence", 0) > 0
    )

    # Inflow flow stats
    all_integrity = [f for r in results for f in r.get("inflow_flows", [])]
    total_integrity = len(all_integrity)
    sites_with_integrity = sum(
        1 for r in results if len(r.get("inflow_flows", [])) > 0
    )

    stats = {
        "crawl_summary": {
            "total_crawled_sites": total_crawled_sites,
            "total_sites_analyzed": total_sites,
        },
        "detection_summary": {
            "total_potential_identifiers": total_identifiers,
            "total_exfiltration_events": total_exfils,
            "third_party_exfiltrations": third_party_exfils,
            "known_tracker_exfiltrations": known_tracker_exfils,
            "total_inflow_flows": total_integrity,
            "sites_with_inflow_flows": sites_with_integrity,
        },
        "confidence_breakdown": {
            "high": high,
            "medium": med,
            "low": low,
        },
        "site_classification": {
            "sites_with_any_exfiltration": sites_with_exfils,
            "sites_with_high_confidence_tracking": sites_with_high_conf,
        },
        "top_tracker_domains": dict(tracker_domains.most_common(20)),
        "identifier_type_distribution": dict(id_reasons.most_common(10)),
        "paper_metrics": paper_metrics,
    }

    with open(path, "w", encoding="utf-8") as f:
        json.dump(stats, f, indent=2)
    logger.info(f"📈 Statistics JSON → {path}")

    return stats


def _generate_charts(results: list[dict], stats: dict, paper_metrics: dict):
    """Generate matplotlib charts and save to results directory."""
    charts_dir = config.CHARTS_DIR

    # Use a clean academic style
    plt.style.use("seaborn-v0_8-whitegrid")
    colors = ["#e74c3c", "#f39c12", "#2ecc71", "#3498db", "#9b59b6",
              "#1abc9c", "#e67e22", "#34495e", "#7f8c8d", "#c0392b"]

    # ── Chart 1: Confidence Distribution (Pie) ─────────────────────
    conf = stats["confidence_breakdown"]
    if any(v > 0 for v in conf.values()):
        fig, ax = plt.subplots(figsize=(8, 6))
        labels = ["HIGH", "MEDIUM", "LOW"]
        sizes = [conf["high"], conf["medium"], conf["low"]]
        pie_colors = ["#e74c3c", "#f39c12", "#2ecc71"]
        wedges, texts, autotexts = ax.pie(
            sizes, labels=labels, colors=pie_colors, autopct="%1.1f%%",
            startangle=90, textprops={"fontsize": 12, "fontweight": "bold"},
        )
        ax.set_title("Exfiltration Confidence Distribution",
                     fontsize=14, fontweight="bold", pad=20)
        plt.tight_layout()
        path = os.path.join(charts_dir, "confidence_distribution.png")
        fig.savefig(path, dpi=150, bbox_inches="tight")
        plt.close(fig)
        logger.info(f"📊 Chart → {path}")

    # ── Chart 2: Top Tracker Domains (Horizontal Bar) ──────────────
    top_trackers = stats.get("top_tracker_domains", {})
    if top_trackers:
        fig, ax = plt.subplots(figsize=(10, 6))
        items = list(top_trackers.items())[:10]
        domains = [d for d, _ in items]
        counts = [c for _, c in items]
        y_pos = range(len(domains))
        ax.barh(y_pos, counts, color=colors[:len(domains)], edgecolor="white")
        ax.set_yticks(y_pos)
        ax.set_yticklabels(domains, fontsize=10)
        ax.invert_yaxis()
        ax.set_xlabel("Number of Exfiltration Events", fontsize=12)
        ax.set_title("Top 10 Third-Party Tracker Domains",
                     fontsize=14, fontweight="bold")
        for i, v in enumerate(counts):
            ax.text(v + 0.3, i, str(v), va="center", fontsize=10,
                    fontweight="bold")
        plt.tight_layout()
        path = os.path.join(charts_dir, "top_trackers.png")
        fig.savefig(path, dpi=150, bbox_inches="tight")
        plt.close(fig)
        logger.info(f"📊 Chart → {path}")

    # ── Chart 3: Confinement Analysis (Pie) ────────────────────────
    t3 = paper_metrics["table_iii_confinement"]
    internal = t3["internal"]["total"]
    external = t3["external"]["total"]
    if internal + external > 0:
        fig, ax = plt.subplots(figsize=(8, 6))
        ax.pie([internal, external],
               labels=["Internal\n(Confined)", "External\n(Escaped)"],
               colors=["#2ecc71", "#e74c3c"],
               autopct="%1.1f%%", startangle=90,
               textprops={"fontsize": 12, "fontweight": "bold"})
        ax.set_title("Confinement Analysis — Internal vs External Flows",
                     fontsize=14, fontweight="bold", pad=20)
        plt.tight_layout()
        path = os.path.join(charts_dir, "confinement_analysis.png")
        fig.savefig(path, dpi=150, bbox_inches="tight")
        plt.close(fig)
        logger.info(f"📊 Chart → {path}")

    # ── Chart 4: Flow Overview (Stacked Bar) ───────────────────────
    ov = paper_metrics["overview"]
    if ov["total_flows"] > 0:
        fig, ax = plt.subplots(figsize=(8, 5))
        categories = ["Outflow", "Inflow"]
        values = [ov["outflow_flows"], ov["inflow_flows"]]
        bars = ax.bar(categories, values,
                      color=["#3498db", "#e67e22"], edgecolor="white",
                      width=0.5)
        ax.set_ylabel("Number of Flows", fontsize=12)
        ax.set_title("Information Flow Direction — Outflow vs Inflow",
                     fontsize=14, fontweight="bold")
        for bar, val in zip(bars, values):
            ax.text(bar.get_x() + bar.get_width()/2., bar.get_height() + 2,
                    f"{val}\n({val/ov['total_flows']*100:.1f}%)",
                    ha="center", va="bottom", fontsize=11, fontweight="bold")
        plt.tight_layout()
        path = os.path.join(charts_dir, "flow_direction.png")
        fig.savefig(path, dpi=150, bbox_inches="tight")
        plt.close(fig)
        logger.info(f"📊 Chart → {path}")

    # ── Chart 5: External Flows — Same-site vs Cross-site (Pie) ───
    t4 = paper_metrics["table_iv_external_breakdown"]
    same = t4["same_site"]["outflow"]
    cross = t4["cross_site"]["outflow"]
    if same + cross > 0:
        fig, ax = plt.subplots(figsize=(8, 6))
        ax.pie([same, cross],
               labels=["Same-site", "Cross-site"],
               colors=["#f39c12", "#9b59b6"],
               autopct="%1.1f%%", startangle=90,
               textprops={"fontsize": 12, "fontweight": "bold"})
        ax.set_title("External Flows — Same-site vs Cross-site",
                     fontsize=14, fontweight="bold", pad=20)
        plt.tight_layout()
        path = os.path.join(charts_dir, "cross_site_breakdown.png")
        fig.savefig(path, dpi=150, bbox_inches="tight")
        plt.close(fig)
        logger.info(f"📊 Chart → {path}")

    # ── Chart 6: Identifier Types (Bar) ────────────────────────────
    id_types = stats.get("identifier_type_distribution", {})
    if id_types:
        fig, ax = plt.subplots(figsize=(10, 5))
        types = list(id_types.keys())[:8]
        counts = [id_types[t] for t in types]
        # Clean labels
        clean_labels = [t.replace("tracking_key_name:", "key:") for t in types]
        bars = ax.bar(clean_labels, counts,
                      color=colors[:len(types)], edgecolor="white")
        ax.set_ylabel("Count", fontsize=12)
        ax.set_title("Identifier Type Distribution",
                     fontsize=14, fontweight="bold")
        ax.set_xticks(range(len(clean_labels)))
        ax.set_xticklabels(clean_labels, rotation=35, ha="right", fontsize=10)
        for bar, val in zip(bars, counts):
            ax.text(bar.get_x() + bar.get_width()/2., bar.get_height() + 0.5,
                    str(val), ha="center", va="bottom", fontsize=10,
                    fontweight="bold")
        plt.tight_layout()
        path = os.path.join(charts_dir, "identifier_types.png")
        fig.savefig(path, dpi=150, bbox_inches="tight")
        plt.close(fig)
        logger.info(f"📊 Chart → {path}")

    # ── Chart 7: 3D Tracking Landscape (Scatter) ──────────────────
    try:
        from mpl_toolkits.mplot3d import Axes3D
        all_events = [e for r in results for e in r.get("exfiltration_events", [])]
        if len(all_events) >= 3:
            fig = plt.figure(figsize=(12, 8))
            ax = fig.add_subplot(111, projection='3d')
            
            # X: Site Index, Y: Tracker Index, Z: Confidence Score
            unique_sites = list(set(r.get("domain", "unknown") for r in results))
            unique_trackers = list(set(e.get("request_domain", "unknown") for e in all_events))
            
            site_map = {s: i for i, s in enumerate(unique_sites)}
            tracker_map = {t: i for i, t in enumerate(unique_trackers)}
            conf_map = {config.CONFIDENCE_HIGH: 3, config.CONFIDENCE_MEDIUM: 2, config.CONFIDENCE_LOW: 1}
            
            x = [site_map.get(r.get("domain", "unknown"), 0) for r in results for e in r.get("exfiltration_events", [])]
            y = [tracker_map.get(e.get("request_domain", "unknown"), 0) for r in results for e in r.get("exfiltration_events", [])]
            z = [conf_map.get(e.get("confidence", ""), 0) for r in results for e in r.get("exfiltration_events", [])]
            
            scatter = ax.scatter(x, y, z, c=z, cmap='coolwarm', s=100, alpha=0.7, edgecolors='w')
            
            ax.set_xlabel('Site Index', fontsize=10, labelpad=10)
            ax.set_ylabel('Tracker Index', fontsize=10, labelpad=10)
            ax.set_zlabel('Confidence Level', fontsize=10, labelpad=10)
            ax.set_title("3D Tracking Landscape: Confidence vs Reach", fontsize=15, fontweight='bold', pad=20)
            
            # Customizing Z axis
            ax.set_zticks([1, 2, 3])
            ax.set_zticklabels(['LOW', 'MEDIUM', 'HIGH'])
            
            fig.colorbar(scatter, ax=ax, shrink=0.5, aspect=5, label='Confidence Intensity')
            
            plt.tight_layout()
            path = os.path.join(charts_dir, "tracking_landscape_3d.png")
            fig.savefig(path, dpi=150, bbox_inches="tight")
            plt.close(fig)
            logger.info(f"📊 3D Chart → {path}")
    except Exception as e:
        logger.warning(f"Could not generate 3D chart: {e}")

    logger.info(f"📊 All charts saved to {charts_dir}/")


def _print_console_summary(results: list[dict], stats: dict,
                           paper_metrics: dict, total_crawled_sites: int):
    """Print pandas + numpy tabular summary to the console."""

    print("\n" + "=" * 70)
    print("  IndexedDB DYNAMIC TAINT ANALYSIS — RESULTS SUMMARY")
    print("=" * 70)

    # ── Per-Site Results (pandas DataFrame) ───────────────────────────
    site_data = []
    for r in results:
        net = r.get("network_summary", {})
        exf = r.get("exfiltration_summary", {})
        fc = r.get("flow_classification", {})
        site_data.append({
            "Domain": r.get("domain", "?"),
            "Net Reqs": net.get("total_requests", 0),
            "IDs Found": r.get("identifiers_found", 0),
            "Exfil": exf.get("total", 0),
            "HIGH": exf.get("high_confidence", 0),
            "MED": exf.get("medium_confidence", 0),
            "LOW": exf.get("low_confidence", 0),
            "Inflow": fc.get("inflow_flows", 0),
            "Internal": fc.get("internal_flows", 0),
            "External": fc.get("external_flows", 0),
        })

    df_sites = pd.DataFrame(site_data)

    # Show only sites with activity (exfiltrations or inflow flows)
    df_active = df_sites[
        (df_sites["Exfil"] > 0) | (df_sites["Inflow"] > 0)
    ].copy()

    if not df_active.empty:
        print("\n  📋 SITES WITH DETECTED FLOWS (pandas DataFrame)")
        print("  " + "─" * 68)
        # Set Domain as index for prettier display
        df_display = df_active.set_index("Domain")
        with pd.option_context("display.max_rows", 50, "display.max_columns", 15,
                               "display.width", 120):
            print(df_display.to_string())
        print()

        # Aggregate stats via pandas
        print("\n  📊 AGGREGATE STATISTICS (pandas)")
        print("  " + "─" * 68)
        numeric_cols = df_sites.columns.drop("Domain")
        agg_df = pd.DataFrame({
            "Total": df_sites[numeric_cols].sum(),
            "Mean": df_sites[numeric_cols].mean().round(2),
        })
        with pd.option_context("display.max_rows", 20, "display.width", 100):
            print(agg_df.to_string())
        print()

        # Save per-site DataFrame to CSV
        csv_path = os.path.join(config.ANALYSIS_DIR, "per_site_analysis.csv")
        df_sites.to_csv(csv_path, index=False)
        logger.info(f"📊 Per-site analysis CSV → {csv_path}")
    else:
        print("\n  📋 No sites with detected flows.")

    # Summaries are done.

    # ── Network Requests ─────────────────────────────────────────────
    net_rows = []
    for r in results:
        for req in r.get("network_requests", []):
            net_rows.append({
                "Domain": r.get("domain", "?"),
                "Request URL": req.get("url", "")[:100],
                "Method": req.get("method", ""),
                "Request Domain": req.get("domain", ""),
                "Third Party": req.get("is_third_party", False),
                "POST Data": req.get("has_post_data", False),
            })

    if net_rows:
        df_net = pd.DataFrame(net_rows)
        total_3p = df_net["Third Party"].sum()
        print(f"\n  🌐 NETWORK REQUESTS CAPTURED")
        print("  " + "─" * 68)
        print(f"  Total requests: {len(df_net)} | Third-party: {total_3p} ({total_3p/len(df_net)*100:.1f}%)")

        # Show top third-party domains
        tp_domains = df_net[df_net["Third Party"]]["Request Domain"].value_counts().head(15)
        if not tp_domains.empty:
            print("\n  Top third-party request domains:")
            for domain, count in tp_domains.items():
                print(f"    {count:>4}× {domain}")
        print()

        # Save full network requests CSV
        csv_path = os.path.join(config.ANALYSIS_DIR, "network_requests.csv")
        df_net.to_csv(csv_path, index=False)
        logger.info(f"🌐 Network requests CSV → {csv_path}")

    # ── Table 2: Confidence Breakdown ───────────────────────────────
    conf = stats["confidence_breakdown"]
    conf_headers = ["Confidence", "Count"]
    conf_rows = [
        ["🔴 HIGH", conf["high"]],
        ["🟡 MEDIUM", conf["medium"]],
        ["🟢 LOW", conf["low"]],
    ]
    _print_table("⚠️  CONFIDENCE BREAKDOWN", conf_headers, conf_rows,
                 col_aligns=['l', 'r'])

    # ── Table 3: Top Tracker Domains ────────────────────────────────
    top_trackers = stats.get("top_tracker_domains", {})
    if top_trackers:
        tracker_headers = ["Tracker Domain", "Events"]
        tracker_rows = [[d, c] for d, c in list(top_trackers.items())[:10]]
        _print_table("📡 TOP TRACKER DOMAINS", tracker_headers, tracker_rows,
                     col_aligns=['l', 'r'])

    # ── Table 4: Identifier Type Distribution ───────────────────────
    id_types = stats.get("identifier_type_distribution", {})
    if id_types:
        id_headers = ["Identifier Type", "Count"]
        id_rows = [[t, c] for t, c in list(id_types.items())[:10]]
        _print_table("🏷️  IDENTIFIER TYPES DETECTED", id_headers, id_rows,
                     col_aligns=['l', 'r'])

    # ── Table 5: Overall Classification ─────────────────────────────
    sites_stat = stats["site_classification"]
    detect = stats["detection_summary"]
    class_headers = ["Classification", "Value"]
    class_rows = [
        ["Total crawled sites", total_crawled_sites],
        ["Total sites analyzed", stats["crawl_summary"]["total_sites_analyzed"]],
        ["Third-party exfiltrations", detect["third_party_exfiltrations"]],
        ["Known tracker matches", detect["known_tracker_exfiltrations"]],
    ]
    _print_table("🌐 OVERALL CLASSIFICATION", class_headers, class_rows,
                 col_aligns=['l', 'r'])

    # ══════════════════════════════════════════════════════════════════
    # PAPER-ALIGNED TABLES ("What Storage" Paper)
    # ══════════════════════════════════════════════════════════════════
    print("\n" + "=" * 70)
    print('  "WHAT STORAGE" PAPER — ANALYTICAL FRAMEWORK RESULTS')
    print("=" * 70)

    ov = paper_metrics["overview"]

    # ── Paper Table: Flow Overview ──────────────────────────────────
    flow_headers = ["Metric", "Count", "%"]
    flow_rows = [
        ["Total sites", ov["total_sites"], "—"],
        ["Total information flows", ov["total_flows"], "100%"],
        ["  └ Outflow flows", ov["outflow_flows"],
         f"{ov['outflow_flows']/max(ov['total_flows'],1)*100:.1f}%"],
        ["  └ Inflow flows", ov["inflow_flows"],
         f"{ov['inflow_flows']/max(ov['total_flows'],1)*100:.1f}%"],
    ]
    _print_table("📄 FLOW OVERVIEW (Paper Section IV.B)",
                 flow_headers, flow_rows,
                 col_aligns=['l', 'r', 'r'])

    # ── Paper Table III: Confinement (Internal vs External) ─────────
    t3 = paper_metrics["table_iii_confinement"]
    conf3_headers = ["Confinement", "Outflow", "Inflow", "Total", "% of Total"]
    conf3_rows = [
        ["Internal",
         t3["internal"]["outflow"], t3["internal"]["inflow"],
         t3["internal"]["total"], f"{t3['internal']['pct_of_total']}%"],
        ["External",
         t3["external"]["outflow"], t3["external"]["inflow"],
         t3["external"]["total"], f"{t3['external']['pct_of_total']}%"],
    ]
    _print_table(
        "📊 TABLE III: CONFINEMENT ANALYSIS (Internal vs External)",
        conf3_headers, conf3_rows,
        col_aligns=['l', 'r', 'r', 'r', 'r'],
    )

    # ── Paper Table IV: External Breakdown (Same-site vs Cross-site)
    t4 = paper_metrics["table_iv_external_breakdown"]
    ext_headers = ["Category", "Outflow Flows", "Tracking", "Non-Tracking", "% of External"]
    ext_rows = [
        ["Same-site",
         t4["same_site"]["outflow"], t4["same_site"]["tracking"],
         t4["same_site"]["non_tracking"], f"{t4['same_site']['pct_of_external']}%"],
        ["Cross-site",
         t4["cross_site"]["outflow"], t4["cross_site"]["tracking"],
         t4["cross_site"]["non_tracking"], f"{t4['cross_site']['pct_of_external']}%"],
    ]
    _print_table(
        "📊 TABLE IV: EXTERNAL FLOWS BREAKDOWN (Same-site vs Cross-site)",
        ext_headers, ext_rows,
        col_aligns=['l', 'r', 'r', 'r', 'r'],
    )

    # ── Paper: Tracking Classification ──────────────────────────────
    tc = paper_metrics["tracking_classification"]
    track_headers = ["Category", "Outflow", "Inflow"]
    track_rows = [
        ["Tracking", tc["outflow_tracking"], tc["inflow_tracking"]],
        ["Non-tracking", tc["outflow_non_tracking"], tc["inflow_non_tracking"]],
        ["% Tracking", f"{tc['pct_outflow_tracking']}%", "—"],
    ]
    _print_table(
        "📊 TRACKING vs NON-TRACKING CLASSIFICATION",
        track_headers, track_rows,
        col_aligns=['l', 'r', 'r'],
    )

    # ── Sink distribution ───────────────────────────────────────────
    sink_dist = paper_metrics.get("sink_distribution", {})
    if sink_dist:
        sink_headers = ["Sink Class", "Flows"]
        sink_rows = [[k, v] for k, v in sink_dist.items()]
        _print_table("📡 SINK CLASS DISTRIBUTION (Outflow Flows)",
                     sink_headers, sink_rows, col_aligns=['l', 'r'])

    # ── Source distribution (inflow) ─────────────────────────────
    src_dist = paper_metrics.get("source_distribution", {})
    if src_dist:
        src_headers = ["Source Class", "Flows"]
        src_rows = [[k, v] for k, v in src_dist.items()]
        _print_table("📡 SOURCE CLASS DISTRIBUTION (Inflow Flows)",
                     src_headers, src_rows, col_aligns=['l', 'r'])

    # ── Top IDB databases by flow count ─────────────────────────────
    top_dbs = paper_metrics.get("top_databases", {})
    if top_dbs:
        db_headers = ["Database Name", "Flows"]
        db_rows = [[k, v] for k, v in list(top_dbs.items())[:10]]
        _print_table("🗄️  TOP IndexedDB DATABASES BY FLOW COUNT",
                     db_headers, db_rows, col_aligns=['l', 'r'])

    # ── Paper Metrics Summary ───────────────────────────────────────
    pct_ext_tracking = tc.get("pct_external_tracking", 0)
    t4_cs = t4["cross_site"]
    summary_headers = ["Paper Metric", "Value"]
    summary_rows = [
        ["% sites with IndexedDB", f"{ov['pct_sites_with_idb']}%"],
        ["Total information flows", ov["total_flows"]],
        ["% outflow flows",
         f"{ov['outflow_flows']/max(ov['total_flows'],1)*100:.1f}%"],
        ["% inflow flows",
         f"{ov['inflow_flows']/max(ov['total_flows'],1)*100:.1f}%"],
        ["% internal (confined) flows", f"{t3['internal']['pct_of_total']}%"],
        ["% external flows", f"{t3['external']['pct_of_total']}%"],
        ["% cross-site (of external)", f"{t4_cs['pct_of_external']}%"],
        ["% external flows = tracking", f"{pct_ext_tracking}%"],
        ["% outflow flows = tracking", f"{tc['pct_outflow_tracking']}%"],
    ]
    _print_table(
        "📈 PAPER METRICS SUMMARY (What Storage — Section IV.B)",
        summary_headers, summary_rows,
        col_aligns=['l', 'r'],
    )

    print("\n" + "=" * 70)
    print(f"  Full results: {config.RESULTS_DIR}/")
    print("=" * 70 + "\n")
