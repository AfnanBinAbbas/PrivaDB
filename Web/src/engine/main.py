"""
IndexedDB Dynamic Taint Analysis — Main Entry Point

Orchestrates the full pipeline: crawl → detect → report.

Usage:
    python main.py                            # Full pipeline (all sites)
    python main.py --crawl-only               # Just collect data
    python main.py --detect-only              # Just analyze existing data
    python main.py --sites 5                  # Limit to first N sites
    python main.py --input-file domains.txt   # Use custom domain file
"""

import argparse
import asyncio
import json
import logging
import sys
import os
import app_config as config

class Tee:
    """Duplicates stdout to both the original stdout and a file."""
    def __init__(self, filename):
        self.file = open(filename, "w", encoding="utf-8")
        self.stdout = sys.stdout

    def write(self, data):
        self.stdout.write(data)
        self.file.write(data)

    def flush(self):
        self.stdout.flush()
        self.file.flush()

    def close(self):
        self.file.close()


def setup_logging():
    """Configure logging for the pipeline."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler(
                os.path.join(config.RESULTS_DIR, "pipeline.log"),
                mode="w",
            ) if os.path.exists(config.RESULTS_DIR) else logging.StreamHandler(),
        ],
    )


def load_sites_from_file(filepath: str) -> list[dict]:
    """
    Load a custom site list from a user-provided file.

    Supported formats:
      - Plain text (.txt): one URL or domain per line
      - JSON (.json): either a list of URLs or a dict with a "sites" key

    Lines starting with # are treated as comments and skipped.
    Empty lines are skipped.
    Domains without a scheme get https:// prepended.
    """
    if not os.path.isfile(filepath):
        print(f"\n❌ Error: File not found: {filepath}")
        sys.exit(1)

    sites = []
    ext = os.path.splitext(filepath)[1].lower()

    if ext == ".json":
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
        # Support both formats: [{"url": ...}] or {"sites": [{"url": ...}]}
        if isinstance(data, dict) and "sites" in data:
            entries = data["sites"]
        elif isinstance(data, list):
            entries = data
        else:
            print(f"\n❌ Error: JSON must be a list of URLs or a dict with a 'sites' key")
            sys.exit(1)

        for entry in entries:
            if isinstance(entry, str):
                url = entry.strip()
                if url and not url.startswith("#"):
                    sites.append({"url": _normalize_url(url), "reason": "custom input"})
            elif isinstance(entry, dict) and "url" in entry:
                sites.append(entry)
    else:
        # Plain text: one URL/domain per line
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    sites.append({"url": _normalize_url(line), "reason": "custom input"})

    if not sites:
        print(f"\n❌ Error: No valid URLs found in {filepath}")
        sys.exit(1)

    print(f"\n📂 Loaded {len(sites)} site(s) from {filepath}")
    return sites


def _normalize_url(url: str) -> str:
    """Ensure URL has a scheme. Bare domains get https:// prepended."""
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    if not url.endswith("/"):
        url += "/"
    return url


def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="python main.py",
        description=(
            "IndexedDB Dynamic Taint Analysis Pipeline\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            "Detects persistent web tracking via IndexedDB.\n"
            "Three-phase pipeline: Crawl → Detect → Report."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Examples:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Full pipeline (default sites.json):
    python main.py

  Custom domain list from a text file:
    python main.py --input-file /path/to/domains.txt

  Custom domain list from a JSON file:
    python main.py --input-file /path/to/targets.json

  Crawl only (save raw data, skip analysis):
    python main.py --crawl-only

  Analyze existing crawled data:
    python main.py --detect-only

  Limit to first 5 sites:
    python main.py --sites 5

  Show browser window for debugging:
    python main.py --no-headless

  Combine flags:
    python main.py --input-file mydomains.txt --sites 10 --no-headless

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Input file formats:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Plain text (.txt) — one URL or domain per line:
    # My target sites
    https://example.com
    another-site.org
    www.tracker-test.com

  JSON (.json) — list of URLs or objects:
    ["https://example.com", "another-site.org"]
    -- or --
    {"sites": [{"url": "https://example.com", "reason": "test"}]}
        """,
    )
    parser.add_argument(
        "--input-file",
        type=str,
        default=None,
        metavar="FILE",
        help="Path to a custom file with domains/URLs to scan (.txt or .json)",
    )
    parser.add_argument(
        "--url",
        type=str,
        default=None,
        metavar="URL",
        help="Directly scan a single URL (overrides --input-file)",
    )
    parser.add_argument(
        "--crawl-only",
        action="store_true",
        help="Only crawl sites, skip detection and reporting",
    )
    parser.add_argument(
        "--detect-only",
        action="store_true",
        help="Only run detection on existing crawled data (no crawling)",
    )
    parser.add_argument(
        "--sites",
        type=int,
        default=None,
        metavar="N",
        help="Limit to the first N sites from the list (default: all)",
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=None,
        metavar="N",
        help="Number of crawl iterations per site (default: 3)",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        metavar="FILE",
        help="Path to a file where terminal output will be saved",
    )
    parser.add_argument(
        "--no-headless",
        action="store_true",
        help="Show browser window instead of running headless (for debugging)",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Overwrite existing results without asking",
    )
    parser.add_argument(
        "--no-overwrite",
        action="store_true",
        help="Skip if existing results found (no prompt, no overwrite)",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Run full automated pipeline (implies --overwrite and --output=output_detectonly_500.txt)",
    )
    parser.add_argument(
        "--engine",
        type=str,
        choices=["chrome", "foxhound"],
        default="chrome",
        help="Browser engine to use for scanning (chrome or foxhound/firefox)",
    )
    return parser.parse_args()


def main():
    """Run the full analysis pipeline."""
    args = parse_args()

    # Apply runtime config overrides
    if args.no_headless:
        config.HEADLESS = False
    if args.iterations is not None:
        config.CRAWL_ITERATIONS = args.iterations
    
    config.ENGINE = args.engine

    if args.all:
        args.overwrite = True
        if not args.output:
            args.output = "output_detectonly_500.txt"

    # Setup output file teeing if requested
    tee = None
    if args.output:
        tee = Tee(args.output)
        sys.stdout = tee

    try:
        # ── Check for existing results (Overwriting logic) ──
        results_exist = (
            os.path.exists(os.path.join(config.ANALYSIS_DIR, "summary.json"))
            or os.path.exists(os.path.join(config.ANALYSIS_DIR, "statistics.json"))
            or os.path.exists(os.path.join(config.ANALYSIS_DIR, "tracking_events.csv"))
        )

        if results_exist and not args.all:
            if args.no_overwrite:
                print("\n⚠️  Existing results found. --no-overwrite set, skipping.\n")
                return
            elif not args.overwrite:
                print("\n⚠️  Existing results found in:", config.ANALYSIS_DIR)
                answer = input("   Overwrite? [y/N]: ").strip().lower()
                if answer not in ("y", "yes"):
                    print("\n❌ Aborted.\n")
                    return
            print("   ✅ Overwriting results...\n")

        # Ensure results directory exists (for log file)
        os.makedirs(config.RESULTS_DIR, exist_ok=True)
        setup_logging()

        logger = logging.getLogger(__name__)

        print("\n" + "=" * 70)
        print("  IndexedDB DYNAMIC TAINT ANALYSIS PIPELINE")
        print("  PrivaDB: Detecting Persistent Web Tracking via IndexedDB")
        print("=" * 70 + "\n")

        # ── Load custom sites (Direct URL takes precedence) ──────────────
        custom_sites = None
        if args.url:
            custom_sites = [{"url": args.url, "reason": "User requested scan"}]
        elif args.input_file:
            custom_sites = load_sites_from_file(args.input_file)

        # ── Phase 1: Crawl ──────────────────────────────────────────────
        if not args.detect_only:
            print("━" * 70)
            print("  PHASE 1: CRAWLING TARGET SITES")
            print("━" * 70)

            from crawler import crawl_all_sites
            crawled_data = asyncio.run(
                crawl_all_sites(site_limit=args.sites, custom_sites=custom_sites)
            )
            logger.info(f"Phase 1 complete: {len(crawled_data)} sites crawled")

            if args.crawl_only:
                print(f"\n✅ Crawl complete. Raw data saved to {config.RAW_DATA_DIR}/")
                print("   Run `python main.py --detect-only` to analyze.\n")
                return

        # ── Phase 2: Detect ─────────────────────────────────────────────
        print("\n" + "━" * 70)
        print("  PHASE 2: TRACKING DETECTION & TAINT ANALYSIS")
        print("━" * 70)

        from detector import analyze_all_sites

        # When running full pipeline, only analyze the sites we just crawled
        if not args.detect_only:
            crawled_files = []
            for cd in crawled_data:
                safe = cd["domain"].replace(".", "_").replace("/", "_")
                crawled_files.append(f"{safe}.json")
            analysis_results = analyze_all_sites(only_files=crawled_files)
        else:
            analysis_results = analyze_all_sites(site_limit=args.sites)
        logger.info(f"Phase 2 complete: {len(analysis_results)} sites analyzed")

        # ── Phase 3: Report ─────────────────────────────────────────────
        print("\n" + "━" * 70)
        print("  PHASE 3: GENERATING REPORTS")
        print("━" * 70)

        from reporter import generate_reports
        generate_reports(analysis_results)
        logger.info("Phase 3 complete: reports generated")

    except Exception as e:
        logger.exception(f"Pipeline failed: {e}")
        sys.exit(1)
    finally:
        if tee:
            sys.stdout = tee.stdout
            tee.close()
            print(f"\n✅ Terminal output saved to: {args.output}")


if __name__ == "__main__":
    main()
