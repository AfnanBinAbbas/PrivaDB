"""
Configuration for IndexedDB Dynamic Taint Analysis Pipeline.

Central settings: timeouts, output paths, identifier detection patterns,
and known tracker domain classifications.
"""

import os
import re

# ─── Engine Selection ───────────────────────────────────────────────
ENGINE = "chrome"  # or "foxhound"

# ─── Dynamic Paths ──────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SITES_FILE = os.path.join(BASE_DIR, "sites.json")

def get_results_dir() -> str:
    """Get the base results directory for the current engine."""
    # Maps engine name to a properly capitalized folder name
    folder_name = "Chrome" if ENGINE == "chrome" else "Foxhound"
    return os.path.join(BASE_DIR, "results", folder_name)

# These will be updated dynamically via set_engine()
RESULTS_DIR = get_results_dir()
RAW_DATA_DIR = os.path.join(RESULTS_DIR, "crawled")       # Phase 1: raw crawl JSON
ANALYSIS_DIR = os.path.join(RESULTS_DIR, "analysis")       # Phase 2: detection output
CHARTS_DIR = os.path.join(RESULTS_DIR, "charts")           # Phase 3: visualizations

def set_engine(engine_name: str):
    """
    Dynamically switch the engine and update all dependent paths.
    This ensures no hardcoding and a clean separation of results.
    """
    global ENGINE, RESULTS_DIR, RAW_DATA_DIR, ANALYSIS_DIR, CHARTS_DIR
    ENGINE = engine_name.lower()
    
    RESULTS_DIR = get_results_dir()
    RAW_DATA_DIR = os.path.join(RESULTS_DIR, "crawled")
    ANALYSIS_DIR = os.path.join(RESULTS_DIR, "analysis")
    CHARTS_DIR = os.path.join(RESULTS_DIR, "charts")
    
    # Ensure directories exist
    for d in [RESULTS_DIR, RAW_DATA_DIR, ANALYSIS_DIR, CHARTS_DIR]:
        os.makedirs(d, exist_ok=True)

# ─── Crawler Settings ───────────────────────────────────────────────
HEADLESS = True                    # Set False for debugging
PAGE_LOAD_TIMEOUT = 30_000         # ms — max wait for page load
IDLE_WAIT = 8_000                  # ms — wait after load for async scripts
NAVIGATION_TIMEOUT = 45_000        # ms — max wait for navigation
CRAWL_ITERATIONS = 3               # Number of fresh crawls per site for diff analysis
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)

def _resolve_path(value: str) -> str:
    """Resolve a project-relative path only when a path separator is present."""
    if not value:
        return value
    if os.path.isabs(value) or os.path.dirname(value):
        return os.path.abspath(os.path.join(BASE_DIR, "..", "..", value)) if not os.path.isabs(value) else value
    return value

def _resolve_firefox_executable() -> str:
    """Resolve Firefox executable by checking common paths and PATH."""
    # Check environment variable first
    if "FIREFOX_EXECUTABLE" in os.environ:
        return os.environ["FIREFOX_EXECUTABLE"]
    
    # Check common installation paths
    common_paths = [
        "/usr/bin/firefox",
        "/usr/local/bin/firefox",
        "/snap/bin/firefox",
        "/opt/firefox/firefox",
    ]
    for path in common_paths:
        if os.path.exists(path):
            return path
    
    # Try to find with `which` command
    try:
        import subprocess
        result = subprocess.run(['which', 'firefox'], 
                              capture_output=True, text=True, timeout=2)
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception:
        pass
    
    # Fallback: return "firefox" and let Playwright handle it
    return "firefox"

FIREFOX_BIN = os.environ.get("FIREFOX_BIN", _resolve_firefox_executable())
FIREFOX_EXECUTABLE = os.environ.get("FIREFOX_EXECUTABLE", FIREFOX_BIN)
FOXHOUND_BIN = _resolve_path(os.environ.get("FOXHOUND_BIN", os.path.join("foxhound", "foxhound")))
FOXHOUND_RESULTS_DIR = _resolve_path(os.environ.get("FOXHOUND_RESULTS_DIR", os.path.join("foxhound", "results")))

# Initial directory creation for default engine
set_engine(ENGINE)

# Compiled patterns for value matching
UUID_V4_RE = re.compile(
    r'[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}',
    re.IGNORECASE
)
HEX_STRING_RE = re.compile(r'^[0-9a-f]{16,}$', re.IGNORECASE)
BASE64_RE = re.compile(r'^[A-Za-z0-9+/]{20,}={0,2}$')

# Minimum string length to consider as a potential identifier
MIN_ID_LENGTH = 8
# Shannon entropy threshold for high-entropy string detection
ENTROPY_THRESHOLD = 3.0

# ─── Known Tracker Domains ──────────────────────────────────────────
# Derived from BQ_trackersdomains_Q2.txt — third-party script domains
# that appear across multiple websites with high IndexedDB usage counts.
KNOWN_TRACKER_DOMAINS = {
    # Analytics & tracking platforms
    "klaviyo.com",
    "static-tracking.klaviyo.com",
    "crazyegg.com",
    "script.crazyegg.com",
    "quantummetric.com",
    "cdn.quantummetric.com",
    "noibu.com",
    "cdn.noibu.com",
    "adsafeprotected.com",
    "static.adsafeprotected.com",
    "cybba.solutions",
    "files2.cybba.solutions",
    "btloader.com",
    "sdiapi.com",
    "services.sdiapi.com",

    # Push notification / engagement
    "pushowl.com",
    "cdn.pushowl.com",
    "webpush.jp",
    "cdn.webpush.jp",
    "wonderpush.com",
    "cdn.by.wonderpush.com",
    "slickstream.com",
    "c.slickstream.com",

    # Social / video embeds with tracking
    "youtube.com",
    "www.youtube.com",
    "youtube-nocookie.com",
    "www.youtube-nocookie.com",

    # Firebase (used for analytics)
    "gstatic.com",
    "www.gstatic.com",

    # Russian mail.ru tracking
    "mail.ru",
    "privacy-cs.mail.ru",

    # Ad-tech / payment tracking  
    "travelpayouts.com",
    "www.travelpayouts.com",
    "mercadolibre.com",
    "www.mercadolibre.com",
    "mercadopago.com",
    "api.mercadopago.com",

    # Shopify pixel / web pixel
    "shopify.com",
    "cdn.shopify.com",

    # Misc third-party
    "funraise.io",
    "assets.funraise.io",
    "bablic.com",
    "d.bablic.com",
    "sappiv.com",
    "zdassets.com",
    "static.zdassets.com",
    "ada.support",
    "spotifycdn.com",
    "embed-cdn.spotifycdn.com",
    "usecorner.io",
    "art.usecorner.io",
    "get-potions.com",
    "client.get-potions.com",
    "ptwmstcnt.com",
    "daktela.com",
    "pandavideo.com.br",
    "futureplc-com.videoplayerhub.com",
}

# ─── External Blacklisted Tracker Files ─────────────────────────────
BLACKLIST_FILES = [
    os.path.join(BASE_DIR, "blacklisted-trackers_all_HTTP.txt"),
    os.path.join(BASE_DIR, "blacklisted-trackers_all_HTTPS.txt"),
]


def _load_blacklisted_tracker_domains() -> set[str]:
    """
    Load tracker domains from external blacklist files.

    Parses announce URLs from the blacklist files, extracts hostnames,
    and returns the set of unique tracker domains.
    """
    from urllib.parse import urlparse

    domains = set()
    for filepath in BLACKLIST_FILES:
        if not os.path.exists(filepath):
            continue
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    parsed = urlparse(line)
                    host = parsed.hostname
                    if host and not host.replace(".", "").isdigit():
                        # Skip pure IP addresses
                        domains.add(host.lower())
                except Exception:
                    pass
    return domains


# Merge external blacklist with hardcoded known trackers
BLACKLISTED_TRACKER_DOMAINS = _load_blacklisted_tracker_domains()
ALL_TRACKER_DOMAINS = KNOWN_TRACKER_DOMAINS | BLACKLISTED_TRACKER_DOMAINS

# Domains to exclude from tracking analysis (legitimate uses)
LEGITIMATE_DOMAINS = {
    "localhost",
    "127.0.0.1",
}

# ─── Detection Confidence Thresholds ────────────────────────────────
CONFIDENCE_HIGH = "HIGH"       # Third-party + high-entropy + known tracker
CONFIDENCE_MEDIUM = "MEDIUM"   # Third-party + identifier pattern
CONFIDENCE_LOW = "LOW"         # First-party or ambiguous

# ─── Paper-Aligned Flow Classification ("What Storage" Paper) ───────
# Flow direction (Table I of paper)
FLOW_OUTFLOW = "outflow"           # storage → sink (data leaving IDB)
FLOW_INFLOW = "inflow"             # source → storage (data entering IDB)

# Confinement (Table III of paper)
CONFINEMENT_INTERNAL = "internal"     # Same origin as the page
CONFINEMENT_EXTERNAL = "external"     # Different origin from the page

# Cross-origin breakdown (Table IV of paper)
CROSS_SAME_SITE = "same_site"         # Same registrable domain, different origin
CROSS_CROSS_SITE = "cross_site"       # Different registrable domain

# ─── IndexedDB-Specific Source/Sink Definitions ─────────────────────
#
# Outflow flows: IDB read (source) → external destination (sink)
# Inflow flows:  external origin (source) → IDB write (sink)
#
# Sources: where data originates
IDB_SOURCES = {
    # IDB read operations (outflow sources — data read FROM IDB)
    "IDBObjectStore.get":       "IDB record read",
    "IDBObjectStore.getAll":    "IDB bulk read",
    "IDBObjectStore.getKey":    "IDB key read",
    "IDBObjectStore.openCursor":"IDB cursor iteration",
    "IDBIndex.get":             "IDB index read",
    "IDBIndex.getAll":          "IDB index bulk read",
    "IDBIndex.openCursor":      "IDB index cursor",
}

EXTERNAL_SOURCES = {
    # External data origins (inflow sources — data entering IDB)
    "url_parameter":    "Data from URL query parameters",
    "navigator_prop":   "Data from navigator properties (userAgent, etc.)",
    "network_response": "Data from network response bodies",
    "document_cookie":  "Data from document.cookie",
    "document_referrer":"Data from document.referrer",
}

# Sinks: where data flows TO
IDB_SINKS = {
    # IDB write operations (inflow sinks — data written TO IDB)
    "IDBObjectStore.put":   "IDB record upsert",
    "IDBObjectStore.add":   "IDB record insert",
    "IDBObjectStore.delete":"IDB record deletion",
    "IDBObjectStore.clear": "IDB store clear",
    "IDBDatabase.createObjectStore": "IDB store creation",
}

EXTERNAL_SINKS = {
    # Network destinations (outflow sinks — IDB data sent out)
    "xhr_url":              "XMLHttpRequest URL parameter",
    "xhr_body":             "XMLHttpRequest POST body",
    "fetch_url":            "Fetch API URL parameter",
    "fetch_body":           "Fetch API POST body",
    "sendbeacon":           "navigator.sendBeacon",
    "img_src":              "Image src (pixel tracking)",
    "script_src":           "Script src parameter",
    "header_cookie":        "Cookie header in request",
}
