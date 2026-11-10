#!/usr/bin/env python3
"""
Playwright Firefox-driver patch (reproducibility, Phase UID).

Bug: playwright's FF dispatcher does `pageError.location.url/lineNumber/
columnNumber` without a guard. Live pages that raise an uncaught script
error WITHOUT location info (cross-origin "Script errors", OOM-class
failures) crash the node driver:

    TypeError: Cannot read properties of undefined (reading 'url')
        at FFBrowserContext.<anonymous> (…coreBundle.js:53885)

Once the driver dies, every JS-based extraction (IndexedDB dump, flow
hooks, other-storage) silently returns empty while event-based network
capture still records — i.e., crawls look "done" with 0 identifiers.

This script idempotently guards all six field references in the venv's
coreBundle.js and keeps a .prividb.bak backup. Run it after every
`pip install -r requirements.txt` / playwright upgrade:

    python scripts/patch_playwright_ff.py            # apply/verify
    python scripts/patch_playwright_ff.py --check    # exit 1 if unpatched
"""
import argparse
import os
import shutil
import sys

FIELDS = (
    ("pageError.location.url,",
     '(pageError.location ? pageError.location.url : ""),'),
    ("pageError.location.lineNumber,",
     '(pageError.location ? pageError.location.lineNumber : 0),'),
    ("pageError.location.columnNumber\n",
     '(pageError.location ? pageError.location.columnNumber : 0)\n'),
)


def find_bundle() -> str:
    try:
        import playwright
        base = os.path.dirname(playwright.__file__)
        path = os.path.join(base, "driver", "package", "lib",
                            "coreBundle.js")
        if os.path.exists(path):
            return path
    except Exception:
        pass
    sys.exit("playwright not importable / coreBundle.js not found")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true",
                    help="verify only; exit 1 if unpatched")
    args = ap.parse_args()

    path = find_bundle()
    src = open(path, encoding="utf-8").read()
    missing = [old for old, _ in FIELDS if old in src]

    if args.check:
        if missing:
            print(f"UNPATCHED ({len(missing)} patterns) → {path}")
            return 1
        print(f"patched OK → {path}")
        return 0

    if not missing:
        print(f"already patched → {path}")
        return 0

    bak = path + ".prividb.bak"
    if not os.path.exists(bak):
        shutil.copy2(path, bak)
        print(f"backup → {bak}")
    for old, new in FIELDS:
        src = src.replace(old, new)
    open(path, "w", encoding="utf-8").write(src)
    print(f"patched {len(missing)} pattern(s) → {path}")

    # syntax sanity: node --check when node is available
    import shutil as _sh
    import subprocess
    node = _sh.which("node")
    if node:
        r = subprocess.run([node, "--check", path],
                           capture_output=True, text=True)
        if r.returncode != 0:
            print("WARNING: node --check failed after patch:", r.stderr[:400])
            shutil.copy2(bak, path)
            print("restored backup — please report this")
            return 2
        print("node --check OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
