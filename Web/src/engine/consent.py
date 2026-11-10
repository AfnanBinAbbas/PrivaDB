"""
Consent-state crawling (Phase 4).

Detects cookie-consent banners (CMPs) and performs the three study
conditions — no interaction / accept-all / reject-all — each in a fresh
browser context, so IDB writes and exfiltration flows can be compared
before consent, after accept, and after reject.

Detection: known CMP selectors first (OneTrust, Cookiebot, Didomi,
Quantcast, TrustArc, Usercentrics, Klaro, Osano, CookieYes, Complianz),
then button-text heuristics. Failures are reported explicitly so
"banner_failed" never silently counts as "no banner".
"""

from __future__ import annotations

import logging
import re
from typing import Optional

logger = logging.getLogger(__name__)

# ─── CMP selector matrix ────────────────────────────────────────────
# Each CMP: accept selector(s), reject selector(s).
CMP_SELECTORS: dict[str, dict[str, list[str]]] = {
    "onetrust": {
        "accept": ["#onetrust-accept-btn-handler",
                   "button#onetrust-accept-btn-handler"],
        "reject": ["#onetrust-reject-all-handler",
                   "#onetrust-pc-btn-handler"],  # "Privacy choices" → fallback text
    },
    "cookiebot": {
        "accept": ["#CybotCookiebotDialogBodyLevelButtonLevelOptinAllowAll",
                   "#CybotCookiebotDialogBodyButtonAccept"],
        "reject": ["#CybotCookiebotDialogBodyButtonDecline",
                   "#CybotCookiebotDialogBodyLevelButtonLevelOptinDeny"],
    },
    "didomi": {
        "accept": ["#didomi-notice-agree-button",
                   ".didomi-continue-without-agreeing ~ * #didomi-notice-agree-button"],
        "reject": ["#didomi-notice-disagree-button",
                   ".didomi-notice-disagree"],
    },
    "quantcast": {
        "accept": [".qc-cmp2-summary-buttons button[mode=\"primary\"]",
                   "button[aria-label=\"AGREE\"]"],
        "reject": [".qc-cmp2-summary-buttons button[mode=\"secondary\"]",
                   "button[aria-label=\"REJECT\"]"],
    },
    "trustarc": {
        "accept": ["#truste-consent-button",
                   ".trustarc-reject-btn"],
        "reject": [".trustarc-decline-btn",
                   "#truste-consent-required"],
    },
    "usercentrics": {
        "accept": ["[data-testid=\"uc-accept-all-button\"]",
                   "#accept-recommended-btn-holder button"],
        "reject": ["[data-testid=\"uc-deny-all-button\"]"],
    },
    "klaro": {
        "accept": ["button.cn-accept-all"],
        "reject": ["button.cn-decline-all"],
    },
    "osano": {
        "accept": ["button.osano-cm-accept"],
        "reject": ["button.osano-cm-deny"],
    },
    "cookieyes": {
        "accept": ["button.cky-btn-accept"],
        "reject": ["button.cky-btn-reject"],
    },
    "complianz": {
        "accept": ["#cmplz-accept-all-btn"],
        "reject": ["#cmplz-deny"],
    },
    "termly": {
        "accept": ["[data-tid=\"banner-accept\"]"],
        "reject": ["[data-tid=\"banner-decline\"]"],
    },
}

# ─── Button-text heuristics (fallback when no known CMP matches) ───
ACCEPT_TEXTS = [
    "accept all", "accept cookies", "accept all cookies", "allow all",
    "allow all cookies", "agree", "i agree", "agree and continue",
    "got it", "continue", "ok, accept",
]
REJECT_TEXTS = [
    "reject all", "reject all cookies", "decline", "decline all",
    "deny", "deny all", "necessary only", "essential only",
    "only necessary", "disagree", "refuse",
]


def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "")).strip().lower()


async def detect_banner(page) -> dict:
    """
    Detect a consent banner in the main frame (and same-origin frames).

    Returns {detected, cmp, accept_sel, reject_sel, error}.
    """
    result = {"detected": False, "cmp": None, "accept_sel": None,
              "reject_sel": None, "error": None}
    try:
        # 1) known CMP selectors
        for cmp_name, sides in CMP_SELECTORS.items():
            for side in ("accept", "reject"):
                for sel in sides[side]:
                    try:
                        el = await page.query_selector(sel)
                    except Exception:
                        el = None
                    if el and await el.is_visible():
                        result["detected"] = True
                        result["cmp"] = cmp_name
                        if side == "accept":
                            result["accept_sel"] = sel
                        else:
                            result["reject_sel"] = sel
                        break
            if result["detected"]:
                break

        if result["detected"]:
            return result

        # 2) text heuristic over visible buttons
        for side, texts in (("accept", ACCEPT_TEXTS),
                            ("reject", REJECT_TEXTS)):
            btns = await page.query_selector_all(
                "button, [role=button], a.btn, input[type=button], "
                "input[type=submit]")
            for btn in btns:
                try:
                    if not await btn.is_visible():
                        continue
                    label = _norm(await btn.inner_text() or
                                  (await btn.get_attribute("aria-label") or ""))
                except Exception:
                    continue
                if label and any(t == label or t in label for t in texts):
                    result["detected"] = True
                    result["cmp"] = "heuristic"
                    # store a JS-side handle by index is fragile; click directly
                    if side == "accept" and not result["accept_sel"]:
                        result["accept_sel"] = f"__text__:{label}"
                    if side == "reject" and not result["reject_sel"]:
                        result["reject_sel"] = f"__text__:{label}"
            if result["detected"]:
                break
    except Exception as e:
        result["error"] = str(e)
        logger.warning(f"  CMP detection error: {e}")
    return result


async def _click_handle(page, handle: str) -> bool:
    """Click either a CSS selector or a '__text__:label' text handle."""
    if not handle:
        return False
    try:
        if handle.startswith("__text__:"):
            label = handle.split(":", 1)[1]
            btns = await page.query_selector_all(
                "button, [role=button], a.btn, input[type=button], "
                "input[type=submit]")
            for btn in btns:
                try:
                    if not await btn.is_visible():
                        continue
                    txt = _norm(await btn.inner_text() or
                                (await btn.get_attribute("aria-label") or ""))
                    if txt and (label == txt or label in txt):
                        await btn.click(timeout=3000)
                        return True
                except Exception:
                    continue
            return False
        el = await page.query_selector(handle)
        if el and await el.is_visible():
            await el.click(timeout=3000)
            return True
        return False
    except Exception as e:
        logger.warning(f"  Consent click failed ({handle}): {e}")
        return False


async def act(page, banner: dict, action: str) -> dict:
    """
    Perform a consent action.

    action: "none" | "accept" | "reject"
    Returns {state, clicked, method, error} where state is one of
    schema.CONSENT_* values.
    """
    from schema import (CONSENT_UNKNOWN, CONSENT_PRE, CONSENT_ACCEPTED,
                        CONSENT_REJECTED, CONSENT_NO_BANNER,
                        CONSENT_BANNER_FAILED)

    if action == "none":
        if banner.get("detected"):
            return {"state": CONSENT_PRE, "clicked": False,
                    "method": None, "error": None}
        return {"state": CONSENT_NO_BANNER, "clicked": False,
                "method": None, "error": None}

    if not banner.get("detected"):
        return {"state": CONSENT_NO_BANNER, "clicked": False,
                "method": None,
                "error": "no banner detected for action=" + action}

    handle = (banner.get("accept_sel") if action == "accept"
              else banner.get("reject_sel"))
    clicked = await _click_handle(page, handle)
    if clicked:
        state = CONSENT_ACCEPTED if action == "accept" else CONSENT_REJECTED
        return {"state": state, "clicked": True,
                "method": banner.get("cmp"), "error": None}

    # Selector failed — attempt the opposite side's absence is not useful;
    # report failure explicitly (never silently downgrade to no_banner).
    return {"state": CONSENT_BANNER_FAILED, "clicked": False,
            "method": banner.get("cmp"),
            "error": f"banner detected ({banner.get('cmp')}) but "
                     f"{action} click failed "
                     f"(sel={handle!r})"}
