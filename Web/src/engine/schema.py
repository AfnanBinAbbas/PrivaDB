"""
Unified exfiltration-event schema.

Every detection mechanism (substring match, transform-aware match,
Foxhound taint flow, IDB hook flow, inflow/integrity flow) emits events
in this shape so downstream code (reporter, API, evaluation harness)
treats them uniformly.

Mechanism tags:
    substring   — raw value found verbatim in a network request
    transform   — value found after decode/hash/encode variant expansion
    taint       — Foxhound taint flow: source → sink provenance
    idb_hook    — in-page IDB-read → network-send hook correlation
    stealth     — legacy engine output (kept for backward compatibility)

Consent states (Phase 4 will populate these):
    unknown        — no consent interaction observed
    pre_consent    — before any consent banner interaction
    accepted       — after "accept all"
    rejected       — after "reject all"
    no_banner     — no consent banner detected
    banner_failed  — banner detected but interaction failed
"""

from __future__ import annotations

import hashlib
import uuid
from typing import Any, Optional

SCHEMA_VERSION = 1

# ─── Mechanism / method tags ────────────────────────────────────────
MECH_SUBSTRING = "substring"
MECH_TRANSFORM = "transform"
MECH_TAINT = "taint"
MECH_IDB_HOOK = "idb_hook"
MECH_STEALTH = "stealth"          # legacy engine event
MECHANISMS = (MECH_SUBSTRING, MECH_TRANSFORM, MECH_TAINT,
              MECH_IDB_HOOK, MECH_STEALTH)

# ─── Consent states ─────────────────────────────────────────────────
CONSENT_UNKNOWN = "unknown"
CONSENT_PRE = "pre_consent"
CONSENT_ACCEPTED = "accepted"
CONSENT_REJECTED = "rejected"
CONSENT_NO_BANNER = "no_banner"
CONSENT_BANNER_FAILED = "banner_failed"
CONSENT_STATES = (CONSENT_UNKNOWN, CONSENT_PRE, CONSENT_ACCEPTED,
                  CONSENT_REJECTED, CONSENT_NO_BANNER, CONSENT_BANNER_FAILED)


def value_hash(value: Optional[str]) -> str:
    """SHA-256 (truncated to 16 hex chars) of an identifier value.

    Reports should circulate the hash, not the raw value: the raw
    identifier is personal data, the hash is evidence.
    """
    if not value:
        return ""
    return hashlib.sha256(str(value).encode("utf-8", "ignore")).hexdigest()[:16]


def build_event(
    *,
    site: str,
    # ── source side ──
    source_db: str = "",
    source_store: str = "",
    source_key: str = "",
    source_path: str = "",
    source_operation: str = "",
    source_function: Optional[str] = None,
    source_line: Optional[int] = None,
    value: Optional[str] = None,
    value_reason: str = "",
    entropy: float = 0.0,
    # ── sink side ──
    sink_type: str = "",
    sink_url: str = "",
    sink_domain: str = "",
    sink_method: str = "",
    match_location: str = "",
    # ── classification ──
    mechanism: str = MECH_SUBSTRING,
    confidence: str = "",
    is_third_party: bool = False,
    is_known_tracker: bool = False,
    tracker_domain: str = "",
    confinement: str = "",
    cross_origin: str = "",
    flow_direction: str = "outflow",
    # ── provenance / context ──
    method: Optional[str] = None,          # detector method label (alias)
    transform_chain: Optional[list[str]] = None,
    consent_state: str = CONSENT_UNKNOWN,
    initiator_script: Optional[str] = None,
    iteration: Optional[int] = None,
    timestamp: Optional[str] = None,
    # ── pass-through of engine-specific fields ──
    extra: Optional[dict[str, Any]] = None,
) -> dict:
    """Construct one unified event dict. See module docstring for fields."""
    mech = mechanism if mechanism in MECHANISMS else MECH_SUBSTRING
    cons = consent_state if consent_state in CONSENT_STATES else CONSENT_UNKNOWN

    event = {
        "schema_version": SCHEMA_VERSION,
        "id": str(uuid.uuid4()),
        "site": site,
        "iteration": iteration,
        "timestamp": timestamp,

        "source": {
            "database": source_db,
            "store": source_store,
            "key": source_key,
            "path": source_path,
            "operation": source_operation,
            "function": source_function,
            "line": source_line,
        },

        "value": value,
        "value_hash": value_hash(value),
        "value_reason": value_reason,
        "entropy": round(float(entropy or 0.0), 4),

        "sink": {
            "type": sink_type,
            "url": sink_url,
            "domain": sink_domain,
            "method": sink_method,
            "match_location": match_location,
        },

        "mechanism": mech,
        "method": method or mech,
        "transform_chain": list(transform_chain or []),
        "consent_state": cons,
        "initiator_script": initiator_script,

        "confidence": confidence,
        "is_third_party": bool(is_third_party),
        "is_known_tracker": bool(is_known_tracker),
        "tracker_domain": tracker_domain,
        "confinement": confinement,
        "cross_origin": cross_origin,
        "flow_direction": flow_direction,
    }
    if extra:
        event["extra"] = extra
    return event


def is_valid_event(event: Any) -> bool:
    """Structural check: does an event carry every required top-level key?"""
    if not isinstance(event, dict):
        return False
    required = ("schema_version", "id", "site", "source", "sink",
                "mechanism", "consent_state", "flow_direction", "value_hash")
    return all(k in event for k in required)


def from_legacy(event: dict, site: str, mechanism: str = MECH_STEALTH) -> dict:
    """Map a legacy detector event (raw key names) onto the unified schema.

    Accepts both outflow exfil events (identifier_* keys) and inflow
    integrity events. Returns a unified event.
    """
    is_inflow = event.get("flow_direction") == "inflow"
    value = event.get("identifier_value") or event.get("value") or ""
    url = event.get("request_url") or event.get("target") or ""
    domain = event.get("request_domain") or ""

    return build_event(
        site=event.get("site_domain") or site,
        source_db=event.get("database", ""),
        source_store=event.get("store", ""),
        source_key=event.get("record_key", ""),
        source_path=event.get("identifier_path", ""),
        source_operation=event.get("source_class", ""),
        value=value,
        value_reason=event.get("identifier_reason", ""),
        entropy=event.get("identifier_entropy", 0.0),
        sink_type=event.get("sink_class", ""),
        sink_url=url,
        sink_domain=domain,
        sink_method=event.get("request_method", ""),
        match_location=event.get("match_location", ""),
        mechanism=mechanism,
        confidence=event.get("confidence", ""),
        is_third_party=bool(event.get("is_third_party", False)),
        is_known_tracker=bool(event.get("is_known_tracker", False)),
        tracker_domain=event.get("tracker_domain", ""),
        confinement=event.get("confinement", ""),
        cross_origin=event.get("cross_origin", ""),
        flow_direction="inflow" if is_inflow else "outflow",
        extra={k: v for k, v in event.items()
               if k.startswith(("request_", "identifier_")) and k != "identifier_value"},
    )


def from_taint_flow(tf: dict, site: str) -> dict:
    """Map a detector taint flow onto the unified schema."""
    return build_event(
        site=site,
        source_operation=tf.get("source_operation", ""),
        source_function=tf.get("source_function"),
        source_line=tf.get("source_line"),
        source_path=tf.get("source_file") or "",
        value=tf.get("tainted_value"),
        value_reason=f"taint:{tf.get('source_hint', '')}",
        sink_type=tf.get("sink", ""),
        sink_url=tf.get("target") or "",
        sink_domain=tf.get("request_domain") or "",
        match_location=f"taint:{tf.get('sink', '')}",
        mechanism=MECH_TAINT,
        confidence=tf.get("confidence", ""),
        is_third_party=bool(tf.get("is_third_party", False)),
        is_known_tracker=bool(tf.get("is_known_tracker", False)),
        confinement=tf.get("confinement", ""),
        cross_origin=tf.get("cross_origin", ""),
        flow_direction=tf.get("flow_direction", "outflow"),
        initiator_script=tf.get("source_function"),
        timestamp=tf.get("timestamp"),
        extra={"storage_source": tf.get("storage_source", ""),
               "sink_kind": tf.get("sink_kind", ""),
               "subframe": tf.get("subframe", False)},
    )


def from_idb_hook_flow(hf: dict, site: str) -> dict:
    """Map a detector IDB-hook flow onto the unified schema."""
    return build_event(
        site=site,
        source_db="", source_store=hf.get("source_store", ""),
        source_operation=hf.get("source_operation", ""),
        source_function=hf.get("source_function"),
        value=hf.get("idb_value"),
        value_reason=f"idb_hook:{hf.get('sink_hook', '')}",
        sink_type=hf.get("sink", ""),
        sink_url=hf.get("target") or "",
        sink_domain=hf.get("request_domain") or "",
        match_location=f"idb_hook:{hf.get('sink_hook', '')}",
        mechanism=MECH_IDB_HOOK,
        confidence=hf.get("confidence", ""),
        is_third_party=bool(hf.get("is_third_party", False)),
        is_known_tracker=bool(hf.get("is_known_tracker", False)),
        confinement=hf.get("confinement", ""),
        cross_origin=hf.get("cross_origin", ""),
        flow_direction=hf.get("flow_direction", "outflow"),
        initiator_script=hf.get("sink_function"),
        timestamp=hf.get("timestamp"),
        extra={"sink_hook": hf.get("sink_hook", ""),
               "sink_function": hf.get("sink_function")},
    )
