"""
ml-service/pipeline/anonymize.py
==================================
Sprint 5 — Data Pseudonymization for the CERT Pipeline

Pseudonymizes sensitive identifiers before they are written to Parquet
or inserted into Postgres. This module is called by run_etl.py and
seed_postgres.py — it operates on the normalized DataFrame produced by
ingest.py before any writes occur.

Pseudonymization strategy:
  user_id  — HMAC-SHA256 truncated to 16 hex chars (reversible with key)
  pc       — HMAC-SHA256 of workstation name, prefix "PC-"
  email    — local-part replaced with HMAC token; domain replaced with [redacted]
  url      — full URL replaced with domain-hash only (path stripped)
  ip       — replaced with "IP-<8-char hash>"

Identity mapping:
  Returns a list of { hashed_id, original_id, source } dicts that the caller
  writes to the IdentityMapping Postgres table via db.py.

Usage:
    from pipeline.anonymize import pseudonymize_dataframe

    df, mappings = pseudonymize_dataframe(df, source="logon")
    # write mappings to IdentityMapping table
    # write df to Parquet
"""

import hashlib
import hmac
import json
import logging
import os
from typing import Optional

import pandas as pd

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Key material
# ---------------------------------------------------------------------------

_SECRET: bytes = os.getenv(
    "ANONYMIZATION_SECRET", "npci-dev-anon-secret-change-me"
).encode("utf-8")


# ---------------------------------------------------------------------------
# Core: HMAC-SHA256
# ---------------------------------------------------------------------------

def _hmac_hex(value: str) -> str:
    """Return the HMAC-SHA256 hex digest of *value* using the anonymization secret."""
    return hmac.new(_SECRET, value.encode("utf-8"), hashlib.sha256).hexdigest()


# ---------------------------------------------------------------------------
# Per-field pseudonymizers
# ---------------------------------------------------------------------------

def pseudonymize_user_id(original: str) -> str:
    """16-char hex token — deterministic, keyed, non-reversible without key."""
    return _hmac_hex(original)[:16]


def pseudonymize_pc(pc: str) -> str:
    if not pc or pc == "UNKNOWN-PC":
        return "UNKNOWN-PC"
    return f"PC-{_hmac_hex(pc)[:8]}"


def pseudonymize_email(email: str) -> str:
    """Replace local part; keep '[redacted]' as domain."""
    if not email or "@" not in email:
        return "[redacted]"
    token = _hmac_hex(email)[:16]
    return f"{token}@[redacted]"


def pseudonymize_url(url: str) -> str:
    """Replace full URL with a domain-hash token (path removed)."""
    if not url or url == "UNKNOWN-URL":
        return "UNKNOWN-URL"
    # Extract domain heuristically
    try:
        from urllib.parse import urlparse
        domain = urlparse(url).netloc or url.split("/")[0]
    except Exception:
        domain = url[:50]
    return f"URL-{_hmac_hex(domain)[:12]}"


def pseudonymize_ip(ip: str) -> str:
    if not ip:
        return "IP-unknown"
    return f"IP-{_hmac_hex(ip)[:8]}"


# ---------------------------------------------------------------------------
# DataFrame-level pseudonymization
# ---------------------------------------------------------------------------

def pseudonymize_dataframe(
    df: pd.DataFrame,
    source: str,
    *,
    pseudonymize_urls: bool = False,
) -> tuple[pd.DataFrame, list[dict]]:
    """
    Pseudonymize all sensitive columns in *df* in place.

    Returns:
        (modified_df, identity_mappings)
        where identity_mappings is a list of dicts:
            { "hashedUserId": str, "originalId": str, "source": str }
        to be written to the IdentityMapping table.
    """
    df = df.copy()
    mappings: list[dict] = []
    seen: set[str] = set()

    # ── user_id ──────────────────────────────────────────────────────────────
    if "user_id" in df.columns:
        originals = df["user_id"].astype(str)
        hashed = originals.apply(pseudonymize_user_id)

        for orig, hsh in zip(originals, hashed):
            if hsh not in seen:
                seen.add(hsh)
                mappings.append({
                    "hashedUserId": hsh,
                    "originalId": orig,
                    "source": source.upper(),
                })

        df["user_id"] = hashed
        logger.info(
            "  [anonymize] %s: pseudonymized %d unique user_ids → %d mappings",
            source, originals.nunique(), len(mappings),
        )

    # ── pc / workstation ─────────────────────────────────────────────────────
    if "pc" in df.columns:
        df["pc"] = df["pc"].astype(str).apply(pseudonymize_pc)

    # ── metadata JSON fields (email addresses, URLs inside JSON) ─────────────
    if "metadata" in df.columns:
        df["metadata"] = df["metadata"].apply(
            lambda m: _scrub_metadata(m, source, pseudonymize_urls)
        )

    return df, mappings


# ---------------------------------------------------------------------------
# Metadata JSON scrubber
# ---------------------------------------------------------------------------

def _scrub_metadata(raw: str, source: str, pseudonymize_urls: bool) -> str:
    """
    Parse the JSON metadata string, pseudonymize sensitive keys, re-serialize.
    Unknown keys are preserved as-is (no over-scrubbing).
    """
    try:
        obj: dict = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return raw

    # Email fields
    for key in ("from_addr", "to", "cc", "bcc", "email"):
        if key in obj and isinstance(obj[key], str):
            obj[key] = pseudonymize_email(obj[key])

    # URL fields
    if pseudonymize_urls:
        for key in ("url",):
            if key in obj and isinstance(obj[key], str):
                obj[key] = pseudonymize_url(obj[key])

    # IP fields
    for key in ("ip", "src_ip", "dst_ip"):
        if key in obj and isinstance(obj[key], str):
            obj[key] = pseudonymize_ip(obj[key])

    return json.dumps(obj)
