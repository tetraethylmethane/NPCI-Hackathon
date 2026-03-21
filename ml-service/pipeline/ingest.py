"""
Sprint 1 — CERT Insider Threat Dataset ETL Pipeline
=====================================================
Ingests all five CMU CERT log sources, normalises their schemas into a single
unified event format, assigns risk weights, and writes Parquet outputs
indexed by (user_id, date).

Unified NormalizedEvent schema:
  event_id        str   — original CERT row ID
  timestamp       datetime64[ns, UTC]
  user_id         str   — CERT user identifier (e.g. "ACM2278")
  pc              str   — workstation / "UNKNOWN-PC" if null
  source          str   — "logon" | "device" | "file" | "email" | "http"
  action_type     str   — mapped to ActivityType enum values
  risk_weight     int   — sprint-defined scoring table (see ACTION_WEIGHTS)
  is_after_hours  bool
  is_weekend      bool
  metadata        str   — JSON-encoded source-specific fields
  is_null_flagged bool  — True when any critical field was imputed

Action weight table (sprint-defined):
  Logon success              2 pts
  Logon failure              8 pts
  After-hours logon bonus   +10 pts (added on top of base)
  File access (open/read)    5 pts
  File copy                 20 pts
  File delete               10 pts
  Email sent (no attach)     3 pts
  Email with attachment     15 pts  (replaces base 3 pts)
  HTTP visit                 1 pt
  HTTP to cloud/job site    +5 pts  (added on top of base)
  USB connect                5 pts
  USB file copy             20 pts

Usage:
  from pipeline.ingest import run_pipeline
  stats = run_pipeline(dataset_dir=Path("dataset"), output_dir=Path("dataset/processed"))
"""

import json
import logging
from pathlib import Path
from typing import Optional

import pandas as pd
import numpy as np

from pipeline.anonymize import pseudonymize_dataframe

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

from pipeline.constants import (
    WORK_START, WORK_END,
    CLOUD_STORAGE_DOMAINS, JOB_SITE_DOMAINS, SENSITIVE_EXTENSIONS,
    is_after_hours as _is_after_hours,
    is_weekend    as _is_weekend,
    domain_of     as _domain_of,
)

# All CERT timestamps are organisation-local (no tz info).
# We treat them as UTC for normalisation — no offset applied.
CERT_TS_FORMATS = [
    "%m/%d/%Y %H:%M:%S",   # r4.2 standard: 01/02/2010 07:14:00
    "%Y-%m-%d %H:%M:%S",   # alternate ISO format seen in some releases
    "%m/%d/%Y %H:%M",      # truncated seconds variant
]


# Base risk weights — sprint specification
BASE_WEIGHTS: dict[str, int] = {
    "LOGON_SUCCESS":       2,
    "LOGON_FAILURE":       8,
    "LOGOFF":              0,
    "USB_DEVICE_CONNECTED": 5,
    "USB_DEVICE_DISCONNECT": 0,
    "USB_FILE_COPY":      20,
    "FILE_ACCESS":         5,
    "FILE_COPY":          20,
    "FILE_DELETE":        10,
    "FILE_WRITE":          5,
    "EMAIL_SENT":          3,
    "EMAIL_SENT_ATTACH":  15,   # overrides EMAIL_SENT when attachment present
    "EMAIL_RECEIVED":      1,
    "HTTP_VISIT":          1,
    "HTTP_CLOUD":          6,   # cloud/job-site visit (1 base + 5 bonus)
    "HTTP_JOB_SITE":       6,
}

AFTER_HOURS_BONUS = 10  # added on top of base for logon events after hours


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_timestamp(ts_series: pd.Series) -> pd.Series:
    """
    Robust timestamp parser that tries multiple CERT date formats.
    Converts to UTC-aware datetime64. Unparseable rows become NaT.
    """
    result = pd.to_datetime(ts_series, errors="coerce", utc=False)
    # If most values failed, try explicit formats
    null_pct = result.isna().mean()
    if null_pct > 0.05:
        for fmt in CERT_TS_FORMATS:
            attempt = pd.to_datetime(ts_series, format=fmt, errors="coerce")
            if attempt.notna().mean() > result.notna().mean():
                result = attempt
    # Localise as UTC (CERT data has no tz info — treat as UTC)
    return result.dt.tz_localize("UTC", ambiguous="infer", nonexistent="shift_forward")


def _to_metadata(row: dict) -> str:
    """Serialise extra source-specific fields to compact JSON string."""
    safe = {k: (v if pd.notna(v) else None) for k, v in row.items()}
    return json.dumps(safe, default=str)


# ---------------------------------------------------------------------------
# Per-source normalisers
# ---------------------------------------------------------------------------

def _normalize_logon(path: Path) -> pd.DataFrame:
    """
    logon.csv columns: id, date, user, pc, activity
    activity values:   "Logon" | "Logoff" | "Failed logon" (some versions)
    """
    logger.info("Loading logon.csv (%s)", path)
    df = pd.read_csv(path, dtype=str)
    df.columns = df.columns.str.strip().str.lower()

    # Column rename
    df = df.rename(columns={"id": "event_id", "date": "timestamp",
                             "user": "user_id", "activity": "raw_activity"})

    # Impute missing pc
    null_pc = df["pc"].isna().sum()
    df["pc"] = df["pc"].fillna("UNKNOWN-PC")
    df["is_null_flagged"] = df["pc"] == "UNKNOWN-PC"

    # Parse timestamps
    df["timestamp"] = _parse_timestamp(df["timestamp"])
    corrupt_ts = df["timestamp"].isna().sum()
    df = df.dropna(subset=["timestamp"])

    # Map activity → action_type
    act_lower = df["raw_activity"].str.lower().str.strip()
    conditions = [
        act_lower.str.contains("fail", na=False),
        act_lower == "logoff",
    ]
    choices = ["LOGON_FAILURE", "LOGOFF"]
    df["action_type"] = np.select(conditions, choices, default="LOGON_SUCCESS")

    # Temporal flags
    df["is_after_hours"] = _is_after_hours(df["timestamp"])
    df["is_weekend"] = _is_weekend(df["timestamp"])

    # Risk weight: base + after-hours bonus for successful logons
    df["risk_weight"] = df["action_type"].map(BASE_WEIGHTS).fillna(2).astype(int)
    after_hours_logon_mask = (df["action_type"] == "LOGON_SUCCESS") & df["is_after_hours"]
    df.loc[after_hours_logon_mask, "risk_weight"] += AFTER_HOURS_BONUS

    df["source"] = "logon"
    df["metadata"] = df[["raw_activity"]].apply(
        lambda r: _to_metadata(r.to_dict()), axis=1
    )

    logger.info("  logon: %d events, %d null-pc imputed, %d corrupt timestamps dropped",
                len(df), null_pc, corrupt_ts)
    return df[_unified_cols()]


def _normalize_device(path: Path) -> pd.DataFrame:
    """
    device.csv columns: id, date, user, pc, activity
    activity values:    "Connect" | "Disconnect"
    """
    logger.info("Loading device.csv (%s)", path)
    df = pd.read_csv(path, dtype=str)
    df.columns = df.columns.str.strip().str.lower()
    df = df.rename(columns={"id": "event_id", "date": "timestamp",
                             "user": "user_id", "activity": "raw_activity"})

    null_pc = df["pc"].isna().sum()
    df["pc"] = df["pc"].fillna("UNKNOWN-PC")
    df["is_null_flagged"] = df["pc"] == "UNKNOWN-PC"

    df["timestamp"] = _parse_timestamp(df["timestamp"])
    corrupt_ts = df["timestamp"].isna().sum()
    df = df.dropna(subset=["timestamp"])

    act_lower = df["raw_activity"].str.lower().str.strip()
    df["action_type"] = np.where(
        act_lower.str.contains("disconnect|remove", na=False),
        "USB_DEVICE_DISCONNECT",
        "USB_DEVICE_CONNECTED"
    )

    df["is_after_hours"] = _is_after_hours(df["timestamp"])
    df["is_weekend"] = _is_weekend(df["timestamp"])
    df["risk_weight"] = df["action_type"].map(BASE_WEIGHTS).fillna(5).astype(int)
    df["source"] = "device"
    df["metadata"] = df[["raw_activity"]].apply(
        lambda r: _to_metadata(r.to_dict()), axis=1
    )

    logger.info("  device: %d events, %d null-pc imputed, %d corrupt dropped",
                len(df), null_pc, corrupt_ts)
    return df[_unified_cols()]


def _normalize_file(path: Path) -> pd.DataFrame:
    """
    file.csv columns: id, date, user, pc, filename, activity
    activity values:  "open" | "write" | "copy" | "delete" | "rename"
    """
    logger.info("Loading file.csv (%s)", path)
    df = pd.read_csv(path, dtype=str)
    df.columns = df.columns.str.strip().str.lower()
    df = df.rename(columns={"id": "event_id", "date": "timestamp",
                             "user": "user_id", "activity": "raw_activity"})

    null_pc = df["pc"].isna().sum()
    df["pc"] = df["pc"].fillna("UNKNOWN-PC")
    # filename nulls → impute as sentinel
    null_fn = df["filename"].isna().sum() if "filename" in df.columns else 0
    if "filename" in df.columns:
        df["filename"] = df["filename"].fillna("UNKNOWN-FILE")
    df["is_null_flagged"] = (df["pc"] == "UNKNOWN-PC") | (
        (df["filename"] == "UNKNOWN-FILE") if "filename" in df.columns else False
    )

    df["timestamp"] = _parse_timestamp(df["timestamp"])
    corrupt_ts = df["timestamp"].isna().sum()
    df = df.dropna(subset=["timestamp"])

    act_lower = df["raw_activity"].str.lower().str.strip()
    conditions = [
        act_lower.str.contains("copy", na=False),
        act_lower.str.contains("delete|remove", na=False),
        act_lower.str.contains("write", na=False),
    ]
    choices = ["FILE_COPY", "FILE_DELETE", "FILE_WRITE"]
    df["action_type"] = np.select(conditions, choices, default="FILE_ACCESS")

    df["is_after_hours"] = _is_after_hours(df["timestamp"])
    df["is_weekend"] = _is_weekend(df["timestamp"])
    df["risk_weight"] = df["action_type"].map(BASE_WEIGHTS).fillna(5).astype(int)
    df["source"] = "file"

    meta_cols = [c for c in ["raw_activity", "filename"] if c in df.columns]
    df["metadata"] = df[meta_cols].apply(
        lambda r: _to_metadata(r.to_dict()), axis=1
    )

    logger.info("  file: %d events, %d null-filename imputed, %d corrupt dropped",
                len(df), null_fn, corrupt_ts)
    return df[_unified_cols()]


def _normalize_email(path: Path, chunksize: int = 200_000) -> pd.DataFrame:
    """
    email.csv columns: id, date, user, pc, to, cc, bcc, from, size, attachments, content
    Large file (1.3 GB+): read in chunks.
    """
    logger.info("Loading email.csv (%s) in chunks of %d", path, chunksize)
    chunks = []
    corrupt_total = 0

    for chunk in pd.read_csv(path, dtype=str, chunksize=chunksize):
        chunk.columns = chunk.columns.str.strip().str.lower()
        chunk = chunk.rename(columns={
            "id": "event_id", "date": "timestamp", "user": "user_id",
            "from": "from_addr",
        })

        chunk["pc"] = chunk["pc"].fillna("UNKNOWN-PC") if "pc" in chunk.columns else "UNKNOWN-PC"
        chunk["is_null_flagged"] = chunk["pc"] == "UNKNOWN-PC"

        chunk["timestamp"] = _parse_timestamp(chunk["timestamp"])
        corrupt = chunk["timestamp"].isna().sum()
        corrupt_total += corrupt
        chunk = chunk.dropna(subset=["timestamp"])

        # Determine if email has attachments
        has_attach = False
        if "attachments" in chunk.columns:
            has_attach = pd.to_numeric(chunk["attachments"], errors="coerce").fillna(0) > 0
        elif "size" in chunk.columns:
            # Proxy: size > 100KB suggests attachment
            has_attach = pd.to_numeric(chunk["size"], errors="coerce").fillna(0) > 100_000

        chunk["action_type"] = np.where(has_attach, "EMAIL_SENT_ATTACH", "EMAIL_SENT")

        # Detect "View" / received emails
        if "activity" in chunk.columns:
            view_mask = chunk["activity"].str.lower().str.contains("view|receive", na=False)
            chunk.loc[view_mask, "action_type"] = "EMAIL_RECEIVED"

        chunk["is_after_hours"] = _is_after_hours(chunk["timestamp"])
        chunk["is_weekend"] = _is_weekend(chunk["timestamp"])
        chunk["risk_weight"] = chunk["action_type"].map(BASE_WEIGHTS).fillna(3).astype(int)
        chunk["source"] = "email"

        meta_cols = [c for c in ["from_addr", "attachments", "size"] if c in chunk.columns]
        chunk["metadata"] = chunk[meta_cols].apply(
            lambda r: _to_metadata(r.to_dict()), axis=1
        )
        chunks.append(chunk[_unified_cols()])

    df = pd.concat(chunks, ignore_index=True) if chunks else pd.DataFrame(columns=_unified_cols())
    logger.info("  email: %d events loaded, %d corrupt timestamps dropped", len(df), corrupt_total)
    return df


def _normalize_http(path: Path) -> pd.DataFrame:
    """
    http.csv columns: id, date, user, pc, url, activity
    """
    logger.info("Loading http.csv (%s)", path)
    df = pd.read_csv(path, dtype=str)
    df.columns = df.columns.str.strip().str.lower()
    df = df.rename(columns={"id": "event_id", "date": "timestamp",
                             "user": "user_id", "activity": "raw_activity"})

    null_pc = df["pc"].isna().sum()
    df["pc"] = df["pc"].fillna("UNKNOWN-PC")
    if "url" in df.columns:
        df["url"] = df["url"].fillna("UNKNOWN-URL")
    df["is_null_flagged"] = df["pc"] == "UNKNOWN-PC"

    df["timestamp"] = _parse_timestamp(df["timestamp"])
    corrupt_ts = df["timestamp"].isna().sum()
    df = df.dropna(subset=["timestamp"])

    # Classify URL domain for bonus weight
    if "url" in df.columns:
        domains = df["url"].apply(_domain_of)
        cloud_mask = domains.isin(CLOUD_STORAGE_DOMAINS)
        job_mask = domains.isin(JOB_SITE_DOMAINS)
        df["action_type"] = np.where(cloud_mask, "HTTP_CLOUD",
                             np.where(job_mask, "HTTP_JOB_SITE", "HTTP_VISIT"))
    else:
        df["action_type"] = "HTTP_VISIT"

    df["is_after_hours"] = _is_after_hours(df["timestamp"])
    df["is_weekend"] = _is_weekend(df["timestamp"])
    df["risk_weight"] = df["action_type"].map(BASE_WEIGHTS).fillna(1).astype(int)
    df["source"] = "http"

    meta_cols = [c for c in ["raw_activity", "url"] if c in df.columns]
    df["metadata"] = df[meta_cols].apply(
        lambda r: _to_metadata(r.to_dict()), axis=1
    )

    logger.info("  http: %d events, %d null-pc imputed, %d corrupt dropped",
                len(df), null_pc, corrupt_ts)
    return df[_unified_cols()]


def _unified_cols() -> list[str]:
    return [
        "event_id", "timestamp", "user_id", "pc",
        "source", "action_type", "risk_weight",
        "is_after_hours", "is_weekend",
        "metadata", "is_null_flagged",
    ]


# ---------------------------------------------------------------------------
# Ground truth loader
# ---------------------------------------------------------------------------

def load_ground_truth(path: Optional[Path] = None) -> pd.DataFrame:
    """
    Load CERT r4.2 ground truth labels.
    answers/insiders.csv — columns vary; always has 'user' or 'user_id'.
    Returns DataFrame with columns: user_id, scenario.
    """
    dataset_dir = Path(__file__).parent.parent.parent / "dataset"
    path = path or dataset_dir / "answers" / "insiders.csv"
    if not path.exists():
        logger.warning("Ground truth file not found at %s — supervised training disabled.", path)
        return pd.DataFrame(columns=["user_id", "scenario"])
    df = pd.read_csv(path, dtype=str)
    df.columns = df.columns.str.strip().str.lower()
    if "user" in df.columns:
        df = df.rename(columns={"user": "user_id"})
    cols = [c for c in ["user_id", "scenario"] if c in df.columns]
    return df[cols].drop_duplicates()


# ---------------------------------------------------------------------------
# Main pipeline runner
# ---------------------------------------------------------------------------

def run_pipeline(
    dataset_dir: Optional[Path] = None,
    output_dir: Optional[Path] = None,
    sources: Optional[list[str]] = None,
) -> dict:
    """
    Full ETL pipeline: load → normalise → weight → write Parquet.

    Args:
        dataset_dir: Directory containing the raw CERT CSVs. Defaults to /dataset.
        output_dir:  Directory for Parquet output. Defaults to /dataset/processed.
        sources:     Subset of sources to process. Defaults to all five.

    Returns:
        dict with row counts and file paths for each source.
    """
    dataset_dir = dataset_dir or Path(__file__).parent.parent.parent / "dataset"
    output_dir = output_dir or dataset_dir / "processed" / "normalized"
    output_dir.mkdir(parents=True, exist_ok=True)

    all_sources = sources or ["logon", "device", "file", "email", "http"]
    loaders = {
        "logon":  _normalize_logon,
        "device": _normalize_device,
        "file":   _normalize_file,
        "email":  _normalize_email,
        "http":   _normalize_http,
    }

    # Accumulate identity mappings across all sources for deduplication
    all_mappings: list[dict] = []

    results = {}
    for src in all_sources:
        csv_path = dataset_dir / f"{src}.csv"
        if not csv_path.exists():
            logger.warning("  %s.csv not found — skipping.", src)
            results[src] = {"status": "skipped", "reason": "file not found"}
            continue
        try:
            df = loaders[src](csv_path)

            # Sprint 5 — pseudonymize before Parquet write
            df, mappings = pseudonymize_dataframe(df, source=src)
            all_mappings.extend(mappings)

            out_path = output_dir / f"{src}.parquet"
            df.to_parquet(out_path, index=False, engine="pyarrow",
                          partition_cols=None)   # partitioning done at transform layer
            results[src] = {
                "status": "ok",
                "rows": len(df),
                "users": int(df["user_id"].nunique()),
                "date_range": [
                    str(df["timestamp"].min()),
                    str(df["timestamp"].max()),
                ],
                "output": str(out_path),
            }
            logger.info("  ✓ %s → %s (%d rows)", src, out_path.name, len(df))
        except Exception as exc:
            logger.exception("  ✗ Failed to process %s: %s", src, exc)
            results[src] = {"status": "error", "reason": str(exc)}

    # Deduplicate mappings (same user appears in multiple sources)
    seen_hashes: set[str] = set()
    deduped: list[dict] = []
    for m in all_mappings:
        if m["hashedUserId"] not in seen_hashes:
            seen_hashes.add(m["hashedUserId"])
            deduped.append(m)
    results["_identity_mappings"] = deduped
    logger.info(
        "  Sprint 5 anonymization: %d unique identity mappings generated",
        len(deduped),
    )

    return results


# ---------------------------------------------------------------------------
# Convenience re-loaders (used by features.py and seed_postgres.py)
# ---------------------------------------------------------------------------

def load_normalized(source: str, output_dir: Optional[Path] = None) -> pd.DataFrame:
    """Load a previously written normalized Parquet file for a given source."""
    output_dir = output_dir or (
        Path(__file__).parent.parent.parent / "dataset" / "processed" / "normalized"
    )
    path = output_dir / f"{source}.parquet"
    if not path.exists():
        raise FileNotFoundError(
            f"Normalized {source}.parquet not found at {path}. "
            "Run run_pipeline() first."
        )
    return pd.read_parquet(path, engine="pyarrow")


def load_all_normalized(output_dir: Optional[Path] = None) -> dict[str, pd.DataFrame]:
    """Load all five normalized sources. Missing sources return empty DataFrames."""
    sources = ["logon", "device", "file", "email", "http"]
    return {
        src: (load_normalized(src, output_dir)
              if (output_dir or Path(__file__).parent.parent.parent / "dataset" / "processed" / "normalized")
              .joinpath(f"{src}.parquet").exists()
              else pd.DataFrame(columns=_unified_cols()))
        for src in sources
    }
