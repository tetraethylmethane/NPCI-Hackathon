"""
Sprint 1 — Daily Aggregation & Risk Snapshot Builder
======================================================
Reads the normalised per-source Parquet files produced by ingest.py and
produces two aggregated outputs:

  1. daily_snapshots.parquet  — one row per (user_id, date)
     Columns:
       user_id, date, total_events, total_risk_score,
       logon_count, device_events, file_events, email_events, http_events,
       after_hours_events, weekend_events,
       logon_risk, device_risk, file_risk, email_risk, http_risk,
       null_flagged_count

  2. user_risk_profiles.parquet — one row per user (30-day rolling summary)
     Columns:
       user_id, days_observed, avg_daily_risk, max_daily_risk,
       total_risk, total_events,
       p90_daily_risk,         ← 90th percentile daily score
       risk_trend,             ← linear slope (positive = escalating)
       is_malicious            ← from ground truth (1/0/-1 unknown)

Usage:
  from pipeline.transform import build_aggregates
  daily_df, profile_df = build_aggregates()
"""

import logging
from pathlib import Path
from typing import Optional

import numpy as np
import pandas as pd
from scipy.stats import linregress   # for risk_trend slope

logger = logging.getLogger(__name__)

PROCESSED_DIR = Path(__file__).parent.parent.parent / "dataset" / "processed"


# ---------------------------------------------------------------------------
# Daily aggregation
# ---------------------------------------------------------------------------

def aggregate_daily(combined_df: pd.DataFrame) -> pd.DataFrame:
    """
    Group the combined normalised event frame by (user_id, date) and
    compute per-day risk totals.

    Args:
        combined_df: pd.concat of all five normalised source DataFrames.

    Returns:
        daily_df indexed by (user_id, date) with risk and event counts.
    """
    df = combined_df.copy()
    df["date"] = df["timestamp"].dt.date.astype(str)

    # Source-specific event counts
    for src in ["logon", "device", "file", "email", "http"]:
        df[f"{src}_event"] = (df["source"] == src).astype(int)
        df[f"{src}_risk"] = df["risk_weight"] * (df["source"] == src).astype(int)

    agg = (
        df.groupby(["user_id", "date"], sort=False)
        .agg(
            total_events=("event_id", "count"),
            total_risk_score=("risk_weight", "sum"),
            logon_count=("logon_event", "sum"),
            device_events=("device_event", "sum"),
            file_events=("file_event", "sum"),
            email_events=("email_event", "sum"),
            http_events=("http_event", "sum"),
            after_hours_events=("is_after_hours", "sum"),
            weekend_events=("is_weekend", "sum"),
            logon_risk=("logon_risk", "sum"),
            device_risk=("device_risk", "sum"),
            file_risk=("file_risk", "sum"),
            email_risk=("email_risk", "sum"),
            http_risk=("http_risk", "sum"),
            null_flagged_count=("is_null_flagged", "sum"),
        )
        .reset_index()
    )

    agg["date"] = pd.to_datetime(agg["date"])
    agg = agg.sort_values(["user_id", "date"]).reset_index(drop=True)

    logger.info("Daily aggregation: %d rows across %d users",
                len(agg), agg["user_id"].nunique())
    return agg


# ---------------------------------------------------------------------------
# Per-user risk profiles (rolling 30-day summary)
# ---------------------------------------------------------------------------

def _risk_trend_slope(series: pd.Series) -> float:
    """Linear regression slope of daily risk scores. Positive = escalating."""
    if len(series) < 3:
        return 0.0
    x = np.arange(len(series))
    y = series.values
    try:
        slope, _, _, _, _ = linregress(x, y)
        return round(float(slope), 4)
    except Exception:
        return 0.0


def build_user_profiles(
    daily_df: pd.DataFrame,
    ground_truth_df: Optional[pd.DataFrame] = None,
    window_days: int = 30,
) -> pd.DataFrame:
    """
    Build a single-row-per-user risk profile from the daily snapshot table.

    Args:
        daily_df:        Output of aggregate_daily().
        ground_truth_df: Optional DataFrame with columns [user_id, scenario].
        window_days:     Rolling window for time-series statistics.

    Returns:
        DataFrame with one row per user and profile statistics.
    """
    records = []

    for user_id, grp in daily_df.groupby("user_id"):
        grp = grp.sort_values("date")
        risk = grp["total_risk_score"]

        records.append({
            "user_id": user_id,
            "days_observed": len(grp),
            "avg_daily_risk": round(float(risk.mean()), 2),
            "max_daily_risk": int(risk.max()),
            "total_risk": int(risk.sum()),
            "total_events": int(grp["total_events"].sum()),
            "p90_daily_risk": round(float(risk.quantile(0.9)), 2),
            "risk_trend": _risk_trend_slope(risk),
            "avg_after_hours_events": round(float(grp["after_hours_events"].mean()), 2),
            "avg_file_risk": round(float(grp["file_risk"].mean()), 2),
            "avg_email_risk": round(float(grp["email_risk"].mean()), 2),
            "is_malicious": -1,   # unknown by default
        })

    profiles = pd.DataFrame(records)

    if ground_truth_df is not None and not ground_truth_df.empty:
        malicious_ids = set(ground_truth_df["user_id"].tolist())
        profiles["is_malicious"] = profiles["user_id"].apply(
            lambda uid: 1 if uid in malicious_ids else 0
        )
        n_mal = (profiles["is_malicious"] == 1).sum()
        logger.info("Labelled %d users as malicious from ground truth.", n_mal)

    logger.info("User profiles built: %d users", len(profiles))
    return profiles.sort_values("total_risk", ascending=False).reset_index(drop=True)


# ---------------------------------------------------------------------------
# Top-level orchestrator
# ---------------------------------------------------------------------------

def build_aggregates(
    normalized_dir: Optional[Path] = None,
    output_dir: Optional[Path] = None,
    ground_truth_df: Optional[pd.DataFrame] = None,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """
    Load all normalised Parquet files, aggregate, and write output Parquet files.

    Returns:
        (daily_df, profiles_df)
    """
    from pipeline.ingest import load_all_normalized

    normalized_dir = normalized_dir or PROCESSED_DIR / "normalized"
    output_dir = output_dir or PROCESSED_DIR / "aggregated"
    output_dir.mkdir(parents=True, exist_ok=True)

    sources = load_all_normalized(normalized_dir)
    available = [df for df in sources.values() if not df.empty]

    if not available:
        raise RuntimeError(
            "No normalized Parquet files found. Run run_pipeline() from ingest.py first."
        )

    combined = pd.concat(available, ignore_index=True)
    logger.info("Combined dataset: %d events from %d users",
                len(combined), combined["user_id"].nunique())

    daily_df = aggregate_daily(combined)
    profiles_df = build_user_profiles(daily_df, ground_truth_df)

    daily_path = output_dir / "daily_snapshots.parquet"
    profiles_path = output_dir / "user_risk_profiles.parquet"

    daily_df.to_parquet(daily_path, index=False, engine="pyarrow")
    profiles_df.to_parquet(profiles_path, index=False, engine="pyarrow")

    logger.info("✓ daily_snapshots.parquet  → %d rows", len(daily_df))
    logger.info("✓ user_risk_profiles.parquet → %d rows", len(profiles_df))

    return daily_df, profiles_df


# ---------------------------------------------------------------------------
# Query helpers (used by seed_postgres.py and features.py)
# ---------------------------------------------------------------------------

def load_daily_snapshots(output_dir: Optional[Path] = None) -> pd.DataFrame:
    path = (output_dir or PROCESSED_DIR / "aggregated") / "daily_snapshots.parquet"
    if not path.exists():
        raise FileNotFoundError(f"daily_snapshots.parquet not found at {path}.")
    return pd.read_parquet(path, engine="pyarrow")


def load_user_profiles(output_dir: Optional[Path] = None) -> pd.DataFrame:
    path = (output_dir or PROCESSED_DIR / "aggregated") / "user_risk_profiles.parquet"
    if not path.exists():
        raise FileNotFoundError(f"user_risk_profiles.parquet not found at {path}.")
    return pd.read_parquet(path, engine="pyarrow")


def get_user_daily_risk(user_id: str, output_dir: Optional[Path] = None) -> pd.DataFrame:
    """Return the daily risk time series for a single user. Used by SHAP/dashboard."""
    df = load_daily_snapshots(output_dir)
    return df[df["user_id"] == user_id].sort_values("date").reset_index(drop=True)
