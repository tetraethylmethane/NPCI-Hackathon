"""
ml-service/evaluation/split.py
================================
Sprint 6 — Time-Based Train / Test Split

Implements a temporal 70/30 split over the CERT dataset to prevent data leakage.
Random splits would allow the model to "see" future behaviour during training;
a time-based split faithfully simulates deployment: train on early data, test on
events that happened after the training window closed.

Split strategy
--------------
1. Load all normalised Parquet files (or a combined DataFrame).
2. Identify the global timestamp range [T_min, T_max].
3. Compute T_cutoff = T_min + 0.70 × (T_max - T_min).
4. Classify each unique user_id:
     train_set  — users whose last event is before T_cutoff
     test_set   — users whose last event is at or after T_cutoff
5. Return train/test feature matrices and label arrays.

Why user-level (not event-level)?
   Features are per-user aggregates; splitting at the event level would mix
   training and test events for the same user, causing leakage.
   We assign each user to the latest split period they appear in.
"""

import logging
from pathlib import Path
from typing import Optional

import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)

TRAIN_FRACTION = 0.70


# ---------------------------------------------------------------------------
# Timestamp cutoff from normalised Parquet
# ---------------------------------------------------------------------------

def compute_cutoff(
    normalized_dir: Optional[Path] = None,
    sources: list[str] | None = None,
) -> pd.Timestamp:
    """
    Compute the 70th-percentile timestamp cutoff across all CERT log sources.

    Returns a timezone-aware Timestamp. Raises RuntimeError if no Parquet
    files are available.
    """
    normalized_dir = normalized_dir or (
        Path(__file__).parent.parent.parent / "dataset" / "processed" / "normalized"
    )
    sources = sources or ["logon", "device", "file", "email", "http"]

    all_ts: list[pd.Series] = []
    for src in sources:
        path = normalized_dir / f"{src}.parquet"
        if path.exists():
            df = pd.read_parquet(path, columns=["timestamp"], engine="pyarrow")
            all_ts.append(df["timestamp"])

    if not all_ts:
        raise RuntimeError(
            f"No normalised Parquet files found in {normalized_dir}. "
            "Run run_pipeline() first."
        )

    combined = pd.concat(all_ts, ignore_index=True).dropna()
    t_min = combined.min()
    t_max = combined.max()
    t_cutoff = t_min + TRAIN_FRACTION * (t_max - t_min)

    logger.info(
        "Time split cutoff:  T_min=%s  T_cutoff=%s  T_max=%s",
        t_min.date(), t_cutoff.date(), t_max.date(),
    )
    return t_cutoff


# ---------------------------------------------------------------------------
# Per-user last-event timestamps
# ---------------------------------------------------------------------------

def user_last_event(
    normalized_dir: Optional[Path] = None,
    sources: list[str] | None = None,
) -> dict[str, pd.Timestamp]:
    """
    Returns { user_id → timestamp_of_last_event } across all sources.
    """
    normalized_dir = normalized_dir or (
        Path(__file__).parent.parent.parent / "dataset" / "processed" / "normalized"
    )
    sources = sources or ["logon", "device", "file", "email", "http"]

    frames: list[pd.DataFrame] = []
    for src in sources:
        path = normalized_dir / f"{src}.parquet"
        if path.exists():
            df = pd.read_parquet(
                path, columns=["user_id", "timestamp"], engine="pyarrow"
            )
            frames.append(df)

    if not frames:
        return {}

    combined = pd.concat(frames, ignore_index=True).dropna(subset=["timestamp"])
    last_event = combined.groupby("user_id")["timestamp"].max()
    return last_event.to_dict()


# ---------------------------------------------------------------------------
# Main split function
# ---------------------------------------------------------------------------

def temporal_split(
    X: np.ndarray,
    user_ids: list[str],
    y: np.ndarray | None = None,
    normalized_dir: Optional[Path] = None,
    train_fraction: float = TRAIN_FRACTION,
) -> dict:
    """
    Split a feature matrix (X) and optional label array (y) into train / test
    sets using a time-based cutoff.

    Args:
        X:          Feature matrix (n_users, n_features).
        user_ids:   List of user identifiers matching X rows.
        y:          Binary label array (n_users,). None if unsupervised only.
        normalized_dir: Path to normalised Parquet files.
        train_fraction: Fraction of timeline used for training (default 0.70).

    Returns:
        {
          "X_train": ndarray, "X_test": ndarray,
          "y_train": ndarray | None, "y_test": ndarray | None,
          "train_ids": list[str], "test_ids": list[str],
          "cutoff": pd.Timestamp,
          "n_train": int, "n_test": int,
        }
    """
    cutoff = compute_cutoff(normalized_dir)
    last_events = user_last_event(normalized_dir)

    train_mask = np.array([
        last_events.get(uid, cutoff) < cutoff
        for uid in user_ids
    ])
    test_mask = ~train_mask

    result = {
        "X_train":   X[train_mask],
        "X_test":    X[test_mask],
        "y_train":   y[train_mask] if y is not None else None,
        "y_test":    y[test_mask]  if y is not None else None,
        "train_ids": [uid for uid, m in zip(user_ids, train_mask) if m],
        "test_ids":  [uid for uid, m in zip(user_ids, test_mask)  if m],
        "cutoff":    cutoff,
        "n_train":   int(train_mask.sum()),
        "n_test":    int(test_mask.sum()),
    }

    logger.info(
        "Temporal split: %d train users / %d test users  (cutoff=%s)",
        result["n_train"], result["n_test"], cutoff.date(),
    )
    return result
