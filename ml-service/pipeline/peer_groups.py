"""
Sprint 3 — Peer Group Deviation Scoring
=========================================
Computes how far each user deviates from their role-level cohort.

Role/department extraction:
  CERT user IDs follow "<3-LETTER-CODE><4-DIGITS>" (e.g. "ACM2278").
  The uppercase letter prefix is treated as the department identifier.
  Users that don't match the pattern are placed in cohort "UNKNOWN".

Feature indices used for deviation scoring (match FEATURE_NAMES in features.py):
  after_hours_ratio       → idx 1
  file_access_vs_mean     → idx 8
  usb_plugin_count        → idx 10
  email_volume_ratio      → idx 12
  total_risk_weight       → idx 13

Deviation is expressed as a Z-score within the cohort, capped to [-3, 3].
"""

import json
import logging
import re
from pathlib import Path
from typing import Optional

import numpy as np

logger = logging.getLogger(__name__)

_DEPT_RE = re.compile(r"^([A-Za-z]{2,5})\d+$")

# Indices of features used for peer comparison (must stay in sync with FEATURE_NAMES)
_IDX_AFTER_HOURS  = 1
_IDX_FILE_VOL     = 8
_IDX_USB_COUNT    = 10
_IDX_EMAIL_VOL    = 12
_IDX_RISK_WEIGHT  = 13
_COHORT_IDXS      = [_IDX_AFTER_HOURS, _IDX_FILE_VOL, _IDX_USB_COUNT,
                     _IDX_EMAIL_VOL, _IDX_RISK_WEIGHT]

_COHORT_STATS_PATH = (
    Path(__file__).parent.parent.parent
    / "dataset" / "processed" / "aggregated" / "cohort_stats.json"
)


def extract_role(user_id: str) -> str:
    """Extract department/role code from a CERT user_id string."""
    m = _DEPT_RE.match(user_id.strip())
    return m.group(1).upper() if m else "UNKNOWN"


def build_cohort_stats(
    X: np.ndarray,
    user_ids: list[str],
) -> dict[str, dict[int, tuple[float, float]]]:
    """
    Compute per-cohort (mean, std) for each key feature index.

    Args:
        X:         (n_users, n_features) feature matrix.
        user_ids:  Matching user ID list.

    Returns:
        { role -> { feature_idx -> (mean, std) } }
        Cohorts with fewer than 3 members are excluded.
    """
    import pandas as pd

    roles = [extract_role(uid) for uid in user_ids]
    n_feat = X.shape[1]
    df = pd.DataFrame(X[:, :n_feat], columns=list(range(n_feat)))
    df["role"] = roles

    stats: dict[str, dict[int, tuple[float, float]]] = {}
    for role, grp in df.groupby("role"):
        if len(grp) < 3:
            continue
        stats[role] = {}
        for idx in _COHORT_IDXS:
            if idx < n_feat:
                mean = float(grp[idx].mean())
                std  = float(grp[idx].std(ddof=1))
                stats[role][idx] = (mean, max(std, 1e-9))

    logger.info("Cohort stats built for %d departments.", len(stats))
    return stats


def save_cohort_stats(stats: dict, path: Optional[Path] = None) -> None:
    """Persist cohort stats to JSON for fast online inference."""
    out = path or _COHORT_STATS_PATH
    out.parent.mkdir(parents=True, exist_ok=True)
    # JSON keys must be strings
    serializable = {
        role: {str(k): list(v) for k, v in feat_map.items()}
        for role, feat_map in stats.items()
    }
    with open(out, "w") as f:
        json.dump(serializable, f)
    logger.info("Cohort stats saved → %s", out)


def load_cohort_stats(path: Optional[Path] = None) -> dict[str, dict[int, tuple[float, float]]]:
    """Load cohort stats previously saved by save_cohort_stats()."""
    src = path or _COHORT_STATS_PATH
    if not src.exists():
        return {}
    with open(src) as f:
        raw = json.load(f)
    return {
        role: {int(k): tuple(v) for k, v in feat_map.items()}
        for role, feat_map in raw.items()
    }


def get_peer_deviations(
    user_id: str,
    feature_vector: np.ndarray,
    cohort_stats: Optional[dict] = None,
) -> list[float]:
    """
    Return 5 peer-deviation features for one user:
      [peer_after_hours_deviation, peer_file_volume_deviation,
       peer_usb_deviation, peer_email_deviation, cohort_risk_percentile]

    Each deviation is a Z-score within the cohort, capped to [-3, 3].
    cohort_risk_percentile is the Z-score linearly mapped to [0, 1].

    Returns [0, 0, 0, 0, 0.5] when cohort stats are unavailable.
    """
    if cohort_stats is None:
        return [0.0, 0.0, 0.0, 0.0, 0.5]

    role  = extract_role(user_id)
    stats = cohort_stats.get(role, {})
    if not stats:
        return [0.0, 0.0, 0.0, 0.0, 0.5]

    def _z(idx: int) -> float:
        if idx not in stats or idx >= len(feature_vector):
            return 0.0
        mean, std = stats[idx]
        return float(np.clip((feature_vector[idx] - mean) / std, -3.0, 3.0))

    # Map risk Z-score from [-3, 3] → percentile [0, 1]
    risk_z      = _z(_IDX_RISK_WEIGHT)
    percentile  = float(np.clip((risk_z + 3.0) / 6.0, 0.0, 1.0))

    return [
        _z(_IDX_AFTER_HOURS),   # peer_after_hours_deviation
        _z(_IDX_FILE_VOL),      # peer_file_volume_deviation
        _z(_IDX_USB_COUNT),     # peer_usb_deviation
        _z(_IDX_EMAIL_VOL),     # peer_email_deviation
        percentile,             # cohort_risk_percentile
    ]
