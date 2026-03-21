"""
Sprint 3 — Feature Engineering (32-dimensional vector)
========================================================
Extracts a rich, structured feature vector per user organised into four groups
that maximally separate normal from insider-threat behaviour.

Feature groups and indices
─────────────────────────
  Temporal    [0–7]   — login hour entropy, after-hours/late-night/weekend
                        ratios, daily activity statistics
  Volume      [8–14]  — file/email volume vs personal baseline, USB counts,
                        cloud uploads, total risk weight
  Contextual  [15–22] — host variance, failed logins, sensitive files, delete
                        ratio, external email, job-site visits, exe downloads
  Peer Group  [23–27] — Z-score deviation within role/department cohort
  Baseline    [28–31] — retained high-signal Sprint-1 features

Two extraction modes
────────────────────
  MODE A — from normalised Parquet (batch / training):
    load_feature_matrix()  → (X: ndarray(n, 32), user_ids)
    get_user_vector(uid)   → ndarray(32,)

  MODE B — from raw DataFrames (online inference via FastAPI):
    extract_features(uid, logon_df, device_df, file_df, email_df, http_df,
                     personal_baseline=None, cohort_stats=None)
                         → ndarray(32,)
"""

import json
import logging
from functools import lru_cache
from pathlib import Path
from typing import Optional

import numpy as np
import pandas as pd
from scipy.stats import entropy as _scipy_entropy

from pipeline.constants import (
    WORK_START, WORK_END,
    CLOUD_STORAGE_DOMAINS, JOB_SITE_DOMAINS, SENSITIVE_EXTENSIONS,
    LATE_NIGHT_START, LATE_NIGHT_END,
    is_after_hours  as _is_after_hours,
    is_weekend      as _is_weekend,
    is_late_night   as _is_late_night,
    domain_of       as _domain_of,
)

logger = logging.getLogger(__name__)

# ── Feature definitions ────────────────────────────────────────────────────────

FEATURE_NAMES: list[str] = [
    # Temporal [0–7]
    "login_hour_entropy",          # Shannon entropy of logon-hour distribution
    "after_hours_ratio",           # events 22:00–06:00 / total  (Sprint-3 spec)
    "weekend_ratio",               # events on weekends / total
    "avg_daily_events",            # mean events per active day
    "activity_burst_score",        # max single-day events / 30d personal mean
    "logon_hour_std",              # std of logon hours (high = irregular)
    "days_active_ratio",           # days with ≥1 event / 30
    "deep_night_ratio",            # events 00:00–04:00 / total
    # Volume [8–14]
    "file_access_vs_mean",         # file events / 30d personal mean (capped 5×)
    "email_attachment_rate",       # emails with attachment / total sent
    "usb_plugin_count",            # USB DEVICE_CONNECTED events (raw)
    "bulk_copy_count",             # USB_FILE_COPY events (data staging)
    "email_volume_ratio",          # email events / 30d personal mean (capped 5×)
    "total_risk_weight",           # Σ risk_weights / 100 (normalised)
    "http_cloud_visit_count",      # visits to cloud-storage domains
    # Contextual [15–22]
    "unique_host_count",           # distinct PCs / workstations
    "failed_login_ratio",          # LOGON_FAILURE / total login attempts
    "sensitive_file_access_count", # files with .sql/.bak/.key/.pem/.env …
    "file_delete_ratio",           # FILE_DELETE / total file events
    "external_email_ratio",        # external recipients / total recipients
    "job_site_visit_count",        # visits to job-search sites
    "executable_download_count",   # .exe/.bat/.sh/.ps1/.cmd downloads
    "bcc_usage_count",             # emails with BCC field populated
    # Peer Group [23–27]
    "peer_after_hours_deviation",  # Z-score vs role cohort after_hours_ratio
    "peer_file_volume_deviation",  # Z-score vs role cohort file event volume
    "peer_usb_deviation",          # Z-score vs role cohort USB count
    "peer_email_deviation",        # Z-score vs role cohort email volume
    "cohort_risk_percentile",      # risk percentile within department [0, 1]
    # Statistical Baseline [28–31]
    "after_hours_logon_ratio",     # logons outside 08:00-18:00 / total logons
    "failed_login_count",          # raw count (threshold signal)
    "avg_session_duration_mins",   # mean logon-to-logoff duration
    "device_after_hours_ratio",    # USB events outside work hours / total USB
]

assert len(FEATURE_NAMES) == 32, "Feature count must remain 32"

# Groups for dashboard / SHAP display
FEATURE_GROUPS = {
    "temporal":    list(range(0, 8)),
    "volume":      list(range(8, 15)),
    "contextual":  list(range(15, 23)),
    "peer_group":  list(range(23, 28)),
    "baseline":    list(range(28, 32)),
}

_WINDOW_DAYS = 30
_DEEP_NIGHT_END = pd.Timestamp("04:00").time()


# ── Internal per-group extractors ──────────────────────────────────────────────

def _temporal_features(all_df: pd.DataFrame, logon_df: pd.DataFrame) -> list[float]:
    """Indices 0–7: temporal activity patterns."""
    if all_df.empty:
        return [0.0] * 8

    ts = all_df["timestamp"]

    # 0 — login_hour_entropy
    if not logon_df.empty and "timestamp" in logon_df.columns:
        hour_probs = logon_df["timestamp"].dt.hour.value_counts(normalize=True).values
        entropy = float(_scipy_entropy(hour_probs, base=2)) if len(hour_probs) > 1 else 0.0
    else:
        entropy = 0.0

    total = max(len(all_df), 1)

    # 1 — after_hours_ratio  (10 PM – 6 AM)
    late = _is_late_night(ts).sum()
    after_hours_ratio = late / total

    # 2 — weekend_ratio
    weekend_ratio = _is_weekend(ts).sum() / total

    # 3 — avg_daily_events
    unique_dates = ts.dt.date.nunique()
    avg_daily = len(all_df) / max(unique_dates, 1)

    # 4 — activity_burst_score  (requires personal_baseline from caller; default 1.0)
    daily_counts = all_df.groupby(ts.dt.date).size()
    max_day = float(daily_counts.max()) if not daily_counts.empty else 0.0
    # We use population mean as burst denominator when personal baseline not available.
    burst = max_day / max(avg_daily, 1.0)

    # 5 — logon_hour_std
    if not logon_df.empty and "timestamp" in logon_df.columns:
        hours = logon_df["timestamp"].dt.hour
        logon_std = float(hours.std(ddof=1)) if len(hours) > 1 else 0.0
    else:
        logon_std = 0.0

    # 6 — days_active_ratio
    days_active = unique_dates / _WINDOW_DAYS

    # 7 — deep_night_ratio  (midnight – 4 AM)
    deep_t = ts.dt.time
    deep = deep_t.apply(lambda x: x < _DEEP_NIGHT_END if pd.notna(x) else False).sum()
    deep_night_ratio = deep / total

    return [
        entropy,
        after_hours_ratio,
        weekend_ratio,
        avg_daily,
        burst,
        logon_std,
        min(days_active, 1.0),
        deep_night_ratio,
    ]


def _volume_features(
    file_df: pd.DataFrame,
    email_df: pd.DataFrame,
    device_df: pd.DataFrame,
    http_df: pd.DataFrame,
    all_df: pd.DataFrame,
    personal_baseline: Optional[dict] = None,
) -> list[float]:
    """Indices 8–14: data-exfiltration volume signals."""
    pb = personal_baseline or {}

    # 8 — file_access_vs_mean
    file_count  = len(file_df)
    file_mean   = pb.get("file_events_mean", max(file_count, 1))
    file_ratio  = min(file_count / max(file_mean, 1), 5.0)

    # 9 — email_attachment_rate
    n_sent  = max(email_df[email_df["action_type"].isin(
        ["EMAIL_SENT", "EMAIL_SENT_ATTACH"])].shape[0], 1) if not email_df.empty else 1
    n_attach = email_df[email_df["action_type"] == "EMAIL_SENT_ATTACH"].shape[0] \
        if not email_df.empty else 0
    attach_rate = n_attach / n_sent

    # 10 — usb_plugin_count
    usb_count = device_df[device_df["action_type"] == "USB_DEVICE_CONNECTED"].shape[0] \
        if not device_df.empty else 0

    # 11 — bulk_copy_count
    bulk_copy = device_df[device_df["action_type"] == "USB_FILE_COPY"].shape[0] \
        if not device_df.empty else 0

    # 12 — email_volume_ratio
    email_count = len(email_df)
    email_mean  = pb.get("email_events_mean", max(email_count, 1))
    email_ratio = min(email_count / max(email_mean, 1), 5.0)

    # 13 — total_risk_weight  (normalised to 0–100)
    total_risk = all_df["risk_weight"].sum() if ("risk_weight" in all_df.columns and not all_df.empty) else 0
    risk_norm  = min(float(total_risk) / 100.0, 100.0)

    # 14 — http_cloud_visit_count
    cloud_count = 0
    if not http_df.empty:
        cloud_count = http_df[http_df["action_type"] == "HTTP_CLOUD"].shape[0]
        if cloud_count == 0 and "metadata" in http_df.columns:
            for meta_str in http_df["metadata"].dropna():
                try:
                    meta = json.loads(meta_str) if isinstance(meta_str, str) else {}
                    if _domain_of(str(meta.get("url", ""))) in CLOUD_STORAGE_DOMAINS:
                        cloud_count += 1
                except (json.JSONDecodeError, TypeError):
                    pass

    return [
        file_ratio,
        attach_rate,
        float(usb_count),
        float(bulk_copy),
        email_ratio,
        risk_norm,
        float(cloud_count),
    ]


def _contextual_features(
    logon_df: pd.DataFrame,
    file_df: pd.DataFrame,
    email_df: pd.DataFrame,
    http_df: pd.DataFrame,
    all_df: pd.DataFrame,
) -> list[float]:
    """Indices 15–22: access context and misuse signals."""
    # 15 — unique_host_count
    unique_hosts = all_df["pc"].nunique() if ("pc" in all_df.columns and not all_df.empty) else 0

    # 16 — failed_login_ratio
    total_attempts = logon_df[logon_df["action_type"].isin(
        ["LOGON_SUCCESS", "LOGON_FAILURE"])].shape[0] if not logon_df.empty else 0
    failures = logon_df[logon_df["action_type"] == "LOGON_FAILURE"].shape[0] \
        if not logon_df.empty else 0
    fail_ratio = failures / max(total_attempts, 1)

    # 17 — sensitive_file_access_count
    sensitive_count = 0
    if not file_df.empty and "metadata" in file_df.columns:
        for meta_str in file_df["metadata"].dropna():
            try:
                meta = json.loads(meta_str) if isinstance(meta_str, str) else {}
                fn = str(meta.get("filename", "")).lower()
                if any(fn.endswith(ext) for ext in SENSITIVE_EXTENSIONS):
                    sensitive_count += 1
            except (json.JSONDecodeError, TypeError):
                pass

    # 18 — file_delete_ratio
    file_total  = max(len(file_df), 1)
    deletes     = file_df[file_df["action_type"] == "FILE_DELETE"].shape[0] \
        if not file_df.empty else 0
    delete_ratio = deletes / file_total

    # 19 — external_email_ratio
    ext_ratio = _external_email_ratio(email_df)

    # 20 — job_site_visit_count
    job_count = 0
    if not http_df.empty:
        job_count = http_df[http_df["action_type"] == "HTTP_JOB_SITE"].shape[0]
        if job_count == 0 and "metadata" in http_df.columns:
            for meta_str in http_df["metadata"].dropna():
                try:
                    meta = json.loads(meta_str) if isinstance(meta_str, str) else {}
                    if _domain_of(str(meta.get("url", ""))) in JOB_SITE_DOMAINS:
                        job_count += 1
                except (json.JSONDecodeError, TypeError):
                    pass

    # 21 — executable_download_count
    exe_count = 0
    if not file_df.empty and "metadata" in file_df.columns:
        for meta_str in file_df["metadata"].dropna():
            try:
                meta = json.loads(meta_str) if isinstance(meta_str, str) else {}
                fn = str(meta.get("filename", "")).lower()
                if fn.endswith((".exe", ".bat", ".sh", ".ps1", ".cmd")):
                    exe_count += 1
            except (json.JSONDecodeError, TypeError):
                pass

    # 22 — bcc_usage_count
    bcc_count = 0
    if not email_df.empty and "metadata" in email_df.columns:
        for meta_str in email_df["metadata"].dropna():
            try:
                meta = json.loads(meta_str) if isinstance(meta_str, str) else {}
                if meta.get("bcc") and str(meta["bcc"]).strip():
                    bcc_count += 1
            except (json.JSONDecodeError, TypeError):
                pass

    return [
        float(unique_hosts),
        fail_ratio,
        float(sensitive_count),
        delete_ratio,
        ext_ratio,
        float(job_count),
        float(exe_count),
        float(bcc_count),
    ]


def _baseline_features(logon_df: pd.DataFrame, device_df: pd.DataFrame) -> list[float]:
    """Indices 28–31: retained high-signal Sprint-1 features."""
    # 28 — after_hours_logon_ratio  (work-hours definition: outside 08:00-18:00)
    if not logon_df.empty:
        logons = logon_df[logon_df["action_type"] == "LOGON_SUCCESS"]
        n_logons = max(len(logons), 1)
        ah_logon = _is_after_hours(logons["timestamp"]).sum() if not logons.empty else 0
        ah_ratio = ah_logon / n_logons
        failed   = logon_df[logon_df["action_type"] == "LOGON_FAILURE"].shape[0]
    else:
        ah_ratio, failed, logons = 0.0, 0, pd.DataFrame()

    # 29 — failed_login_count (raw)

    # 30 — avg_session_duration_mins
    avg_session = 0.0
    if not logon_df.empty:
        logoffs = logon_df[logon_df["action_type"] == "LOGOFF"]
        if not logons.empty and not logoffs.empty:
            diffs = []
            for _, lon in logons.head(200).iterrows():
                later = logoffs[logoffs["timestamp"] > lon["timestamp"]]
                if not later.empty:
                    secs = (later.iloc[0]["timestamp"] - lon["timestamp"]).total_seconds()
                    if 0 < secs < 86400:
                        diffs.append(secs / 60)
            avg_session = float(np.mean(diffs)) if diffs else 0.0

    # 31 — device_after_hours_ratio
    if not device_df.empty:
        connects = device_df[device_df["action_type"] == "USB_DEVICE_CONNECTED"]
        n_dev    = max(len(connects), 1)
        ah_dev   = _is_after_hours(connects["timestamp"]).sum() if not connects.empty else 0
        dev_ah   = ah_dev / n_dev
    else:
        dev_ah = 0.0

    return [ah_ratio, float(failed), avg_session, dev_ah]


# ── Helper ─────────────────────────────────────────────────────────────────────

def _external_email_ratio(email_df: pd.DataFrame) -> float:
    if email_df.empty or "metadata" not in email_df.columns:
        return 0.0
    ext_total, total_checked = 0, 0
    for meta_str in email_df["metadata"].dropna():
        try:
            meta = json.loads(meta_str) if isinstance(meta_str, str) else {}
            to_str = str(meta.get("to", "") or "")
            if "@" not in to_str:
                continue
            addrs = [a.strip() for a in to_str.replace(";", ",").split(",") if "@" in a]
            if not addrs:
                continue
            domains = [a.split("@")[-1].lower() for a in addrs]
            org     = domains[0]
            ext_total   += sum(1 for d in domains if d != org)
            total_checked += len(domains)
        except (json.JSONDecodeError, TypeError, AttributeError):
            pass
    return ext_total / max(total_checked, 1)


# ── Public API — Mode B: online inference ──────────────────────────────────────

def extract_features(
    user_id: str,
    logon_df: pd.DataFrame,
    device_df: pd.DataFrame,
    file_df: pd.DataFrame,
    email_df: pd.DataFrame,
    http_df: pd.DataFrame,
    personal_baseline: Optional[dict] = None,
    cohort_stats: Optional[dict] = None,
) -> np.ndarray:
    """
    Build the 32-feature vector for one user.

    Args:
        user_id:           Target user.
        logon/device/…_df: Full-population DataFrames — filtered internally.
        personal_baseline: {"file_events_mean": float, "email_events_mean": float}
        cohort_stats:      Output of peer_groups.build_cohort_stats() — for peer features.

    Returns:
        ndarray shape (32,) dtype float32.
    """
    def _filter(df: pd.DataFrame) -> pd.DataFrame:
        if df.empty or "user_id" not in df.columns:
            return df
        return df[df["user_id"] == user_id]

    l = _filter(logon_df)
    d = _filter(device_df)
    f = _filter(file_df)
    e = _filter(email_df)
    h = _filter(http_df)

    sources = [df for df in [l, d, f, e, h] if not df.empty]
    all_df  = pd.concat(sources, ignore_index=True) if sources else pd.DataFrame()

    temporal    = _temporal_features(all_df, l)
    volume      = _volume_features(f, e, d, h, all_df, personal_baseline)
    contextual  = _contextual_features(l, f, e, h, all_df)

    # Peer group: placeholder zeros — filled in by load_feature_matrix two-pass
    peer        = [0.0, 0.0, 0.0, 0.0, 0.5]
    baseline    = _baseline_features(l, d)

    fv = np.array(
        temporal + volume + contextual + peer + baseline,
        dtype=np.float32,
    )
    assert len(fv) == 32

    # Fill peer features immediately if cohort_stats are provided
    if cohort_stats is not None:
        from pipeline.peer_groups import get_peer_deviations
        fv[23:28] = get_peer_deviations(user_id, fv, cohort_stats)

    return fv


def build_feature_payload(user_id: str, fv: np.ndarray) -> dict:
    """
    Wrap a feature vector into the JSON shape stored in RiskSnapshot.featureVector.
    """
    return {
        "names":  FEATURE_NAMES,
        "values": [round(float(v), 6) for v in fv],
        "groups": FEATURE_GROUPS,
        "user_id": user_id,
    }


# ── Public API — Mode A: batch from Parquet ────────────────────────────────────

@lru_cache(maxsize=4)
def _load_sources_cached(normalized_dir: Optional[Path] = None) -> dict:
    """Load all normalised Parquet files once and cache by directory path."""
    from pipeline.ingest import load_all_normalized
    return load_all_normalized(normalized_dir)


def _compute_personal_baselines(normalized_dir: Optional[Path] = None) -> dict[str, dict]:
    """
    Returns {user_id: {"file_events_mean": float, "email_events_mean": float}}
    from daily_snapshots.parquet.  Falls back to empty dict if file not found.
    """
    try:
        from pipeline.transform import load_daily_snapshots
        daily = load_daily_snapshots()
        baselines: dict[str, dict] = {}
        for uid, grp in daily.groupby("user_id"):
            baselines[uid] = {
                "file_events_mean":  float(grp["file_events"].mean()),
                "email_events_mean": float(grp["email_events"].mean()),
            }
        return baselines
    except Exception as e:
        logger.debug("Personal baselines unavailable (%s); ratios will be population-normalised.", e)
        return {}


def load_feature_matrix(
    normalized_dir: Optional[Path] = None,
    user_ids: Optional[list[str]] = None,
) -> tuple[np.ndarray, list[str]]:
    """
    Build the full (n_users × 32) feature matrix from normalised Parquet files.

    Two-pass approach:
      Pass 1 — extract base features (indices 0-22, 28-31); peer group = zeros.
      Pass 2 — build cohort stats and fill peer features (indices 23-27).

    Returns:
        (X, user_id_list) — float32 feature matrix and matching user IDs.
    """
    from pipeline.peer_groups import build_cohort_stats, get_peer_deviations, save_cohort_stats

    sources   = _load_sources_cached(normalized_dir)
    baselines = _compute_personal_baselines(normalized_dir)

    all_users: set[str] = set()
    for df in sources.values():
        if not df.empty and "user_id" in df.columns:
            all_users.update(df["user_id"].dropna().unique())
    if user_ids:
        all_users = all_users.intersection(user_ids)
    all_users_list = sorted(all_users)

    logger.info("Building 32-feature matrix for %d users…", len(all_users_list))

    # ── Pass 1 ──
    rows: list[np.ndarray] = []
    for uid in all_users_list:
        fv = extract_features(
            uid,
            sources.get("logon",  pd.DataFrame()),
            sources.get("device", pd.DataFrame()),
            sources.get("file",   pd.DataFrame()),
            sources.get("email",  pd.DataFrame()),
            sources.get("http",   pd.DataFrame()),
            personal_baseline=baselines.get(uid),
            cohort_stats=None,   # peer features filled in pass 2
        )
        rows.append(fv)

    X = np.array(rows, dtype=np.float32) if rows else np.zeros((0, 32), dtype=np.float32)

    # ── Pass 2: compute and inject peer features ──
    if len(X) >= 3:
        cohort_stats = build_cohort_stats(X, all_users_list)
        save_cohort_stats(cohort_stats)          # persist for online inference
        for i, uid in enumerate(all_users_list):
            X[i, 23:28] = get_peer_deviations(uid, X[i], cohort_stats)
    else:
        cohort_stats = {}

    logger.info("Feature matrix shape: %s", X.shape)
    return X, all_users_list


def get_user_vector(
    user_id: str,
    normalized_dir: Optional[Path] = None,
) -> np.ndarray:
    """
    Extract the 32-feature vector for a single user from Parquet files.
    Uses pre-computed cohort stats from disk for peer-group features.
    """
    from pipeline.peer_groups import load_cohort_stats

    sources   = _load_sources_cached(normalized_dir)
    baselines = _compute_personal_baselines(normalized_dir)
    cohort_stats = load_cohort_stats()   # returns {} if not yet computed

    return extract_features(
        user_id,
        sources.get("logon",  pd.DataFrame()),
        sources.get("device", pd.DataFrame()),
        sources.get("file",   pd.DataFrame()),
        sources.get("email",  pd.DataFrame()),
        sources.get("http",   pd.DataFrame()),
        personal_baseline=baselines.get(user_id),
        cohort_stats=cohort_stats or None,
    )
