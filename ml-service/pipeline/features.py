"""
Feature Engineering
--------------------
Extracts a 20-dimensional behavioural feature vector per user from CERT logs.

Feature groups:
  [0-4]   Logon features
  [5-8]   Device features
  [9-13]  File features
  [14-17] Email features
  [18-19] HTTP features

Call:
  vector = extract_features(user_id, logon_df, device_df, file_df, email_df, http_df)
"""

import numpy as np
import pandas as pd
from datetime import time

WORK_START = time(8, 0)
WORK_END = time(18, 0)
CLOUD_STORAGE_DOMAINS = {"dropbox.com", "drive.google.com", "onedrive.live.com", "box.com", "mega.nz"}
JOB_SITE_DOMAINS = {"linkedin.com", "indeed.com", "glassdoor.com", "monster.com", "naukri.com"}
SENSITIVE_EXTENSIONS = {".sql", ".bak", ".key", ".pem", ".env", ".csv", ".xlsx", ".pdf"}


def _is_after_hours(ts: pd.Timestamp) -> bool:
    t = ts.time()
    return t < WORK_START or t > WORK_END


def _is_weekend(ts: pd.Timestamp) -> bool:
    return ts.dayofweek >= 5


def extract_logon_features(user_df: pd.DataFrame) -> list[float]:
    """5 features from logon.csv rows for a single user."""
    if user_df.empty:
        return [0.0] * 5

    total = len(user_df)
    logons = user_df[user_df["activity"].str.lower() == "logon"]
    logoffs = user_df[user_df["activity"].str.lower() == "logoff"]

    after_hours = logons["timestamp"].apply(_is_after_hours).sum()
    weekend = logons["timestamp"].apply(_is_weekend).sum()

    # Estimate session duration (logon → nearest following logoff)
    avg_session = 0.0
    if len(logons) > 0 and len(logoffs) > 0:
        diffs = []
        for _, lon in logons.iterrows():
            after = logoffs[logoffs["timestamp"] > lon["timestamp"]]
            if not after.empty:
                diffs.append((after.iloc[0]["timestamp"] - lon["timestamp"]).seconds / 60)
        avg_session = float(np.mean(diffs)) if diffs else 0.0

    failed = user_df[user_df["activity"].str.lower().str.contains("fail", na=False)]
    unique_hosts = user_df["pc"].nunique()

    return [
        after_hours / max(len(logons), 1),   # after_hours_logon_ratio
        weekend / max(len(logons), 1),        # weekend_logon_ratio
        float(len(failed)),                   # failed_login_count
        float(unique_hosts),                  # unique_host_count
        avg_session,                          # avg_session_duration_mins
    ]


def extract_device_features(user_df: pd.DataFrame) -> list[float]:
    """4 features from device.csv rows for a single user."""
    if user_df.empty:
        return [0.0] * 4

    connect = user_df[user_df["activity"].str.lower().str.contains("connect", na=False)]
    copy = user_df[user_df["activity"].str.lower().str.contains("copy|write", na=False)]

    after_hours_device = connect["timestamp"].apply(_is_after_hours).sum()

    return [
        float(len(connect)),                              # usb_mount_count
        float(user_df["pc"].nunique()),                   # unique_device_count (reuse pc col)
        1.0 if len(copy) > 10 else float(len(copy)) / 10, # bulk_file_copy_flag (normalised)
        after_hours_device / max(len(connect), 1),        # device_after_hours_ratio
    ]


def extract_file_features(user_df: pd.DataFrame) -> list[float]:
    """5 features from file.csv rows for a single user."""
    if user_df.empty:
        return [0.0] * 5

    total = len(user_df)
    deletes = user_df[user_df["activity"].str.lower().str.contains("delete|remove", na=False)]
    exes = user_df[user_df["filename"].fillna("").str.lower().str.endswith((".exe", ".bat", ".sh", ".ps1"))]
    sensitive = user_df[
        user_df["filename"].fillna("").apply(
            lambda f: any(f.lower().endswith(ext) for ext in SENSITIVE_EXTENSIONS)
        )
    ]
    bulk_access = 1.0 if total > 200 else 0.0

    return [
        float(len(sensitive)),           # sensitive_file_access_count
        len(deletes) / max(total, 1),    # file_delete_ratio
        float(len(exes)),                # executable_download_count
        bulk_access,                     # bulk_access_flag
        float(total),                    # total_file_events (raw volume)
    ]


def extract_email_features(user_df: pd.DataFrame) -> list[float]:
    """4 features from email.csv rows for a single user."""
    if user_df.empty:
        return [0.0] * 4

    sent = user_df[user_df["activity"].str.lower().str.contains("send", na=False)]
    after_hours_email = sent["timestamp"].apply(_is_after_hours).sum()

    # Detect external recipients (no @company domain) — heuristic: contains different domain
    external_ratio = 0.0
    if "external_recipients" in user_df.columns:
        external_ratio = float(user_df["external_recipients"].mean())

    # Large attachments: size > 5MB (5_000_000 bytes) — column may be 'size' or 'attachments'
    large_attach = 0
    if "size" in user_df.columns:
        large_attach = int((pd.to_numeric(user_df["size"], errors="coerce").fillna(0) > 5_000_000).sum())
    elif "attachments" in user_df.columns:
        large_attach = int((pd.to_numeric(user_df["attachments"], errors="coerce").fillna(0) > 0).sum())

    bcc_count = 0
    if "bcc" in user_df.columns:
        bcc_count = int(user_df["bcc"].fillna("").str.len().gt(0).sum())

    return [
        external_ratio,                            # external_recipient_ratio
        float(large_attach),                       # large_attachment_count
        after_hours_email / max(len(sent), 1),     # after_hours_email_ratio
        float(bcc_count),                          # bcc_usage_count
    ]


def extract_http_features(user_df: pd.DataFrame) -> list[float]:
    """2 features from http.csv rows for a single user."""
    if user_df.empty:
        return [0.0] * 2

    def _domain(url: str) -> str:
        try:
            from urllib.parse import urlparse
            return urlparse(url).netloc.lower().replace("www.", "")
        except Exception:
            return ""

    if "url" in user_df.columns:
        domains = user_df["url"].fillna("").apply(_domain)
        cloud = domains.isin(CLOUD_STORAGE_DOMAINS).sum()
        job_sites = domains.isin(JOB_SITE_DOMAINS).sum()
    else:
        cloud, job_sites = 0, 0

    return [
        float(cloud),     # cloud_storage_visit_count
        float(job_sites), # job_site_visit_count
    ]


FEATURE_NAMES = [
    # Logon [0-4]
    "after_hours_logon_ratio", "weekend_logon_ratio", "failed_login_count",
    "unique_host_count", "avg_session_duration_mins",
    # Device [5-8]
    "usb_mount_count", "unique_device_count", "bulk_file_copy_flag", "device_after_hours_ratio",
    # File [9-13]
    "sensitive_file_access_count", "file_delete_ratio", "executable_download_count",
    "bulk_access_flag", "total_file_events",
    # Email [14-17]
    "external_recipient_ratio", "large_attachment_count", "after_hours_email_ratio", "bcc_usage_count",
    # HTTP [18-19]
    "cloud_storage_visit_count", "job_site_visit_count",
]


def extract_features(
    user_id: str,
    logon_df: pd.DataFrame,
    device_df: pd.DataFrame,
    file_df: pd.DataFrame,
    email_df: pd.DataFrame,
    http_df: pd.DataFrame,
) -> np.ndarray:
    """
    Build a 20-feature vector for a single user.

    Args:
        user_id: The user identifier (matches 'user_id' column in all DataFrames).
        *_df: Full dataset DataFrames (not pre-filtered).

    Returns:
        np.ndarray of shape (20,) — the feature vector.
    """
    def _filter(df: pd.DataFrame) -> pd.DataFrame:
        return df[df["user_id"] == user_id] if not df.empty else df

    features = (
        extract_logon_features(_filter(logon_df))
        + extract_device_features(_filter(device_df))
        + extract_file_features(_filter(file_df))
        + extract_email_features(_filter(email_df))
        + extract_http_features(_filter(http_df))
    )

    return np.array(features, dtype=np.float32)
