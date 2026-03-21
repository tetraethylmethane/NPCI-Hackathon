"""
ml-service/tests/conftest.py
==============================
Sprint 6 — Shared pytest fixtures for the NPCI Identity Guard test suite.

Provides synthetic DataFrames that match the CERT normalised schema
used by ingest.py, features.py, and ensemble.py — without requiring
the real 1.3 GB CERT CSV files.
"""

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

# ---------------------------------------------------------------------------
# Timestamp helpers
# ---------------------------------------------------------------------------

BASE_DT = datetime(2010, 3, 15, 9, 0, 0, tzinfo=timezone.utc)


def make_timestamps(n: int, start: datetime = BASE_DT, interval_minutes: int = 30):
    return pd.array(
        [pd.Timestamp(start + timedelta(minutes=i * interval_minutes)) for i in range(n)],
        dtype="datetime64[ns, UTC]",
    )


# ---------------------------------------------------------------------------
# Fixtures: normalised DataFrames (one per source)
# ---------------------------------------------------------------------------

@pytest.fixture
def logon_df():
    """Minimal normalised logon DataFrame for a single benign user."""
    n = 20
    return pd.DataFrame({
        "event_id":      [f"L{i}" for i in range(n)],
        "timestamp":     make_timestamps(n),
        "user_id":       ["user_A"] * n,
        "pc":            ["PC-00aabbcc"] * n,
        "source":        ["logon"] * n,
        "action_type":   (["LOGON_SUCCESS"] * 16 + ["LOGON_FAILURE"] * 2 + ["LOGOFF"] * 2),
        "risk_weight":   ([2] * 16 + [8] * 2 + [0] * 2),
        "is_after_hours":[False] * n,
        "is_weekend":    [False] * n,
        "metadata":      ['{"raw_activity": "Logon"}'] * n,
        "is_null_flagged":[False] * n,
    })


@pytest.fixture
def device_df():
    """Minimal normalised device DataFrame."""
    n = 4
    return pd.DataFrame({
        "event_id":      [f"D{i}" for i in range(n)],
        "timestamp":     make_timestamps(n),
        "user_id":       ["user_A"] * n,
        "pc":            ["PC-00aabbcc"] * n,
        "source":        ["device"] * n,
        "action_type":   (["USB_DEVICE_CONNECTED"] * 2 + ["USB_DEVICE_DISCONNECT"] * 2),
        "risk_weight":   ([5] * 2 + [0] * 2),
        "is_after_hours":[False] * n,
        "is_weekend":    [False] * n,
        "metadata":      ['{"raw_activity": "Connect"}'] * n,
        "is_null_flagged":[False] * n,
    })


@pytest.fixture
def file_df():
    """Minimal normalised file DataFrame."""
    n = 10
    return pd.DataFrame({
        "event_id":      [f"F{i}" for i in range(n)],
        "timestamp":     make_timestamps(n),
        "user_id":       ["user_A"] * n,
        "pc":            ["PC-00aabbcc"] * n,
        "source":        ["file"] * n,
        "action_type":   ["FILE_ACCESS"] * n,
        "risk_weight":   [5] * n,
        "is_after_hours":[False] * n,
        "is_weekend":    [False] * n,
        "metadata":      ['{"raw_activity": "open", "filename": "report.docx"}'] * n,
        "is_null_flagged":[False] * n,
    })


@pytest.fixture
def email_df():
    """Minimal normalised email DataFrame."""
    n = 6
    return pd.DataFrame({
        "event_id":      [f"E{i}" for i in range(n)],
        "timestamp":     make_timestamps(n),
        "user_id":       ["user_A"] * n,
        "pc":            ["PC-00aabbcc"] * n,
        "source":        ["email"] * n,
        "action_type":   ["EMAIL_SENT"] * 4 + ["EMAIL_RECEIVED"] * 2,
        "risk_weight":   [3] * 4 + [1] * 2,
        "is_after_hours":[False] * n,
        "is_weekend":    [False] * n,
        "metadata":      ['{"from_addr": "abcd1234@[redacted]"}'] * n,
        "is_null_flagged":[False] * n,
    })


@pytest.fixture
def http_df():
    """Minimal normalised HTTP DataFrame."""
    n = 8
    return pd.DataFrame({
        "event_id":      [f"H{i}" for i in range(n)],
        "timestamp":     make_timestamps(n),
        "user_id":       ["user_A"] * n,
        "pc":            ["PC-00aabbcc"] * n,
        "source":        ["http"] * n,
        "action_type":   ["HTTP_VISIT"] * 6 + ["HTTP_CLOUD"] * 2,
        "risk_weight":   [1] * 6 + [6] * 2,
        "is_after_hours":[False] * n,
        "is_weekend":    [False] * n,
        "metadata":      ['{"url": "URL-aabbccdd1122"}'] * n,
        "is_null_flagged":[False] * n,
    })


# ---------------------------------------------------------------------------
# Fixture: threat actor logon DataFrame (for attack scenario tests)
# ---------------------------------------------------------------------------

@pytest.fixture
def threat_logon_df():
    """
    After-hours logon DataFrame for a simulated malicious insider.
    High: after_hours_ratio, failed_login_ratio, unique_host_count.
    """
    n = 30
    # All events after 22:00
    start = datetime(2010, 3, 15, 22, 30, 0, tzinfo=timezone.utc)
    return pd.DataFrame({
        "event_id":      [f"TL{i}" for i in range(n)],
        "timestamp":     make_timestamps(n, start=start, interval_minutes=15),
        "user_id":       ["threat_user"] * n,
        "pc":            [f"PC-host{i % 5:02d}aabb" for i in range(n)],  # 5 different PCs
        "source":        ["logon"] * n,
        "action_type":   (["LOGON_FAILURE"] * 10 + ["LOGON_SUCCESS"] * 15 + ["LOGOFF"] * 5),
        "risk_weight":   ([8] * 10 + [2] * 15 + [0] * 5),
        "is_after_hours":[True] * n,
        "is_weekend":    [True] * 10 + [False] * 20,
        "metadata":      ['{"raw_activity": "Logon"}'] * n,
        "is_null_flagged":[False] * n,
    })


@pytest.fixture
def exfil_device_df():
    """
    USB bulk-copy DataFrame for a simulated data exfiltration scenario.
    High: bulk_copy_count, usb_plugin_count.
    """
    n = 20
    return pd.DataFrame({
        "event_id":      [f"ED{i}" for i in range(n)],
        "timestamp":     make_timestamps(n),
        "user_id":       ["threat_user"] * n,
        "pc":            ["PC-00aabbcc"] * n,
        "source":        ["device"] * n,
        "action_type":   (["USB_DEVICE_CONNECTED"] * 5 + ["USB_FILE_COPY"] * 15),
        "risk_weight":   ([5] * 5 + [20] * 15),
        "is_after_hours":[True] * n,
        "is_weekend":    [False] * n,
        "metadata":      ['{"raw_activity": "Connect"}'] * n,
        "is_null_flagged":[False] * n,
    })


# ---------------------------------------------------------------------------
# Fixture: 32-dim feature vector (benign baseline)
# ---------------------------------------------------------------------------

@pytest.fixture
def benign_feature_vector():
    """32-dimensional feature vector representing a typical benign user."""
    from pipeline.features import FEATURE_NAMES
    rng = np.random.default_rng(42)
    v = np.zeros(len(FEATURE_NAMES), dtype=np.float32)
    # Temporal: moderate entropy, low after-hours
    v[0]  = 2.5    # login_hour_entropy
    v[1]  = 0.05   # after_hours_ratio
    v[2]  = 0.1    # weekend_ratio
    v[3]  = 15.0   # avg_daily_events
    v[4]  = 1.2    # activity_burst_score
    v[5]  = 1.8    # logon_hour_std
    v[6]  = 0.7    # days_active_ratio
    v[7]  = 0.01   # deep_night_ratio
    # Volume: normal
    v[8]  = 1.0    # file_access_vs_mean
    v[9]  = 0.1    # email_attachment_rate
    v[10] = 0.5    # usb_plugin_count
    v[11] = 0.0    # bulk_copy_count
    v[12] = 1.0    # email_volume_ratio
    v[13] = 5.0    # total_risk_weight (normalised)
    v[14] = 1.0    # http_cloud_visit_count
    # Contextual
    v[15] = 1.0    # unique_host_count
    v[16] = 0.05   # failed_login_ratio
    v[17] = 0.0    # sensitive_file_access_count
    v[18] = 0.05   # file_delete_ratio
    v[19] = 0.1    # external_email_ratio
    v[20] = 0.0    # job_site_visit_count
    v[21] = 0.0    # executable_download_count
    v[22] = 0.0    # bcc_usage_count
    # Peer group + baseline
    v[23:] = 0.0
    return v


@pytest.fixture
def threat_feature_vector():
    """32-dimensional feature vector representing a malicious insider."""
    from pipeline.features import FEATURE_NAMES
    v = np.zeros(len(FEATURE_NAMES), dtype=np.float32)
    # High after-hours, high failures, many hosts, bulk USB copy
    v[0]  = 0.5    # low entropy (concentrated logons)
    v[1]  = 0.75   # after_hours_ratio HIGH
    v[2]  = 0.4    # weekend_ratio HIGH
    v[3]  = 45.0   # avg_daily_events HIGH burst
    v[4]  = 8.5    # activity_burst_score HIGH
    v[5]  = 3.9    # logon_hour_std HIGH (irregular)
    v[6]  = 0.3    # days_active_ratio LOW (concentrated)
    v[7]  = 0.35   # deep_night_ratio HIGH
    v[8]  = 5.0    # file_access_vs_mean 5× baseline (capped)
    v[9]  = 0.8    # email_attachment_rate HIGH
    v[10] = 12.0   # usb_plugin_count HIGH
    v[11] = 18.0   # bulk_copy_count HIGH
    v[12] = 4.5    # email_volume_ratio HIGH
    v[13] = 42.0   # total_risk_weight HIGH
    v[14] = 15.0   # http_cloud_visit_count HIGH
    v[15] = 7.0    # unique_host_count HIGH (multiple machines)
    v[16] = 0.45   # failed_login_ratio HIGH
    v[17] = 5.0    # sensitive_file_access_count HIGH
    v[18] = 0.35   # file_delete_ratio HIGH
    v[19] = 0.8    # external_email_ratio HIGH
    v[20] = 6.0    # job_site_visit_count HIGH
    v[21] = 3.0    # executable_download_count
    v[22] = 4.0    # bcc_usage_count
    v[23:] = 3.5   # peer group deviations HIGH
    return v
