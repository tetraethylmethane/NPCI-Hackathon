"""
Shared constants for the CERT ETL pipeline and feature engineering.
Centralises domain lists, time-window definitions, and helper functions
used by both ingest.py and features.py.
"""

from datetime import time as dtime
from urllib.parse import urlparse

import pandas as pd

WORK_START = dtime(8, 0)
WORK_END   = dtime(18, 0)

# Sprint 3: Late-night window (10 PM – 6 AM) — wraps midnight
LATE_NIGHT_START = dtime(22, 0)
LATE_NIGHT_END   = dtime(6, 0)

CLOUD_STORAGE_DOMAINS = frozenset({
    "dropbox.com", "drive.google.com", "onedrive.live.com", "box.com",
    "mega.nz", "wetransfer.com",
})
JOB_SITE_DOMAINS = frozenset({
    "linkedin.com", "indeed.com", "glassdoor.com",
    "monster.com", "naukri.com", "careerbuilder.com",
})
SENSITIVE_EXTENSIONS = frozenset({
    ".sql", ".bak", ".key", ".pem", ".env", ".csv",
    ".xlsx", ".xls", ".pdf", ".db", ".mdb",
})


def is_late_night(ts: pd.Series) -> pd.Series:
    """True for timestamps between 22:00 and 06:00 (wraps midnight)."""
    t = ts.dt.time
    return t.apply(
        lambda x: (x >= LATE_NIGHT_START or x < LATE_NIGHT_END) if pd.notna(x) else False
    )


def is_after_hours(ts: pd.Series) -> pd.Series:
    t = ts.dt.time
    return t.apply(lambda x: x < WORK_START or x > WORK_END if pd.notna(x) else False)


def is_weekend(ts: pd.Series) -> pd.Series:
    return ts.dt.dayofweek >= 5


def domain_of(url: str) -> str:
    try:
        return urlparse(str(url)).netloc.lower().replace("www.", "")
    except Exception:
        return ""
