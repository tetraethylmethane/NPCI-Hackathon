"""
CERT Dataset Ingestion Pipeline
--------------------------------
Loads and normalises the CMU CERT Insider Threat dataset (r4.2 / r6.2).

Expected CSV files (place in /dataset/):
  logon.csv   — columns: id, date, user, pc, activity
  device.csv  — columns: id, date, user, pc, activity
  file.csv    — columns: id, date, user, pc, filename, activity
  email.csv   — columns: id, date, user, pc, to, cc, bcc, from, size, attachments, content
  http.csv    — columns: id, date, user, pc, url, activity

Ground-truth labels (r4.2):
  answers/insiders.csv — columns: dataset, details, user, scenario, action_date, ...
"""

import os
import pandas as pd
from pathlib import Path
from datetime import datetime
from typing import Optional

DATASET_DIR = Path(__file__).parent.parent.parent / "dataset"

# Canonical column names after normalisation
COMMON_COLS = ["event_id", "timestamp", "user_id", "pc", "event_type", "source"]


def _parse_cert_timestamp(ts_str: str) -> datetime:
    """Parse CERT dataset timestamp format: MM/DD/YYYY HH:MM:SS"""
    return datetime.strptime(ts_str.strip(), "%m/%d/%Y %H:%M:%S")


def load_logon(path: Optional[Path] = None) -> pd.DataFrame:
    path = path or DATASET_DIR / "logon.csv"
    df = pd.read_csv(path)
    df = df.rename(columns={"id": "event_id", "date": "timestamp", "user": "user_id"})
    df["source"] = "logon"
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df[["event_id", "timestamp", "user_id", "pc", "activity", "source"]]


def load_device(path: Optional[Path] = None) -> pd.DataFrame:
    path = path or DATASET_DIR / "device.csv"
    df = pd.read_csv(path)
    df = df.rename(columns={"id": "event_id", "date": "timestamp", "user": "user_id"})
    df["source"] = "device"
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df[["event_id", "timestamp", "user_id", "pc", "activity", "source"]]


def load_file(path: Optional[Path] = None) -> pd.DataFrame:
    path = path or DATASET_DIR / "file.csv"
    df = pd.read_csv(path)
    df = df.rename(columns={"id": "event_id", "date": "timestamp", "user": "user_id"})
    df["source"] = "file"
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df[["event_id", "timestamp", "user_id", "pc", "filename", "activity", "source"]]


def load_email(path: Optional[Path] = None) -> pd.DataFrame:
    path = path or DATASET_DIR / "email.csv"
    df = pd.read_csv(path)
    df = df.rename(columns={"id": "event_id", "date": "timestamp", "user": "user_id"})
    df["source"] = "email"
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    # Parse recipient counts from to/cc/bcc columns (semicolon-separated)
    df["external_recipients"] = (
        df["to"].fillna("").str.count(";") + 1 +
        df["cc"].fillna("").str.count(";") +
        df["bcc"].fillna("").str.count(";")
    )
    return df


def load_http(path: Optional[Path] = None) -> pd.DataFrame:
    path = path or DATASET_DIR / "http.csv"
    df = pd.read_csv(path)
    df = df.rename(columns={"id": "event_id", "date": "timestamp", "user": "user_id"})
    df["source"] = "http"
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df


def load_ground_truth(path: Optional[Path] = None) -> pd.DataFrame:
    """Load CERT r4.2 ground truth labels. Returns user IDs flagged as malicious."""
    path = path or DATASET_DIR / "answers" / "insiders.csv"
    if not path.exists():
        return pd.DataFrame(columns=["user_id", "scenario"])
    df = pd.read_csv(path)
    df = df.rename(columns={"user": "user_id"})
    return df[["user_id", "scenario"]].drop_duplicates()


def ingest_cert_dataset() -> dict:
    """
    Load all available CERT sources and return summary stats.
    Called by FastAPI POST /ingest/cert endpoint.
    """
    results = {}
    loaders = {
        "logon": load_logon,
        "device": load_device,
        "file": load_file,
        "email": load_email,
        "http": load_http,
    }
    for name, loader in loaders.items():
        csv_path = DATASET_DIR / f"{name}.csv"
        if csv_path.exists():
            try:
                df = loader(csv_path)
                results[name] = {"rows": len(df), "users": df["user_id"].nunique()}
            except Exception as e:
                results[name] = {"error": str(e)}
        else:
            results[name] = {"skipped": "file not found"}

    gt = load_ground_truth()
    results["ground_truth"] = {"malicious_users": len(gt)}
    return results
