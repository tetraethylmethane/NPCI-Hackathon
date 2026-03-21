"""
ml-service/tests/test_ingest.py
=================================
Sprint 6 — Unit tests for pipeline/ingest.py

Tests use synthetic in-memory CSV data — no real CERT files required.
All tests run without internet access or a database connection.
"""

import io
from datetime import datetime, timezone

import numpy as np
import pandas as pd
import pytest


# ---------------------------------------------------------------------------
# Helpers to build synthetic CSV content
# ---------------------------------------------------------------------------

def _logon_csv(rows: list[dict]) -> str:
    lines = ["id,date,user,pc,activity"]
    for r in rows:
        lines.append(f"{r['id']},{r['date']},{r['user']},{r['pc']},{r['activity']}")
    return "\n".join(lines)


def _device_csv(rows: list[dict]) -> str:
    lines = ["id,date,user,pc,activity"]
    for r in rows:
        lines.append(f"{r['id']},{r['date']},{r['user']},{r['pc']},{r['activity']}")
    return "\n".join(lines)


def _file_csv(rows: list[dict]) -> str:
    lines = ["id,date,user,pc,filename,activity"]
    for r in rows:
        lines.append(f"{r['id']},{r['date']},{r['user']},{r['pc']},{r['filename']},{r['activity']}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Tests: _parse_timestamp
# ---------------------------------------------------------------------------

class TestParseTimestamp:
    def test_standard_cert_format(self):
        from pipeline.ingest import _parse_timestamp
        s = pd.Series(["01/02/2010 07:14:00", "12/31/2010 23:59:00"])
        result = _parse_timestamp(s)
        assert result.notna().all(), "All standard CERT timestamps should parse"
        assert result.dt.tz is not None, "Should be timezone-aware"

    def test_iso_format(self):
        from pipeline.ingest import _parse_timestamp
        s = pd.Series(["2010-06-15 08:30:00", "2011-01-20 17:00:00"])
        result = _parse_timestamp(s)
        assert result.notna().all()

    def test_corrupt_timestamps_become_nat(self):
        from pipeline.ingest import _parse_timestamp
        s = pd.Series(["not-a-date", "also-bad", "01/01/2010 00:00:00"])
        result = _parse_timestamp(s)
        assert result.isna().sum() == 2, "Two corrupt timestamps should be NaT"
        assert result.notna().sum() == 1

    def test_empty_series(self):
        from pipeline.ingest import _parse_timestamp
        result = _parse_timestamp(pd.Series([], dtype=str))
        assert len(result) == 0


# ---------------------------------------------------------------------------
# Tests: _normalize_logon
# ---------------------------------------------------------------------------

class TestNormalizeLogon:
    def _make_path(self, tmp_path, content: str):
        p = tmp_path / "logon.csv"
        p.write_text(content)
        return p

    def test_basic_structure(self, tmp_path):
        from pipeline.ingest import _normalize_logon
        csv = _logon_csv([
            {"id": "L1", "date": "01/10/2010 09:00:00", "user": "ACM1234", "pc": "PC-1", "activity": "Logon"},
            {"id": "L2", "date": "01/10/2010 17:00:00", "user": "ACM1234", "pc": "PC-1", "activity": "Logoff"},
        ])
        path = self._make_path(tmp_path, csv)
        df = _normalize_logon(path)

        expected_cols = {"event_id", "timestamp", "user_id", "pc", "source",
                         "action_type", "risk_weight", "is_after_hours",
                         "is_weekend", "metadata", "is_null_flagged"}
        assert expected_cols.issubset(set(df.columns)), "Must have all unified schema columns"
        assert len(df) == 2

    def test_action_type_mapping(self, tmp_path):
        from pipeline.ingest import _normalize_logon
        csv = _logon_csv([
            {"id": "L1", "date": "01/10/2010 09:00:00", "user": "U1", "pc": "PC-1", "activity": "Logon"},
            {"id": "L2", "date": "01/10/2010 09:10:00", "user": "U1", "pc": "PC-1", "activity": "Logoff"},
            {"id": "L3", "date": "01/10/2010 09:20:00", "user": "U1", "pc": "PC-1", "activity": "Failed logon"},
        ])
        df = _normalize_logon(self._make_path(tmp_path, csv))
        types = df["action_type"].tolist()
        assert "LOGON_SUCCESS" in types
        assert "LOGOFF" in types
        assert "LOGON_FAILURE" in types

    def test_null_pc_imputed(self, tmp_path):
        from pipeline.ingest import _normalize_logon
        csv = "id,date,user,pc,activity\nL1,01/10/2010 09:00:00,U1,,Logon"
        df = _normalize_logon(self._make_path(tmp_path, csv))
        assert df.iloc[0]["pc"] == "UNKNOWN-PC"
        assert df.iloc[0]["is_null_flagged"] is True or df.iloc[0]["is_null_flagged"] == True

    def test_corrupt_timestamp_dropped(self, tmp_path):
        from pipeline.ingest import _normalize_logon
        csv = _logon_csv([
            {"id": "L1", "date": "NOT-A-DATE",           "user": "U1", "pc": "PC-1", "activity": "Logon"},
            {"id": "L2", "date": "01/10/2010 09:00:00",  "user": "U1", "pc": "PC-1", "activity": "Logon"},
        ])
        df = _normalize_logon(self._make_path(tmp_path, csv))
        assert len(df) == 1, "Row with corrupt timestamp should be dropped"

    def test_risk_weight_after_hours_bonus(self, tmp_path):
        from pipeline.ingest import _normalize_logon, AFTER_HOURS_BONUS, BASE_WEIGHTS
        # 23:00 = after hours
        csv = _logon_csv([
            {"id": "L1", "date": "01/10/2010 23:00:00", "user": "U1", "pc": "PC-1", "activity": "Logon"},
        ])
        df = _normalize_logon(self._make_path(tmp_path, csv))
        expected = BASE_WEIGHTS["LOGON_SUCCESS"] + AFTER_HOURS_BONUS
        assert df.iloc[0]["risk_weight"] == expected

    def test_source_field(self, tmp_path):
        from pipeline.ingest import _normalize_logon
        csv = _logon_csv([
            {"id": "L1", "date": "01/10/2010 09:00:00", "user": "U1", "pc": "PC-1", "activity": "Logon"},
        ])
        df = _normalize_logon(self._make_path(tmp_path, csv))
        assert (df["source"] == "logon").all()


# ---------------------------------------------------------------------------
# Tests: _normalize_device
# ---------------------------------------------------------------------------

class TestNormalizeDevice:
    def test_connect_disconnect_mapping(self, tmp_path):
        from pipeline.ingest import _normalize_device
        csv = _device_csv([
            {"id": "D1", "date": "01/10/2010 09:00:00", "user": "U1", "pc": "PC-1", "activity": "Connect"},
            {"id": "D2", "date": "01/10/2010 09:10:00", "user": "U1", "pc": "PC-1", "activity": "Disconnect"},
        ])
        path = tmp_path / "device.csv"
        path.write_text(csv)
        df = _normalize_device(path)
        assert "USB_DEVICE_CONNECTED" in df["action_type"].values
        assert "USB_DEVICE_DISCONNECT" in df["action_type"].values


# ---------------------------------------------------------------------------
# Tests: _normalize_file
# ---------------------------------------------------------------------------

class TestNormalizeFile:
    def test_file_action_mapping(self, tmp_path):
        from pipeline.ingest import _normalize_file
        rows = [
            ("F1", "open"),
            ("F2", "copy"),
            ("F3", "delete"),
            ("F4", "write"),
        ]
        lines = ["id,date,user,pc,filename,activity"]
        for fid, act in rows:
            lines.append(f"{fid},01/10/2010 09:00:00,U1,PC-1,file.txt,{act}")
        path = tmp_path / "file.csv"
        path.write_text("\n".join(lines))
        df = _normalize_file(path)
        types = set(df["action_type"].tolist())
        assert "FILE_ACCESS" in types
        assert "FILE_COPY" in types
        assert "FILE_DELETE" in types
        assert "FILE_WRITE" in types


# ---------------------------------------------------------------------------
# Tests: unified_cols
# ---------------------------------------------------------------------------

def test_unified_cols_length():
    from pipeline.ingest import _unified_cols
    cols = _unified_cols()
    assert len(cols) == 11, "Unified schema should have exactly 11 columns"
    assert "user_id" in cols
    assert "action_type" in cols


# ---------------------------------------------------------------------------
# Tests: load_ground_truth
# ---------------------------------------------------------------------------

def test_load_ground_truth_missing(tmp_path):
    from pipeline.ingest import load_ground_truth
    result = load_ground_truth(tmp_path / "nonexistent.csv")
    assert isinstance(result, pd.DataFrame)
    assert len(result) == 0
    assert "user_id" in result.columns


def test_load_ground_truth_valid(tmp_path):
    from pipeline.ingest import load_ground_truth
    gt = tmp_path / "insiders.csv"
    gt.write_text("user,scenario\nACM1234,1\nBCD5678,2\n")
    result = load_ground_truth(gt)
    assert "user_id" in result.columns
    assert len(result) == 2
    assert "ACM1234" in result["user_id"].values
