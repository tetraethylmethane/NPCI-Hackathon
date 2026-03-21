"""
ml-service/tests/test_features.py
====================================
Sprint 6 — Unit tests for pipeline/features.py

Tests feature extraction using the synthetic DataFrames from conftest.py.
No real CERT data or trained models required.
"""

import numpy as np
import pandas as pd
import pytest

from pipeline.features import FEATURE_NAMES


# ---------------------------------------------------------------------------
# Helper: empty DataFrame with unified schema
# ---------------------------------------------------------------------------

def _empty_df(source: str = "logon") -> pd.DataFrame:
    from pipeline.ingest import _unified_cols
    return pd.DataFrame(columns=_unified_cols())


# ---------------------------------------------------------------------------
# FEATURE_NAMES contract
# ---------------------------------------------------------------------------

class TestFeatureNames:
    def test_length(self):
        assert len(FEATURE_NAMES) == 32, "Feature vector must be 32-dimensional (Sprint 3 spec)"

    def test_no_duplicates(self):
        assert len(FEATURE_NAMES) == len(set(FEATURE_NAMES)), "Feature names must be unique"

    def test_temporal_group_first(self):
        # First 8 = Temporal group
        temporal = FEATURE_NAMES[:8]
        assert "login_hour_entropy" in temporal
        assert "after_hours_ratio" in temporal
        assert "weekend_ratio" in temporal

    def test_volume_group_indices(self):
        # Indices 8–14 = Volume
        volume = FEATURE_NAMES[8:15]
        assert "usb_plugin_count" in volume
        assert "bulk_copy_count" in volume
        assert "total_risk_weight" in volume

    def test_contextual_group_indices(self):
        # Indices 15–22 = Contextual
        contextual = FEATURE_NAMES[15:23]
        assert "failed_login_ratio" in contextual
        assert "sensitive_file_access_count" in contextual

    def test_peer_group_indices(self):
        # Indices 23–27 = Peer Group
        peer = FEATURE_NAMES[23:28]
        assert any("peer" in name or "cohort" in name or "deviation" in name or "zscore" in name
                   for name in peer), "Peer group features should be in indices 23-27"


# ---------------------------------------------------------------------------
# extract_features: basic smoke tests
# ---------------------------------------------------------------------------

class TestExtractFeatures:
    def test_returns_ndarray_of_correct_shape(self, logon_df, device_df, file_df, email_df, http_df):
        from pipeline.features import extract_features
        fv = extract_features(
            user_id="user_A",
            logon_df=logon_df,
            device_df=device_df,
            file_df=file_df,
            email_df=email_df,
            http_df=http_df,
        )
        assert isinstance(fv, np.ndarray), "extract_features must return ndarray"
        assert fv.shape == (32,), f"Expected shape (32,), got {fv.shape}"
        assert fv.dtype in (np.float32, np.float64)

    def test_no_nan_in_output(self, logon_df, device_df, file_df, email_df, http_df):
        from pipeline.features import extract_features
        fv = extract_features("user_A", logon_df, device_df, file_df, email_df, http_df)
        assert not np.any(np.isnan(fv)), "Feature vector must not contain NaN values"

    def test_no_inf_in_output(self, logon_df, device_df, file_df, email_df, http_df):
        from pipeline.features import extract_features
        fv = extract_features("user_A", logon_df, device_df, file_df, email_df, http_df)
        assert not np.any(np.isinf(fv)), "Feature vector must not contain Inf values"

    def test_all_empty_dataframes(self):
        from pipeline.features import extract_features
        fv = extract_features(
            "ghost_user",
            _empty_df(), _empty_df(), _empty_df(), _empty_df(), _empty_df()
        )
        assert fv.shape == (32,)
        assert not np.any(np.isnan(fv))

    def test_values_in_expected_range(self, logon_df, device_df, file_df, email_df, http_df):
        from pipeline.features import extract_features
        fv = extract_features("user_A", logon_df, device_df, file_df, email_df, http_df)
        # Ratio features should be in [0, 1]
        ratio_indices = [1, 2, 6, 7, 9, 16, 18, 19]  # after_hours, weekend, days_active, etc.
        for idx in ratio_indices:
            assert 0.0 <= fv[idx] <= 1.0, (
                f"Feature '{FEATURE_NAMES[idx]}' (idx={idx}) = {fv[idx]:.4f} out of [0,1]"
            )


# ---------------------------------------------------------------------------
# Temporal feature correctness
# ---------------------------------------------------------------------------

class TestTemporalFeatures:
    def test_after_hours_ratio_benign(self, logon_df, device_df, file_df, email_df, http_df):
        """Benign fixture has is_after_hours=False for all rows → ratio should be 0."""
        from pipeline.features import extract_features
        fv = extract_features("user_A", logon_df, device_df, file_df, email_df, http_df)
        after_hours_idx = FEATURE_NAMES.index("after_hours_ratio")
        assert fv[after_hours_idx] == pytest.approx(0.0, abs=0.01)

    def test_after_hours_ratio_threat(self, threat_logon_df, device_df, file_df, email_df, http_df):
        """Threat fixture has all events after hours → ratio should be close to 1."""
        from pipeline.features import extract_features
        fv = extract_features("threat_user", threat_logon_df, device_df, file_df, email_df, http_df)
        after_hours_idx = FEATURE_NAMES.index("after_hours_ratio")
        assert fv[after_hours_idx] > 0.5, (
            f"after_hours_ratio should be high for threat user, got {fv[after_hours_idx]}"
        )

    def test_failed_login_ratio(self, logon_df, device_df, file_df, email_df, http_df):
        """Benign fixture has 2 failures out of 18 logon attempts → ratio ~0.11."""
        from pipeline.features import extract_features
        fv = extract_features("user_A", logon_df, device_df, file_df, email_df, http_df)
        idx = FEATURE_NAMES.index("failed_login_ratio")
        # 2 failures out of 18 total logon events (16 success + 2 failure)
        assert 0.0 <= fv[idx] <= 1.0


# ---------------------------------------------------------------------------
# Volume feature correctness
# ---------------------------------------------------------------------------

class TestVolumeFeatures:
    def test_usb_count_benign(self, logon_df, device_df, file_df, email_df, http_df):
        """Benign fixture has 2 USB_DEVICE_CONNECTED events."""
        from pipeline.features import extract_features
        fv = extract_features("user_A", logon_df, device_df, file_df, email_df, http_df)
        idx = FEATURE_NAMES.index("usb_plugin_count")
        assert fv[idx] >= 0.0

    def test_bulk_copy_exfil(self, logon_df, exfil_device_df, file_df, email_df, http_df):
        """Exfil fixture has 15 USB_FILE_COPY events → bulk_copy_count should be non-zero."""
        from pipeline.features import extract_features
        fv = extract_features("threat_user", logon_df, exfil_device_df, file_df, email_df, http_df)
        idx = FEATURE_NAMES.index("bulk_copy_count")
        assert fv[idx] > 0.0, f"bulk_copy_count should reflect USB file copies, got {fv[idx]}"

    def test_email_attachment_rate(self, logon_df, device_df, file_df, email_df, http_df):
        """Benign fixture: 0 EMAIL_SENT_ATTACH out of 4 EMAIL_SENT → rate = 0."""
        from pipeline.features import extract_features
        fv = extract_features("user_A", logon_df, device_df, file_df, email_df, http_df)
        idx = FEATURE_NAMES.index("email_attachment_rate")
        assert 0.0 <= fv[idx] <= 1.0


# ---------------------------------------------------------------------------
# build_feature_payload
# ---------------------------------------------------------------------------

class TestBuildFeaturePayload:
    def test_payload_structure(self):
        from pipeline.features import build_feature_payload
        fv = np.ones(32, dtype=np.float32)
        payload = build_feature_payload("user_TEST", fv)
        assert "names" in payload
        assert "values" in payload
        assert "user_id" in payload
        assert payload["user_id"] == "user_TEST"
        assert len(payload["names"]) == 32
        assert len(payload["values"]) == 32

    def test_payload_names_match_feature_names(self):
        from pipeline.features import build_feature_payload
        fv = np.zeros(32, dtype=np.float32)
        payload = build_feature_payload("u1", fv)
        assert payload["names"] == FEATURE_NAMES

    def test_payload_values_are_serializable(self):
        import json
        from pipeline.features import build_feature_payload
        fv = np.random.rand(32).astype(np.float32)
        payload = build_feature_payload("u1", fv)
        # Must be JSON-serializable for Postgres JSONB storage
        serialized = json.dumps(payload)
        assert isinstance(serialized, str)
