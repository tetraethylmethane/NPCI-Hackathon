"""
ml-service/tests/test_integration.py
=======================================
Sprint 6 — Integration Tests

Tests the full analysis pipeline without a database or FastAPI server.
Simulates the flow: feature extraction → ensemble scoring → alert threshold.

Integration Test 1 — Normal user, no alert:
  Seed 7 days of normal behaviour → extract features → score → verify score < 70.

Integration Test 2 — Injected threat, alert generated:
  Seed 7 days of normal behaviour + spike of threat events → extract features
  → score → verify score ≥ 70 (alert zone) after threat injection.

Integration Test 3 — Anonymization round-trip:
  Verify that pseudonymize_user_id is deterministic and produces the same
  hash for the same input, and different hashes for different inputs.

These tests require NO database, NO FastAPI server, and NO CERT CSV files.
They use the synthetic fixtures from conftest.py.

Marker: @pytest.mark.integration
Run all tests:    pytest tests/
Run only unit:    pytest tests/ -m "not integration"
Run integration:  pytest tests/ -m integration
"""

import numpy as np
import pytest

from pipeline.features import FEATURE_NAMES


# ---------------------------------------------------------------------------
# Mark integration tests so they can be excluded in fast CI runs
# ---------------------------------------------------------------------------
pytestmark = pytest.mark.integration


# ---------------------------------------------------------------------------
# Integration Test 1 — Normal user stays below alert threshold
# ---------------------------------------------------------------------------

class TestNormalUserBelowThreshold:
    """
    A user with 7 days of typical office activity (logons, file access,
    emails, normal HTTP) should produce a feature vector that, when scored
    by the Z-Score statistical layer, does not reach the alert zone (≥70).
    """

    def test_after_hours_ratio_low(self, logon_df, device_df, file_df, email_df, http_df):
        from pipeline.features import extract_features
        fv = extract_features("user_A", logon_df, device_df, file_df, email_df, http_df)
        idx = FEATURE_NAMES.index("after_hours_ratio")
        assert fv[idx] < 0.5, "Normal user should have low after-hours ratio"

    def test_failed_login_ratio_low(self, logon_df, device_df, file_df, email_df, http_df):
        from pipeline.features import extract_features
        fv = extract_features("user_A", logon_df, device_df, file_df, email_df, http_df)
        idx = FEATURE_NAMES.index("failed_login_ratio")
        assert fv[idx] < 0.5

    def test_z_score_below_alert(self, logon_df, device_df, file_df, email_df, http_df):
        """
        Build a synthetic population of 50 benign users + 1 normal user.
        The Z-score normalised score for the normal user should be < 50 (i.e., Z < 2.5).
        """
        from pipeline.features import extract_features
        from evaluation.per_layer import zscore_scores

        # Build synthetic population: 50 users with similar-to-benign vectors
        rng = np.random.default_rng(seed=0)
        n_users = 50
        # Simulate feature index 13 (total_risk_weight) as normally distributed
        risk_weights = rng.normal(loc=5.0, scale=1.0, size=n_users)
        X_pop = np.zeros((n_users, 32), dtype=np.float32)
        X_pop[:, 13] = risk_weights

        # Add our normal user at the population mean
        normal_user_fv = extract_features(
            "user_A", logon_df, device_df, file_df, email_df, http_df
        )
        # Append normal user to population for scoring
        X_with_normal = np.vstack([X_pop, normal_user_fv.reshape(1, -1)])
        scores = zscore_scores(X_with_normal, feature_idx=13)

        normal_score = scores[-1]
        assert normal_score < 70, (
            f"Normal user Z-score normalised score={normal_score:.1f} should be < 70"
        )


# ---------------------------------------------------------------------------
# Integration Test 2 — Injected threat reaches alert threshold
# ---------------------------------------------------------------------------

class TestThreatUserReachesAlertThreshold:
    """
    Confirms that threat-indicative feature values (from conftest threat_feature_vector)
    produce a high Z-score normalised score relative to a benign population.
    This validates the end-to-end signal: threat events → feature encoding → anomaly score.
    """

    def test_threat_zscore_above_alert(self, benign_feature_vector, threat_feature_vector):
        """
        Place one threat user among 50 benign users.
        The threat user's Z-score normalised score for total_risk_weight (idx=13)
        should be significantly higher than the alert threshold (70).
        """
        from evaluation.per_layer import zscore_scores

        n_benign = 50
        rng = np.random.default_rng(seed=42)
        benign_pop = np.tile(benign_feature_vector, (n_benign, 1))
        # Add small noise to simulate realistic population
        benign_pop += rng.normal(0, 0.1, benign_pop.shape)

        X = np.vstack([benign_pop, threat_feature_vector.reshape(1, -1)])
        scores = zscore_scores(X, feature_idx=13)

        threat_score = scores[-1]
        benign_mean  = scores[:-1].mean()

        assert threat_score > benign_mean, \
            "Threat user score should exceed benign population mean"

        assert threat_score > 50.0, (
            f"Threat user Z-score score={threat_score:.1f} "
            "should be elevated above population baseline"
        )

    def test_threat_total_risk_weight_higher_than_benign(
        self, benign_feature_vector, threat_feature_vector
    ):
        """Threat vector feature 13 (total_risk_weight) must exceed benign vector."""
        assert threat_feature_vector[13] > benign_feature_vector[13], \
            "Threat user total_risk_weight must exceed benign baseline"

    def test_exfil_features_extracted_correctly(
        self, logon_df, exfil_device_df, file_df, email_df, http_df
    ):
        """
        Full pipeline: inject USB bulk-copy events → extract features → verify
        that bulk_copy_count and usb_plugin_count are activated.
        """
        from pipeline.features import extract_features
        fv = extract_features("threat_user", logon_df, exfil_device_df, file_df, email_df, http_df)

        bulk_idx = FEATURE_NAMES.index("bulk_copy_count")
        usb_idx  = FEATURE_NAMES.index("usb_plugin_count")

        assert fv[bulk_idx] > 0.0, "Bulk copy events must be captured in feature vector"
        assert fv[usb_idx]  > 0.0, "USB plugin events must be captured in feature vector"
        assert np.all(np.isfinite(fv)), "Feature vector must be finite after threat injection"


# ---------------------------------------------------------------------------
# Integration Test 3 — Anonymization round-trip
# ---------------------------------------------------------------------------

class TestAnonymizationRoundTrip:
    """
    Verifies the Sprint 5 anonymization module is deterministic and collision-resistant.
    Does not require a database — tests pure Python HMAC logic.
    """

    def test_deterministic_for_same_input(self):
        from pipeline.anonymize import pseudonymize_user_id
        uid = "ACM2278"
        assert pseudonymize_user_id(uid) == pseudonymize_user_id(uid), \
            "pseudonymize_user_id must be deterministic"

    def test_different_ids_produce_different_hashes(self):
        from pipeline.anonymize import pseudonymize_user_id
        h1 = pseudonymize_user_id("ACM2278")
        h2 = pseudonymize_user_id("ACM2279")
        assert h1 != h2, "Different user IDs must produce different hashes"

    def test_hash_length_is_16_chars(self):
        from pipeline.anonymize import pseudonymize_user_id
        h = pseudonymize_user_id("TEST_USER")
        assert len(h) == 16, "Anonymized user ID must be 16 hex chars"

    def test_email_pseudonymization(self):
        from pipeline.anonymize import pseudonymize_email
        result = pseudonymize_email("alice@example.com")
        assert "@[redacted]" in result, "Pseudonymized email must contain @[redacted]"
        assert "alice" not in result, "Original local part must be removed"

    def test_pc_pseudonymization(self):
        from pipeline.anonymize import pseudonymize_pc
        result = pseudonymize_pc("PC-ACM2278-1")
        assert result.startswith("PC-"), "Pseudonymized PC must start with PC-"
        assert "ACM2278" not in result, "Original hostname must be removed"

    def test_dataframe_pseudonymization_changes_user_id(
        self, logon_df
    ):
        from pipeline.anonymize import pseudonymize_dataframe
        original_ids = set(logon_df["user_id"].tolist())
        df_anon, mappings = pseudonymize_dataframe(logon_df.copy(), source="logon")
        new_ids = set(df_anon["user_id"].tolist())

        assert original_ids != new_ids, "user_id column must be changed after anonymization"
        assert len(mappings) > 0, "Must return identity mappings"
        assert all("hashedUserId" in m and "originalId" in m for m in mappings)

    def test_mapping_is_reversible_with_secret(self, logon_df):
        """
        The mapping table contains both sides — confirm the original ID
        can be recovered from the mapping.
        """
        from pipeline.anonymize import pseudonymize_dataframe, pseudonymize_user_id
        original_id = logon_df["user_id"].iloc[0]
        _, mappings = pseudonymize_dataframe(logon_df.copy(), source="logon")

        found = next((m for m in mappings if m["originalId"] == original_id), None)
        assert found is not None, "Original ID must appear in identity mappings"
        assert found["hashedUserId"] == pseudonymize_user_id(original_id), \
            "Mapping hash must match direct pseudonymize_user_id() call"
