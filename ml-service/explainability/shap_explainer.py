"""
SHAP Explainability Layer
--------------------------
Wraps shap.TreeExplainer around the Random Forest model to produce
per-prediction feature attributions.

Output (stored in UserSnapshot.vectorData and returned via /explain/{user_id}):
  {
    "top_features": [
      { "name": "after_hours_logon_ratio", "value": 0.82, "impact": 0.34, "direction": "increases_risk" },
      { "name": "usb_mount_count",         "value": 4.0,  "impact": 0.21, "direction": "increases_risk" },
      { "name": "file_delete_ratio",       "value": 0.05, "impact": -0.08,"direction": "decreases_risk" },
    ],
    "summary": "Risk driven by after-hours logons (0.82×) and USB activity (4 mounts).",
    "model": "RandomForest",
    "shap_base_value": 0.05
  }
"""

import numpy as np
from typing import Any

try:
    import shap
    SHAP_AVAILABLE = True
except ImportError:
    SHAP_AVAILABLE = False
    print("⚠️  shap not installed — explainability will return feature importance fallback.")

from pipeline.features import FEATURE_NAMES


HUMAN_LABELS = {
    "after_hours_logon_ratio":   "after-hours logon activity",
    "weekend_logon_ratio":       "weekend logon activity",
    "failed_login_count":        "failed login attempts",
    "unique_host_count":         "logins from multiple machines",
    "avg_session_duration_mins": "unusually long sessions",
    "usb_mount_count":           "USB device connections",
    "unique_device_count":       "multiple unique devices",
    "bulk_file_copy_flag":       "bulk file copy activity",
    "device_after_hours_ratio":  "after-hours device use",
    "sensitive_file_access_count": "sensitive file accesses",
    "file_delete_ratio":         "file deletion rate",
    "executable_download_count": "executable file downloads",
    "bulk_access_flag":          "bulk file access event",
    "total_file_events":         "high file activity volume",
    "external_recipient_ratio":  "external email recipients",
    "large_attachment_count":    "large email attachments",
    "after_hours_email_ratio":   "after-hours email activity",
    "bcc_usage_count":           "BCC email usage",
    "cloud_storage_visit_count": "cloud storage visits",
    "job_site_visit_count":      "job site browsing",
}


class SHAPExplainer:
    def __init__(self, rf_model=None):
        self.rf_model = rf_model
        self._explainer = None

        if SHAP_AVAILABLE and rf_model is not None and getattr(rf_model, "trained", False):
            self._explainer = shap.TreeExplainer(rf_model.model)

    def explain(self, feature_vector: np.ndarray, top_k: int = 3) -> dict:
        """
        Generate SHAP explanation for a single user's feature vector.

        Falls back to RF feature_importances_ if SHAP is unavailable.
        """
        if self._explainer is not None:
            return self._explain_shap(feature_vector, top_k)
        elif self.rf_model is not None and getattr(self.rf_model, "feature_importances_", None) is not None:
            return self._explain_importance_fallback(feature_vector, top_k)
        else:
            return self._explain_unavailable()

    def _explain_shap(self, x: np.ndarray, top_k: int) -> dict:
        x_scaled = self.rf_model.scaler.transform(x.reshape(1, -1))
        shap_values = self._explainer.shap_values(x_scaled)

        # shap_values shape: (2, 1, n_features) for binary RF — use class-1 (malicious)
        if isinstance(shap_values, list):
            values = shap_values[1][0]
        else:
            values = shap_values[0]

        base_value = float(self._explainer.expected_value[1] if isinstance(
            self._explainer.expected_value, (list, np.ndarray)
        ) else self._explainer.expected_value)

        ranked_idx = np.argsort(np.abs(values))[::-1][:top_k]
        top_features = []
        for i in ranked_idx:
            impact = float(values[i])
            top_features.append({
                "name": FEATURE_NAMES[i],
                "label": HUMAN_LABELS.get(FEATURE_NAMES[i], FEATURE_NAMES[i]),
                "value": float(x[i]),
                "impact": round(impact, 4),
                "direction": "increases_risk" if impact > 0 else "decreases_risk",
            })

        summary = _build_summary(top_features)
        return {
            "top_features": top_features,
            "summary": summary,
            "model": "RandomForest+SHAP",
            "shap_base_value": round(base_value, 4),
        }

    def _explain_importance_fallback(self, x: np.ndarray, top_k: int) -> dict:
        importances = self.rf_model.feature_importances_
        ranked_idx = np.argsort(importances)[::-1][:top_k]
        top_features = []
        for i in ranked_idx:
            top_features.append({
                "name": FEATURE_NAMES[i],
                "label": HUMAN_LABELS.get(FEATURE_NAMES[i], FEATURE_NAMES[i]),
                "value": float(x[i]),
                "impact": round(float(importances[i]), 4),
                "direction": "increases_risk",
            })
        return {
            "top_features": top_features,
            "summary": _build_summary(top_features),
            "model": "RandomForest+FeatureImportance",
            "shap_base_value": None,
        }

    def _explain_unavailable(self) -> dict:
        return {
            "top_features": [],
            "summary": "Explanation unavailable (model not trained or SHAP not installed).",
            "model": "none",
            "shap_base_value": None,
        }


def _build_summary(top_features: list[dict]) -> str:
    """Build a human-readable 1-sentence explanation from top features."""
    if not top_features:
        return "No explanation available."
    parts = []
    for f in top_features[:3]:
        if f["direction"] == "increases_risk":
            parts.append(f"{f['label']} ({f['value']:.1f})")
    if not parts:
        return "Risk score is within normal range."
    return "Risk driven by: " + ", ".join(parts) + "."
