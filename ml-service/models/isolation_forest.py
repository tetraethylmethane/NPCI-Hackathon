"""
Isolation Forest — Unsupervised Anomaly Detector
--------------------------------------------------
Primary model. Requires no labels. Trained on the full CERT user population.

Anomaly score is mapped to a 0-100 risk scale:
  score_if ∈ [-1, 0]  (sklearn convention: lower = more anomalous)
  risk = (1 - score_if) * 50   → maps [-1,0] to [100, 50]
  Clamped to [0, 100].
"""

import os
import joblib
import numpy as np
from pathlib import Path
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

WEIGHTS_DIR = Path(__file__).parent / "weights"
WEIGHTS_DIR.mkdir(exist_ok=True)

IF_PATH = WEIGHTS_DIR / "isolation_forest.joblib"
SCALER_PATH = WEIGHTS_DIR / "scaler_if.joblib"


class IsolationForestModel:
    def __init__(self, contamination: float = 0.05, n_estimators: int = 200, random_state: int = 42):
        self.contamination = contamination
        self.model = IsolationForest(
            n_estimators=n_estimators,
            contamination=contamination,
            random_state=random_state,
            n_jobs=-1,
        )
        self.scaler = StandardScaler()
        self.trained = False

    def train(self, X: np.ndarray) -> None:
        """Fit on the full user-feature matrix (unlabelled)."""
        X_scaled = self.scaler.fit_transform(X)
        self.model.fit(X_scaled)
        self.trained = True
        joblib.dump(self.model, IF_PATH)
        joblib.dump(self.scaler, SCALER_PATH)
        print(f"IsolationForest trained on {X.shape[0]} users, {X.shape[1]} features. Saved to {IF_PATH}")

    def predict_score(self, x: np.ndarray) -> float:
        """
        Returns risk score in [0, 100] for a single feature vector x of shape (n_features,).
        Higher = more anomalous.
        """
        if not self.trained:
            raise RuntimeError("Model not trained. Call train() or load() first.")
        x_scaled = self.scaler.transform(x.reshape(1, -1))
        raw_score = self.model.score_samples(x_scaled)[0]   # [-1, 0]
        risk = float(np.clip((1.0 + abs(raw_score)) * 50, 0, 100))
        return risk

    def predict_batch(self, X: np.ndarray) -> np.ndarray:
        """Returns risk scores for a batch (n_users, n_features) → (n_users,) in [0, 100]."""
        if not self.trained:
            raise RuntimeError("Model not trained.")
        X_scaled = self.scaler.transform(X)
        raw_scores = self.model.score_samples(X_scaled)
        return np.clip((1.0 + np.abs(raw_scores)) * 50, 0, 100)

    def load(self) -> bool:
        """Load persisted model weights. Returns True if successful."""
        if IF_PATH.exists() and SCALER_PATH.exists():
            self.model = joblib.load(IF_PATH)
            self.scaler = joblib.load(SCALER_PATH)
            self.trained = True
            return True
        return False
