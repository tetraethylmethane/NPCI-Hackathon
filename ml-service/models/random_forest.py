"""
Random Forest Classifier — Supervised Threat Detector
-------------------------------------------------------
Requires CERT ground-truth labels (answers/insiders.csv).
Trained only when labelled data is available.

Output: malicious_probability ∈ [0, 1], multiplied by 100 for risk contribution.
"""

import joblib
import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import StratifiedKFold, cross_val_score
from sklearn.metrics import classification_report

WEIGHTS_DIR = Path(__file__).parent / "weights"
WEIGHTS_DIR.mkdir(exist_ok=True)

RF_PATH = WEIGHTS_DIR / "random_forest.joblib"
SCALER_PATH = WEIGHTS_DIR / "scaler_rf.joblib"


class RandomForestModel:
    def __init__(self, n_estimators: int = 300, class_weight: str = "balanced", random_state: int = 42):
        # class_weight="balanced" is critical: CERT dataset is highly imbalanced (~5% malicious)
        self.model = RandomForestClassifier(
            n_estimators=n_estimators,
            class_weight=class_weight,
            random_state=random_state,
            n_jobs=-1,
        )
        self.scaler = StandardScaler()
        self.trained = False
        self.feature_importances_: np.ndarray | None = None

    def train(self, X: np.ndarray, y: np.ndarray) -> dict:
        """
        Train on labelled data.

        Args:
            X: Feature matrix (n_users, n_features)
            y: Binary labels — 1 = malicious, 0 = benign

        Returns:
            dict with cross-validation metrics
        """
        X_scaled = self.scaler.fit_transform(X)
        # 5-fold stratified CV for evaluation
        cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
        roc_scores = cross_val_score(self.model, X_scaled, y, cv=cv, scoring="roc_auc")

        self.model.fit(X_scaled, y)
        self.trained = True
        self.feature_importances_ = self.model.feature_importances_

        joblib.dump(self.model, RF_PATH)
        joblib.dump(self.scaler, SCALER_PATH)

        metrics = {
            "roc_auc_mean": float(roc_scores.mean()),
            "roc_auc_std": float(roc_scores.std()),
            "n_train": len(y),
            "n_malicious": int(y.sum()),
        }
        print(f"RandomForest trained. ROC-AUC: {metrics['roc_auc_mean']:.3f} ± {metrics['roc_auc_std']:.3f}")
        return metrics

    def predict_proba(self, x: np.ndarray) -> float:
        """Returns malicious probability ∈ [0, 1] for a single feature vector."""
        if not self.trained:
            return 0.0
        x_scaled = self.scaler.transform(x.reshape(1, -1))
        return float(self.model.predict_proba(x_scaled)[0][1])

    def predict_proba_batch(self, X: np.ndarray) -> np.ndarray:
        """Returns malicious probabilities for a batch → (n_users,) ∈ [0, 1]."""
        if not self.trained:
            return np.zeros(len(X))
        X_scaled = self.scaler.transform(X)
        return self.model.predict_proba(X_scaled)[:, 1]

    def load(self) -> bool:
        if RF_PATH.exists() and SCALER_PATH.exists():
            self.model = joblib.load(RF_PATH)
            self.scaler = joblib.load(SCALER_PATH)
            self.trained = True
            self.feature_importances_ = self.model.feature_importances_
            return True
        return False
