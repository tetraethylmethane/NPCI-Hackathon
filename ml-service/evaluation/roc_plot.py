"""
ml-service/evaluation/roc_plot.py
====================================
Sprint 6 — ROC Curve & Precision-Recall Curve Generation

Generates and saves:
  docs/roc_curve.png              — ROC curve for all three layers
  docs/precision_recall_curve.png — Precision-Recall curve for ensemble

Both plots use the NPCI colour palette (navy #003478, orange #f7941d).
Saves source data as JSON alongside each PNG for reproducibility.

Usage (standalone):
  python -m evaluation.roc_plot

Usage (from eval pipeline):
  from evaluation.roc_plot import plot_roc, plot_precision_recall
"""

import json
import logging
from pathlib import Path
from typing import Optional

import numpy as np

logger = logging.getLogger(__name__)

DOCS_DIR = Path(__file__).parent.parent.parent / "docs"
ROC_PATH = DOCS_DIR / "roc_curve.png"
PR_PATH  = DOCS_DIR / "precision_recall_curve.png"

NPCI_NAVY   = "#003478"
NPCI_ORANGE = "#f7941d"
NPCI_LIGHT  = "#6baed6"


# ---------------------------------------------------------------------------
# Core plot functions
# ---------------------------------------------------------------------------

def plot_roc(
    layer_results: list[dict],       # output of per_layer.evaluate_all_layers()
    y_true: np.ndarray,
    X: np.ndarray,
    user_ids: list[str],
    output_path: Optional[Path] = None,
) -> Path:
    """
    Plot ROC curves for each layer on a single figure.

    layer_results: list of per-layer metric dicts (each contains at least 'layer')
    y_true:        ground-truth binary labels
    X:             feature matrix (needed to compute per-layer raw scores)
    Returns the path to the saved PNG.
    """
    import matplotlib
    matplotlib.use("Agg")  # headless, no display needed
    import matplotlib.pyplot as plt
    from sklearn.metrics import roc_curve, auc

    from evaluation.per_layer import zscore_scores, evaluate_if_layer
    from models.ensemble import EnsembleModel
    from models.isolation_forest import IsolationForestModel

    output_path = output_path or ROC_PATH
    output_path.parent.mkdir(parents=True, exist_ok=True)

    fig, ax = plt.subplots(figsize=(8, 6))
    ax.plot([0, 1], [0, 1], "k--", lw=1, alpha=0.4, label="Random (AUC=0.50)")

    colors = [NPCI_NAVY, NPCI_ORANGE, NPCI_LIGHT]
    layer_score_fns = [
        ("Z-Score (Statistical)", lambda: zscore_scores(X)),
        ("Isolation Forest",      lambda: _if_batch_scores(X)),
        ("Ensemble (3-Layer)",    lambda: _ensemble_batch_scores(X, user_ids)),
    ]

    roc_data: list[dict] = []
    for (label, score_fn), color in zip(layer_score_fns, colors):
        try:
            scores = score_fn()
            if len(np.unique(y_true)) < 2:
                logger.warning("Only one class in y_true — ROC curve skipped.")
                continue
            fpr, tpr, thresholds = roc_curve(y_true, scores)
            roc_auc = auc(fpr, tpr)
            ax.plot(fpr, tpr, color=color, lw=2,
                    label=f"{label}  (AUC={roc_auc:.3f})")
            roc_data.append({
                "layer": label,
                "auc": round(float(roc_auc), 4),
                "fpr": fpr.tolist(),
                "tpr": tpr.tolist(),
            })
        except Exception as e:
            logger.warning("Skipping %s ROC: %s", label, e)

    ax.set_xlabel("False Positive Rate", fontsize=12)
    ax.set_ylabel("True Positive Rate (Recall)", fontsize=12)
    ax.set_title("ROC Curves — NPCI Identity Guard\n(CMU CERT r4.2 Ground Truth, Time-Split Test Set)",
                 fontsize=11, fontweight="bold", color=NPCI_NAVY)
    ax.legend(loc="lower right", fontsize=10)
    ax.set_xlim([0, 1])
    ax.set_ylim([0, 1.02])
    ax.grid(True, alpha=0.3)
    fig.tight_layout()
    fig.savefig(output_path, dpi=150, bbox_inches="tight")
    plt.close(fig)

    # Save source data
    json_path = output_path.with_suffix(".json")
    with open(json_path, "w") as f:
        json.dump(roc_data, f, indent=2)

    logger.info("ROC curve saved to %s", output_path)
    return output_path


def plot_precision_recall(
    y_true: np.ndarray,
    X: np.ndarray,
    user_ids: list[str],
    output_path: Optional[Path] = None,
) -> Path:
    """
    Plot Precision-Recall curve for the Ensemble model (most relevant for
    imbalanced datasets like CERT where malicious users are ~5%).
    """
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from sklearn.metrics import precision_recall_curve, average_precision_score

    output_path = output_path or PR_PATH
    output_path.parent.mkdir(parents=True, exist_ok=True)

    scores = _ensemble_batch_scores(X, user_ids)
    precision, recall, _ = precision_recall_curve(y_true, scores)
    ap = average_precision_score(y_true, scores)

    # Baseline = fraction of positives
    baseline = float(y_true.mean())

    fig, ax = plt.subplots(figsize=(8, 6))
    ax.plot(recall, precision, color=NPCI_NAVY, lw=2,
            label=f"Ensemble  (AP={ap:.3f})")
    ax.axhline(baseline, color=NPCI_ORANGE, linestyle="--", lw=1.5,
               label=f"No-skill baseline ({baseline:.3f})")
    ax.set_xlabel("Recall", fontsize=12)
    ax.set_ylabel("Precision", fontsize=12)
    ax.set_title("Precision-Recall Curve — Ensemble Model\n(CMU CERT r4.2, Malicious class)",
                 fontsize=11, fontweight="bold", color=NPCI_NAVY)
    ax.legend(loc="upper right", fontsize=10)
    ax.set_xlim([0, 1])
    ax.set_ylim([0, 1.02])
    ax.grid(True, alpha=0.3)
    fig.tight_layout()
    fig.savefig(output_path, dpi=150, bbox_inches="tight")
    plt.close(fig)

    logger.info("Precision-Recall curve saved to %s", output_path)
    return output_path


# ---------------------------------------------------------------------------
# Internal batch score helpers
# ---------------------------------------------------------------------------

def _if_batch_scores(X: np.ndarray) -> np.ndarray:
    from models.isolation_forest import IsolationForestModel
    model = IsolationForestModel()
    if not model.load():
        raise RuntimeError("IF weights not found.")
    return model.predict_batch(X)


def _ensemble_batch_scores(X: np.ndarray, user_ids: list[str]) -> np.ndarray:
    from models.ensemble import EnsembleModel
    ensemble = EnsembleModel()
    ensemble.load()
    scores = np.zeros(len(user_ids))
    for i, (uid, fv) in enumerate(zip(user_ids, X)):
        try:
            result = ensemble.analyze_user(uid, fv)
            scores[i] = result["threat_score"]
        except Exception:
            pass
    return scores


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

    from pipeline.features import load_feature_matrix
    from pipeline.ingest import load_ground_truth

    X, user_ids = load_feature_matrix()
    gt_df = load_ground_truth()
    malicious = set(gt_df["user_id"].tolist()) if not gt_df.empty else set()
    y_true = np.array([1 if uid in malicious else 0 for uid in user_ids])

    plot_roc([], y_true, X, user_ids)
    if y_true.sum() > 0:
        plot_precision_recall(y_true, X, user_ids)
    print(f"Plots saved to {DOCS_DIR}")
