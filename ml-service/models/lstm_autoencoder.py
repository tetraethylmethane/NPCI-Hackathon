"""
Sprint 2 — Layer 3: LSTM Autoencoder
======================================
Sequence model trained on 30-day per-user behavioural time series.
Anomaly detection via reconstruction error: a user whose current
30-day pattern deviates significantly from what the encoder learned
to reconstruct will have a high MSE → high anomaly score.

Architecture (CPU-optimised, trains in minutes on CERT dataset):
  Input   : (batch, seq_len=30, input_size=8)
  Encoder : LSTM(8 → 64) → last hidden state → Linear(64 → 16) [latent]
  Decoder : repeat latent → LSTM(16 → 64) → Linear(64 → 8) [reconstructed seq]
  Loss    : MSE(original, reconstructed)

Training strategy:
  • Train on BENIGN users only (if labels available) so the model learns
    "normal" patterns. Malicious users will have high reconstruction error.
  • If no labels: train on all users (semi-supervised assumption).

Sequence features (8-dim, from daily_snapshots.parquet):
  total_risk_score, logon_risk, device_risk, file_risk,
  email_risk, http_risk, after_hours_events, total_events

Usage:
  model = LSTMAutoencoderModel()
  model.train(sequences_array)            # (n_users, 30, 8)
  score = model.anomaly_score(seq)        # single sequence (30, 8) → float [0,100]
  scores = model.anomaly_score_batch(X)  # (n, 30, 8) → (n,)
"""

import logging
from pathlib import Path

import numpy as np

logger = logging.getLogger(__name__)

WEIGHTS_DIR = Path(__file__).parent / "weights"
WEIGHTS_DIR.mkdir(exist_ok=True)
LSTM_PATH = WEIGHTS_DIR / "lstm_autoencoder.pt"
THRESHOLD_PATH = WEIGHTS_DIR / "lstm_threshold.npy"

SEQ_LEN    = 30
INPUT_SIZE = 8
HIDDEN     = 64
LATENT     = 16

# Sequence feature column names — must match daily_snapshots.parquet columns
SEQ_FEATURE_COLS = [
    "total_risk_score", "logon_risk", "device_risk", "file_risk",
    "email_risk", "http_risk", "after_hours_events", "total_events",
]

# ─────────────────────────────────────────────────────────────────────────────
# Try importing PyTorch — graceful degradation if not installed
# ─────────────────────────────────────────────────────────────────────────────

try:
    import torch
    import torch.nn as nn
    from torch.utils.data import DataLoader, TensorDataset
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False
    logger.warning(
        "PyTorch not installed — LSTM Autoencoder disabled. "
        "Install with: pip install torch --index-url https://download.pytorch.org/whl/cpu"
    )


# ─────────────────────────────────────────────────────────────────────────────
# Network definition (only compiled when torch is available)
# ─────────────────────────────────────────────────────────────────────────────

if TORCH_AVAILABLE:
    class _Encoder(nn.Module):
        def __init__(self):
            super().__init__()
            self.lstm = nn.LSTM(INPUT_SIZE, HIDDEN, num_layers=1,
                                batch_first=True, dropout=0.0)
            self.fc   = nn.Linear(HIDDEN, LATENT)

        def forward(self, x):                        # x: (B, T, 8)
            _, (h_n, _) = self.lstm(x)               # h_n: (1, B, 64)
            return self.fc(h_n[-1])                  # (B, 16)

    class _Decoder(nn.Module):
        def __init__(self):
            super().__init__()
            self.lstm = nn.LSTM(LATENT, HIDDEN, num_layers=1,
                                batch_first=True, dropout=0.0)
            self.fc   = nn.Linear(HIDDEN, INPUT_SIZE)

        def forward(self, z):                        # z: (B, 16)
            z_rep = z.unsqueeze(1).expand(-1, SEQ_LEN, -1)  # (B, T, 16)
            out, _ = self.lstm(z_rep)                        # (B, T, 64)
            return self.fc(out)                              # (B, T, 8)

    class _LSTMAutoencoder(nn.Module):
        def __init__(self):
            super().__init__()
            self.encoder = _Encoder()
            self.decoder = _Decoder()

        def forward(self, x):
            return self.decoder(self.encoder(x))


# ─────────────────────────────────────────────────────────────────────────────
# Public wrapper
# ─────────────────────────────────────────────────────────────────────────────

class LSTMAutoencoderModel:
    """
    Thin wrapper around the PyTorch LSTM AE.
    Handles training, serialisation, and anomaly scoring.
    """

    def __init__(self, epochs: int = 50, batch_size: int = 32, lr: float = 1e-3,
                 patience: int = 7):
        self.epochs     = epochs
        self.batch_size = batch_size
        self.lr         = lr
        self.patience   = patience
        self.trained    = False
        self._threshold: float | None = None  # MSE threshold for [0,100] mapping
        self._net = None

        if TORCH_AVAILABLE:
            self._net = _LSTMAutoencoder()

    # ── Training ──────────────────────────────────────────────────────────────

    def train(self, X: np.ndarray, y: np.ndarray | None = None) -> dict:
        """
        Train on an array of user sequences.

        Args:
            X: (n_users, SEQ_LEN, INPUT_SIZE) float32 array
            y: Optional binary labels (1=malicious). If provided, train only
               on benign (y==0) users so the model learns "normal" patterns.

        Returns:
            Training stats dict.
        """
        if not TORCH_AVAILABLE:
            logger.warning("LSTM training skipped — PyTorch not installed.")
            return {"status": "skipped", "reason": "torch not installed"}

        # Train only on benign users if labels are available
        if y is not None:
            benign_mask = y == 0
            X_train = X[benign_mask]
            logger.info("LSTM: training on %d benign users (of %d total)",
                        X_train.shape[0], X.shape[0])
        else:
            X_train = X
            logger.info("LSTM: training on all %d users (no labels)", X.shape[0])

        if len(X_train) < 4:
            return {"status": "skipped", "reason": "insufficient training data"}

        X_train = _normalize_sequences(X_train)

        tensor = torch.tensor(X_train, dtype=torch.float32)
        loader = DataLoader(TensorDataset(tensor), batch_size=self.batch_size, shuffle=True)

        optimizer = torch.optim.Adam(self._net.parameters(), lr=self.lr)
        criterion = nn.MSELoss()

        best_loss    = float("inf")
        no_improve   = 0
        train_losses = []

        for epoch in range(1, self.epochs + 1):
            self._net.train()
            epoch_loss = 0.0
            for (batch,) in loader:
                optimizer.zero_grad()
                recon  = self._net(batch)
                loss   = criterion(recon, batch)
                loss.backward()
                optimizer.step()
                epoch_loss += loss.item() * len(batch)
            avg_loss = epoch_loss / len(X_train)
            train_losses.append(avg_loss)

            if avg_loss < best_loss - 1e-6:
                best_loss  = avg_loss
                no_improve = 0
                torch.save(self._net.state_dict(), LSTM_PATH)  # checkpoint best
            else:
                no_improve += 1

            if epoch % 10 == 0:
                logger.info("  LSTM epoch %d/%d  loss=%.6f", epoch, self.epochs, avg_loss)

            if no_improve >= self.patience:
                logger.info("  Early stopping at epoch %d (patience=%d)", epoch, self.patience)
                break

        # Load best checkpoint
        self._net.load_state_dict(torch.load(LSTM_PATH, map_location="cpu"))

        # Calibrate threshold on training set
        errors = self._reconstruction_errors(X_train)
        self._threshold = float(np.mean(errors) + 2.0 * np.std(errors))
        np.save(THRESHOLD_PATH, np.array([self._threshold]))

        self.trained = True
        return {
            "status": "trained",
            "epochs_run": len(train_losses),
            "final_loss": round(train_losses[-1], 6),
            "best_loss":  round(best_loss, 6),
            "threshold":  round(self._threshold, 6),
            "train_users": len(X_train),
        }

    # ── Inference ─────────────────────────────────────────────────────────────

    def anomaly_score(self, sequence: np.ndarray) -> float:
        """
        Score a single user's 30-day sequence.

        Args:
            sequence: (SEQ_LEN, INPUT_SIZE) array

        Returns:
            float in [0, 100] — higher = more anomalous
        """
        if not self.trained or not TORCH_AVAILABLE:
            return 0.0
        errors = self._reconstruction_errors(sequence.reshape(1, SEQ_LEN, INPUT_SIZE))
        return float(self._to_score(errors[0]))

    def anomaly_score_batch(self, X: np.ndarray) -> np.ndarray:
        """Score a batch of sequences. Returns (n,) array in [0, 100]."""
        if not self.trained or not TORCH_AVAILABLE:
            return np.zeros(len(X))
        X_norm  = _normalize_sequences(X)
        errors  = self._reconstruction_errors(X_norm)
        return np.vectorize(self._to_score)(errors)

    # ── Persistence ───────────────────────────────────────────────────────────

    def load(self) -> bool:
        """Load saved weights. Returns True on success."""
        if not TORCH_AVAILABLE:
            return False
        if LSTM_PATH.exists() and THRESHOLD_PATH.exists():
            try:
                self._net.load_state_dict(
                    torch.load(LSTM_PATH, map_location="cpu", weights_only=True)
                )
                self._net.eval()
                self._threshold = float(np.load(THRESHOLD_PATH)[0])
                self.trained = True
                return True
            except Exception as e:
                logger.warning("LSTM load failed: %s", e)
        return False

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _reconstruction_errors(self, X: np.ndarray) -> np.ndarray:
        """Returns per-sample MSE reconstruction errors."""
        self._net.eval()
        with torch.no_grad():
            t     = torch.tensor(X, dtype=torch.float32)
            recon = self._net(t).numpy()
        return np.mean((X - recon) ** 2, axis=(1, 2))   # (n,)

    def _to_score(self, mse: float) -> float:
        """Map raw MSE to [0, 100] using calibrated threshold."""
        if self._threshold is None or self._threshold <= 0:
            return 0.0
        return float(np.clip(mse / (self._threshold * 1.5) * 100, 0, 100))


# ─────────────────────────────────────────────────────────────────────────────
# Sequence builders (used by trainer.py and routes.py)
# ─────────────────────────────────────────────────────────────────────────────

def _normalize_sequences(X: np.ndarray) -> np.ndarray:
    """Min-max normalise across the time and feature axes (per-batch)."""
    X = X.copy()
    max_val = X.max()
    if max_val > 0:
        X = X / max_val
    return X


def build_sequences_from_daily(
    daily_df,  # pd.DataFrame from transform.load_daily_snapshots()
    seq_len: int = SEQ_LEN,
) -> tuple[np.ndarray, list[str]]:
    """
    Build (n_users, seq_len, 8) sequence array from daily_snapshots DataFrame.
    Missing features are zero-filled. Sequences shorter than seq_len are left-padded.

    Returns:
        (X, user_ids) — float32 array and matching user ID list
    """
    import pandas as pd

    available_cols = [c for c in SEQ_FEATURE_COLS if c in daily_df.columns]
    missing_cols   = [c for c in SEQ_FEATURE_COLS if c not in daily_df.columns]
    if missing_cols:
        logger.warning("LSTM: missing daily columns %s — zero-filled.", missing_cols)

    seqs     = []
    user_ids = []

    for uid, grp in daily_df.groupby("user_id"):
        grp = grp.sort_values("date")
        feats = grp[available_cols].values.astype(np.float32)

        # Pad missing feature columns on the right
        if len(available_cols) < INPUT_SIZE:
            pad_cols = np.zeros((len(feats), INPUT_SIZE - len(available_cols)), dtype=np.float32)
            feats = np.hstack([feats, pad_cols])

        # Pad or truncate the time dimension
        if len(feats) >= seq_len:
            seq = feats[-seq_len:]          # most recent window
        else:
            pad = np.zeros((seq_len - len(feats), INPUT_SIZE), dtype=np.float32)
            seq = np.vstack([pad, feats])   # left-pad with zeros

        seqs.append(seq)
        user_ids.append(uid)

    X = np.array(seqs, dtype=np.float32) if seqs else np.zeros((0, seq_len, INPUT_SIZE), np.float32)
    return X, list(user_ids)
