"""
Vanguard NIDS — AI Engine Module
Anomaly detection using Scikit-learn Isolation Forest.
Classifies network feature vectors as BENIGN or MALICIOUS.
"""

import logging
import os
import queue
import threading
import time
from datetime import datetime
from typing import Optional, Callable

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# ── Logging ────────────────────────────────────────────────────────────────────
logger = logging.getLogger("vanguard.ai_engine")

# ── Constants ──────────────────────────────────────────────────────────────────
MODEL_PATH  = "vanguard/ai_engine/model.pkl"
SCALER_PATH = "vanguard/ai_engine/scaler.pkl"

# These are the exact feature keys we extract — order matters for numpy arrays
FEATURE_KEYS = [
    "total_packets",
    "unique_src_ips",
    "unique_dst_ips",
    "unique_dst_ports",
    "packet_rate",
    "tcp_count",
    "udp_count",
    "icmp_count",
    "tcp_ratio",
    "udp_ratio",
    "payload_mean",
    "payload_std",
    "payload_max",
    "payload_min",
    "payload_median",
    "syn_ratio",
    "max_ports_per_src",
    "mean_ports_per_src",
    "src_ip_entropy",
]


# ── Result Data Model ──────────────────────────────────────────────────────────
class DetectionResult:
    """Holds the output of a single detection evaluation."""

    def __init__(self, label: str, score: float, features: dict):
        self.timestamp  = datetime.utcnow().isoformat()
        self.label      = label        # "BENIGN" or "MALICIOUS"
        self.score      = score        # Raw anomaly score from Isolation Forest
        self.features   = features     # Original feature vector

    def is_malicious(self) -> bool:
        return self.label == "MALICIOUS"

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "label":     self.label,
            "score":     round(self.score, 6),
            "features":  self.features,
        }

    def __repr__(self):
        return (
            f"DetectionResult(label={self.label}, "
            f"score={self.score:.4f}, "
            f"time={self.timestamp})"
        )


# ── AI Detection Engine ────────────────────────────────────────────────────────
class AnomalyDetector:
    """
    Wraps an Isolation Forest model.
    - Can be TRAINED on baseline (normal) traffic data.
    - Can be LOADED from disk if a model already exists.
    - Runs as a background thread consuming feature vectors
      and publishing DetectionResults downstream.
    """

    def __init__(
        self,
        feature_queue: queue.Queue,
        result_queue: queue.Queue,
        contamination: float = 0.05,
        poll_interval: float = 0.5,
        on_alert: Optional[Callable[[DetectionResult], None]] = None,
    ):
        """
        Args:
            feature_queue:  Input queue from FeatureExtractor.
            result_queue:   Output queue to feed the Mitigation Engine.
            contamination:  Expected fraction of anomalies (0.01–0.5).
            poll_interval:  How often to check the queue (seconds).
            on_alert:       Optional callback fired immediately on MALICIOUS result.
        """
        self.feature_queue  = feature_queue
        self.result_queue   = result_queue
        self.contamination  = contamination
        self.poll_interval  = poll_interval
        self.on_alert       = on_alert

        self._model:   Optional[IsolationForest] = None
        self._scaler:  Optional[StandardScaler]  = None
        self._running  = False
        self._thread:  Optional[threading.Thread] = None

        self._evaluated  = 0
        self._alerts     = 0

    # ── Feature Vector → Numpy Array ──────────────────────────────────────────
    def _vectorize(self, features: dict) -> np.ndarray:
        """Convert a feature dict into an ordered numpy array."""
        return np.array(
            [features.get(k, 0.0) for k in FEATURE_KEYS],
            dtype=np.float64
        ).reshape(1, -1)

    # ── Training ───────────────────────────────────────────────────────────────
    def train(self, training_data: list[dict]) -> None:
        """
        Train the Isolation Forest on a list of NORMAL feature vectors.
        Call this during a baseline capture period (no attacks).

        Args:
            training_data: List of feature dicts from FeatureExtractor.
        """
        if not training_data:
            raise ValueError("Training data cannot be empty.")

        logger.info(f"Training Isolation Forest on {len(training_data)} samples...")

        X = np.array(
            [[d.get(k, 0.0) for k in FEATURE_KEYS] for d in training_data],
            dtype=np.float64
        )

        # Scale features to zero mean / unit variance
        self._scaler = StandardScaler()
        X_scaled = self._scaler.fit_transform(X)

        # Train the model
        self._model = IsolationForest(
            n_estimators=200,       # More trees = more stable predictions
            contamination=self.contamination,
            max_samples="auto",
            random_state=42,
            n_jobs=-1               # Use all CPU cores
        )
        self._model.fit(X_scaled)

        # Persist model and scaler to disk
        os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
        joblib.dump(self._model,  MODEL_PATH)
        joblib.dump(self._scaler, SCALER_PATH)

        logger.info(f"✅ Model trained and saved to {MODEL_PATH}")

    # ── Load Pretrained Model ──────────────────────────────────────────────────
    def load(self) -> bool:
        """Load a previously trained model and scaler from disk."""
        if os.path.exists(MODEL_PATH) and os.path.exists(SCALER_PATH):
            self._model  = joblib.load(MODEL_PATH)
            self._scaler = joblib.load(SCALER_PATH)
            logger.info("✅ Pre-trained model loaded from disk.")
            return True
        logger.warning("No saved model found. Please run training first.")
        return False

    # ── Single Prediction ──────────────────────────────────────────────────────
    def predict(self, features: dict) -> DetectionResult:
        """
        Evaluate a single feature vector.

        Isolation Forest returns:
          +1 → inlier  (BENIGN)
          -1 → outlier (MALICIOUS)
        """
        if self._model is None or self._scaler is None:
            raise RuntimeError("Model not loaded. Call train() or load() first.")

        X = self._vectorize(features)
        X_scaled = self._scaler.transform(X)

        raw_pred  = self._model.predict(X_scaled)[0]         # +1 or -1
        raw_score = self._model.score_samples(X_scaled)[0]   # lower = more anomalous

        label = "BENIGN" if raw_pred == 1 else "MALICIOUS"
        return DetectionResult(label=label, score=float(raw_score), features=features)

    # ── Background Worker ──────────────────────────────────────────────────────
    def _run(self) -> None:
        """Continuously pull feature vectors, classify, and route results."""
        logger.info("✅ AI detection engine thread started.")

        while self._running:
            try:
                features = self.feature_queue.get(timeout=self.poll_interval)
            except queue.Empty:
                continue

            try:
                result = self.predict(features)
                self._evaluated += 1

                if result.is_malicious():
                    self._alerts += 1
                    logger.warning(
                        f"🚨 MALICIOUS TRAFFIC DETECTED | "
                        f"Score: {result.score:.4f} | "
                        f"Packets: {features.get('total_packets')} | "
                        f"SYN ratio: {features.get('syn_ratio')} | "
                        f"Unique ports: {features.get('unique_dst_ports')}"
                    )
                    # Fire immediate callback (e.g., for real-time dashboard)
                    if self.on_alert:
                        self.on_alert(result)
                else:
                    logger.info(
                        f"✅ Benign | Score: {result.score:.4f} | "
                        f"Packets: {features.get('total_packets')}"
                    )

                # Push result downstream to Mitigation Engine
                try:
                    self.result_queue.put_nowait(result)
                except queue.Full:
                    logger.warning("Result queue full — detection result dropped.")

            except Exception as e:
                logger.error(f"Prediction error: {e}", exc_info=True)

        logger.info("🛑 AI detection engine stopped.")

    # ── Start / Stop ───────────────────────────────────────────────────────────
    def start(self) -> None:
        if not self._model:
            raise RuntimeError("Cannot start without a trained/loaded model.")
        if self._running:
            logger.warning("Detector already running.")
            return
        self._running = True
        self._thread = threading.Thread(
            target=self._run, daemon=True, name="AnomalyDetector"
        )
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        logger.info(
            f"🛑 Detector stopped. "
            f"Evaluated: {self._evaluated} | Alerts: {self._alerts}"
        )

    # ── Status ─────────────────────────────────────────────────────────────────
    def get_stats(self) -> dict:
        return {
            "running":   self._running,
            "evaluated": self._evaluated,
            "alerts":    self._alerts,
            "model_loaded": self._model is not None,
        }
