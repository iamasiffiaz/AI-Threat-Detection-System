"""
Anomaly Detection Engine using Isolation Forest (primary) and LOF (secondary).
Supports training on baseline data and scoring new log entries.
Optionally uses PyOD models if available.
"""
import numpy as np
import pickle
import os
import logging
from typing import List, Tuple, Optional, Dict, Any
from datetime import datetime, timezone
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline

try:
    from pyod.models.iforest import IForest as PyODIForest
    from pyod.models.lof import LOF as PyODLOF
    from pyod.models.ocsvm import OCSVM
    PYOD_AVAILABLE = True
except ImportError:
    PYOD_AVAILABLE = False
    logging.getLogger(__name__).warning("PyOD not available; using sklearn models only")

logger = logging.getLogger(__name__)

MODEL_DIR = os.path.join(os.path.dirname(__file__), "saved_models")
os.makedirs(MODEL_DIR, exist_ok=True)


class AnomalyDetector:
    """
    Ensemble anomaly detector combining Isolation Forest and LOF.
    Scores are normalized to [0, 1] where 1 = most anomalous.
    """

    def __init__(
        self,
        contamination: float = 0.05,
        n_estimators: int = 200,
        random_state: int = 42,
    ):
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.random_state = random_state
        self.is_trained = False
        self.trained_at: Optional[datetime] = None
        self.training_samples: int = 0

        self._build_pipelines()

    def _build_pipelines(self):
        """Build sklearn pipelines with scaling."""
        self.isolation_forest_pipeline = Pipeline([
            ("scaler", StandardScaler()),
            ("model", IsolationForest(
                n_estimators=self.n_estimators,
                contamination=self.contamination,
                random_state=self.random_state,
                n_jobs=-1,
            )),
        ])

        # LOF cannot predict on new data without fitting again — use novelty=True
        self.lof_pipeline = Pipeline([
            ("scaler", StandardScaler()),
            ("model", LocalOutlierFactor(
                n_neighbors=20,
                contamination=self.contamination,
                novelty=True,
                n_jobs=-1,
            )),
        ])

        if PYOD_AVAILABLE:
            self.pyod_model = PyODIForest(
                contamination=self.contamination,
                n_estimators=self.n_estimators,
                random_state=self.random_state,
            )
        else:
            self.pyod_model = None

    def train(self, X: np.ndarray) -> Dict[str, Any]:
        """
        Train the anomaly detection ensemble on baseline (normal) data.
        Returns training metrics.
        """
        if X.shape[0] < 10:
            raise ValueError(f"Need at least 10 samples to train; got {X.shape[0]}")

        logger.info(f"Training anomaly detector on {X.shape[0]} samples...")

        # Replace NaN/inf with 0
        X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)

        self.isolation_forest_pipeline.fit(X)
        self.lof_pipeline.fit(X)

        if self.pyod_model:
            self.pyod_model.fit(X)

        self.is_trained = True
        self.trained_at = datetime.now(timezone.utc)
        self.training_samples = X.shape[0]

        logger.info("Anomaly detector training complete")
        return {
            "trained_at": self.trained_at.isoformat(),
            "training_samples": self.training_samples,
            "models": ["IsolationForest", "LOF"] + (["PyOD_IForest"] if self.pyod_model else []),
        }

    def score(self, X: np.ndarray) -> np.ndarray:
        """
        Score samples. Returns anomaly scores in [0, 1].
        Higher score = more anomalous.
        """
        if not self.is_trained:
            raise RuntimeError("Model has not been trained. Call train() first.")

        X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)

        # Guard: if the saved model was trained on a different feature count,
        # reset so the caller falls back to 0.0 scores until re-trained.
        expected = getattr(
            self.isolation_forest_pipeline.named_steps.get("scaler"), "n_features_in_", None
        )
        if expected is not None and X.shape[1] != expected:
            logger.warning(
                "Feature count mismatch: model expects %d but got %d — "
                "resetting model and deleting stale pkl so it retrains.",
                expected, X.shape[1],
            )
            self.is_trained = False
            self._build_pipelines()
            # Delete stale pkl so next startup doesn't load it again
            stale_path = os.path.join(MODEL_DIR, "anomaly_detector.pkl")
            try:
                if os.path.exists(stale_path):
                    os.remove(stale_path)
            except Exception:
                pass
            raise RuntimeError(
                f"Stale model (trained on {expected} features) reset; "
                "will retrain on next threshold crossing."
            )

        # Isolation Forest: decision_function returns negative scores for anomalies
        if_scores_raw = self.isolation_forest_pipeline.decision_function(X)
        # Normalize: more negative = more anomalous → invert and normalize to [0,1]
        if_scores = 1.0 - self._minmax_normalize(if_scores_raw)

        # LOF: decision_function returns negative outlier factor
        lof_scores_raw = self.lof_pipeline.decision_function(X)
        lof_scores = 1.0 - self._minmax_normalize(lof_scores_raw)

        if self.pyod_model:
            pyod_scores = self.pyod_model.decision_function(X)
            pyod_scores_norm = self._minmax_normalize(pyod_scores)
            # Weighted ensemble: IF=40%, LOF=30%, PyOD=30%
            ensemble = 0.4 * if_scores + 0.3 * lof_scores + 0.3 * pyod_scores_norm
        else:
            # Equal weight between IF and LOF
            ensemble = 0.6 * if_scores + 0.4 * lof_scores

        return np.clip(ensemble, 0.0, 1.0)

    def predict(self, X: np.ndarray, threshold: float = 0.6) -> Tuple[np.ndarray, np.ndarray]:
        """
        Predict anomalies. Returns (labels, scores).
        Labels: 1 = anomaly, 0 = normal.
        """
        scores = self.score(X)
        labels = (scores >= threshold).astype(int)
        return labels, scores

    def score_single(self, x: np.ndarray) -> float:
        """Score a single sample. Returns scalar anomaly score in [0, 1]."""
        return float(self.score(x.reshape(1, -1))[0])

    def _minmax_normalize(self, arr: np.ndarray) -> np.ndarray:
        """Normalize array to [0, 1] range."""
        min_val = arr.min()
        max_val = arr.max()
        if max_val == min_val:
            return np.zeros_like(arr)
        return (arr - min_val) / (max_val - min_val)

    def save(self, path: Optional[str] = None) -> str:
        """Persist the trained model to disk."""
        path = path or os.path.join(MODEL_DIR, "anomaly_detector.pkl")
        with open(path, "wb") as f:
            pickle.dump({
                "if_pipeline": self.isolation_forest_pipeline,
                "lof_pipeline": self.lof_pipeline,
                "pyod_model": self.pyod_model,
                "is_trained": self.is_trained,
                "trained_at": self.trained_at,
                "training_samples": self.training_samples,
                "contamination": self.contamination,
            }, f)
        logger.info(f"Model saved to {path}")
        return path

    # Number of features the current FeatureEngineer produces
    EXPECTED_FEATURES = 35

    def load(self, path: Optional[str] = None) -> bool:
        """Load a persisted model from disk. Returns True on success."""
        path = path or os.path.join(MODEL_DIR, "anomaly_detector.pkl")
        if not os.path.exists(path):
            logger.info(f"No saved model at {path} — will train from scratch.")
            return False
        try:
            with open(path, "rb") as f:
                data = pickle.load(f)

            # Validate feature count before accepting the model
            scaler = data["if_pipeline"].named_steps.get("scaler")
            saved_features = getattr(scaler, "n_features_in_", None)
            if saved_features is not None and saved_features != self.EXPECTED_FEATURES:
                logger.warning(
                    "Stale model (trained on %d features, expected %d) — "
                    "deleting pkl and retraining.",
                    saved_features, self.EXPECTED_FEATURES,
                )
                os.remove(path)
                return False

            self.isolation_forest_pipeline = data["if_pipeline"]
            self.lof_pipeline = data["lof_pipeline"]
            self.pyod_model = data.get("pyod_model")
            self.is_trained = data["is_trained"]
            self.trained_at = data["trained_at"]
            self.training_samples = data["training_samples"]
            self.contamination = data["contamination"]
            logger.info(f"Model loaded from {path} ({saved_features} features)")
            return True
        except Exception as e:
            logger.error(f"Failed to load model: {e}")
            # Delete corrupted pkl
            try:
                os.remove(path)
            except Exception:
                pass
            return False

    def get_info(self) -> Dict[str, Any]:
        """Return model metadata."""
        return {
            "model_name": "EnsembleAnomalyDetector",
            "algorithm": "IsolationForest + LOF" + (" + PyOD" if self.pyod_model else ""),
            "trained_at": self.trained_at.isoformat() if self.trained_at else None,
            "training_samples": self.training_samples,
            "threshold": 0.6,
            "contamination": self.contamination,
            "is_trained": self.is_trained,
        }
