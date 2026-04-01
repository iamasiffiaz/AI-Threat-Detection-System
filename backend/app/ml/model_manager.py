"""
Model Manager: handles model lifecycle - training, persistence, and retraining scheduling.
Acts as the central coordinator for all ML operations.
"""
import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional
from app.ml.anomaly_detector import AnomalyDetector
from app.ml.feature_engineering import FeatureEngineer
from app.core.config import settings

logger = logging.getLogger(__name__)


class ModelManager:
    """
    Singleton-style manager for the anomaly detection model lifecycle.
    Handles training, retraining, and scoring operations.
    """

    def __init__(self):
        self.detector = AnomalyDetector(contamination=0.05, n_estimators=200)
        self.engineer = FeatureEngineer()
        self._last_retrain_check: Optional[datetime] = None
        self._training_lock = asyncio.Lock()

    async def initialize(self) -> bool:
        """
        Load existing model from disk on startup.
        Returns True if a trained model was found.
        """
        loaded = self.detector.load()
        if loaded:
            logger.info("Loaded existing anomaly detection model from disk")
        else:
            logger.info("No pre-trained model found; will train when enough data is available")
        return loaded

    async def train_model(
        self,
        logs: List[Dict[str, Any]],
        force: bool = False,
    ) -> Dict[str, Any]:
        """
        Train the anomaly detection model on a list of log dicts.
        Uses a lock to prevent concurrent training.
        """
        async with self._training_lock:
            if not force and self.detector.is_trained:
                last_trained = self.detector.trained_at
                if last_trained:
                    hours_since = (datetime.now(timezone.utc) - last_trained).total_seconds() / 3600
                    if hours_since < settings.MODEL_RETRAIN_INTERVAL_HOURS:
                        return {
                            "status": "skipped",
                            "reason": f"Model trained {hours_since:.1f}h ago; threshold is {settings.MODEL_RETRAIN_INTERVAL_HOURS}h",
                        }

            if len(logs) < settings.MIN_TRAINING_SAMPLES:
                return {
                    "status": "insufficient_data",
                    "reason": f"Need {settings.MIN_TRAINING_SAMPLES} samples; got {len(logs)}",
                    "samples_available": len(logs),
                }

            logger.info(f"Starting model training with {len(logs)} log entries...")

            # Run CPU-intensive training in thread pool to avoid blocking event loop
            loop = asyncio.get_event_loop()
            X = await loop.run_in_executor(
                None, self.engineer.extract_bulk_features, logs
            )

            result = await loop.run_in_executor(None, self.detector.train, X)
            await loop.run_in_executor(None, self.detector.save)

            return {"status": "trained", **result}

    async def score_log(self, log: Dict[str, Any]) -> float:
        """
        Score a single log entry. Returns anomaly score in [0, 1].
        If model is untrained, returns 0.0 (assume normal).
        """
        if not self.detector.is_trained:
            return 0.0

        loop = asyncio.get_event_loop()
        features = await loop.run_in_executor(
            None, self.engineer.extract_features, log
        )
        score = await loop.run_in_executor(
            None, self.detector.score_single, features
        )
        return score

    async def score_bulk(
        self, logs: List[Dict[str, Any]]
    ) -> List[float]:
        """Score multiple log entries. Returns list of scores."""
        if not self.detector.is_trained or not logs:
            return [0.0] * len(logs)

        loop = asyncio.get_event_loop()
        X = await loop.run_in_executor(
            None, self.engineer.extract_bulk_features, logs
        )
        scores_arr = await loop.run_in_executor(None, self.detector.score, X)
        return scores_arr.tolist()

    def get_model_info(self) -> Dict[str, Any]:
        """Return current model metadata."""
        return self.detector.get_info()

    def get_feature_names(self) -> List[str]:
        """Return list of feature names used by the model."""
        return self.engineer.FEATURE_NAMES


# Application-scoped singleton
model_manager = ModelManager()
