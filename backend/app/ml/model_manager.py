"""
Model Manager: advanced lifecycle management for the anomaly detection ensemble.
Handles auto-training from DB, periodic retraining, and thread-safe scoring.
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
    Singleton manager for the anomaly detection model lifecycle.
    Key improvements over basic version:
      - auto_train_from_db(): queries PostgreSQL logs and trains on first startup
      - auto-retrain trigger after bulk ingestion
      - logs_since_last_train counter to know when to retrain
      - thread-safe scoring with asyncio executor
    """

    def __init__(self):
        self.detector = AnomalyDetector(contamination=0.05, n_estimators=300)
        self.engineer = FeatureEngineer()
        self._training_lock = asyncio.Lock()
        self._logs_since_retrain: int = 0
        self._retrain_threshold: int = 500  # retrain after this many new logs

    async def initialize(self) -> bool:
        """
        Load existing model from disk.  If no saved model is found, the
        caller should invoke auto_train_from_db() once enough data exists.
        """
        loaded = self.detector.load()
        if loaded:
            logger.info(
                f"Loaded anomaly model: {self.detector.training_samples} training samples, "
                f"trained at {self.detector.trained_at}"
            )
        else:
            logger.info("No pre-trained model found; will auto-train from DB on startup")
        return loaded

    async def auto_train_from_db(self, db_session) -> Dict[str, Any]:
        """
        Pull recent log entries from PostgreSQL and train the model.
        Called on startup (and after bulk ingestion) so the model is always warm.
        """
        from sqlalchemy import select, desc
        from app.models.log_entry import LogEntry

        try:
            # Use up to 10 000 most recent logs for training
            result = await db_session.execute(
                select(LogEntry)
                .order_by(desc(LogEntry.ingested_at))
                .limit(10_000)
            )
            log_entries = result.scalars().all()

            if len(log_entries) < settings.MIN_TRAINING_SAMPLES:
                logger.info(
                    f"Not enough logs to train ({len(log_entries)} < {settings.MIN_TRAINING_SAMPLES}); "
                    "skipping auto-train"
                )
                return {
                    "status": "insufficient_data",
                    "samples_available": len(log_entries),
                    "required": settings.MIN_TRAINING_SAMPLES,
                }

            log_dicts = [
                {
                    "timestamp":        e.timestamp,
                    "source_ip":        e.source_ip,
                    "destination_ip":   e.destination_ip,
                    "destination_port": e.destination_port,
                    "source_port":      e.source_port,
                    "protocol":         e.protocol.value if e.protocol else "OTHER",
                    "event_type":       e.event_type,
                    "severity":         e.severity.value if e.severity else "info",
                    "bytes_sent":       e.bytes_sent,
                    "bytes_received":   e.bytes_received,
                    "duration_ms":      e.duration_ms,
                    "username":         e.username,
                }
                for e in log_entries
            ]

            result = await self.train_model(log_dicts, force=True)
            if result.get("status") == "trained":
                logger.info(
                    f"Auto-trained anomaly model on {len(log_dicts)} DB logs "
                    f"({result.get('training_samples')} samples)"
                )
            return result

        except Exception as e:
            logger.error(f"auto_train_from_db failed: {e}")
            return {"status": "error", "reason": str(e)}

    async def train_model(
        self,
        logs: List[Dict[str, Any]],
        force: bool = False,
    ) -> Dict[str, Any]:
        """Train on a list of log dicts.  Thread-safe via asyncio.Lock."""
        async with self._training_lock:
            if not force and self.detector.is_trained:
                last = self.detector.trained_at
                if last:
                    hours_since = (datetime.now(timezone.utc) - last).total_seconds() / 3600
                    if hours_since < settings.MODEL_RETRAIN_INTERVAL_HOURS:
                        return {
                            "status": "skipped",
                            "reason": f"Trained {hours_since:.1f}h ago; threshold {settings.MODEL_RETRAIN_INTERVAL_HOURS}h",
                        }

            if len(logs) < settings.MIN_TRAINING_SAMPLES:
                return {
                    "status": "insufficient_data",
                    "reason": f"Need {settings.MIN_TRAINING_SAMPLES} samples; got {len(logs)}",
                    "samples_available": len(logs),
                }

            logger.info(f"Training anomaly model on {len(logs)} samples …")
            loop = asyncio.get_event_loop()

            X = await loop.run_in_executor(None, self.engineer.extract_bulk_features, logs)
            metrics = await loop.run_in_executor(None, self.detector.train, X)
            await loop.run_in_executor(None, self.detector.save)

            self._logs_since_retrain = 0
            logger.info(f"Training complete — {metrics}")
            return {"status": "trained", **metrics}

    def notify_ingested(self, count: int = 1):
        """
        Called by LogService after ingestion.  Triggers background retraining
        when accumulated new logs exceed the threshold.
        """
        self._logs_since_retrain += count

    def should_retrain(self) -> bool:
        return self._logs_since_retrain >= self._retrain_threshold

    async def score_log(self, log: Dict[str, Any]) -> float:
        """Score a single log.  Returns 0.0 if model is untrained or on error."""
        if not self.detector.is_trained:
            return 0.0
        try:
            loop = asyncio.get_event_loop()
            features = await loop.run_in_executor(None, self.engineer.extract_features, log)
            return float(await loop.run_in_executor(None, self.detector.score_single, features))
        except Exception:
            return 0.0

    async def score_bulk(self, logs: List[Dict[str, Any]]) -> List[float]:
        """Score multiple logs.  Returns all-zero list if untrained or on error."""
        if not self.detector.is_trained or not logs:
            return [0.0] * len(logs)
        try:
            loop = asyncio.get_event_loop()
            X = await loop.run_in_executor(None, self.engineer.extract_bulk_features, logs)
            arr = await loop.run_in_executor(None, self.detector.score, X)
            return arr.tolist()
        except RuntimeError as exc:
            # Feature mismatch — model was reset; schedule retraining
            logger.warning("score_bulk reset model (%s) — scheduling retrain", exc)
            asyncio.create_task(self._safe_retrain())
            return [0.0] * len(logs)
        except Exception as exc:
            logger.error("score_bulk failed: %s", exc)
            return [0.0] * len(logs)

    async def _safe_retrain(self):
        """Background retraining with its own DB session — safe to call from create_task."""
        try:
            from app.core.database import AsyncSessionLocal
            async with AsyncSessionLocal() as session:
                result = await self.auto_train_from_db(session)
                logger.info("Background retrain: %s", result.get("status"))
        except Exception as exc:
            logger.error("Background retrain failed: %s", exc)

    def get_model_info(self) -> Dict[str, Any]:
        info = self.detector.get_info()
        info["logs_since_last_retrain"] = self._logs_since_retrain
        info["retrain_threshold"] = self._retrain_threshold
        info["feature_count"] = len(self.engineer.FEATURE_NAMES)
        return info

    def get_feature_names(self) -> List[str]:
        return self.engineer.FEATURE_NAMES


model_manager = ModelManager()
