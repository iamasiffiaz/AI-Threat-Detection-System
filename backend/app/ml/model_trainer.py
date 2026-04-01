"""
Model training service.
Pulls log entries from the database, builds feature vectors, and trains the detector.
Can be called on-demand or scheduled (via APScheduler / background task).
"""
import logging
from typing import Dict

import pandas as pd
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.ml.anomaly_detector import detector
from app.ml.feature_engineering import extract_features_bulk
from app.models.log import LogEntry

logger = logging.getLogger(__name__)


async def retrain_model(db: AsyncSession, limit: int = 50_000) -> Dict:
    """
    Fetch the most recent `limit` logs, extract features, and retrain the detector.
    Returns a summary dict.
    """
    logger.info("Starting model retraining …")

    result = await db.execute(
        select(LogEntry)
        .order_by(LogEntry.timestamp.desc())
        .limit(limit)
    )
    logs = result.scalars().all()

    if len(logs) < 10:
        return {"status": "skipped", "reason": "Not enough data", "samples": len(logs)}

    log_dicts = [
        {
            "id": l.id,
            "timestamp": l.timestamp,
            "source_ip": l.source_ip,
            "destination_ip": l.destination_ip,
            "source_port": l.source_port,
            "destination_port": l.destination_port,
            "protocol": l.protocol,
            "event_type": l.event_type,
            "severity": l.severity,
            "message": l.message,
        }
        for l in logs
    ]

    X = extract_features_bulk(log_dicts)
    result_meta = detector.train(X)
    result_meta["status"] = "success"
    result_meta["logs_used"] = len(logs)
    return result_meta


async def score_logs(db: AsyncSession, log_ids: list[int]) -> Dict[int, tuple[int, float]]:
    """
    Score specific logs by ID.
    Returns {log_id: (is_anomaly, score)}.
    """
    if not log_ids:
        return {}

    result = await db.execute(select(LogEntry).where(LogEntry.id.in_(log_ids)))
    logs = result.scalars().all()

    log_dicts = [
        {
            "id": l.id,
            "timestamp": l.timestamp,
            "source_ip": l.source_ip,
            "destination_ip": l.destination_ip,
            "source_port": l.source_port,
            "destination_port": l.destination_port,
            "protocol": l.protocol,
            "event_type": l.event_type,
            "severity": l.severity,
            "message": l.message,
        }
        for l in logs
    ]

    from app.ml.feature_engineering import extract_features_bulk
    X = extract_features_bulk(log_dicts)
    labels, scores = detector.predict(X)

    return {log.id: (int(labels[i]), float(scores[i])) for i, log in enumerate(logs)}
