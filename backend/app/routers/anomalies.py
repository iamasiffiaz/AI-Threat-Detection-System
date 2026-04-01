"""
Anomalies router: ML detection results, trends, and model management.
"""
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc
from typing import Optional
from datetime import datetime, timedelta, timezone
from app.core.database import get_db
from app.core.dependencies import get_current_active_user, require_analyst_or_admin
from app.models.user import User
from app.models.anomaly import Anomaly
from app.schemas.anomaly import AnomalyResponse, ModelInfo
from app.ml.model_manager import model_manager

router = APIRouter(prefix="/anomalies", tags=["Anomaly Detection"])


@router.get("", response_model=dict)
async def get_anomalies(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    min_score: float = Query(0.0, ge=0.0, le=1.0),
    source_ip: Optional[str] = None,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Retrieve paginated anomaly records with filtering."""
    filters = [Anomaly.anomaly_score >= min_score]

    if source_ip:
        filters.append(Anomaly.source_ip == source_ip)
    if start_time:
        filters.append(Anomaly.detected_at >= start_time)
    if end_time:
        filters.append(Anomaly.detected_at <= end_time)

    from sqlalchemy import and_
    count_q = select(func.count(Anomaly.id)).where(and_(*filters))
    total = (await db.execute(count_q)).scalar() or 0

    anomalies = (
        await db.execute(
            select(Anomaly)
            .where(and_(*filters))
            .order_by(desc(Anomaly.anomaly_score))
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
    ).scalars().all()

    return {
        "items": [AnomalyResponse.model_validate(a) for a in anomalies],
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": (total + page_size - 1) // page_size,
    }


@router.get("/trends", response_model=list)
async def get_anomaly_trends(
    hours: int = Query(24, ge=1, le=168),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Get anomaly counts and average scores over time (hourly buckets)."""
    from sqlalchemy import text
    since = datetime.now(timezone.utc) - timedelta(hours=hours)

    result = await db.execute(
        text("""
            SELECT
                date_trunc('hour', detected_at) as hour,
                COUNT(*) as count,
                AVG(anomaly_score) as avg_score
            FROM anomalies
            WHERE detected_at >= :since
            GROUP BY hour
            ORDER BY hour
        """),
        {"since": since},
    )
    return [
        {
            "timestamp": row[0].isoformat(),
            "count": row[1],
            "avg_score": round(float(row[2]), 4) if row[2] else 0.0,
        }
        for row in result
    ]


@router.get("/top-ips", response_model=list)
async def get_top_anomalous_ips(
    limit: int = Query(10, ge=1, le=50),
    hours: int = Query(24, ge=1, le=168),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Get IPs with the most anomalies in the last N hours."""
    since = datetime.now(timezone.utc) - timedelta(hours=hours)

    result = await db.execute(
        select(
            Anomaly.source_ip,
            func.count(Anomaly.id).label("count"),
            func.avg(Anomaly.anomaly_score).label("avg_score"),
            func.max(Anomaly.anomaly_score).label("max_score"),
        )
        .where(Anomaly.detected_at >= since)
        .group_by(Anomaly.source_ip)
        .order_by(desc("count"))
        .limit(limit)
    )

    return [
        {
            "source_ip": row[0],
            "count": row[1],
            "avg_score": round(float(row[2]), 4) if row[2] else 0.0,
            "max_score": round(float(row[3]), 4) if row[3] else 0.0,
        }
        for row in result
    ]


@router.get("/model-info", response_model=ModelInfo)
async def get_model_info(
    current_user: User = Depends(get_current_active_user),
):
    """Get information about the current anomaly detection model."""
    info = model_manager.get_model_info()
    from datetime import datetime as dt
    trained_at = None
    if info.get("trained_at"):
        try:
            trained_at = dt.fromisoformat(info["trained_at"])
        except Exception:
            pass

    return ModelInfo(
        model_name=info["model_name"],
        algorithm=info["algorithm"],
        trained_at=trained_at,
        training_samples=info["training_samples"],
        threshold=info["threshold"],
        is_trained=info["is_trained"],
    )
