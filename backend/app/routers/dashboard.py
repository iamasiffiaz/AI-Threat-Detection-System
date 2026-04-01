"""
Dashboard router: aggregated metrics endpoint combining logs, alerts, and anomalies.
"""
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, text
from datetime import datetime, timedelta, timezone
from app.core.database import get_db
from app.core.dependencies import get_current_active_user
from app.models.user import User
from app.models.log_entry import LogEntry
from app.models.alert import Alert, AlertStatus, AlertSeverity
from app.models.anomaly import Anomaly
from app.ml.model_manager import model_manager
from app.services.llm_service import llm_service

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


@router.get("/overview")
async def get_overview(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """
    Get all dashboard KPIs in a single request:
    - Log totals and recent activity
    - Alert counts by severity/status
    - Anomaly summary
    - Model status
    - LLM availability
    """
    now = datetime.now(timezone.utc)
    hour_ago = now - timedelta(hours=1)
    day_ago = now - timedelta(hours=24)
    week_ago = now - timedelta(days=7)

    # Log metrics
    total_logs = (await db.execute(select(func.count(LogEntry.id)))).scalar() or 0
    logs_last_hour = (
        await db.execute(select(func.count(LogEntry.id)).where(LogEntry.ingested_at >= hour_ago))
    ).scalar() or 0
    logs_last_24h = (
        await db.execute(select(func.count(LogEntry.id)).where(LogEntry.ingested_at >= day_ago))
    ).scalar() or 0

    # Alert metrics
    total_alerts = (await db.execute(select(func.count(Alert.id)))).scalar() or 0
    open_alerts = (
        await db.execute(select(func.count(Alert.id)).where(Alert.status == AlertStatus.OPEN))
    ).scalar() or 0
    critical_alerts = (
        await db.execute(
            select(func.count(Alert.id)).where(Alert.severity == AlertSeverity.CRITICAL)
        )
    ).scalar() or 0
    alerts_24h = (
        await db.execute(
            select(func.count(Alert.id)).where(Alert.triggered_at >= day_ago)
        )
    ).scalar() or 0

    # Anomaly metrics
    total_anomalies = (await db.execute(select(func.count(Anomaly.id)))).scalar() or 0
    anomalies_24h = (
        await db.execute(
            select(func.count(Anomaly.id)).where(Anomaly.detected_at >= day_ago)
        )
    ).scalar() or 0
    avg_score_result = await db.execute(
        select(func.avg(Anomaly.anomaly_score)).where(Anomaly.detected_at >= day_ago)
    )
    avg_anomaly_score = avg_score_result.scalar()

    # Traffic timeline (last 24h, hourly)
    try:
        timeline_result = await db.execute(
            text("""
                SELECT date_trunc('hour', timestamp) as hour, COUNT(*) as count
                FROM log_entries WHERE timestamp >= :since
                GROUP BY hour ORDER BY hour
            """),
            {"since": day_ago},
        )
        traffic_timeline = [
            {"timestamp": row[0].isoformat(), "count": row[1]}
            for row in timeline_result
        ]
    except Exception:
        traffic_timeline = []

    # Severity distribution
    try:
        sev_result = await db.execute(
            select(Alert.severity, func.count(Alert.id))
            .group_by(Alert.severity)
        )
        severity_dist = {row[0].value: row[1] for row in sev_result}
    except Exception:
        severity_dist = {}

    # Recent alerts
    recent_alerts = (
        await db.execute(
            select(Alert).order_by(Alert.triggered_at.desc()).limit(5)
        )
    ).scalars().all()

    # Recent anomalies
    recent_anomalies = (
        await db.execute(
            select(Anomaly).order_by(Anomaly.detected_at.desc()).limit(5)
        )
    ).scalars().all()

    return {
        "logs": {
            "total": total_logs,
            "last_hour": logs_last_hour,
            "last_24h": logs_last_24h,
        },
        "alerts": {
            "total": total_alerts,
            "open": open_alerts,
            "critical": critical_alerts,
            "last_24h": alerts_24h,
            "by_severity": severity_dist,
        },
        "anomalies": {
            "total": total_anomalies,
            "last_24h": anomalies_24h,
            "avg_score_24h": round(float(avg_anomaly_score), 4) if avg_anomaly_score else 0.0,
        },
        "model": model_manager.get_model_info(),
        "system": {
            "llm_available": await llm_service.check_availability(),
            "server_time": now.isoformat(),
        },
        "charts": {
            "traffic_timeline": traffic_timeline,
        },
        "recent_alerts": [
            {
                "id": a.id,
                "title": a.title,
                "severity": a.severity.value,
                "status": a.status.value,
                "triggered_at": a.triggered_at.isoformat(),
            }
            for a in recent_alerts
        ],
        "recent_anomalies": [
            {
                "id": a.id,
                "source_ip": a.source_ip,
                "anomaly_score": round(a.anomaly_score, 4),
                "detected_at": a.detected_at.isoformat(),
            }
            for a in recent_anomalies
        ],
    }
