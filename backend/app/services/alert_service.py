"""
Alert Service: creates, retrieves, and manages security alerts.
Handles both rule-based and ML-generated alerts with LLM enrichment.
"""
import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Dict, Any
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, desc
from app.models.alert import Alert, AlertSeverity, AlertStatus, AlertType
from app.schemas.alert import AlertCreate, AlertSummary
from app.services.rule_engine import RuleMatch
from app.services.llm_service import llm_service

logger = logging.getLogger(__name__)

# In-memory set for WebSocket broadcasting
_alert_subscribers: List[asyncio.Queue] = []


def subscribe_to_alerts() -> asyncio.Queue:
    """Subscribe to real-time alert notifications."""
    q: asyncio.Queue = asyncio.Queue(maxsize=100)
    _alert_subscribers.append(q)
    return q


def unsubscribe_from_alerts(q: asyncio.Queue):
    """Unsubscribe from alert notifications."""
    if q in _alert_subscribers:
        _alert_subscribers.remove(q)


async def _broadcast_alert(alert_data: dict):
    """Broadcast a new alert to all WebSocket subscribers."""
    dead_queues = []
    for q in _alert_subscribers:
        try:
            q.put_nowait(alert_data)
        except asyncio.QueueFull:
            dead_queues.append(q)
    for q in dead_queues:
        unsubscribe_from_alerts(q)


class AlertService:
    """CRUD and business logic for security alerts."""

    async def create_from_rule_match(
        self,
        db: AsyncSession,
        match: RuleMatch,
        log_dict: Optional[Dict[str, Any]] = None,
    ) -> Alert:
        """Create an alert from a rule engine match, with async LLM enrichment."""
        alert = Alert(
            title=match.title,
            description=match.description,
            severity=match.severity,
            alert_type=AlertType.RULE_BASED,
            source_ip=match.source_ip,
            rule_name=match.rule_name,
            log_entry_id=match.log_entry_id,
        )
        db.add(alert)
        await db.flush()  # Get the ID before enrichment

        # Enrich with LLM asynchronously (non-blocking)
        asyncio.create_task(
            self._enrich_alert_with_llm(db, alert.id, match, log_dict)
        )

        await db.commit()
        await db.refresh(alert)

        # Broadcast to WebSocket subscribers
        await _broadcast_alert({
            "type": "new_alert",
            "alert": {
                "id": alert.id,
                "title": alert.title,
                "severity": alert.severity.value,
                "status": alert.status.value,
                "triggered_at": alert.triggered_at.isoformat(),
            },
        })

        logger.info(f"Created alert: {alert.title} (severity={alert.severity.value})")
        return alert

    async def create_from_anomaly(
        self,
        db: AsyncSession,
        anomaly_score: float,
        log_dict: Dict[str, Any],
        log_entry_id: Optional[int] = None,
    ) -> Optional[Alert]:
        """Create an alert from an ML-detected anomaly."""
        severity = self._score_to_severity(anomaly_score)

        alert = Alert(
            title=f"ML Anomaly Detected: {log_dict.get('source_ip', 'Unknown')}",
            description=(
                f"ML model detected anomalous behavior with score {anomaly_score:.3f}. "
                f"Event: {log_dict.get('event_type', 'Unknown')}. "
                f"Source: {log_dict.get('source_ip', 'Unknown')}."
            ),
            severity=severity,
            alert_type=AlertType.ANOMALY,
            source_ip=log_dict.get("source_ip"),
            anomaly_score=anomaly_score,
            log_entry_id=log_entry_id,
        )
        db.add(alert)
        await db.flush()

        asyncio.create_task(
            self._enrich_alert_with_llm(
                db, alert.id,
                RuleMatch(
                    rule_name="ml_anomaly",
                    title=alert.title,
                    description=alert.description,
                    severity=severity,
                    source_ip=log_dict.get("source_ip"),
                    context={"anomaly_score": anomaly_score},
                ),
                log_dict,
            )
        )

        await db.commit()
        await db.refresh(alert)

        await _broadcast_alert({
            "type": "new_alert",
            "alert": {
                "id": alert.id,
                "title": alert.title,
                "severity": alert.severity.value,
                "anomaly_score": anomaly_score,
                "triggered_at": alert.triggered_at.isoformat(),
            },
        })

        return alert

    async def _enrich_alert_with_llm(
        self,
        db: AsyncSession,
        alert_id: int,
        match: RuleMatch,
        log_dict: Optional[Dict[str, Any]],
    ):
        """Asynchronously enrich an alert with LLM threat analysis."""
        try:
            analysis = await llm_service.analyze_threat(
                anomaly_data={
                    "rule_name": match.rule_name,
                    "anomaly_score": match.context.get("anomaly_score", 0),
                    "description": match.description,
                },
                log_data=log_dict,
            )

            # Re-fetch alert in a new session to avoid stale state
            result = await db.execute(select(Alert).where(Alert.id == alert_id))
            alert = result.scalar_one_or_none()
            if alert:
                alert.llm_explanation = analysis.get("explanation")
                alert.attack_type = analysis.get("attack_type")
                alert.mitigation_steps = "\n".join(
                    f"• {step}" for step in analysis.get("mitigation_steps", [])
                )
                await db.commit()
                logger.debug(f"LLM enrichment complete for alert {alert_id}")

        except Exception as e:
            logger.error(f"LLM enrichment failed for alert {alert_id}: {e}")

    def _score_to_severity(self, score: float) -> AlertSeverity:
        """Convert an anomaly score to alert severity."""
        if score >= 0.9:
            return AlertSeverity.CRITICAL
        elif score >= 0.75:
            return AlertSeverity.HIGH
        elif score >= 0.6:
            return AlertSeverity.MEDIUM
        return AlertSeverity.LOW

    async def get_alerts(
        self,
        db: AsyncSession,
        page: int = 1,
        page_size: int = 50,
        severity: Optional[AlertSeverity] = None,
        status: Optional[AlertStatus] = None,
        alert_type: Optional[AlertType] = None,
        source_ip: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> tuple[List[Alert], int]:
        """Paginated alert retrieval with filtering."""
        query = select(Alert)
        count_query = select(func.count(Alert.id))

        filters = []
        if severity:
            filters.append(Alert.severity == severity)
        if status:
            filters.append(Alert.status == status)
        if alert_type:
            filters.append(Alert.alert_type == alert_type)
        if source_ip:
            filters.append(Alert.source_ip == source_ip)
        if start_time:
            filters.append(Alert.triggered_at >= start_time)
        if end_time:
            filters.append(Alert.triggered_at <= end_time)

        if filters:
            query = query.where(and_(*filters))
            count_query = count_query.where(and_(*filters))

        total = (await db.execute(count_query)).scalar() or 0
        alerts = (
            await db.execute(
                query.order_by(desc(Alert.triggered_at))
                .offset((page - 1) * page_size)
                .limit(page_size)
            )
        ).scalars().all()

        return list(alerts), total

    async def get_summary(self, db: AsyncSession) -> AlertSummary:
        """Get dashboard summary statistics for alerts."""
        now = datetime.now(timezone.utc)
        day_ago = now - timedelta(hours=24)

        total = (await db.execute(select(func.count(Alert.id)))).scalar() or 0
        open_alerts = (
            await db.execute(select(func.count(Alert.id)).where(Alert.status == AlertStatus.OPEN))
        ).scalar() or 0
        critical = (
            await db.execute(
                select(func.count(Alert.id)).where(Alert.severity == AlertSeverity.CRITICAL)
            )
        ).scalar() or 0
        high = (
            await db.execute(
                select(func.count(Alert.id)).where(Alert.severity == AlertSeverity.HIGH)
            )
        ).scalar() or 0
        last_24h = (
            await db.execute(
                select(func.count(Alert.id)).where(Alert.triggered_at >= day_ago)
            )
        ).scalar() or 0

        recent_alerts = (
            await db.execute(
                select(Alert).order_by(desc(Alert.triggered_at)).limit(10)
            )
        ).scalars().all()

        return AlertSummary(
            total_alerts=total,
            open_alerts=open_alerts,
            critical_alerts=critical,
            high_alerts=high,
            alerts_last_24h=last_24h,
            by_type={"anomaly": 0, "rule_based": 0, "hybrid": 0},
            by_status={"open": open_alerts, "investigating": 0, "resolved": 0},
            recent_alerts=list(recent_alerts),
        )

    async def update_alert(
        self,
        db: AsyncSession,
        alert_id: int,
        updates: Dict[str, Any],
    ) -> Optional[Alert]:
        """Update an alert's fields."""
        result = await db.execute(select(Alert).where(Alert.id == alert_id))
        alert = result.scalar_one_or_none()
        if not alert:
            return None

        for key, value in updates.items():
            if hasattr(alert, key) and value is not None:
                setattr(alert, key, value)

        if updates.get("status") in (AlertStatus.RESOLVED, "resolved"):
            alert.resolved_at = datetime.now(timezone.utc)

        await db.commit()
        await db.refresh(alert)
        return alert


alert_service = AlertService()
