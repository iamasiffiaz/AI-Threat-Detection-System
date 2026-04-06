"""
Alert Service — enterprise SOC edition.

Pipeline for each new alert:
  1. Persist alert to DB
  2. Risk scoring   (ML + rules + TI + behavior → 0-100)
  3. Classification (attack type + confidence)
  4. Threat Intel   (GeoIP + reputation)
  5. Correlation    (check if alert belongs to an existing Incident)
  6. SOAR           (auto-block if risk >= 85)
  7. LLM enrichment (MITRE kill-chain explanation — async background task)
  8. Broadcast      (WebSocket + Redis pub/sub)
"""
import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Dict, Any

from sqlalchemy import select, func, and_, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.alert import Alert, AlertSeverity, AlertStatus, AlertType
from app.models.log_entry import LogEntry
from app.schemas.alert import AlertCreate, AlertSummary
from app.services.rule_engine import RuleMatch
from app.services.llm_service import llm_service
from app.services.cache_service import cache_service
from app.services.risk_scoring_service import risk_scoring_service
from app.services.classification_service import classification_service
from app.services.threat_intel_service import threat_intel_service
from app.services.correlation_service import correlation_service
from app.services.soar_service import soar_service
from app.services.behavioral_profile_service import behavioral_profile_service
from app.core.database import AsyncSessionLocal

logger = logging.getLogger(__name__)

# In-memory queue for WebSocket broadcasting
_alert_subscribers: List[asyncio.Queue] = []


def subscribe_to_alerts() -> asyncio.Queue:
    q: asyncio.Queue = asyncio.Queue(maxsize=100)
    _alert_subscribers.append(q)
    return q


def unsubscribe_from_alerts(q: asyncio.Queue):
    if q in _alert_subscribers:
        _alert_subscribers.remove(q)


async def _broadcast_alert(alert_data: dict):
    dead: list = []
    for q in _alert_subscribers:
        try:
            q.put_nowait(alert_data)
        except asyncio.QueueFull:
            dead.append(q)
    for q in dead:
        unsubscribe_from_alerts(q)
    # Also publish to Redis pub/sub for multi-process setups
    await cache_service.publish_alert(alert_data)


class AlertService:

    # -----------------------------------------------------------------------
    # Create from rule engine match
    # -----------------------------------------------------------------------

    async def create_from_rule_match(
        self,
        db: AsyncSession,
        match: RuleMatch,
        log_dict: Optional[Dict[str, Any]] = None,
    ) -> Alert:
        """Full pipeline: create → risk score → classify → TI → correlate → SOAR → LLM."""

        ip         = match.source_ip
        rule_names = [match.rule_name] if match.rule_name else []

        # 1. Behavioral profile (quick sync read, already updated in log_service)
        profile = await behavioral_profile_service.get_profile_ip(ip or "")

        # 2. Threat Intelligence — async lookup
        ti_result = None
        if ip:
            try:
                ti_result = await threat_intel_service.lookup(ip, db)
            except Exception as exc:
                logger.debug("TI lookup failed for %s: %s", ip, exc)

        ti_rep    = ti_result.reputation_score if ti_result else 0.0
        is_bad_ip = bool(ti_result and ti_result.is_known_bad)

        # 3. Classification
        anomaly_score = float(match.context.get("anomaly_score") or 0)
        clf = classification_service.classify(
            rule_name=match.rule_name,
            event_type=log_dict.get("event_type") if log_dict else None,
            message=log_dict.get("message") if log_dict else None,
            raw_log=log_dict.get("raw_log") if log_dict else None,
            anomaly_score=anomaly_score,
            behavior_score=profile.deviation_score,
            unique_ports=profile.unique_ports_1h,
            bytes_out=profile.bytes_out_1h,
            failed_logins=profile.failed_logins_1h,
            is_known_bad=is_bad_ip,
        )

        # 4. Risk score
        ip_alert_count = await cache_service.get_ip_alerts(ip) if ip else 0
        risk = risk_scoring_service.compute(
            anomaly_score=anomaly_score,
            rule_names=rule_names,
            threat_reputation=ti_rep,
            behavior_score=profile.deviation_score,
            is_known_bad_ip=is_bad_ip,
            classification_conf=clf.confidence_score,
            ip_alert_count=ip_alert_count,
        )

        # Determine severity from risk score (overrides rule severity for >= HIGH)
        final_severity = risk.severity
        rule_sev_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        if rule_sev_order.get(risk.severity.value, 0) < rule_sev_order.get(match.severity.value, 0):
            final_severity = match.severity  # Keep original if rule says higher

        # 5. Persist alert
        alert = Alert(
            title=match.title,
            description=match.description,
            severity=final_severity,
            alert_type=AlertType.RULE_BASED,
            source_ip=ip,
            rule_name=match.rule_name,
            log_entry_id=match.log_entry_id,
            anomaly_score=anomaly_score or None,
            risk_score=risk.risk_score,
            attack_type=clf.attack_type,
            geo_country=ti_result.country_name if ti_result else None,
            geo_city=ti_result.city if ti_result else None,
            threat_reputation=ti_rep,
            is_known_bad_ip=is_bad_ip,
            behavior_score=profile.deviation_score,
        )
        db.add(alert)
        await db.flush()
        await db.commit()
        await db.refresh(alert)

        # 6. Correlation — may create or update an Incident
        try:
            incident_id = await correlation_service.evaluate(alert, db)
            if incident_id:
                await db.refresh(alert)
        except Exception as exc:
            logger.warning("Correlation failed for alert %d: %s", alert.id, exc)

        # 7. SOAR auto-response
        try:
            playbook_name = await soar_service.auto_respond(
                alert_data={
                    "source_ip":   ip,
                    "risk_score":  risk.risk_score,
                    "attack_type": clf.attack_type,
                    "rule_name":   match.rule_name,
                },
                db=db,
            )
            if playbook_name:
                logger.info("SOAR auto-response triggered: %s for IP %s", playbook_name, ip)
        except Exception as exc:
            logger.debug("SOAR auto-respond failed: %s", exc)

        # 8. Increment IP alert counter
        if ip:
            await cache_service.increment_ip_alerts(ip)

        # 9. LLM enrichment in background (non-blocking)
        asyncio.create_task(
            self._enrich_alert_with_llm(alert.id, match, log_dict, ti_result, profile)
        )

        # 10. Broadcast
        await _broadcast_alert({
            "type":      "new_alert",
            "alert": {
                "id":          alert.id,
                "title":       alert.title,
                "severity":    alert.severity.value,
                "risk_score":  alert.risk_score,
                "attack_type": alert.attack_type,
                "source_ip":   alert.source_ip,
                "geo_country": alert.geo_country,
                "status":      alert.status.value,
                "triggered_at": alert.triggered_at.isoformat(),
            },
        })

        logger.info(
            "Alert created #%d | %s | risk=%.1f | type=%s | sev=%s",
            alert.id, alert.title, alert.risk_score or 0,
            alert.attack_type, alert.severity.value,
        )
        return alert

    # -----------------------------------------------------------------------
    # Create from ML anomaly
    # -----------------------------------------------------------------------

    async def create_from_anomaly(
        self,
        db: AsyncSession,
        anomaly_score: float,
        log_dict: Dict[str, Any],
        log_entry_id: Optional[int] = None,
    ) -> Optional[Alert]:
        """Create an alert from ML-detected anomaly with full enrichment pipeline."""

        ip      = log_dict.get("source_ip")
        profile = await behavioral_profile_service.get_profile_ip(ip or "")

        ti_result = None
        if ip:
            try:
                ti_result = await threat_intel_service.lookup(ip, db)
            except Exception:
                pass

        ti_rep    = ti_result.reputation_score if ti_result else 0.0
        is_bad_ip = bool(ti_result and ti_result.is_known_bad)

        clf = classification_service.classify(
            event_type=log_dict.get("event_type"),
            message=log_dict.get("message"),
            anomaly_score=anomaly_score,
            behavior_score=profile.deviation_score,
            unique_ports=profile.unique_ports_1h,
            bytes_out=profile.bytes_out_1h,
            failed_logins=profile.failed_logins_1h,
            is_known_bad=is_bad_ip,
        )

        ip_alert_count = await cache_service.get_ip_alerts(ip) if ip else 0
        risk = risk_scoring_service.compute(
            anomaly_score=anomaly_score,
            rule_names=[],
            threat_reputation=ti_rep,
            behavior_score=profile.deviation_score,
            is_known_bad_ip=is_bad_ip,
            classification_conf=clf.confidence_score,
            ip_alert_count=ip_alert_count,
        )

        alert = Alert(
            title=f"ML Anomaly: {clf.attack_type} from {ip or 'Unknown'}",
            description=(
                f"ML model detected anomalous behavior (score {anomaly_score:.3f}). "
                f"Classification: {clf.attack_type} (confidence {clf.confidence_score:.2f}). "
                f"Event: {log_dict.get('event_type', 'Unknown')}."
            ),
            severity=risk.severity,
            alert_type=AlertType.ANOMALY,
            source_ip=ip,
            anomaly_score=anomaly_score,
            risk_score=risk.risk_score,
            attack_type=clf.attack_type,
            log_entry_id=log_entry_id,
            geo_country=ti_result.country_name if ti_result else None,
            geo_city=ti_result.city if ti_result else None,
            threat_reputation=ti_rep,
            is_known_bad_ip=is_bad_ip,
            behavior_score=profile.deviation_score,
        )
        db.add(alert)
        await db.flush()
        await db.commit()
        await db.refresh(alert)

        # Correlation
        try:
            await correlation_service.evaluate(alert, db)
        except Exception as exc:
            logger.debug("Correlation error: %s", exc)

        # SOAR
        try:
            await soar_service.auto_respond(
                alert_data={
                    "source_ip":  ip,
                    "risk_score": risk.risk_score,
                    "attack_type": clf.attack_type,
                    "rule_name":   None,
                },
                db=db,
            )
        except Exception:
            pass

        if ip:
            await cache_service.increment_ip_alerts(ip)

        asyncio.create_task(
            self._enrich_alert_with_llm(
                alert.id,
                RuleMatch(
                    rule_name="ml_anomaly",
                    title=alert.title,
                    description=alert.description,
                    severity=risk.severity,
                    source_ip=ip,
                    context={"anomaly_score": anomaly_score},
                    log_entry_id=log_entry_id,
                ),
                log_dict,
                ti_result,
                profile,
            )
        )

        await _broadcast_alert({
            "type":  "new_alert",
            "alert": {
                "id":           alert.id,
                "title":        alert.title,
                "severity":     alert.severity.value,
                "risk_score":   alert.risk_score,
                "attack_type":  alert.attack_type,
                "anomaly_score": anomaly_score,
                "source_ip":    alert.source_ip,
                "triggered_at": alert.triggered_at.isoformat(),
            },
        })

        return alert

    # -----------------------------------------------------------------------
    # LLM enrichment (background task)
    # -----------------------------------------------------------------------

    async def _enrich_alert_with_llm(
        self,
        alert_id: int,
        match: RuleMatch,
        log_dict: Optional[Dict[str, Any]],
        ti_result=None,
        profile=None,
    ):
        """
        Full MITRE ATT&CK kill-chain analysis via LLM.
        Runs as an asyncio background task with its own DB session.
        """
        try:
            ip = (log_dict or {}).get("source_ip") or match.source_ip

            # Build behavioral context dict for LLM prompt
            behavior_data = None
            if profile:
                behavior_data = {
                    "requests_per_minute": profile.req_count_1h,
                    "failed_logins":       profile.failed_logins_1h,
                    "unique_ports_count":  profile.unique_ports_1h,
                    "unique_destinations": profile.unique_dests_1h,
                    "total_bytes_mb":      round(profile.bytes_out_1h / 1024 / 1024, 2),
                    "prior_alerts_24h":    await cache_service.get_ip_alerts(ip) if ip else 0,
                    "deviation_score":     profile.deviation_score,
                    "is_new_source":       profile.is_new_source,
                }
            elif ip and cache_service.available:
                behavior_data = {
                    "failed_logins":       await cache_service.rule_get("brute_force", ip),
                    "unique_ports_count":  await cache_service.rule_scard("portscan", ip),
                    "prior_alerts_24h":    await cache_service.get_ip_alerts(ip),
                }

            related_alerts = []
            if ip:
                alert_count = await cache_service.get_ip_alerts(ip)
                if alert_count > 0:
                    related_alerts.append(f"IP {ip} has triggered {alert_count} alerts in the last 24h")
                if ti_result and ti_result.is_known_bad:
                    related_alerts.append(
                        f"IP {ip} is in known-bad dataset: {', '.join(ti_result.threat_categories)}"
                    )
                if ti_result and ti_result.country_name:
                    related_alerts.append(f"Geo origin: {ti_result.country_name} ({ti_result.isp})")

            analysis = await llm_service.analyze_threat(
                anomaly_data={
                    "rule_name":     match.rule_name,
                    "anomaly_score": match.context.get("anomaly_score", 0),
                    "description":   match.description,
                    "context":       match.context,
                },
                log_data=log_dict,
                behavior_data=behavior_data,
                related_alerts=related_alerts,
            )

            async with AsyncSessionLocal() as session:
                result = await session.execute(select(Alert).where(Alert.id == alert_id))
                alert = result.scalar_one_or_none()
                if alert:
                    alert.llm_explanation  = analysis.get("explanation")
                    alert.attack_type      = analysis.get("attack_type") or alert.attack_type
                    alert.mitigation_steps = "\n".join(
                        f"• {s}" for s in analysis.get("mitigation_steps", [])
                    )
                    alert.kill_chain_phase          = analysis.get("kill_chain_phase")
                    alert.mitre_ttps                = str(analysis.get("mitre_ttps", []))
                    alert.false_positive_likelihood = analysis.get("false_positive_likelihood")
                    await session.commit()
                    logger.info(
                        "LLM enrichment done — alert #%d | type=%s | fp=%s | source=%s",
                        alert_id, analysis.get("attack_type"),
                        analysis.get("false_positive_likelihood"),
                        analysis.get("source", "llm"),
                    )

        except Exception as exc:
            logger.error("LLM enrichment failed for alert %d: %s", alert_id, exc)

    # -----------------------------------------------------------------------
    # CRUD helpers (unchanged from original)
    # -----------------------------------------------------------------------

    def _score_to_severity(self, score: float) -> AlertSeverity:
        if score >= 0.9:
            return AlertSeverity.CRITICAL
        if score >= 0.75:
            return AlertSeverity.HIGH
        if score >= 0.6:
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
        query = select(Alert)
        count_q = select(func.count(Alert.id))
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
            query   = query.where(and_(*filters))
            count_q = count_q.where(and_(*filters))

        total  = (await db.execute(count_q)).scalar() or 0
        alerts = (
            await db.execute(
                query.order_by(desc(Alert.triggered_at))
                .offset((page - 1) * page_size)
                .limit(page_size)
            )
        ).scalars().all()

        return list(alerts), total

    async def get_summary(self, db: AsyncSession) -> AlertSummary:
        now     = datetime.now(timezone.utc)
        day_ago = now - timedelta(hours=24)

        total      = (await db.execute(select(func.count(Alert.id)))).scalar() or 0
        open_count = (await db.execute(
            select(func.count(Alert.id)).where(Alert.status == AlertStatus.OPEN)
        )).scalar() or 0
        critical = (await db.execute(
            select(func.count(Alert.id)).where(Alert.severity == AlertSeverity.CRITICAL)
        )).scalar() or 0
        high = (await db.execute(
            select(func.count(Alert.id)).where(Alert.severity == AlertSeverity.HIGH)
        )).scalar() or 0
        last_24h = (await db.execute(
            select(func.count(Alert.id)).where(Alert.triggered_at >= day_ago)
        )).scalar() or 0

        recent = (
            await db.execute(select(Alert).order_by(desc(Alert.triggered_at)).limit(10))
        ).scalars().all()

        return AlertSummary(
            total_alerts=total,
            open_alerts=open_count,
            critical_alerts=critical,
            high_alerts=high,
            alerts_last_24h=last_24h,
            by_type={"anomaly": 0, "rule_based": 0, "hybrid": 0},
            by_status={"open": open_count, "investigating": 0, "resolved": 0},
            recent_alerts=list(recent),
        )

    async def update_alert(
        self,
        db: AsyncSession,
        alert_id: int,
        updates: Dict[str, Any],
    ) -> Optional[Alert]:
        result = await db.execute(select(Alert).where(Alert.id == alert_id))
        alert  = result.scalar_one_or_none()
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
