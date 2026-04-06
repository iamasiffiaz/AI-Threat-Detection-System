"""
Correlation Engine
===================
Groups related alerts into Incidents using time-windowed, IP-centric correlation.

Correlation strategies:
  1. SAME_IP_BURST        — 3+ alerts from same IP within 5 minutes
  2. MULTI_RULE_CHAIN     — 2+ different rule types from same IP within 15 min
  3. MULTI_USER_TARGETING — same IP hitting multiple users within 10 min
  4. HIGH_RISK_SINGLE     — single alert with risk_score >= 85 (auto-incident)

Flow:
  - On each new alert: check Redis correlation state
  - If correlation threshold met → create or update Incident in PostgreSQL
  - Alert gets incident_id FK set

Redis keys:
  corr:ip:<ip>:alerts        ZSET  alert_id → timestamp (5-min window)
  corr:ip:<ip>:rules         SET   triggered rule names
  corr:ip:<ip>:users         SET   targeted usernames
  corr:incident:<ip>:open    STRING  existing open incident_id for this IP
"""
import json
import logging
import time
from datetime import datetime, timezone
from typing import Optional, List

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.incident import Incident, IncidentSeverity, IncidentStatus
from app.models.alert import Alert
from app.services.cache_service import cache_service
from app.services.risk_scoring_service import risk_scoring_service

logger = logging.getLogger(__name__)

_BURST_WINDOW       = 300    # 5-minute window for burst detection
_CHAIN_WINDOW       = 900    # 15-minute window for multi-rule chaining
_USER_TARGET_WINDOW = 600    # 10-minute window for multi-user targeting
_BURST_THRESHOLD    = 3      # alerts to trigger burst incident
_CHAIN_THRESHOLD    = 2      # different rule types to trigger chain incident
_USER_THRESHOLD     = 2      # distinct users targeted to trigger incident
_AUTO_INCIDENT_RISK = 85.0   # single-alert risk score that auto-creates incident
_CORR_ALERT_TTL     = 900    # how long to keep correlation state (15 min)
_INCIDENT_LOCK_TTL  = 300    # 5-min lock to prevent duplicate incident creation


class CorrelationService:

    async def evaluate(self, alert: Alert, db: AsyncSession) -> Optional[int]:
        """
        Evaluate whether the alert should be correlated into an incident.
        Returns the incident_id if one was created/updated, else None.
        """
        if not alert.source_ip:
            return None

        ip = alert.source_ip
        now_ts = time.time()

        incident_id = None

        # ------------------------------------------------------------------
        # Strategy 4: High-risk single event — immediate incident
        # ------------------------------------------------------------------
        if alert.risk_score and alert.risk_score >= _AUTO_INCIDENT_RISK:
            incident_id = await self._get_or_create_incident(
                ip=ip, db=db,
                alert=alert,
                trigger_reason=f"Critical risk score ({alert.risk_score:.1f})",
                alert_ids=[alert.id],
            )
            await self._link_alert(alert, incident_id, db)
            return incident_id

        # ------------------------------------------------------------------
        # Update Redis correlation windows
        # ------------------------------------------------------------------
        burst_key  = f"corr:ip:{ip}:alerts"
        rules_key  = f"corr:ip:{ip}:rules"
        users_key  = f"corr:ip:{ip}:users"

        if cache_service.available:
            # ZSET: add alert_id with score=timestamp (auto-expires old entries)
            client = cache_service._client
            try:
                pipe = client.pipeline()
                await pipe.zadd(burst_key, {str(alert.id): now_ts})
                await pipe.zremrangebyscore(burst_key, 0, now_ts - _BURST_WINDOW)
                await pipe.expire(burst_key, _CORR_ALERT_TTL)
                if alert.rule_name:
                    await pipe.sadd(rules_key,  alert.rule_name)
                    await pipe.expire(rules_key, _CHAIN_WINDOW)
                await pipe.execute()

                # If alert references a username, track it
                alert_user = await self._get_alert_username(alert.log_entry_id, db)
                if alert_user:
                    await client.sadd(users_key, alert_user)
                    await client.expire(users_key, _USER_TARGET_WINDOW)

                # Read current window state
                burst_count   = await client.zcard(burst_key)
                rule_count    = await client.scard(rules_key)
                user_count    = await client.scard(users_key)
                recent_ids    = [int(x) for x in await client.zrange(burst_key, 0, -1)]
            except Exception as exc:
                logger.debug("Correlation Redis error: %s", exc)
                return None
        else:
            # No Redis — fall back to DB-only high-risk check
            return None

        # ------------------------------------------------------------------
        # Strategy 1: Burst from same IP
        # ------------------------------------------------------------------
        if burst_count >= _BURST_THRESHOLD:
            reason = f"Alert burst: {burst_count} alerts from {ip} in 5 min"
            incident_id = await self._get_or_create_incident(
                ip=ip, db=db, alert=alert,
                trigger_reason=reason, alert_ids=recent_ids,
            )

        # ------------------------------------------------------------------
        # Strategy 2: Multi-rule chain
        # ------------------------------------------------------------------
        elif rule_count >= _CHAIN_THRESHOLD:
            rule_names = await client.smembers(rules_key)
            reason = f"Multi-rule chain: {', '.join(rule_names)} from {ip}"
            incident_id = await self._get_or_create_incident(
                ip=ip, db=db, alert=alert,
                trigger_reason=reason, alert_ids=recent_ids,
            )

        # ------------------------------------------------------------------
        # Strategy 3: Multi-user targeting
        # ------------------------------------------------------------------
        elif user_count >= _USER_THRESHOLD:
            users = await client.smembers(users_key)
            reason = f"Multi-user targeting: {ip} hitting {len(users)} accounts"
            incident_id = await self._get_or_create_incident(
                ip=ip, db=db, alert=alert,
                trigger_reason=reason, alert_ids=recent_ids,
            )

        if incident_id:
            await self._link_alert(alert, incident_id, db)
            # Clear burst window to avoid duplicate incident spam
            await client.delete(burst_key)

        return incident_id

    # -----------------------------------------------------------------------
    # Incident create / update
    # -----------------------------------------------------------------------

    async def _get_or_create_incident(
        self, ip: str, db: AsyncSession,
        alert: Alert,
        trigger_reason: str,
        alert_ids: List[int],
    ) -> int:
        """
        Return existing open incident for this IP, or create a new one.
        Uses a Redis lock to prevent duplicate creation under concurrent ingestion.
        """
        lock_key = f"corr:incident:{ip}:open"

        if cache_service.available:
            # Check if we already have an open incident ID in Redis
            existing_id_str = await cache_service._client.get(lock_key)
            if existing_id_str:
                incident_id = int(existing_id_str)
                await self._update_incident(incident_id, alert, alert_ids, db)
                return incident_id

        # Check PostgreSQL for an open incident for this IP (last 2 hours)
        from datetime import timedelta
        cutoff = datetime.now(timezone.utc) - timedelta(hours=2)
        result = await db.execute(
            select(Incident)
            .where(Incident.source_ip == ip)
            .where(Incident.status.in_([IncidentStatus.OPEN, IncidentStatus.INVESTIGATING]))
            .where(Incident.first_seen >= cutoff)
            .order_by(Incident.first_seen.desc())
            .limit(1)
        )
        incident = result.scalar_one_or_none()

        if incident:
            await self._update_incident(incident.id, alert, alert_ids, db)
            if cache_service.available:
                await cache_service._client.setex(lock_key, _INCIDENT_LOCK_TTL, str(incident.id))
            return incident.id

        # Create new incident
        incident = await self._create_incident(ip, alert, alert_ids, trigger_reason, db)
        if cache_service.available:
            await cache_service._client.setex(lock_key, _INCIDENT_LOCK_TTL, str(incident.id))

        logger.info("🚨 New incident #%d created for IP %s — %s", incident.id, ip, trigger_reason)
        return incident.id

    async def _create_incident(
        self,
        ip: str, alert: Alert,
        alert_ids: List[int],
        trigger_reason: str,
        db: AsyncSession,
    ) -> Incident:
        severity_map = {
            "low":      IncidentSeverity.LOW,
            "medium":   IncidentSeverity.MEDIUM,
            "high":     IncidentSeverity.HIGH,
            "critical": IncidentSeverity.CRITICAL,
        }
        inc_severity = severity_map.get(str(alert.severity.value).lower(), IncidentSeverity.MEDIUM)

        attack_types_list = [alert.attack_type] if alert.attack_type else []
        rule_names_list   = [alert.rule_name]   if alert.rule_name   else []

        incident = Incident(
            title=f"Incident — {alert.attack_type or 'Anomaly'} from {ip}",
            description=trigger_reason,
            severity=inc_severity,
            status=IncidentStatus.OPEN,
            source_ip=ip,
            source_ips=json.dumps([ip]),
            risk_score=alert.risk_score or 0.0,
            alert_count=len(alert_ids),
            alert_ids=json.dumps(alert_ids),
            attack_types=json.dumps(attack_types_list),
            mitre_ttps=alert.mitre_ttps,
            kill_chain_phases=json.dumps([alert.kill_chain_phase] if alert.kill_chain_phase else []),
            geo_country=alert.geo_country,
            threat_reputation=alert.threat_reputation,
            is_known_bad_ip=bool(alert.is_known_bad_ip),
            first_seen=alert.triggered_at or datetime.now(timezone.utc),
            last_seen=alert.triggered_at or datetime.now(timezone.utc),
        )
        db.add(incident)
        await db.commit()
        await db.refresh(incident)
        return incident

    async def _update_incident(
        self, incident_id: int, alert: Alert,
        alert_ids: List[int], db: AsyncSession,
    ):
        """Add alert to existing incident, update risk score and timeline."""
        result = await db.execute(select(Incident).where(Incident.id == incident_id))
        incident = result.scalar_one_or_none()
        if not incident:
            return

        existing_ids = json.loads(incident.alert_ids or "[]")
        if alert.id not in existing_ids:
            existing_ids.append(alert.id)

        # Merge attack types
        existing_types = json.loads(incident.attack_types or "[]")
        if alert.attack_type and alert.attack_type not in existing_types:
            existing_types.append(alert.attack_type)

        incident.alert_ids    = json.dumps(existing_ids)
        incident.alert_count  = len(existing_ids)
        incident.attack_types = json.dumps(existing_types)
        incident.last_seen    = datetime.now(timezone.utc)
        incident.risk_score   = max(incident.risk_score, alert.risk_score or 0.0)

        # Escalate severity if risk score justifies it
        from app.services.risk_scoring_service import risk_scoring_service
        new_sev = risk_scoring_service.score_to_severity(incident.risk_score)
        sev_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        current_sev_val = sev_order.get(incident.severity.value, 0)
        new_sev_val     = sev_order.get(new_sev.value, 0)
        if new_sev_val > current_sev_val:
            incident.severity = new_sev.value  # type: ignore[assignment]

        await db.commit()

    async def _link_alert(self, alert: Alert, incident_id: int, db: AsyncSession):
        alert.incident_id = incident_id
        await db.commit()

    async def _get_alert_username(self, log_entry_id: Optional[int], db: AsyncSession) -> Optional[str]:
        if not log_entry_id:
            return None
        from app.models.log_entry import LogEntry
        result = await db.execute(
            select(LogEntry.username).where(LogEntry.id == log_entry_id)
        )
        row = result.one_or_none()
        return row[0] if row else None


# Singleton
correlation_service = CorrelationService()
