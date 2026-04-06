"""
Forensics & Investigation router.

When an analyst clicks on an alert or incident they get a full
forensic view: log history, alert timeline, behavior summary,
related incidents and threat intel.

Endpoints:
  GET /api/v1/investigation/ip/{ip}          Full forensic report for an IP
  GET /api/v1/investigation/ip/{ip}/logs     All logs from this IP (paginated)
  GET /api/v1/investigation/ip/{ip}/alerts   All alerts for this IP
  GET /api/v1/investigation/ip/{ip}/behavior Behavioral profile summary
  GET /api/v1/investigation/alert/{id}       Deep dive on a single alert
"""
import logging
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Any, Dict

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import select, desc, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import get_db, get_current_user
from app.models.user import User
from app.models.log_entry import LogEntry
from app.models.alert import Alert
from app.models.incident import Incident
from app.schemas.alert import AlertResponse
from app.services.behavioral_profile_service import behavioral_profile_service
from app.services.threat_intel_service import threat_intel_service

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/investigation", tags=["investigation"])


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class LogSummary(BaseModel):
    id:            int
    timestamp:     datetime
    event_type:    str
    severity:      str
    source_port:   Optional[int]
    destination_ip: Optional[str]
    destination_port: Optional[int]
    protocol:      str
    message:       Optional[str]
    bytes_sent:    Optional[int]
    username:      Optional[str]
    anomaly_score: Optional[float]
    risk_score:    Optional[float]
    attack_type:   Optional[str]
    model_config   = {"from_attributes": True}


class ForensicReport(BaseModel):
    ip_address:      str
    first_seen:      Optional[datetime]
    last_seen:       Optional[datetime]
    total_logs:      int
    total_alerts:    int
    open_incidents:  int
    risk_score_max:  float
    attack_types:    List[str]
    geo_info:        Dict[str, Any]
    behavior_summary: Dict[str, Any]
    recent_alerts:   List[Dict[str, Any]]
    timeline_events: List[Dict[str, Any]]


# ---------------------------------------------------------------------------
# Full forensic report
# ---------------------------------------------------------------------------

@router.get("/ip/{ip}", response_model=ForensicReport)
async def forensic_report(
    ip: str,
    hours: int = Query(24, ge=1, le=720),
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    """Complete forensic investigation report for an IP address."""
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)

    # Logs
    logs_result = await db.execute(
        select(LogEntry)
        .where(LogEntry.source_ip == ip)
        .where(LogEntry.timestamp >= cutoff)
        .order_by(desc(LogEntry.timestamp))
        .limit(200)
    )
    logs = logs_result.scalars().all()

    # Alerts
    alerts_result = await db.execute(
        select(Alert)
        .where(Alert.source_ip == ip)
        .where(Alert.triggered_at >= cutoff)
        .order_by(desc(Alert.triggered_at))
        .limit(50)
    )
    alerts = alerts_result.scalars().all()

    # Incidents
    incidents_result = await db.execute(
        select(func.count(Incident.id))
        .where(Incident.source_ip == ip)
        .where(Incident.status.in_(["open", "investigating"]))
    )
    open_incidents = incidents_result.scalar() or 0

    # GeoIP
    ti_result = await threat_intel_service.lookup(ip, db)
    geo_info = {
        "country_code": ti_result.country_code,
        "country_name": ti_result.country_name,
        "city": ti_result.city,
        "isp": ti_result.isp,
        "asn": ti_result.asn,
        "latitude": ti_result.latitude,
        "longitude": ti_result.longitude,
        "is_tor_exit": ti_result.is_tor_exit,
        "is_proxy": ti_result.is_proxy,
        "is_known_bad": ti_result.is_known_bad,
        "reputation_score": ti_result.reputation_score,
        "threat_categories": ti_result.threat_categories,
    }

    # Behavioral profile
    profile = await behavioral_profile_service.get_profile_ip(ip)
    behavior_summary = {
        "requests_1h":       profile.req_count_1h,
        "failed_logins_1h":  profile.failed_logins_1h,
        "unique_ports_1h":   profile.unique_ports_1h,
        "unique_dests_1h":   profile.unique_dests_1h,
        "bytes_out_1h":      profile.bytes_out_1h,
        "requests_24h":      profile.req_count_24h,
        "deviation_score":   profile.deviation_score,
        "is_new_source":     profile.is_new_source,
        "baseline_requests": profile.baseline_req,
        "baseline_failures": profile.baseline_failed,
    }

    # Attack types seen
    attack_types = list({a.attack_type for a in alerts if a.attack_type})

    # Max risk score
    max_risk = max((a.risk_score or 0 for a in alerts), default=0.0)

    # Timestamps
    all_times = [l.timestamp for l in logs] + [a.triggered_at for a in alerts]
    first_seen = min(all_times) if all_times else None
    last_seen  = max(all_times) if all_times else None

    # Timeline events (merge logs + alerts, sorted by time)
    timeline = []
    for log in logs[:50]:
        timeline.append({
            "time":        log.timestamp,
            "type":        "log",
            "event":       log.event_type,
            "severity":    log.severity.value if log.severity else "info",
            "details":     log.message or "",
            "risk_score":  log.risk_score,
            "attack_type": log.attack_type,
        })
    for alert in alerts[:20]:
        timeline.append({
            "time":        alert.triggered_at,
            "type":        "alert",
            "event":       alert.title,
            "severity":    alert.severity.value,
            "details":     alert.description or "",
            "risk_score":  alert.risk_score,
            "attack_type": alert.attack_type,
            "rule_name":   alert.rule_name,
        })
    timeline.sort(key=lambda x: x["time"], reverse=True)

    recent_alerts = [
        {
            "id":          a.id,
            "title":       a.title,
            "severity":    a.severity.value,
            "risk_score":  a.risk_score,
            "attack_type": a.attack_type,
            "rule_name":   a.rule_name,
            "triggered_at": a.triggered_at,
            "status":      a.status.value,
        }
        for a in alerts[:10]
    ]

    return ForensicReport(
        ip_address=ip,
        first_seen=first_seen,
        last_seen=last_seen,
        total_logs=len(logs),
        total_alerts=len(alerts),
        open_incidents=open_incidents,
        risk_score_max=max_risk,
        attack_types=attack_types,
        geo_info=geo_info,
        behavior_summary=behavior_summary,
        recent_alerts=recent_alerts,
        timeline_events=timeline[:100],
    )


# ---------------------------------------------------------------------------
# Individual endpoints
# ---------------------------------------------------------------------------

@router.get("/ip/{ip}/logs", response_model=List[LogSummary])
async def ip_logs(
    ip: str,
    hours: int = Query(24, ge=1, le=720),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    result = await db.execute(
        select(LogEntry)
        .where(LogEntry.source_ip == ip)
        .where(LogEntry.timestamp >= cutoff)
        .order_by(desc(LogEntry.timestamp))
        .offset(offset).limit(limit)
    )
    return result.scalars().all()


@router.get("/ip/{ip}/alerts", response_model=List[AlertResponse])
async def ip_alerts(
    ip: str,
    hours: int = Query(72, ge=1, le=720),
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    result = await db.execute(
        select(Alert)
        .where(Alert.source_ip == ip)
        .where(Alert.triggered_at >= cutoff)
        .order_by(desc(Alert.triggered_at))
        .limit(100)
    )
    return result.scalars().all()


@router.get("/ip/{ip}/behavior")
async def ip_behavior(
    ip: str,
    _user: User = Depends(get_current_user),
):
    profile = await behavioral_profile_service.get_profile_ip(ip)
    return {
        "ip": ip,
        "current_window_1h": {
            "requests":      profile.req_count_1h,
            "failed_logins": profile.failed_logins_1h,
            "unique_ports":  profile.unique_ports_1h,
            "unique_dests":  profile.unique_dests_1h,
            "bytes_out":     profile.bytes_out_1h,
        },
        "24h_totals": {
            "requests":      profile.req_count_24h,
            "failed_logins": profile.failed_logins_24h,
        },
        "baselines": {
            "avg_requests":      profile.baseline_req,
            "avg_failed_logins": profile.baseline_failed,
            "avg_unique_ports":  profile.baseline_ports,
        },
        "risk_indicators": {
            "deviation_score": profile.deviation_score,
            "is_new_source":   profile.is_new_source,
        },
    }


@router.get("/alert/{alert_id}")
async def alert_deep_dive(
    alert_id: int,
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    """
    Deep dive on a single alert:
    includes linked log entry, TI enrichment, behavior, and incident context.
    """
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Alert not found")

    # Linked log entry
    log_data = None
    if alert.log_entry_id:
        log_result = await db.execute(
            select(LogEntry).where(LogEntry.id == alert.log_entry_id)
        )
        log = log_result.scalar_one_or_none()
        if log:
            log_data = {
                "id": log.id, "timestamp": log.timestamp,
                "event_type": log.event_type, "severity": log.severity.value,
                "protocol": log.protocol.value if log.protocol else None,
                "source_port": log.source_port,
                "destination_ip": log.destination_ip,
                "destination_port": log.destination_port,
                "message": log.message, "raw_log": log.raw_log,
                "bytes_sent": log.bytes_sent, "bytes_received": log.bytes_received,
                "username": log.username,
            }

    # Incident context
    incident_data = None
    if alert.incident_id:
        inc_result = await db.execute(
            select(Incident).where(Incident.id == alert.incident_id)
        )
        inc = inc_result.scalar_one_or_none()
        if inc:
            incident_data = {
                "id": inc.id, "title": inc.title, "severity": inc.severity.value,
                "status": inc.status.value, "alert_count": inc.alert_count,
                "risk_score": inc.risk_score, "first_seen": inc.first_seen,
            }

    # TI
    ti_data = {}
    if alert.source_ip:
        ti = await threat_intel_service.lookup(alert.source_ip, db)
        ti_data = {
            "country": ti.country_name, "city": ti.city, "isp": ti.isp,
            "is_tor_exit": ti.is_tor_exit, "is_proxy": ti.is_proxy,
            "reputation_score": ti.reputation_score,
            "threat_categories": ti.threat_categories,
        }

    return {
        "alert": {
            "id": alert.id, "title": alert.title,
            "description": alert.description,
            "severity": alert.severity.value,
            "status": alert.status.value,
            "source_ip": alert.source_ip,
            "rule_name": alert.rule_name,
            "attack_type": alert.attack_type,
            "risk_score": alert.risk_score,
            "anomaly_score": alert.anomaly_score,
            "behavior_score": alert.behavior_score,
            "kill_chain_phase": alert.kill_chain_phase,
            "mitre_ttps": alert.mitre_ttps,
            "false_positive_likelihood": alert.false_positive_likelihood,
            "llm_explanation": alert.llm_explanation,
            "mitigation_steps": alert.mitigation_steps,
            "triggered_at": alert.triggered_at,
        },
        "log_entry":      log_data,
        "incident":       incident_data,
        "threat_intel":   ti_data,
    }
