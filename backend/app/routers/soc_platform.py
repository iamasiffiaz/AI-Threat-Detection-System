"""
Severity scoring, explanations, timeline, settings, and SOC dashboard extensions.
"""
import json
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select, func, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import get_db, get_current_user
from app.models.user import User
from app.models.alert import Alert, AlertSeverity, AlertStatus
from app.models.incident import Incident, IncidentStatus
from app.models.threat_feed import ThreatFeedItem
from app.models.mitre_mapping import MitreMapping
from app.models.extracted_ioc import ExtractedIOC
from app.models.platform_settings import PlatformSettings
from app.services.severity_scoring_service import severity_scoring_service
from app.services.incident_explanation_service import incident_explanation_service
from app.services.timeline_service import timeline_service
from app.services.mitre_mapping_service import mitre_mapping_service
from app.services.ioc_extraction_service import ioc_extraction_service

router = APIRouter(prefix="/api/v1/soc", tags=["SOC Platform 2.0"])


class SettingsUpdate(BaseModel):
    organization_name: Optional[str] = None
    default_role: Optional[str] = None
    ai_provider: Optional[str] = None
    api_key_placeholder: Optional[str] = None
    threat_feed_refresh_interval: Optional[int] = None
    severity_threshold: Optional[float] = None
    mitre_mapping_enabled: Optional[bool] = None
    pdf_reports_enabled: Optional[bool] = None
    audit_logging_enabled: Optional[bool] = None


@router.post("/severity/score-alert/{alert_id}")
async def score_alert(
    alert_id: int,
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    alert = (await db.execute(select(Alert).where(Alert.id == alert_id))).scalar_one_or_none()
    if not alert:
        raise HTTPException(404, "Alert not found")

    text = f"{alert.title}\n{alert.description}\n{alert.source_ip or ''}"
    iocs = ioc_extraction_service.extract_iocs_from_text(text)
    iocs = await ioc_extraction_service.enrich_iocs_with_feed_matches(iocs, db)
    mitre = mitre_mapping_service.map_alert_to_mitre({
        "title": alert.title,
        "description": alert.description,
        "attack_type": alert.attack_type,
        "rule_name": alert.rule_name,
    })
    result = severity_scoring_service.calculate_alert_severity(alert, iocs, mitre)
    fields = severity_scoring_service.to_alert_fields(result)
    alert.risk_score = fields["risk_score"]
    try:
        alert.severity = AlertSeverity(fields["severity"])
    except Exception:
        pass
    alert.severity_reason = fields["severity_reason"]
    alert.recommended_action = fields["recommended_action"]
    alert.scoring_factors = fields["scoring_factors"]
    await db.commit()
    return {
        "alert_id": alert_id,
        "risk_score": result.risk_score,
        "severity": result.severity,
        "severity_reason": result.severity_reason,
        "recommended_action": result.recommended_action,
        "scoring_factors": result.scoring_factors,
    }


@router.post("/explain/alert/{alert_id}")
async def explain_alert(
    alert_id: int,
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    alert = (await db.execute(select(Alert).where(Alert.id == alert_id))).scalar_one_or_none()
    if not alert:
        raise HTTPException(404, "Alert not found")
    text = f"{alert.title}\n{alert.description}"
    iocs = await ioc_extraction_service.enrich_iocs_with_feed_matches(
        ioc_extraction_service.extract_iocs_from_text(text), db
    )
    mitre = mitre_mapping_service.map_alert_to_mitre({
        "title": alert.title, "description": alert.description,
        "attack_type": alert.attack_type, "rule_name": alert.rule_name,
    })
    return await incident_explanation_service.explain_alert(alert, iocs, mitre)


@router.post("/explain/incident/{incident_id}")
async def explain_incident(
    incident_id: int,
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    incident = (await db.execute(select(Incident).where(Incident.id == incident_id))).scalar_one_or_none()
    if not incident:
        raise HTTPException(404, "Incident not found")
    alerts = (await db.execute(select(Alert).where(Alert.incident_id == incident_id))).scalars().all()
    iocs_rows = (await db.execute(select(ExtractedIOC).where(ExtractedIOC.incident_id == incident_id))).scalars().all()
    iocs = [{"ioc_type": i.ioc_type, "ioc_value": i.ioc_value, "feed_match": i.feed_match} for i in iocs_rows]
    mitre_rows = (await db.execute(select(MitreMapping).where(MitreMapping.incident_id == incident_id))).scalars().all()
    mitre = [{"tactic": m.tactic, "technique_id": m.technique_id, "technique_name": m.technique_name} for m in mitre_rows]
    timeline = await timeline_service.reconstruct_incident_timeline(db, incident_id)
    return await incident_explanation_service.explain_incident(
        incident, list(alerts), iocs, mitre, timeline.get("summary")
    )


@router.get("/timeline/{incident_id}")
async def get_timeline(
    incident_id: int,
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    return await timeline_service.reconstruct_incident_timeline(db, incident_id)


@router.post("/timeline/{incident_id}/reconstruct")
async def reconstruct_timeline(
    incident_id: int,
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    # Force rebuild by clearing sparse timelines is handled in service when <2 events
    return await timeline_service.reconstruct_incident_timeline(db, incident_id)


@router.get("/settings")
async def get_settings(
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    row = (await db.execute(select(PlatformSettings).limit(1))).scalar_one_or_none()
    if not row:
        row = PlatformSettings()
        db.add(row)
        await db.commit()
        await db.refresh(row)
    return {
        "organization_name": row.organization_name,
        "default_role": row.default_role,
        "ai_provider": row.ai_provider,
        "api_key_placeholder": row.api_key_placeholder or "",
        "threat_feed_refresh_interval": row.threat_feed_refresh_interval,
        "severity_threshold": row.severity_threshold,
        "mitre_mapping_enabled": row.mitre_mapping_enabled,
        "pdf_reports_enabled": row.pdf_reports_enabled,
        "audit_logging_enabled": row.audit_logging_enabled,
    }


@router.put("/settings")
async def update_settings(
    body: SettingsUpdate,
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    row = (await db.execute(select(PlatformSettings).limit(1))).scalar_one_or_none()
    if not row:
        row = PlatformSettings()
        db.add(row)
    for k, v in body.model_dump(exclude_unset=True).items():
        setattr(row, k, v)
    await db.commit()
    await db.refresh(row)
    return await get_settings(db, _user)


@router.get("/dashboard-stats")
async def soc_dashboard_stats(
    role: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    total_alerts = (await db.execute(select(func.count(Alert.id)))).scalar() or 0
    critical_alerts = (await db.execute(
        select(func.count(Alert.id)).where(Alert.severity == AlertSeverity.CRITICAL)
    )).scalar() or 0
    open_alerts = (await db.execute(
        select(func.count(Alert.id)).where(Alert.status == AlertStatus.OPEN)
    )).scalar() or 0
    open_incidents = (await db.execute(
        select(func.count(Incident.id)).where(
            Incident.status.in_([IncidentStatus.OPEN, IncidentStatus.INVESTIGATING, IncidentStatus.CONTAINED])
        )
    )).scalar() or 0
    feed_count = (await db.execute(
        select(func.count(ThreatFeedItem.id)).where(ThreatFeedItem.is_active == True)  # noqa: E712
    )).scalar() or 0
    ioc_matches = (await db.execute(
        select(func.count(ExtractedIOC.id)).where(ExtractedIOC.feed_match == True)  # noqa: E712
    )).scalar() or 0
    avg_risk = (await db.execute(select(func.avg(Alert.risk_score)))).scalar() or 0
    mitre_tactics = (await db.execute(
        select(MitreMapping.tactic, func.count(MitreMapping.id)).group_by(MitreMapping.tactic)
    )).all()

    severity_dist = {}
    for sev in AlertSeverity:
        severity_dist[sev.value] = (await db.execute(
            select(func.count(Alert.id)).where(Alert.severity == sev)
        )).scalar() or 0

    status_dist = {}
    for st in IncidentStatus:
        status_dist[st.value] = (await db.execute(
            select(func.count(Incident.id)).where(Incident.status == st)
        )).scalar() or 0

    recent_iocs = (await db.execute(
        select(ExtractedIOC).order_by(desc(ExtractedIOC.created_at)).limit(10)
    )).scalars().all()

    ioc_types = (await db.execute(
        select(ExtractedIOC.ioc_type, func.count(ExtractedIOC.id)).group_by(ExtractedIOC.ioc_type)
    )).all()

    top_assets = (await db.execute(
        select(Alert.source_ip, func.count(Alert.id))
        .where(Alert.source_ip.isnot(None))
        .group_by(Alert.source_ip)
        .order_by(desc(func.count(Alert.id)))
        .limit(10)
    )).all()

    return {
        "role_view": role or getattr(_user.role, "value", str(_user.role)),
        "total_alerts": total_alerts,
        "critical_alerts": critical_alerts,
        "open_alerts": open_alerts,
        "open_incidents": open_incidents,
        "threat_feed_items": feed_count,
        "threat_feed_matches": ioc_matches,
        "average_risk_score": round(float(avg_risk or 0), 2),
        "mitre_tactics_detected": {t: c for t, c in mitre_tactics},
        "alert_severity_chart": severity_dist,
        "incident_status_chart": status_dist,
        "recent_ioc_matches": [
            {"id": i.id, "ioc_type": i.ioc_type, "ioc_value": i.ioc_value, "feed_match": i.feed_match}
            for i in recent_iocs
        ],
        "top_ioc_types": {t: c for t, c in ioc_types},
        "top_affected_assets": [{"asset": a, "alerts": c} for a, c in top_assets],
    }
