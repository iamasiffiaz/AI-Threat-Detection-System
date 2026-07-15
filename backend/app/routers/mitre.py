"""
MITRE ATT&CK mapping API.
"""
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import get_db, get_current_user
from app.models.user import User
from app.models.alert import Alert
from app.models.incident import Incident
from app.models.mitre_mapping import MitreMapping
from app.services.mitre_mapping_service import mitre_mapping_service

router = APIRouter(prefix="/api/v1/mitre", tags=["MITRE ATT&CK"])


def _serialize(m: MitreMapping) -> dict:
    return {
        "id": m.id,
        "alert_id": m.alert_id,
        "incident_id": m.incident_id,
        "tactic": m.tactic,
        "technique_id": m.technique_id,
        "technique_name": m.technique_name,
        "confidence": m.confidence,
        "reasoning": m.reasoning,
        "created_at": m.created_at.isoformat() if m.created_at else None,
    }


@router.get("/mappings")
async def list_mappings(
    alert_id: Optional[int] = None,
    incident_id: Optional[int] = None,
    limit: int = Query(100, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    stmt = select(MitreMapping).order_by(desc(MitreMapping.created_at)).limit(limit)
    if alert_id:
        stmt = stmt.where(MitreMapping.alert_id == alert_id)
    if incident_id:
        stmt = stmt.where(MitreMapping.incident_id == incident_id)
    rows = (await db.execute(stmt)).scalars().all()
    return [_serialize(r) for r in rows]


@router.post("/map-alert/{alert_id}")
async def map_alert(
    alert_id: int,
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    alert = (await db.execute(select(Alert).where(Alert.id == alert_id))).scalar_one_or_none()
    if not alert:
        raise HTTPException(404, "Alert not found")

    mappings = mitre_mapping_service.map_alert_to_mitre({
        "title": alert.title,
        "description": alert.description,
        "attack_type": alert.attack_type,
        "rule_name": alert.rule_name,
        "alert_type": alert.alert_type.value if alert.alert_type else None,
    })
    rows = await mitre_mapping_service.persist_mappings(
        db, mappings, alert_id=alert_id, incident_id=alert.incident_id
    )
    await db.commit()
    return {
        "alert_id": alert_id,
        "mappings": [_serialize(r) for r in rows],
        "recommendations": mitre_mapping_service.generate_mitre_recommendations(mappings),
    }


@router.post("/map-incident/{incident_id}")
async def map_incident(
    incident_id: int,
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    incident = (await db.execute(select(Incident).where(Incident.id == incident_id))).scalar_one_or_none()
    if not incident:
        raise HTTPException(404, "Incident not found")

    alerts = (await db.execute(select(Alert).where(Alert.incident_id == incident_id))).scalars().all()
    all_mappings = []
    for alert in alerts:
        mapped = mitre_mapping_service.map_alert_to_mitre({
            "title": alert.title,
            "description": alert.description,
            "attack_type": alert.attack_type,
            "rule_name": alert.rule_name,
        })
        all_mappings.extend(mapped)

    all_mappings.extend(mitre_mapping_service.map_alert_to_mitre({
        "title": incident.title,
        "description": incident.description or "",
        "attack_type": incident.attack_types or "",
    }))

    seen = set()
    unique = []
    for m in all_mappings:
        if m["technique_id"] not in seen:
            seen.add(m["technique_id"])
            unique.append(m)

    rows = await mitre_mapping_service.persist_mappings(db, unique, incident_id=incident_id)
    await db.commit()
    summary = await mitre_mapping_service.get_mitre_tactics_summary(db, incident_id)
    return {
        "incident_id": incident_id,
        "mappings": [_serialize(r) for r in rows],
        "summary": summary,
        "recommendations": mitre_mapping_service.generate_mitre_recommendations(unique),
    }


@router.get("/incident/{incident_id}")
async def get_incident_mitre(
    incident_id: int,
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    summary = await mitre_mapping_service.get_mitre_tactics_summary(db, incident_id)
    summary["recommendations"] = mitre_mapping_service.generate_mitre_recommendations(
        summary.get("techniques", [])
    )
    return summary
