"""
Incidents router — full CRUD for the Incident Management System.

Endpoints:
  GET    /api/v1/incidents                List incidents (filterable)
  GET    /api/v1/incidents/{id}           Incident detail
  PATCH  /api/v1/incidents/{id}           Update status / assignment
  GET    /api/v1/incidents/{id}/timeline  Ordered list of related alerts
  POST   /api/v1/incidents/{id}/escalate  Escalate severity
  DELETE /api/v1/incidents/{id}           Delete (admin only)
"""
import json
import logging
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import select, desc, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import get_db, get_current_user, require_admin
from app.models.incident import Incident, IncidentStatus, IncidentSeverity
from app.models.alert import Alert
from app.models.user import User
from app.schemas.alert import AlertResponse

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/incidents", tags=["incidents"])


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class IncidentResponse(BaseModel):
    id:            int
    title:         str
    description:   Optional[str]
    severity:      IncidentSeverity
    status:        IncidentStatus
    risk_score:    float
    alert_count:   int
    source_ip:     Optional[str]
    attack_types:  Optional[list]
    mitre_ttps:    Optional[str]
    kill_chain_phases: Optional[list]
    geo_country:   Optional[str]
    threat_reputation: Optional[float]
    is_known_bad_ip:   bool
    assigned_to:   Optional[str]
    llm_summary:   Optional[str]
    recommended_playbook: Optional[str]
    auto_actions_taken:  Optional[list]
    first_seen:    datetime
    last_seen:     datetime
    resolved_at:   Optional[datetime]
    model_config = {"from_attributes": True}

    @classmethod
    def from_orm_safe(cls, inc: Incident) -> "IncidentResponse":
        def _parse(val) -> Optional[list]:
            if not val:
                return []
            try:
                return json.loads(val)
            except Exception:
                return [val]
        return cls(
            id=inc.id,
            title=inc.title,
            description=inc.description,
            severity=inc.severity,
            status=inc.status,
            risk_score=inc.risk_score,
            alert_count=inc.alert_count,
            source_ip=inc.source_ip,
            attack_types=_parse(inc.attack_types),
            mitre_ttps=inc.mitre_ttps,
            kill_chain_phases=_parse(inc.kill_chain_phases),
            geo_country=inc.geo_country,
            threat_reputation=inc.threat_reputation,
            is_known_bad_ip=inc.is_known_bad_ip,
            assigned_to=inc.assigned_to,
            llm_summary=inc.llm_summary,
            recommended_playbook=inc.recommended_playbook,
            auto_actions_taken=_parse(inc.auto_actions_taken),
            first_seen=inc.first_seen,
            last_seen=inc.last_seen,
            resolved_at=inc.resolved_at,
        )


class IncidentUpdate(BaseModel):
    status:      Optional[IncidentStatus] = None
    assigned_to: Optional[str]            = None
    description: Optional[str]            = None
    notes:       Optional[str]            = None


class IncidentSummary(BaseModel):
    total:        int
    open:         int
    investigating: int
    resolved:     int
    critical:     int
    high:         int
    avg_risk_score: float


# ---------------------------------------------------------------------------
# List
# ---------------------------------------------------------------------------

@router.get("", response_model=List[IncidentResponse])
async def list_incidents(
    status:   Optional[IncidentStatus]   = Query(None),
    severity: Optional[IncidentSeverity] = Query(None),
    source_ip: Optional[str]             = Query(None),
    limit:    int = Query(50, ge=1, le=500),
    offset:   int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    q = select(Incident).order_by(desc(Incident.last_seen))
    if status:
        q = q.where(Incident.status == status)
    if severity:
        q = q.where(Incident.severity == severity)
    if source_ip:
        q = q.where(Incident.source_ip == source_ip)
    q = q.offset(offset).limit(limit)
    result = await db.execute(q)
    incidents = result.scalars().all()
    return [IncidentResponse.from_orm_safe(i) for i in incidents]


@router.get("/summary", response_model=IncidentSummary)
async def incidents_summary(
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    result = await db.execute(select(Incident))
    incidents = result.scalars().all()
    total      = len(incidents)
    open_inc   = sum(1 for i in incidents if i.status == IncidentStatus.OPEN)
    invest     = sum(1 for i in incidents if i.status == IncidentStatus.INVESTIGATING)
    resolved   = sum(1 for i in incidents if i.status == IncidentStatus.RESOLVED)
    critical   = sum(1 for i in incidents if i.severity == IncidentSeverity.CRITICAL)
    high       = sum(1 for i in incidents if i.severity == IncidentSeverity.HIGH)
    avg_risk   = round(sum(i.risk_score for i in incidents) / total, 2) if total else 0.0
    return IncidentSummary(
        total=total, open=open_inc, investigating=invest,
        resolved=resolved, critical=critical, high=high,
        avg_risk_score=avg_risk,
    )


# ---------------------------------------------------------------------------
# Detail
# ---------------------------------------------------------------------------

@router.get("/{incident_id}", response_model=IncidentResponse)
async def get_incident(
    incident_id: int,
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    inc = result.scalar_one_or_none()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    return IncidentResponse.from_orm_safe(inc)


@router.get("/{incident_id}/timeline", response_model=List[AlertResponse])
async def incident_timeline(
    incident_id: int,
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    """All alerts linked to this incident, ordered by time."""
    result = await db.execute(
        select(Alert)
        .where(Alert.incident_id == incident_id)
        .order_by(Alert.triggered_at)
    )
    return result.scalars().all()


# ---------------------------------------------------------------------------
# Update
# ---------------------------------------------------------------------------

@router.patch("/{incident_id}", response_model=IncidentResponse)
async def update_incident(
    incident_id: int,
    payload: IncidentUpdate,
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    inc = result.scalar_one_or_none()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")

    if payload.status is not None:
        inc.status = payload.status
        if payload.status == IncidentStatus.RESOLVED:
            inc.resolved_at = datetime.now(timezone.utc)

    if payload.assigned_to is not None:
        inc.assigned_to = payload.assigned_to
    if payload.description is not None:
        inc.description = payload.description

    await db.commit()
    await db.refresh(inc)
    return IncidentResponse.from_orm_safe(inc)


@router.post("/{incident_id}/escalate", response_model=IncidentResponse)
async def escalate_incident(
    incident_id: int,
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    """Escalate incident severity by one level."""
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    inc = result.scalar_one_or_none()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")

    order = [IncidentSeverity.LOW, IncidentSeverity.MEDIUM, IncidentSeverity.HIGH, IncidentSeverity.CRITICAL]
    current_idx = next((i for i, s in enumerate(order) if s == inc.severity), 0)
    if current_idx < len(order) - 1:
        inc.severity = order[current_idx + 1]

    inc.status = IncidentStatus.INVESTIGATING
    await db.commit()
    await db.refresh(inc)
    return IncidentResponse.from_orm_safe(inc)


@router.delete("/{incident_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_incident(
    incident_id: int,
    db: AsyncSession = Depends(get_db),
    _admin: User = Depends(require_admin),
):
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    inc = result.scalar_one_or_none()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    await db.delete(inc)
    await db.commit()
