"""
SOAR router — automated response and IP management.

Endpoints:
  GET    /api/v1/soar/blacklist              List all blocked IPs
  POST   /api/v1/soar/blacklist              Manually block an IP
  DELETE /api/v1/soar/blacklist/{ip}         Unblock an IP
  GET    /api/v1/soar/blacklist/{ip}         Check if IP is blocked
  GET    /api/v1/soar/playbooks              All playbook templates
  GET    /api/v1/soar/playbooks/{attack}     Playbook for specific attack type
  POST   /api/v1/soar/respond/{alert_id}     Trigger manual SOAR response for alert
"""
import json
import logging
from datetime import datetime
from typing import List, Optional, Dict, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import get_db, get_current_user, require_admin
from app.models.blacklist import IPBlacklist
from app.models.alert import Alert
from app.models.user import User
from app.services.soar_service import soar_service

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/soar", tags=["soar"])


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class BlockIPRequest(BaseModel):
    ip_address:     str
    reason:         str
    attack_types:   Optional[List[str]] = None
    expires_in_hours: Optional[int]     = None
    notes:          Optional[str]       = None


class BlacklistEntry(BaseModel):
    id:           int
    ip_address:   str
    reason:       str
    attack_types: Optional[List[str]]
    risk_score:   Optional[float]
    added_by:     str
    is_active:    bool
    block_hits:   int
    expires_at:   Optional[datetime]
    created_at:   datetime

    @classmethod
    def from_model(cls, entry: IPBlacklist) -> "BlacklistEntry":
        def _parse(v):
            if not v:
                return []
            try:
                return json.loads(v)
            except Exception:
                return [v]
        return cls(
            id=entry.id,
            ip_address=entry.ip_address,
            reason=entry.reason,
            attack_types=_parse(entry.attack_types),
            risk_score=entry.risk_score,
            added_by=entry.added_by,
            is_active=entry.is_active,
            block_hits=entry.block_hits,
            expires_at=entry.expires_at,
            created_at=entry.created_at,
        )


# ---------------------------------------------------------------------------
# Blacklist CRUD
# ---------------------------------------------------------------------------

@router.get("/blacklist", response_model=List[BlacklistEntry])
async def list_blacklist(
    active_only: bool = Query(True),
    limit: int = Query(100, ge=1, le=1000),
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    q = select(IPBlacklist).order_by(desc(IPBlacklist.created_at)).limit(limit)
    if active_only:
        q = q.where(IPBlacklist.is_active == True)
    result = await db.execute(q)
    return [BlacklistEntry.from_model(e) for e in result.scalars().all()]


@router.get("/blacklist/{ip}")
async def check_blacklist(
    ip: str,
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    is_blocked = await soar_service.is_blocked(ip)
    entry = None
    if not is_blocked:
        # Fallback DB check (Redis may be cold)
        result = await db.execute(
            select(IPBlacklist).where(IPBlacklist.ip_address == ip, IPBlacklist.is_active == True)
        )
        entry_model = result.scalar_one_or_none()
        is_blocked = entry_model is not None
        if entry_model:
            entry = BlacklistEntry.from_model(entry_model)

    return {"ip": ip, "is_blocked": is_blocked, "entry": entry}


@router.post("/blacklist", response_model=BlacklistEntry, status_code=status.HTTP_201_CREATED)
async def block_ip(
    request: BlockIPRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    entry = await soar_service.block_ip(
        ip=request.ip_address,
        reason=request.reason,
        db=db,
        added_by=current_user.username,
        attack_types=request.attack_types,
        expires_in_hours=request.expires_in_hours,
        notes=request.notes,
    )
    return BlacklistEntry.from_model(entry)


@router.delete("/blacklist/{ip}", status_code=status.HTTP_204_NO_CONTENT)
async def unblock_ip(
    ip: str,
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    success = await soar_service.unblock_ip(ip, db)
    if not success:
        raise HTTPException(status_code=404, detail=f"IP {ip} not found in blacklist")


# ---------------------------------------------------------------------------
# Playbooks
# ---------------------------------------------------------------------------

@router.get("/playbooks")
async def list_playbooks(_user: User = Depends(get_current_user)):
    """All SOAR playbook templates."""
    playbooks = soar_service.get_all_playbooks()
    return {
        "count": len(playbooks),
        "playbooks": playbooks,
    }


@router.get("/playbooks/{attack_type:path}")
async def get_playbook(
    attack_type: str,
    _user: User = Depends(get_current_user),
):
    """Get the playbook for a specific attack type."""
    pb = soar_service.get_playbook(attack_type)
    return pb


# ---------------------------------------------------------------------------
# Manual SOAR trigger
# ---------------------------------------------------------------------------

@router.post("/respond/{alert_id}")
async def trigger_response(
    alert_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Manually trigger SOAR response for an alert."""
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    playbook_name = await soar_service.auto_respond(
        alert_data={
            "source_ip":   alert.source_ip,
            "risk_score":  alert.risk_score or 50.0,  # Force run even if below threshold
            "attack_type": alert.attack_type,
            "rule_name":   alert.rule_name,
        },
        db=db,
    )

    playbook = soar_service.get_playbook(alert.attack_type)

    return {
        "alert_id":       alert_id,
        "source_ip":      alert.source_ip,
        "playbook_name":  playbook_name or playbook.get("name"),
        "playbook_steps": playbook.get("steps", []),
        "auto_actions":   playbook.get("auto_actions", []),
        "sla_minutes":    playbook.get("sla_minutes"),
        "triggered_by":   current_user.username,
    }


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

@router.get("/stats")
async def soar_stats(
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    result = await db.execute(select(IPBlacklist))
    entries = result.scalars().all()
    total          = len(entries)
    active         = sum(1 for e in entries if e.is_active)
    total_hits     = sum(e.block_hits for e in entries)
    auto_blocked   = sum(1 for e in entries if e.added_by == "soar_auto")
    manual_blocked = total - auto_blocked
    return {
        "total_entries":    total,
        "active_blocks":    active,
        "total_block_hits": total_hits,
        "auto_blocked":     auto_blocked,
        "manual_blocked":   manual_blocked,
    }
