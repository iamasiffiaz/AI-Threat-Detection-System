"""
Analyst notes API.
"""
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import get_db, get_current_user
from app.models.user import User
from app.models.analyst_note import AnalystNote, NoteType
from app.services.timeline_service import timeline_service

router = APIRouter(prefix="/api/v1/analyst-notes", tags=["Analyst Notes"])


class NoteCreate(BaseModel):
    alert_id: Optional[int] = None
    incident_id: Optional[int] = None
    analyst_name: str = Field(..., min_length=1, max_length=100)
    note_text: str = Field(..., min_length=1, max_length=10_000)
    note_type: NoteType = NoteType.OBSERVATION


class NoteUpdate(BaseModel):
    note_text: Optional[str] = Field(None, min_length=1, max_length=10_000)
    note_type: Optional[NoteType] = None
    analyst_name: Optional[str] = Field(None, min_length=1, max_length=100)


def _ser(n: AnalystNote) -> dict:
    return {
        "id": n.id,
        "alert_id": n.alert_id,
        "incident_id": n.incident_id,
        "analyst_name": n.analyst_name,
        "note_text": n.note_text,
        "note_type": n.note_type.value if n.note_type else None,
        "created_at": n.created_at.isoformat() if n.created_at else None,
        "updated_at": n.updated_at.isoformat() if n.updated_at else None,
    }


@router.get("")
async def list_notes(
    alert_id: Optional[int] = None,
    incident_id: Optional[int] = None,
    note_type: Optional[str] = None,
    limit: int = Query(100, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    stmt = select(AnalystNote).order_by(desc(AnalystNote.created_at)).limit(limit)
    if alert_id:
        stmt = stmt.where(AnalystNote.alert_id == alert_id)
    if incident_id:
        stmt = stmt.where(AnalystNote.incident_id == incident_id)
    if note_type:
        try:
            stmt = stmt.where(AnalystNote.note_type == NoteType(note_type))
        except ValueError:
            raise HTTPException(400, f"Invalid note_type: {note_type}")
    rows = (await db.execute(stmt)).scalars().all()
    return [_ser(r) for r in rows]


@router.post("")
async def create_note(
    body: NoteCreate,
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    if not body.alert_id and not body.incident_id:
        raise HTTPException(400, "alert_id or incident_id required")
    note = AnalystNote(
        alert_id=body.alert_id,
        incident_id=body.incident_id,
        analyst_name=body.analyst_name,
        note_text=body.note_text,
        note_type=body.note_type,
    )
    db.add(note)
    await db.flush()
    if body.incident_id:
        await timeline_service.add_timeline_event(
            db, body.incident_id,
            event_type="analyst_note",
            title=f"Analyst note ({body.note_type.value}): {body.analyst_name}",
            description=body.note_text[:500],
            source="analyst",
        )
    await db.commit()
    await db.refresh(note)
    return _ser(note)


@router.put("/{note_id}")
async def update_note(
    note_id: int,
    body: NoteUpdate,
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    note = (await db.execute(select(AnalystNote).where(AnalystNote.id == note_id))).scalar_one_or_none()
    if not note:
        raise HTTPException(404, "Note not found")
    if body.note_text is not None:
        note.note_text = body.note_text
    if body.note_type is not None:
        note.note_type = body.note_type
    if body.analyst_name is not None:
        note.analyst_name = body.analyst_name
    note.updated_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(note)
    return _ser(note)


@router.delete("/{note_id}")
async def delete_note(
    note_id: int,
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    note = (await db.execute(select(AnalystNote).where(AnalystNote.id == note_id))).scalar_one_or_none()
    if not note:
        raise HTTPException(404, "Note not found")
    await db.delete(note)
    await db.commit()
    return {"deleted": note_id}
