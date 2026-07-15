"""
Incident report generation API.
"""
import json
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import get_db, get_current_user
from app.models.user import User
from app.models.incident_report import IncidentReport
from app.services.report_service import report_service

router = APIRouter(prefix="/api/v1/reports", tags=["Reports"])


def _ser(r: IncidentReport) -> dict:
    data = {}
    try:
        data = json.loads(r.report_json) if r.report_json else {}
    except Exception:
        data = {}
    return {
        "id": r.id,
        "incident_id": r.incident_id,
        "title": r.title,
        "severity": r.severity,
        "risk_score": r.risk_score,
        "generated_by": r.generated_by,
        "created_at": r.created_at.isoformat() if r.created_at else None,
        "has_pdf": bool(r.pdf_path),
        "report": data,
    }


@router.post("/generate/{incident_id}")
async def generate_report(
    incident_id: int,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    try:
        report = await report_service.generate_report(
            db, incident_id, generated_by=user.username
        )
    except ValueError as e:
        raise HTTPException(404, str(e))
    return _ser(report)


@router.get("")
async def list_reports(
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    rows = (
        await db.execute(select(IncidentReport).order_by(desc(IncidentReport.created_at)).limit(100))
    ).scalars().all()
    return [_ser(r) for r in rows]


@router.get("/{report_id}")
async def get_report(
    report_id: int,
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    r = (await db.execute(select(IncidentReport).where(IncidentReport.id == report_id))).scalar_one_or_none()
    if not r:
        raise HTTPException(404, "Report not found")
    return _ser(r)


@router.get("/{report_id}/download")
async def download_report(
    report_id: int,
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    r = (await db.execute(select(IncidentReport).where(IncidentReport.id == report_id))).scalar_one_or_none()
    if not r:
        raise HTTPException(404, "Report not found")
    if not r.pdf_path or not Path(r.pdf_path).exists():
        raise HTTPException(404, "Report file not available")
    media = "application/pdf" if r.pdf_path.endswith(".pdf") else "text/html"
    return FileResponse(r.pdf_path, media_type=media, filename=Path(r.pdf_path).name)
