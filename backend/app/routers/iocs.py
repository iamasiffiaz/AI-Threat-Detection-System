"""
IOC extraction API with validation.
"""
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import get_db, get_current_user
from app.models.user import User
from app.models.extracted_ioc import ExtractedIOC
from app.services.ioc_extraction_service import ioc_extraction_service

router = APIRouter(prefix="/api/v1/iocs", tags=["IOC Extraction"])


class ExtractRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=200_000)
    alert_id: Optional[int] = None
    incident_id: Optional[int] = None
    persist: bool = False
    source_context: str = Field(default="manual", max_length=50)


@router.post("/extract")
async def extract_iocs(
    body: ExtractRequest,
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    text = body.text.strip()
    if not text:
        raise HTTPException(status_code=422, detail="text must not be empty")

    iocs = ioc_extraction_service.extract_iocs_from_text(text)
    enriched = await ioc_extraction_service.enrich_iocs_with_feed_matches(iocs, db)

    saved = []
    if body.persist:
        for ioc in enriched:
            row = ExtractedIOC(
                ioc_value=ioc["ioc_value"],
                ioc_type=ioc["ioc_type"],
                source_text=ioc.get("source_text"),
                source_context=body.source_context,
                alert_id=body.alert_id,
                incident_id=body.incident_id,
                feed_match=bool(ioc.get("feed_match")),
                feed_item_id=ioc.get("feed_item_id"),
                confidence=float(ioc.get("feed_confidence") or 70),
            )
            db.add(row)
            saved.append(row)
        await db.commit()
        for r in saved:
            await db.refresh(r)

    return {
        "count": len(enriched),
        "iocs": enriched,
        "persisted": len(saved),
        "status": "ok",
    }
