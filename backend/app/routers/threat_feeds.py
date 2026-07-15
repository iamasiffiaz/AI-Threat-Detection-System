"""
Threat feed ingestion API — manual IOC entry, CSV/JSON import, mock feeds.
Routes under /api/v1/threat-feeds (aliased concept: /api/threat-feeds).
"""
import csv
import io
import json
from datetime import datetime, timezone, timedelta
from typing import List, Optional

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile, status
from pydantic import BaseModel, Field
from sqlalchemy import select, desc, func, or_
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import get_db, get_current_user
from app.models.user import User
from app.models.threat_feed import ThreatFeedItem, IOCType, ThreatFeedSeverity

router = APIRouter(prefix="/api/v1/threat-feeds", tags=["Threat Feeds"])


class ManualIOCCreate(BaseModel):
    ioc_value: str = Field(..., min_length=1, max_length=512)
    ioc_type: IOCType
    source: str = Field(default="manual", max_length=150)
    confidence_score: float = Field(70.0, ge=0, le=100)
    threat_category: Optional[str] = Field(None, max_length=100)
    tags: Optional[List[str]] = None
    description: Optional[str] = Field(None, max_length=5000)
    severity: ThreatFeedSeverity = ThreatFeedSeverity.MEDIUM
    is_active: bool = True


class ThreatFeedResponse(BaseModel):
    id: int
    ioc_value: str
    ioc_type: str
    source: str
    confidence_score: float
    threat_category: Optional[str]
    first_seen: datetime
    last_seen: datetime
    tags: Optional[list]
    description: Optional[str]
    severity: str
    is_active: bool
    created_at: datetime

    model_config = {"from_attributes": True}

    @classmethod
    def from_orm_safe(cls, item: ThreatFeedItem) -> "ThreatFeedResponse":
        tags = []
        if item.tags:
            try:
                tags = json.loads(item.tags)
            except Exception:
                tags = [item.tags]
        return cls(
            id=item.id,
            ioc_value=item.ioc_value,
            ioc_type=item.ioc_type.value if hasattr(item.ioc_type, "value") else str(item.ioc_type),
            source=item.source,
            confidence_score=item.confidence_score,
            threat_category=item.threat_category,
            first_seen=item.first_seen,
            last_seen=item.last_seen,
            tags=tags,
            description=item.description,
            severity=item.severity.value if hasattr(item.severity, "value") else str(item.severity),
            is_active=item.is_active,
            created_at=item.created_at,
        )


def _parse_ioc_type(raw: str) -> IOCType:
    mapping = {
        "ip": IOCType.IP, "ipv4": IOCType.IP, "ip_address": IOCType.IP,
        "domain": IOCType.DOMAIN, "url": IOCType.URL,
        "hash": IOCType.FILE_HASH, "file_hash": IOCType.FILE_HASH, "md5": IOCType.FILE_HASH,
        "sha1": IOCType.FILE_HASH, "sha256": IOCType.FILE_HASH,
        "email": IOCType.EMAIL, "cve": IOCType.CVE,
        "malware": IOCType.MALWARE_FAMILY, "malware_family": IOCType.MALWARE_FAMILY,
        "threat_actor": IOCType.THREAT_ACTOR, "actor": IOCType.THREAT_ACTOR,
    }
    return mapping.get((raw or "ip").lower().strip(), IOCType.IP)


def _parse_severity(raw: str) -> ThreatFeedSeverity:
    try:
        return ThreatFeedSeverity((raw or "medium").lower())
    except Exception:
        return ThreatFeedSeverity.MEDIUM


@router.get("", response_model=List[ThreatFeedResponse])
async def list_threat_feeds(
    q: Optional[str] = Query(None),
    ioc_type: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    source: Optional[str] = Query(None),
    is_active: Optional[bool] = Query(None),
    min_confidence: Optional[float] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    stmt = select(ThreatFeedItem).order_by(desc(ThreatFeedItem.created_at))
    if q:
        stmt = stmt.where(
            or_(
                ThreatFeedItem.ioc_value.ilike(f"%{q}%"),
                ThreatFeedItem.description.ilike(f"%{q}%"),
                ThreatFeedItem.tags.ilike(f"%{q}%"),
            )
        )
    if ioc_type:
        stmt = stmt.where(ThreatFeedItem.ioc_type == _parse_ioc_type(ioc_type))
    if severity:
        stmt = stmt.where(ThreatFeedItem.severity == _parse_severity(severity))
    if source:
        stmt = stmt.where(ThreatFeedItem.source.ilike(f"%{source}%"))
    if is_active is not None:
        stmt = stmt.where(ThreatFeedItem.is_active == is_active)
    if min_confidence is not None:
        stmt = stmt.where(ThreatFeedItem.confidence_score >= min_confidence)
    stmt = stmt.offset(offset).limit(limit)
    rows = (await db.execute(stmt)).scalars().all()
    return [ThreatFeedResponse.from_orm_safe(r) for r in rows]


@router.post("/manual", response_model=ThreatFeedResponse, status_code=status.HTTP_201_CREATED)
async def create_manual_ioc(
    body: ManualIOCCreate,
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    now = datetime.now(timezone.utc)
    item = ThreatFeedItem(
        ioc_value=body.ioc_value.strip(),
        ioc_type=body.ioc_type,
        source=body.source,
        confidence_score=body.confidence_score,
        threat_category=body.threat_category,
        tags=json.dumps(body.tags or []),
        description=body.description,
        severity=body.severity,
        is_active=body.is_active,
        first_seen=now,
        last_seen=now,
    )
    db.add(item)
    await db.commit()
    await db.refresh(item)
    return ThreatFeedResponse.from_orm_safe(item)


@router.post("/import")
async def import_threat_feed(
    file: Optional[UploadFile] = File(None),
    mock: bool = Query(False, description="Ingest a mock external threat feed"),
    payload: Optional[str] = Query(None, description="Optional raw JSON string"),
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    items_data = []
    source_name = "import"

    if mock:
        source_name = "mock_external_feed"
        now = datetime.now(timezone.utc)
        items_data = [
            {"ioc_value": "185.220.101.45", "ioc_type": "ip", "severity": "high", "confidence_score": 92, "threat_category": "tor_exit", "description": "Known malicious relay", "tags": ["tor", "c2"]},
            {"ioc_value": "malware-c2.evil.example", "ioc_type": "domain", "severity": "critical", "confidence_score": 95, "threat_category": "c2", "description": "Beacon domain", "tags": ["c2", "beacon"]},
            {"ioc_value": "http://phish.example/login", "ioc_type": "url", "severity": "high", "confidence_score": 88, "threat_category": "phishing", "description": "Credential harvest URL", "tags": ["phishing"]},
            {"ioc_value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "ioc_type": "file_hash", "severity": "medium", "confidence_score": 70, "threat_category": "malware", "description": "Sample hash", "tags": ["hash"]},
            {"ioc_value": "CVE-2024-21762", "ioc_type": "cve", "severity": "critical", "confidence_score": 90, "threat_category": "vuln", "description": "Actively exploited CVE", "tags": ["cve"]},
            {"ioc_value": "lockbit", "ioc_type": "malware_family", "severity": "critical", "confidence_score": 85, "threat_category": "ransomware", "description": "Ransomware family", "tags": ["ransomware"]},
            {"ioc_value": "apt29", "ioc_type": "threat_actor", "severity": "high", "confidence_score": 80, "threat_category": "apt", "description": "Threat actor alias", "tags": ["apt"]},
            {"ioc_value": "attacker@evil.example", "ioc_type": "email", "severity": "medium", "confidence_score": 75, "threat_category": "phishing", "description": "Malicious sender", "tags": ["email"]},
        ]
        for d in items_data:
            d["first_seen"] = (now - timedelta(days=3)).isoformat()
            d["last_seen"] = now.isoformat()
    elif file is not None:
        content = (await file.read()).decode("utf-8", errors="ignore")
        fname = (file.filename or "").lower()
        source_name = f"upload:{file.filename}"
        if fname.endswith(".json") or content.strip().startswith(("[", "{")):
            parsed = json.loads(content)
            items_data = parsed if isinstance(parsed, list) else parsed.get("iocs", parsed.get("indicators", [parsed]))
        else:
            reader = csv.DictReader(io.StringIO(content))
            items_data = list(reader)
    elif payload:
        source_name = "json_payload"
        parsed = json.loads(payload)
        items_data = parsed if isinstance(parsed, list) else [parsed]
    else:
        raise HTTPException(400, "Provide a file, payload, or mock=true")

    created = 0
    now = datetime.now(timezone.utc)
    for raw in items_data:
        if not isinstance(raw, dict):
            continue
        value = (raw.get("ioc_value") or raw.get("value") or raw.get("indicator") or "").strip()
        if not value:
            continue
        item = ThreatFeedItem(
            ioc_value=value,
            ioc_type=_parse_ioc_type(raw.get("ioc_type") or raw.get("type") or "ip"),
            source=raw.get("source") or source_name,
            confidence_score=float(raw.get("confidence_score") or raw.get("confidence") or 70),
            threat_category=raw.get("threat_category") or raw.get("category"),
            tags=json.dumps(raw.get("tags") or []),
            description=raw.get("description"),
            severity=_parse_severity(raw.get("severity") or "medium"),
            is_active=str(raw.get("is_active", True)).lower() not in ("false", "0", "no"),
            first_seen=now,
            last_seen=now,
        )
        db.add(item)
        created += 1

    await db.commit()
    return {"imported": created, "source": source_name}


@router.get("/{item_id}", response_model=ThreatFeedResponse)
async def get_threat_feed_item(
    item_id: int,
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    item = (await db.execute(select(ThreatFeedItem).where(ThreatFeedItem.id == item_id))).scalar_one_or_none()
    if not item:
        raise HTTPException(404, "Threat feed item not found")
    return ThreatFeedResponse.from_orm_safe(item)


@router.delete("/{item_id}")
async def delete_threat_feed_item(
    item_id: int,
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    item = (await db.execute(select(ThreatFeedItem).where(ThreatFeedItem.id == item_id))).scalar_one_or_none()
    if not item:
        raise HTTPException(404, "Threat feed item not found")
    await db.delete(item)
    await db.commit()
    return {"deleted": item_id}
