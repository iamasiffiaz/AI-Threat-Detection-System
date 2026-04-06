"""
Threat Intelligence router.

Endpoints:
  GET  /api/v1/intelligence/ip/{ip}       Full TI lookup for an IP
  GET  /api/v1/intelligence/ip/{ip}/geo   GeoIP only
  POST /api/v1/intelligence/bulk          Bulk TI lookup (up to 50 IPs)
  GET  /api/v1/intelligence/top-threats   Top known-bad IPs seen in logs
"""
import logging
from typing import List, Optional, Dict, Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import get_db, get_current_user
from app.models.user import User
from app.models.threat_intel import ThreatIntelEntry
from app.services.threat_intel_service import threat_intel_service, ThreatIntelResult

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/intelligence", tags=["threat-intelligence"])


class TIResponse(BaseModel):
    ip_address:       str
    country_code:     str
    country_name:     str
    region:           str
    city:             str
    isp:              str
    asn:              str
    latitude:         float
    longitude:        float
    timezone_name:    str
    is_known_bad:     bool
    is_tor_exit:      bool
    is_proxy:         bool
    is_datacenter:    bool
    reputation_score: float
    threat_categories: List[str]
    abuse_confidence:  int
    source:           str
    cached:           bool


class BulkLookupRequest(BaseModel):
    ips: List[str]


class BulkLookupResponse(BaseModel):
    results: Dict[str, TIResponse]


def _result_to_response(r: ThreatIntelResult) -> TIResponse:
    return TIResponse(
        ip_address=r.ip_address,
        country_code=r.country_code,
        country_name=r.country_name,
        region=r.region,
        city=r.city,
        isp=r.isp,
        asn=r.asn,
        latitude=r.latitude,
        longitude=r.longitude,
        timezone_name=r.timezone_name,
        is_known_bad=r.is_known_bad,
        is_tor_exit=r.is_tor_exit,
        is_proxy=r.is_proxy,
        is_datacenter=r.is_datacenter,
        reputation_score=r.reputation_score,
        threat_categories=r.threat_categories,
        abuse_confidence=r.abuse_confidence,
        source=r.source,
        cached=r.cached,
    )


@router.get("/ip/{ip}", response_model=TIResponse)
async def lookup_ip(
    ip: str,
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    """Full threat intelligence lookup for a single IP address."""
    result = await threat_intel_service.lookup(ip, db)
    return _result_to_response(result)


@router.get("/ip/{ip}/geo")
async def geo_lookup(
    ip: str,
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    """Lightweight GeoIP only — country, city, coordinates."""
    result = await threat_intel_service.lookup(ip, db)
    return {
        "ip": result.ip_address,
        "country_code": result.country_code,
        "country_name": result.country_name,
        "city": result.city,
        "region": result.region,
        "latitude": result.latitude,
        "longitude": result.longitude,
        "isp": result.isp,
    }


@router.post("/bulk", response_model=BulkLookupResponse)
async def bulk_lookup(
    request: BulkLookupRequest,
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    """Bulk TI lookup — maximum 50 IPs per request."""
    if len(request.ips) > 50:
        raise HTTPException(status_code=400, detail="Maximum 50 IPs per bulk request")

    results = await threat_intel_service.bulk_lookup(request.ips, db)
    return BulkLookupResponse(
        results={ip: _result_to_response(r) for ip, r in results.items()}
    )


@router.get("/top-threats")
async def top_threat_ips(
    limit: int = Query(20, ge=1, le=100),
    min_reputation: float = Query(50.0, ge=0.0, le=100.0),
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    """IPs with highest reputation scores seen in our threat intel cache."""
    result = await db.execute(
        select(ThreatIntelEntry)
        .where(ThreatIntelEntry.reputation_score >= min_reputation)
        .order_by(desc(ThreatIntelEntry.reputation_score))
        .limit(limit)
    )
    entries = result.scalars().all()
    return [
        {
            "ip": e.ip_address,
            "country": e.country_name,
            "reputation_score": e.reputation_score,
            "is_known_bad": e.is_known_bad,
            "is_tor_exit": e.is_tor_exit,
            "isp": e.isp,
            "abuse_confidence": e.abuse_confidence,
            "fetched_at": e.fetched_at,
        }
        for e in entries
    ]
