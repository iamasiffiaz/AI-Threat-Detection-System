"""
Threat Intelligence Service
============================
Provides GeoIP data and IP reputation scoring by:

1. ip-api.com  — free GeoIP + proxy/tor/hosting flags (45 req/min, no key needed)
2. AbuseIPDB   — abuse confidence score (requires ABUSEIPDB_API_KEY in .env, optional)
3. Internal mock dataset — hardcoded known-bad IPs (CISA KEV, common scanners)
4. Redis cache  — 1-hour TTL to minimise external API calls
5. PostgreSQL   — long-term cache & history

Returns a ThreatIntelResult dataclass consumed by risk_scoring_service.
"""
import json
import logging
import re
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from typing import Optional, List

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.threat_intel import ThreatIntelEntry
from app.services.cache_service import cache_service

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Known-bad IP mock dataset
# Contains ranges/IPs from major threat feeds (illustrative — real deployments
# should load from a file or live feed).
# ---------------------------------------------------------------------------
_KNOWN_BAD_IPS: set[str] = {
    # Common internet scanners / research orgs often abused
    "45.33.32.156", "198.20.69.74", "198.20.69.75",
    # Tor exit node examples
    "185.220.101.1", "185.220.101.2", "185.220.101.3",
    "185.220.102.4", "185.220.102.8",
    # Shodan / Censys scan sources
    "66.240.192.138", "66.240.236.119", "71.6.135.131",
    "80.82.77.33", "80.82.77.139", "93.174.95.106",
    # Known C2 infrastructure (illustrative)
    "91.92.109.75", "91.92.109.100",
    "194.165.16.11", "194.165.16.158",
    # Brute-force farms
    "45.142.212.100", "45.142.212.200",
    "179.43.128.10",  "179.43.129.10",
}

# Known-bad CIDR /24 prefixes (checked via prefix match)
_KNOWN_BAD_PREFIXES: list[str] = [
    "185.220.101.",   # Tor relays
    "185.220.102.",
    "194.165.16.",    # Known malicious hosting
    "45.142.212.",    # Brute-force farms
]

# Private / RFC1918 ranges — skip TI lookup
_PRIVATE_PREFIXES: tuple[str, ...] = (
    "10.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
    "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
    "172.30.", "172.31.",
    "192.168.", "127.", "::1", "fc", "fd",
)

_GEO_API_TIMEOUT = 5.0   # seconds


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass
class ThreatIntelResult:
    ip_address:       str
    country_code:     str = ""
    country_name:     str = ""
    region:           str = ""
    city:             str = ""
    isp:              str = ""
    asn:              str = ""
    latitude:         float = 0.0
    longitude:        float = 0.0
    timezone_name:    str = ""

    is_known_bad:     bool  = False
    is_tor_exit:      bool  = False
    is_proxy:         bool  = False
    is_datacenter:    bool  = False
    reputation_score: float = 0.0    # 0-100, higher = more malicious
    threat_categories: List[str] = field(default_factory=list)
    abuse_confidence:  int   = 0
    total_reports:     int   = 0

    source:           str = "unknown"
    cached:           bool = False


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------

class ThreatIntelService:

    def __init__(self):
        self._http: Optional[httpx.AsyncClient] = None

    @property
    def http(self) -> httpx.AsyncClient:
        if self._http is None or self._http.is_closed:
            self._http = httpx.AsyncClient(timeout=_GEO_API_TIMEOUT)
        return self._http

    async def close(self):
        if self._http and not self._http.is_closed:
            await self._http.aclose()

    # -----------------------------------------------------------------------
    # Public interface
    # -----------------------------------------------------------------------

    async def lookup(self, ip: str, db: AsyncSession) -> ThreatIntelResult:
        """
        Full TI lookup: Redis → PostgreSQL → external APIs → store results.
        Returns immediately for private/loopback IPs.
        """
        ip = ip.strip()

        if self._is_private(ip):
            return ThreatIntelResult(ip_address=ip, source="private", country_code="PRIVATE")

        # 1. Redis hot cache
        cached = await self._from_redis(ip)
        if cached:
            return cached

        # 2. PostgreSQL warm cache (< 1 h old)
        db_entry = await self._from_postgres(ip, db)
        if db_entry:
            result = self._model_to_result(db_entry)
            result.cached = True
            await self._to_redis(result)
            return result

        # 3. Fetch fresh data
        result = await self._fetch_fresh(ip)

        # 4. Persist
        await self._upsert_postgres(result, db)
        await self._to_redis(result)

        return result

    async def bulk_lookup(self, ips: List[str], db: AsyncSession) -> dict[str, ThreatIntelResult]:
        results = {}
        for ip in set(ips):
            try:
                results[ip] = await self.lookup(ip, db)
            except Exception as exc:
                logger.debug("TI lookup failed for %s: %s", ip, exc)
                results[ip] = ThreatIntelResult(ip_address=ip, source="error")
        return results

    def quick_reputation(self, ip: str) -> float:
        """
        Synchronous quick check against internal dataset only.
        Returns 0-100.  Used when async context is unavailable.
        """
        if self._is_private(ip):
            return 0.0
        if ip in _KNOWN_BAD_IPS:
            return 90.0
        for prefix in _KNOWN_BAD_PREFIXES:
            if ip.startswith(prefix):
                return 75.0
        return 0.0

    # -----------------------------------------------------------------------
    # Private helpers
    # -----------------------------------------------------------------------

    @staticmethod
    def _is_private(ip: str) -> bool:
        return any(ip.startswith(p) for p in _PRIVATE_PREFIXES)

    def _check_internal_dataset(self, ip: str) -> tuple[bool, float, list[str]]:
        """Returns (is_known_bad, reputation_score, threat_categories)."""
        cats: list[str] = []
        score = 0.0
        bad = False

        if ip in _KNOWN_BAD_IPS:
            bad = True
            score = 90.0
            cats.append("known_malicious")

        for prefix in _KNOWN_BAD_PREFIXES:
            if ip.startswith(prefix):
                bad = True
                score = max(score, 75.0)
                if "185.220" in ip:
                    cats.append("tor_exit")
                elif "45.142" in ip:
                    cats.append("bruteforce_farm")
                else:
                    cats.append("malicious_hosting")

        return bad, score, cats

    async def _from_redis(self, ip: str) -> Optional[ThreatIntelResult]:
        key = f"ti:{ip}"
        data = await cache_service.get(key)
        if data:
            try:
                d = json.loads(data) if isinstance(data, str) else data
                return ThreatIntelResult(**d, cached=True)
            except Exception:
                pass
        return None

    async def _to_redis(self, result: ThreatIntelResult):
        key = f"ti:{result.ip_address}"
        d = asdict(result)
        try:
            await cache_service.set(key, json.dumps(d), ttl=3600)
        except Exception:
            pass

    async def _from_postgres(self, ip: str, db: AsyncSession) -> Optional[ThreatIntelEntry]:
        cutoff = datetime.now(timezone.utc) - timedelta(hours=1)
        result = await db.execute(
            select(ThreatIntelEntry)
            .where(ThreatIntelEntry.ip_address == ip)
            .where(ThreatIntelEntry.fetched_at >= cutoff)
            .limit(1)
        )
        return result.scalar_one_or_none()

    async def _upsert_postgres(self, result: ThreatIntelResult, db: AsyncSession):
        try:
            existing = await db.execute(
                select(ThreatIntelEntry).where(ThreatIntelEntry.ip_address == result.ip_address)
            )
            entry = existing.scalar_one_or_none()

            if entry is None:
                entry = ThreatIntelEntry(ip_address=result.ip_address)
                db.add(entry)

            entry.country_code    = result.country_code
            entry.country_name    = result.country_name
            entry.region          = result.region
            entry.city            = result.city
            entry.isp             = result.isp
            entry.asn             = result.asn
            entry.latitude        = result.latitude
            entry.longitude       = result.longitude
            entry.timezone_name   = result.timezone_name
            entry.is_known_bad    = result.is_known_bad
            entry.is_tor_exit     = result.is_tor_exit
            entry.is_proxy        = result.is_proxy
            entry.is_datacenter   = result.is_datacenter
            entry.reputation_score = result.reputation_score
            entry.threat_categories = json.dumps(result.threat_categories)
            entry.abuse_confidence  = result.abuse_confidence
            entry.total_reports     = result.total_reports
            entry.source      = result.source
            entry.fetched_at  = datetime.now(timezone.utc)
            entry.expires_at  = datetime.now(timezone.utc) + timedelta(hours=1)

            await db.commit()
        except Exception as exc:
            await db.rollback()
            logger.debug("TI postgres upsert failed: %s", exc)

    @staticmethod
    def _model_to_result(entry: ThreatIntelEntry) -> ThreatIntelResult:
        cats = []
        if entry.threat_categories:
            try:
                cats = json.loads(entry.threat_categories)
            except Exception:
                cats = [entry.threat_categories]
        return ThreatIntelResult(
            ip_address=entry.ip_address,
            country_code=entry.country_code or "",
            country_name=entry.country_name or "",
            region=entry.region or "",
            city=entry.city or "",
            isp=entry.isp or "",
            asn=entry.asn or "",
            latitude=entry.latitude or 0.0,
            longitude=entry.longitude or 0.0,
            timezone_name=entry.timezone_name or "",
            is_known_bad=entry.is_known_bad,
            is_tor_exit=entry.is_tor_exit,
            is_proxy=entry.is_proxy,
            is_datacenter=entry.is_datacenter,
            reputation_score=entry.reputation_score,
            threat_categories=cats,
            abuse_confidence=int(entry.abuse_confidence or 0),
            total_reports=int(entry.total_reports or 0),
            source=entry.source or "db",
        )

    async def _fetch_fresh(self, ip: str) -> ThreatIntelResult:
        """Fetch from ip-api.com and merge with internal dataset."""
        # 1. Internal dataset (instant, no network)
        is_bad, rep_score, cats = self._check_internal_dataset(ip)
        is_tor = "tor_exit" in cats

        result = ThreatIntelResult(
            ip_address=ip,
            is_known_bad=is_bad,
            is_tor_exit=is_tor,
            reputation_score=rep_score,
            threat_categories=cats,
            source="internal",
        )

        # 2. ip-api.com GeoIP + proxy flags
        try:
            fields = "status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,proxy,hosting,query"
            resp = await self.http.get(
                f"http://ip-api.com/json/{ip}",
                params={"fields": fields},
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == "success":
                    result.country_code  = data.get("countryCode", "")
                    result.country_name  = data.get("country", "")
                    result.region        = data.get("regionName", "")
                    result.city          = data.get("city", "")
                    result.isp           = data.get("isp", "")
                    result.asn           = data.get("as", "")
                    result.latitude      = float(data.get("lat", 0))
                    result.longitude     = float(data.get("lon", 0))
                    result.timezone_name = data.get("timezone", "")
                    result.is_proxy      = bool(data.get("proxy", False))
                    result.is_datacenter = bool(data.get("hosting", False))
                    result.source        = "ip-api"

                    # Boost reputation for proxy/datacenter
                    if result.is_proxy:
                        result.reputation_score = max(result.reputation_score, 40.0)
                        if "proxy" not in result.threat_categories:
                            result.threat_categories.append("proxy")
                    if result.is_datacenter and not result.is_known_bad:
                        result.reputation_score = max(result.reputation_score, 20.0)
                        if "datacenter" not in result.threat_categories:
                            result.threat_categories.append("datacenter")
        except Exception as exc:
            logger.debug("ip-api lookup failed for %s: %s", ip, exc)

        # 3. AbuseIPDB (optional — only if API key is set)
        abuse_key = getattr(settings, "ABUSEIPDB_API_KEY", None)
        if abuse_key:
            try:
                resp = await self.http.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    params={"ipAddress": ip, "maxAgeInDays": 30},
                    headers={"Key": abuse_key, "Accept": "application/json"},
                )
                if resp.status_code == 200:
                    adata = resp.json().get("data", {})
                    result.abuse_confidence = adata.get("abuseConfidenceScore", 0)
                    result.total_reports    = adata.get("totalReports", 0)
                    result.source = "abuseipdb"
                    # Merge scores: weight AbuseIPDB heavily
                    if result.abuse_confidence > 0:
                        result.reputation_score = max(
                            result.reputation_score,
                            result.abuse_confidence * 0.85
                        )
                        if result.abuse_confidence >= 50:
                            result.is_known_bad = True
                            if "abuse_reported" not in result.threat_categories:
                                result.threat_categories.append("abuse_reported")
            except Exception as exc:
                logger.debug("AbuseIPDB lookup failed for %s: %s", ip, exc)

        return result


# Singleton
threat_intel_service = ThreatIntelService()
