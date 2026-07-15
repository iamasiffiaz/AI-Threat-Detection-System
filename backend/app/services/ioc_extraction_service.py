"""
IOC Extraction Engine — defensive indicator extraction from text.
Extracts IPs, domains, URLs, hashes, emails, CVEs, and suspicious filenames.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.threat_feed import ThreatFeedItem


# Defensive regex patterns only — detection/analysis purpose
IP_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|co|ru|cn|xyz|top|info|biz|tk|ml|ga|cf|onion|example|local)\b",
    re.IGNORECASE,
)
URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
EMAIL_RE = re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b")
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
FILENAME_RE = re.compile(
    r"\b[\w\-]+\.(?:exe|dll|bat|ps1|vbs|js|scr|hta|msi|jar|docm|xlsm|pptm)\b",
    re.IGNORECASE,
)

MALWARE_KEYWORDS = {
    "emotet", "trickbot", "cobalt strike", "mimikatz", "ransomware",
    "lockbit", "ryuk", "wannacry", "agenttesla", "redline", "asyncrat",
    "metasploit", "powersploit", "bloodhound", "impacket",
}

PRIVATE_IP_PREFIXES = ("10.", "127.", "192.168.", "169.254.")


def _is_private_ip(ip: str) -> bool:
    if ip.startswith(PRIVATE_IP_PREFIXES):
        return True
    if ip.startswith("172."):
        try:
            second = int(ip.split(".")[1])
            return 16 <= second <= 31
        except Exception:
            return False
    return False


class IOCExtractionService:
    """Extract and enrich indicators of compromise from unstructured text."""

    def classify_ioc_type(self, value: str) -> str:
        v = value.strip()
        if CVE_RE.fullmatch(v):
            return "cve"
        if EMAIL_RE.fullmatch(v):
            return "email"
        if URL_RE.fullmatch(v) or v.lower().startswith(("http://", "https://")):
            return "url"
        if SHA256_RE.fullmatch(v):
            return "file_hash"
        if SHA1_RE.fullmatch(v):
            return "file_hash"
        if MD5_RE.fullmatch(v):
            return "file_hash"
        if IP_RE.fullmatch(v):
            return "ip"
        if FILENAME_RE.fullmatch(v):
            return "suspicious_filename"
        if v.lower() in MALWARE_KEYWORDS or any(k in v.lower() for k in MALWARE_KEYWORDS):
            return "malware_family"
        if DOMAIN_RE.fullmatch(v):
            return "domain"
        return "unknown"

    def normalize_ioc(self, value: str, ioc_type: Optional[str] = None) -> str:
        v = value.strip().strip(".,;:()[]{}\"'<>")
        itype = ioc_type or self.classify_ioc_type(v)
        if itype in ("domain", "email", "url", "malware_family", "cve"):
            return v.lower().rstrip("/")
        if itype == "file_hash":
            return v.lower()
        return v

    def extract_iocs_from_text(self, text: str) -> List[Dict[str, Any]]:
        if not text or not text.strip():
            return []

        found: List[Dict[str, Any]] = []
        hash_spans: List[tuple] = []

        def _add(value: str, ioc_type: str, span: tuple):
            start, end = span
            context = text[max(0, start - 40): min(len(text), end + 40)]
            found.append({
                "ioc_value": self.normalize_ioc(value, ioc_type),
                "ioc_type": ioc_type,
                "source_text": context.strip(),
                "raw_value": value,
            })

        for m in URL_RE.finditer(text):
            _add(m.group(0), "url", m.span())
        for m in EMAIL_RE.finditer(text):
            _add(m.group(0), "email", m.span())
        for m in CVE_RE.finditer(text):
            _add(m.group(0).upper(), "cve", m.span())
        for m in SHA256_RE.finditer(text):
            hash_spans.append(m.span())
            _add(m.group(0), "file_hash", m.span())
        for m in SHA1_RE.finditer(text):
            span = m.span()
            if any(span[0] >= hs[0] and span[1] <= hs[1] for hs in hash_spans):
                continue
            hash_spans.append(span)
            _add(m.group(0), "file_hash", span)
        for m in MD5_RE.finditer(text):
            span = m.span()
            if any(span[0] >= hs[0] and span[1] <= hs[1] for hs in hash_spans):
                continue
            hash_spans.append(span)
            _add(m.group(0), "file_hash", span)
        for m in IP_RE.finditer(text):
            ip = m.group(0)
            if not _is_private_ip(ip):
                _add(ip, "ip", m.span())
        for m in DOMAIN_RE.finditer(text):
            domain = m.group(0).lower()
            if any(domain in f["ioc_value"] for f in found if f["ioc_type"] in ("url", "email")):
                continue
            _add(domain, "domain", m.span())
        for m in FILENAME_RE.finditer(text):
            _add(m.group(0), "suspicious_filename", m.span())

        lower = text.lower()
        for kw in MALWARE_KEYWORDS:
            idx = lower.find(kw)
            if idx >= 0:
                _add(kw, "malware_family", (idx, idx + len(kw)))

        return self.deduplicate_iocs(found)

    def deduplicate_iocs(self, iocs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        seen = set()
        unique = []
        for ioc in iocs:
            key = (ioc.get("ioc_type"), ioc.get("ioc_value"))
            if key in seen or not ioc.get("ioc_value"):
                continue
            seen.add(key)
            unique.append(ioc)
        return unique

    async def enrich_iocs_with_feed_matches(
        self,
        iocs: List[Dict[str, Any]],
        db: AsyncSession,
    ) -> List[Dict[str, Any]]:
        if not iocs:
            return []

        values = [i["ioc_value"] for i in iocs]
        result = await db.execute(
            select(ThreatFeedItem).where(
                ThreatFeedItem.is_active == True,  # noqa: E712
                func.lower(ThreatFeedItem.ioc_value).in_([v.lower() for v in values]),
            )
        )
        feed_items = result.scalars().all()
        feed_map = {item.ioc_value.lower(): item for item in feed_items}

        enriched = []
        for ioc in iocs:
            match = feed_map.get(ioc["ioc_value"].lower())
            entry = dict(ioc)
            entry["feed_match"] = match is not None
            entry["feed_item_id"] = match.id if match else None
            entry["feed_source"] = match.source if match else None
            entry["feed_confidence"] = match.confidence_score if match else None
            entry["feed_severity"] = match.severity.value if match else None
            enriched.append(entry)
        return enriched


ioc_extraction_service = IOCExtractionService()
