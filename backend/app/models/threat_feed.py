"""
Threat intelligence feed / IOC registry model.
Stores ingested indicators from manual entry, CSV, JSON, and mock feeds.
"""
import enum
from datetime import datetime, timezone
from sqlalchemy import String, Integer, Float, DateTime, Enum as SAEnum, Text, Boolean, Index
from sqlalchemy.orm import Mapped, mapped_column
from app.core.database import Base


class IOCType(str, enum.Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    FILE_HASH = "file_hash"
    EMAIL = "email"
    CVE = "cve"
    MALWARE_FAMILY = "malware_family"
    THREAT_ACTOR = "threat_actor"


class ThreatFeedSeverity(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ThreatFeedItem(Base):
    __tablename__ = "threat_feed_items"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    ioc_value: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    ioc_type: Mapped[IOCType] = mapped_column(SAEnum(IOCType, native_enum=False), nullable=False, index=True)
    source: Mapped[str] = mapped_column(String(150), nullable=False, default="manual", index=True)
    confidence_score: Mapped[float] = mapped_column(Float, default=50.0, nullable=False)
    threat_category: Mapped[str] = mapped_column(String(100), nullable=True)
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    tags: Mapped[str] = mapped_column(Text, nullable=True)  # JSON list
    description: Mapped[str] = mapped_column(Text, nullable=True)
    severity: Mapped[ThreatFeedSeverity] = mapped_column(
        SAEnum(ThreatFeedSeverity, native_enum=False),
        default=ThreatFeedSeverity.MEDIUM,
        nullable=False,
        index=True,
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    __table_args__ = (
        Index("ix_threat_feed_value_type", "ioc_value", "ioc_type"),
    )

    def __repr__(self) -> str:
        return f"<ThreatFeedItem(id={self.id}, type={self.ioc_type}, value={self.ioc_value[:40]})>"
