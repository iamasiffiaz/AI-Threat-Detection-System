"""
Threat Intelligence cache model.
Stores GeoIP data and IP reputation scores fetched from external sources.
Cached in PostgreSQL to reduce API calls and provide history.
"""
from datetime import datetime, timezone
from sqlalchemy import String, Float, DateTime, Text, Boolean, Index
from sqlalchemy.orm import Mapped, mapped_column
from app.core.database import Base


class ThreatIntelEntry(Base):
    __tablename__ = "threat_intel"

    id:         Mapped[int] = mapped_column(primary_key=True, index=True)
    ip_address: Mapped[str] = mapped_column(String(45), unique=True, index=True, nullable=False)

    # GeoIP
    country_code: Mapped[str] = mapped_column(String(5),   nullable=True)
    country_name: Mapped[str] = mapped_column(String(100), nullable=True)
    region:       Mapped[str] = mapped_column(String(100), nullable=True)
    city:         Mapped[str] = mapped_column(String(100), nullable=True)
    isp:          Mapped[str] = mapped_column(String(200), nullable=True)
    asn:          Mapped[str] = mapped_column(String(50),  nullable=True)
    latitude:     Mapped[float] = mapped_column(Float, nullable=True)
    longitude:    Mapped[float] = mapped_column(Float, nullable=True)
    timezone_name: Mapped[str] = mapped_column(String(100), nullable=True)

    # Reputation
    is_known_bad:       Mapped[bool]  = mapped_column(Boolean, default=False, nullable=False)
    is_tor_exit:        Mapped[bool]  = mapped_column(Boolean, default=False, nullable=False)
    is_proxy:           Mapped[bool]  = mapped_column(Boolean, default=False, nullable=False)
    is_datacenter:      Mapped[bool]  = mapped_column(Boolean, default=False, nullable=False)
    reputation_score:   Mapped[float] = mapped_column(Float, default=0.0, nullable=False)  # 0-100, higher = more malicious
    threat_categories:  Mapped[str]   = mapped_column(Text, nullable=True)  # JSON list
    abuse_confidence:   Mapped[int]   = mapped_column(Float, default=0, nullable=False)    # 0-100 %
    total_reports:      Mapped[int]   = mapped_column(Float, default=0, nullable=False)

    # Source and freshness
    source:       Mapped[str]      = mapped_column(String(50), default="ip-api", nullable=False)
    fetched_at:   Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    expires_at:   Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        Index("ix_threat_intel_reputation", "reputation_score"),
        Index("ix_threat_intel_country", "country_code"),
    )

    def __repr__(self) -> str:
        return f"<ThreatIntel(ip={self.ip_address}, rep={self.reputation_score}, country={self.country_code})>"
