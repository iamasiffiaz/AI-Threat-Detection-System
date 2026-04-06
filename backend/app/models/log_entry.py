"""
Log entry model: normalized security log format stored in PostgreSQL.
Indexed for high-performance queries on timestamp, source_ip, and severity.
"""
import enum
from datetime import datetime, timezone
from sqlalchemy import String, Integer, Float, DateTime, Enum as SAEnum, Text, Index, Boolean
from sqlalchemy.orm import Mapped, mapped_column
from app.core.database import Base


class Protocol(str, enum.Enum):
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"
    HTTP = "HTTP"
    HTTPS = "HTTPS"
    DNS = "DNS"
    FTP = "FTP"
    SSH = "SSH"
    OTHER = "OTHER"


class Severity(str, enum.Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class LogEntry(Base):
    __tablename__ = "log_entries"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), index=True, nullable=False
    )
    source_ip: Mapped[str] = mapped_column(String(45), index=True, nullable=False)
    destination_ip: Mapped[str] = mapped_column(String(45), index=True, nullable=True)
    source_port: Mapped[int] = mapped_column(Integer, nullable=True)
    destination_port: Mapped[int] = mapped_column(Integer, nullable=True)
    protocol: Mapped[Protocol] = mapped_column(
        SAEnum(Protocol), default=Protocol.OTHER, nullable=False
    )
    event_type: Mapped[str] = mapped_column(String(100), index=True, nullable=False)
    severity: Mapped[Severity] = mapped_column(
        SAEnum(Severity), default=Severity.INFO, index=True, nullable=False
    )
    message: Mapped[str] = mapped_column(Text, nullable=True)
    raw_log: Mapped[str] = mapped_column(Text, nullable=True)
    bytes_sent: Mapped[int] = mapped_column(Integer, nullable=True)
    bytes_received: Mapped[int] = mapped_column(Integer, nullable=True)
    duration_ms: Mapped[float] = mapped_column(Float, nullable=True)
    user_agent: Mapped[str] = mapped_column(String(512), nullable=True)
    username: Mapped[str] = mapped_column(String(100), nullable=True)
    country_code: Mapped[str] = mapped_column(String(2), nullable=True)

    # Extended GeoIP fields
    geo_city: Mapped[str] = mapped_column(String(100), nullable=True)
    geo_isp:  Mapped[str] = mapped_column(String(200), nullable=True)
    geo_asn:  Mapped[str] = mapped_column(String(50),  nullable=True)
    latitude:  Mapped[float] = mapped_column(Float, nullable=True)
    longitude: Mapped[float] = mapped_column(Float, nullable=True)

    # Threat intelligence
    threat_reputation: Mapped[float] = mapped_column(Float, nullable=True)   # 0-100
    is_known_bad_ip:   Mapped[bool]  = mapped_column(Boolean, nullable=True, default=False)
    is_blacklisted:    Mapped[bool]  = mapped_column(Boolean, nullable=True, default=False)

    # ML / detection enrichment
    anomaly_score:  Mapped[float] = mapped_column(Float, nullable=True)   # from anomaly detector
    risk_score:     Mapped[float] = mapped_column(Float, nullable=True)   # composite 0-100
    attack_type:    Mapped[str]   = mapped_column(String(100), nullable=True)
    alert_generated: Mapped[bool] = mapped_column(Boolean, nullable=True, default=False)

    # Multi-tenant
    tenant_id: Mapped[int] = mapped_column(Integer, nullable=True, index=True)

    ingested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Composite indexes for common query patterns
    __table_args__ = (
        Index("ix_log_entries_timestamp_severity", "timestamp", "severity"),
        Index("ix_log_entries_source_ip_timestamp", "source_ip", "timestamp"),
        Index("ix_log_entries_event_type_timestamp", "event_type", "timestamp"),
    )

    def __repr__(self) -> str:
        return f"<LogEntry(id={self.id}, src={self.source_ip}, event={self.event_type})>"
