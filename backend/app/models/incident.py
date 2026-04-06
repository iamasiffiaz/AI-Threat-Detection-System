"""
Incident model: aggregates multiple related alerts into a single tracked incident.
Core of the SOC incident management workflow.
"""
import enum
from datetime import datetime, timezone
from sqlalchemy import String, Integer, Float, DateTime, Enum as SAEnum, Text, Boolean, JSON, Index
from sqlalchemy.orm import Mapped, mapped_column
from app.core.database import Base


class IncidentStatus(str, enum.Enum):
    OPEN          = "open"
    INVESTIGATING = "investigating"
    CONTAINED     = "contained"
    RESOLVED      = "resolved"
    FALSE_POSITIVE = "false_positive"


class IncidentSeverity(str, enum.Enum):
    LOW      = "low"
    MEDIUM   = "medium"
    HIGH     = "high"
    CRITICAL = "critical"


class Incident(Base):
    __tablename__ = "incidents"

    id:    Mapped[int] = mapped_column(primary_key=True, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=True)

    # Classification
    severity:      Mapped[IncidentSeverity] = mapped_column(SAEnum(IncidentSeverity), index=True, nullable=False)
    status:        Mapped[IncidentStatus]   = mapped_column(SAEnum(IncidentStatus), default=IncidentStatus.OPEN, index=True, nullable=False)
    attack_types:  Mapped[str] = mapped_column(Text, nullable=True)   # JSON list of attack types
    mitre_ttps:    Mapped[str] = mapped_column(Text, nullable=True)   # JSON list of TTP IDs
    kill_chain_phases: Mapped[str] = mapped_column(Text, nullable=True)  # JSON list

    # Risk
    risk_score:  Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    alert_count: Mapped[int]   = mapped_column(Integer, default=0, nullable=False)
    alert_ids:   Mapped[str]   = mapped_column(Text, nullable=True)   # JSON list of alert IDs

    # Scope
    source_ips: Mapped[str] = mapped_column(Text, nullable=True)      # JSON list
    source_ip:  Mapped[str] = mapped_column(String(45), index=True, nullable=True)  # primary IP

    # Threat Intelligence
    geo_country:        Mapped[str]   = mapped_column(String(100), nullable=True)
    threat_reputation:  Mapped[float] = mapped_column(Float, nullable=True)
    is_known_bad_ip:    Mapped[bool]  = mapped_column(Boolean, default=False, nullable=False)

    # LLM-generated intelligence
    llm_summary:       Mapped[str] = mapped_column(Text, nullable=True)
    recommended_playbook: Mapped[str] = mapped_column(String(100), nullable=True)
    auto_actions_taken: Mapped[str] = mapped_column(Text, nullable=True)  # JSON list

    # Assignment
    assigned_to: Mapped[str] = mapped_column(String(100), nullable=True)
    tenant_id:   Mapped[int] = mapped_column(Integer, nullable=True, index=True)

    # Timeline
    first_seen:  Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True, nullable=False)
    last_seen:   Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    resolved_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        Index("ix_incidents_source_ip_first_seen", "source_ip", "first_seen"),
        Index("ix_incidents_status_severity", "status", "severity"),
    )

    def __repr__(self) -> str:
        return f"<Incident(id={self.id}, severity={self.severity}, status={self.status}, ip={self.source_ip})>"
