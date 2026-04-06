"""
Alert model: stores triggered security alerts from rule engine and ML anomaly detection.
Extended with risk scoring, threat intelligence, and incident correlation fields.
"""
import enum
from datetime import datetime, timezone
from sqlalchemy import String, Integer, Float, DateTime, Enum as SAEnum, Text, Boolean, ForeignKey, Index
from sqlalchemy.orm import Mapped, mapped_column
from app.core.database import Base


class AlertSeverity(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertStatus(str, enum.Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class AlertType(str, enum.Enum):
    ANOMALY = "anomaly"
    RULE_BASED = "rule_based"
    HYBRID = "hybrid"


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[AlertSeverity] = mapped_column(
        SAEnum(AlertSeverity), index=True, nullable=False
    )
    alert_type: Mapped[AlertType] = mapped_column(
        SAEnum(AlertType), default=AlertType.RULE_BASED, nullable=False
    )
    status: Mapped[AlertStatus] = mapped_column(
        SAEnum(AlertStatus), default=AlertStatus.OPEN, index=True, nullable=False
    )

    # Related log entry
    log_entry_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("log_entries.id", ondelete="SET NULL"), nullable=True, index=True
    )

    # Source information
    source_ip: Mapped[str] = mapped_column(String(45), index=True, nullable=True)
    rule_name: Mapped[str] = mapped_column(String(100), nullable=True)

    # ML anomaly score (if applicable)
    anomaly_score: Mapped[float] = mapped_column(Float, nullable=True)

    # LLM-generated threat explanation
    llm_explanation: Mapped[str] = mapped_column(Text, nullable=True)
    attack_type: Mapped[str] = mapped_column(String(100), nullable=True)
    mitigation_steps: Mapped[str] = mapped_column(Text, nullable=True)

    # Risk scoring (0-100 composite score replacing binary severity)
    risk_score: Mapped[float] = mapped_column(Float, nullable=True, index=True)

    # Incident correlation — FK added after incidents table is created via migration
    incident_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True, index=True
    )

    # Threat intelligence enrichment
    geo_country:       Mapped[str]   = mapped_column(String(100), nullable=True)
    geo_city:          Mapped[str]   = mapped_column(String(100), nullable=True)
    threat_reputation: Mapped[float] = mapped_column(Float, nullable=True)   # 0-100
    is_known_bad_ip:   Mapped[bool]  = mapped_column(Boolean, nullable=True)

    # LLM kill-chain fields
    kill_chain_phase:          Mapped[str] = mapped_column(String(50), nullable=True)
    mitre_ttps:                Mapped[str] = mapped_column(Text, nullable=True)   # JSON
    false_positive_likelihood: Mapped[str] = mapped_column(String(20), nullable=True)

    # Behavioral deviation context
    behavior_score: Mapped[float] = mapped_column(Float, nullable=True)

    # Multi-tenant
    tenant_id: Mapped[int] = mapped_column(Integer, nullable=True, index=True)

    # Notification tracking
    notified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Timestamps
    triggered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        index=True,
        nullable=False,
    )
    resolved_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        Index("ix_alerts_risk_score", "risk_score"),
        Index("ix_alerts_source_ip_triggered", "source_ip", "triggered_at"),
    )

    def __repr__(self) -> str:
        return f"<Alert(id={self.id}, severity={self.severity}, risk={self.risk_score}, status={self.status})>"
