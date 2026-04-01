"""
Alert model: stores triggered security alerts from rule engine and ML anomaly detection.
"""
import enum
from datetime import datetime, timezone
from sqlalchemy import String, Integer, Float, DateTime, Enum as SAEnum, Text, Boolean, ForeignKey
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

    def __repr__(self) -> str:
        return f"<Alert(id={self.id}, severity={self.severity}, status={self.status})>"
