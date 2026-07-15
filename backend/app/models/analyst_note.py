"""
Analyst notes for alerts and incidents.
"""
import enum
from datetime import datetime, timezone
from sqlalchemy import String, Integer, DateTime, Enum as SAEnum, Text, ForeignKey, Index
from sqlalchemy.orm import Mapped, mapped_column
from app.core.database import Base


class NoteType(str, enum.Enum):
    OBSERVATION = "Observation"
    ACTION_TAKEN = "Action Taken"
    ESCALATION = "Escalation"
    FALSE_POSITIVE = "False Positive"
    RECOMMENDATION = "Recommendation"


class AnalystNote(Base):
    __tablename__ = "analyst_notes"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    alert_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("alerts.id", ondelete="SET NULL"), nullable=True, index=True
    )
    incident_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True, index=True
    )
    analyst_name: Mapped[str] = mapped_column(String(100), nullable=False)
    note_text: Mapped[str] = mapped_column(Text, nullable=False)
    note_type: Mapped[NoteType] = mapped_column(
        SAEnum(NoteType, native_enum=False),
        default=NoteType.OBSERVATION,
        nullable=False,
        index=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    __table_args__ = (
        Index("ix_analyst_notes_alert_incident", "alert_id", "incident_id"),
    )
