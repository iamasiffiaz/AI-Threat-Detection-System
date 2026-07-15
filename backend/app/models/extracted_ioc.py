"""
Extracted IOC model — indicators pulled from logs, alerts, notes, and reports.
"""
from datetime import datetime, timezone
from sqlalchemy import String, Integer, Float, DateTime, Text, Boolean, ForeignKey, Index
from sqlalchemy.orm import Mapped, mapped_column
from app.core.database import Base


class ExtractedIOC(Base):
    __tablename__ = "extracted_iocs"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    ioc_value: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    ioc_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    source_text: Mapped[str] = mapped_column(Text, nullable=True)
    source_context: Mapped[str] = mapped_column(String(100), nullable=True)  # alert|incident|note|manual
    alert_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("alerts.id", ondelete="SET NULL"), nullable=True, index=True
    )
    incident_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True, index=True
    )
    feed_match: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    feed_item_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("threat_feed_items.id", ondelete="SET NULL"), nullable=True
    )
    confidence: Mapped[float] = mapped_column(Float, default=70.0, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    __table_args__ = (
        Index("ix_extracted_iocs_value_type", "ioc_value", "ioc_type"),
    )
