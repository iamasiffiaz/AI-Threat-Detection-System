"""
Platform settings for SOC Platform 2.0 configuration.
"""
from datetime import datetime, timezone
from sqlalchemy import String, Integer, Float, DateTime, Text, Boolean
from sqlalchemy.orm import Mapped, mapped_column
from app.core.database import Base


class PlatformSettings(Base):
    __tablename__ = "platform_settings"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    organization_name: Mapped[str] = mapped_column(String(200), default="AI SOC Platform", nullable=False)
    default_role: Mapped[str] = mapped_column(String(50), default="soc_analyst", nullable=False)
    ai_provider: Mapped[str] = mapped_column(String(50), default="ollama", nullable=False)
    api_key_placeholder: Mapped[str] = mapped_column(String(255), default="", nullable=True)
    threat_feed_refresh_interval: Mapped[int] = mapped_column(Integer, default=60, nullable=False)
    severity_threshold: Mapped[float] = mapped_column(Float, default=40.0, nullable=False)
    mitre_mapping_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    pdf_reports_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    audit_logging_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    extra_json: Mapped[str] = mapped_column(Text, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
