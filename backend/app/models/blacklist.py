"""
IP Blacklist model: stores blocked IPs with SOAR action metadata.
Acts as the enforcement layer for the automated response system.
"""
from datetime import datetime, timezone
from sqlalchemy import String, Integer, Float, DateTime, Text, Boolean, Index
from sqlalchemy.orm import Mapped, mapped_column
from app.core.database import Base


class IPBlacklist(Base):
    __tablename__ = "ip_blacklist"

    id:         Mapped[int] = mapped_column(primary_key=True, index=True)
    ip_address: Mapped[str] = mapped_column(String(45), unique=True, index=True, nullable=False)

    # Reason for block
    reason:        Mapped[str] = mapped_column(Text, nullable=False)
    attack_types:  Mapped[str] = mapped_column(Text, nullable=True)   # JSON list
    rule_names:    Mapped[str] = mapped_column(Text, nullable=True)   # JSON list

    # Risk at time of block
    risk_score:       Mapped[float] = mapped_column(Float, nullable=True)
    alert_count:      Mapped[int]   = mapped_column(Integer, default=1, nullable=False)
    incident_id:      Mapped[int]   = mapped_column(Integer, nullable=True)

    # Block metadata
    added_by:    Mapped[str]  = mapped_column(String(100), default="auto", nullable=False)
    is_active:   Mapped[bool] = mapped_column(Boolean, default=True, index=True, nullable=False)
    expires_at:  Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)
    notes:       Mapped[str]  = mapped_column(Text, nullable=True)

    # Counters
    block_hits:  Mapped[int] = mapped_column(Integer, default=0, nullable=False)  # how many times blocked traffic hit

    # Timestamps
    created_at:  Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True, nullable=False)
    unblocked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        Index("ix_blacklist_active_ip", "is_active", "ip_address"),
    )

    def __repr__(self) -> str:
        return f"<IPBlacklist(ip={self.ip_address}, active={self.is_active}, risk={self.risk_score})>"
