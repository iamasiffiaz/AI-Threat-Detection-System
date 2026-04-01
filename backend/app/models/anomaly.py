"""
Anomaly model: stores ML detection results with feature vectors and scores.
"""
from datetime import datetime, timezone
from sqlalchemy import String, Integer, Float, DateTime, Text, ForeignKey, JSON
from sqlalchemy.orm import Mapped, mapped_column
from app.core.database import Base


class Anomaly(Base):
    __tablename__ = "anomalies"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)

    # Reference to the log entry that triggered this anomaly
    log_entry_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("log_entries.id", ondelete="CASCADE"), nullable=False, index=True
    )

    # ML model outputs
    anomaly_score: Mapped[float] = mapped_column(Float, nullable=False, index=True)
    model_name: Mapped[str] = mapped_column(String(50), nullable=False)

    # Feature vector used for detection (stored as JSON)
    feature_vector: Mapped[dict] = mapped_column(JSON, nullable=True)

    # Context
    source_ip: Mapped[str] = mapped_column(String(45), index=True, nullable=True)
    event_type: Mapped[str] = mapped_column(String(100), nullable=True)

    # Explanation
    explanation: Mapped[str] = mapped_column(Text, nullable=True)

    detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        index=True,
        nullable=False,
    )

    def __repr__(self) -> str:
        return f"<Anomaly(id={self.id}, score={self.anomaly_score:.3f}, ip={self.source_ip})>"
