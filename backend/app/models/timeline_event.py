"""
Re-export incident timeline model for consistent imports.
"""
from app.models.incident_timeline import IncidentTimelineEvent

__all__ = ["IncidentTimelineEvent"]
