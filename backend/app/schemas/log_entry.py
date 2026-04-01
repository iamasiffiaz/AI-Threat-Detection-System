"""
Pydantic schemas for log entry ingestion and retrieval.
"""
from pydantic import BaseModel, Field, IPvAnyAddress
from typing import Optional, List
from datetime import datetime
from app.models.log_entry import Protocol, Severity


class LogEntryCreate(BaseModel):
    timestamp: datetime
    source_ip: str = Field(..., description="Source IP address")
    destination_ip: Optional[str] = None
    source_port: Optional[int] = Field(None, ge=0, le=65535)
    destination_port: Optional[int] = Field(None, ge=0, le=65535)
    protocol: Protocol = Protocol.OTHER
    event_type: str = Field(..., min_length=1, max_length=100)
    severity: Severity = Severity.INFO
    message: Optional[str] = None
    raw_log: Optional[str] = None
    bytes_sent: Optional[int] = Field(None, ge=0)
    bytes_received: Optional[int] = Field(None, ge=0)
    duration_ms: Optional[float] = Field(None, ge=0)
    user_agent: Optional[str] = Field(None, max_length=512)
    username: Optional[str] = Field(None, max_length=100)
    country_code: Optional[str] = Field(None, max_length=2)


class LogEntryResponse(BaseModel):
    id: int
    timestamp: datetime
    source_ip: str
    destination_ip: Optional[str]
    source_port: Optional[int]
    destination_port: Optional[int]
    protocol: Protocol
    event_type: str
    severity: Severity
    message: Optional[str]
    bytes_sent: Optional[int]
    bytes_received: Optional[int]
    duration_ms: Optional[float]
    username: Optional[str]
    country_code: Optional[str]
    ingested_at: datetime

    model_config = {"from_attributes": True}


class LogEntryBulkCreate(BaseModel):
    logs: List[LogEntryCreate] = Field(..., min_length=1, max_length=10000)


class LogQueryParams(BaseModel):
    page: int = Field(1, ge=1)
    page_size: int = Field(50, ge=1, le=500)
    severity: Optional[Severity] = None
    source_ip: Optional[str] = None
    event_type: Optional[str] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None


class LogStatistics(BaseModel):
    total_logs: int
    logs_last_hour: int
    logs_last_24h: int
    top_source_ips: List[dict]
    events_by_severity: dict
    events_by_protocol: dict
    traffic_timeline: List[dict]
