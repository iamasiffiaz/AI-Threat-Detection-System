"""
Logs router: ingestion endpoints (upload, stream, bulk), retrieval, and training trigger.
"""
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Query, status
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional
from datetime import datetime
from app.core.database import get_db
from app.core.dependencies import get_current_active_user, require_analyst_or_admin
from app.models.user import User
from app.models.log_entry import Severity
from app.schemas.log_entry import (
    LogEntryCreate, LogEntryResponse, LogEntryBulkCreate, LogStatistics
)
from app.services.log_service import log_service
from app.ml.model_manager import model_manager
from app.core.config import settings

router = APIRouter(prefix="/logs", tags=["Log Ingestion & Retrieval"])


@router.post("/stream", response_model=dict, status_code=status.HTTP_201_CREATED)
async def stream_log(
    log_data: LogEntryCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """
    Ingest a single log entry in real-time.
    Triggers ML scoring and rule evaluation immediately.
    """
    log_entry, score = await log_service.ingest_single(db, log_data)
    return {
        "id": log_entry.id,
        "anomaly_score": round(score, 4) if score else 0.0,
        "is_anomaly": score >= settings.ANOMALY_THRESHOLD if score else False,
        "timestamp": log_entry.timestamp.isoformat(),
    }


@router.post("/bulk", response_model=dict, status_code=status.HTTP_201_CREATED)
async def bulk_ingest(
    payload: LogEntryBulkCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """
    Batch ingest multiple log entries.
    More efficient than individual /stream calls for large batches.
    """
    result = await log_service.ingest_bulk(db, payload.logs)
    return result


@router.post("/upload", response_model=dict, status_code=status.HTTP_201_CREATED)
async def upload_logs(
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
):
    """
    Upload a log file (CSV, JSON, syslog) for ingestion.
    Maximum file size: configured via MAX_UPLOAD_SIZE_MB.
    """
    # Validate file extension
    filename = file.filename or ""
    ext = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if ext not in settings.ALLOWED_UPLOAD_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type. Allowed: {settings.ALLOWED_UPLOAD_EXTENSIONS}",
        )

    content = await file.read()
    max_bytes = settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024

    if len(content) > max_bytes:
        raise HTTPException(
            status_code=413,
            detail=f"File too large. Maximum size: {settings.MAX_UPLOAD_SIZE_MB}MB",
        )

    try:
        result = await log_service.parse_and_ingest_file(db, content, filename)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))

    return {"filename": filename, "file_size_bytes": len(content), **result}


@router.get("", response_model=dict)
async def get_logs(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    severity: Optional[Severity] = None,
    source_ip: Optional[str] = None,
    event_type: Optional[str] = None,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Retrieve paginated log entries with optional filters."""
    logs, total = await log_service.get_logs(
        db=db,
        page=page,
        page_size=page_size,
        severity=severity,
        source_ip=source_ip,
        event_type=event_type,
        start_time=start_time,
        end_time=end_time,
    )
    return {
        "items": [LogEntryResponse.model_validate(log) for log in logs],
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": (total + page_size - 1) // page_size,
    }


@router.get("/statistics", response_model=LogStatistics)
async def get_statistics(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Get aggregated log statistics for the dashboard."""
    return await log_service.get_statistics(db)


@router.post("/generate-sample", response_model=dict)
async def generate_sample_data(
    count: int = Query(100, ge=10, le=5000),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
):
    """
    Generate synthetic sample log data for testing and demonstration.
    Useful for populating the dashboard without real log sources.
    """
    result = await log_service.generate_sample_logs(db, count)
    return {"message": f"Generated {count} sample log entries", **result}


@router.post("/train-model", response_model=dict)
async def train_anomaly_model(
    force: bool = Query(False),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
):
    """
    Trigger ML model training on stored log data.
    Set force=true to retrain even if recently trained.
    """
    logs, _ = await log_service.get_logs(db=db, page=1, page_size=10000)
    log_dicts = [log_service._log_to_dict(log) for log in logs]
    result = await model_manager.train_model(log_dicts, force=force)
    return result
