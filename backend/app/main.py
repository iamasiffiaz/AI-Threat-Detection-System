"""
AI Threat Detection System - Main FastAPI Application
Entry point with startup/shutdown lifecycle, middleware, and router registration.
"""
import logging
import time
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError

from app.core.config import settings
from app.core.database import create_tables
from app.ml.model_manager import model_manager
from app.routers import auth, logs, alerts, anomalies, dashboard, websocket

# Configure structured logging
logging.basicConfig(
    level=logging.DEBUG if settings.DEBUG else logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown lifecycle handler."""
    # Startup
    logger.info(f"Starting {settings.APP_NAME} v{settings.APP_VERSION}")
    logger.info(f"Environment: {settings.ENVIRONMENT}")

    try:
        await create_tables()
        logger.info("Database tables initialized")
    except Exception as e:
        logger.error(f"Database initialization failed: {e}")

    try:
        await model_manager.initialize()
        logger.info("ML model manager initialized")
    except Exception as e:
        logger.error(f"ML model initialization failed: {e}")

    yield  # Application runs here

    # Shutdown
    logger.info("Shutting down AI Threat Detection System")


# Initialize FastAPI application
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description=(
        "Production-ready AI-powered security threat detection system with "
        "ML anomaly detection, SIEM-style rules, and LLM threat explanation."
    ),
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
    lifespan=lifespan,
)

# --- Middleware ---

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(GZipMiddleware, minimum_size=1000)


@app.middleware("http")
async def request_timing_middleware(request: Request, call_next):
    """Log request timing and add performance headers."""
    start = time.perf_counter()
    response = await call_next(request)
    duration_ms = (time.perf_counter() - start) * 1000
    response.headers["X-Process-Time-Ms"] = f"{duration_ms:.2f}"

    if duration_ms > 1000:
        logger.warning(
            f"Slow request: {request.method} {request.url.path} took {duration_ms:.0f}ms"
        )

    return response


# --- Exception Handlers ---

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Return structured validation errors."""
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "detail": "Validation error",
            "errors": exc.errors(),
        },
    )


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Catch-all handler for unexpected errors in production."""
    logger.error(f"Unhandled exception on {request.method} {request.url}: {exc}", exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Internal server error"},
    )


# --- Routers ---

API_PREFIX = settings.API_V1_PREFIX

app.include_router(auth.router, prefix=API_PREFIX)
app.include_router(logs.router, prefix=API_PREFIX)
app.include_router(alerts.router, prefix=API_PREFIX)
app.include_router(anomalies.router, prefix=API_PREFIX)
app.include_router(dashboard.router, prefix=API_PREFIX)
app.include_router(websocket.router)  # WebSocket routes without version prefix


# --- Health & Status Endpoints ---

@app.get("/health", tags=["Health"])
async def health_check():
    """Basic liveness probe."""
    return {"status": "healthy", "version": settings.APP_VERSION}


@app.get("/api/v1/status", tags=["Health"])
async def system_status():
    """Detailed system status including model and LLM availability."""
    from app.services.llm_service import llm_service
    return {
        "status": "operational",
        "version": settings.APP_VERSION,
        "environment": settings.ENVIRONMENT,
        "ml_model": model_manager.get_model_info(),
        "llm_available": await llm_service.check_availability(),
    }
