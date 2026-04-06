"""
AI Threat Detection System — Enterprise SOC Platform
Entry point with startup/shutdown lifecycle, middleware, and router registration.
"""
import sys
if sys.platform == "win32":
    import asyncio
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

import logging
import time
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError

from app.core.config import settings
from app.core.database import create_tables, AsyncSessionLocal
from app.core.db_migrations import run_migrations
from app.ml.model_manager import model_manager
from app.services.cache_service import cache_service
from app.services.soar_service import soar_service
from app.services.threat_intel_service import threat_intel_service
from app.services.event_viewer_service import event_viewer_service
from app.routers import auth, logs, alerts, anomalies, dashboard, websocket
from app.routers import incidents, intelligence, investigation, soar, soc_assistant
from app.routers import event_viewer

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
        from app.core.database import engine
        await run_migrations(engine)
        logger.info("Database schema migrations applied")
    except Exception as e:
        logger.error(f"Database migration failed: {e}")
        # Fallback to basic create_all
        try:
            await create_tables()
        except Exception as e2:
            logger.error(f"Database initialization failed: {e2}")

    # Connect Redis
    try:
        await cache_service.connect()
        if cache_service.available:
            logger.info("Redis cache connected — rule engine state persistence enabled")
        else:
            logger.warning("Redis unavailable — rule engine will use in-memory state only")
    except Exception as e:
        logger.error(f"Redis connection failed: {e}")

    # Initialize ML model
    try:
        loaded = await model_manager.initialize()
        logger.info("ML model manager initialized")

        # Auto-train from DB if no saved model or model is stale
        if not loaded:
            logger.info("Auto-training anomaly model from DB logs …")
            async with AsyncSessionLocal() as session:
                result = await model_manager.auto_train_from_db(session)
                logger.info(f"Auto-train result: {result.get('status')} — {result.get('training_samples', 0)} samples")
    except Exception as e:
        logger.error(f"ML model initialization failed: {e}")

    # Load SOAR blacklist into Redis for O(1) block checks
    try:
        async with AsyncSessionLocal() as session:
            await soar_service.sync_blacklist_to_redis(session)
    except Exception as e:
        logger.warning(f"SOAR blacklist sync failed: {e}")

    # Auto-start Windows Event Viewer integration (Windows only)
    try:
        await event_viewer_service.start()
        if event_viewer_service._running:
            logger.info("Windows Event Viewer integration started — real-time threat feed active")
    except Exception as e:
        logger.warning(f"Event Viewer service could not start: {e}")

    logger.info("🚀 Enterprise SOC Platform ready — all subsystems initialized")

    yield  # Application runs here

    # Shutdown
    logger.info("Shutting down AI Threat Detection System")
    await event_viewer_service.stop()
    await cache_service.disconnect()
    await threat_intel_service.close()


# Initialize FastAPI application
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description=(
        "Enterprise AI-Powered SOC Platform with threat intelligence, correlation engine, "
        "incident management, SOAR automation, behavioral profiling, and LLM analysis."
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

app.include_router(auth.router,          prefix=API_PREFIX)
app.include_router(logs.router,          prefix=API_PREFIX)
app.include_router(alerts.router,        prefix=API_PREFIX)
app.include_router(anomalies.router,     prefix=API_PREFIX)
app.include_router(dashboard.router,     prefix=API_PREFIX)
app.include_router(websocket.router)      # WebSocket routes without version prefix

# Enterprise SOC routers
app.include_router(incidents.router)      # /api/v1/incidents (prefix embedded in router)
app.include_router(intelligence.router)   # /api/v1/intelligence
app.include_router(investigation.router)  # /api/v1/investigation
app.include_router(soar.router)           # /api/v1/soar
app.include_router(soc_assistant.router)  # /api/v1/soc-assistant
app.include_router(event_viewer.router)   # /api/v1/event-viewer


# --- Health & Status Endpoints ---

@app.get("/health", tags=["Health"])
async def health_check():
    """Basic liveness probe."""
    return {"status": "healthy", "version": settings.APP_VERSION}


@app.get("/api/v1/status", tags=["Health"])
async def system_status():
    """Detailed system status including all SOC subsystem availability."""
    from app.services.llm_service import llm_service
    return {
        "status":        "operational",
        "version":       settings.APP_VERSION,
        "environment":   settings.ENVIRONMENT,
        "platform":      "Enterprise SOC",
        "ml_model":      model_manager.get_model_info(),
        "llm_available": await llm_service.check_availability(),
        "redis_available":  cache_service.available,
        "subsystems": {
            "threat_intelligence":    True,
            "behavioral_profiling":   cache_service.available,
            "correlation_engine":     cache_service.available,
            "soar_automation":        True,
            "incident_management":    True,
            "risk_scoring":           True,
            "classification_engine":  True,
            "event_viewer":           event_viewer_service._running,
        },
        "event_viewer": event_viewer_service.get_status(),
    }
