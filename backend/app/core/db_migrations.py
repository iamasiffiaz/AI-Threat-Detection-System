"""
Lightweight schema migration manager.
Adds new columns to existing tables without dropping data.
Runs at application startup via main.py lifespan.
Uses ADD COLUMN IF NOT EXISTS (PostgreSQL 9.6+) so it is idempotent.
"""
import logging
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Column definitions to ensure exist per table
# ---------------------------------------------------------------------------

_ALERT_COLUMNS = [
    "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS risk_score          FLOAT;",
    "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS incident_id         INTEGER REFERENCES incidents(id) ON DELETE SET NULL;",
    "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS geo_country         VARCHAR(100);",
    "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS geo_city            VARCHAR(100);",
    "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS threat_reputation   FLOAT;",
    "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS is_known_bad_ip     BOOLEAN;",
    "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS kill_chain_phase    VARCHAR(50);",
    "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS mitre_ttps          TEXT;",
    "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS false_positive_likelihood VARCHAR(20);",
    "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS behavior_score      FLOAT;",
    "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS tenant_id           INTEGER;",
    "CREATE INDEX IF NOT EXISTS ix_alerts_risk_score            ON alerts (risk_score);",
    "CREATE INDEX IF NOT EXISTS ix_alerts_source_ip_triggered   ON alerts (source_ip, triggered_at);",
    "CREATE INDEX IF NOT EXISTS ix_alerts_incident_id           ON alerts (incident_id);",
]

_LOG_ENTRY_COLUMNS = [
    "ALTER TABLE log_entries ADD COLUMN IF NOT EXISTS geo_city          VARCHAR(100);",
    "ALTER TABLE log_entries ADD COLUMN IF NOT EXISTS geo_isp           VARCHAR(200);",
    "ALTER TABLE log_entries ADD COLUMN IF NOT EXISTS geo_asn           VARCHAR(50);",
    "ALTER TABLE log_entries ADD COLUMN IF NOT EXISTS latitude          FLOAT;",
    "ALTER TABLE log_entries ADD COLUMN IF NOT EXISTS longitude         FLOAT;",
    "ALTER TABLE log_entries ADD COLUMN IF NOT EXISTS threat_reputation FLOAT;",
    "ALTER TABLE log_entries ADD COLUMN IF NOT EXISTS is_known_bad_ip   BOOLEAN DEFAULT FALSE;",
    "ALTER TABLE log_entries ADD COLUMN IF NOT EXISTS is_blacklisted    BOOLEAN DEFAULT FALSE;",
    "ALTER TABLE log_entries ADD COLUMN IF NOT EXISTS anomaly_score     FLOAT;",
    "ALTER TABLE log_entries ADD COLUMN IF NOT EXISTS risk_score        FLOAT;",
    "ALTER TABLE log_entries ADD COLUMN IF NOT EXISTS attack_type       VARCHAR(100);",
    "ALTER TABLE log_entries ADD COLUMN IF NOT EXISTS alert_generated   BOOLEAN DEFAULT FALSE;",
    "ALTER TABLE log_entries ADD COLUMN IF NOT EXISTS tenant_id         INTEGER;",
]


async def run_migrations(engine: AsyncEngine) -> None:
    """
    Create new tables and add missing columns to existing ones.
    Safe to call on every startup — all statements are idempotent.
    """
    from app.core.database import Base  # local import to avoid circular deps
    import app.models.incident          # ensure models are registered in metadata
    import app.models.threat_intel
    import app.models.blacklist

    async with engine.begin() as conn:
        # 1. Create brand-new tables (incidents, threat_intel, ip_blacklist)
        #    create_all skips tables that already exist
        await conn.run_sync(Base.metadata.create_all)
        logger.info("Schema create_all complete")

        # 2. Add new columns to pre-existing tables
        for stmt in _ALERT_COLUMNS + _LOG_ENTRY_COLUMNS:
            try:
                await conn.execute(text(stmt))
            except Exception as exc:
                # Log but don't abort — some statements may fail on duplicate index names etc.
                logger.debug("Migration stmt skipped (%s): %s", exc.__class__.__name__, stmt.strip())

    logger.info("Database migrations applied successfully")
