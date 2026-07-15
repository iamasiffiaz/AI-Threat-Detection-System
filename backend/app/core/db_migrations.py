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

_INCIDENT_COLUMNS = [
    "ALTER TABLE incidents ADD COLUMN IF NOT EXISTS affected_assets TEXT;",
    "ALTER TABLE incidents ADD COLUMN IF NOT EXISTS related_iocs TEXT;",
    "ALTER TABLE incidents ADD COLUMN IF NOT EXISTS closed_date TIMESTAMPTZ;",
    "ALTER TABLE incidents ADD COLUMN IF NOT EXISTS business_impact TEXT;",
]

_SOC_V2_COLUMNS = [
    "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS severity_reason TEXT;",
    "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS recommended_action TEXT;",
    "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS scoring_factors TEXT;",
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
    import app.models.threat_feed
    import app.models.extracted_ioc
    import app.models.mitre_mapping
    import app.models.analyst_note
    import app.models.incident_timeline
    import app.models.incident_report
    import app.models.platform_settings

    # Separate transactions so a single failed ALTER/CREATE INDEX cannot roll back create_all
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        logger.info("Schema create_all complete")

    async with engine.begin() as conn:
        for stmt in _ALERT_COLUMNS + _LOG_ENTRY_COLUMNS + _INCIDENT_COLUMNS + _SOC_V2_COLUMNS:
            try:
                await conn.execute(text(stmt))
            except Exception as exc:
                logger.debug("Migration stmt skipped (%s): %s", exc.__class__.__name__, stmt.strip())

    logger.info("Database migrations applied successfully")
