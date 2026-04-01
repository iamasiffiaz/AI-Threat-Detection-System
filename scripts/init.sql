-- Database initialization script
-- Creates extensions and initial admin user will be created via API

-- Enable extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_stat_statements";

-- Log a note
DO $$
BEGIN
    RAISE NOTICE 'AI Threat Detection System database initialized';
END $$;
