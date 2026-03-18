-- ARGUS PostgreSQL init script
-- Runs on first container start (docker-entrypoint-initdb.d).
-- Creates database, extensions, RLS defaults, and migration user privileges.
--
-- Note: When using POSTGRES_DB=argus, the database is created by the image.
-- This script ensures argus exists when run standalone or with different config.

-- Switch to postgres to create argus if needed (scripts run in POSTGRES_DB by default)
\connect postgres

SELECT 'CREATE DATABASE argus OWNER argus'
WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'argus')\gexec

\connect argus

-- Extensions (pgvector for future RAG/embeddings)
CREATE EXTENSION IF NOT EXISTS vector;

-- RLS: enforce row-level security at database level (defense in depth)
-- Tables enable RLS in Alembic migrations; this ensures it cannot be bypassed
ALTER DATABASE argus SET row_security = on;

-- Migration user privileges (must match POSTGRES_USER from .env)
-- Same user for app and Alembic migrations per project convention
GRANT CONNECT ON DATABASE argus TO argus;
GRANT USAGE, CREATE ON SCHEMA public TO argus;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO argus;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO argus;
GRANT ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public TO argus;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO argus;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO argus;
