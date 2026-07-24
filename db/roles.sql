-- ---------------------------------------------------------------------------
-- Restricted application roles — DEV bootstrap.
--
-- The migrations CREATE these roles (LOGIN, no password) and apply grants + RLS:
--   patchmgmt_app     (RlsAndRoles)      — the request path. Tenant tables: full
--                                          CRUD under RLS. Content catalogue:
--                                          SELECT only.
--   patchmgmt_content (ContentCatalogue) — Phase 5 content ingestion. Content
--                                          catalogue: SELECT/INSERT/UPDATE, no
--                                          DELETE. See ADR 0010.
--
-- This script only PROVISIONS THE DEV PASSWORDS so they can connect locally. In
-- production passwords are provisioned out-of-band (a secret manager / DBA) and
-- this file is NOT used — no secret belongs in the repo beyond a throwaway
-- local-dev value.
--
-- The CREATE ROLE guards are required, not defensive noise: roles are
-- CLUSTER-GLOBAL and outlive any single database, so an unguarded CREATE throws
-- 42710 ("role already exists") on the second run.
--
-- Apply (dev), after `dotnet ef database update`:
--   docker exec -e PGPASSWORD=patchmgmt patchmgmt-postgres \
--     psql -U patchmgmt -d patchmgmt -f - < db/roles.sql
-- ---------------------------------------------------------------------------

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'patchmgmt_app') THEN
        CREATE ROLE patchmgmt_app LOGIN;
    END IF;
END
$$;

ALTER ROLE patchmgmt_app WITH LOGIN PASSWORD 'patchmgmt_app_dev';

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'patchmgmt_content') THEN
        CREATE ROLE patchmgmt_content LOGIN;
    END IF;
END
$$;

ALTER ROLE patchmgmt_content WITH LOGIN PASSWORD 'patchmgmt_content_dev';
