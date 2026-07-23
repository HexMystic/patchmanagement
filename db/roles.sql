-- ---------------------------------------------------------------------------
-- Restricted application role — DEV bootstrap.
--
-- The RlsAndRoles migration CREATEs this role (LOGIN, no password) and applies
-- grants + RLS. This script only PROVISIONS THE DEV PASSWORD so the app can
-- connect locally. In production the password is provisioned out-of-band (a
-- secret manager / DBA) and this file is NOT used — no secret belongs in the repo
-- beyond a throwaway local-dev value.
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
