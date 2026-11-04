-- +goose Up
-- Database role model.
--
--   owner / migration role  the login that runs migrations. It owns every object and is the only
--                           role that performs DDL (including event_logs partition upkeep). It is
--                           provisioned by the operator and is not created here.
--   kut_app                 the application role: NOSUPERUSER, NOBYPASSRLS, no DDL. DML on the
--                           application tables only. Created NOLOGIN; the operator attaches a login
--                           and a password out of band (no credentials live in this file).
--   kut_admin               NOLOGIN role referenced by the row-level-security bypass policies.
--                           Created by the baseline and not altered here.
--
-- Table privileges are explicit. A table added by a later migration receives nothing for kut_app
-- until that migration grants it.

-- +goose StatementBegin
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'kut_app') THEN
        CREATE ROLE kut_app NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION;
    ELSIF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'kut_app' AND (rolsuper OR rolbypassrls)) THEN
        RAISE EXCEPTION 'role kut_app must be NOSUPERUSER and NOBYPASSRLS';
    END IF;
END
$$;
-- +goose StatementEnd

GRANT USAGE ON SCHEMA public TO kut_app;

GRANT SELECT, INSERT, UPDATE, DELETE ON
    devices, enrollment_tokens, agent_certificates, policies, policy_rules, device_policies,
    ota_releases, event_logs, event_ack, discovered_hosts, device_commands, artifacts,
    scim_users, cases, verify_checks, tokens, msp_customers, admins, pending_wipes,
    incidents, saved_searches
    TO kut_app;

-- Append-only tables: the application can add and read rows, never change or remove them.
GRANT SELECT, INSERT ON audit_log, evidence_custody TO kut_app;

-- +goose Down
REVOKE ALL ON
    devices, enrollment_tokens, agent_certificates, policies, policy_rules, device_policies,
    ota_releases, event_logs, event_ack, discovered_hosts, device_commands, artifacts,
    scim_users, cases, verify_checks, tokens, msp_customers, admins, pending_wipes,
    incidents, saved_searches, audit_log, evidence_custody
    FROM kut_app;
REVOKE USAGE ON SCHEMA public FROM kut_app;
DROP ROLE IF EXISTS kut_app;
