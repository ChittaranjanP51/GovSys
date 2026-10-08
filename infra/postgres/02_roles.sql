-- =====================================================================
-- Least-privilege database roles. Each AI agent connects as its OWN role,
-- so even if an upstream control fails, the database refuses the action.
-- Passwords are set by scripts/bootstrap.py from environment variables.
-- =====================================================================
DO $$
DECLARE r TEXT;
BEGIN
    FOREACH r IN ARRAY ARRAY['agent_order','agent_billing','agent_admin','gov_audit_writer','gov_reader']
    LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
            EXECUTE format('CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT', r);
        END IF;
    END LOOP;
END $$;

-- Start from zero: nobody gets anything implicitly.
REVOKE CONNECT ON DATABASE govsys FROM PUBLIC;
GRANT  CONNECT ON DATABASE govsys TO agent_order, agent_billing, agent_admin, gov_audit_writer, gov_reader;

REVOKE ALL ON SCHEMA sales, billing, iam, gov FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA sales, billing, iam, gov
    FROM PUBLIC, agent_order, agent_billing, agent_admin, gov_audit_writer, gov_reader;

-- ---------------------------------------------------------- order agent
GRANT USAGE ON SCHEMA sales TO agent_order;
GRANT SELECT ON sales.orders TO agent_order;
GRANT UPDATE (status, updated_at) ON sales.orders TO agent_order;
-- Column-level grant: national_id and date_of_birth are NOT readable.
GRANT SELECT (customer_id, full_name, email, phone, city) ON sales.customers TO agent_order;

-- -------------------------------------------------------- billing agent
GRANT USAGE ON SCHEMA sales, billing TO agent_billing;
GRANT SELECT (order_id, customer_id, total, status) ON sales.orders TO agent_billing;
GRANT SELECT ON billing.invoices TO agent_billing;
GRANT UPDATE (status) ON billing.invoices TO agent_billing;
GRANT SELECT, INSERT ON billing.refunds TO agent_billing;
GRANT USAGE ON SEQUENCE billing.refunds_refund_id_seq TO agent_billing;

-- ---------------------------------------------------------- admin agent
GRANT USAGE ON SCHEMA iam, gov TO agent_admin;
GRANT SELECT (username, full_name, department, roles, status) ON iam.staff TO agent_admin;
GRANT SELECT (id, ts, request_id, username, agent_path, final_decision, blocked_at, latency_ms)
    ON gov.audit_log TO agent_admin;

-- ------------------------------------------------- governance services
-- Audit writer may only INSERT (+ read the chain tip to link hashes).
GRANT USAGE ON SCHEMA gov TO gov_audit_writer;
GRANT INSERT ON gov.audit_log TO gov_audit_writer;
GRANT SELECT (id, row_hash) ON gov.audit_log TO gov_audit_writer;
GRANT USAGE ON SEQUENCE gov.audit_log_id_seq TO gov_audit_writer;

-- Read-only role for dashboard, data-governance layer and compliance reports.
GRANT USAGE ON SCHEMA gov TO gov_reader;
GRANT SELECT ON gov.audit_log, gov.data_catalog TO gov_reader;
-- Account status lookup (continuous verification when Keycloak is the IdP).
GRANT USAGE ON SCHEMA iam TO gov_reader;
GRANT SELECT (username, status) ON iam.staff TO gov_reader;
