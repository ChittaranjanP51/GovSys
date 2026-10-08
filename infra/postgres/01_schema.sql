-- =====================================================================
-- GovSys schema: business data (sales, billing), identity mirror (iam),
-- and governance tables (gov). Idempotent: safe to re-run.
-- =====================================================================
CREATE SCHEMA IF NOT EXISTS sales;
CREATE SCHEMA IF NOT EXISTS billing;
CREATE SCHEMA IF NOT EXISTS iam;
CREATE SCHEMA IF NOT EXISTS gov;

-- ---------------------------------------------------------------- sales
CREATE TABLE IF NOT EXISTS sales.customers (
    customer_id    INT PRIMARY KEY,
    full_name      TEXT NOT NULL,
    email          TEXT NOT NULL,
    phone          TEXT,
    city           TEXT,
    date_of_birth  DATE,
    national_id    TEXT,               -- RESTRICTED: no agent role can read it
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS sales.orders (
    order_id     INT PRIMARY KEY,
    customer_id  INT NOT NULL REFERENCES sales.customers(customer_id),
    item         TEXT NOT NULL,
    quantity     INT NOT NULL CHECK (quantity > 0),
    total        NUMERIC(10,2) NOT NULL,
    status       TEXT NOT NULL CHECK (status IN ('placed','shipped','delivered','cancelled','returned')),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- -------------------------------------------------------------- billing
CREATE TABLE IF NOT EXISTS billing.invoices (
    invoice_id   TEXT PRIMARY KEY,
    order_id     INT NOT NULL REFERENCES sales.orders(order_id),
    amount       NUMERIC(10,2) NOT NULL,
    status       TEXT NOT NULL CHECK (status IN ('paid','unpaid','refunded','partially_refunded')),
    card_last4   TEXT,
    issued_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS billing.refunds (
    refund_id          BIGSERIAL PRIMARY KEY,
    order_id           INT NOT NULL REFERENCES sales.orders(order_id),
    amount             NUMERIC(10,2) NOT NULL CHECK (amount > 0),
    reason             TEXT,
    requested_by       TEXT NOT NULL,      -- human principal
    executed_by_agent  TEXT NOT NULL,      -- agent workload identity (SPIFFE ID)
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ------------------------------------------------------------------ iam
CREATE TABLE IF NOT EXISTS iam.staff (
    username    TEXT PRIMARY KEY,
    full_name   TEXT NOT NULL,
    department  TEXT NOT NULL,
    roles       TEXT[] NOT NULL,
    status      TEXT NOT NULL CHECK (status IN ('active','suspended')),
    password_hash TEXT                    -- never granted to any agent role
);

-- ------------------------------------------------------------------ gov
-- Data catalog: classification drives PII masking at runtime.
CREATE TABLE IF NOT EXISTS gov.data_catalog (
    schema_name     TEXT NOT NULL,
    table_name      TEXT NOT NULL,
    column_name     TEXT NOT NULL,
    classification  TEXT NOT NULL CHECK (classification IN ('public','internal','confidential','pii','restricted')),
    owner           TEXT NOT NULL,
    retention_days  INT,
    description     TEXT,
    PRIMARY KEY (schema_name, table_name, column_name)
);

-- Tamper-evident, append-only audit trail (hash chained).
CREATE TABLE IF NOT EXISTS gov.audit_log (
    id                 BIGSERIAL PRIMARY KEY,
    ts                 TIMESTAMPTZ NOT NULL DEFAULT now(),
    request_id         UUID NOT NULL,
    username           TEXT,
    roles              TEXT[],
    agent_path         TEXT[],
    final_decision     TEXT NOT NULL CHECK (final_decision IN ('allowed','blocked','error')),
    blocked_at         TEXT,
    checks             JSONB NOT NULL,
    tool_calls         JSONB NOT NULL DEFAULT '[]'::jsonb,
    model              TEXT,
    prompt_redacted    TEXT,
    response_redacted  TEXT,
    latency_ms         INT,
    prev_hash          TEXT NOT NULL,
    row_hash           TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_log_ts_idx ON gov.audit_log (ts);

CREATE OR REPLACE FUNCTION gov.forbid_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'gov.audit_log is append-only (% blocked)', TG_OP;
END $$;

-- Statement-level, so even an UPDATE/DELETE that matches zero rows is refused.
-- (A superuser could still disable the trigger; the hash chain makes that detectable.)
DROP TRIGGER IF EXISTS audit_log_no_update ON gov.audit_log;
DROP TRIGGER IF EXISTS audit_log_no_mutation ON gov.audit_log;
CREATE TRIGGER audit_log_no_mutation BEFORE UPDATE OR DELETE OR TRUNCATE ON gov.audit_log
    FOR EACH STATEMENT EXECUTE FUNCTION gov.forbid_mutation();
DROP TRIGGER IF EXISTS audit_log_no_truncate ON gov.audit_log;
