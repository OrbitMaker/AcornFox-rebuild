-- G4 local-only DNS ownership, dry-run, and reconciliation ledger.
-- This migration never contains Tencent credentials or a provider write path.

CREATE TABLE IF NOT EXISTS dns_change_owned_records (
    owner_key text PRIMARY KEY CHECK (owner_key ~ '^[a-z][a-z0-9:_-]{2,127}$'),
    provider text NOT NULL CHECK (provider = 'dnspod'),
    domain_id bigint NOT NULL CHECK (domain_id > 0),
    domain text NOT NULL CHECK (length(trim(domain)) > 0),
    record_id bigint NOT NULL CHECK (record_id > 0),
    host text NOT NULL CHECK (length(trim(host)) > 0),
    record_type text NOT NULL CHECK (record_type IN ('A','CNAME')),
    value text NOT NULL CHECK (length(trim(value)) > 0),
    ttl integer NOT NULL CHECK (ttl BETWEEN 1 AND 604800),
    last_request_id text,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    last_plan_id text,
    UNIQUE (provider, domain_id, record_id)
);

CREATE TABLE IF NOT EXISTS dns_change_plans (
    id text PRIMARY KEY,
    idempotency_key text NOT NULL UNIQUE,
    input_digest text NOT NULL CHECK (input_digest ~ '^sha256:[0-9a-f]{64}$'),
    changes jsonb NOT NULL CHECK (jsonb_typeof(changes) = 'array'),
    created_at timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS dns_change_reconcile_state (
    scope text PRIMARY KEY,
    last_run_at timestamptz NOT NULL
);
