-- Durable DNS provider-write phases. This table contains no provider payload,
-- credentials, or network destinations: only the immutable plan/change fingerprint and
-- whether a request may already have crossed the provider boundary.

CREATE TABLE IF NOT EXISTS dns_change_execution_steps (
    plan_id text NOT NULL REFERENCES dns_change_plans(id) ON DELETE CASCADE,
    change_index integer NOT NULL CHECK (change_index >= 0),
    request_fingerprint text NOT NULL CHECK (request_fingerprint ~ '^sha256:[0-9a-f]{64}$'),
    phase text NOT NULL CHECK (phase IN ('planned','write_started','reconcile_required','applied')),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (plan_id, change_index),
    UNIQUE (plan_id, change_index, request_fingerprint)
);

CREATE INDEX IF NOT EXISTS dns_change_execution_steps_reconcile_idx
    ON dns_change_execution_steps(phase, updated_at, plan_id, change_index)
    WHERE phase IN ('write_started','reconcile_required');

-- A zone has one mutable provider surface. This lease row is retained while
-- its exact step is uncertain, so a different idempotency key cannot issue a
-- concurrent or compensating mutation against the same provider zone.
CREATE TABLE IF NOT EXISTS dns_change_execution_scopes (
    installation_id text NOT NULL CHECK (length(trim(installation_id)) > 0 AND length(installation_id) <= 512),
    provider text NOT NULL CHECK (length(trim(provider)) > 0 AND length(provider) <= 128),
    zone_id text NOT NULL CHECK (length(trim(zone_id)) > 0 AND length(zone_id) <= 512),
    plan_id text NOT NULL,
    change_index integer NOT NULL CHECK (change_index >= 0),
    request_fingerprint text NOT NULL CHECK (request_fingerprint ~ '^sha256:[0-9a-f]{64}$'),
    claimed_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (installation_id, provider, zone_id),
    FOREIGN KEY (plan_id, change_index, request_fingerprint)
        REFERENCES dns_change_execution_steps(plan_id, change_index, request_fingerprint)
        ON DELETE CASCADE
);
