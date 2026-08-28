CREATE TABLE m1_publish_requests (
    idempotency_key text PRIMARY KEY CHECK (length(trim(idempotency_key)) > 0),
    request_digest text NOT NULL CHECK (request_digest ~ '^sha256:[0-9a-f]{64}$'),
    status text NOT NULL CHECK (status IN ('in_progress','completed','failed')),
    response jsonb,
    failure_reason text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CHECK ((status = 'completed') = (response IS NOT NULL)),
    CHECK ((status = 'failed') = (failure_reason IS NOT NULL))
);

COMMENT ON TABLE m1_publish_requests IS
    'Durable whole-pipeline idempotency. Successful retries return the original Source/Build/Release/Deployment identities without rerunning providers.';
