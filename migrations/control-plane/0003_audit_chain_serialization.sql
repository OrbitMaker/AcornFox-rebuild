CREATE OR REPLACE FUNCTION validate_audit_hash_link()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    expected_previous_hash text;
BEGIN
    -- Serialize chain-head reads so concurrent writers cannot create forks.
    PERFORM pg_advisory_xact_lock(hashtextextended('open-card-audit-evidence-chain', 0));

    SELECT record_hash
      INTO expected_previous_hash
      FROM audit_evidence
     ORDER BY sequence DESC
     LIMIT 1;

    IF NEW.previous_hash IS DISTINCT FROM expected_previous_hash THEN
        RAISE EXCEPTION 'audit previous_hash does not match chain head'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
