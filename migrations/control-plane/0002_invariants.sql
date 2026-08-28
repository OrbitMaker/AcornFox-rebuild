CREATE FUNCTION reject_immutable_row_change()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION '% rows are immutable', TG_TABLE_NAME
        USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER releases_are_immutable
    BEFORE UPDATE OR DELETE ON releases
    FOR EACH ROW EXECUTE FUNCTION reject_immutable_row_change();

CREATE TRIGGER source_revisions_are_immutable
    BEFORE UPDATE OR DELETE ON source_revisions
    FOR EACH ROW EXECUTE FUNCTION reject_immutable_row_change();

CREATE TRIGGER delivery_definitions_are_immutable
    BEFORE UPDATE OR DELETE ON delivery_definitions
    FOR EACH ROW EXECUTE FUNCTION reject_immutable_row_change();

CREATE TRIGGER audit_evidence_is_append_only
    BEFORE UPDATE OR DELETE ON audit_evidence
    FOR EACH ROW EXECUTE FUNCTION reject_immutable_row_change();

CREATE FUNCTION validate_audit_hash_link()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    expected_previous_hash text;
BEGIN
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

CREATE TRIGGER audit_evidence_hash_link
    BEFORE INSERT ON audit_evidence
    FOR EACH ROW EXECUTE FUNCTION validate_audit_hash_link();

CREATE FUNCTION reject_release_without_service_digest()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.service_digests = '{}'::jsonb
       OR EXISTS (
            SELECT 1
              FROM jsonb_each_text(NEW.service_digests) AS digest(service_id, value)
             WHERE value !~ '^sha256:[0-9a-f]{64}$'
       ) THEN
        RAISE EXCEPTION 'release requires a non-empty sha256 digest for every service'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER releases_require_service_digests
    BEFORE INSERT ON releases
    FOR EACH ROW EXECUTE FUNCTION reject_release_without_service_digest();
