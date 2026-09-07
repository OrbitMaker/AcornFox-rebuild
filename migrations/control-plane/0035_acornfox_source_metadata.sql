-- Public visibility is an ingest-time provenance claim, not a property that
-- can be reconstructed from historical source_revisions.locator values.
CREATE TABLE IF NOT EXISTS acornfox_source_metadata (
    source_revision_id text PRIMARY KEY REFERENCES source_revisions(id),
    repository_url text NOT NULL,
    accepted_at timestamptz NOT NULL DEFAULT now(),
    CHECK (length(trim(repository_url)) > 0),
    CHECK (repository_url ~ '^https://[^/?#@[:space:]]+/[^?#[:space:]]+$')
);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger
         WHERE tgrelid = 'acornfox_source_metadata'::regclass
           AND tgname = 'acornfox_source_metadata_are_immutable'
           AND NOT tgisinternal
    ) THEN
        CREATE TRIGGER acornfox_source_metadata_are_immutable
            BEFORE UPDATE OR DELETE ON acornfox_source_metadata
            FOR EACH ROW EXECUTE FUNCTION reject_immutable_row_change();
    END IF;
END $$;

COMMENT ON TABLE acornfox_source_metadata IS
    'Explicit public-git ingest provenance. No historical locator is backfilled into this table.';
