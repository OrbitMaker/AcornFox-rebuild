DROP INDEX IF EXISTS source_revisions_m1_content_uidx;

CREATE INDEX source_revisions_m1_content_idx
    ON source_revisions (application_id, source_kind, content_digest, created_at)
    WHERE source_kind IS NOT NULL;

COMMENT ON INDEX source_revisions_m1_content_idx IS
    'Lookup index only: same request key replays, while an explicit re-upload may create a new immutable revision pointing at the same content-addressed workspace.';
