-- An artifact records a particular build and its evidence. Multiple builds
-- may produce the same immutable image; the OCI store deduplicates its bytes.
-- Preserve the build_id uniqueness and immutable artifact trigger.
ALTER TABLE artifacts
    DROP CONSTRAINT IF EXISTS artifacts_image_repository_image_digest_key;

CREATE INDEX IF NOT EXISTS artifacts_image_identity_idx
    ON artifacts (image_repository, image_digest, created_at DESC);
