-- AcornFox log indexes remain pointers to on-disk segments. This migration
-- records only the immutable delivery identity, content SHA-256, and rendering
-- limits needed to read a build or runtime stream; it never copies log bytes
-- into PostgreSQL.
-- NULL stream/truncation/build metadata is retained for rows written before
-- this migration. New writers record an explicit "unknown" when a fact is
-- unavailable rather than inventing it from the path or stream name. A NULL
-- content digest remains legacy internal metadata and is never public.
ALTER TABLE m4_log_indexes
    ADD COLUMN IF NOT EXISTS build_id text REFERENCES builds(id),
    ADD COLUMN IF NOT EXISTS log_stream text,
    ADD COLUMN IF NOT EXISTS truncation text,
    ADD COLUMN IF NOT EXISTS content_digest text;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'm4_log_indexes'::regclass
          AND conname = 'm4_log_indexes_build_metadata_shape'
    ) THEN
        ALTER TABLE m4_log_indexes
            ADD CONSTRAINT m4_log_indexes_build_metadata_shape CHECK (
                build_id IS NULL OR category = 'build'
            );
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'm4_log_indexes'::regclass
          AND conname = 'm4_log_indexes_stream_allowed'
    ) THEN
        ALTER TABLE m4_log_indexes
            ADD CONSTRAINT m4_log_indexes_stream_allowed CHECK (
                log_stream IS NULL OR log_stream IN ('stdout', 'stderr', 'combined', 'unknown')
            );
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'm4_log_indexes'::regclass
          AND conname = 'm4_log_indexes_truncation_allowed'
    ) THEN
        ALTER TABLE m4_log_indexes
            ADD CONSTRAINT m4_log_indexes_truncation_allowed CHECK (
                truncation IS NULL OR truncation IN ('complete', 'source_limited', 'unknown')
            );
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'm4_log_indexes'::regclass
          AND conname = 'm4_log_indexes_content_digest_sha256'
    ) THEN
        ALTER TABLE m4_log_indexes
            ADD CONSTRAINT m4_log_indexes_content_digest_sha256 CHECK (
                content_digest IS NULL OR (
                    char_length(content_digest) = 71
                    AND content_digest ~ '^sha256:[0-9a-f]{64}$'
                )
            );
    END IF;
END $$;

-- These indexes are intentionally partial: ordinary log reconciliation keeps
-- retired segments out of the serving path, and audit indexes never belong to
-- an AcornFox delivery stream.
CREATE INDEX IF NOT EXISTS m4_log_indexes_active_build_delivery_idx
    ON m4_log_indexes(build_id, created_at DESC, id DESC)
    WHERE category = 'build' AND build_id IS NOT NULL AND retired_at IS NULL
      AND content_digest IS NOT NULL;

CREATE INDEX IF NOT EXISTS m4_log_indexes_active_runtime_delivery_idx
    ON m4_log_indexes(deployment_id, created_at DESC, id DESC)
    WHERE category = 'runtime' AND deployment_id IS NOT NULL AND retired_at IS NULL
      AND content_digest IS NOT NULL;
