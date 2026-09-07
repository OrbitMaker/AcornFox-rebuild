-- W10 unpublished application-source candidates. These rows are evidence for
-- bounded candidate work only; they never replace immutable source, build,
-- release or deployment authority.
CREATE TABLE IF NOT EXISTS acornfox_fix_candidates (
    application_id text NOT NULL REFERENCES applications(id) ON DELETE RESTRICT,
    idempotency_key text NOT NULL,
    request_digest text NOT NULL,
    base_source_revision_id text NOT NULL REFERENCES source_revisions(id) ON DELETE RESTRICT,
    owner_admin_id text NOT NULL REFERENCES admin_credentials(id) ON DELETE RESTRICT,
    state text NOT NULL,
    failure_code text,
    candidate_id text UNIQUE,
    base_repository_url text,
    base_commit text,
    base_tree_digest text,
    canonical_diff bytea,
    patch_digest text,
    result_tree_digest text,
	container_port integer,
    changed_paths jsonb,
    validated_image_repository text,
    validated_image_digest text,
    build_log_ref text,
    build_evidence_digest text,
    runtime_evidence jsonb,
    matched_source_revision_id text REFERENCES source_revisions(id) ON DELETE RESTRICT,
    matched_commit text,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    expires_at timestamptz,
    PRIMARY KEY (application_id, idempotency_key),
    CHECK (length(trim(idempotency_key)) BETWEEN 1 AND 256),
    CHECK (request_digest ~ '^sha256:[0-9a-f]{64}$'),
    CHECK (state IN ('preparing','validated','source_matched','failed')),
    CHECK (updated_at >= created_at),
    CHECK (
		(state = 'preparing' AND failure_code IS NULL AND num_nonnulls(candidate_id,base_repository_url,base_commit,base_tree_digest,canonical_diff,patch_digest,result_tree_digest,container_port,changed_paths,validated_image_repository,validated_image_digest,build_log_ref,build_evidence_digest,runtime_evidence,matched_source_revision_id,matched_commit,expires_at) = 0)
		OR (state = 'failed' AND failure_code = 'candidate_failed' AND num_nonnulls(candidate_id,base_repository_url,base_commit,base_tree_digest,canonical_diff,patch_digest,result_tree_digest,container_port,changed_paths,validated_image_repository,validated_image_digest,build_log_ref,build_evidence_digest,runtime_evidence,matched_source_revision_id,matched_commit,expires_at) = 0)
        OR (state IN ('validated','source_matched')
            AND failure_code IS NULL
            AND candidate_id ~ '^candidate_[0-9a-f]{32}$'
            AND base_repository_url = trim(base_repository_url)
			AND base_commit ~ '^[0-9a-f]{40}([0-9a-f]{24})?$'
            AND base_tree_digest ~ '^sha256:[0-9a-f]{64}$'
            AND patch_digest ~ '^sha256:[0-9a-f]{64}$'
            AND result_tree_digest ~ '^sha256:[0-9a-f]{64}$'
            AND base_tree_digest <> result_tree_digest
			AND container_port BETWEEN 1 AND 65535
            AND octet_length(canonical_diff) BETWEEN 1 AND 131072
            AND jsonb_typeof(changed_paths) = 'array'
            AND jsonb_array_length(changed_paths) BETWEEN 1 AND 32
            AND validated_image_digest ~ '^sha256:[0-9a-f]{64}$'
            AND length(trim(validated_image_repository)) > 0
            AND length(trim(build_log_ref)) > 0
            AND build_evidence_digest ~ '^sha256:[0-9a-f]{64}$'
            AND jsonb_typeof(runtime_evidence) = 'object'
			AND (runtime_evidence - ARRAY['task_id','image','runtime_state','probe_outcome','http_status','cleanup_confirmed','evidence_digest']) = '{}'::jsonb
			AND length(trim(runtime_evidence->>'task_id')) > 0
			AND jsonb_typeof(runtime_evidence->'image') = 'object'
			AND ((runtime_evidence->'image') - ARRAY['repository','digest']) = '{}'::jsonb
			AND runtime_evidence->'image'->>'repository' = validated_image_repository
			AND runtime_evidence->'image'->>'digest' = validated_image_digest
			AND runtime_evidence->>'runtime_state' = 'stopped'
			AND runtime_evidence->>'probe_outcome' = 'responded'
			AND runtime_evidence->'cleanup_confirmed' = 'true'::jsonb
			AND runtime_evidence->>'evidence_digest' ~ '^sha256:[0-9a-f]{64}$'
            AND expires_at > created_at)
    ),
    CHECK (
		(state = 'source_matched' AND matched_source_revision_id IS NOT NULL AND matched_commit ~ '^[0-9a-f]{40}([0-9a-f]{24})?$')
        OR (state <> 'source_matched' AND matched_source_revision_id IS NULL AND matched_commit IS NULL)
    )
);

CREATE INDEX IF NOT EXISTS acornfox_fix_candidates_candidate_idx
    ON acornfox_fix_candidates(application_id, candidate_id)
    WHERE candidate_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS acornfox_fix_candidates_expiry_idx
    ON acornfox_fix_candidates(expires_at)
    WHERE state IN ('validated','source_matched');

CREATE OR REPLACE FUNCTION acornfox_fix_candidates_validate_scope()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    source_app text;
    source_kind text;
    source_locator text;
	matched_valid boolean;
BEGIN
    SELECT source.application_id, source.source_kind, source.locator
      INTO source_app, source_kind, source_locator
      FROM source_revisions AS source
      JOIN acornfox_source_metadata AS metadata ON metadata.source_revision_id = source.id
     WHERE source.id = NEW.base_source_revision_id;
    IF NOT FOUND OR source_app <> NEW.application_id OR source_kind <> 'git_https' THEN
        RAISE EXCEPTION 'fix candidate base is not an application-owned public Git source' USING ERRCODE='23514';
    END IF;
    IF NEW.base_repository_url IS NOT NULL AND NEW.base_repository_url <> source_locator THEN
        RAISE EXCEPTION 'fix candidate repository does not match base source' USING ERRCODE='23514';
    END IF;
	IF NEW.state = 'source_matched' THEN
		SELECT EXISTS (
			SELECT 1 FROM source_revisions AS matched
			JOIN acornfox_source_metadata AS matched_metadata ON matched_metadata.source_revision_id=matched.id
			WHERE matched.id=NEW.matched_source_revision_id
			  AND matched.application_id=NEW.application_id
			  AND matched.source_kind='git_https'
			  AND matched.locator=NEW.base_repository_url
			  AND matched.content_digest=NEW.result_tree_digest
			  AND matched.git_commit=NEW.matched_commit
			  AND matched_metadata.repository_url=NEW.base_repository_url
		) INTO matched_valid;
		IF NOT matched_valid THEN
			RAISE EXCEPTION 'fix candidate matched source does not reproduce the candidate' USING ERRCODE='23514';
		END IF;
	END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS acornfox_fix_candidates_scope_trigger ON acornfox_fix_candidates;
CREATE TRIGGER acornfox_fix_candidates_scope_trigger
    BEFORE INSERT OR UPDATE ON acornfox_fix_candidates
    FOR EACH ROW EXECUTE FUNCTION acornfox_fix_candidates_validate_scope();
