-- Atomic M4 rollout plans snapshot current route pointers before the Agent has
-- created the candidate containers. Candidate ports are therefore resolved
-- from the later, independently validated Agent observation; the immutable
-- route identity and expected old pointer revision are fixed at request time.

ALTER TABLE m4_rollout_route_set_entries
    DROP CONSTRAINT IF EXISTS m4_rollout_route_set_entries_candidate_port_check;
ALTER TABLE m4_rollout_route_set_entries
    ALTER COLUMN candidate_port DROP NOT NULL;
ALTER TABLE m4_rollout_route_set_entries
    ADD CONSTRAINT m4_rollout_route_set_entries_candidate_port_check
    CHECK (candidate_port IS NULL OR candidate_port BETWEEN 1 AND 65535);

ALTER TABLE m4_rollout_route_sets
    ADD COLUMN IF NOT EXISTS target_release_id text REFERENCES releases(id);
