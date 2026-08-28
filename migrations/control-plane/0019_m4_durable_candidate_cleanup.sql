-- Candidate cleanup is a durable pre-commit compensation phase. It uses a
-- child task attached to the still-running rollout Operation, so the active
-- environment invariant remains intact while the old deployment keeps serving.

ALTER TABLE m4_rollout_coordinations
    ADD COLUMN IF NOT EXISTS candidate_cleanup_task_id text UNIQUE REFERENCES task_leases(task_id),
    ADD COLUMN IF NOT EXISTS candidate_cleanup_reason text;

ALTER TABLE m4_rollout_coordinations
    DROP CONSTRAINT IF EXISTS m4_rollout_coordinations_phase_allowed;
ALTER TABLE m4_rollout_coordinations
    ADD CONSTRAINT m4_rollout_coordinations_phase_allowed CHECK (
        phase IN ('candidate_requested','candidate_ready','route_staged','candidate_cleanup','route_committed','old_retiring','completed','failed','rolled_back')
    );

ALTER TABLE m4_rollout_coordinations
    DROP CONSTRAINT IF EXISTS m4_rollout_candidate_cleanup_shape;
ALTER TABLE m4_rollout_coordinations
    ADD CONSTRAINT m4_rollout_candidate_cleanup_shape CHECK (
        (phase = 'candidate_cleanup' AND candidate_cleanup_task_id IS NOT NULL AND candidate_cleanup_reason IS NOT NULL AND length(trim(candidate_cleanup_reason)) > 0)
        OR phase <> 'candidate_cleanup'
    );

ALTER TABLE m4_rollout_phase_events
    DROP CONSTRAINT IF EXISTS m4_rollout_phase_events_phase_check;
ALTER TABLE m4_rollout_phase_events
    ADD CONSTRAINT m4_rollout_phase_events_phase_check CHECK (
        phase IN ('candidate_requested','candidate_ready','route_staged','candidate_cleanup','route_committed','old_retiring','completed','failed','rolled_back')
    );
