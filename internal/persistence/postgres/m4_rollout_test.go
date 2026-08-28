package postgres

import (
	"os"
	"strings"
	"testing"
)

func TestM4RolloutPhaseTransitionsFailClosed(t *testing.T) {
	valid := [][2]M4RolloutPhase{
		{M4RolloutCandidateRequested, M4RolloutCandidateReady},
		{M4RolloutCandidateReady, M4RolloutRouteStaged},
		{M4RolloutRouteStaged, M4RolloutRouteCommitted},
		{M4RolloutRouteCommitted, M4RolloutOldRetiring},
		{M4RolloutOldRetiring, M4RolloutCompleted},
	}
	for _, item := range valid {
		if !validM4RolloutTransition(item[0], item[1]) {
			t.Fatalf("valid transition %s -> %s rejected", item[0], item[1])
		}
	}
	for _, item := range [][2]M4RolloutPhase{{M4RolloutCandidateRequested, M4RolloutRouteCommitted}, {M4RolloutRouteCommitted, M4RolloutCandidateReady}, {M4RolloutCompleted, M4RolloutOldRetiring}} {
		if validM4RolloutTransition(item[0], item[1]) {
			t.Fatalf("out-of-order transition %s -> %s accepted", item[0], item[1])
		}
	}
}

func TestM4AtomicRolloutMigrationDefersOnlyCandidatePortResolution(t *testing.T) {
	payload, err := os.ReadFile("../../../migrations/control-plane/0018_m4_atomic_rollout_plan.sql")
	if err != nil {
		t.Fatal(err)
	}
	text := string(payload)
	for _, fragment := range []string{"ALTER COLUMN candidate_port DROP NOT NULL", "candidate_port IS NULL OR candidate_port BETWEEN 1 AND 65535", "target_release_id text REFERENCES releases(id)"} {
		if !strings.Contains(text, fragment) {
			t.Fatalf("0018 missing atomic rollout contract %q", fragment)
		}
	}
	for _, forbidden := range []string{"DROP TABLE", "DELETE FROM", "DROP COLUMN"} {
		if strings.Contains(strings.ToUpper(text), forbidden) {
			t.Fatalf("0018 contains destructive statement %q", forbidden)
		}
	}
}

func TestM4CandidateCleanupMigrationAddsRecoverableTaskPhase(t *testing.T) {
	payload, err := os.ReadFile("../../../migrations/control-plane/0019_m4_durable_candidate_cleanup.sql")
	if err != nil {
		t.Fatal(err)
	}
	text := string(payload)
	for _, fragment := range []string{"candidate_cleanup_task_id", "candidate_cleanup_reason", "phase = 'candidate_cleanup'", "m4_rollout_phase_events_phase_check"} {
		if !strings.Contains(text, fragment) {
			t.Fatalf("0019 missing cleanup contract %q", fragment)
		}
	}
	for _, forbidden := range []string{"DROP TABLE", "DELETE FROM", "DROP COLUMN"} {
		if strings.Contains(strings.ToUpper(text), forbidden) {
			t.Fatalf("0019 contains destructive statement %q", forbidden)
		}
	}
}
