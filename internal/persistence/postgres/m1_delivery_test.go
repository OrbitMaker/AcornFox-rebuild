package postgres

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/domain"
)

func TestM1BuildValidationFailsClosed(t *testing.T) {
	valid := domain.Build{ID: "build_1", PlanID: "plan_1", Status: domain.BuildPending}
	if err := validateM1Build(valid); err != nil {
		t.Fatalf("valid pending build rejected: %v", err)
	}
	for _, item := range []domain.Build{
		{PlanID: "plan_1", Status: domain.BuildPending},
		{ID: "build_1", Status: domain.BuildPending},
		{ID: "build_1", PlanID: "plan_1", Status: domain.BuildStatus("made_up")},
	} {
		if err := validateM1Build(item); err == nil {
			t.Errorf("invalid build accepted: %#v", item)
		}
	}
}

func TestReleaseCreationRequiresFrozenReadyRelease(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	image, err := domain.ParseImageDigest("registry.example/open-card/demo", "sha256:"+strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	release, err := domain.NewRelease("app_1", "group_1", 1, "sha256:config", map[string]domain.ImageDigest{"web": image}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := (ReleaseCreation{Release: *release, DefinitionID: "def_1"}).validate(); err != nil {
		t.Fatalf("ready immutable release rejected: %v", err)
	}

	payload, err := json.Marshal(release)
	if err != nil {
		t.Fatal(err)
	}
	var draft map[string]any
	if err := json.Unmarshal(payload, &draft); err != nil {
		t.Fatal(err)
	}
	draft["status"] = string(domain.ReleaseDraft)
	payload, _ = json.Marshal(draft)
	var invalid domain.Release
	if err := json.Unmarshal(payload, &invalid); err != nil {
		t.Fatal(err)
	}
	if err := (ReleaseCreation{Release: invalid, DefinitionID: "def_1"}).validate(); err == nil {
		t.Fatal("draft release must not enter the M1 ready-release path")
	}
}

func TestM1MigrationCarriesImmutableBuildReleaseGuards(t *testing.T) {
	payload, err := os.ReadFile("../../../migrations/control-plane/0008_m1_delivery.sql")
	if err != nil {
		t.Fatal(err)
	}
	text := string(payload)
	for _, fragment := range []string{
		"CREATE TABLE build_plans",
		"CREATE TABLE artifacts",
		"CREATE TABLE release_artifacts",
		"CREATE TABLE source_workspace_events",
		"state = 'succeeded') = (artifact_id IS NOT NULL)",
		"release_status = 'ready'",
		"build_plans_are_immutable",
		"artifacts_are_immutable",
		"source_revisions_m1_shape_check",
	} {
		if !strings.Contains(text, fragment) {
			t.Errorf("M1 migration is missing %q", fragment)
		}
	}
}

func TestAcornFoxBuildPlanBindingMigrationIsAdditiveAndPaired(t *testing.T) {
	payload, err := os.ReadFile("../../../migrations/control-plane/0025_acornfox_build_plan_binding.sql")
	if err != nil {
		t.Fatal(err)
	}
	text := string(payload)
	for _, fragment := range []string{
		"ADD COLUMN IF NOT EXISTS acornfox_definition_digest text",
		"ADD COLUMN IF NOT EXISTS acornfox_dockerfile_digest text",
		"build_plans_acornfox_binding_check",
		"acornfox_definition_digest IS NULL AND acornfox_dockerfile_digest IS NULL",
		"acornfox_definition_digest IS NOT NULL",
		"acornfox_dockerfile_digest IS NOT NULL",
		"build_kind = 'dockerfile'",
		"context_path = '.'",
		"dockerfile_path = 'Dockerfile'",
		"static_runtime_digest IS NULL",
		"output_contract @> '{\"format\":\"oci\",\"retention\":\"persistent\"}'::jsonb",
		"acornfox_definition_digest ~ '^sha256:[0-9A-Fa-f]{64}$'",
		"acornfox_dockerfile_digest ~ '^sha256:[0-9A-Fa-f]{64}$'",
	} {
		if !strings.Contains(text, fragment) {
			t.Errorf("0025 migration is missing %q", fragment)
		}
	}
	for _, forbidden := range []string{"DROP COLUMN", "DROP TABLE", "DELETE FROM", "UPDATE build_plans"} {
		if strings.Contains(strings.ToUpper(text), forbidden) {
			t.Errorf("0025 migration must not contain %q", forbidden)
		}
	}
}

func TestAcornFoxBuildPlanNetworkPolicyMigrationIsAdditiveAndConstrained(t *testing.T) {
	payload, err := os.ReadFile("../../../migrations/control-plane/0026_acornfox_build_network_policy.sql")
	if err != nil {
		t.Fatal(err)
	}
	text := string(payload)
	for _, fragment := range []string{
		"ADD COLUMN IF NOT EXISTS acornfox_network_mode text",
		"ADD COLUMN IF NOT EXISTS acornfox_worker_policy_digest text",
		"build_plans_acornfox_network_policy_check",
		"acornfox_network_mode IS NULL AND acornfox_worker_policy_digest IS NULL",
		"acornfox_network_mode = 'none' AND acornfox_worker_policy_digest IS NULL",
		"acornfox_network_mode IS NOT NULL",
		"acornfox_network_mode = 'controlled_egress_v1'",
		"acornfox_worker_policy_digest IS NOT NULL",
		"acornfox_worker_policy_digest ~ '^sha256:[a-f0-9]{64}$'",
		"acornfox_definition_digest IS NOT NULL",
		"acornfox_dockerfile_digest IS NOT NULL",
		"build_kind = 'dockerfile'",
		"context_path = '.'",
		"dockerfile_path = 'Dockerfile'",
		"static_runtime_digest IS NULL",
		"output_contract @> '{\"format\":\"oci\",\"retention\":\"persistent\"}'::jsonb",
	} {
		if !strings.Contains(text, fragment) {
			t.Errorf("0026 migration is missing %q", fragment)
		}
	}
	for _, forbidden := range []string{"DROP COLUMN", "DROP TABLE", "DELETE FROM", "UPDATE build_plans"} {
		if strings.Contains(strings.ToUpper(text), forbidden) {
			t.Errorf("0026 migration must not contain %q", forbidden)
		}
	}
}
