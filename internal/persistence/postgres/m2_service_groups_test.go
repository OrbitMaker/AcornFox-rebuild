package postgres

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/domain"
)

func TestM2MigrationIsAdditiveRepeatSafeAndFailClosed(t *testing.T) {
	payload, err := os.ReadFile("../../../migrations/control-plane/0012_m2_service_groups.sql")
	if err != nil {
		t.Fatal(err)
	}
	text := string(payload)
	for _, fragment := range []string{
		"CREATE TABLE IF NOT EXISTS service_groups",
		"CREATE TABLE IF NOT EXISTS service_group_specs",
		"CREATE TABLE IF NOT EXISTS service_group_import_reports",
		"CREATE TABLE IF NOT EXISTS m2_service_group_requests",
		"CREATE TABLE IF NOT EXISTS m2_release_service_bindings",
		"definition_id text",
		"canonical_digest text",
		"service_group_volume_claims",
		"m2_release_volume_claims",
		"m2_release_rollouts",
		"m2_release_image_protections",
		"service_groups_require_m2_identity",
		"service_groups_application_name_version_uidx",
		"validate_m2_service_group_identity",
		"m2_releases_are_immutable",
		"service_group_volume_claims_are_immutable",
		"m2_release_volume_claims_are_immutable",
		"m2_release_rollouts_are_immutable",
		"m2_release_image_protections_are_immutable",
		"release artifact provenance application does not match release",
		"release artifact provenance service does not match release binding",
		"service_group_specs_shape",
		"m2_release_bindings_digest_shape",
		"CREATE OR REPLACE FUNCTION validate_m2_release_digest_set",
		"CREATE OR REPLACE FUNCTION validate_m2_release_artifacts_complete",
		"DEFERRABLE INITIALLY DEFERRED",
		"releases_require_m2_digest_set",
		"release_artifacts_require_m2_complete_set",
		"m2_release_bindings_require_complete_set",
		"service_groups_are_immutable",
		"service_group_specs_are_immutable",
		"service_group_import_reports_are_immutable",
	} {
		if !strings.Contains(text, fragment) {
			t.Errorf("M2 migration is missing %q", fragment)
		}
	}
	for _, forbidden := range []string{"DROP TABLE", "BEGIN;", "COMMIT;"} {
		if strings.Contains(text, forbidden) {
			t.Errorf("M2 migration must not contain destructive/transaction wrapper %q", forbidden)
		}
	}
}

func TestM2ServiceGroupRevisionIdentityIsCanonicalAndVersioned(t *testing.T) {
	group := m2TestServiceGroup()
	configDigest := "sha256:" + strings.Repeat("c", 64)
	request, err := normalizeM2ServiceGroupRequest(ServiceGroupCreateRequest{
		Group:          group,
		ImportReport:   domain.ComposeImportReport{MappedFields: []string{"services.web.image"}},
		IdempotencyKey: "m2-revision-1",
		Identity:       M2ServiceGroupIdentity{DefinitionID: "def_1", Version: 1, ConfigDigest: configDigest},
		VolumeClaims:   []M2ServiceGroupVolumeClaim{{ID: "claim_data", Name: "data", SizeBytes: 1024, Retain: true}},
	})
	if err != nil {
		t.Fatalf("normalize revision: %v", err)
	}
	if request.Identity.DefinitionID != "def_1" || request.Identity.Version != 1 {
		t.Fatalf("revision identity was not retained: %+v", request.Identity)
	}
	if request.Identity.CanonicalDigest == "" || !validM2SHA256(request.Identity.CanonicalDigest) {
		t.Fatalf("canonical digest was not derived: %+v", request.Identity)
	}
	request.Version = 2
	if _, err := normalizeM2ServiceGroupRequest(request); err == nil {
		t.Fatal("conflicting scalar revision identity was accepted")
	}
	request.Version = 1
	request.Identity.CanonicalDigest = "sha256:" + strings.Repeat("d", 64)
	if _, err := normalizeM2ServiceGroupRequest(request); err == nil {
		t.Fatal("caller-supplied canonical digest that does not match normalized facts was accepted")
	}
}

func TestM2ReleaseRolloutAndVolumeClaimsFailClosed(t *testing.T) {
	if _, err := normalizeM2RolloutPolicy(M2ReleaseRollout{Mode: "rolling", PreviousReleaseID: "rel_old", PreviousDeploymentID: "dep_old"}); err == nil {
		t.Fatal("rolling rollout without old traffic preservation was accepted")
	}
	if _, err := normalizeM2RolloutPolicy(M2ReleaseRollout{Mode: "recreate", PreviousReleaseID: "rel_old", PreviousDeploymentID: "dep_old", DowntimeApproved: true}); err != nil {
		t.Fatalf("valid recreate rollout rejected: %v", err)
	}
	if err := validateM2VolumeClaims([]M2ServiceGroupVolumeClaim{{ID: "claim", Name: "../host", SizeBytes: 1, Retain: true}}); err == nil {
		t.Fatal("unsafe volume claim name was accepted")
	}
	if err := validateM2VolumeClaims([]M2ServiceGroupVolumeClaim{{ID: "claim", Name: "data", SizeBytes: 1, Retain: false}}); err == nil {
		t.Fatal("non-retained volume claim was accepted")
	}
}

func TestM2ServiceGroupDigestSetRequiresEveryService(t *testing.T) {
	group := m2TestServiceGroup()
	group.Services = append(group.Services, domain.ServiceSpec{
		Name:     "worker",
		Role:     domain.RoleWorker,
		Required: true,
		Source: domain.ServiceSource{
			Kind:   domain.ServiceStatic,
			Static: &domain.StaticSource{Directory: "worker"},
		},
	})
	image, err := domain.ParseImageDigest("registry.example/web", "sha256:"+strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	release, err := domain.NewRelease(group.ApplicationID, group.ID, 1, "sha256:"+strings.Repeat("b", 64), map[string]domain.ImageDigest{"web": image}, time.Unix(1700000000, 0))
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateReleaseDigestSet(group, *release); err == nil {
		t.Fatal("incomplete release digest set was accepted")
	}
	if err := ValidateM2ReleaseServiceBindings(group, *release, nil); err == nil {
		t.Fatal("release without provenance bindings was accepted")
	}
}

func TestM2ReleaseBindingUnionRejectsFabricatedPrebuiltArtifact(t *testing.T) {
	group := m2TestServiceGroup()
	group.Services[0].Source = domain.ServiceSource{
		Kind:     domain.ServicePrebuilt,
		Prebuilt: &domain.PrebuiltSource{Reference: "registry.example/web:stable"},
	}
	image, err := domain.ParseImageDigest("registry.example/web", "sha256:"+strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	release, err := domain.NewRelease(group.ApplicationID, group.ID, 1, "sha256:"+strings.Repeat("b", 64), map[string]domain.ImageDigest{"web": image}, time.Unix(1700000000, 0))
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateM2ReleaseServiceBindings(group, *release, []M2ReleaseServiceBinding{{ServiceName: "web", Kind: M2ReleaseBindingArtifact, ArtifactID: "artifact_1"}}); err == nil {
		t.Fatal("prebuilt service was allowed to fabricate an artifact binding")
	}
	if err := ValidateM2ReleaseServiceBindings(group, *release, []M2ReleaseServiceBinding{{
		ServiceName:  "web",
		Kind:         M2ReleaseBindingResolvedImage,
		Image:        image,
		ResolvedFrom: "registry.example/web:stable",
	}}); err != nil {
		t.Fatalf("resolved prebuilt binding rejected: %v", err)
	}
}

func TestM2ServiceGroupInputValidationRejectsBlankReportEntries(t *testing.T) {
	group := m2TestServiceGroup()
	if err := validateM2ServiceGroup(group, domain.ComposeImportReport{MappedFields: []string{""}}, "request-1"); err == nil {
		t.Fatal("blank mapped report field was accepted")
	}
	if err := validateM2ServiceGroup(group, domain.ComposeImportReport{Warnings: []string{"warning\nsecret"}}, "request-1"); err == nil {
		t.Fatal("multiline warning was accepted")
	}
}

func m2TestServiceGroup() domain.ServiceGroup {
	return domain.ServiceGroup{
		ID:            "group_m2_test",
		ApplicationID: "app_m2_test",
		Name:          "web-stack",
		CreatedAt:     time.Unix(1700000000, 0).UTC(),
		Services: []domain.ServiceSpec{{
			Name:     "web",
			Role:     domain.RoleIngress,
			Required: true,
			Source: domain.ServiceSource{
				Kind:   domain.ServiceStatic,
				Static: &domain.StaticSource{Directory: "."},
			},
		}},
	}
}
