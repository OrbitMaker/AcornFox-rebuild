package contracts

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/domain"
)

func acornFoxSourceFixture() domain.SourceRevision {
	now := time.Unix(1_700_000_000, 0).UTC()
	return domain.SourceRevision{ID: "src_1", ApplicationID: "app_1", Kind: domain.SourceGitHTTPS, Locator: "https://private.example/repository.git", Ref: "main", Commit: strings.Repeat("a", 40), ContentDigest: "sha256:" + strings.Repeat("b", 64), WorkspaceRef: "/private/workspace/src_1", CreatedAt: now, Immutable: true}
}

func acornFoxReleaseFixture(t *testing.T) (domain.Release, domain.Artifact) {
	t.Helper()
	now := time.Unix(1_700_000_000, 0).UTC()
	image, err := domain.ParseImageDigest("registry.example/acornfox-test", "sha256:"+strings.Repeat("d", 64))
	if err != nil {
		t.Fatal(err)
	}
	release, err := domain.NewRelease("app_1", "group_1", 1, "sha256:"+strings.Repeat("e", 64), map[string]domain.ImageDigest{"web": image}, now)
	if err != nil {
		t.Fatal(err)
	}
	release.ID = "rel_1"
	artifact := domain.Artifact{ID: "art_1", BuildID: "build_1", Image: image, OCIStorageRef: "oci://private/artifact", SizeBytes: 42, CreatedAt: now}
	return *release, artifact
}

func TestProjectAcornFoxInputRevisionIsDeterministicAndRedacted(t *testing.T) {
	input := acornFoxSourceFixture()
	first, err := ProjectAcornFoxInputRevision(input)
	if err != nil {
		t.Fatal(err)
	}
	second, err := ProjectAcornFoxInputRevision(input)
	if err != nil || first != second {
		t.Fatalf("input projection is not deterministic: first=%+v second=%+v err=%v", first, second, err)
	}
	raw, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"private.example", "/private/workspace"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("input projection leaked %q: %s", forbidden, raw)
		}
	}
}

func TestProjectAcornFoxDefinitionSummaryOmitsHostileMetadata(t *testing.T) {
	now := acornFoxSourceFixture().CreatedAt
	evidence := domain.EvidenceRef{ID: "ev_1", Kind: "kind=definition-secret", Digest: "sha256:" + strings.Repeat("c", 64), Locator: "evidence://definition-secret"}
	definition := domain.ApplicationDeliveryDefinition{ID: "def_1", ApplicationID: "app_1", SourceRevisionID: "src_1", Version: 1, Facts: map[string]domain.FieldFact{"TOKEN=definition-secret": {Value: "definition-secret", Source: domain.FactSourceAI, Confidence: 1, Evidence: []domain.EvidenceRef{evidence}, Status: domain.FactObserved}}, Observations: []domain.Observation{{ID: "obs_definition_secret", TargetRef: "target://definition-secret", Kind: "definition-secret", Value: "definition-secret", Source: "definition-secret", ObservedAt: now, Evidence: []domain.EvidenceRef{evidence}}}, CreatedAt: now, Immutable: true}
	projection, err := ProjectAcornFoxDefinitionSummary(definition)
	if err != nil {
		t.Fatal(err)
	}
	if projection.FactCount != 1 || projection.ObservationCount != 1 || projection.RecommendationCount != 0 {
		t.Fatalf("definition summary counts=%+v", projection)
	}
	raw, err := json.Marshal(projection)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"TOKEN", "definition-secret", "kind=", "evidence://"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("definition metadata leaked %q: %s", forbidden, raw)
		}
	}
}

func TestProjectAcornFoxReleaseDigestSnapshotIsPartialAndIndependent(t *testing.T) {
	release, artifact := acornFoxReleaseFixture(t)
	projection, err := ProjectAcornFoxReleaseDigestSnapshot(release, []domain.Artifact{artifact})
	if err != nil {
		t.Fatal(err)
	}
	if len(projection.Images) != 1 || len(projection.ObservedArtifacts) != 1 {
		t.Fatalf("release digest snapshot=%+v", projection)
	}
	raw, err := json.Marshal(projection)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"artifact_set", "complete_m2", "oci://private", "definition_id"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("release snapshot made an unproven claim: %s", raw)
		}
	}
	artifact.Image.Digest = "sha256:" + strings.Repeat("f", 64)
	if _, err := ProjectAcornFoxReleaseDigestSnapshot(release, []domain.Artifact{artifact}); err == nil {
		t.Fatal("artifact outside release digest snapshot was accepted")
	}
}

func TestProjectAcornFoxDeploymentRuntimeStateDoesNotClaimProbeReadiness(t *testing.T) {
	release, _ := acornFoxReleaseFixture(t)
	now := release.CreatedAt
	deployment, err := domain.NewDeployment("app_1", "env_1", release.ID, now)
	if err != nil {
		t.Fatal(err)
	}
	deployment.ID = "dep_1"
	for _, state := range []domain.DeploymentStatus{domain.DeploymentPreparing, domain.DeploymentDeploying, domain.DeploymentRuntimeReady} {
		if err := deployment.Transition(state, now.Add(time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	projection, err := ProjectAcornFoxDeploymentRuntimeState(deployment)
	if err != nil || projection.Stage != AcornFoxDeploymentRuntimeObserved {
		t.Fatalf("runtime state=%+v err=%v", projection, err)
	}
	raw, err := json.Marshal(projection)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"internal_ready", "healthy", "serving", "probe"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("runtime state claimed unproven readiness: %s", raw)
		}
	}
}

func TestAcornFoxMigrationOnlyRouteInventoryIsDefensiveAndComplete(t *testing.T) {
	paths := make([]string, 0)
	for _, route := range AcornFoxMigrationOnlyRouteInventory() {
		paths = append(paths, route.Path)
	}
	for _, required := range []string{
		"/api/v1/publishes",
		"/api/v1/agents/capabilities", "/api/v1/agents/capabilities/legacy-negative", "/api/v1/sources", "/api/v1/service-groups/import", "/api/v1/images/resolve",
		"/api/v1/service-groups/{serviceGroupId}/deployments", "/api/v1/deployments/{deploymentId}", "/api/v1/deployments/{deploymentId}/events", "/api/v1/deployments/{deploymentId}/destroy", "/api/v1/rollouts/{releaseId}",
		"/api/v1/releases/{releaseId}/volumes", "/api/v1/releases/{releaseId}/volumes/{claimId}/destroy", "/api/v1/images/gc",
	} {
		if !containsPath(paths, required) {
			t.Fatalf("known M2/lifecycle/tombstone path is absent: %q", required)
		}
	}
	first := AcornFoxMigrationOnlyRouteInventory()
	first[0].Path = "/api/v1/not-authoritative"
	if AcornFoxMigrationOnlyRouteInventory()[0].Path == first[0].Path {
		t.Fatal("caller mutated route inventory")
	}
}

func TestValidateAcornFoxCleanInstallRoutesNormalizesTemplatesAndTrailingSlash(t *testing.T) {
	for _, bypass := range [][]string{
		{"/api/v1/rollouts/{id}/"},
		{"/api/v1/releases/{id}/volumes/{volume}/destroy/"},
		{"/api/v1/publishes/"},
	} {
		if err := ValidateAcornFoxCleanInstallRoutes(bypass); err == nil {
			t.Fatalf("template or slash bypass was accepted: %v", bypass)
		}
	}
	if err := ValidateAcornFoxCleanInstallRoutes([]string{"/api/v1/acornfox/apps/{application}/deliveries/"}); err != nil {
		t.Fatalf("unrelated future route was rejected: %v", err)
	}
}

func TestCurrentDocumentedOpenAPIFailsTheFutureCleanInstallLeakageGuard(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate repository fixture")
	}
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(file), "..", "..", "api", "openapi", "openapi.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	paths := InventoryOpenAPIPaths(string(raw))
	if len(paths) == 0 || ValidateAcornFoxCleanInstallRoutes(paths) == nil {
		t.Fatal("current documented OpenAPI unexpectedly passed the future clean-install guard")
	}
	for _, required := range []string{"/api/v1/applications/{applicationId}/operations", "/api/v1/operations/views/{applicationId}", "/api/v1/operations/{action}", "/api/v1/access/traffic-switches", "/api/v1/service-groups/{serviceGroupId}/releases"} {
		if !containsPath(paths, required) {
			t.Fatalf("documented OpenAPI inventory lost known route %q", required)
		}
	}
}

func containsPath(paths []string, target string) bool {
	for _, path := range paths {
		if path == target {
			return true
		}
	}
	return false
}
