// Package contracts contains provider-neutral boundaries. This file holds the
// smallest read-only AcornFox compatibility projections that can be proved
// from one existing authoritative fact at a time.
package contracts

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/open-card/open-card/internal/domain"
)

// AcornFoxInputRevision is a redacted projection of one SourceRevision.
// Locator and WorkspaceRef never cross this boundary because older source rows
// can contain private source topology.
type AcornFoxInputRevision struct {
	ID            domain.ID `json:"id"`
	ApplicationID domain.ID `json:"application_id"`
	Kind          string    `json:"kind"`
	LocatorSHA256 string    `json:"locator_sha256"`
	Ref           string    `json:"ref,omitempty"`
	Commit        string    `json:"commit,omitempty"`
	ContentDigest string    `json:"content_digest"`
	CreatedAt     time.Time `json:"created_at"`
	Immutable     bool      `json:"immutable"`
}

func ProjectAcornFoxInputRevision(revision domain.SourceRevision) (AcornFoxInputRevision, error) {
	if err := revision.Validate(); err != nil {
		return AcornFoxInputRevision{}, fmt.Errorf("authoritative source revision: %w", err)
	}
	return AcornFoxInputRevision{
		ID: revision.ID, ApplicationID: revision.ApplicationID, Kind: string(revision.Kind),
		LocatorSHA256: acornFoxSHA256(revision.Locator), Ref: revision.Ref, Commit: revision.Commit,
		ContentDigest: revision.ContentDigest, CreatedAt: revision.CreatedAt.UTC(), Immutable: revision.Immutable,
	}, nil
}

// AcornFoxDefinitionSummary deliberately exposes counts only. Current
// ApplicationDeliveryDefinition facts and observations have arbitrary generic
// metadata, so a façade must not turn their names, sources, statuses, or values
// into a public AcornFox deployment contract.
type AcornFoxDefinitionSummary struct {
	ID                  domain.ID `json:"id"`
	ApplicationID       domain.ID `json:"application_id"`
	InputRevisionID     domain.ID `json:"input_revision_id"`
	Version             int       `json:"version"`
	FactCount           int       `json:"fact_count"`
	ObservationCount    int       `json:"observation_count"`
	RecommendationCount int       `json:"recommendation_count"`
	CreatedAt           time.Time `json:"created_at"`
	Immutable           bool      `json:"immutable"`
}

func ProjectAcornFoxDefinitionSummary(definition domain.ApplicationDeliveryDefinition) (AcornFoxDefinitionSummary, error) {
	if err := definition.Validate(); err != nil {
		return AcornFoxDefinitionSummary{}, fmt.Errorf("authoritative delivery definition: %w", err)
	}
	return AcornFoxDefinitionSummary{
		ID: definition.ID, ApplicationID: definition.ApplicationID, InputRevisionID: definition.SourceRevisionID,
		Version: definition.Version, FactCount: len(definition.Facts), ObservationCount: len(definition.Observations),
		RecommendationCount: len(definition.Recommendations), CreatedAt: definition.CreatedAt.UTC(), Immutable: definition.Immutable,
	}, nil
}

type AcornFoxArtifactImage struct {
	Service    string `json:"service"`
	Repository string `json:"repository"`
	Digest     string `json:"digest"`
}

// AcornFoxObservedArtifact is partial evidence only: it proves an artifact's
// image agrees with a release digest, not its M2 binding provenance or whether
// it is the complete artifact set.
type AcornFoxObservedArtifact struct {
	ID         domain.ID `json:"id"`
	BuildID    domain.ID `json:"build_id"`
	Repository string    `json:"repository"`
	Digest     string    `json:"digest"`
	SizeBytes  int64     `json:"size_bytes"`
	CreatedAt  time.Time `json:"created_at"`
}

// AcornFoxReleaseDigestSnapshot projects only the immutable image digest map
// carried by one Release. It does not claim a definition association, complete
// M2 provenance, or an ArtifactSet.
type AcornFoxReleaseDigestSnapshot struct {
	ReleaseID         domain.ID                  `json:"release_id"`
	ApplicationID     domain.ID                  `json:"application_id"`
	Version           int                        `json:"version"`
	ConfigDigest      string                     `json:"config_digest"`
	Images            []AcornFoxArtifactImage    `json:"images"`
	ObservedArtifacts []AcornFoxObservedArtifact `json:"observed_artifacts"`
	CreatedAt         time.Time                  `json:"created_at"`
	Immutable         bool                       `json:"immutable"`
}

func ProjectAcornFoxReleaseDigestSnapshot(release domain.Release, observed []domain.Artifact) (AcornFoxReleaseDigestSnapshot, error) {
	if err := release.Validate(); err != nil || !release.IsImmutable() {
		return AcornFoxReleaseDigestSnapshot{}, fmt.Errorf("authoritative release is invalid or mutable")
	}
	images := release.ServiceDigests()
	services := make([]string, 0, len(images))
	for service := range images {
		services = append(services, service)
	}
	sort.Strings(services)
	projectedImages := make([]AcornFoxArtifactImage, 0, len(services))
	for _, service := range services {
		image := images[service]
		projectedImages = append(projectedImages, AcornFoxArtifactImage{Service: service, Repository: image.Repository, Digest: image.Digest})
	}
	projectedArtifacts := make([]AcornFoxObservedArtifact, 0, len(observed))
	seenArtifacts := make(map[domain.ID]struct{}, len(observed))
	for _, artifact := range observed {
		if err := artifact.Validate(); err != nil {
			return AcornFoxReleaseDigestSnapshot{}, fmt.Errorf("authoritative artifact: %w", err)
		}
		if _, exists := seenArtifacts[artifact.ID]; exists {
			return AcornFoxReleaseDigestSnapshot{}, fmt.Errorf("duplicate authoritative artifact")
		}
		seenArtifacts[artifact.ID] = struct{}{}
		if !releaseContainsImage(images, artifact.Image) {
			return AcornFoxReleaseDigestSnapshot{}, fmt.Errorf("observed artifact image is absent from release digest snapshot")
		}
		projectedArtifacts = append(projectedArtifacts, AcornFoxObservedArtifact{ID: artifact.ID, BuildID: artifact.BuildID, Repository: artifact.Image.Repository, Digest: artifact.Image.Digest, SizeBytes: artifact.SizeBytes, CreatedAt: artifact.CreatedAt.UTC()})
	}
	sort.Slice(projectedArtifacts, func(i, j int) bool { return projectedArtifacts[i].ID < projectedArtifacts[j].ID })
	return AcornFoxReleaseDigestSnapshot{ReleaseID: release.ID, ApplicationID: release.ApplicationID, Version: release.Version, ConfigDigest: release.ConfigDigest, Images: projectedImages, ObservedArtifacts: projectedArtifacts, CreatedAt: release.CreatedAt.UTC(), Immutable: release.IsImmutable()}, nil
}

func releaseContainsImage(images map[string]domain.ImageDigest, artifact domain.ImageDigest) bool {
	for _, image := range images {
		if image.Repository == artifact.Repository && image.Digest == artifact.Digest {
			return true
		}
	}
	return false
}

type AcornFoxDeploymentRuntimeStage string

const (
	AcornFoxDeploymentStarting        AcornFoxDeploymentRuntimeStage = "starting"
	AcornFoxDeploymentRuntimeObserved AcornFoxDeploymentRuntimeStage = "runtime_observed"
	AcornFoxDeploymentFailed          AcornFoxDeploymentRuntimeStage = "failed"
	AcornFoxDeploymentUnknown         AcornFoxDeploymentRuntimeStage = "unknown"
)

// AcornFoxDeploymentRuntimeState is a projection of one Deployment only. Its
// runtime_observed state is deliberately weaker than internal readiness: no
// current input supplies an authoritative HTTP/TCP response probe.
type AcornFoxDeploymentRuntimeState struct {
	ID            domain.ID                      `json:"id"`
	ApplicationID domain.ID                      `json:"application_id"`
	EnvironmentID domain.ID                      `json:"environment_id"`
	ReleaseID     domain.ID                      `json:"release_id"`
	Stage         AcornFoxDeploymentRuntimeStage `json:"stage"`
	CreatedAt     time.Time                      `json:"created_at"`
	UpdatedAt     time.Time                      `json:"updated_at"`
}

func ProjectAcornFoxDeploymentRuntimeState(deployment domain.Deployment) (AcornFoxDeploymentRuntimeState, error) {
	if err := deployment.Validate(); err != nil {
		return AcornFoxDeploymentRuntimeState{}, fmt.Errorf("authoritative deployment: %w", err)
	}
	return AcornFoxDeploymentRuntimeState{ID: deployment.ID, ApplicationID: deployment.ApplicationID, EnvironmentID: deployment.EnvironmentID, ReleaseID: deployment.ReleaseID, Stage: projectDeploymentRuntimeStage(deployment.Status), CreatedAt: deployment.CreatedAt.UTC(), UpdatedAt: deployment.UpdatedAt.UTC()}, nil
}

func projectDeploymentRuntimeStage(status domain.DeploymentStatus) AcornFoxDeploymentRuntimeStage {
	switch status {
	case domain.DeploymentPending, domain.DeploymentPreparing, domain.DeploymentDeploying:
		return AcornFoxDeploymentStarting
	case domain.DeploymentRuntimeReady, domain.DeploymentDegraded, domain.DeploymentServing:
		return AcornFoxDeploymentRuntimeObserved
	case domain.DeploymentFailed:
		return AcornFoxDeploymentFailed
	default:
		return AcornFoxDeploymentUnknown
	}
}

func acornFoxSHA256(value string) string {
	digest := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(digest[:])
}

type AcornFoxLegacyRouteClass string

const (
	AcornFoxLegacyRouteRollback  AcornFoxLegacyRouteClass = "rollback"
	AcornFoxLegacyRouteRolling   AcornFoxLegacyRouteClass = "rolling"
	AcornFoxLegacyRouteScale     AcornFoxLegacyRouteClass = "scale"
	AcornFoxLegacyRouteM2        AcornFoxLegacyRouteClass = "m2_aggregate"
	AcornFoxLegacyRouteLifecycle AcornFoxLegacyRouteClass = "m2_lifecycle"
	AcornFoxLegacyRouteTombstone AcornFoxLegacyRouteClass = "tombstone"
)

type AcornFoxLegacyRoute struct {
	Path  string                   `json:"path"`
	Class AcornFoxLegacyRouteClass `json:"class"`
}

// AcornFoxPublicRouteInventory is the small clean-install HTTP surface. It is
// intentionally independent from the historical Open Card OpenAPI document;
// callers use it to cross-check the standalone AcornFox document and router.
var acornFoxPublicRoutes = [...]AcornFoxPublicRoute{
	{Path: "/api/v1/acornfox/auth/login", Methods: []string{"post"}},
	{Path: "/api/v1/acornfox/auth/logout", Methods: []string{"post"}},
	{Path: "/api/v1/acornfox/auth/session", Methods: []string{"get"}},
	{Path: "/api/v1/acornfox/auth/password", Methods: []string{"post"}},
	{Path: "/api/v1/acornfox/apps", Methods: []string{"get", "post"}},
	{Path: "/api/v1/acornfox/apps/{applicationId}", Methods: []string{"get"}},
	{Path: "/api/v1/acornfox/apps/{applicationId}/sources/{sourceRevisionId}", Methods: []string{"get"}},
	{Path: "/api/v1/acornfox/apps/{applicationId}/deliveries", Methods: []string{"post"}},
	{Path: "/api/v1/acornfox/apps/{applicationId}/deliveries/{deploymentId}", Methods: []string{"get"}},
	{Path: "/api/v1/acornfox/apps/{applicationId}/deliveries/{deploymentId}/restart", Methods: []string{"post"}},
	{Path: "/api/v1/acornfox/apps/{applicationId}/deliveries/{deploymentId}/redeploy", Methods: []string{"post"}},
	{Path: "/api/v1/acornfox/apps/{applicationId}/deliveries/{deploymentId}/probes", Methods: []string{"post"}},
	{Path: "/api/v1/acornfox/apps/{applicationId}/deliveries/{deploymentId}/logs", Methods: []string{"get"}},
}

type AcornFoxPublicRoute struct {
	Path    string
	Methods []string
}

func AcornFoxPublicRouteInventory() []string {
	items := make([]string, len(acornFoxPublicRoutes))
	for index, route := range acornFoxPublicRoutes {
		items[index] = route.Path
	}
	return items
}

func AcornFoxPublicRouteMethodInventory() []AcornFoxPublicRoute {
	items := make([]AcornFoxPublicRoute, len(acornFoxPublicRoutes))
	for index, route := range acornFoxPublicRoutes {
		items[index] = AcornFoxPublicRoute{Path: route.Path, Methods: append([]string(nil), route.Methods...)}
	}
	return items
}

// acornFoxMigrationOnlyRoutes is a hand-audited immutable snapshot of the
// current OpenAPI, handleM2, and M2LifecycleHandler.Handle surfaces. The
// OpenAPI does not publish a scale endpoint; scale remains an internal legacy
// capability and is still forbidden from a future clean public spec.
var acornFoxMigrationOnlyRoutes = [...]AcornFoxLegacyRoute{
	{Path: "/api/v1/publishes", Class: AcornFoxLegacyRouteTombstone},
	{Path: "/api/v1/applications/{applicationId}/operations", Class: AcornFoxLegacyRouteRollback},
	{Path: "/api/v1/operations/views/{applicationId}", Class: AcornFoxLegacyRouteRollback},
	{Path: "/api/v1/operations/{action}", Class: AcornFoxLegacyRouteRollback},
	{Path: "/api/v1/access/traffic-switches", Class: AcornFoxLegacyRouteRolling},
	{Path: "/api/v1/service-groups/{serviceGroupId}/releases", Class: AcornFoxLegacyRouteRolling},
	{Path: "/api/v1/agents/capabilities", Class: AcornFoxLegacyRouteM2},
	{Path: "/api/v1/agents/capabilities/legacy-negative", Class: AcornFoxLegacyRouteM2},
	{Path: "/api/v1/sources", Class: AcornFoxLegacyRouteM2},
	{Path: "/api/v1/service-groups/import", Class: AcornFoxLegacyRouteM2},
	{Path: "/api/v1/images/resolve", Class: AcornFoxLegacyRouteM2},
	{Path: "/api/v1/service-groups/{serviceGroupId}/deployments", Class: AcornFoxLegacyRouteM2},
	{Path: "/api/v1/deployments/{deploymentId}", Class: AcornFoxLegacyRouteM2},
	{Path: "/api/v1/deployments/{deploymentId}/events", Class: AcornFoxLegacyRouteM2},
	{Path: "/api/v1/deployments/{deploymentId}/destroy", Class: AcornFoxLegacyRouteM2},
	{Path: "/api/v1/rollouts/{releaseId}", Class: AcornFoxLegacyRouteRolling},
	{Path: "/api/v1/releases/{releaseId}/volumes", Class: AcornFoxLegacyRouteLifecycle},
	{Path: "/api/v1/releases/{releaseId}/volumes/{claimId}/destroy", Class: AcornFoxLegacyRouteLifecycle},
	{Path: "/api/v1/images/gc", Class: AcornFoxLegacyRouteLifecycle},
}

func AcornFoxMigrationOnlyRouteInventory() []AcornFoxLegacyRoute {
	items := make([]AcornFoxLegacyRoute, len(acornFoxMigrationOnlyRoutes))
	copy(items, acornFoxMigrationOnlyRoutes[:])
	return items
}

// InventoryOpenAPIPaths extracts top-level path keys from the repository's
// constrained OpenAPI YAML shape without accepting operation content as input.
func InventoryOpenAPIPaths(raw string) []string {
	paths := make([]string, 0)
	for _, line := range strings.Split(raw, "\n") {
		if !strings.HasPrefix(line, "  /") || !strings.HasSuffix(strings.TrimSpace(line), ":") || strings.HasPrefix(line, "    ") {
			continue
		}
		paths = append(paths, strings.TrimSuffix(strings.TrimSpace(line), ":"))
	}
	sort.Strings(paths)
	return paths
}

// InventoryOpenAPIRouteMethods extracts only top-level path operations from
// the constrained repository OpenAPI shape. It intentionally ignores schema
// content, so a generated client cannot disguise a method/path mismatch.
func InventoryOpenAPIRouteMethods(raw string) map[string][]string {
	items := make(map[string][]string)
	current := ""
	for _, line := range strings.Split(raw, "\n") {
		if strings.HasPrefix(line, "  /") && strings.HasSuffix(strings.TrimSpace(line), ":") && !strings.HasPrefix(line, "    ") {
			current = strings.TrimSuffix(strings.TrimSpace(line), ":")
			items[current] = []string{}
			continue
		}
		if current == "" || !strings.HasPrefix(line, "    ") || strings.HasPrefix(line, "      ") {
			continue
		}
		method := strings.SplitN(strings.TrimSpace(line), ":", 2)[0]
		if method == "get" || method == "post" || method == "put" || method == "patch" || method == "delete" {
			items[current] = append(items[current], method)
		}
	}
	for path := range items {
		sort.Strings(items[path])
	}
	return items
}

// ValidateAcornFoxCleanInstallRoutes is the future clean-install leakage guard.
// It compares route templates semantically: parameter names and a terminal
// slash cannot bypass the migration-only inventory.
func ValidateAcornFoxCleanInstallRoutes(paths []string) error {
	present := make(map[string]struct{}, len(paths))
	for _, path := range paths {
		present[canonicalAcornFoxRoutePath(path)] = struct{}{}
	}
	leaks := make([]string, 0)
	for _, route := range acornFoxMigrationOnlyRoutes {
		if _, ok := present[canonicalAcornFoxRoutePath(route.Path)]; ok {
			leaks = append(leaks, route.Path)
		}
	}
	if len(leaks) != 0 {
		sort.Strings(leaks)
		return fmt.Errorf("acornfox clean-install public route leakage: %s", strings.Join(leaks, ","))
	}
	return nil
}

func canonicalAcornFoxRoutePath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	path = strings.TrimRight(path, "/")
	if path == "" {
		return "/"
	}
	parts := strings.Split(path, "/")
	for index, part := range parts {
		if len(part) >= 2 && strings.HasPrefix(part, "{") && strings.HasSuffix(part, "}") {
			parts[index] = "{}"
		}
	}
	return strings.Join(parts, "/")
}
