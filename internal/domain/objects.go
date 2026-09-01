package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"
)

type SourceKind string

const (
	SourceGitHTTPS SourceKind = "git_https"
	SourceGitSSH   SourceKind = "git_ssh"
	SourceUpload   SourceKind = "upload"
)

type EvidenceRef struct {
	ID      ID     `json:"id"`
	Kind    string `json:"kind"`
	Digest  string `json:"digest,omitempty"`
	Locator string `json:"locator,omitempty"`
}

func (e EvidenceRef) Validate() error {
	if e.ID.Empty() {
		return ValidationError("evidence id is required")
	}
	if strings.TrimSpace(e.Kind) == "" {
		return ValidationError("evidence kind is required")
	}
	return nil
}

type Application struct {
	ID        ID        `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func NewApplication(name string, now time.Time) (Application, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return Application{}, ValidationError("application name is required")
	}
	id, err := NewID("app")
	if err != nil {
		return Application{}, WrapError(ErrUnavailable, "generate application id", err)
	}
	return Application{ID: id, Name: name, CreatedAt: now.UTC(), UpdatedAt: now.UTC()}, nil
}

func (a Application) Validate() error {
	if err := RequireID(a.ID, "application id"); err != nil {
		return err
	}
	if strings.TrimSpace(a.Name) == "" {
		return ValidationError("application name is required")
	}
	return nil
}

type Environment struct {
	ID            ID        `json:"id"`
	ApplicationID ID        `json:"application_id"`
	Name          string    `json:"name"`
	NodeID        ID        `json:"node_id"`
	CreatedAt     time.Time `json:"created_at"`
}

func (e Environment) Validate() error {
	if err := RequireID(e.ID, "environment id"); err != nil {
		return err
	}
	if err := RequireID(e.ApplicationID, "environment application id"); err != nil {
		return err
	}
	if strings.TrimSpace(e.Name) == "" {
		return ValidationError("environment name is required")
	}
	if err := RequireID(e.NodeID, "environment node id"); err != nil {
		return err
	}
	return nil
}

// SourceRevision is the immutable, content-addressed input to a build.
type SourceRevision struct {
	ID            ID         `json:"id"`
	ApplicationID ID         `json:"application_id"`
	Kind          SourceKind `json:"kind"`
	Locator       string     `json:"locator"`
	Ref           string     `json:"ref,omitempty"`
	Commit        string     `json:"commit,omitempty"`
	ContentDigest string     `json:"content_digest"`
	WorkspaceRef  string     `json:"workspace_ref"`
	CreatedAt     time.Time  `json:"created_at"`
	Immutable     bool       `json:"immutable"`
}

func NewSourceRevision(applicationID ID, kind SourceKind, locator, ref, commit, contentDigest, workspaceRef string, now time.Time) (SourceRevision, error) {
	id, err := NewID("src")
	if err != nil {
		return SourceRevision{}, WrapError(ErrUnavailable, "generate source revision id", err)
	}
	revision := SourceRevision{
		ID: id, ApplicationID: applicationID, Kind: kind, Locator: strings.TrimSpace(locator),
		Ref: strings.TrimSpace(ref), Commit: strings.TrimSpace(commit), ContentDigest: strings.TrimSpace(contentDigest),
		WorkspaceRef: strings.TrimSpace(workspaceRef), CreatedAt: now.UTC(), Immutable: true,
	}
	if err := revision.Validate(); err != nil {
		return SourceRevision{}, err
	}
	return revision, nil
}

func (s SourceRevision) Validate() error {
	if err := RequireID(s.ID, "source revision id"); err != nil {
		return err
	}
	if err := RequireID(s.ApplicationID, "source revision application id"); err != nil {
		return err
	}
	if s.Kind != SourceGitHTTPS && s.Kind != SourceGitSSH && s.Kind != SourceUpload {
		return ValidationError("source revision kind is unsupported")
	}
	if s.Locator == "" {
		return ValidationError("source revision locator is required")
	}
	if s.Kind == SourceGitHTTPS || s.Kind == SourceGitSSH {
		if err := validateGitLocator(s.Kind, s.Locator); err != nil {
			return err
		}
		if s.Commit == "" {
			return ValidationError("git source revision commit is required")
		}
	}
	if s.ContentDigest == "" {
		return ValidationError("source revision content digest is required")
	}
	if s.WorkspaceRef == "" {
		return ValidationError("source revision workspace reference is required")
	}
	if !s.Immutable {
		return ValidationError("source revision must be immutable")
	}
	return nil
}

func validateGitLocator(kind SourceKind, locator string) error {
	if kind == SourceGitSSH {
		if strings.Contains(locator, " ") || !strings.Contains(locator, "@") {
			return ValidationError("git ssh locator is invalid")
		}
		return nil
	}
	u, err := url.Parse(locator)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return ValidationError("git https locator is invalid")
	}
	return nil
}

type FactSource string

const (
	FactSourceRepository  FactSource = "repository"
	FactSourcePlatform    FactSource = "platform_default"
	FactSourceUser        FactSource = "user_decision"
	FactSourceAI          FactSource = "ai_inference"
	FactSourceObservation FactSource = "observation"
)

type FactStatus string

const (
	FactUnknown   FactStatus = "unknown"
	FactProposed  FactStatus = "proposed"
	FactConfirmed FactStatus = "confirmed"
	FactBlocked   FactStatus = "blocked"
	FactObserved  FactStatus = "observed"
)

// FieldFact carries configuration metadata. A field inferred automatically is
// invalid without source, confidence, evidence, and status.
type FieldFact struct {
	Value      any           `json:"value"`
	Source     FactSource    `json:"source"`
	Confidence float64       `json:"confidence"`
	Evidence   []EvidenceRef `json:"evidence"`
	Status     FactStatus    `json:"status"`
}

func (f FieldFact) Validate() error {
	if f.Source == "" {
		return ValidationError("fact source is required")
	}
	if f.Confidence < 0 || f.Confidence > 1 {
		return ValidationError("fact confidence must be between 0 and 1")
	}
	if f.Status == "" {
		return ValidationError("fact status is required")
	}
	if f.Source == FactSourceAI || f.Source == FactSourceRepository || f.Source == FactSourcePlatform {
		if len(f.Evidence) == 0 {
			return ValidationError("automatic fact requires evidence")
		}
	}
	for _, evidence := range f.Evidence {
		if err := evidence.Validate(); err != nil {
			return err
		}
	}
	return nil
}

type Observation struct {
	ID         ID            `json:"id"`
	TargetRef  string        `json:"target_ref"`
	Kind       string        `json:"kind"`
	Value      any           `json:"value"`
	Source     string        `json:"source"`
	ObservedAt time.Time     `json:"observed_at"`
	Evidence   []EvidenceRef `json:"evidence"`
}

func (o Observation) Validate() error {
	if err := RequireID(o.ID, "observation id"); err != nil {
		return err
	}
	if strings.TrimSpace(o.TargetRef) == "" || strings.TrimSpace(o.Kind) == "" || strings.TrimSpace(o.Source) == "" {
		return ValidationError("observation target, kind, and source are required")
	}
	for _, e := range o.Evidence {
		if err := e.Validate(); err != nil {
			return err
		}
	}
	return nil
}

type RecommendationStatus string

const (
	RecommendationOpen      RecommendationStatus = "open"
	RecommendationAccepted  RecommendationStatus = "accepted"
	RecommendationDismissed RecommendationStatus = "dismissed"
)

// Recommendation is advisory only. It deliberately has no setter that can
// mutate Configuration/Facts on ApplicationDeliveryDefinition.
type Recommendation struct {
	ID        ID                   `json:"id"`
	TargetRef string               `json:"target_ref"`
	Reason    string               `json:"reason"`
	Proposed  any                  `json:"proposed,omitempty"`
	Evidence  []EvidenceRef        `json:"evidence"`
	Status    RecommendationStatus `json:"status"`
	CreatedAt time.Time            `json:"created_at"`
}

func (r Recommendation) Validate() error {
	if err := RequireID(r.ID, "recommendation id"); err != nil {
		return err
	}
	if r.TargetRef == "" || r.Reason == "" {
		return ValidationError("recommendation target and reason are required")
	}
	if r.Status == "" {
		return ValidationError("recommendation status is required")
	}
	for _, e := range r.Evidence {
		if err := e.Validate(); err != nil {
			return err
		}
	}
	return nil
}

type ApplicationDeliveryDefinition struct {
	ID               ID                   `json:"id"`
	ApplicationID    ID                   `json:"application_id"`
	SourceRevisionID ID                   `json:"source_revision_id"`
	Version          int                  `json:"version"`
	Facts            map[string]FieldFact `json:"facts"`
	Observations     []Observation        `json:"observations,omitempty"`
	Recommendations  []Recommendation     `json:"recommendations,omitempty"`
	CreatedAt        time.Time            `json:"created_at"`
	Immutable        bool                 `json:"immutable"`
}

func NewApplicationDeliveryDefinition(applicationID, sourceRevisionID ID, version int, facts map[string]FieldFact, now time.Time) (*ApplicationDeliveryDefinition, error) {
	id, err := NewID("def")
	if err != nil {
		return nil, WrapError(ErrUnavailable, "generate delivery definition id", err)
	}
	copyFacts := make(map[string]FieldFact, len(facts))
	for name, fact := range facts {
		fact.Evidence = append([]EvidenceRef(nil), fact.Evidence...)
		copyFacts[name] = fact
	}
	definition := &ApplicationDeliveryDefinition{ID: id, ApplicationID: applicationID, SourceRevisionID: sourceRevisionID, Version: version, Facts: copyFacts, CreatedAt: now.UTC(), Immutable: true}
	if err := definition.Validate(); err != nil {
		return nil, err
	}
	return definition, nil
}

func (d ApplicationDeliveryDefinition) Validate() error {
	if err := RequireID(d.ID, "delivery definition id"); err != nil {
		return err
	}
	if err := RequireID(d.ApplicationID, "delivery definition application id"); err != nil {
		return err
	}
	if err := RequireID(d.SourceRevisionID, "delivery definition source revision id"); err != nil {
		return err
	}
	if d.Version < 1 {
		return ValidationError("delivery definition version must be positive")
	}
	if !d.Immutable {
		return ValidationError("delivery definition must be immutable")
	}
	for name, fact := range d.Facts {
		if strings.TrimSpace(name) == "" {
			return ValidationError("delivery definition fact name is required")
		}
		if err := fact.Validate(); err != nil {
			return fmt.Errorf("fact %q: %w", name, err)
		}
	}
	for _, observation := range d.Observations {
		if err := observation.Validate(); err != nil {
			return err
		}
	}
	for _, recommendation := range d.Recommendations {
		if err := recommendation.Validate(); err != nil {
			return err
		}
	}
	return nil
}

func (d ApplicationDeliveryDefinition) ConfigFact(name string) (FieldFact, bool) {
	fact, ok := d.Facts[name]
	return fact, ok
}

type BuildKind string

const (
	BuildStatic     BuildKind = "static"
	BuildDockerfile BuildKind = "dockerfile"
)

type BuildPlan struct {
	ID                         ID                  `json:"id"`
	SourceRevisionID           ID                  `json:"source_revision_id"`
	SourceDigest               string              `json:"source_digest"`
	ServiceName                string              `json:"service_name"`
	Kind                       BuildKind           `json:"kind"`
	ContextPath                string              `json:"context_path"`
	DockerfilePath             string              `json:"dockerfile_path,omitempty"`
	StaticRuntimeDigest        string              `json:"static_runtime_digest,omitempty"`
	TargetRepository           string              `json:"target_repository"`
	Output                     BuildOutputContract `json:"output"`
	SecretRefs                 []SecretReference   `json:"secret_refs,omitempty"`
	IdempotencyKey             string              `json:"idempotency_key"`
	CreatedAt                  time.Time           `json:"created_at"`
	AcornFoxDefinitionDigest   string              `json:"acornfox_definition_digest,omitempty"`
	AcornFoxDockerfileDigest   string              `json:"acornfox_dockerfile_digest,omitempty"`
	AcornFoxNetworkMode        string              `json:"acornfox_network_mode,omitempty"`
	AcornFoxWorkerPolicyDigest string              `json:"acornfox_worker_policy_digest,omitempty"`
}

const (
	BuildOutputOCI        = "oci"
	BuildRetentionPersist = "persistent"
)

type BuildOutputContract struct {
	Format     string `json:"format"`
	Retention  string `json:"retention"`
	StorageKey string `json:"storage_key"`
}

func (o BuildOutputContract) Validate() error {
	if o.Format != BuildOutputOCI || o.Retention != BuildRetentionPersist {
		return ValidationError("build output must be persistent OCI")
	}
	key := strings.TrimSpace(o.StorageKey)
	if key == "" || strings.HasPrefix(key, "/") || strings.Contains(key, "..") || strings.ContainsAny(key, "\r\n\x00") {
		return ValidationError("build output storage key is invalid")
	}
	return nil
}

func (p BuildPlan) Validate() error {
	if err := RequireID(p.ID, "build plan id"); err != nil {
		return err
	}
	if err := RequireID(p.SourceRevisionID, "build plan source revision id"); err != nil {
		return err
	}
	if !strings.HasPrefix(p.SourceDigest, "sha256:") || len(strings.TrimPrefix(p.SourceDigest, "sha256:")) != sha256.Size*2 {
		return ValidationError("build plan source digest must be sha256")
	}
	if _, err := hex.DecodeString(strings.TrimPrefix(p.SourceDigest, "sha256:")); err != nil {
		return ValidationError("build plan source digest is not valid hex")
	}
	if strings.TrimSpace(p.ServiceName) == "" || strings.TrimSpace(p.ContextPath) == "" {
		return ValidationError("build plan service and context are required")
	}
	if p.Kind != BuildStatic && p.Kind != BuildDockerfile {
		return ValidationError("build plan kind is unsupported")
	}
	if p.Kind == BuildDockerfile && strings.TrimSpace(p.DockerfilePath) == "" {
		return ValidationError("dockerfile path is required")
	}
	if p.Kind == BuildStatic {
		if !validSHA256(p.StaticRuntimeDigest) {
			return ValidationError("static build platform runtime digest is required")
		}
	} else if p.StaticRuntimeDigest != "" {
		return ValidationError("dockerfile build cannot override the platform static runtime")
	}
	if !validImageRepository(p.TargetRepository) {
		return ValidationError("build target repository is invalid")
	}
	if err := p.Output.Validate(); err != nil {
		return err
	}
	seenSecrets := make(map[ID]struct{}, len(p.SecretRefs))
	for _, reference := range p.SecretRefs {
		if err := reference.Validate(); err != nil {
			return err
		}
		if _, exists := seenSecrets[reference.ID]; exists {
			return ValidationError("build secret references must be unique")
		}
		seenSecrets[reference.ID] = struct{}{}
	}
	if strings.TrimSpace(p.IdempotencyKey) == "" {
		return ValidationError("build plan idempotency key is required")
	}
	if (p.AcornFoxDefinitionDigest == "") != (p.AcornFoxDockerfileDigest == "") || p.AcornFoxDefinitionDigest != "" && (!validSHA256(p.AcornFoxDefinitionDigest) || !validSHA256(p.AcornFoxDockerfileDigest)) {
		return ValidationError("AcornFox build plan digests are invalid")
	}
	if !p.validAcornFoxNetworkPolicy() {
		return ValidationError("AcornFox build plan network policy is invalid")
	}
	if p.AcornFoxDefinitionDigest != "" && (p.Kind != BuildDockerfile || p.ContextPath != "." || p.DockerfilePath != "Dockerfile" || p.StaticRuntimeDigest != "") {
		return ValidationError("AcornFox build plan must bind the root Dockerfile")
	}
	return nil
}

// EffectiveAcornFoxNetworkPolicy keeps nullable historical rows offline while
// making the immutable network identity available to build providers.
func (p BuildPlan) EffectiveAcornFoxNetworkPolicy() (mode, workerPolicyDigest string) {
	if p.AcornFoxNetworkMode == "" {
		return "none", ""
	}
	return p.AcornFoxNetworkMode, p.AcornFoxWorkerPolicyDigest
}

func (p BuildPlan) validAcornFoxNetworkPolicy() bool {
	switch p.AcornFoxNetworkMode {
	case "":
		return p.AcornFoxWorkerPolicyDigest == ""
	case "none":
		return p.AcornFoxWorkerPolicyDigest == ""
	case "controlled_egress_v1":
		return validLowercaseSHA256(p.AcornFoxWorkerPolicyDigest) && p.AcornFoxDefinitionDigest != "" && p.AcornFoxDockerfileDigest != ""
	default:
		return false
	}
}

func validSHA256(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(strings.TrimPrefix(value, "sha256:")) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil
}

func validLowercaseSHA256(value string) bool {
	return validSHA256(value) && value == strings.ToLower(value)
}

type ImageDigest struct {
	Repository  string `json:"repository"`
	Digest      string `json:"digest"`
	ResolvedTag string `json:"resolved_tag,omitempty"`
}

func ParseImageDigest(repository, digest string) (ImageDigest, error) {
	repository = strings.TrimSpace(repository)
	digest = strings.TrimSpace(digest)
	if !validImageRepository(repository) || digest == "" {
		return ImageDigest{}, ValidationError("image repository and digest are required")
	}
	if !strings.HasPrefix(digest, "sha256:") || len(strings.TrimPrefix(digest, "sha256:")) != sha256.Size*2 {
		return ImageDigest{}, ValidationError("image digest must be a sha256 digest")
	}
	if _, err := hex.DecodeString(strings.TrimPrefix(digest, "sha256:")); err != nil {
		return ImageDigest{}, ValidationError("image digest is not valid hex")
	}
	return ImageDigest{Repository: repository, Digest: digest}, nil
}

func validImageRepository(repository string) bool {
	repository = strings.TrimSpace(repository)
	if repository == "" || strings.HasPrefix(repository, "/") || strings.HasSuffix(repository, "/") || strings.Contains(repository, "..") || strings.Contains(repository, "://") || strings.ContainsAny(repository, "@\r\n\x00 \t") {
		return false
	}
	for _, part := range strings.Split(repository, "/") {
		if part == "" {
			return false
		}
	}
	return true
}

func (d ImageDigest) Validate() error {
	_, err := ParseImageDigest(d.Repository, d.Digest)
	return err
}

type Artifact struct {
	ID            ID            `json:"id"`
	BuildID       ID            `json:"build_id"`
	Image         ImageDigest   `json:"image"`
	OCIStorageRef string        `json:"oci_storage_ref"`
	SizeBytes     int64         `json:"size_bytes"`
	Evidence      []EvidenceRef `json:"evidence"`
	CreatedAt     time.Time     `json:"created_at"`
}

func (a Artifact) Validate() error {
	if err := RequireID(a.ID, "artifact id"); err != nil {
		return err
	}
	if err := RequireID(a.BuildID, "artifact build id"); err != nil {
		return err
	}
	if err := a.Image.Validate(); err != nil {
		return err
	}
	if strings.TrimSpace(a.OCIStorageRef) == "" || a.SizeBytes <= 0 {
		return ValidationError("artifact persistent OCI reference and size are required")
	}
	for _, evidence := range a.Evidence {
		if err := evidence.Validate(); err != nil {
			return err
		}
	}
	return nil
}

type BuildStatus string

const (
	BuildPending   BuildStatus = "pending"
	BuildRunning   BuildStatus = "running"
	BuildSucceeded BuildStatus = "succeeded"
	BuildFailed    BuildStatus = "failed"
	BuildCancelled BuildStatus = "cancelled"
)

type Build struct {
	ID         ID          `json:"id"`
	PlanID     ID          `json:"plan_id"`
	Status     BuildStatus `json:"status"`
	ArtifactID ID          `json:"artifact_id,omitempty"`
	Failure    string      `json:"failure,omitempty"`
	CreatedAt  time.Time   `json:"created_at"`
	UpdatedAt  time.Time   `json:"updated_at"`
}

type ServiceRole string

const (
	RoleIngress  ServiceRole = "ingress"
	RoleWorker   ServiceRole = "worker"
	RoleStateful ServiceRole = "stateful"
	RoleOneShot  ServiceRole = "one_shot"
)

type ServiceSourceKind string

const (
	ServiceStatic     ServiceSourceKind = "static"
	ServiceDockerfile ServiceSourceKind = "dockerfile"
	ServicePrebuilt   ServiceSourceKind = "prebuilt"
)

type StaticSource struct {
	Directory string `json:"directory"`
}
type DockerfileSource struct {
	Context    string `json:"context"`
	Dockerfile string `json:"dockerfile"`
}
type PrebuiltSource struct {
	Image     ImageDigest `json:"image"`
	Reference string      `json:"reference,omitempty"`
}

type ServiceSource struct {
	Kind       ServiceSourceKind `json:"kind"`
	Static     *StaticSource     `json:"static,omitempty"`
	Dockerfile *DockerfileSource `json:"dockerfile,omitempty"`
	Prebuilt   *PrebuiltSource   `json:"prebuilt,omitempty"`
}

func (s ServiceSource) Validate() error {
	count := 0
	if s.Static != nil {
		count++
	}
	if s.Dockerfile != nil {
		count++
	}
	if s.Prebuilt != nil {
		count++
	}
	if count != 1 {
		return ValidationError("service source must contain exactly one source variant")
	}
	switch s.Kind {
	case ServiceStatic:
		if s.Static == nil || s.Dockerfile != nil || s.Prebuilt != nil || strings.TrimSpace(s.Static.Directory) == "" {
			return ValidationError("static source directory is required")
		}
	case ServiceDockerfile:
		if s.Dockerfile == nil || s.Static != nil || s.Prebuilt != nil || strings.TrimSpace(s.Dockerfile.Context) == "" || strings.TrimSpace(s.Dockerfile.Dockerfile) == "" {
			return ValidationError("dockerfile source context and path are required")
		}
	case ServicePrebuilt:
		if s.Prebuilt == nil || s.Static != nil || s.Dockerfile != nil {
			return ValidationError("prebuilt source is required")
		}
		if strings.TrimSpace(s.Prebuilt.Reference) != "" {
			if strings.ContainsAny(s.Prebuilt.Reference, "\r\n\x00") {
				return ValidationError("prebuilt image reference contains invalid characters")
			}
			if s.Prebuilt.Image.Repository != "" || s.Prebuilt.Image.Digest != "" {
				return ValidationError("prebuilt source must contain either a resolved image or a reference")
			}
			return nil
		}
		if err := s.Prebuilt.Image.Validate(); err != nil {
			return err
		}
	default:
		return ValidationError("service source kind is unsupported")
	}
	return nil
}

type DependencyCondition string

const (
	DependsStarted   DependencyCondition = "started"
	DependsHealthy   DependencyCondition = "healthy"
	DependsCompleted DependencyCondition = "completed"
)

type ServiceDependency struct {
	Service   string              `json:"service"`
	Condition DependencyCondition `json:"condition"`
}

type ServiceSpec struct {
	Name         string              `json:"name"`
	Role         ServiceRole         `json:"role"`
	Source       ServiceSource       `json:"source"`
	Dependencies []ServiceDependency `json:"dependencies,omitempty"`
	Entrypoint   []string            `json:"entrypoint,omitempty"`
	Command      []string            `json:"command,omitempty"`
	Environment  map[string]string   `json:"environment,omitempty"`
	Volumes      []VolumeMount       `json:"volumes,omitempty"`
	Healthcheck  *HealthcheckSpec    `json:"healthcheck,omitempty"`
	Restart      string              `json:"restart,omitempty"`
	Resources    ResourceLimits      `json:"resources,omitempty"`
	Networks     []string            `json:"networks,omitempty"`
	Port         int                 `json:"port,omitempty"`
	Ports        []int               `json:"ports,omitempty"`
	Required     bool                `json:"required"`
}

func (s ServiceSpec) Validate() error {
	if strings.TrimSpace(s.Name) == "" {
		return ValidationError("service name is required")
	}
	if s.Role != RoleIngress && s.Role != RoleWorker && s.Role != RoleStateful && s.Role != RoleOneShot {
		return ValidationError("service role is unsupported")
	}
	if err := s.Source.Validate(); err != nil {
		return err
	}
	if s.Port < 0 || s.Port > 65535 {
		return ValidationError("service port must be between 0 and 65535")
	}
	for _, port := range s.Ports {
		if port < 1 || port > 65535 {
			return ValidationError("service ports must be between 1 and 65535")
		}
	}
	for name, value := range s.Environment {
		if strings.TrimSpace(name) == "" {
			return ValidationError("service environment name is required")
		}
		if strings.Contains(name, "=") {
			return ValidationError("service environment name must not contain equals")
		}
		if value != "" && sensitiveEnvironmentName(name) {
			return ValidationError("sensitive service environment values require a SecretReference")
		}
	}
	for _, volume := range s.Volumes {
		if err := volume.Validate(); err != nil {
			return err
		}
	}
	if s.Healthcheck != nil {
		if err := s.Healthcheck.Validate(); err != nil {
			return err
		}
	}
	if s.Restart != "" && !validRestartPolicy(s.Restart) {
		return ValidationError("service restart policy is unsupported")
	}
	if err := s.Resources.Validate(); err != nil {
		return err
	}
	seenNetworks := make(map[string]struct{}, len(s.Networks))
	for _, network := range s.Networks {
		network = strings.TrimSpace(network)
		if network == "" {
			return ValidationError("service network name is required")
		}
		if _, ok := seenNetworks[network]; ok {
			return ValidationError("service network names must be unique")
		}
		seenNetworks[network] = struct{}{}
	}
	for _, dep := range s.Dependencies {
		if strings.TrimSpace(dep.Service) == "" || dep.Service == s.Name {
			return ValidationError("service dependency target is invalid")
		}
		if dep.Condition != DependsStarted && dep.Condition != DependsHealthy && dep.Condition != DependsCompleted {
			return ValidationError("service dependency condition is unsupported")
		}
	}
	return nil
}

func sensitiveEnvironmentName(name string) bool {
	upper := strings.ToUpper(strings.TrimSpace(name))
	for _, marker := range []string{"TOKEN", "PASSWORD", "SECRET", "COOKIE", "AUTHORIZATION", "API_KEY", "PRIVATE_KEY"} {
		if upper == marker || strings.HasPrefix(upper, marker+"_") || strings.HasSuffix(upper, "_"+marker) || strings.Contains(upper, "_"+marker+"_") {
			return true
		}
	}
	return false
}

type ServiceGroup struct {
	ID            ID            `json:"id"`
	ApplicationID ID            `json:"application_id"`
	Name          string        `json:"name"`
	Services      []ServiceSpec `json:"services"`
	CreatedAt     time.Time     `json:"created_at"`
}

func (g ServiceGroup) Validate() error {
	if err := RequireID(g.ID, "service group id"); err != nil {
		return err
	}
	if err := RequireID(g.ApplicationID, "service group application id"); err != nil {
		return err
	}
	if len(g.Services) == 0 {
		return ValidationError("service group must contain a service")
	}
	names := make(map[string]struct{}, len(g.Services))
	for _, service := range g.Services {
		if err := service.Validate(); err != nil {
			return fmt.Errorf("service %q: %w", service.Name, err)
		}
		if _, ok := names[service.Name]; ok {
			return ValidationError("service names must be unique")
		}
		names[service.Name] = struct{}{}
	}
	for _, service := range g.Services {
		for _, dep := range service.Dependencies {
			if _, ok := names[dep.Service]; !ok {
				return ValidationError("service dependency target does not exist")
			}
		}
	}
	return nil
}

// DependencyOrder returns a deterministic topological order and rejects
// cycles. The order is grouped by the declared dependency graph, not by fixed
// sleeps or provider-specific readiness behavior.
func (g ServiceGroup) DependencyOrder() ([]string, error) {
	if err := g.Validate(); err != nil {
		return nil, err
	}
	indegree := make(map[string]int, len(g.Services))
	out := make(map[string][]string, len(g.Services))
	for _, service := range g.Services {
		indegree[service.Name] = 0
	}
	for _, service := range g.Services {
		for _, dep := range service.Dependencies {
			indegree[service.Name]++
			out[dep.Service] = append(out[dep.Service], service.Name)
		}
	}
	queue := make([]string, 0, len(indegree))
	for name, degree := range indegree {
		if degree == 0 {
			queue = append(queue, name)
		}
	}
	sort.Strings(queue)
	order := make([]string, 0, len(indegree))
	for len(queue) > 0 {
		name := queue[0]
		queue = queue[1:]
		order = append(order, name)
		children := out[name]
		sort.Strings(children)
		for _, child := range children {
			indegree[child]--
			if indegree[child] == 0 {
				queue = append(queue, child)
				sort.Strings(queue)
			}
		}
	}
	if len(order) != len(indegree) {
		return nil, ValidationError("service dependency graph contains a cycle")
	}
	return order, nil
}

// Release freezes a complete service digest set. The map is private so callers
// cannot mutate a frozen release through an alias.
type Release struct {
	ID             ID            `json:"id"`
	ApplicationID  ID            `json:"application_id"`
	ServiceGroupID ID            `json:"service_group_id"`
	Version        int           `json:"version"`
	ConfigDigest   string        `json:"config_digest"`
	Status         ReleaseStatus `json:"status"`
	CreatedAt      time.Time     `json:"created_at"`
	immutable      bool
	digests        map[string]ImageDigest
}

// MarshalJSON keeps the private digest set visible in API responses without
// exposing a mutable map on the Go value itself.
func (r Release) MarshalJSON() ([]byte, error) {
	type releaseJSON struct {
		ID             ID                     `json:"id"`
		ApplicationID  ID                     `json:"application_id"`
		ServiceGroupID ID                     `json:"service_group_id"`
		Version        int                    `json:"version"`
		ConfigDigest   string                 `json:"config_digest"`
		Status         ReleaseStatus          `json:"status"`
		ServiceDigests map[string]ImageDigest `json:"service_digests"`
		CreatedAt      time.Time              `json:"created_at"`
		Immutable      bool                   `json:"immutable"`
	}
	return json.Marshal(releaseJSON{ID: r.ID, ApplicationID: r.ApplicationID, ServiceGroupID: r.ServiceGroupID, Version: r.Version, ConfigDigest: r.ConfigDigest, Status: r.Status, ServiceDigests: r.ServiceDigests(), CreatedAt: r.CreatedAt, Immutable: r.immutable})
}

func (r *Release) UnmarshalJSON(data []byte) error {
	type releaseJSON struct {
		ID             ID                     `json:"id"`
		ApplicationID  ID                     `json:"application_id"`
		ServiceGroupID ID                     `json:"service_group_id"`
		Version        int                    `json:"version"`
		ConfigDigest   string                 `json:"config_digest"`
		Status         ReleaseStatus          `json:"status"`
		ServiceDigests map[string]ImageDigest `json:"service_digests"`
		CreatedAt      time.Time              `json:"created_at"`
		Immutable      bool                   `json:"immutable"`
	}
	var value releaseJSON
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	copyDigests := make(map[string]ImageDigest, len(value.ServiceDigests))
	for name, digest := range value.ServiceDigests {
		copyDigests[name] = digest
	}
	if !value.Immutable {
		return ValidationError("release must be immutable")
	}
	*r = Release{ID: value.ID, ApplicationID: value.ApplicationID, ServiceGroupID: value.ServiceGroupID, Version: value.Version, ConfigDigest: value.ConfigDigest, Status: value.Status, CreatedAt: value.CreatedAt, immutable: value.Immutable, digests: copyDigests}
	if err := r.Validate(); err != nil {
		return err
	}
	return nil
}

func NewRelease(applicationID, serviceGroupID ID, version int, configDigest string, digests map[string]ImageDigest, now time.Time) (*Release, error) {
	id, err := NewID("rel")
	if err != nil {
		return nil, WrapError(ErrUnavailable, "generate release id", err)
	}
	r := &Release{ID: id, ApplicationID: applicationID, ServiceGroupID: serviceGroupID, Version: version, ConfigDigest: strings.TrimSpace(configDigest), Status: ReleaseReady, CreatedAt: now.UTC()}
	if err := r.SetServiceDigests(digests); err != nil {
		return nil, err
	}
	if err := r.Freeze(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *Release) SetServiceDigests(digests map[string]ImageDigest) error {
	if r == nil {
		return ValidationError("release is nil")
	}
	if r.immutable {
		return ImmutableError("release")
	}
	if len(digests) == 0 {
		return ValidationError("release must contain all service image digests")
	}
	copyDigests := make(map[string]ImageDigest, len(digests))
	for service, digest := range digests {
		if strings.TrimSpace(service) == "" {
			return ValidationError("release service name is required")
		}
		if err := digest.Validate(); err != nil {
			return fmt.Errorf("release service %q: %w", service, err)
		}
		copyDigests[service] = digest
	}
	r.digests = copyDigests
	return nil
}

func (r *Release) AddServiceDigest(service string, digest ImageDigest) error {
	if r == nil {
		return ValidationError("release is nil")
	}
	if r.immutable {
		return ImmutableError("release")
	}
	if err := digest.Validate(); err != nil {
		return err
	}
	if r.digests == nil {
		r.digests = map[string]ImageDigest{}
	}
	if strings.TrimSpace(service) == "" {
		return ValidationError("release service name is required")
	}
	r.digests[service] = digest
	return nil
}

func (r *Release) Freeze() error {
	if r == nil {
		return ValidationError("release is nil")
	}
	if r.immutable {
		return nil
	}
	if err := r.Validate(); err != nil {
		return err
	}
	r.immutable = true
	return nil
}

func (r Release) IsImmutable() bool { return r.immutable }

func (r Release) ServiceDigests() map[string]ImageDigest {
	copyDigests := make(map[string]ImageDigest, len(r.digests))
	for name, digest := range r.digests {
		copyDigests[name] = digest
	}
	return copyDigests
}

func (r Release) Validate() error {
	if err := RequireID(r.ID, "release id"); err != nil {
		return err
	}
	if err := RequireID(r.ApplicationID, "release application id"); err != nil {
		return err
	}
	if err := RequireID(r.ServiceGroupID, "release service group id"); err != nil {
		return err
	}
	if r.Version < 1 {
		return ValidationError("release version must be positive")
	}
	if strings.TrimSpace(r.ConfigDigest) == "" {
		return ValidationError("release config digest is required")
	}
	if !r.Status.valid() {
		return ValidationError("release status is unsupported")
	}
	if len(r.digests) == 0 {
		return ValidationError("release must contain all service image digests")
	}
	for service, digest := range r.digests {
		if service == "" {
			return ValidationError("release service name is required")
		}
		if err := digest.Validate(); err != nil {
			return err
		}
	}
	return nil
}

func (r *Release) Transition(to ReleaseStatus) error {
	if r == nil {
		return ValidationError("release is nil")
	}
	if r.immutable {
		return ImmutableError("release")
	}
	if err := r.Status.Transition(to); err != nil {
		return err
	}
	r.Status = to
	return nil
}

type Deployment struct {
	ID            ID               `json:"id"`
	ApplicationID ID               `json:"application_id"`
	EnvironmentID ID               `json:"environment_id"`
	ReleaseID     ID               `json:"release_id"`
	Status        DeploymentStatus `json:"status"`
	FailureReason string           `json:"failure_reason,omitempty"`
	CreatedAt     time.Time        `json:"created_at"`
	UpdatedAt     time.Time        `json:"updated_at"`
}

func NewDeployment(applicationID, environmentID, releaseID ID, now time.Time) (Deployment, error) {
	id, err := NewID("dep")
	if err != nil {
		return Deployment{}, err
	}
	d := Deployment{ID: id, ApplicationID: applicationID, EnvironmentID: environmentID, ReleaseID: releaseID, Status: DeploymentPending, CreatedAt: now.UTC(), UpdatedAt: now.UTC()}
	if err := d.Validate(); err != nil {
		return Deployment{}, err
	}
	return d, nil
}

func (d Deployment) Validate() error {
	if err := RequireID(d.ID, "deployment id"); err != nil {
		return err
	}
	if err := RequireID(d.ApplicationID, "deployment application id"); err != nil {
		return err
	}
	if err := RequireID(d.EnvironmentID, "deployment environment id"); err != nil {
		return err
	}
	if err := RequireID(d.ReleaseID, "deployment release id"); err != nil {
		return err
	}
	if !d.Status.valid() {
		return ValidationError("deployment status is unsupported")
	}
	return nil
}

func (d *Deployment) Transition(to DeploymentStatus, now time.Time) error {
	if d == nil {
		return ValidationError("deployment is nil")
	}
	if err := d.Status.Transition(to); err != nil {
		return err
	}
	d.Status = to
	d.UpdatedAt = now.UTC()
	return nil
}

func (d Deployment) RuntimeReady() bool {
	return d.Status == DeploymentRuntimeReady || d.Status == DeploymentDegraded || d.Status == DeploymentServing
}
func (d Deployment) Serving() bool { return d.Status == DeploymentServing }

type OperationType string

const (
	OperationCreateApplication OperationType = "create_application"
	OperationBuild             OperationType = "build"
	OperationObserve           OperationType = "observe"
	OperationDeploy            OperationType = "deploy"
	OperationRestart           OperationType = "restart"
	OperationRedeploy          OperationType = "redeploy"
	OperationRollback          OperationType = "rollback"
	OperationRoute             OperationType = "route"
	OperationDestroy           OperationType = "destroy"
)

type Operation struct {
	ID             ID              `json:"id"`
	ApplicationID  ID              `json:"application_id"`
	EnvironmentID  ID              `json:"environment_id"`
	TargetRef      string          `json:"target_ref"`
	Type           OperationType   `json:"type"`
	IdempotencyKey string          `json:"idempotency_key"`
	Status         OperationStatus `json:"status"`
	FailureReason  string          `json:"failure_reason,omitempty"`
	CreatedAt      time.Time       `json:"created_at"`
	UpdatedAt      time.Time       `json:"updated_at"`
}

func NewOperation(applicationID, environmentID ID, operationType OperationType, target, idempotency string, now time.Time) (Operation, error) {
	id, err := NewID("op")
	if err != nil {
		return Operation{}, err
	}
	o := Operation{ID: id, ApplicationID: applicationID, EnvironmentID: environmentID, Type: operationType, TargetRef: strings.TrimSpace(target), IdempotencyKey: strings.TrimSpace(idempotency), Status: OperationPending, CreatedAt: now.UTC(), UpdatedAt: now.UTC()}
	if err := o.Validate(); err != nil {
		return Operation{}, err
	}
	return o, nil
}

func (o Operation) Validate() error {
	if err := RequireID(o.ID, "operation id"); err != nil {
		return err
	}
	if err := RequireID(o.ApplicationID, "operation application id"); err != nil {
		return err
	}
	if err := RequireID(o.EnvironmentID, "operation environment id"); err != nil {
		return err
	}
	if o.TargetRef == "" || o.IdempotencyKey == "" {
		return ValidationError("operation target and idempotency key are required")
	}
	switch o.Type {
	case OperationCreateApplication, OperationBuild, OperationObserve, OperationDeploy, OperationRestart, OperationRedeploy, OperationRollback, OperationRoute, OperationDestroy:
	default:
		return ValidationError("operation type is unsupported")
	}
	if !o.Status.valid() {
		return ValidationError("operation status is unsupported")
	}
	return nil
}

func (o *Operation) Transition(to OperationStatus, now time.Time) error {
	if o == nil {
		return ValidationError("operation is nil")
	}
	if err := o.Status.Transition(to); err != nil {
		return err
	}
	o.Status = to
	o.UpdatedAt = now.UTC()
	return nil
}

type Route struct {
	ID             ID        `json:"id"`
	ApplicationID  ID        `json:"application_id"`
	DeploymentID   ID        `json:"deployment_id"`
	ServiceName    string    `json:"service_name,omitempty"`
	Host           string    `json:"host"`
	Path           string    `json:"path"`
	CertificateRef string    `json:"certificate_ref,omitempty"`
	Verified       bool      `json:"verified"`
	Serving        bool      `json:"serving"`
	CreatedAt      time.Time `json:"created_at"`
}

func (r Route) Validate() error {
	if err := RequireID(r.ID, "route id"); err != nil {
		return err
	}
	if err := RequireID(r.ApplicationID, "route application id"); err != nil {
		return err
	}
	if err := RequireID(r.DeploymentID, "route deployment id"); err != nil {
		return err
	}
	if _, err := NormalizeRouteHost(r.Host); err != nil {
		return err
	}
	if _, err := NormalizeRoutePath(r.Path); err != nil {
		return err
	}
	return nil
}

type UsageAggregate struct {
	ID                          ID        `json:"id"`
	ApplicationID               ID        `json:"application_id"`
	EnvironmentID               ID        `json:"environment_id,omitempty"`
	DeploymentID                ID        `json:"deployment_id,omitempty"`
	ServiceName                 string    `json:"service_name"`
	ReleaseID                   ID        `json:"release_id"`
	WindowStart                 time.Time `json:"window_start"`
	WindowEnd                   time.Time `json:"window_end"`
	SampleCount                 uint64    `json:"sample_count"`
	CPUSeconds                  float64   `json:"cpu_seconds"`
	MemoryByteSeconds           float64   `json:"memory_byte_seconds"`
	DiskByteSeconds             float64   `json:"disk_byte_seconds"`
	NetworkRxBytes              uint64    `json:"network_rx_bytes"`
	NetworkTxBytes              uint64    `json:"network_tx_bytes"`
	RuntimeSeconds              float64   `json:"runtime_seconds"`
	RestartCount                uint64    `json:"restart_count"`
	ExceptionCount              uint64    `json:"exception_count"`
	PeakCPUMillicores           int64     `json:"peak_cpu_millicores"`
	PeakMemoryBytes             int64     `json:"peak_memory_bytes"`
	PeakDiskBytes               int64     `json:"peak_disk_bytes"`
	AverageCPUMillicores        float64   `json:"average_cpu_millicores"`
	AverageMemoryBytes          float64   `json:"average_memory_bytes"`
	AverageDiskBytes            float64   `json:"average_disk_bytes"`
	TrendCPUMillicoresPerSecond float64   `json:"trend_cpu_millicores_per_second"`
	TrendMemoryBytesPerSecond   float64   `json:"trend_memory_bytes_per_second"`
	TrendDiskBytesPerSecond     float64   `json:"trend_disk_bytes_per_second"`
	LimitCPUMillicores          int64     `json:"limit_cpu_millicores"`
	LimitMemoryBytes            int64     `json:"limit_memory_bytes"`
	LimitDiskBytes              int64     `json:"limit_disk_bytes"`
	LimitPIDs                   int64     `json:"limit_pids"`
}

type AuditEvidence struct {
	ID           ID            `json:"id"`
	Actor        string        `json:"actor"`
	Reason       string        `json:"reason"`
	InputDigest  string        `json:"input_digest"`
	ResultDigest string        `json:"result_digest"`
	Evidence     []EvidenceRef `json:"evidence"`
	PreviousHash string        `json:"previous_hash,omitempty"`
	Hash         string        `json:"hash"`
	CreatedAt    time.Time     `json:"created_at"`
}

type SecretReference struct {
	ID       ID     `json:"id"`
	Name     string `json:"name"`
	Provider string `json:"provider"`
	Version  string `json:"version,omitempty"`
}

func (s SecretReference) Validate() error {
	if err := RequireID(s.ID, "secret reference id"); err != nil {
		return err
	}
	if strings.TrimSpace(s.Name) == "" || strings.TrimSpace(s.Provider) == "" {
		return ValidationError("secret reference name and provider are required")
	}
	return nil
}

type Node struct {
	ID           ID        `json:"id"`
	InstanceID   ID        `json:"instance_id"`
	Name         string    `json:"name"`
	AgentVersion string    `json:"agent_version"`
	Online       bool      `json:"online"`
	LastSeenAt   time.Time `json:"last_seen_at"`
}

type WebhookEvent struct {
	ID            ID        `json:"id"`
	EventType     string    `json:"event_type"`
	PayloadDigest string    `json:"payload_digest"`
	OccurredAt    time.Time `json:"occurred_at"`
	Signature     string    `json:"signature"`
}

type AIInvocation struct {
	ID                 ID     `json:"id"`
	Provider           string `json:"provider"`
	Model              string `json:"model"`
	Profile            string `json:"profile"`
	PolicyVersion      string `json:"policy_version"`
	PromptVersion      string `json:"prompt_version"`
	ProblemFingerprint string `json:"problem_fingerprint"`
	ContextID          ID     `json:"context_id"`
	ContextDigest      string `json:"context_digest"`
	Tokens             uint64 `json:"tokens"`
	DurationMS         int64  `json:"duration_ms"`
	Cached             bool   `json:"cached"`
	Status             string `json:"status"`
}
type AIContextPackage struct {
	ID              ID                `json:"id"`
	ApplicationID   ID                `json:"application_id"`
	TaskType        string            `json:"task_type"`
	Profile         string            `json:"profile"`
	Scope           []string          `json:"scope"`
	ObjectVersions  map[string]string `json:"object_versions"`
	SourceRefs      []EvidenceRef     `json:"source_refs"`
	ManifestDigest  string            `json:"manifest_digest"`
	Bytes           int64             `json:"bytes"`
	Authorized      bool              `json:"authorized"`
	Redacted        bool              `json:"redacted"`
	UntrustedData   bool              `json:"untrusted_data"`
	TemplateVersion string            `json:"template_version"`
}
type AIAction struct {
	ToolID         string         `json:"tool_id"`
	ToolVersion    string         `json:"tool_version"`
	Parameters     map[string]any `json:"parameters,omitempty"`
	Risk           string         `json:"risk"`
	ExpectedResult string         `json:"expected_result"`
	ValidationID   string         `json:"validation_id"`
}
type AIPlanBudget struct {
	MaxTokens     int   `json:"max_tokens"`
	MaxDurationMS int64 `json:"max_duration_ms"`
	MaxActions    int   `json:"max_actions"`
}
type AIActionPlan struct {
	ID                       ID                `json:"id"`
	SchemaVersion            string            `json:"schema_version"`
	PolicyVersion            string            `json:"policy_version"`
	TaskType                 string            `json:"task_type"`
	TargetRefs               map[string]string `json:"target_refs"`
	Sources                  []string          `json:"sources"`
	Assumptions              []string          `json:"assumptions,omitempty"`
	EvidenceRefs             []EvidenceRef     `json:"evidence_refs"`
	Actions                  []AIAction        `json:"actions"`
	Budget                   AIPlanBudget      `json:"budget"`
	RollbackID               string            `json:"rollback_id,omitempty"`
	Confidence               float64           `json:"confidence"`
	RequiresUserConfirmation bool              `json:"requires_user_confirmation"`
}
type AIInterventionRecord struct {
	ID                 ID            `json:"id"`
	ApplicationID      ID            `json:"application_id"`
	ProblemFingerprint string        `json:"problem_fingerprint"`
	InvocationID       ID            `json:"invocation_id"`
	PlanID             ID            `json:"plan_id"`
	Outcome            string        `json:"outcome"`
	Verification       []EvidenceRef `json:"verification"`
	RollbackEvidence   []EvidenceRef `json:"rollback_evidence,omitempty"`
	Tokens             uint64        `json:"tokens"`
	DurationMS         int64         `json:"duration_ms"`
	RolledBack         bool          `json:"rolled_back"`
}
type AIRecommendation struct {
	ID                 ID         `json:"id"`
	TargetRef          string     `json:"target_ref"`
	Reason             string     `json:"reason"`
	SuggestedActions   []AIAction `json:"suggested_actions"`
	RequiresController bool       `json:"requires_controller"`
}
type RuleCandidate struct {
	ID               ID            `json:"id"`
	Fingerprint      string        `json:"fingerprint"`
	Status           string        `json:"status"`
	SuccessCount     int           `json:"success_count"`
	ApplicationCount int           `json:"application_count"`
	TestEvidence     []EvidenceRef `json:"test_evidence"`
	RegressionPassed bool          `json:"regression_passed"`
	ShadowPassed     bool          `json:"shadow_passed"`
	ReviewDecision   string        `json:"review_decision,omitempty"`
	ReviewedBy       string        `json:"reviewed_by,omitempty"`
	ProposedVersion  string        `json:"proposed_version,omitempty"`
}
type DeterministicRule struct {
	ID              ID     `json:"id"`
	CandidateID     ID     `json:"candidate_id"`
	Version         string `json:"version"`
	Enabled         bool   `json:"enabled"`
	ShadowVerified  bool   `json:"shadow_verified"`
	ReviewedBy      string `json:"reviewed_by"`
	RollbackVersion string `json:"rollback_version,omitempty"`
}
type EvaluationEvidence struct {
	ID              ID            `json:"id"`
	RuleCandidateID ID            `json:"rule_candidate_id"`
	TestName        string        `json:"test_name"`
	Passed          bool          `json:"passed"`
	Evidence        []EvidenceRef `json:"evidence"`
}
