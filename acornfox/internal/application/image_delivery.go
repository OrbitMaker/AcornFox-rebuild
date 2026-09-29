package application

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"

	appcontracts "github.com/acornfox/acornfox/internal/application/contracts"
	"github.com/acornfox/acornfox/internal/contracts"
	"github.com/acornfox/acornfox/internal/domain"
	"github.com/distribution/reference"
)

var (
	appNameRegex    = regexp.MustCompile(`^[a-z0-9]([a-z0-9_-]{0,62}[a-z0-9])?$`)
	envNameRegex    = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)
	volumeNameRegex = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$`)
)

type ImageDeliveryService struct {
	Resolver appcontracts.ImageMetadataResolver
	Clock    func() time.Time
}

func NewImageDeliveryService(resolver appcontracts.ImageMetadataResolver) *ImageDeliveryService {
	return &ImageDeliveryService{
		Resolver: resolver,
		Clock:    time.Now,
	}
}

// RegistryMetadataAdapter adapts contracts.RegistryImageProvider to appcontracts.ImageMetadataResolver
type RegistryMetadataAdapter struct {
	Provider contracts.RegistryImageProvider
}

func (a *RegistryMetadataAdapter) ResolveMetadata(ctx context.Context, repository, reference string) (appcontracts.ResolvedMetadataResult, error) {
	if a.Provider == nil {
		return appcontracts.ResolvedMetadataResult{}, domain.NewError(domain.ErrUnavailable, "registry provider is nil")
	}
	now := time.Now().UTC()
	opContext := contracts.OperationContext{
		IdempotencyKey: fmt.Sprintf("resolve:%s:%s:%d", repository, reference, now.UnixNano()),
		Deadline:       now.Add(30 * time.Second),
	}
	req := contracts.ImageResolveRequest{
		Repository: repository,
		Tag:        reference,
		Operation:  opContext,
	}
	res, err := a.Provider.Resolve(ctx, req)
	if err != nil {
		return appcontracts.ResolvedMetadataResult{}, err
	}
	evidenceRef := ""
	if len(res.Evidence.Refs) > 0 {
		evidenceRef = res.Evidence.Refs[0].ID.String()
	}
	return appcontracts.ResolvedMetadataResult{
		Repository:  res.Image.Repository,
		Digest:      res.Image.Digest,
		ResolvedTag: res.Image.ResolvedTag,
		EvidenceRef: evidenceRef,
	}, nil
}

// CreatePlan validates all inputs, resolves public metadata if valid, and generates an immutable plan.
func (s *ImageDeliveryService) CreatePlan(ctx context.Context, adminID domain.ID, input appcontracts.ImagePlanInput) (appcontracts.ImagePlan, error) {
	if adminID.Empty() {
		return appcontracts.ImagePlan{}, domain.NewError(domain.ErrUnauthorized, "authenticated admin context is required")
	}

	// 1. Validate application name before any network action
	appName := strings.TrimSpace(input.AppName)
	if appName == "" {
		return appcontracts.ImagePlan{}, domain.ValidationError("app_name is required")
	}
	if !appNameRegex.MatchString(appName) {
		return appcontracts.ImagePlan{}, domain.ValidationError("app_name must be 1-64 lowercase alphanumeric, dash, or underscore characters")
	}

	// 2. Reject unsupported options clearly before network reads
	if input.Secrets != nil {
		return appcontracts.ImagePlan{}, domain.NewError(domain.ErrUnsupportedCapability, "secrets are not supported in native image plan")
	}
	if input.HostMounts != nil {
		return appcontracts.ImagePlan{}, domain.NewError(domain.ErrUnsupportedCapability, "host mounts are not supported; use declared named volumes")
	}
	if input.Privileged != nil {
		return appcontracts.ImagePlan{}, domain.NewError(domain.ErrUnsupportedCapability, "privileged containers are not supported")
	}
	if input.Command != nil || input.Entrypoint != nil {
		return appcontracts.ImagePlan{}, domain.NewError(domain.ErrUnsupportedCapability, "custom command or entrypoint override is not supported")
	}

	// 3. Parse and strictly validate image locator before network reads
	repo, ref, isDigest, err := ParseAndValidateImageLocator(input.Image)
	if err != nil {
		return appcontracts.ImagePlan{}, err
	}

	// 4. Validate environment variables using existing non-secret contract
	envVars, err := normalizeEnvironment(input.Environment)
	if err != nil {
		return appcontracts.ImagePlan{}, err
	}

	// 5. Validate named volumes
	volumes, err := normalizeVolumes(input.Volumes)
	if err != nil {
		return appcontracts.ImagePlan{}, err
	}

	// 6. Validate or apply default resources
	resources, err := normalizeResources(input.Resources)
	if err != nil {
		return appcontracts.ImagePlan{}, err
	}

	// 7. Check container port
	var missingInputs []string
	status := appcontracts.ImagePlanStatusPlanned
	port := input.Port
	if port <= 0 || port > 65535 {
		status = appcontracts.ImagePlanStatusNeedsInput
		missingInputs = append(missingInputs, "container_port")
		port = 0
	}

	// 8. Resolve public metadata once via narrow seam
	if s.Resolver == nil {
		return appcontracts.ImagePlan{}, domain.NewError(domain.ErrUnavailable, "image metadata resolver is unconfigured")
	}

	now := time.Now().UTC()
	if s.Clock != nil {
		now = s.Clock().UTC()
	}

	resolveRes, err := s.Resolver.ResolveMetadata(ctx, repo, ref)
	if err != nil {
		return appcontracts.ImagePlan{}, sanitizeResolverError(err)
	}

	if resolveRes.Digest == "" || !validDigest(resolveRes.Digest) {
		return appcontracts.ImagePlan{}, domain.NewError(domain.ErrUnavailable, "resolver returned invalid image digest")
	}

	// P2 Fix: Returned repository must match canonical requested repository (normalizing equivalent aliases)
	resRepoNorm := normalizeCanonicalRepo(resolveRes.Repository)
	reqRepoNorm := normalizeCanonicalRepo(repo)
	if resRepoNorm != reqRepoNorm {
		return appcontracts.ImagePlan{}, domain.NewError(domain.ErrConflict, fmt.Sprintf("resolver repository %q does not match requested repository %q", resolveRes.Repository, repo))
	}

	resolvedImage := appcontracts.ResolvedImage{
		Repository:   reqRepoNorm,
		Digest:       resolveRes.Digest,
		ResolvedTag:  resolveRes.ResolvedTag,
		Architecture: "amd64",
		OS:           "linux",
	}
	if resolvedImage.ResolvedTag == "" && !isDigest {
		resolvedImage.ResolvedTag = ref
	}

	evidenceRef := resolveRes.EvidenceRef
	provenance := appcontracts.ResolverProvenance{
		Provider:    "registryhttp",
		EvidenceRef: evidenceRef,
		Digest:      resolveRes.Digest,
		ResolvedAt:  now,
	}

	canonicalInput := appcontracts.CanonicalExecutionInput{
		AppName:     appName,
		Repository:  reqRepoNorm,
		ResolvedRef: ref,
		Port:        port,
		Environment: envVars,
		Resources:   resources,
		Volumes:     volumes,
	}

	// 9. Compute deterministic plan digest covering all behavior-affecting parameters
	planDigest, err := appcontracts.ComputePlanDigest(canonicalInput, resolvedImage.Digest)
	if err != nil {
		return appcontracts.ImagePlan{}, domain.WrapError(domain.ErrUnavailable, "compute plan digest", err)
	}

	planID, err := domain.NewID("ipl")
	if err != nil {
		return appcontracts.ImagePlan{}, domain.WrapError(domain.ErrUnavailable, "generate plan id", err)
	}

	plan := appcontracts.ImagePlan{
		ID:                 planID,
		AdminID:            adminID,
		AppName:            appName,
		Status:             status,
		PlanDigest:         planDigest,
		CanonicalInput:     canonicalInput,
		ResolvedImage:      resolvedImage,
		ResolverProvenance: provenance,
		MissingInputs:      missingInputs,
		CreatedAt:          now,
		UpdatedAt:          now,
	}

	if err := appcontracts.ValidatePlanConsistency(plan); err != nil {
		return appcontracts.ImagePlan{}, err
	}

	return plan, nil
}

// ParseAndValidateImageLocator verifies public Docker Hub or GHCR repository and reference using distribution/reference.
// Strictly rejects URLs, schemes, credentials, query, fragment, private IPs, or arbitrary hosts.
func ParseAndValidateImageLocator(raw string) (repo string, ref string, isDigest bool, err error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", "", false, domain.ValidationError("image locator is required")
	}

	// 1. Reject schemes, fragments, queries, spaces, control characters
	if strings.Contains(trimmed, "://") {
		return "", "", false, domain.ValidationError("image locator must not contain URL scheme")
	}
	if strings.ContainsAny(trimmed, " \t\r\n?#\\") {
		return "", "", false, domain.ValidationError("image locator contains invalid characters")
	}

	// 2. Parse using distribution/reference.ParseNormalizedNamed
	named, parseErr := reference.ParseNormalizedNamed(trimmed)
	if parseErr != nil {
		return "", "", false, domain.ValidationError("image locator is invalid: " + parseErr.Error())
	}

	// 3. Strict host whitelist: only canonical Docker Hub and GHCR supported
	host := reference.Domain(named)
	if host == "localhost" || net.ParseIP(host) != nil {
		return "", "", false, domain.ValidationError("private or loopback registry hosts are rejected")
	}
	switch host {
	case "docker.io", "registry-1.docker.io":
		// Canonical transport mapping freezes registry-1.docker.io
		repoPath := reference.Path(named)
		repo = "registry-1.docker.io/" + repoPath
	case "ghcr.io":
		repoPath := reference.Path(named)
		// ghcr.io repository requires owner and image (at least one slash in path)
		if !strings.Contains(repoPath, "/") {
			return "", "", false, domain.ValidationError("ghcr.io repository requires owner and image name")
		}
		repo = "ghcr.io/" + repoPath
	default:
		return "", "", false, domain.ValidationError("unsupported registry host: only canonical Docker Hub and GHCR are supported in this slice")
	}

	// 4. Extract reference (digest or tag)
	if canonical, ok := named.(reference.Canonical); ok {
		ref = canonical.Digest().String()
		isDigest = true
	} else if tagged, ok := named.(reference.NamedTagged); ok {
		ref = tagged.Tag()
		isDigest = false
	} else {
		ref = "latest"
		isDigest = false
	}

	return repo, ref, isDigest, nil
}

func normalizeCanonicalRepo(r string) string {
	r = strings.TrimSpace(r)
	if strings.HasPrefix(r, "docker.io/") {
		r = "registry-1.docker.io/" + strings.TrimPrefix(r, "docker.io/")
	} else if !strings.Contains(r, ".") && !strings.HasPrefix(r, "registry-1.docker.io/") && !strings.HasPrefix(r, "ghcr.io/") {
		if !strings.Contains(r, "/") {
			r = "registry-1.docker.io/library/" + r
		} else {
			r = "registry-1.docker.io/" + r
		}
	}
	return r
}

func validDigest(d string) bool {
	if !strings.HasPrefix(d, "sha256:") || len(d) != len("sha256:")+64 {
		return false
	}
	hexPart := strings.TrimPrefix(d, "sha256:")
	if hexPart != strings.ToLower(hexPart) {
		return false
	}
	_, err := hex.DecodeString(hexPart)
	return err == nil
}

func normalizeEnvironment(env map[string]string) ([]appcontracts.RuntimeEnvironmentVariable, error) {
	if len(env) == 0 {
		return nil, nil
	}
	if len(env) > 128 {
		return nil, domain.ValidationError("environment variables count exceeds limit (128)")
	}
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	res := make([]appcontracts.RuntimeEnvironmentVariable, 0, len(keys))
	for _, k := range keys {
		if !envNameRegex.MatchString(k) {
			return nil, domain.ValidationError(fmt.Sprintf("environment variable name %q is invalid", k))
		}
		v := env[k]
		if len(v) > 8192 {
			return nil, domain.ValidationError(fmt.Sprintf("environment variable %q value exceeds 8192 bytes", k))
		}

		// P1 Fix: Adapt to existing contracts.RuntimeEnvironmentVariable and enforce its validation semantics
		legacyVar := contracts.RuntimeEnvironmentVariable{
			Name:  k,
			Value: v,
			Kind:  contracts.RuntimeEnvironmentLiteral,
		}
		if err := legacyVar.Validate(); err != nil {
			return nil, err
		}

		res = append(res, appcontracts.RuntimeEnvironmentVariable{
			Name:  k,
			Value: v,
			Kind:  "literal",
		})
	}
	return res, nil
}

func normalizeVolumes(volumes []appcontracts.RuntimeVolume) ([]appcontracts.RuntimeVolume, error) {
	if len(volumes) == 0 {
		return nil, nil
	}
	if len(volumes) > 16 {
		return nil, domain.ValidationError("volumes count exceeds limit (16)")
	}
	seenNames := make(map[string]bool)
	normalized := make([]appcontracts.RuntimeVolume, 0, len(volumes))

	for i, v := range volumes {
		v.Name = strings.TrimSpace(v.Name)
		v.MountPath = strings.TrimSpace(v.MountPath)

		if !volumeNameRegex.MatchString(v.Name) {
			return nil, domain.ValidationError(fmt.Sprintf("volume name %q is invalid", v.Name))
		}
		if seenNames[v.Name] {
			return nil, domain.ValidationError(fmt.Sprintf("duplicate volume name %q", v.Name))
		}
		seenNames[v.Name] = true

		if v.SizeBytes <= 0 || v.SizeBytes > 1<<50 {
			return nil, domain.ValidationError(fmt.Sprintf("volume %q size_bytes is invalid", v.Name))
		}

		if !isMountPathSafe(v.MountPath) {
			return nil, domain.ValidationError(fmt.Sprintf("volume %q mount_path %q is disallowed or unsafe", v.Name, v.MountPath))
		}

		for _, prev := range normalized[:i] {
			if pathsOverlap(v.MountPath, prev.MountPath) {
				return nil, domain.ValidationError(fmt.Sprintf("volume mount paths %q and %q overlap", v.MountPath, prev.MountPath))
			}
		}

		normalized = append(normalized, v)
	}

	sort.Slice(normalized, func(i, j int) bool {
		return normalized[i].Name < normalized[j].Name
	})
	return normalized, nil
}

func isMountPathSafe(p string) bool {
	if len(p) > 512 || p == "/" || !path.IsAbs(p) || path.Clean(p) != p || strings.ContainsAny(p, "\x00\\,") {
		return false
	}
	for _, protected := range []string{"/proc", "/sys", "/dev", "/run/secrets", "/var/run/docker.sock", "/run/docker.sock"} {
		if pathsOverlap(p, protected) {
			return false
		}
	}
	return true
}

func pathsOverlap(a, b string) bool {
	return a == b || strings.HasPrefix(a, b+"/") || strings.HasPrefix(b, a+"/")
}

func normalizeResources(r *appcontracts.RuntimeRequestedResources) (appcontracts.RuntimeRequestedResources, error) {
	if r == nil {
		return appcontracts.RuntimeRequestedResources{
			CPUMillis:            500,
			MemoryBytes:          512 << 20,
			PIDs:                 128,
			DiskReservationBytes: 1 << 30,
		}, nil
	}
	if r.CPUMillis < 10 || r.CPUMillis > 1000000 {
		return appcontracts.RuntimeRequestedResources{}, domain.ValidationError("cpu_millis must be between 10 and 1,000,000")
	}
	if r.MemoryBytes < 6<<20 || r.MemoryBytes > 1<<50 {
		return appcontracts.RuntimeRequestedResources{}, domain.ValidationError("memory_bytes must be between 6MB and 1PB")
	}
	if r.PIDs < 1 || r.PIDs > 1000000 {
		return appcontracts.RuntimeRequestedResources{}, domain.ValidationError("pids must be between 1 and 1,000,000")
	}
	if r.DiskReservationBytes < 0 || r.DiskReservationBytes > 1<<50 {
		return appcontracts.RuntimeRequestedResources{}, domain.ValidationError("disk_reservation_bytes is invalid")
	}
	return *r, nil
}

func sanitizeResolverError(err error) error {
	if err == nil {
		return nil
	}
	var provErr *contracts.ProviderError
	if errors.As(err, &provErr) {
		switch provErr.Code {
		case contracts.ErrNotFound:
			return domain.NewError(domain.ErrNotFound, "registry image or tag not found")
		case contracts.ErrUnauthorized:
			return domain.NewError(domain.ErrUnauthorized, "registry authentication required or denied")
		case contracts.ErrForbidden:
			return domain.NewError(domain.ErrForbidden, "registry access forbidden")
		case contracts.ErrConflict:
			return domain.NewError(domain.ErrConflict, provErr.Message)
		case contracts.ErrValidation:
			return domain.ValidationError(provErr.Message)
		case contracts.ErrTimeout:
			return domain.NewError(domain.ErrTimeout, "registry metadata request timed out")
		default:
			return domain.NewError(domain.ErrUnavailable, "registry service unavailable: "+provErr.Message)
		}
	}
	return domain.NewError(domain.ErrUnavailable, "registry metadata resolution failed")
}
