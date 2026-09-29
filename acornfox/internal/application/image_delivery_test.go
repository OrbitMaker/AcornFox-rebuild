package application

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	appcontracts "github.com/acornfox/acornfox/internal/application/contracts"
	"github.com/acornfox/acornfox/internal/domain"
)

type fakeResolver struct {
	callCount   int32
	resolveFunc func(ctx context.Context, repository, reference string) (appcontracts.ResolvedMetadataResult, error)
}

func (f *fakeResolver) ResolveMetadata(ctx context.Context, repository, reference string) (appcontracts.ResolvedMetadataResult, error) {
	atomic.AddInt32(&f.callCount, 1)
	if f.resolveFunc != nil {
		return f.resolveFunc(ctx, repository, reference)
	}
	return appcontracts.ResolvedMetadataResult{
		Repository:  repository,
		Digest:      "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		ResolvedTag: reference,
		EvidenceRef: "ev_test123",
	}, nil
}

func TestImagePlan_InputValidationAndDigestBinding(t *testing.T) {
	fake := &fakeResolver{}
	service := NewImageDeliveryService(fake)
	service.Clock = func() time.Time {
		return time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	}

	adminID := domain.ID("adm_0123456789abcdef")

	// 1. Success case with valid input and explicit port
	validInput := appcontracts.ImagePlanInput{
		AppName: "my-web-app",
		Image:   "nginx:1.27.0",
		Port:    8080,
		Environment: map[string]string{
			"LOG_LEVEL": "info",
			"APP_ENV":   "production",
		},
		Volumes: []appcontracts.RuntimeVolume{
			{Name: "app-data", MountPath: "/data", SizeBytes: 1024 * 1024 * 100},
		},
	}

	plan, err := service.CreatePlan(context.Background(), adminID, validInput)
	if err != nil {
		t.Fatalf("unexpected error creating plan: %v", err)
	}
	if plan.Status != appcontracts.ImagePlanStatusPlanned {
		t.Fatalf("expected status planned, got %s", plan.Status)
	}
	if plan.CanonicalInput.Repository != "registry-1.docker.io/library/nginx" {
		t.Fatalf("expected canonical transport repository registry-1.docker.io/library/nginx, got %s", plan.CanonicalInput.Repository)
	}
	if plan.CanonicalInput.ResolvedRef != "1.27.0" {
		t.Fatalf("expected ref 1.27.0, got %s", plan.CanonicalInput.ResolvedRef)
	}
	if plan.PlanDigest == "" || !strings.HasPrefix(plan.PlanDigest, "sha256:") {
		t.Fatalf("expected valid plan digest, got %s", plan.PlanDigest)
	}
	if atomic.LoadInt32(&fake.callCount) != 1 {
		t.Fatalf("expected resolver called once, got %d", fake.callCount)
	}

	// Verify plan digest is deterministic for identical input
	plan2, err := service.CreatePlan(context.Background(), adminID, validInput)
	if err != nil {
		t.Fatalf("unexpected error creating second plan: %v", err)
	}
	if plan.PlanDigest != plan2.PlanDigest {
		t.Fatalf("expected deterministic plan digest, got %s and %s", plan.PlanDigest, plan2.PlanDigest)
	}

	// 2. GHCR repository locator
	ghcrInput := appcontracts.ImagePlanInput{
		AppName: "ghcr-app",
		Image:   "ghcr.io/open-card/service:v1.0",
		Port:    3000,
	}
	ghcrPlan, err := service.CreatePlan(context.Background(), adminID, ghcrInput)
	if err != nil {
		t.Fatalf("unexpected error creating ghcr plan: %v", err)
	}
	if ghcrPlan.CanonicalInput.Repository != "ghcr.io/open-card/service" {
		t.Fatalf("expected ghcr repository, got %s", ghcrPlan.CanonicalInput.Repository)
	}

	// 3. Missing port results in needs_input status
	missingPortInput := appcontracts.ImagePlanInput{
		AppName: "no-port-app",
		Image:   "nginx:latest",
		Port:    0,
	}
	needsInputPlan, err := service.CreatePlan(context.Background(), adminID, missingPortInput)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if needsInputPlan.Status != appcontracts.ImagePlanStatusNeedsInput {
		t.Fatalf("expected status needs_input, got %s", needsInputPlan.Status)
	}
	if len(needsInputPlan.MissingInputs) != 1 || needsInputPlan.MissingInputs[0] != "container_port" {
		t.Fatalf("expected missing_inputs [container_port], got %v", needsInputPlan.MissingInputs)
	}
}

func TestImagePlan_InvalidInputsNoResolverCalls(t *testing.T) {
	fake := &fakeResolver{}
	service := NewImageDeliveryService(fake)
	adminID := domain.ID("adm_0123456789abcdef")

	invalidCases := []struct {
		name  string
		input appcontracts.ImagePlanInput
	}{
		{
			name: "empty app name",
			input: appcontracts.ImagePlanInput{
				AppName: "",
				Image:   "nginx:latest",
				Port:    80,
			},
		},
		{
			name: "uppercase in app name",
			input: appcontracts.ImagePlanInput{
				AppName: "MyApp",
				Image:   "nginx:latest",
				Port:    80,
			},
		},
		{
			name: "URL scheme in image",
			input: appcontracts.ImagePlanInput{
				AppName: "scheme-app",
				Image:   "https://docker.io/library/nginx:latest",
				Port:    80,
			},
		},
		{
			name: "query parameters in image",
			input: appcontracts.ImagePlanInput{
				AppName: "query-app",
				Image:   "nginx:latest?foo=bar",
				Port:    80,
			},
		},
		{
			name: "credentials in image",
			input: appcontracts.ImagePlanInput{
				AppName: "cred-app",
				Image:   "user:pass@nginx:latest",
				Port:    80,
			},
		},
		{
			name: "unsupported private registry host",
			input: appcontracts.ImagePlanInput{
				AppName: "private-app",
				Image:   "registry.example.internal/myorg/myimage:v1",
				Port:    80,
			},
		},
		{
			name: "loopback registry host",
			input: appcontracts.ImagePlanInput{
				AppName: "loopback-app",
				Image:   "127.0.0.1:5000/myimage:v1",
				Port:    80,
			},
		},
		{
			name: "uppercase in image repository",
			input: appcontracts.ImagePlanInput{
				AppName: "upper-img-app",
				Image:   "MyUser/MyImage:latest",
				Port:    80,
			},
		},
		{
			name: "invalid tag starting with dot",
			input: appcontracts.ImagePlanInput{
				AppName: "bad-tag-app",
				Image:   "nginx:.bad",
				Port:    80,
			},
		},
		{
			name: "ghcr missing image name",
			input: appcontracts.ImagePlanInput{
				AppName: "ghcr-no-image",
				Image:   "ghcr.io/owner",
				Port:    80,
			},
		},
		{
			name: "sensitive env name API_KEY rejected as literal",
			input: appcontracts.ImagePlanInput{
				AppName: "sensitive-env-app",
				Image:   "nginx:latest",
				Port:    80,
				Environment: map[string]string{
					"API_KEY": "example-value",
				},
			},
		},
		{
			name: "env value contains NUL byte",
			input: appcontracts.ImagePlanInput{
				AppName: "nul-env-app",
				Image:   "nginx:latest",
				Port:    80,
				Environment: map[string]string{
					"APP_ENV": "x\x00y",
				},
			},
		},
		{
			name: "unsupported secrets specified",
			input: appcontracts.ImagePlanInput{
				AppName: "secret-app",
				Image:   "nginx:latest",
				Port:    80,
				Secrets: []string{"sec-1"},
			},
		},
		{
			name: "unsupported host mount specified",
			input: appcontracts.ImagePlanInput{
				AppName:    "mount-app",
				Image:      "nginx:latest",
				Port:       80,
				HostMounts: []string{"/host:/container"},
			},
		},
		{
			name: "unsupported privileged specified",
			input: appcontracts.ImagePlanInput{
				AppName:    "priv-app",
				Image:      "nginx:latest",
				Port:       80,
				Privileged: true,
			},
		},
		{
			name: "unsupported custom command specified",
			input: appcontracts.ImagePlanInput{
				AppName: "cmd-app",
				Image:   "nginx:latest",
				Port:    80,
				Command: []string{"/bin/sh"},
			},
		},
		{
			name: "unsafe volume mount path",
			input: appcontracts.ImagePlanInput{
				AppName: "unsafe-vol-app",
				Image:   "nginx:latest",
				Port:    80,
				Volumes: []appcontracts.RuntimeVolume{
					{Name: "data", MountPath: "/proc/sys", SizeBytes: 1024},
				},
			},
		},
		{
			name: "overlapping volume mount paths",
			input: appcontracts.ImagePlanInput{
				AppName: "overlap-vol-app",
				Image:   "nginx:latest",
				Port:    80,
				Volumes: []appcontracts.RuntimeVolume{
					{Name: "data1", MountPath: "/var/data", SizeBytes: 1024},
					{Name: "data2", MountPath: "/var/data/sub", SizeBytes: 1024},
				},
			},
		},
	}

	for _, tc := range invalidCases {
		t.Run(tc.name, func(t *testing.T) {
			beforeCalls := atomic.LoadInt32(&fake.callCount)
			_, err := service.CreatePlan(context.Background(), adminID, tc.input)
			if err == nil {
				t.Fatalf("expected error for case %q, but got nil", tc.name)
			}
			afterCalls := atomic.LoadInt32(&fake.callCount)
			if afterCalls != beforeCalls {
				t.Fatalf("expected 0 resolver calls for invalid input %q, got %d calls", tc.name, afterCalls-beforeCalls)
			}
		})
	}
}

func TestImagePlan_DigestPreservation(t *testing.T) {
	fake := &fakeResolver{
		resolveFunc: func(ctx context.Context, repository, reference string) (appcontracts.ResolvedMetadataResult, error) {
			if reference != "sha256:ba8225b31402a22a76ddc2328aa9583485718d6eaccda53e4d9cc3704207f3c4" {
				return appcontracts.ResolvedMetadataResult{}, errors.New("expected exact digest in resolve request")
			}
			return appcontracts.ResolvedMetadataResult{
				Repository:  repository,
				Digest:      reference,
				ResolvedTag: reference,
				EvidenceRef: "ev_test_digest",
			}, nil
		},
	}
	service := NewImageDeliveryService(fake)
	adminID := domain.ID("adm_0123456789abcdef")

	// Verify supplied digest is passed through directly without conversion to latest
	input := appcontracts.ImagePlanInput{
		AppName: "digest-app",
		Image:   "nginx@sha256:ba8225b31402a22a76ddc2328aa9583485718d6eaccda53e4d9cc3704207f3c4",
		Port:    80,
	}

	plan, err := service.CreatePlan(context.Background(), adminID, input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if plan.ResolvedImage.Digest != "sha256:ba8225b31402a22a76ddc2328aa9583485718d6eaccda53e4d9cc3704207f3c4" {
		t.Fatalf("expected preserved digest, got %s", plan.ResolvedImage.Digest)
	}
}

func TestImagePlan_ResolvedRepositoryMismatchRefused(t *testing.T) {
	fake := &fakeResolver{
		resolveFunc: func(ctx context.Context, repository, reference string) (appcontracts.ResolvedMetadataResult, error) {
			return appcontracts.ResolvedMetadataResult{
				Repository:  "registry-1.docker.io/other/repo",
				Digest:      "sha256:ba8225b31402a22a76ddc2328aa9583485718d6eaccda53e4d9cc3704207f3c4",
				ResolvedTag: reference,
				EvidenceRef: "ev_test_mismatch",
			}, nil
		},
	}
	service := NewImageDeliveryService(fake)
	adminID := domain.ID("adm_0123456789abcdef")

	input := appcontracts.ImagePlanInput{
		AppName: "mismatch-app",
		Image:   "nginx:latest",
		Port:    80,
	}

	_, err := service.CreatePlan(context.Background(), adminID, input)
	if err == nil {
		t.Fatalf("expected conflict error on mismatched resolver repository, got nil")
	}
	var domErr *domain.DomainError
	if !errors.As(err, &domErr) || domErr.Code != domain.ErrConflict {
		t.Fatalf("expected ErrConflict, got: %v", err)
	}
}
