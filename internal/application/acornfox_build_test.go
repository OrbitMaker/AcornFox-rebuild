package application

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/foundation"
)

func TestAcornFoxBuildBinderPinsReadyRootDockerfileOffline(t *testing.T) {
	workspace := t.TempDir()
	dockerfile := []byte("FROM scratch\nCMD [\"/app\"]\n")
	if err := os.WriteFile(filepath.Join(workspace, "Dockerfile"), dockerfile, 0o400); err != nil {
		t.Fatal(err)
	}
	sourceDigest, err := foundation.HashDirectory(workspace)
	if err != nil {
		t.Fatal(err)
	}
	source := domain.SourceRevision{ID: "src_1", ApplicationID: "app_1", Kind: domain.SourceUpload, Locator: "upload://fixture", ContentDigest: "sha256:" + sourceDigest, WorkspaceRef: workspace, CreatedAt: time.Unix(1, 0).UTC(), Immutable: true}
	dockerfileDigest := "sha256:" + strings.Repeat("a", 64)
	definition, err := contracts.FinalizeAcornFoxDockerfileDefinition(contracts.AcornFoxDockerfileDefinition{Status: contracts.AcornFoxDockerfileReady, SourceRevisionID: source.ID, SourceContentDigest: source.ContentDigest, DockerfileDigest: dockerfileDigest, StageCount: 1, FinalStage: &contracts.AcornFoxDockerfileStage{Name: "final", Index: 0, From: "scratch"}})
	if err != nil {
		t.Fatalf("test definition invalid: %v", err)
	}
	now := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	binder := AcornFoxBuildBinder{}
	first, err := binder.Bind(definition, source, "publish-1", "registry.open-card.local/apps/web", "builds/src_1/web", now)
	if err != nil {
		t.Fatal(err)
	}
	second, err := binder.Bind(definition, source, "publish-1", "registry.open-card.local/apps/web", "builds/src_1/web", now)
	if err != nil {
		t.Fatal(err)
	}
	if first.BuildID != second.BuildID || first.Plan.ID != second.Plan.ID || first.Plan.AcornFoxDefinitionDigest != definition.DefinitionDigest || first.Plan.AcornFoxDockerfileDigest != definition.DockerfileDigest {
		t.Fatalf("binder did not deterministically preserve paired definition digests: first=%#v second=%#v", first, second)
	}
	if first.Plan.Kind != domain.BuildDockerfile || first.Plan.ContextPath != "." || first.Plan.DockerfilePath != "Dockerfile" || first.Resources != (contracts.ResourceLimits{CPUMillis: 500, MemoryBytes: 512 << 20, DiskBytes: 1 << 30, TimeoutSeconds: 300, ConcurrencySlot: 1}) || first.Network.Mode != "none" || first.Plan.AcornFoxNetworkMode != string(first.Network.Mode) || first.Plan.AcornFoxWorkerPolicyDigest != "" || first.Resources.PIDs != 0 {
		t.Fatalf("binder did not enforce the offline one-build policy: %#v", first)
	}
	controlled, err := binder.BindControlledEgress(definition, source, "publish-1", "registry.open-card.local/apps/web", "builds/src_1/web", "sha256:"+strings.Repeat("b", 64), now)
	if err != nil {
		t.Fatal(err)
	}
	if controlled.Network.Mode != contracts.NetworkModeControlledEgressV1 || controlled.Network.WorkerPolicyDigest != "sha256:"+strings.Repeat("b", 64) || controlled.Plan.AcornFoxNetworkMode != string(controlled.Network.Mode) || controlled.Plan.AcornFoxWorkerPolicyDigest != controlled.Network.WorkerPolicyDigest || controlled.BuildID == first.BuildID || controlled.Plan.ID == first.Plan.ID {
		t.Fatalf("controlled egress was not separately bound: offline=%#v controlled=%#v", first, controlled)
	}
	if _, err := binder.BindControlledEgress(definition, source, "publish-1", "registry.open-card.local/apps/web", "builds/src_1/web", "sha256:malformed", now); err == nil {
		t.Fatal("malformed controlled-egress policy digest was accepted")
	}
}

func TestAcornFoxBuildBinderRejectsStaleDefinitionDigestAndZeroAcceptedTime(t *testing.T) {
	workspace := t.TempDir()
	if err := os.WriteFile(filepath.Join(workspace, "Dockerfile"), []byte("FROM scratch\nWORKDIR /app\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	digest, err := foundation.HashDirectory(workspace)
	if err != nil {
		t.Fatal(err)
	}
	source := domain.SourceRevision{ID: "src_2", ApplicationID: "app_2", Kind: domain.SourceUpload, Locator: "upload://fixture", ContentDigest: "sha256:" + digest, WorkspaceRef: workspace, CreatedAt: time.Unix(1, 0).UTC(), Immutable: true}
	definition, err := contracts.FinalizeAcornFoxDockerfileDefinition(contracts.AcornFoxDockerfileDefinition{Status: contracts.AcornFoxDockerfileReady, SourceRevisionID: source.ID, SourceContentDigest: source.ContentDigest, DockerfileDigest: "sha256:" + strings.Repeat("a", 64), StageCount: 1, FinalStage: &contracts.AcornFoxDockerfileStage{Name: "final", Index: 0, From: "scratch"}, Workdir: "/app", Command: &contracts.AcornFoxDockerfileCommand{Form: "exec", Values: []string{"/app"}}, ExposedPorts: []contracts.AcornFoxDockerfilePort{{Port: 8080, Protocol: "tcp"}}, Environment: []contracts.AcornFoxDockerfileEnvironment{{Name: "MODE", Value: "prod"}}, Healthcheck: contracts.AcornFoxDockerfileHealthcheck{Present: true, Form: "exec", Test: []string{"/app", "health"}, IntervalSeconds: 30, TimeoutSeconds: 30, Retries: 3}, Gaps: []string{"external_base_config_unobserved"}, Warnings: []string{"run_instruction"}})
	if err != nil {
		t.Fatal(err)
	}
	binder := AcornFoxBuildBinder{}
	if _, err := binder.Bind(definition, source, "build", "registry.open-card.local/apps/web", "builds-web", time.Time{}); err == nil {
		t.Fatal("zero accepted time was accepted")
	}
	for name, mutate := range map[string]func(*contracts.AcornFoxDockerfileDefinition){
		"workdir": func(value *contracts.AcornFoxDockerfileDefinition) { value.Workdir = "/mutated" },
		"command": func(value *contracts.AcornFoxDockerfileDefinition) {
			value.Command = &contracts.AcornFoxDockerfileCommand{Form: "exec", Values: []string{"/other"}}
		},
		"environment": func(value *contracts.AcornFoxDockerfileDefinition) {
			value.Environment = []contracts.AcornFoxDockerfileEnvironment{{Name: "MODE", Value: "debug"}}
		},
		"healthcheck": func(value *contracts.AcornFoxDockerfileDefinition) { value.Healthcheck.TimeoutSeconds = 31 },
		"ports": func(value *contracts.AcornFoxDockerfileDefinition) {
			value.ExposedPorts = []contracts.AcornFoxDockerfilePort{{Port: 9090, Protocol: "tcp"}}
		},
		"gaps":     func(value *contracts.AcornFoxDockerfileDefinition) { value.Gaps = []string{"healthcheck_missing"} },
		"warnings": func(value *contracts.AcornFoxDockerfileDefinition) { value.Warnings = []string{"copy_instruction"} },
	} {
		t.Run(name, func(t *testing.T) {
			stale := definition
			mutate(&stale)
			if _, err := binder.Bind(stale, source, "build", "registry.open-card.local/apps/web", "builds-web", time.Now()); err == nil {
				t.Fatal("semantic definition mutation retained an old digest")
			}
		})
	}
}

func TestAcornFoxBuildBinderRejectsNonReadyOrMismatchedSource(t *testing.T) {
	source := domain.SourceRevision{ID: "src_1", ApplicationID: "app_1", Kind: domain.SourceUpload, Locator: "upload://fixture", ContentDigest: "sha256:" + strings.Repeat("a", 64), WorkspaceRef: t.TempDir(), CreatedAt: time.Unix(1, 0).UTC(), Immutable: true}
	definition := contracts.AcornFoxDockerfileDefinition{Status: contracts.AcornFoxDockerfileWaitingLater, SourceRevisionID: source.ID, SourceContentDigest: source.ContentDigest, DefinitionDigest: "sha256:" + strings.Repeat("b", 64), Gaps: []string{"root_dockerfile_missing"}}
	if _, err := (AcornFoxBuildBinder{}).Bind(definition, source, "build", "registry.open-card.local/apps/web", "builds/web", time.Now()); err == nil {
		t.Fatal("waiting definition was accepted for a build")
	}
}
