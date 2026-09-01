package domain

import (
	"strings"
	"testing"
)

func TestBuildPlanAcornFoxDigestBindingIsOptionalAndPaired(t *testing.T) {
	base := BuildPlan{
		ID:               "plan_1",
		SourceRevisionID: "src_1",
		SourceDigest:     "sha256:" + strings.Repeat("a", 64),
		ServiceName:      "web",
		Kind:             BuildDockerfile,
		ContextPath:      ".",
		DockerfilePath:   "Dockerfile",
		TargetRepository: "registry.example/open-card/web",
		Output:           BuildOutputContract{Format: BuildOutputOCI, Retention: BuildRetentionPersist, StorageKey: "app_1/src_1/web"},
		IdempotencyKey:   "build-plan-1",
	}
	if err := base.Validate(); err != nil {
		t.Fatalf("legacy unbound plan rejected: %v", err)
	}
	legacyStatic := base
	legacyStatic.Kind = BuildStatic
	legacyStatic.ContextPath = "dist"
	legacyStatic.DockerfilePath = ""
	legacyStatic.StaticRuntimeDigest = "sha256:" + strings.Repeat("d", 64)
	if err := legacyStatic.Validate(); err != nil {
		t.Fatalf("legacy unbound static plan rejected: %v", err)
	}
	legacyNested := base
	legacyNested.ContextPath = "service"
	legacyNested.DockerfilePath = "service/Dockerfile"
	if err := legacyNested.Validate(); err != nil {
		t.Fatalf("legacy unbound nested Dockerfile plan rejected: %v", err)
	}

	for _, candidate := range []BuildPlan{
		func() BuildPlan {
			plan := base
			plan.AcornFoxDefinitionDigest = "sha256:" + strings.Repeat("b", 64)
			return plan
		}(),
		func() BuildPlan {
			plan := base
			plan.AcornFoxDefinitionDigest = "sha256:" + strings.Repeat("b", 64)
			plan.AcornFoxDockerfileDigest = "sha256:not-a-digest"
			return plan
		}(),
	} {
		if err := candidate.Validate(); err == nil {
			t.Fatalf("invalid AcornFox digest binding accepted: %+v", candidate)
		}
	}

	bound := base
	bound.AcornFoxDefinitionDigest = "sha256:" + strings.Repeat("b", 64)
	bound.AcornFoxDockerfileDigest = "sha256:" + strings.Repeat("c", 64)
	if err := bound.Validate(); err != nil {
		t.Fatalf("bound plan rejected: %v", err)
	}

	for _, candidate := range []BuildPlan{
		func() BuildPlan {
			plan := bound
			plan.Kind = BuildStatic
			plan.DockerfilePath = ""
			plan.StaticRuntimeDigest = "sha256:" + strings.Repeat("d", 64)
			return plan
		}(),
		func() BuildPlan {
			plan := bound
			plan.ContextPath = "service"
			return plan
		}(),
		func() BuildPlan {
			plan := bound
			plan.DockerfilePath = "service/Dockerfile"
			return plan
		}(),
		func() BuildPlan {
			plan := bound
			plan.StaticRuntimeDigest = "sha256:" + strings.Repeat("d", 64)
			return plan
		}(),
	} {
		if err := candidate.Validate(); err == nil {
			t.Fatalf("non-root AcornFox digest binding accepted: %+v", candidate)
		}
	}
}
