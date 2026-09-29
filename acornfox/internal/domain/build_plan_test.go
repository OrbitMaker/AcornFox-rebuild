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

func TestBuildPlanAcornFoxNetworkPolicyIsNullableOfflineOrBoundControlledEgress(t *testing.T) {
	base := BuildPlan{
		ID: "plan_egress", SourceRevisionID: "src_egress", SourceDigest: "sha256:" + strings.Repeat("a", 64),
		ServiceName: "web", Kind: BuildDockerfile, ContextPath: ".", DockerfilePath: "Dockerfile", TargetRepository: "registry.example/open-card/web",
		Output: BuildOutputContract{Format: BuildOutputOCI, Retention: BuildRetentionPersist, StorageKey: "app_1/src_egress/web"}, IdempotencyKey: "build-plan-egress",
	}
	for name, plan := range map[string]BuildPlan{
		"legacy_null_is_offline": base,
		"explicit_offline":       func() BuildPlan { value := base; value.AcornFoxNetworkMode = "none"; return value }(),
	} {
		t.Run(name, func(t *testing.T) {
			if err := plan.Validate(); err != nil {
				t.Fatalf("valid offline plan rejected: %v", err)
			}
			mode, digest := plan.EffectiveAcornFoxNetworkPolicy()
			if mode != "none" || digest != "" {
				t.Fatalf("effective offline identity = %q/%q", mode, digest)
			}
		})
	}

	controlled := base
	controlled.AcornFoxDefinitionDigest = "sha256:" + strings.Repeat("b", 64)
	controlled.AcornFoxDockerfileDigest = "sha256:" + strings.Repeat("c", 64)
	controlled.AcornFoxNetworkMode = "controlled_egress_v1"
	controlled.AcornFoxWorkerPolicyDigest = "sha256:" + strings.Repeat("d", 64)
	if err := controlled.Validate(); err != nil {
		t.Fatalf("bound controlled plan rejected: %v", err)
	}
	if mode, digest := controlled.EffectiveAcornFoxNetworkPolicy(); mode != controlled.AcornFoxNetworkMode || digest != controlled.AcornFoxWorkerPolicyDigest {
		t.Fatalf("controlled identity = %q/%q", mode, digest)
	}

	for name, plan := range map[string]BuildPlan{
		"legacy_digest": func() BuildPlan {
			value := base
			value.AcornFoxWorkerPolicyDigest = controlled.AcornFoxWorkerPolicyDigest
			return value
		}(),
		"offline_digest": func() BuildPlan {
			value := base
			value.AcornFoxNetworkMode = "none"
			value.AcornFoxWorkerPolicyDigest = controlled.AcornFoxWorkerPolicyDigest
			return value
		}(),
		"unknown_mode": func() BuildPlan { value := base; value.AcornFoxNetworkMode = "default"; return value }(),
		"controlled_unbound": func() BuildPlan {
			value := base
			value.AcornFoxNetworkMode = "controlled_egress_v1"
			value.AcornFoxWorkerPolicyDigest = controlled.AcornFoxWorkerPolicyDigest
			return value
		}(),
		"controlled_uppercase": func() BuildPlan {
			value := controlled
			value.AcornFoxWorkerPolicyDigest = "sha256:" + strings.Repeat("D", 64)
			return value
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			if err := plan.Validate(); err == nil {
				t.Fatalf("invalid network policy accepted: %+v", plan)
			}
		})
	}
}
