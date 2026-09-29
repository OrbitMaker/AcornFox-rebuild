package domain

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func testImageDigest() ImageDigest {
	return ImageDigest{Repository: "registry.example.test/open-card/app", Digest: "sha256:" + strings.Repeat("a", 64)}
}

func TestSCHEMA_SERVICE_001_ServiceSourceIsAnExactTaggedUnion(t *testing.T) {
	image := testImageDigest()
	cases := []struct {
		name   string
		source ServiceSource
		valid  bool
	}{
		{name: "static", source: ServiceSource{Kind: ServiceStatic, Static: &StaticSource{Directory: "public"}}, valid: true},
		{name: "dockerfile", source: ServiceSource{Kind: ServiceDockerfile, Dockerfile: &DockerfileSource{Context: ".", Dockerfile: "Dockerfile"}}, valid: true},
		{name: "prebuilt", source: ServiceSource{Kind: ServicePrebuilt, Prebuilt: &PrebuiltSource{Image: image}}, valid: true},
		{name: "prebuilt reference awaiting resolution", source: ServiceSource{Kind: ServicePrebuilt, Prebuilt: &PrebuiltSource{Reference: "nginx:stable"}}, valid: true},
		{name: "two variants", source: ServiceSource{Kind: ServiceStatic, Static: &StaticSource{Directory: "public"}, Dockerfile: &DockerfileSource{Context: ".", Dockerfile: "Dockerfile"}}, valid: false},
		{name: "kind mismatch", source: ServiceSource{Kind: ServiceStatic, Dockerfile: &DockerfileSource{Context: ".", Dockerfile: "Dockerfile"}}, valid: false},
		{name: "missing variant", source: ServiceSource{Kind: ServicePrebuilt}, valid: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.source.Validate()
			if tc.valid && err != nil {
				t.Fatalf("expected valid source, got %v", err)
			}
			if !tc.valid && err == nil {
				t.Fatal("expected invalid source to be rejected")
			}
		})
	}
}

func TestSCHEMA_COMP_001_ComposeSupportedSubsetMapsToControlledServiceGroup(t *testing.T) {
	file := ComposeFile{
		Version:  "3.9",
		Networks: map[string]ComposeNetwork{"private": {Internal: true}},
		Volumes:  map[string]ComposeVolume{"data": {}},
		Services: map[string]ComposeService{
			"db": {
				Image:       "postgres@sha256:" + strings.Repeat("b", 64),
				Volumes:     []ComposeVolumeMount{{Source: "data", Target: "/var/lib/postgresql/data"}},
				Networks:    []string{"private"},
				Restart:     "unless-stopped",
				Environment: map[string]string{"POSTGRES_DB": "app"},
			},
			"web": {
				Build:       &ComposeBuild{Context: ".", Dockerfile: "deploy/Dockerfile"},
				Command:     []string{"server", "--listen", ":8080"},
				Entrypoint:  []string{"/bin/app"},
				Environment: map[string]string{"APP_ENV": "test"},
				Ports:       []ComposePort{{Target: 8080, Protocol: "tcp"}},
				Volumes:     []ComposeVolumeMount{{Source: "data", Target: "/var/lib/app", ReadOnly: true}},
				DependsOn:   map[string]ComposeDependency{"db": {Condition: "service_healthy"}},
				Healthcheck: &ComposeHealthcheck{Test: []string{"CMD", "wget", "-qO-", "http://localhost:8080/health"}, Interval: "5s", Timeout: "2s", Retries: 3},
				Restart:     "always",
				Networks:    []string{"private"},
				Deploy:      &ComposeDeploy{Resources: &ComposeResources{Limits: &ComposeResourceLimits{CPUs: "500m", Memory: "64MiB"}}},
			},
		},
	}
	group, report, err := file.ToServiceGroup(ID("app_schema"), "compose-test", time.Unix(100, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(group.Services) != 2 || group.Services[0].Name != "db" || group.Services[1].Name != "web" {
		t.Fatalf("unexpected deterministic service order: %#v", group.Services)
	}
	if group.Services[1].Role != RoleIngress || group.Services[1].Port != 8080 || group.Services[1].Resources.CPUMillis != 500 || group.Services[1].Resources.MemoryBytes != 64*1024*1024 {
		t.Fatalf("supported compose fields were not mapped: %#v", group.Services[1])
	}
	if group.Services[0].Role != RoleStateful {
		t.Fatalf("writable named-volume service was not classified stateful: %#v", group.Services[0])
	}
	for _, want := range []string{"services.web.build.context", "services.web.command", "services.web.depends_on", "services.web.deploy.resources", "services.web.environment", "services.web.healthcheck", "services.web.networks", "services.web.ports", "services.web.volumes", "services.db.image"} {
		found := false
		for _, got := range report.MappedFields {
			if got == want || strings.HasPrefix(got, want) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("mapping report missing %q: %#v", want, report.MappedFields)
		}
	}
	if err := group.Validate(); err != nil {
		t.Fatal(err)
	}
	file.Services["web"].Environment["DATABASE_PASSWORD"] = "bare-runtime-canary"
	if _, _, err := file.ToServiceGroup(ID("app_schema"), "compose-sensitive-literal", time.Unix(101, 0)); err == nil {
		t.Fatal("sensitive Compose environment literal bypassed SecretReference")
	}
}

func TestSCHEMA_COMP_002_ComposeUnknownFieldsFailClosedWithPath(t *testing.T) {
	data := []byte(`{"services":{"web":{"image":"registry.example.test/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","mystery":true}}}`)
	_, err := DecodeComposeJSON(data)
	if err == nil {
		t.Fatal("expected unknown compose field to be rejected")
	}
	if !strings.Contains(err.Error(), "services.web.mystery") {
		t.Fatalf("unknown field path was not reported: %v", err)
	}
	nested := []byte(`{"services":{"web":{"build":{"context":".","mystery":true}}}}`)
	_, err = DecodeComposeJSON(nested)
	if err == nil || !strings.Contains(err.Error(), "services.web.build.mystery") {
		t.Fatalf("nested unknown field path was not reported: %v", err)
	}

	for name, service := range map[string]ComposeService{
		"published host port": {Image: "registry.example.test/app@sha256:" + strings.Repeat("c", 64), Ports: []ComposePort{{Target: 8080, Published: 8080}}},
		"privileged":          {Image: "registry.example.test/app@sha256:" + strings.Repeat("d", 64), Privileged: boolPtr(true)},
		"host bind":           {Image: "registry.example.test/app@sha256:" + strings.Repeat("e", 64), Volumes: []ComposeVolumeMount{{Source: "/var/run/docker.sock", Target: "/var/run/docker.sock", Type: "bind"}}},
	} {
		t.Run(name, func(t *testing.T) {
			if err := service.Validate(); err == nil {
				t.Fatal("expected forbidden compose capability to fail closed")
			}
		})
	}
}

func TestSCHEMA_OP_001_OneActiveOperationPerEnvironment(t *testing.T) {
	base := Operation{ApplicationID: ID("app_schema"), EnvironmentID: ID("env_schema"), TargetRef: "deployment/1", Type: OperationDeploy, IdempotencyKey: "op-1", Status: OperationRunning}
	base.ID = ID("op-1")
	second := base
	second.ID = ID("op-2")
	second.IdempotencyKey = "op-2"
	if err := ValidateActiveOperations([]Operation{base, second}); err == nil {
		t.Fatal("expected two active operations in one environment to be rejected")
	}
	second.EnvironmentID = ID("env-other")
	if err := ValidateActiveOperations([]Operation{base, second}); err != nil {
		t.Fatalf("different environments should allow active operations: %v", err)
	}
	base.Status = OperationSucceeded
	second.EnvironmentID = ID("env_schema")
	if err := ValidateActiveOperations([]Operation{base, second}); err != nil {
		t.Fatalf("terminal operation should not block a new active operation: %v", err)
	}
}

func TestSCHEMA_ROUTE_001_RouteUniquenessAndIngressTarget(t *testing.T) {
	app := ID("app_schema")
	image := testImageDigest()
	group := ServiceGroup{ID: ID("group_schema"), ApplicationID: app, Services: []ServiceSpec{
		{Name: "web", Role: RoleIngress, Required: true, Source: ServiceSource{Kind: ServicePrebuilt, Prebuilt: &PrebuiltSource{Image: image}}},
		{Name: "worker", Role: RoleWorker, Required: true, Source: ServiceSource{Kind: ServicePrebuilt, Prebuilt: &PrebuiltSource{Image: image}}},
	}}
	route := Route{ID: ID("route-1"), ApplicationID: app, DeploymentID: ID("dep-1"), ServiceName: "web", Host: "Example.test", Path: "/", Verified: true}
	duplicate := route
	duplicate.ID = ID("route-2")
	duplicate.Host = "example.test"
	duplicate.Path = "///"
	if err := ValidateRouteSet([]Route{route, duplicate}, group); err == nil {
		t.Fatal("expected duplicate host/path route to be rejected")
	}
	nonIngress := route
	nonIngress.ID = ID("route-3")
	nonIngress.ServiceName = "worker"
	nonIngress.Path = "/worker"
	if err := ValidateRouteSet([]Route{nonIngress}, group); err == nil {
		t.Fatal("expected non-ingress route target to be rejected")
	}
	if err := ValidateRouteSet([]Route{route}, group); err != nil {
		t.Fatalf("valid ingress route was rejected: %v", err)
	}
}

func TestSCHEMA_AI_001_AIActionPlanRequiresBoundedActionSchema(t *testing.T) {
	evidence := EvidenceRef{ID: ID("ev-ai"), Kind: "test", Digest: "sha256:evidence"}
	plan := AIActionPlan{ID: ID("plan-ai"), SchemaVersion: "1.0", PolicyVersion: "policy-v1", TaskType: "build_failure", TargetRefs: map[string]string{"build": "build-1"}, Sources: []string{"context:sha256:test"}, EvidenceRefs: []EvidenceRef{evidence}, Actions: []AIAction{{ToolID: "workspace.build_test", ToolVersion: "v1", Risk: AIRiskSandboxValidation, ExpectedResult: "build exit and artifact evidence", ValidationID: "validation-1"}}, Budget: AIPlanBudget{MaxTokens: 128, MaxDurationMS: 1000, MaxActions: 1}, RollbackID: "workspace.discard", Confidence: 0.8}
	if err := plan.Validate(); err != nil {
		t.Fatal(err)
	}
	for field := range map[string]struct{}{"tool": {}, "version": {}, "risk": {}, "expected": {}, "validation": {}} {
		invalid := plan
		invalid.Actions = append([]AIAction(nil), plan.Actions...)
		switch field {
		case "tool":
			invalid.Actions[0].ToolID = ""
		case "version":
			invalid.Actions[0].ToolVersion = ""
		case "risk":
			invalid.Actions[0].Risk = ""
		case "expected":
			invalid.Actions[0].ExpectedResult = ""
		case "validation":
			invalid.Actions[0].ValidationID = ""
		}
		if err := invalid.Validate(); err == nil {
			t.Errorf("missing %s should be rejected", field)
		}
	}
}

func TestSCHEMA_AI_002_RuleCandidateRequiresReviewTestsAndVersionedPromotion(t *testing.T) {
	evidence := EvidenceRef{ID: ID("ev-rule"), Kind: "regression", Digest: "sha256:rule"}
	candidate := RuleCandidate{ID: ID("candidate-1"), Fingerprint: "dockerfile-missing-port", Status: RuleCandidateTesting, SuccessCount: 3, ApplicationCount: 2, TestEvidence: []EvidenceRef{evidence}}
	if err := candidate.Transition(RuleCandidateActive); !IsCode(err, ErrInvalidTransition) {
		t.Fatalf("direct active transition must be rejected as invalid_transition, got %v", err)
	}
	if _, err := candidate.Promote("v1"); err == nil {
		t.Fatal("candidate without approval/reviewer must not promote")
	}
	candidate.Status = RuleCandidateActive
	if err := candidate.Validate(); err == nil {
		t.Fatal("active must not be a RuleCandidate state")
	}
	candidate.Status = RuleCandidateApproved
	if _, err := candidate.Promote("v1"); err == nil {
		t.Fatal("candidate without reviewer must not promote")
	}
	candidate.ReviewedBy = "operator-1"
	candidate.ReviewDecision = "approved"
	candidate.RegressionPassed = true
	candidate.ShadowPassed = true
	candidate.ProposedVersion = "v1"
	rule, err := candidate.Promote("v1")
	if err != nil {
		t.Fatal(err)
	}
	if !rule.Enabled || rule.CandidateID != candidate.ID || candidate.Status != RuleCandidatePromoted {
		t.Fatalf("promotion did not produce a versioned enabled rule: candidate=%#v rule=%#v", candidate, rule)
	}
	if err := rule.Validate(); err != nil {
		t.Fatal(err)
	}
}

func boolPtr(value bool) *bool { return &value }

func TestSCHEMA_COMP_JSONRoundTripKeepsStrictModel(t *testing.T) {
	file := ComposeFile{Services: map[string]ComposeService{"web": {Image: "registry.example.test/app@sha256:" + strings.Repeat("f", 64)}}}
	data, err := json.Marshal(file)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeComposeJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Services["web"].Image != file.Services["web"].Image {
		t.Fatalf("strict compose round trip changed image: %#v", decoded)
	}
}
