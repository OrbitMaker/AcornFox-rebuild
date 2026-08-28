package tools

import (
	"errors"
	"testing"

	"github.com/open-card/open-card/internal/domain"
)

func TestAI_CATALOG_001_DefaultCatalogAllowsBoundedReadAndBuildFixture(t *testing.T) {
	catalog := DefaultCatalog()
	if got := len(catalog.List()); got != 7 {
		t.Fatalf("default catalog contains %d tools, want 7", got)
	}
	read, err := catalog.ValidateAction(domain.AIAction{
		ToolID:         ToolWorkspaceRead,
		ToolVersion:    ToolVersionV1,
		Risk:           string(RiskR0),
		ExpectedResult: "bounded file contents",
		ValidationID:   "workspace.read.v1",
		Parameters:     map[string]any{"path": "README.md"},
	})
	if err != nil {
		t.Fatalf("bounded read rejected: %v", err)
	}
	if read.Risk != RiskR0 || read.Network.Mode != NetworkDisabled {
		t.Fatalf("read descriptor lost policy: %#v", read)
	}
	build, err := catalog.ValidateAction(domain.AIAction{
		ToolID:         ToolWorkspaceBuildTest,
		ToolVersion:    ToolVersionV1,
		Risk:           string(RiskR1),
		ExpectedResult: "fixture passes",
		ValidationID:   "build.exit_and_artifact_check",
	})
	if err != nil {
		t.Fatalf("bounded build fixture rejected: %v", err)
	}
	if build.Kind != KindBuildTest || build.Risk != RiskR1 {
		t.Fatalf("unexpected build descriptor: %#v", build)
	}
}

func TestAI_CATALOG_002_UnknownVersionParametersAndForbiddenActionsFailClosed(t *testing.T) {
	catalog := DefaultCatalog()
	base := domain.AIAction{ToolID: ToolWorkspaceRead, ToolVersion: ToolVersionV1, Risk: string(RiskR0), ExpectedResult: "bounded file contents", ValidationID: "workspace.read.v1", Parameters: map[string]any{"path": "README.md"}}
	unknownVersion := base
	unknownVersion.ToolVersion = "v2"
	if _, err := catalog.ValidateAction(unknownVersion); !errors.Is(err, ErrVersion) {
		t.Fatalf("unknown version error = %v, want ErrVersion", err)
	}
	unknownParameter := base
	unknownParameter.Parameters = map[string]any{"path": "README.md", "shell": "cat README.md"}
	if _, err := catalog.ValidateAction(unknownParameter); !errors.Is(err, ErrParameters) {
		t.Fatalf("unknown parameter error = %v, want ErrParameters", err)
	}
	dangerous := base
	dangerous.Parameters = map[string]any{"path": "/var/run/docker.sock"}
	if _, err := catalog.ValidateAction(dangerous); !errors.Is(err, ErrForbidden) && !errors.Is(err, ErrParameters) {
		t.Fatalf("dangerous path error = %v, want forbidden/parameters", err)
	}
	production := domain.AIAction{ToolID: "production.restart", ToolVersion: ToolVersionV1, Risk: string(RiskR3), ExpectedResult: "controller handoff", ValidationID: "controller.restart"}
	custom := ToolDescriptor{ID: production.ToolID, Version: ToolVersionV1, Kind: KindBuildTest, Risk: RiskR3, ParameterSchema: ParameterSchema{}, Workspace: ScopeWorkspace, Limits: DefaultResourceLimits(), Network: NetworkPolicy{Mode: NetworkDisabled}, ValidationID: production.ValidationID, ControllerHandoffOnly: true, RequiresUserConfirmation: true}
	if err := catalog.Register(custom); err == nil {
		t.Fatal("production mutation descriptor was registered")
	}
}

func TestToolCatalogRejectsInvalidRiskAndR2WithoutConfirmation(t *testing.T) {
	descriptor := ToolDescriptor{ID: "workspace.candidate", Version: ToolVersionV1, Kind: KindPatch, Risk: RiskR2, ParameterSchema: ParameterSchema{}, Workspace: ScopeWorkspace, Limits: DefaultResourceLimits(), Network: NetworkPolicy{Mode: NetworkDisabled}, ValidationID: "candidate.v1"}
	if err := descriptor.Validate(); err == nil {
		t.Fatal("R2 descriptor without confirmation was accepted")
	}
	if RiskClass("R9").Valid() {
		t.Fatal("unknown risk class was accepted")
	}
}
