package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
)

type acornFoxDeploymentPlanImporter struct {
	definition contracts.AcornFoxDockerfileDefinition
	err        error
}

func (i acornFoxDeploymentPlanImporter) Import(domain.SourceRevision) (contracts.AcornFoxDockerfileDefinition, error) {
	return i.definition, i.err
}

func acornFoxDeploymentPlanSource() domain.SourceRevision {
	return domain.SourceRevision{
		ID: "src_plan", ApplicationID: "app_plan", Kind: domain.SourceGitHTTPS,
		Locator: "https://github.com/example/app.git", Ref: "main", Commit: strings.Repeat("a", 40),
		ContentDigest: "sha256:" + strings.Repeat("b", 64), WorkspaceRef: "/tmp/acornfox-plan",
		CreatedAt: time.Unix(1_700_000_000, 0).UTC(), Immutable: true,
	}
}

func acornFoxDeploymentPlanDefinition(status contracts.AcornFoxDockerfileStatus, ports ...int) contracts.AcornFoxDockerfileDefinition {
	source := acornFoxDeploymentPlanSource()
	definition := contracts.AcornFoxDockerfileDefinition{
		Status: status, SourceRevisionID: source.ID, SourceContentDigest: source.ContentDigest,
		DefinitionDigest: "sha256:" + strings.Repeat("c", 64),
		ExposedPorts:     []contracts.AcornFoxDockerfilePort{}, Environment: []contracts.AcornFoxDockerfileEnvironment{},
		Gaps: []string{}, Warnings: []string{},
	}
	if status == contracts.AcornFoxDockerfileReady {
		definition.DockerfileDigest = "sha256:" + strings.Repeat("d", 64)
		definition.StageCount = 1
		definition.FinalStage = &contracts.AcornFoxDockerfileStage{Name: "final", Index: 0, From: "scratch"}
		for _, port := range ports {
			definition.ExposedPorts = append(definition.ExposedPorts, contracts.AcornFoxDockerfilePort{Port: port, Protocol: "tcp"})
		}
	}
	if status == contracts.AcornFoxDockerfileWaitingLater {
		definition.Gaps = []string{"root_dockerfile_missing"}
	}
	return definition
}

func TestAcornFoxDeploymentPlanProjectsPortAndHealthFacts(t *testing.T) {
	source := acornFoxDeploymentPlanSource()
	definition := acornFoxDeploymentPlanDefinition(contracts.AcornFoxDockerfileReady, 3000)
	definition.Healthcheck = contracts.AcornFoxDockerfileHealthcheck{Present: true, Form: "shell", Test: []string{"curl -f http://localhost:3000/health"}, IntervalSeconds: 30, TimeoutSeconds: 3, Retries: 3}
	definition.Environment = []contracts.AcornFoxDockerfileEnvironment{{Name: "PORT", Value: "3000"}, {Name: "API_TOKEN", Redacted: true}}
	server := NewAcornFoxServer()
	server.SetAcornFoxDeploymentStore(acornFoxDirectReadFixture{source: source})
	server.SetAcornFoxDockerfileImporter(acornFoxDeploymentPlanImporter{definition: definition})
	now := time.Unix(1_700_000_000, 0).UTC()
	_, session, _ := attachTestAcornFoxAdministratorTokens(t, server, &now)

	request := httptest.NewRequest(http.MethodGet, acornFoxAPIBase+"/app_plan/sources/src_plan/deployment-plan", nil)
	request.AddCookie(session)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var plan acornFoxDeploymentPlanResponse
	if err := json.Unmarshal(response.Body.Bytes(), &plan); err != nil {
		t.Fatal(err)
	}
	if plan.SourceRevisionID != source.ID || plan.RepositoryURL != source.Locator || plan.Ref != "main" || plan.Commit != source.Commit {
		t.Fatalf("source identity=%+v", plan)
	}
	if plan.PortSelection.Status != "selected" || plan.PortSelection.Reason != "dockerfile_expose" || plan.PortSelection.SelectedPort == nil || *plan.PortSelection.SelectedPort != 3000 || !plan.ReadyToDeploy {
		t.Fatalf("port selection=%+v ready=%v", plan.PortSelection, plan.ReadyToDeploy)
	}
	if !plan.Healthcheck.Present || plan.Healthcheck.Test[0] != "curl -f http://localhost:3000/health" {
		t.Fatalf("healthcheck=%+v", plan.Healthcheck)
	}
	if len(plan.Environment) != 2 || !plan.Environment[1].Redacted || plan.Environment[1].Value != "" {
		t.Fatalf("environment leaked or invalid: %+v", plan.Environment)
	}
}

func TestAcornFoxDeploymentPlanRequiresUserChoiceForAmbiguousOrMissingPort(t *testing.T) {
	for name, definition := range map[string]contracts.AcornFoxDockerfileDefinition{
		"multiple": acornFoxDeploymentPlanDefinition(contracts.AcornFoxDockerfileReady, 3000, 8080),
		"missing":  acornFoxDeploymentPlanDefinition(contracts.AcornFoxDockerfileReady),
	} {
		t.Run(name, func(t *testing.T) {
			source := acornFoxDeploymentPlanSource()
			server := NewAcornFoxServer()
			server.SetAcornFoxDeploymentStore(acornFoxDirectReadFixture{source: source})
			server.SetAcornFoxDockerfileImporter(acornFoxDeploymentPlanImporter{definition: definition})
			now := time.Unix(1_700_000_000, 0).UTC()
			_, session, _ := attachTestAcornFoxAdministratorTokens(t, server, &now)
			request := httptest.NewRequest(http.MethodGet, acornFoxAPIBase+"/app_plan/sources/src_plan/deployment-plan", nil)
			request.AddCookie(session)
			response := httptest.NewRecorder()
			server.Handler().ServeHTTP(response, request)
			if response.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			var plan acornFoxDeploymentPlanResponse
			if err := json.Unmarshal(response.Body.Bytes(), &plan); err != nil {
				t.Fatal(err)
			}
			if plan.PortSelection.Status != "required" || plan.PortSelection.SelectedPort != nil || plan.ReadyToDeploy {
				t.Fatalf("port selection=%+v ready=%v", plan.PortSelection, plan.ReadyToDeploy)
			}
			if name == "multiple" && len(plan.PortSelection.Candidates) != 2 {
				t.Fatalf("multiple candidates=%v", plan.PortSelection.Candidates)
			}
			if name == "missing" && len(plan.PortSelection.SuggestedPorts) == 0 {
				t.Fatalf("missing suggestions=%v", plan.PortSelection)
			}
		})
	}
}

func TestAcornFoxDeploymentPlanReportsMissingDockerfile(t *testing.T) {
	source := acornFoxDeploymentPlanSource()
	server := NewAcornFoxServer()
	server.SetAcornFoxDeploymentStore(acornFoxDirectReadFixture{source: source})
	server.SetAcornFoxDockerfileImporter(acornFoxDeploymentPlanImporter{definition: acornFoxDeploymentPlanDefinition(contracts.AcornFoxDockerfileWaitingLater)})
	now := time.Unix(1_700_000_000, 0).UTC()
	_, session, _ := attachTestAcornFoxAdministratorTokens(t, server, &now)
	request := httptest.NewRequest(http.MethodGet, acornFoxAPIBase+"/app_plan/sources/src_plan/deployment-plan", nil)
	request.AddCookie(session)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var plan acornFoxDeploymentPlanResponse
	if err := json.Unmarshal(response.Body.Bytes(), &plan); err != nil {
		t.Fatal(err)
	}
	if plan.ReadyToDeploy || plan.Dockerfile.Status != contracts.AcornFoxDockerfileWaitingLater || len(plan.RequiredActions) != 1 || plan.RequiredActions[0] != "在仓库根目录添加 Dockerfile" {
		t.Fatalf("plan=%+v", plan)
	}
}

func TestAcornFoxUploadedPlanKeepsStorageLocatorPrivate(t *testing.T) {
	source := domain.SourceRevision{ID: "src_local", ApplicationID: "app_local", Kind: domain.SourceUpload, Locator: "upload://private-id", Ref: "private-id"}
	plan := projectAcornFoxDeploymentPlan(source, contracts.AcornFoxDockerfileDefinition{Status: contracts.AcornFoxDockerfileWaitingLater})
	raw, err := json.Marshal(plan)
	if err != nil || plan.SourceType != "upload" || plan.RepositoryURL != "" || plan.Commit != "" || strings.Contains(string(raw), "upload://") {
		t.Fatal("local plan exposed storage locator", err)
	}
	source.Kind = domain.SourceGitHTTPS
	source.Locator = "https://github.com/acme/app.git"
	source.Ref = "main"
	source.Commit = strings.Repeat("a", 40)
	git := projectAcornFoxDeploymentPlan(source, contracts.AcornFoxDockerfileDefinition{Status: contracts.AcornFoxDockerfileWaitingLater})
	raw, _ = json.Marshal(git)
	if strings.Contains(string(raw), "source_type") || git.RepositoryURL != source.Locator {
		t.Fatal("Git plan compatibility changed")
	}
}
