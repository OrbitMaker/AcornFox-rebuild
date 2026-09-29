package main

import (
	"net/http"
	"strings"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
)

// acornFoxDockerfileImporter is deliberately read-only. The public API can
// inspect an already imported immutable source revision, but it cannot submit
// a workspace path or Dockerfile contents.
type acornFoxDockerfileImporter interface {
	Import(domain.SourceRevision) (contracts.AcornFoxDockerfileDefinition, error)
}

type acornFoxDeploymentPlanResponse struct {
	SourceType       string                                    `json:"source_type,omitempty"`
	ApplicationID    domain.ID                                 `json:"application_id"`
	SourceRevisionID domain.ID                                 `json:"source_revision_id"`
	RepositoryURL    string                                    `json:"repository_url"`
	Ref              string                                    `json:"ref"`
	Commit           string                                    `json:"commit"`
	Dockerfile       acornFoxDeploymentPlanDockerfile          `json:"dockerfile"`
	Ports            []acornFoxDeploymentPlanPort              `json:"ports"`
	PortSelection    acornFoxDeploymentPlanPortChoice          `json:"port_selection"`
	Healthcheck      contracts.AcornFoxDockerfileHealthcheck   `json:"healthcheck"`
	Environment      []contracts.AcornFoxDockerfileEnvironment `json:"environment"`
	Gaps             []string                                  `json:"gaps"`
	Warnings         []string                                  `json:"warnings"`
	RequiredActions  []string                                  `json:"required_actions"`
	ReadyToDeploy    bool                                      `json:"ready_to_deploy"`
}

type acornFoxDeploymentPlanDockerfile struct {
	Status     contracts.AcornFoxDockerfileStatus   `json:"status"`
	Path       string                               `json:"path"`
	Digest     string                               `json:"digest,omitempty"`
	StageCount int                                  `json:"stage_count"`
	FinalStage *contracts.AcornFoxDockerfileStage   `json:"final_stage,omitempty"`
	Workdir    string                               `json:"workdir,omitempty"`
	Entrypoint *contracts.AcornFoxDockerfileCommand `json:"entrypoint,omitempty"`
	Command    *contracts.AcornFoxDockerfileCommand `json:"command,omitempty"`
}

type acornFoxDeploymentPlanPort struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Source   string `json:"source"`
}

type acornFoxDeploymentPlanPortChoice struct {
	Status         string `json:"status"`
	Reason         string `json:"reason"`
	SelectedPort   *int   `json:"selected_port,omitempty"`
	Candidates     []int  `json:"candidates"`
	SuggestedPorts []int  `json:"suggested_ports,omitempty"`
}

func (s *Server) handleAcornFoxDeploymentPlan(w http.ResponseWriter, r *http.Request, applicationID, sourceRevisionID domain.ID) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET, OPTIONS")
		writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	if s.acornFoxDeployments == nil || s.acornFoxDockerfileImporter == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "deployment_plan_unavailable", "deployment plan is unavailable")
		return
	}
	source, err := s.acornFoxDeployments.GetAcornFoxSourceRevision(r.Context(), applicationID, sourceRevisionID)
	if err != nil {
		writeAcornFoxError(w, errOrNotFound(err))
		return
	}
	definition, err := s.acornFoxDockerfileImporter.Import(source)
	if err != nil {
		writeJSONError(w, http.StatusServiceUnavailable, "deployment_plan_unavailable", "deployment plan is unavailable")
		return
	}
	plan := projectAcornFoxDeploymentPlan(source, definition)
	writeJSON(w, http.StatusOK, plan)
}

func projectAcornFoxDeploymentPlan(source domain.SourceRevision, definition contracts.AcornFoxDockerfileDefinition) acornFoxDeploymentPlanResponse {
	plan := acornFoxDeploymentPlanResponse{
		ApplicationID: source.ApplicationID, SourceRevisionID: source.ID,
		RepositoryURL: source.Locator, Ref: source.Ref, Commit: source.Commit,
		Dockerfile: acornFoxDeploymentPlanDockerfile{
			Status: definition.Status, Path: "Dockerfile", Digest: definition.DockerfileDigest,
			StageCount: definition.StageCount, FinalStage: definition.FinalStage, Workdir: definition.Workdir,
			Entrypoint: definition.Entrypoint, Command: definition.Command,
		},
		Ports:           acornFoxDeploymentPlanPorts(definition.ExposedPorts),
		PortSelection:   acornFoxDeploymentPlanPortSelection(definition),
		Healthcheck:     definition.Healthcheck,
		Environment:     append([]contracts.AcornFoxDockerfileEnvironment{}, definition.Environment...),
		Gaps:            append([]string{}, definition.Gaps...),
		Warnings:        append([]string{}, definition.Warnings...),
		RequiredActions: acornFoxDeploymentPlanActions(definition),
	}
	if source.Kind == domain.SourceUpload {
		plan.SourceType = "upload"
		plan.RepositoryURL = ""
		plan.Commit = ""
	}
	plan.ReadyToDeploy = definition.Status == contracts.AcornFoxDockerfileReady && plan.PortSelection.SelectedPort != nil
	return plan
}

func acornFoxDeploymentPlanPorts(values []contracts.AcornFoxDockerfilePort) []acornFoxDeploymentPlanPort {
	result := make([]acornFoxDeploymentPlanPort, 0, len(values))
	for _, value := range values {
		result = append(result, acornFoxDeploymentPlanPort{Port: value.Port, Protocol: value.Protocol, Source: "dockerfile_expose"})
	}
	return result
}

func acornFoxDeploymentPlanPortSelection(definition contracts.AcornFoxDockerfileDefinition) acornFoxDeploymentPlanPortChoice {
	choice := acornFoxDeploymentPlanPortChoice{Candidates: []int{}}
	if definition.Status != contracts.AcornFoxDockerfileReady {
		choice.Status, choice.Reason = "unavailable", "dockerfile_not_ready"
		return choice
	}
	tcp := make([]int, 0, len(definition.ExposedPorts))
	for _, port := range definition.ExposedPorts {
		if port.Protocol == "tcp" {
			tcp = append(tcp, port.Port)
		}
	}
	switch len(tcp) {
	case 0:
		choice.Status, choice.Reason = "required", "no_dockerfile_port"
		choice.SuggestedPorts = []int{3000, 8080, 8000}
	case 1:
		selected := tcp[0]
		choice.Status, choice.Reason, choice.SelectedPort, choice.Candidates = "selected", "dockerfile_expose", &selected, []int{selected}
	default:
		choice.Status, choice.Reason, choice.Candidates = "required", "multiple_dockerfile_ports", tcp
	}
	return choice
}

func acornFoxDeploymentPlanActions(definition contracts.AcornFoxDockerfileDefinition) []string {
	actions := []string{}
	for _, gap := range definition.Gaps {
		switch {
		case gap == "root_dockerfile_missing":
			actions = append(actions, "在仓库根目录添加 Dockerfile")
		case gap == "dockerfile_unsupported":
			actions = append(actions, "检查 Dockerfile 语法和使用的指令")
		case gap == "healthcheck_missing":
			actions = append(actions, "建议在 Dockerfile 中配置 HEALTHCHECK，或部署后手动检查应用响应")
		case gap == "healthcheck_external_base_unobserved":
			actions = append(actions, "基础镜像来自外部仓库，健康检查需在部署后验证")
		case strings.HasPrefix(gap, "unresolved_variable_expansion:"):
			actions = append(actions, "Dockerfile 中存在无法解析的变量，请改为明确值或运行时环境变量")
		case strings.HasPrefix(gap, "sensitive_env_value_redacted:"):
			actions = append(actions, "敏感环境变量值已隐藏，部署时请单独配置")
		}
	}
	return actions
}
