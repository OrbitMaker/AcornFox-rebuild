package domain

import (
	"fmt"
	"strings"
	"time"
)

type ApplicationHealthState string

const (
	ApplicationHealthy   ApplicationHealthState = "healthy"
	ApplicationAttention ApplicationHealthState = "attention"
	ApplicationPartial   ApplicationHealthState = "partial"
	ApplicationStopped   ApplicationHealthState = "stopped"
)

type ResourceObservation struct {
	ContainerID          string  `json:"container_id,omitempty"`
	CPUCores             float64 `json:"cpu_cores"`
	MemoryBytes          uint64  `json:"memory_bytes"`
	DiskBytes            uint64  `json:"disk_bytes"`
	NetworkRxBytes       uint64  `json:"network_rx_bytes"`
	NetworkTxBytes       uint64  `json:"network_tx_bytes"`
	RestartCount         uint64  `json:"restart_count"`
	PIDsCurrent          uint64  `json:"pids_current"`
	AppliedCPUMillicores uint64  `json:"applied_cpu_millicores"`
	AppliedMemoryBytes   uint64  `json:"applied_memory_bytes"`
	AppliedPIDs          uint64  `json:"applied_pids"`
	ChangedPathCount     uint64  `json:"changed_path_count"`
	CgroupVerified       bool    `json:"cgroup_verified"`
	MetricsKnown         bool    `json:"metrics_known"`
	HostPort             int     `json:"host_port,omitempty"`
}

type ServiceOperationsFact struct {
	Name         string              `json:"name"`
	Role         ServiceRole         `json:"role"`
	DeploymentID ID                  `json:"deployment_id"`
	ReleaseID    ID                  `json:"release_id"`
	Status       string              `json:"status"`
	Healthy      bool                `json:"healthy"`
	Required     bool                `json:"required"`
	Impact       string              `json:"impact"`
	NextAction   string              `json:"next_action,omitempty"`
	Actual       ResourceObservation `json:"actual"`
	ObservedAt   time.Time           `json:"observed_at"`
}

func (f ServiceOperationsFact) Validate() error {
	if strings.TrimSpace(f.Name) == "" || !validOperationsServiceRole(f.Role) {
		return ValidationError("operations service name and role are required")
	}
	if err := RequireID(f.DeploymentID, "operations service deployment id"); err != nil {
		return err
	}
	if err := RequireID(f.ReleaseID, "operations service release id"); err != nil {
		return err
	}
	if strings.TrimSpace(f.Status) == "" || strings.TrimSpace(f.Impact) == "" || f.ObservedAt.IsZero() {
		return ValidationError("operations service status, impact, and observed time are required")
	}
	if !f.Healthy && strings.TrimSpace(f.NextAction) == "" {
		return ValidationError("unhealthy service requires an actionable next step")
	}
	return nil
}

func validOperationsServiceRole(role ServiceRole) bool {
	switch role {
	case RoleIngress, RoleWorker, RoleStateful, RoleOneShot:
		return true
	default:
		return false
	}
}

type OperationsAllowedActions struct {
	RestartServices []string `json:"restart_services"`
	Redeploy        bool     `json:"redeploy"`
	Rollback        bool     `json:"rollback"`
	RollbackData    bool     `json:"rollback_data"`
}

// ApplicationOperationsView is the sole M4 fact projection. Ordinary and
// operator UIs may omit detail, but must carry this same Version and
// ObservedAt rather than compute independent health state.
type ApplicationOperationsView struct {
	Version         string                   `json:"version"`
	ApplicationID   ID                       `json:"application_id"`
	ApplicationName string                   `json:"application_name"`
	EnvironmentID   ID                       `json:"environment_id"`
	ReleaseID       ID                       `json:"release_id"`
	State           ApplicationHealthState   `json:"state"`
	Serving         bool                     `json:"serving"`
	Summary         string                   `json:"summary"`
	Impact          string                   `json:"impact"`
	NextStep        string                   `json:"next_step"`
	Services        []ServiceOperationsFact  `json:"services"`
	AllowedActions  OperationsAllowedActions `json:"allowed_actions"`
	DataNotice      string                   `json:"data_notice"`
	AIStatus        string                   `json:"ai_status"`
	ObservedAt      time.Time                `json:"observed_at"`
}

func (v ApplicationOperationsView) Validate() error {
	if strings.TrimSpace(v.Version) == "" || strings.TrimSpace(v.ApplicationName) == "" || strings.TrimSpace(v.Summary) == "" || strings.TrimSpace(v.Impact) == "" || strings.TrimSpace(v.NextStep) == "" || v.ObservedAt.IsZero() {
		return ValidationError("operations fact version, application name, summary, impact, next step, and observed time are required")
	}
	for label, id := range map[string]ID{"application": v.ApplicationID, "environment": v.EnvironmentID, "release": v.ReleaseID} {
		if err := RequireID(id, "operations "+label+" id"); err != nil {
			return err
		}
	}
	switch v.State {
	case ApplicationHealthy, ApplicationAttention, ApplicationPartial, ApplicationStopped:
	default:
		return ValidationError("operations application state is unsupported")
	}
	if v.AIStatus != "disabled" && v.AIStatus != "unavailable" {
		return ValidationError("M4 AI status must remain disabled or unavailable")
	}
	if v.AllowedActions.RollbackData {
		return ValidationError("M4 must not claim application data rollback")
	}
	if strings.TrimSpace(v.DataNotice) == "" {
		return ValidationError("operations view must disclose that data is not rolled back")
	}
	seen := make(map[string]struct{}, len(v.Services))
	for _, service := range v.Services {
		if err := service.Validate(); err != nil {
			return err
		}
		if service.ReleaseID != v.ReleaseID || service.ObservedAt.After(v.ObservedAt) {
			return ValidationError("operations service fact is outside the projected release or observation time")
		}
		if _, duplicate := seen[service.Name]; duplicate {
			return NewError(ErrConflict, fmt.Sprintf("duplicate operations service %s", service.Name))
		}
		seen[service.Name] = struct{}{}
	}
	for _, service := range v.AllowedActions.RestartServices {
		if _, exists := seen[service]; !exists {
			return ValidationError("restart action references an unknown service")
		}
	}
	return nil
}

type OrdinaryOperationsView struct {
	Version       string                 `json:"version"`
	ApplicationID ID                     `json:"application_id"`
	State         ApplicationHealthState `json:"state"`
	Summary       string                 `json:"summary"`
	Impacts       []string               `json:"impacts"`
	NextActions   []string               `json:"next_actions"`
	ObservedAt    time.Time              `json:"observed_at"`
}

type OperatorOperationsView struct {
	ApplicationOperationsView
}

func (v ApplicationOperationsView) Ordinary() OrdinaryOperationsView {
	result := OrdinaryOperationsView{Version: v.Version, ApplicationID: v.ApplicationID, State: v.State, Summary: v.Summary, ObservedAt: v.ObservedAt}
	for _, service := range v.Services {
		if service.Healthy {
			continue
		}
		result.Impacts = append(result.Impacts, service.Impact)
		result.NextActions = append(result.NextActions, service.NextAction)
	}
	return result
}

func (v ApplicationOperationsView) Operator() OperatorOperationsView {
	return OperatorOperationsView{ApplicationOperationsView: v}
}
