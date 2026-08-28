package controllers

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
)

var ErrRolloutCapacity = errors.New("insufficient capacity for parallel rollout")

type RolloutPlan struct {
	Mode                     contracts.RuntimeRolloutMode `json:"mode"`
	ChangedServices          []string                     `json:"changed_services"`
	UnchangedServices        []string                     `json:"unchanged_services"`
	StartOrder               []string                     `json:"start_order"`
	StopOrder                []string                     `json:"stop_order"`
	PreserveOldUntilHealthy  bool                         `json:"preserve_old_until_healthy"`
	RequiresDowntimeApproval bool                         `json:"requires_downtime_approval"`
	RollbackWholeRelease     bool                         `json:"rollback_whole_release"`
	RollbackData             bool                         `json:"rollback_data"`
	TargetConfigDigest       string                       `json:"target_config_digest"`
}

// PlanServiceGroupRollout makes the single-node trade-off explicit. Stateless
// changes need enough capacity to keep the old combination alive. A changed
// writable stateful service uses stop/start only with prior downtime approval.
func PlanServiceGroupRollout(current *contracts.ServiceGroupRuntimeSpec, target contracts.ServiceGroupRuntimeSpec, parallelCapacityAvailable bool) (RolloutPlan, error) {
	if err := target.Validate(); err != nil {
		return RolloutPlan{}, err
	}
	order, err := target.DependencyOrder()
	if err != nil {
		return RolloutPlan{}, err
	}
	plan := RolloutPlan{Mode: contracts.RuntimeRolloutInitial, StartOrder: order, RollbackWholeRelease: true, TargetConfigDigest: target.ConfigDigest}
	if current == nil {
		plan.ChangedServices = append([]string(nil), order...)
		plan.StopOrder = reverseStrings(order)
		return plan, nil
	}
	if err := current.Validate(); err != nil {
		return RolloutPlan{}, err
	}
	if current.ApplicationID != target.ApplicationID || current.EnvironmentID != target.EnvironmentID {
		return RolloutPlan{}, domain.ValidationError("rollout current and target group scope do not match")
	}
	currentByName := make(map[string]contracts.ServiceRuntimeSpec, len(current.Services))
	for _, service := range current.Services {
		currentByName[service.Name] = service
	}
	changedStatefulWriter := false
	for _, service := range target.Services {
		previous, exists := currentByName[service.Name]
		if !exists || serviceFingerprint(previous) != serviceFingerprint(service) {
			plan.ChangedServices = append(plan.ChangedServices, service.Name)
			if service.Role == domain.RoleStateful && hasWritableVolume(service) {
				changedStatefulWriter = true
			}
		} else {
			plan.UnchangedServices = append(plan.UnchangedServices, service.Name)
		}
		delete(currentByName, service.Name)
	}
	for removed := range currentByName {
		plan.ChangedServices = append(plan.ChangedServices, removed)
	}
	sort.Strings(plan.ChangedServices)
	sort.Strings(plan.UnchangedServices)
	plan.StopOrder = reverseStrings(order)
	if len(plan.ChangedServices) == 0 {
		plan.Mode = contracts.RuntimeRolloutRolling
		plan.PreserveOldUntilHealthy = true
		return plan, nil
	}
	if changedStatefulWriter {
		plan.Mode = contracts.RuntimeRolloutRecreate
		plan.RequiresDowntimeApproval = true
		if target.Rollout.Mode != contracts.RuntimeRolloutRecreate || !target.Rollout.DowntimeApproved {
			return plan, domain.ValidationError("changed writable stateful service requires explicit recreate downtime approval")
		}
		return plan, nil
	}
	plan.Mode = contracts.RuntimeRolloutRolling
	plan.PreserveOldUntilHealthy = true
	if target.Rollout.Mode != contracts.RuntimeRolloutRolling || !target.Rollout.PreserveOldUntilHealthy {
		return plan, domain.ValidationError("stateless update requires preserve-old rolling policy")
	}
	if !parallelCapacityAvailable {
		return plan, ErrRolloutCapacity
	}
	return plan, nil
}

func hasWritableVolume(service contracts.ServiceRuntimeSpec) bool {
	for _, volume := range service.Volumes {
		if !volume.ReadOnly {
			return true
		}
	}
	return false
}

func serviceFingerprint(service contracts.ServiceRuntimeSpec) string {
	encoded, _ := json.Marshal(service)
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}

func reverseStrings(values []string) []string {
	result := append([]string(nil), values...)
	for left, right := 0, len(result)-1; left < right; left, right = left+1, right-1 {
		result[left], result[right] = result[right], result[left]
	}
	return result
}
