package domain

import "fmt"

// ReleaseStatus describes an immutable release record's lifecycle. A release
// is created once its complete digest set is known; subsequent deployments do
// not mutate that digest set.
type ReleaseStatus string

const (
	ReleaseDraft      ReleaseStatus = "draft"
	ReleaseReady      ReleaseStatus = "ready"
	ReleaseFailed     ReleaseStatus = "failed"
	ReleaseSuperseded ReleaseStatus = "superseded"
)

func (s ReleaseStatus) String() string { return string(s) }

func (s ReleaseStatus) valid() bool {
	switch s {
	case ReleaseDraft, ReleaseReady, ReleaseFailed, ReleaseSuperseded:
		return true
	default:
		return false
	}
}

func (s ReleaseStatus) CanTransition(to ReleaseStatus) bool {
	switch s {
	case ReleaseDraft:
		return to == ReleaseReady || to == ReleaseFailed
	case ReleaseReady:
		return to == ReleaseSuperseded
	default:
		return false
	}
}

func (s ReleaseStatus) Transition(to ReleaseStatus) error {
	if !s.valid() || !to.valid() || !s.CanTransition(to) {
		return TransitionError("release", s.String(), to.String())
	}
	return nil
}

// DeploymentStatus separates internal runtime readiness from public serving.
type DeploymentStatus string

const (
	DeploymentPending      DeploymentStatus = "pending"
	DeploymentPreparing    DeploymentStatus = "preparing"
	DeploymentDeploying    DeploymentStatus = "deploying"
	DeploymentRuntimeReady DeploymentStatus = "runtime_ready"
	DeploymentDegraded     DeploymentStatus = "degraded"
	DeploymentServing      DeploymentStatus = "serving"
	DeploymentFailed       DeploymentStatus = "failed"
	DeploymentRollingBack  DeploymentStatus = "rolling_back"
	DeploymentRolledBack   DeploymentStatus = "rolled_back"
	DeploymentStopped      DeploymentStatus = "stopped"
	DeploymentUnknown      DeploymentStatus = "unknown"
)

func (s DeploymentStatus) String() string { return string(s) }

func (s DeploymentStatus) valid() bool {
	switch s {
	case DeploymentPending, DeploymentPreparing, DeploymentDeploying,
		DeploymentRuntimeReady, DeploymentDegraded, DeploymentServing, DeploymentFailed,
		DeploymentRollingBack, DeploymentRolledBack, DeploymentStopped,
		DeploymentUnknown:
		return true
	default:
		return false
	}
}

func (s DeploymentStatus) CanTransition(to DeploymentStatus) bool {
	switch s {
	case DeploymentPending:
		return to == DeploymentPreparing || to == DeploymentFailed || to == DeploymentStopped || to == DeploymentUnknown
	case DeploymentPreparing:
		return to == DeploymentDeploying || to == DeploymentFailed || to == DeploymentStopped || to == DeploymentUnknown
	case DeploymentDeploying:
		return to == DeploymentRuntimeReady || to == DeploymentDegraded || to == DeploymentFailed || to == DeploymentRollingBack || to == DeploymentStopped || to == DeploymentUnknown
	case DeploymentRuntimeReady:
		return to == DeploymentServing || to == DeploymentDegraded || to == DeploymentFailed || to == DeploymentRollingBack || to == DeploymentStopped || to == DeploymentUnknown
	case DeploymentDegraded:
		return to == DeploymentRuntimeReady || to == DeploymentServing || to == DeploymentFailed || to == DeploymentRollingBack || to == DeploymentStopped || to == DeploymentUnknown
	case DeploymentServing:
		return to == DeploymentFailed || to == DeploymentRollingBack || to == DeploymentStopped || to == DeploymentUnknown
	case DeploymentFailed:
		return to == DeploymentRollingBack || to == DeploymentRolledBack || to == DeploymentStopped
	case DeploymentRollingBack:
		return to == DeploymentRolledBack || to == DeploymentFailed || to == DeploymentUnknown
	case DeploymentRolledBack:
		return to == DeploymentStopped
	case DeploymentUnknown:
		return to == DeploymentPreparing || to == DeploymentDeploying || to == DeploymentRuntimeReady || to == DeploymentDegraded || to == DeploymentFailed || to == DeploymentRollingBack || to == DeploymentStopped
	default:
		return false
	}
}

func (s DeploymentStatus) Transition(to DeploymentStatus) error {
	if !s.valid() || !to.valid() || !s.CanTransition(to) {
		return TransitionError("deployment", s.String(), to.String())
	}
	return nil
}

// OperationStatus is the state of a concrete task, not the desired or actual
// state of an application.
type OperationStatus string

const (
	OperationPending     OperationStatus = "pending"
	OperationLeased      OperationStatus = "leased"
	OperationRunning     OperationStatus = "running"
	OperationWaiting     OperationStatus = "waiting"
	OperationCancelling  OperationStatus = "cancelling"
	OperationSucceeded   OperationStatus = "succeeded"
	OperationFailed      OperationStatus = "failed"
	OperationCancelled   OperationStatus = "cancelled"
	OperationRollingBack OperationStatus = "rolling_back"
	OperationRolledBack  OperationStatus = "rolled_back"
)

func (s OperationStatus) String() string { return string(s) }

func (s OperationStatus) valid() bool {
	switch s {
	case OperationPending, OperationLeased, OperationRunning, OperationWaiting,
		OperationCancelling, OperationSucceeded, OperationFailed, OperationCancelled,
		OperationRollingBack, OperationRolledBack:
		return true
	default:
		return false
	}
}

func (s OperationStatus) CanTransition(to OperationStatus) bool {
	switch s {
	case OperationPending:
		return to == OperationLeased || to == OperationRunning || to == OperationCancelled
	case OperationLeased:
		return to == OperationRunning || to == OperationWaiting || to == OperationFailed || to == OperationCancelled
	case OperationRunning:
		return to == OperationWaiting || to == OperationSucceeded || to == OperationFailed || to == OperationCancelling || to == OperationCancelled || to == OperationRollingBack
	case OperationWaiting:
		return to == OperationLeased || to == OperationRunning || to == OperationFailed || to == OperationCancelling || to == OperationCancelled
	case OperationCancelling:
		return to == OperationCancelled || to == OperationFailed
	case OperationFailed:
		return to == OperationRollingBack || to == OperationRolledBack
	case OperationRollingBack:
		return to == OperationRolledBack || to == OperationFailed
	default:
		return false
	}
}

func (s OperationStatus) IsTerminal() bool {
	return s == OperationSucceeded || s == OperationFailed || s == OperationCancelled || s == OperationRolledBack
}

func (s OperationStatus) Transition(to OperationStatus) error {
	if !s.valid() || !to.valid() || !s.CanTransition(to) {
		return TransitionError("operation", s.String(), to.String())
	}
	return nil
}

// PublishStatus is the intentionally small user-facing projection. Internal
// status and evidence remain available through the API.
type PublishStatus string

const (
	PublishPreparing PublishStatus = "preparing"
	PublishBuilding  PublishStatus = "building"
	PublishDeploying PublishStatus = "deploying"
	PublishSucceeded PublishStatus = "succeeded"
	PublishFailed    PublishStatus = "failed"
)

func (s PublishStatus) String() string { return string(s) }

func PublishStatusFor(operation OperationStatus, deployment DeploymentStatus) PublishStatus {
	if operation == OperationFailed || operation == OperationCancelled || deployment == DeploymentFailed {
		return PublishFailed
	}
	if operation == OperationSucceeded && (deployment == DeploymentRuntimeReady || deployment == DeploymentDegraded || deployment == DeploymentServing) {
		return PublishSucceeded
	}
	switch operation {
	case OperationPending, OperationLeased, OperationWaiting, OperationCancelling:
		return PublishPreparing
	case OperationRunning:
		if deployment == DeploymentDeploying || deployment == DeploymentRuntimeReady || deployment == DeploymentDegraded || deployment == DeploymentServing {
			return PublishDeploying
		}
		return PublishBuilding
	default:
		return PublishPreparing
	}
}

func ValidateStatePair(operation OperationStatus, deployment DeploymentStatus) error {
	if !operation.valid() {
		return fmt.Errorf("invalid operation status %q", operation)
	}
	if !deployment.valid() {
		return fmt.Errorf("invalid deployment status %q", deployment)
	}
	return nil
}
