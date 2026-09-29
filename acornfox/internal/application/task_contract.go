package application

import persistence "github.com/acornfox/acornfox/internal/application/contracts"

type TaskState = persistence.TaskState
type Task = persistence.Task
type LeasePolicy = persistence.LeasePolicy
type ClaimTaskRequest = persistence.ClaimTaskRequest
type TaskMutationRequest = persistence.TaskMutationRequest
type FailTaskRequest = persistence.FailTaskRequest

const (
	TaskReady     = persistence.TaskReady
	TaskLeased    = persistence.TaskLeased
	TaskCompleted = persistence.TaskCompleted
	TaskFailed    = persistence.TaskFailed
	TaskCancelled = persistence.TaskCancelled
)
