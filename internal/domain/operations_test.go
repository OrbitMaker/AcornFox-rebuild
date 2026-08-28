package domain

import (
	"testing"
	"time"
)

func TestM4OperationsViewsShareOneFactVersionAndNeverClaimDataRollback(t *testing.T) {
	now := time.Unix(10, 0).UTC()
	view := ApplicationOperationsView{
		Version: "observation-set-1", ApplicationID: "app_test", ApplicationName: "operations test", EnvironmentID: "env_test", ReleaseID: "release_test",
		State: ApplicationPartial, Serving: true, Summary: "API is unhealthy; frontend remains available", Impact: "API requests may fail", NextStep: "restart api", ObservedAt: now,
		Services: []ServiceOperationsFact{
			{Name: "frontend", Role: RoleIngress, DeploymentID: "deployment_frontend", ReleaseID: "release_test", Status: "running", Healthy: true, Required: true, Impact: "frontend is available", ObservedAt: now},
			{Name: "api", Role: RoleWorker, DeploymentID: "deployment_api", ReleaseID: "release_test", Status: "unhealthy", Healthy: false, Required: true, Impact: "API requests may fail", NextAction: "restart api", ObservedAt: now},
		},
		AllowedActions: OperationsAllowedActions{RestartServices: []string{"api"}, Redeploy: true, Rollback: true},
		DataNotice:     "Rollback changes code and configuration only; application data is not rolled back.",
		AIStatus:       "disabled",
	}
	if err := view.Validate(); err != nil {
		t.Fatal(err)
	}
	ordinary, operator := view.Ordinary(), view.Operator()
	if ordinary.Version != operator.Version || !ordinary.ObservedAt.Equal(operator.ObservedAt) || len(ordinary.Impacts) != 1 || operator.AllowedActions.RollbackData {
		t.Fatalf("views diverged: ordinary=%#v operator=%#v", ordinary, operator)
	}
	view.AllowedActions.RollbackData = true
	if err := view.Validate(); err == nil {
		t.Fatal("view claimed application data rollback")
	}
}
