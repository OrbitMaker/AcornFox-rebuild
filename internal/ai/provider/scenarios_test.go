package provider

import (
	"context"
	"testing"
)

func TestM6DefinitionAmbiguityProducesMinimalReadOnlyPlan(t *testing.T) {
	request := testRequest("definition-ambiguity")
	request.TaskType, request.Context.TaskType = "definition_ambiguity", "definition_ambiguity"
	result, err := NewFake(ProfileLocal).StructuredCall(context.Background(), request)
	if err != nil || len(result.Plan.Actions) != 1 || result.Plan.Actions[0].ToolID != "workspace.read" || result.Plan.Actions[0].Parameters["path"] != "delivery.yaml" || result.Plan.RequiresUserConfirmation {
		t.Fatalf("definition plan=%+v err=%v", result.Plan, err)
	}
}

func TestM6LogAnomalyAndUsageAnalysisRemainReadOnlySummaries(t *testing.T) {
	for task, path := range map[string]string{"log_anomaly_analysis": "logs.txt", "usage_analysis": "usage.json"} {
		request := testRequest(task)
		request.TaskType, request.Context.TaskType = task, task
		result, err := NewFake(ProfileLocal).StructuredCall(context.Background(), request)
		if err != nil || result.Plan.Actions[0].Risk != "R0" || result.Plan.Actions[0].Parameters["path"] != path {
			t.Fatalf("task=%s plan=%+v err=%v", task, result.Plan, err)
		}
	}
}
