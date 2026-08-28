package main

import (
	"context"
	"testing"

	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/persistence/postgres"
)

func TestApplicationTaskHandlerClosesOnlyExactControlPlaneTask(t *testing.T) {
	task := postgres.ControllerTask{
		Task:      postgres.Task{Payload: []byte(`{"kind":"application.create","application_id":"app_test","operation_id":"op_test"}`)},
		Operation: domain.Operation{ID: "op_test", ApplicationID: "app_test"},
	}
	if result := (applicationTaskHandler{}).Execute(context.Background(), task, nil); result.Err != nil {
		t.Fatalf("exact application task failed: %v", result.Err)
	}
	for name, payload := range map[string]string{
		"agent kind":        `{"kind":"deploy_group","application_id":"app_test","operation_id":"op_test"}`,
		"wrong application": `{"kind":"application.create","application_id":"app_other","operation_id":"op_test"}`,
		"wrong operation":   `{"kind":"application.create","application_id":"app_test","operation_id":"op_other"}`,
		"malformed payload": `{`,
	} {
		t.Run(name, func(t *testing.T) {
			copy := task
			copy.Task.Payload = []byte(payload)
			if result := (applicationTaskHandler{}).Execute(context.Background(), copy, nil); result.Err == nil || result.Retryable {
				t.Fatalf("unsafe task was accepted or made retryable: %#v", result)
			}
		})
	}
}
