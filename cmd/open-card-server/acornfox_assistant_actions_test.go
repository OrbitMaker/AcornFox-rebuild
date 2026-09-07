package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/assistant"
	"github.com/open-card/open-card/internal/assistantactions"
	"github.com/open-card/open-card/internal/assistanttools"
	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
)

type actionHTTPResolver struct{ target assistantactions.Target }

func (r actionHTTPResolver) ResolveExact(context.Context, domain.ID, domain.ID) (assistantactions.Target, error) {
	return r.target, nil
}

type actionHTTPExecutor struct{ calls int }

func (e *actionHTTPExecutor) Execute(context.Context, assistantactions.ExecutionRequest) (assistantactions.ExecutionResult, error) {
	e.calls++
	return assistantactions.ExecutionResult{OperationID: "operation_http", Accepted: true}, nil
}

func TestAssistantActionsHTTPRequiresActorAndExplicitDecision(t *testing.T) {
	actor := assistant.Actor{AdminID: "admin_http"}
	executor := &actionHTTPExecutor{}
	clock := time.Date(2026, 9, 7, 16, 0, 0, 0, time.UTC)
	service, err := assistantactions.NewService(assistantactions.Config{Store: assistantactions.NewMemoryStore(), Resolver: actionHTTPResolver{assistantactions.Target{ApplicationID: "app_http", DeploymentID: "dep_http", ReleaseID: "release_http", ReleaseVersion: 1, ApplicationName: "HTTP App"}}, Executor: executor, Clock: func() time.Time { return clock }})
	if err != nil {
		t.Fatal(err)
	}
	proposal, err := service.PrepareProposal(context.Background(), actor, "session_http", "run_http", assistantactions.PrepareInput{Action: assistantactions.ActionRestart, ApplicationID: "app_http", DeploymentID: "dep_http"}, "tool-http")
	if err != nil {
		t.Fatal(err)
	}
	handler := &AcornFoxAssistantActionsHTTPHandler{Service: service}
	path := assistant.HTTPBasePath + "/sessions/session_http/actions/" + proposal.ID.String() + "/decision"
	unauthorized := httptest.NewRecorder()
	handler.Handle(unauthorized, httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"approve":true}`)))
	if unauthorized.Code != http.StatusUnauthorized || executor.calls != 0 {
		t.Fatalf("unauthorized=%d calls=%d", unauthorized.Code, executor.calls)
	}
	missing := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{}`))
	request.Header.Set("Content-Type", "application/json")
	request = request.WithContext(assistant.WithActor(request.Context(), actor))
	handler.Handle(missing, request)
	if missing.Code != http.StatusBadRequest || executor.calls != 0 {
		t.Fatalf("missing=%d calls=%d", missing.Code, executor.calls)
	}
	approve := httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"approve":true}`))
	request.Header.Set("Content-Type", "application/json")
	request = request.WithContext(assistant.WithActor(request.Context(), actor))
	handler.Handle(approve, request)
	if approve.Code != http.StatusAccepted || !strings.Contains(approve.Body.String(), `"state":"accepted"`) || !strings.Contains(approve.Body.String(), `"operation_id":"operation_http"`) || executor.calls != 1 {
		t.Fatalf("approve=%d %s calls=%d", approve.Code, approve.Body.String(), executor.calls)
	}
	list := httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodGet, assistant.HTTPBasePath+"/sessions/session_http/actions", nil)
	request = request.WithContext(assistant.WithActor(request.Context(), actor))
	handler.Handle(list, request)
	if list.Code != http.StatusOK || !strings.Contains(list.Body.String(), proposal.ID.String()) {
		t.Fatalf("list=%d %s", list.Code, list.Body.String())
	}
}

func TestAssistantActionExecutorUsesOnlyFixedProposalTarget(t *testing.T) {
	command := &acornFoxCommandFixture{}
	executor := acornFoxAssistantActionExecutor{Command: command}
	request := assistantactions.ExecutionRequest{ProposalID: "proposal_1", Actor: assistant.Actor{AdminID: "admin_1"}, Action: assistantactions.ActionRedeploy, Target: assistantactions.Target{ApplicationID: "app_1", DeploymentID: "dep_1"}, IdempotencyKey: "fixed-key"}
	result, err := executor.Execute(context.Background(), request)
	if err != nil || result.OperationID != "op_redeploy" || !result.Accepted || len(command.calls) != 1 || command.calls[0] != "redeploy:fixed-key" {
		t.Fatalf("result=%+v calls=%v err=%v", result, command.calls, err)
	}
}

type assistantActionEvidenceFixture struct {
	result contracts.AcornFoxOperationResult
}

func (f assistantActionEvidenceFixture) GetAcornFoxOperationResult(context.Context, domain.ID, domain.ID) (contracts.AcornFoxOperationResult, error) {
	return f.result, nil
}
func TestAssistantActionVerifierRejectsDifferentActionAndDeployment(t *testing.T) {
	now := time.Now().UTC()
	target := assistantactions.Target{ApplicationID: "app_1", DeploymentID: "dep_1", ReleaseID: "release_1", ReleaseVersion: 1, ApplicationName: "Test"}
	result := contracts.AcornFoxOperationResult{OperationID: "op_1", OperationType: "probe", Status: contracts.AcornFoxOperationVerified, TaskID: "task_1", DeploymentID: "dep_1", AcceptedAt: now, UpdatedAt: now, Evidence: &contracts.AcornFoxOperationEvidence{Kind: contracts.AcornFoxOperationRuntimeObservation, Verdict: contracts.AcornFoxOperationEvidenceObserved, ObservedAt: now}}
	verifier := acornFoxAssistantActionVerifier{Reader: assistantActionEvidenceFixture{result}}
	if _, err := verifier.Verify(context.Background(), assistantactions.ActionRestart, target, "op_1"); err == nil {
		t.Fatal("probe verified a restart")
	}
	result.OperationType = "restart"
	result.DeploymentID = "dep_other"
	verifier.Reader = assistantActionEvidenceFixture{result}
	if _, err := verifier.Verify(context.Background(), assistantactions.ActionRestart, target, "op_1"); err == nil {
		t.Fatal("other deployment verified this action")
	}
	result.DeploymentID = "dep_1"
	verifier.Reader = assistantActionEvidenceFixture{result}
	verified, err := verifier.Verify(context.Background(), assistantactions.ActionRestart, target, "op_1")
	if err != nil || verified.State != assistantactions.VerificationVerified || verified.Verdict != "observed" {
		t.Fatalf("verification=%+v err=%v", verified, err)
	}
}
func TestAssistantToolPreparesScopedCardWithoutExecuting(t *testing.T) {
	executor := &actionHTTPExecutor{}
	service, err := assistantactions.NewService(assistantactions.Config{Store: assistantactions.NewMemoryStore(), Resolver: actionHTTPResolver{assistantactions.Target{ApplicationID: "app_1", DeploymentID: "dep_1", ReleaseID: "release_1", ReleaseVersion: 1, ApplicationName: "Test"}}, Executor: executor})
	if err != nil {
		t.Fatal(err)
	}
	server := NewAcornFoxServer()
	server.acornFoxAssistantActions = &AcornFoxAssistantActionsHTTPHandler{Service: service}
	tool := newAcornFoxAssistantToolExecutor(server, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/acornfox/host/metrics" {
			t.Error("metrics target changed")
		}
		w.Write([]byte(`{"availability":"available"}`))
	}))
	grant := assistanttools.Grant{Actor: "admin_1", SessionID: "session_1", RunID: "run_1", Scope: assistanttools.Scope{ApplicationID: "app_1"}}
	result := tool(context.Background(), grant, assistanttools.Call{Tool: "acornfox_propose_restart", CallID: "call_1", Arguments: json.RawMessage(`{"deployment_id":"dep_1"}`)})
	if !result.OK || executor.calls != 0 {
		t.Fatalf("prepare=%+v executions=%d", result, executor.calls)
	}
	var proposal assistantactions.Proposal
	if json.Unmarshal(result.Result, &proposal) != nil || proposal.Target.ApplicationID != "app_1" || proposal.State != assistantactions.StatePending {
		t.Fatal("proposal lost frozen scope")
	}
	denied := tool(context.Background(), grant, assistanttools.Call{Tool: "acornfox_propose_restart", CallID: "call_2", Arguments: json.RawMessage(`{"application_id":"app_other","deployment_id":"dep_1"}`)})
	if denied.OK || denied.Code != "forbidden" || executor.calls != 0 {
		t.Fatal("foreign app or model approval was accepted")
	}
	invalid := tool(context.Background(), grant, assistanttools.Call{Tool: "acornfox_app", CallID: "call_3", Arguments: json.RawMessage(`null`)})
	if invalid.Code != "invalid_request" {
		t.Fatal("null arguments accepted")
	}
	metrics := tool(context.Background(), grant, assistanttools.Call{Tool: "acornfox_host_metrics", CallID: "call_4", Arguments: json.RawMessage(`{}`)})
	if !metrics.OK {
		t.Fatal("application diagnosis cannot read its host resource facts")
	}
}
