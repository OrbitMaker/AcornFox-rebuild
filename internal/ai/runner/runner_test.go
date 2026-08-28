package runner

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/ai/tools"
	"github.com/open-card/open-card/internal/domain"
)

func testWorkspace(t *testing.T) Workspace {
	t.Helper()
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "drafts"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "src"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "src", "config.yaml"), []byte("port: 8080\n"), 0600); err != nil {
		t.Fatal(err)
	}
	return Workspace{Root: root, DraftRoot: "drafts"}
}

func testAction(id, risk, validation string, parameters map[string]any) domain.AIAction {
	return domain.AIAction{ToolID: id, ToolVersion: tools.ToolVersionV1, Risk: risk, ExpectedResult: "bounded result", ValidationID: validation, Parameters: parameters}
}

func run(t *testing.T, runner *ActionRunner, action domain.AIAction, workspace Workspace, key string) (RunResult, error) {
	t.Helper()
	return runner.Run(context.Background(), ActionRequest{Action: action, Workspace: workspace, IdempotencyKey: key})
}

func TestAI_CATALOG_001_RunnerExecutesBoundedReadAndIndependentVerification(t *testing.T) {
	workspace := testWorkspace(t)
	runner := Default()
	result, err := run(t, runner, testAction(tools.ToolWorkspaceRead, string(tools.RiskR0), "workspace.read.v1", map[string]any{"path": "src/config.yaml"}), workspace, "read-1")
	if err != nil {
		t.Fatalf("bounded read failed: %v", err)
	}
	if result.Status != StatusSucceeded || !result.Verification.Independent || !result.Evidence.Redacted || !result.Cleanup {
		t.Fatalf("read result lacks independent bounded evidence: %#v", result)
	}
	output, ok := result.Output.(map[string]any)
	if !ok || output["content"] != "port: 8080\n" {
		t.Fatalf("unexpected read output: %#v", result.Output)
	}
}

func TestAI_SEC_002_003_005_RejectsUnsafePathsAndKeepsCorePatchCandidateUnpublished(t *testing.T) {
	workspace := testWorkspace(t)
	outside := filepath.Join(t.TempDir(), "outside.txt")
	if err := os.WriteFile(outside, []byte("secret outside"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(workspace.Root, "src", "escape.txt")); err != nil {
		t.Fatal(err)
	}
	runner := Default()
	_, err := run(t, runner, testAction(tools.ToolWorkspaceRead, string(tools.RiskR0), "workspace.read.v1", map[string]any{"path": "src/escape.txt"}), workspace, "symlink-1")
	if !errors.Is(err, ErrSymlinkEscape) {
		t.Fatalf("symlink escape error = %v, want ErrSymlinkEscape", err)
	}
	corePath := filepath.Join(workspace.Root, "internal", "core.go")
	if err := os.MkdirAll(filepath.Dir(corePath), 0700); err != nil {
		t.Fatal(err)
	}
	original := []byte("package core\n")
	if err := os.WriteFile(corePath, original, 0600); err != nil {
		t.Fatal(err)
	}
	patchAction := testAction(tools.ToolWorkspacePatch, string(tools.RiskR2), "patch.diff_and_no_write.v1", map[string]any{"path": "internal/core.go", "content": "package core\n// candidate\n"})
	if _, err := run(t, runner, patchAction, workspace, "patch-no-confirm"); !errors.Is(err, ErrConfirmationRequired) {
		t.Fatalf("R2 without confirmation error = %v", err)
	}
	result, err := runner.Run(context.Background(), ActionRequest{Action: patchAction, Workspace: workspace, IdempotencyKey: "patch-no-confirm", Confirmed: true})
	if err != nil {
		t.Fatalf("candidate patch failed: %v", err)
	}
	if result.Status != StatusSucceeded || result.Diff == "" {
		t.Fatalf("candidate patch did not produce explicit diff: %#v", result)
	}
	after, err := os.ReadFile(corePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(original) {
		t.Fatal("candidate patch modified core source")
	}
	draftAction := testAction(tools.ToolWorkspaceDraftEdit, string(tools.RiskR2), "draft.diff_and_scope.v1", map[string]any{"path": "internal/core.go", "content": "not allowed"})
	coreDraftWorkspace := workspace
	coreDraftWorkspace.DraftRoot = "."
	_, err = runner.Run(context.Background(), ActionRequest{Action: draftAction, Workspace: coreDraftWorkspace, IdempotencyKey: "core-draft", Confirmed: true})
	if !errors.Is(err, ErrWorkspaceBoundary) {
		t.Fatalf("core draft edit error = %v, want workspace boundary", err)
	}
}

func TestAI_RUNNER_001_TimeoutResourceNetworkAndCleanup(t *testing.T) {
	workspace := testWorkspace(t)
	runner := Default()
	timeoutAction := testAction(tools.ToolWorkspaceBuildTest, string(tools.RiskR1), "build.exit_and_artifact_check", map[string]any{"fixture": "timeout"})
	_, err := runner.Run(context.Background(), ActionRequest{Action: timeoutAction, Workspace: workspace, IdempotencyKey: "timeout-1", Limits: tools.ResourceLimits{MaxDuration: 5 * time.Millisecond}})
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("timeout error = %v, want ErrTimeout", err)
	}
	resourceAction := testAction(tools.ToolWorkspaceBuildTest, string(tools.RiskR1), "build.exit_and_artifact_check", map[string]any{"fixture": "resource"})
	_, err = runner.Run(context.Background(), ActionRequest{Action: resourceAction, Workspace: workspace, IdempotencyKey: "resource-1", Limits: tools.ResourceLimits{MaxOutputBytes: 128}})
	if !errors.Is(err, ErrResourceLimit) {
		t.Fatalf("resource error = %v, want ErrResourceLimit", err)
	}
	networkAction := testAction(tools.ToolWorkspaceBuildTest, string(tools.RiskR1), "build.exit_and_artifact_check", nil)
	_, err = runner.Run(context.Background(), ActionRequest{Action: networkAction, Workspace: workspace, IdempotencyKey: "network-1", Network: tools.NetworkPolicy{Mode: tools.NetworkAllowlist, AllowedCIDRs: []string{"0.0.0.0/0"}}})
	if !errors.Is(err, ErrNetworkDenied) {
		t.Fatalf("network error = %v, want ErrNetworkDenied", err)
	}
	temp := filepath.Join(workspace.Root, "temporary-artifact")
	if err := os.WriteFile(temp, []byte("remove"), 0600); err != nil {
		t.Fatal(err)
	}
	cleanupRunner := New(nil, Options{
		Executor: ExecutorFunc(func(context.Context, ExecutionRequest) (ExecutionOutput, error) {
			return ExecutionOutput{Value: map[string]any{"ok": true}, Digest: "sha256:fixture", Bytes: 1, Files: 1, TempPaths: []string{"temporary-artifact"}}, nil
		}),
	})
	cleanupAction := testAction(tools.ToolWorkspaceBuildTest, string(tools.RiskR1), "build.exit_and_artifact_check", nil)
	if _, err := run(t, cleanupRunner, cleanupAction, workspace, "cleanup-1"); err != nil {
		t.Fatalf("cleanup fixture failed: %v", err)
	}
	if _, err := os.Stat(temp); !os.IsNotExist(err) {
		t.Fatalf("temporary artifact was not cleaned up: %v", err)
	}
}

func TestAI_RUNNER_001_IdempotentReplayAndIndependentRollback(t *testing.T) {
	workspace := testWorkspace(t)
	var calls atomic.Int32
	replayRunner := New(nil, Options{
		Executor: ExecutorFunc(func(context.Context, ExecutionRequest) (ExecutionOutput, error) {
			calls.Add(1)
			value := map[string]any{"ok": true}
			return ExecutionOutput{Value: value, Digest: outputDigest(value, ""), Bytes: 1, Files: 1}, nil
		}),
	})
	action := testAction(tools.ToolWorkspaceBuildTest, string(tools.RiskR1), "build.exit_and_artifact_check", nil)
	first, err := run(t, replayRunner, action, workspace, "replay-1")
	if err != nil {
		t.Fatal(err)
	}
	second, err := run(t, replayRunner, action, workspace, "replay-1")
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 || second.Status != StatusReplayed || !second.Replay {
		t.Fatalf("replay was not idempotent: calls=%d first=%#v second=%#v", calls.Load(), first, second)
	}

	draftPath := filepath.Join(workspace.Root, "drafts", "candidate.txt")
	if err := os.WriteFile(draftPath, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	rollbackRunner := New(nil, Options{Verifier: VerifierFunc(func(context.Context, VerificationRequest) (Evidence, error) {
		return Evidence{}, errors.New("fixture verifier rejected output")
	})})
	draftAction := testAction(tools.ToolWorkspaceDraftEdit, string(tools.RiskR2), "draft.diff_and_scope.v1", map[string]any{"path": "candidate.txt", "content": "changed"})
	_, err = rollbackRunner.Run(context.Background(), ActionRequest{Action: draftAction, Workspace: workspace, IdempotencyKey: "rollback-1", Confirmed: true})
	if !errors.Is(err, ErrVerification) && !errors.Is(err, ErrRollback) {
		t.Fatalf("verification failure error = %v", err)
	}
	content, readErr := os.ReadFile(draftPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(content) != "original" {
		t.Fatalf("independent rollback did not restore draft: %q", content)
	}
}

func TestAI_SEC_003_R3AlwaysHandsOffController(t *testing.T) {
	catalog := tools.DefaultCatalog()
	if err := catalog.Register(tools.ToolDescriptor{ID: "controller.mutate", Version: tools.ToolVersionV1, Kind: tools.KindBuildTest, Risk: tools.RiskR3, ParameterSchema: tools.ParameterSchema{}, Workspace: tools.ScopeWorkspace, Limits: tools.DefaultResourceLimits(), Network: tools.NetworkPolicy{Mode: tools.NetworkDisabled}, ValidationID: "controller.mutate.v1", RequiresUserConfirmation: true, ControllerHandoffOnly: true}); err != nil {
		t.Fatal(err)
	}
	var called atomic.Bool
	runner := New(catalog, Options{Executor: ExecutorFunc(func(context.Context, ExecutionRequest) (ExecutionOutput, error) {
		called.Store(true)
		return ExecutionOutput{}, nil
	})})
	result, err := runner.Run(context.Background(), ActionRequest{Action: testAction("controller.mutate", string(tools.RiskR3), "controller.mutate.v1", nil), Workspace: testWorkspace(t), IdempotencyKey: "r3-1", Confirmed: true})
	if !errors.Is(err, ErrControllerHandoff) || result.Status != StatusHandoff || result.Handoff == nil || called.Load() {
		t.Fatalf("R3 execution did not hand off safely: result=%#v err=%v called=%v", result, err, called.Load())
	}
}

func TestWorkspaceRejectsAbsoluteTraversalAndSensitiveFiles(t *testing.T) {
	workspace := testWorkspace(t)
	if err := os.WriteFile(filepath.Join(workspace.Root, ".env"), []byte("TOKEN=secret"), 0600); err != nil {
		t.Fatal(err)
	}
	runner := Default()
	for index, path := range []string{"/etc/passwd", "../outside", ".env"} {
		_, err := run(t, runner, testAction(tools.ToolWorkspaceRead, string(tools.RiskR0), "workspace.read.v1", map[string]any{"path": path}), workspace, "blocked-"+string(rune('a'+index)))
		if err == nil || (!errors.Is(err, ErrWorkspaceBoundary) && !errors.Is(err, ErrSensitivePath)) {
			t.Fatalf("path %q was not rejected safely: %v", path, err)
		}
	}
	if strings.Contains(resultError(t, runner, workspace), "secret") {
		t.Fatal("sensitive path appeared in result error")
	}
}

func resultError(t *testing.T, runner *ActionRunner, workspace Workspace) string {
	t.Helper()
	result, _ := run(t, runner, testAction(tools.ToolWorkspaceRead, string(tools.RiskR0), "workspace.read.v1", map[string]any{"path": ".env"}), workspace, "blocked-replay")
	return result.Error
}
