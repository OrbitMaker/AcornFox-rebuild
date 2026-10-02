package cli

import (
	"context"
	"testing"

	"github.com/acornfox/acornfox/internal/client"
)

func TestDiagnoseLatestDeploymentAfterFailedDeploy(t *testing.T) {
	h := newHarness(t)
	h.addTarget("dev", "http://127.0.0.1:18800")
	h.writeDockerfile()
	h.api.deployFn = func(ctx context.Context, app string, opt client.DeployOptions) (client.Deployment, bool, error) {
		return client.Deployment{ID: "d1", App: app, Seq: 1, Status: "queued"}, true, nil
	}
	var asked string
	h.api.deploymentFn = func(ctx context.Context, id string, after int64) (client.Deployment, []client.Event, error) {
		asked = id
		return client.Deployment{
			ID: id, Status: "failed",
			Diagnosis: &client.Diagnosis{Stage: "build", Code: "build_failed", Message: "构建失败"},
		}, nil, nil
	}
	if code, _, _ := h.run("--json", "deploy"); code != exitOpFailed {
		t.Fatalf("deploy exit = %d", code)
	}

	asked = ""
	code, out, errOut := h.run("--json", "diagnose")
	if code != exitOK {
		t.Fatalf("diagnose exit = %d stderr=%s", code, errOut)
	}
	if asked != "d1" {
		t.Fatalf("diagnose queried %q, want d1", asked)
	}
	m := decodeJSON(t, out)
	if m["status"] != "failed" || m["deployment_id"] != "d1" {
		t.Fatalf("unexpected output: %v", m)
	}
	d := m["diagnosis"].(map[string]any)
	if d["code"] != "build_failed" {
		t.Fatalf("code = %v", d["code"])
	}
}

func TestDiagnoseExplicitID(t *testing.T) {
	h := newHarness(t)
	h.addTarget("dev", "http://127.0.0.1:18800")
	code, out, _ := h.run("--json", "--app", "notes", "diagnose", "xyz")
	if code != exitOK {
		t.Fatalf("exit = %d", code)
	}
	if m := decodeJSON(t, out); m["deployment_id"] != "xyz" {
		t.Fatalf("deployment_id = %v", m["deployment_id"])
	}
}

func TestDiagnoseWithoutHistoryIsUsageError(t *testing.T) {
	h := newHarness(t)
	h.addTarget("dev", "http://127.0.0.1:18800")
	if code, _, _ := h.run("--json", "--app", "notes", "diagnose"); code != exitUsage {
		t.Fatalf("exit = %d want %d", code, exitUsage)
	}
}
