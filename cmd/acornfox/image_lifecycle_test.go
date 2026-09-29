package main

import (
	"bytes"
	"encoding/json"
	"errors"
	appcontracts "github.com/open-card/open-card/internal/application/contracts"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNativeImageLifecycleCommandsFreshIdentityAndUnknown(t *testing.T) {
	now := time.Now().UTC()
	digest := "sha256:" + strings.Repeat("a", 64)
	command := appcontracts.ImageLifecycleOperation{OperationID: "op_command", TaskID: "task_command", DeploymentID: "dep_same", ReleaseID: "rel_same", ApplicationID: "app_same", EnvironmentID: "env_same", DeployOperationID: "op_original", PlanID: "plan_original", PlanDigest: digest, ManifestDigest: digest, ContainerID: "same-cid", ImageID: digest, HostPort: 39081, ContainerPort: 80, Action: appcontracts.ImageLifecycleStop, State: "pending", CreatedAt: now}
	mode := "valid"
	calls := 0
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		actual := command
		if r.Method == http.MethodPost {
			if r.URL.Path != apiBase+"/image-deployments/dep_same/lifecycle" || r.Header.Get("Idempotency-Key") != "same-key" || r.Header.Get("X-AcornFox-CSRF") != "csrf" || r.Header.Get("Origin") != server.URL {
				t.Error("lifecycle request lost explicit identity/CSRF proof")
			}
			var input appcontracts.ImageLifecycleCommandInput
			if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
				t.Error(err)
			}
			if input.IdempotencyKey != "same-key" {
				t.Error("key changed")
			}
			actual.Action = input.Action
		} else if r.URL.Path != apiBase+"/image-lifecycle-operations/op_command" {
			t.Error("incorrect lifecycle operation route")
		}
		switch mode {
		case "wrong-deployment":
			actual.DeploymentID = "dep_other"
		case "wrong-action":
			actual.Action = appcontracts.ImageLifecycleRestart
		case "wrong-state":
			actual.State = "unknown"
			actual.RecoveryRequired = true
		case "wrong-op":
			actual.OperationID = "op_other"
		case "unavailable":
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = io.WriteString(w, `{"code":"unavailable","message":"retry later"}`)
			return
		case "unknown":
			actual.State = "unknown"
			actual.RecoveryRequired = true
		}
		_ = json.NewEncoder(w).Encode(actual)
	}))
	defer server.Close()
	root := t.TempDir()
	env := func(k string) string {
		if k == "XDG_STATE_HOME" {
			return root
		}
		return ""
	}
	if err := saveState(env, sessionState{Origin: server.URL, Session: "session", CSRF: "csrf", ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"stop", "start", "restart"} {
		out := &bytes.Buffer{}
		c := &cli{out: out, err: io.Discard, env: env, client: server.Client(), json: true}
		if err := c.command([]string{"image", action, "dep_same", "--idempotency-key", "same-key"}); err != nil {
			t.Fatal(err)
		}
		var actual appcontracts.ImageLifecycleOperation
		if err := json.Unmarshal(out.Bytes(), &actual); err != nil {
			t.Fatal(err)
		}
		if actual.OperationID == actual.DeployOperationID || string(actual.Action) != action {
			t.Fatal("command reused deployment operation")
		}
	}
	for _, bad := range []string{"wrong-deployment", "wrong-action", "wrong-state", "unavailable"} {
		mode = bad
		c := &cli{out: io.Discard, err: io.Discard, env: env, client: server.Client()}
		err := c.command([]string{"image", "stop", "dep_same", "--idempotency-key", "same-key"})
		var apiErr apiError
		if !errors.As(err, &apiErr) || !strings.Contains(apiErr.Message, "same --idempotency-key") {
			t.Fatalf("uncertain action did not preserve retry key: %v", err)
		}
	}
	mode = "wrong-op"
	c := &cli{out: io.Discard, err: io.Discard, env: env, client: server.Client()}
	if err := c.command([]string{"image", "lifecycle-operation", "op_command"}); err == nil {
		t.Fatal("mismatched query operation accepted")
	}
	mode = "unknown"
	note := &bytes.Buffer{}
	c = &cli{out: io.Discard, err: note, env: env, client: server.Client()}
	if err := c.command([]string{"image", "lifecycle-operation", "op_command"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(note.String(), "same --idempotency-key") {
		t.Fatal("unknown query omitted recovery guidance")
	}
	before := calls
	if err := c.command([]string{"image", "stop", "dep_same"}); err == nil || calls != before {
		t.Fatal("missing idempotency key caused network action")
	}
}
func TestLifecycleResponseRejectsBorrowedOrReadyStoppedResults(t *testing.T) {
	now := time.Now().UTC()
	digest := "sha256:" + strings.Repeat("a", 64)
	result := appcontracts.ImageLifecycleResult{VerifiedIdentity: true, ContainerID: "same", ImageID: digest, ManifestDigest: digest, ObservedAt: now}
	v := appcontracts.ImageLifecycleOperation{OperationID: "op_new", TaskID: "task_new", DeploymentID: "dep_same", ReleaseID: "rel_same", ApplicationID: "app_same", EnvironmentID: "env_same", DeployOperationID: "op_old", PlanID: "plan_old", PlanDigest: digest, ManifestDigest: digest, ContainerID: "same", ImageID: digest, HostPort: 39081, ContainerPort: 80, Action: appcontracts.ImageLifecycleStop, State: "succeeded", CreatedAt: now, Result: &result}
	if !validateNativeImageLifecycle(&v) {
		t.Fatal("valid stopped result rejected")
	}
	result.EndpointReady = true
	if validateNativeImageLifecycle(&v) {
		t.Fatal("stopped result reported ready")
	}
	result.EndpointReady = false
	v.OperationID = v.DeployOperationID
	if validateNativeImageLifecycle(&v) {
		t.Fatal("old deploy operation reused as command")
	}
	old := appcontracts.ImageOperationDetailWithResult{ImageOperationDetail: appcontracts.ImageOperationDetail{OperationID: "op_old", ApplicationID: "app_same", EnvironmentID: "env_same", PlanID: "plan_old", TaskID: "task_old", OperationType: "deploy_image", State: "succeeded", PlanDigest: digest, CreatedAt: now, UpdatedAt: now}, Result: &appcontracts.ImageOperationExecutionResult{DeploymentID: "dep_same", ReleaseID: "rel_same", Status: "stopped", HostIP: "127.0.0.1", HostPort: 39081, ContainerPort: 80, Endpoint: "http://127.0.0.1:39081"}}
	if validateNativeImageOperation(&old) {
		t.Fatal("stopped deployment endpoint accepted")
	}
}
