package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	appcontracts "github.com/open-card/open-card/internal/application/contracts"
)

func TestNativeDomainCLIRequiresExact202AndSameCommand(t *testing.T) {
	now := time.Now().UTC()
	command := appcontracts.ImagePublicAccessOperation{OperationID: "op_domain", TaskID: "task_domain", ApprovalID: "access_domain", DeploymentID: "dep_same", Hostname: "app.customer.example", Action: appcontracts.ImagePublicAccessEnsure, State: "pending", CreatedAt: now}
	mode := "valid"
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		actual := command
		switch r.Method {
		case http.MethodPost:
			if r.URL.Path != apiBase+"/image-deployments/dep_same/domain-commands" || r.Header.Get("Idempotency-Key") != "same-key" || r.Header.Get("X-AcornFox-CSRF") != "csrf" || r.Header.Get("Origin") != server.URL {
				t.Error("domain POST lost exact route, key or CSRF proof")
			}
			var body appcontracts.ImagePublicAccessCommandInput
			if json.NewDecoder(r.Body).Decode(&body) != nil || body.Hostname != command.Hostname || body.Action != command.Action || body.IdempotencyKey != "same-key" {
				t.Error("domain POST changed exact body")
			}
			if mode == "wrong-status" {
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(actual)
				return
			}
			w.WriteHeader(http.StatusAccepted)
		case http.MethodGet:
			if r.URL.Path == apiBase+"/image-domain-operations/op_domain" {
				actual.State, actual.Reason = "unknown", "local route outcome requires reconciliation"
			} else if r.URL.Path == apiBase+"/image-deployments/dep_same/domain" {
				actual.State, actual.Reason = "unknown", "local route outcome requires reconciliation"
				_ = json.NewEncoder(w).Encode(appcontracts.ImagePublicAccessCurrent{Operation: actual, DesiredPublic: true, LocalRouteState: "reconcile_required", DeploymentStatus: "stopped", Availability: "degraded"})
				return
			} else {
				t.Error("domain GET used wrong route")
			}
		default:
			t.Error("unexpected domain method")
		}
		switch mode {
		case "wrong-host":
			actual.Hostname = "other.customer.example"
		case "wrong-operation":
			// A newly assigned operation ID cannot be predicted by the CLI,
			// but an absent ID is an objectively invalid accepted response.
			actual.OperationID = ""
		case "wrong-state":
			actual.State = "succeeded"
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
	call := func(args ...string) error {
		c := &cli{out: &bytes.Buffer{}, err: io.Discard, env: env, client: server.Client(), json: true}
		return c.command(append([]string{"domain"}, args...))
	}
	if err := call("bind", "dep_same", "--hostname", command.Hostname, "--idempotency-key", "same-key"); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"wrong-status", "wrong-host", "wrong-operation", "wrong-state"} {
		mode = bad
		if err := call("bind", "dep_same", "--hostname", command.Hostname, "--idempotency-key", "same-key"); err == nil {
			t.Fatalf("unsafe domain POST response accepted: %s", bad)
		}
	}
	mode = "valid"
	if err := call("operation", "op_domain"); err != nil {
		t.Fatal(err)
	}
	if err := call("get", "dep_same"); err != nil {
		t.Fatal(err)
	}
	if err := call("bind", "dep_same", "--hostname", "App.Customer.Example", "--idempotency-key", "same-key"); err == nil {
		t.Fatal("noncanonical hostname accepted")
	}
	if err := call("remove", "dep_same", "--hostname", command.Hostname); err == nil {
		t.Fatal("domain mutation without explicit idempotency key accepted")
	}
}
