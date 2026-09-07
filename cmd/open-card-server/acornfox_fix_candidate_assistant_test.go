package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/acornfoxcandidate"
	"github.com/open-card/open-card/internal/assistanttools"
)

func TestAssistantFixCandidateToolUsesRunScopedIdempotencyAndAdministratorOwner(t *testing.T) {
	fixture := &fixCandidateHTTPFixture{value: fixCandidateHTTPValue(time.Unix(1_700_000_000, 0).UTC())}
	server := &Server{acornFoxFixCandidate: &AcornFoxFixCandidateHTTPHandler{Service: fixture, Store: fixture}}
	executor := newAcornFoxAssistantToolExecutor(server, nil)
	arguments, _ := json.Marshal(map[string]any{"application_id": "app_candidate", "base_source_revision_id": "src_base", "paths": []string{"Dockerfile"}, "unified_diff": "diff\n", "container_port": 8080})
	response := executor(context.Background(), assistanttools.Grant{Actor: "admin_candidate", SessionID: "session", RunID: "run_1", Scope: assistanttools.Scope{ApplicationID: "app_candidate"}}, assistanttools.Call{Tool: "acornfox_create_fix_candidate", CallID: "call_1", Arguments: arguments})
	if !response.OK || fixture.request.OwnerAdminID != "admin_candidate" || fixture.request.IdempotencyKey != "assistant:run_1:call_1" || !strings.Contains(string(response.Result), `"candidate_id":"candidate_0123456789abcdef0123456789abcdef"`) {
		t.Fatalf("response=%+v request=%+v", response, fixture.request)
	}
}

func TestAssistantFixSourceReadUsesRedactedUntrustedContextPackage(t *testing.T) {
	fixture := &fixCandidateHTTPFixture{read: acornfoxcandidate.ReadResult{BaseSourceRevisionID: "src_base", BaseCommit: strings.Repeat("a", 40), BaseTreeDigest: "sha256:" + strings.Repeat("b", 64), Files: []acornfoxcandidate.SourceFile{{Path: "Dockerfile", Content: "FROM scratch\nARG TOKEN=oc-secret-canary-123\n", Digest: "sha256:" + strings.Repeat("c", 64), Bytes: 48}}, TotalBytes: 48}}
	server := &Server{acornFoxFixCandidate: &AcornFoxFixCandidateHTTPHandler{Service: fixture, Store: fixture}}
	executor := newAcornFoxAssistantToolExecutor(server, nil)
	arguments, _ := json.Marshal(map[string]any{"application_id": "app_candidate", "source_revision_id": "src_base", "paths": []string{"Dockerfile"}})
	response := executor(context.Background(), assistanttools.Grant{Actor: "admin_candidate", SessionID: "session", RunID: "run_1", Scope: assistanttools.Scope{ApplicationID: "app_candidate"}}, assistanttools.Call{Tool: "acornfox_read_fix_source", CallID: "read_1", Arguments: arguments})
	if !response.OK || strings.Contains(string(response.Result), "oc-secret-canary-123") || !strings.Contains(string(response.Result), `"untrusted":true`) || !strings.Contains(string(response.Result), "[REDACTED]") {
		t.Fatalf("response=%+v", response)
	}
}
