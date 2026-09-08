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

func TestAssistantFixCandidateMissingNewlineReportsCorrectionBeforeCreate(t *testing.T) {
	fixture := &fixCandidateHTTPFixture{value: fixCandidateHTTPValue(time.Unix(1_700_000_000, 0).UTC())}
	server := &Server{acornFoxFixCandidate: &AcornFoxFixCandidateHTTPHandler{Service: fixture, Store: fixture}}
	executor := newAcornFoxAssistantToolExecutor(server, nil)
	grant := assistanttools.Grant{Actor: "admin_candidate", SessionID: "session", RunID: "run_format", Scope: assistanttools.Scope{ApplicationID: "app_candidate"}}
	patch := "diff --git a/Dockerfile b/Dockerfile\n--- a/Dockerfile\n+++ b/Dockerfile\n@@ -1,2 +1,2 @@\n FROM scratch\n-COPY --chmod=0500 hello /hello\n+COPY --chmod=0555 hello /hello"
	invoke := func(diff, callID string) assistanttools.Response {
		arguments, _ := json.Marshal(map[string]any{"application_id": "app_candidate", "base_source_revision_id": "src_base", "paths": []string{"Dockerfile"}, "unified_diff": diff, "container_port": 8000})
		return executor(context.Background(), grant, assistanttools.Call{Tool: "acornfox_create_fix_candidate", CallID: callID, Arguments: arguments})
	}
	response := invoke(patch, "missing_lf")
	var detail struct {
		Field, Reason, Correction string
	}
	if response.OK || response.Code != "invalid_request" || json.Unmarshal(response.Result, &detail) != nil || detail.Field != "unified_diff" || detail.Reason != "missing_final_newline" || !strings.Contains(detail.Correction, "once") || !fixture.request.ApplicationID.Empty() {
		t.Fatalf("missing LF must report a bounded correction without creating a candidate: %+v", response)
	}
	if strings.Contains(string(response.Result), "COPY") {
		t.Fatal("format feedback echoed source content")
	}
	response = invoke(patch+"\n", "corrected_lf")
	if !response.OK || string(fixture.request.UnifiedDiff) != patch+"\n" || fixture.request.IdempotencyKey != "assistant:run_format:corrected_lf" {
		t.Fatalf("the caller-corrected patch must reach the unchanged create path: %+v", response)
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
