package main

import (
	"context"
	"encoding/json"
	"github.com/open-card/open-card/internal/assistanttools"
	"strings"
	"testing"
	"time"
)

func TestAssistantCandidateFactsBoundLargeDiffAndOwnership(t *testing.T) {
	value := fixCandidateHTTPValue(time.Now().Add(-2 * time.Hour))
	value.CanonicalDiff = strings.Repeat("PATCH_CANARY", 10000)
	if err := value.Validate(); err != nil {
		t.Fatal(err)
	}
	reader := &fixCandidateHTTPFixture{value: value}
	grant := assistanttools.Grant{Actor: "admin_candidate", SessionID: "session_candidate", Scope: assistanttools.Scope{ApplicationID: "app_candidate"}}
	base := assistanttools.Response{OK: true, Result: []byte(`{"actions":[]}`)}
	result := assistantAttachCandidateFacts(context.Background(), reader, grant, "app_candidate", base)
	if !result.OK || len(result.Result) > 2048 || strings.Contains(string(result.Result), "PATCH_CANARY") || strings.Contains(string(result.Result), "candidate-key") {
		t.Fatalf("candidate projection was not bounded: %s", result.Code)
	}
	if !strings.Contains(string(result.Result), `"build_evidence_digest":"`+value.BuildEvidenceDigest+`"`) || !strings.Contains(string(result.Result), `"runtime_evidence_digest":"`+value.Runtime.EvidenceDigest+`"`) {
		t.Fatal("validation evidence digests missing")
	}
	var body struct {
		Availability string `json:"candidate_availability"`
		Candidates   []struct {
			Status  string `json:"status"`
			Expired bool   `json:"expired"`
		} `json:"candidates"`
	}
	if json.Unmarshal(result.Result, &body) != nil || body.Availability != "available" || len(body.Candidates) != 1 || body.Candidates[0].Status != "validated" || !body.Candidates[0].Expired {
		t.Fatal("missing authoritative candidate status")
	}
	reader.value.OwnerAdminID = "another_admin"
	if assistantAttachCandidateFacts(context.Background(), reader, grant, "app_candidate", base).OK {
		t.Fatal("foreign candidate leaked")
	}
	if assistantAttachCandidateFacts(context.Background(), nil, grant, "different_app", base).Code != "forbidden" {
		t.Fatal("scope mismatch accepted")
	}
	result = assistantAttachCandidateFacts(context.Background(), nil, grant, "app_candidate", base)
	if !result.OK || !strings.Contains(string(result.Result), `"candidate_availability":"unavailable"`) || !strings.Contains(string(result.Result), `"actions":[]`) {
		t.Fatal("candidate outage erased existing action facts")
	}
}
