package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/open-card/open-card/internal/acornfoxcandidate"
	aicontext "github.com/open-card/open-card/internal/ai/context"
	"github.com/open-card/open-card/internal/application"
	"github.com/open-card/open-card/internal/assistant"
	"github.com/open-card/open-card/internal/assistantactions"
	"github.com/open-card/open-card/internal/assistanttools"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/persistence/postgres"
)

// newAcornFoxAssistantToolExecutor adapts existing server-authoritative DTOs.
// The caller owns the Unix listener and supplies the already-running metrics
// handler; this function does not bypass authentication on public HTTP.
func newAcornFoxAssistantToolExecutor(server *Server, metrics http.Handler) assistanttools.Executor {
	return func(ctx context.Context, grant assistanttools.Grant, call assistanttools.Call) assistanttools.Response {
		if server == nil {
			return assistanttools.Response{Code: "unavailable"}
		}
		if call.Tool == "acornfox_read_fix_source" || call.Tool == "acornfox_create_fix_candidate" {
			return assistantFixCandidateTool(ctx, server, grant, call)
		}
		var args map[string]string
		if json.Unmarshal(call.Arguments, &args) != nil || args == nil {
			return assistanttools.Response{Code: "invalid_request"}
		}
		if !grant.Scope.Admin && call.Tool != "acornfox_host_metrics" && call.Tool != "acornfox_list_apps" && args["application_id"] == "" {
			args["application_id"] = grant.Scope.ApplicationID
		}
		if !assistantToolArguments(call.Tool, args) {
			return assistanttools.Response{Code: "invalid_request"}
		}
		app := args["application_id"]
		if app != "" && (!assistantToolID(app) || (!grant.Scope.Admin && app != grant.Scope.ApplicationID)) {
			return assistanttools.Response{Code: "forbidden"}
		}
		if app == "" && call.Tool != "acornfox_host_metrics" && call.Tool != "acornfox_list_apps" {
			return assistanttools.Response{Code: "invalid_request"}
		}
		if call.Tool == "acornfox_list_apps" && !grant.Scope.Admin {
			return assistanttools.Response{Code: "forbidden"}
		}
		if call.Tool == "acornfox_host_metrics" {
			if metrics == nil {
				return assistanttools.Response{Code: "unavailable"}
			}
			return assistantToolHTTP(ctx, grant, call, metrics, "/api/v1/acornfox/host/metrics", http.MethodGet)
		}
		if call.Tool == "acornfox_operation_result" && args["operation_id"] == "" {
			if server == nil || server.acornFoxAssistantActions == nil {
				return assistanttools.Response{Code: "unavailable"}
			}
			facts := assistantCurrentActionFacts(ctx, server.acornFoxAssistantActions.Service, grant, app)
			var candidates acornFoxFixCandidateReader
			if server.acornFoxFixCandidate != nil {
				candidates = server.acornFoxFixCandidate.Store
			}
			return assistantAttachCandidateFacts(ctx, candidates, grant, app, facts)
		}
		if call.Tool == "acornfox_propose_restart" || call.Tool == "acornfox_propose_redeploy" {
			if server.acornFoxAssistantActions == nil || server.acornFoxAssistantActions.Service == nil {
				return assistanttools.Response{Code: "unavailable"}
			}
			action := assistantactions.ActionRestart
			if call.Tool == "acornfox_propose_redeploy" {
				action = assistantactions.ActionRedeploy
			}
			proposal, err := server.acornFoxAssistantActions.Service.PrepareProposal(ctx, assistant.Actor{AdminID: domain.ID(grant.Actor)}, domain.ID(grant.SessionID), domain.ID(grant.RunID), assistantactions.PrepareInput{Action: action, ApplicationID: domain.ID(app), DeploymentID: domain.ID(args["deployment_id"])}, call.CallID)
			if err != nil {
				return assistanttools.Response{Code: "unavailable"}
			}
			body, err := json.Marshal(proposal)
			if err != nil {
				return assistanttools.Response{Code: "unavailable"}
			}
			return assistanttools.Response{OK: true, Result: body}
		}
		path, method := assistantToolPath(call.Tool, app, args["deployment_id"], args["operation_id"])
		if call.Tool == "acornfox_logs" && args["source"] == "build" {
			path = strings.Replace(path, "?source=runtime&limit=1", "?source=build&limit=1", 1)
		}
		if path == "" {
			return assistanttools.Response{Code: "invalid_request"}
		}
		return assistantToolHTTP(ctx, grant, call, assistantAcornFoxHandler{server}, path, method)
	}
}

func assistantFixCandidateTool(ctx context.Context, server *Server, grant assistanttools.Grant, call assistanttools.Call) assistanttools.Response {
	if server == nil || server.acornFoxFixCandidate == nil || server.acornFoxFixCandidate.Service == nil {
		return assistanttools.Response{Code: "unavailable"}
	}
	type arguments struct {
		ApplicationID        domain.ID `json:"application_id"`
		BaseSourceRevisionID domain.ID `json:"base_source_revision_id,omitempty"`
		SourceRevisionID     domain.ID `json:"source_revision_id,omitempty"`
		Paths                []string  `json:"paths"`
		UnifiedDiff          string    `json:"unified_diff,omitempty"`
		ContainerPort        int       `json:"container_port,omitempty"`
	}
	var input arguments
	decoder := json.NewDecoder(strings.NewReader(string(call.Arguments)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&input) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return assistanttools.Response{Code: "invalid_request"}
	}
	if input.ApplicationID.Empty() && !grant.Scope.Admin {
		input.ApplicationID = domain.ID(grant.Scope.ApplicationID)
	}
	if input.ApplicationID.Empty() || (!grant.Scope.Admin && input.ApplicationID.String() != grant.Scope.ApplicationID) {
		return assistanttools.Response{Code: "forbidden"}
	}
	var value any
	var err error
	switch call.Tool {
	case "acornfox_read_fix_source":
		if !input.BaseSourceRevisionID.Empty() || input.UnifiedDiff != "" || input.ContainerPort != 0 {
			return assistanttools.Response{Code: "invalid_request"}
		}
		var read acornfoxcandidate.ReadResult
		read, err = server.acornFoxFixCandidate.Service.ReadSourceForAI(ctx, input.ApplicationID, input.SourceRevisionID, input.Paths)
		if err == nil {
			files := make([]aicontext.SourceFile, 0, len(read.Files))
			for _, file := range read.Files {
				files = append(files, aicontext.SourceFile{ApplicationID: input.ApplicationID, Scope: aicontext.ScopeSourceFiles, Path: file.Path, Content: file.Content, Digest: file.Digest, Bytes: file.Bytes, Untrusted: true})
			}
			builder := aicontext.New(aicontext.Config{MaxBytes: aicontext.DefaultMaxBytes, MaxFileBytes: aicontext.DefaultMaxFileBytes, TemplateVersion: "fix-candidate-context-v1"})
			value, err = builder.BuildPackage(aicontext.Input{ApplicationID: input.ApplicationID, TaskType: "source_fix_candidate", Profile: "local", AuthorizedScopes: []string{aicontext.ScopeSourceFiles, aicontext.ScopeObjectVersions}, SourceFiles: files, RelevantFiles: input.Paths, Objects: []aicontext.ObjectVersion{{ApplicationID: input.ApplicationID, Scope: aicontext.ScopeObjectVersions, Kind: "source_revision", ID: read.BaseSourceRevisionID.String(), Version: read.BaseTreeDigest}}, RelevantObjectIDs: []string{read.BaseSourceRevisionID.String()}, TemplateVersion: "fix-candidate-context-v1"})
		}
	case "acornfox_create_fix_candidate":
		if !input.SourceRevisionID.Empty() || len(input.UnifiedDiff) == 0 || len(input.UnifiedDiff) > 48<<10 {
			return assistanttools.Response{Code: "invalid_request"}
		}
		value, err = server.acornFoxFixCandidate.Service.Create(ctx, application.AcornFoxFixCandidateCreateRequest{ApplicationID: input.ApplicationID, BaseSourceRevisionID: input.BaseSourceRevisionID, Paths: input.Paths, UnifiedDiff: []byte(input.UnifiedDiff), ContainerPort: input.ContainerPort, IdempotencyKey: "assistant:" + grant.RunID + ":" + call.CallID, OwnerAdminID: domain.ID(grant.Actor)})
	}
	if err != nil {
		if errors.Is(err, postgres.ErrNotFound) {
			return assistanttools.Response{Code: "not_found"}
		}
		if errors.Is(err, postgres.ErrIdempotencyConflict) {
			return assistanttools.Response{Code: "idempotency_conflict"}
		}
		if domain.IsCode(err, domain.ErrValidation) {
			return assistanttools.Response{Code: "invalid_request"}
		}
		return assistanttools.Response{Code: "unavailable"}
	}
	raw, err := json.Marshal(value)
	if err != nil || len(raw) > assistanttools.MaxResult {
		return assistanttools.Response{Code: "result_too_large"}
	}
	return assistanttools.Response{OK: true, Result: raw}
}

type assistantAcornFoxHandler struct{ server *Server }

func (h assistantAcornFoxHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	_ = h.server.handleAcornFoxAPI(w, r)
}
func (h assistantAcornFoxHandler) Handle(w http.ResponseWriter, r *http.Request) bool {
	return h.server.handleAcornFoxAPI(w, r)
}

func assistantToolArguments(tool string, args map[string]string) bool {
	want := map[string]bool{}
	switch tool {
	case "acornfox_app", "acornfox_sources", "acornfox_deliveries":
		want["application_id"] = true
	case "acornfox_delivery_status", "acornfox_logs", "acornfox_public_access", "acornfox_access_observation", "acornfox_probe", "acornfox_propose_restart", "acornfox_propose_redeploy":
		want["application_id"], want["deployment_id"] = true, true
	case "acornfox_operation_result":
		want["application_id"] = true
		if _, present := args["operation_id"]; present {
			want["operation_id"] = true
		}
	}
	for key := range args {
		if tool == "acornfox_logs" && key == "source" {
			if args[key] != "build" && args[key] != "runtime" {
				return false
			}
			continue
		}
		if !want[key] {
			return false
		}
	}
	for key := range want {
		if !assistantToolID(args[key]) {
			return false
		}
	}
	return true
}

// This read projects current decisions from the same actor and conversation.
// Like the existing GET actions API, List may persist expiry or verification
// derived from an already issued operation. It never approves or executes work.
// Historical model messages are never used as approval or execution evidence.
func assistantCurrentActionFacts(ctx context.Context, service *assistantactions.Service, grant assistanttools.Grant, app string) assistanttools.Response {
	if service == nil || grant.SessionID == "" || grant.Actor == "" || !assistantToolID(app) || (!grant.Scope.Admin && grant.Scope.ApplicationID != app) {
		return assistanttools.Response{Code: "forbidden"}
	}
	items, err := service.List(ctx, assistant.Actor{AdminID: domain.ID(grant.Actor)}, domain.ID(grant.SessionID))
	if err != nil {
		return assistanttools.Response{Code: "unavailable"}
	}
	selected := make([]assistantactions.Proposal, 0)
	for _, item := range items {
		if item.Target.ApplicationID.String() == app {
			selected = append(selected, item)
		}
	}
	raw, err := json.Marshal(map[string]any{"actions": selected})
	if err != nil || len(raw) > assistanttools.MaxResult {
		return assistanttools.Response{Code: "result_too_large"}
	}
	return assistanttools.Response{OK: true, Result: raw}
}

// Candidate summaries exclude patches and private request/owner fields so the
// current-state tool stays bounded even when a validated diff is large.
func assistantAttachCandidateFacts(ctx context.Context, reader acornFoxFixCandidateReader, grant assistanttools.Grant, app string, facts assistanttools.Response) assistanttools.Response {
	if !facts.OK {
		return facts
	}
	if grant.Actor == "" || !assistantToolID(app) || (!grant.Scope.Admin && grant.Scope.ApplicationID != app) {
		return assistanttools.Response{Code: "forbidden"}
	}
	var body map[string]any
	if json.Unmarshal(facts.Result, &body) != nil || body == nil {
		return assistanttools.Response{Code: "unavailable"}
	}
	body["candidate_availability"] = "unavailable"
	if reader != nil {
		values, err := reader.ListAcornFoxFixCandidates(ctx, domain.ID(app), domain.ID(grant.Actor))
		if err == nil {
			if len(values) > 50 {
				return assistanttools.Response{Code: "result_too_large"}
			}
			summaries := make([]map[string]any, 0, len(values))
			for _, value := range values {
				if value.Validate() != nil || value.ApplicationID.String() != app || value.OwnerAdminID.String() != grant.Actor {
					return assistanttools.Response{Code: "unavailable"}
				}
				summary := map[string]any{"candidate_id": value.ID, "application_id": value.ApplicationID, "base_source_revision_id": value.BaseSourceRevisionID, "status": value.Status, "created_at": value.CreatedAt}
				if !value.ExpiresAt.IsZero() {
					summary["expires_at"] = value.ExpiresAt
					summary["expired"] = !time.Now().Before(value.ExpiresAt)
				}
				if value.Status == application.AcornFoxFixCandidateValidated || value.Status == application.AcornFoxFixCandidateSourceMatched {
					summary["result_tree_digest"] = value.ResultTreeDigest
					summary["validated_image"] = value.ValidatedImage
					summary["build_evidence_digest"] = value.BuildEvidenceDigest
					summary["runtime_evidence_digest"] = value.Runtime.EvidenceDigest
					summary["cleanup_confirmed"] = value.Runtime.CleanupConfirmed
				}
				if !value.MatchedSourceRevisionID.Empty() {
					summary["matched_source_revision_id"] = value.MatchedSourceRevisionID
				}
				summaries = append(summaries, summary)
			}
			body["candidate_availability"] = "available"
			body["candidates"] = summaries
		}
	}
	raw, err := json.Marshal(body)
	if err != nil || len(raw) > assistanttools.MaxResult {
		return assistanttools.Response{Code: "result_too_large"}
	}
	return assistanttools.Response{OK: true, Result: raw}
}

func assistantToolPath(tool, app, deployment, operation string) (string, string) {
	e := url.PathEscape
	switch tool {
	case "acornfox_list_apps":
		return "/api/v1/acornfox/apps", http.MethodGet
	case "acornfox_app":
		return "/api/v1/acornfox/apps/" + e(app), http.MethodGet
	case "acornfox_sources":
		return "/api/v1/acornfox/apps/" + e(app) + "/sources", http.MethodGet
	case "acornfox_deliveries":
		return "/api/v1/acornfox/apps/" + e(app) + "/deliveries", http.MethodGet
	case "acornfox_delivery_status":
		return "/api/v1/acornfox/apps/" + e(app) + "/deliveries/" + e(deployment), http.MethodGet
	case "acornfox_logs":
		// One 8 KiB segment remains below the 64 KiB tool limit even after JSON escaping.
		return "/api/v1/acornfox/apps/" + e(app) + "/deliveries/" + e(deployment) + "/logs?source=runtime&limit=1", http.MethodGet
	case "acornfox_public_access":
		return "/api/v1/acornfox/apps/" + e(app) + "/deliveries/" + e(deployment) + "/public-access", http.MethodGet
	case "acornfox_access_observation":
		return "/api/v1/acornfox/apps/" + e(app) + "/deliveries/" + e(deployment) + "/access-observation", http.MethodGet
	case "acornfox_probe":
		return "/api/v1/acornfox/apps/" + e(app) + "/deliveries/" + e(deployment) + "/probes", http.MethodPost
	case "acornfox_operation_result":
		if assistantToolID(operation) {
			return "/api/v1/acornfox/apps/" + e(app) + "/operations/" + e(operation), http.MethodGet
		}
	}
	return "", ""
}
func assistantToolHTTP(ctx context.Context, g assistanttools.Grant, c assistanttools.Call, h http.Handler, path, method string) assistanttools.Response {
	var body *strings.Reader
	if method == http.MethodPost {
		body = strings.NewReader(`{"protocol":"http","path":"/"}`)
	} else {
		body = strings.NewReader("")
	}
	req := httptest.NewRequest(method, path, body).WithContext(ctx)
	req = withControlPlaneIdentity(req, domain.ID(g.Actor))
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
		sum := sha256.Sum256([]byte(g.RunID + "\x00" + c.CallID))
		req.Header.Set("Idempotency-Key", hex.EncodeToString(sum[:]))
	}
	out := httptest.NewRecorder()
	handled := true
	if adapter, ok := h.(interface {
		Handle(http.ResponseWriter, *http.Request) bool
	}); ok {
		handled = adapter.Handle(out, req)
	} else {
		h.ServeHTTP(out, req)
	}
	if !handled {
		return assistanttools.Response{Code: "not_found"}
	}
	if out.Code < 200 || out.Code >= 300 {
		if out.Code == http.StatusNotFound {
			return assistanttools.Response{Code: "not_found"}
		}
		return assistanttools.Response{Code: "unavailable"}
	}
	if out.Body.Len() > assistanttools.MaxResult {
		return assistanttools.Response{Code: "result_too_large"}
	}
	return assistanttools.Response{OK: true, Result: append([]byte(nil), out.Body.Bytes()...)}
}

var assistantToolIdentifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)

func assistantToolID(value string) bool { return assistantToolIdentifier.MatchString(value) }
