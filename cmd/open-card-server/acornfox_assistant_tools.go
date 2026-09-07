package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"

	"github.com/open-card/open-card/internal/assistant"
	"github.com/open-card/open-card/internal/assistantactions"
	"github.com/open-card/open-card/internal/assistanttools"
	"github.com/open-card/open-card/internal/domain"
)

// newAcornFoxAssistantToolExecutor adapts existing server-authoritative DTOs.
// The caller owns the Unix listener and supplies the already-running metrics
// handler; this function does not bypass authentication on public HTTP.
func newAcornFoxAssistantToolExecutor(server *Server, metrics http.Handler) assistanttools.Executor {
	return func(ctx context.Context, grant assistanttools.Grant, call assistanttools.Call) assistanttools.Response {
		if server == nil {
			return assistanttools.Response{Code: "unavailable"}
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
		if path == "" {
			return assistanttools.Response{Code: "invalid_request"}
		}
		return assistantToolHTTP(ctx, grant, call, assistantAcornFoxHandler{server}, path, method)
	}
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
	case "acornfox_delivery_status", "acornfox_logs", "acornfox_public_access", "acornfox_probe", "acornfox_propose_restart", "acornfox_propose_redeploy":
		want["application_id"], want["deployment_id"] = true, true
	case "acornfox_operation_result":
		want["application_id"], want["operation_id"] = true, true
	}
	for key := range args {
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
		return "/api/v1/acornfox/apps/" + e(app) + "/deliveries/" + e(deployment) + "/logs", http.MethodGet
	case "acornfox_public_access":
		return "/api/v1/acornfox/apps/" + e(app) + "/deliveries/" + e(deployment) + "/public-access", http.MethodGet
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
