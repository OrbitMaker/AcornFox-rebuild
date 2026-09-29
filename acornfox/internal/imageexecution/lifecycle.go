package imageexecution

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	appcontracts "github.com/acornfox/acornfox/internal/application/contracts"
	"github.com/acornfox/acornfox/internal/contracts"
	"github.com/acornfox/acornfox/internal/domain"
	"github.com/acornfox/acornfox/internal/providers/standalone"
	"net/http"
	"sync/atomic"
	"time"
)

type LifecycleRequest struct {
	Binding   appcontracts.ImageLifecycleBinding        `json:"binding"`
	Authority appcontracts.ImageLifecycleAuthorityInput `json:"authority"`
}
type LifecycleResponse struct {
	Success        bool                              `json:"success"`
	OutcomeUnknown bool                              `json:"outcome_unknown,omitempty"`
	Error          string                            `json:"error,omitempty"`
	Result         appcontracts.ImageLifecycleResult `json:"result"`
}
type LifecycleAuthorityResponse struct {
	Authorized bool                               `json:"authorized"`
	Error      string                             `json:"error,omitempty"`
	Binding    appcontracts.ImageLifecycleBinding `json:"binding"`
}

var _ appcontracts.ContainerLifecycleClient = (*Client)(nil)

func (c *Client) ExecuteLifecycle(ctx context.Context, b appcontracts.ImageLifecycleBinding, a appcontracts.ImageLifecycleAuthorityInput) (appcontracts.ImageLifecycleResult, error) {
	var empty appcontracts.ImageLifecycleResult
	payload, err := json.Marshal(LifecycleRequest{Binding: b, Authority: a})
	if err != nil {
		return empty, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://unix/v1/image/lifecycle", bytes.NewReader(payload))
	if err != nil {
		return empty, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, body, err := c.httpClient.Do(req)
	if err != nil {
		return empty, fmt.Errorf("%w: lifecycle dispatch: %v", appcontracts.ErrOutcomeUnknown, err)
	}
	if resp.StatusCode != http.StatusOK {
		return empty, fmt.Errorf("%w: lifecycle status %d", appcontracts.ErrOutcomeUnknown, resp.StatusCode)
	}
	var result LifecycleResponse
	if err := decodeStrictJSON(bytes.NewReader(body), &result); err != nil {
		return empty, fmt.Errorf("%w: lifecycle response: %v", appcontracts.ErrOutcomeUnknown, err)
	}
	if !result.Success {
		if result.OutcomeUnknown {
			return empty, fmt.Errorf("%w: %s", appcontracts.ErrOutcomeUnknown, result.Error)
		}
		return empty, errors.New(result.Error)
	}
	if result.OutcomeUnknown || result.Error != "" {
		return empty, fmt.Errorf("%w: contradictory lifecycle response", appcontracts.ErrOutcomeUnknown)
	}
	if err := validateLifecycleResult(b, result.Result); err != nil {
		return empty, fmt.Errorf("%w: %v", appcontracts.ErrOutcomeUnknown, err)
	}
	return result.Result, nil
}
func validateLifecycleResult(b appcontracts.ImageLifecycleBinding, r appcontracts.ImageLifecycleResult) error {
	if !r.VerifiedIdentity || r.ContainerID != b.ContainerID || r.ImageID != b.ImageID || r.ManifestDigest != b.ManifestDigest || r.ObservedAt.IsZero() || r.ObservedAt.Before(b.CreatedAt) || r.ObservedAt.After(time.Now().UTC()) || r.ObservedAt.Before(time.Now().UTC().Add(-2*time.Minute)) {
		return errors.New("lifecycle result identity or observation mismatch")
	}
	switch b.Action {
	case appcontracts.ImageLifecycleStop:
		if r.Running || r.EndpointReady {
			return errors.New("stop returned running or ready endpoint")
		}
	case appcontracts.ImageLifecycleStart, appcontracts.ImageLifecycleRestart:
		if !r.Running || !r.EndpointReady || r.HostPort != b.HostPort || r.ContainerPort != b.ContainerPort {
			return errors.New("lifecycle running endpoint mismatch")
		}
	default:
		return errors.New("unsupported lifecycle action")
	}
	return nil
}
func lifecycleAuthorityMatches(b appcontracts.ImageLifecycleBinding, a appcontracts.ImageLifecycleAuthorityInput) bool {
	return b.OperationID == a.OperationID && b.TaskID == a.TaskID && b.DeploymentID == a.DeploymentID && b.ReleaseID == a.ReleaseID && b.ContainerID == a.ContainerID && b.PlanDigest == a.PlanDigest && b.Action == a.Action
}
func (r *ContainerRuntime) checkLifecycleAuthority(ctx context.Context, req LifecycleRequest) error {
	if r.authorityClient == nil || !lifecycleAuthorityMatches(req.Binding, req.Authority) {
		return errors.New("lifecycle authority tuple mismatch")
	}
	payload, err := json.Marshal(req.Authority)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://unix/v1/authority/lifecycle", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	resp, body, err := r.authorityClient.Do(request)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("lifecycle authority status %d", resp.StatusCode)
	}
	var verdict LifecycleAuthorityResponse
	if err := decodeStrictJSON(bytes.NewReader(body), &verdict); err != nil {
		return err
	}
	if !verdict.Authorized {
		return errors.New("lifecycle authority rejected: " + verdict.Error)
	}
	// Compare the entire approved immutable command spec, not ambient caller input.
	actual, want := verdict.Binding, req.Binding
	actual.State = ""
	want.State = ""
	actual.RecoveryRequired = false
	want.RecoveryRequired = false
	actual.Result = nil
	want.Result = nil
	actualJSON, err := json.Marshal(actual)
	if err != nil {
		return err
	}
	wantJSON, err := json.Marshal(want)
	if err != nil {
		return err
	}
	if !bytes.Equal(actualJSON, wantJSON) {
		return errors.New("lifecycle command differs from Core binding")
	}
	return nil
}
func (r *ContainerRuntime) Lifecycle(ctx context.Context, req LifecycleRequest) LifecycleResponse {
	b := req.Binding
	unlock := r.lockDeployment(b.DeploymentID)
	defer unlock()
	if err := appcontracts.ValidatePlanConsistency(b.Plan); err != nil {
		return LifecycleResponse{Error: err.Error()}
	}
	if b.Plan.ID != b.PlanID || b.Plan.PlanDigest != b.PlanDigest || b.Plan.ResolvedImage.Digest != b.ManifestDigest || b.Plan.CanonicalInput.Port != b.ContainerPort || b.HostPort <= 0 || b.ContainerID == "" {
		return LifecycleResponse{Error: "lifecycle original plan mismatch"}
	}
	switch b.Action {
	case appcontracts.ImageLifecycleStop, appcontracts.ImageLifecycleStart, appcontracts.ImageLifecycleRestart:
	default:
		return LifecycleResponse{Error: "unsupported lifecycle action"}
	}
	if err := r.checkLifecycleAuthority(ctx, req); err != nil {
		return LifecycleResponse{Error: err.Error()}
	}
	// Operation key is stable across lease generations. Provider public lifecycle
	// methods own durable action receipts and started-at convergence for restart.
	op := contracts.OperationContext{IdempotencyKey: "image.lifecycle:" + b.OperationID.String(), Deadline: time.Now().UTC().Add(2 * time.Minute)}
	expectedSpec, err := mappedImageRuntimeSpec(DeployRequest{ApplicationID: b.ApplicationID, EnvironmentID: b.EnvironmentID, ReleaseID: b.ReleaseID, CanonicalInput: b.Plan.CanonicalInput}, domain.ImageDigest{Repository: b.Plan.ResolvedImage.Repository, Digest: b.ImageID})
	if err != nil {
		return LifecycleResponse{Error: err.Error()}
	}
	// Inspect first even on reclaim; observation alone never completes a restart.
	before, err := r.standalone.ObserveExpectedDeploymentSnapshot(ctx, contracts.ObserveRequest{DeploymentID: b.DeploymentID, Operation: op}, expectedSpec)
	if err != nil {
		return LifecycleResponse{OutcomeUnknown: true, Error: err.Error()}
	}
	if _, err := r.lifecycleSnapshot(ctx, b, op, before, false); err != nil {
		return LifecycleResponse{OutcomeUnknown: true, Error: err.Error()}
	}
	var effectAttempted atomic.Bool
	reqCtx := withAuthorityCheck(ctx, func(writeCtx context.Context) error {
		if err := r.checkLifecycleAuthority(writeCtx, req); err != nil {
			return err
		}
		effectAttempted.Store(true)
		return nil
	})
	switch b.Action {
	case appcontracts.ImageLifecycleStop:
		err = r.standalone.Stop(reqCtx, contracts.StopRequest{DeploymentID: b.DeploymentID, ServiceName: "web", Operation: op})
	case appcontracts.ImageLifecycleStart:
		err = r.standalone.Start(reqCtx, contracts.StartRequest{DeploymentID: b.DeploymentID, ServiceName: "web", Operation: op})
	case appcontracts.ImageLifecycleRestart:
		err = r.standalone.Restart(reqCtx, contracts.RestartRequest{DeploymentID: b.DeploymentID, ServiceName: "web", Operation: op})
	}
	if err != nil {
		return lifecycleEffectFailure(err, effectAttempted.Load())
	}
	after, err := r.standalone.ObserveExpectedDeploymentSnapshot(ctx, contracts.ObserveRequest{DeploymentID: b.DeploymentID, Operation: op}, expectedSpec)
	if err != nil {
		return LifecycleResponse{OutcomeUnknown: true, Error: err.Error()}
	}
	result, err := r.lifecycleSnapshot(ctx, b, op, after, true)
	if err != nil {
		return LifecycleResponse{OutcomeUnknown: true, Error: err.Error()}
	}
	if err := r.checkLifecycleAuthority(ctx, req); err != nil {
		return LifecycleResponse{OutcomeUnknown: true, Error: err.Error()}
	}
	return LifecycleResponse{Success: true, Result: result}
}
func (r *ContainerRuntime) lifecycleSnapshot(ctx context.Context, b appcontracts.ImageLifecycleBinding, op contracts.OperationContext, snapshot standalone.DeploymentObservationSnapshot, final bool) (appcontracts.ImageLifecycleResult, error) {
	// Original deploy provenance authenticates the OCI image, while only the new
	// command lease authorizes effects and completion. Never borrow deploy success.
	original := DeployRequest{DeploymentID: b.DeploymentID, ReleaseID: b.ReleaseID, ApplicationID: b.ApplicationID, EnvironmentID: b.EnvironmentID, PlanDigest: b.PlanDigest, CanonicalInput: b.Plan.CanonicalInput, ResolvedImage: b.Plan.ResolvedImage}
	receipt, err := r.verifiedReceipt(ctx, b.DeployOperationID, b.DeploymentID, op, snapshot, original)
	if err != nil {
		return appcontracts.ImageLifecycleResult{}, err
	}
	if receipt.ContainerID != b.ContainerID || receipt.ImageID != b.ImageID || receipt.ManifestDigest != b.ManifestDigest || receipt.ContainerPort != b.ContainerPort || receipt.HostPort != b.HostPort {
		return appcontracts.ImageLifecycleResult{}, errors.New("lifecycle snapshot immutable identity drift")
	}
	result := appcontracts.ImageLifecycleResult{Running: receipt.Running, VerifiedIdentity: true, ContainerID: receipt.ContainerID, ImageID: receipt.ImageID, ManifestDigest: receipt.ManifestDigest, HostPort: receipt.HostPort, ContainerPort: receipt.ContainerPort, ObservedAt: receipt.ObservedAt}
	if !final {
		return result, nil
	}
	if b.Action != appcontracts.ImageLifecycleStop {
		if !receipt.Running || receipt.HostPort != b.HostPort {
			return result, errors.New("lifecycle runtime did not retain running port")
		}
		probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		request, err := http.NewRequestWithContext(probeCtx, http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/", b.HostPort), nil)
		if err != nil {
			return result, err
		}
		transport := &http.Transport{Proxy: nil, DisableKeepAlives: true}
		defer transport.CloseIdleConnections()
		client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		resp, err := client.Do(request)
		if err != nil {
			return result, err
		}
		_ = resp.Body.Close()
		// Any actual HTTP response proves the retained loopback endpoint is reachable;
		// this is not a root-path application health policy. Redirects are not followed.
		result.EndpointReady = true
	}
	return result, validateLifecycleResult(b, result)
}
func (cs *ContainerServer) handleLifecycle(w http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req LifecycleRequest
	if err := decodeStrictJSON(request.Body, &req); err != nil {
		http.Error(w, "invalid lifecycle request", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(cs.runtime.Lifecycle(request.Context(), req))
}
func (as *CoreAuthorityServer) handleLifecycleAuthority(w http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req appcontracts.ImageLifecycleAuthorityInput
	if err := decodeStrictJSON(request.Body, &req); err != nil {
		http.Error(w, "invalid lifecycle authority", http.StatusBadRequest)
		return
	}
	if as.lifecycleStore == nil {
		http.Error(w, "lifecycle unavailable", http.StatusServiceUnavailable)
		return
	}
	binding, err := as.lifecycleStore.AuthorizeImageLifecycle(request.Context(), req)
	resp := LifecycleAuthorityResponse{Authorized: err == nil, Binding: binding}
	if err != nil {
		resp.Error = err.Error()
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// Some retained driver post-write verification errors are terminal-looking.
// Once a Docker write was attempted, only a verified receipt can settle it.
func lifecycleEffectFailure(err error, effectAttempted bool) LifecycleResponse {
	return LifecycleResponse{OutcomeUnknown: effectAttempted || contracts.IsProviderOutcomeUnknown(err) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled), Error: err.Error()}
}
