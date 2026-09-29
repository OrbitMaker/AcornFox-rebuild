package imageexecution

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	appcontracts "github.com/acornfox/acornfox/internal/application/contracts"
	"github.com/acornfox/acornfox/internal/contracts"
	"github.com/acornfox/acornfox/internal/domain"
	"github.com/acornfox/acornfox/internal/packmanager"
)

// Client executes image deployment and observation operations against the Container role daemon.
type Client struct {
	httpClient   *packmanager.UnixHTTPClient
	streamClient *packmanager.UnixHTTPClient
	socketPath   string
	timeout      time.Duration
}

// ClientConfig configures the Unix domain socket client with peer verification.
type ClientConfig struct {
	SocketPath    string
	ExpectedPID   int32
	ExpectedUID   uint32
	PeerValidator func(pid int32, uid uint32) error
	Timeout       time.Duration
}

// NewClient constructs a new image execution Unix client.
func NewClient(cfg ClientConfig) (*Client, error) {
	if cfg.SocketPath == "" {
		return nil, domain.ValidationError("socket path is required")
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 2 * time.Minute
	}
	httpClient := packmanager.NewUnixHTTPClient(cfg.SocketPath, cfg.ExpectedPID, cfg.ExpectedUID, cfg.PeerValidator, timeout)
	return &Client{
		httpClient:   httpClient,
		streamClient: packmanager.NewUnixHTTPClient(cfg.SocketPath, cfg.ExpectedPID, cfg.ExpectedUID, cfg.PeerValidator, 0),
		socketPath:   cfg.SocketPath,
		timeout:      timeout,
	}, nil
}

// CheckReady verifies the container role server is responsive on its Unix socket.
func (c *Client) CheckReady(ctx context.Context) error {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://unix/v1/healthz", nil)
	if err != nil {
		return err
	}
	resp, body, err := c.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("container healthz dial failed: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("container healthz returned status %d: %s", resp.StatusCode, string(body))
	}
	return nil
}

// ExecuteDeployment dispatches a deployment execution to the container role process.
func (c *Client) ExecuteDeployment(ctx context.Context, binding appcontracts.ImageExecutionBinding) (appcontracts.CommitImageExecutionResultInput, error) {
	reqBody := DeployRequest{
		DeploymentID:    binding.DeploymentID,
		ReleaseID:       binding.ReleaseID,
		ApplicationID:   binding.ApplicationID,
		EnvironmentID:   binding.EnvironmentID,
		OperationID:     binding.OperationID,
		TaskID:          binding.TaskID,
		TaskOwner:       binding.Owner,
		CoreGeneration:  binding.CoreGeneration,
		LeaseGeneration: binding.LeaseGeneration,
		PlanDigest:      binding.Plan.PlanDigest,
		ImageOrigin: func() string {
			if binding.SourceArtifact != nil {
				return "source-build"
			}
			return "registryhttp"
		}(),
		CanonicalInput: binding.Plan.CanonicalInput,
		ResolvedImage:  binding.Plan.ResolvedImage,
		TimeoutSeconds: int64(c.timeout.Seconds()),
	}

	payload, err := json.Marshal(reqBody)
	if err != nil {
		return appcontracts.CommitImageExecutionResultInput{}, fmt.Errorf("encode deploy request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://unix/v1/image/deploy", bytes.NewReader(payload))
	if err != nil {
		return appcontracts.CommitImageExecutionResultInput{}, fmt.Errorf("create deploy request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	httpResp, body, err := c.httpClient.Do(httpReq)
	if err != nil {
		return appcontracts.CommitImageExecutionResultInput{}, fmt.Errorf("%w: dispatch deploy failed: %v", appcontracts.ErrOutcomeUnknown, err)
	}
	if httpResp.StatusCode != http.StatusOK {
		return appcontracts.CommitImageExecutionResultInput{}, fmt.Errorf("deploy returned status %d: %s", httpResp.StatusCode, string(body))
	}

	var resp DeployResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return appcontracts.CommitImageExecutionResultInput{}, fmt.Errorf("%w: decode deploy response: %v", appcontracts.ErrOutcomeUnknown, err)
	}
	if !resp.Success {
		errMsg := resp.Error
		if errMsg == "" {
			errMsg = "deployment execution failed"
		}
		if resp.OutcomeUnknown {
			return appcontracts.CommitImageExecutionResultInput{}, fmt.Errorf("%w: %s", appcontracts.ErrOutcomeUnknown, errMsg)
		}
		return appcontracts.CommitImageExecutionResultInput{}, errors.New(errMsg)
	}

	if resp.ObservedAt.IsZero() {
		return appcontracts.CommitImageExecutionResultInput{}, fmt.Errorf("%w: container role returned zero observed_at", appcontracts.ErrOutcomeUnknown)
	}
	now := time.Now().UTC()
	if resp.ObservedAt.After(now) {
		return appcontracts.CommitImageExecutionResultInput{}, fmt.Errorf("%w: container role returned future observed_at", appcontracts.ErrOutcomeUnknown)
	}

	if resp.ManifestDigest != binding.Plan.ResolvedImage.Digest {
		return appcontracts.CommitImageExecutionResultInput{}, fmt.Errorf("%w: response manifest digest %q does not match binding %q", appcontracts.ErrOutcomeUnknown, resp.ManifestDigest, binding.Plan.ResolvedImage.Digest)
	}
	if binding.SourceArtifact != nil && (resp.StorageRef != binding.SourceArtifact.StorageRef || resp.ContentDigest != binding.SourceArtifact.ArchiveSHA256 || resp.SizeBytes != binding.SourceArtifact.SizeBytes) {
		return appcontracts.CommitImageExecutionResultInput{}, fmt.Errorf("%w: source-built archive receipt differs from original Core artifact", appcontracts.ErrOutcomeUnknown)
	}

	return appcontracts.CommitImageExecutionResultInput{
		TaskID:          binding.TaskID,
		OperationID:     binding.OperationID,
		DeploymentID:    binding.DeploymentID,
		ReleaseID:       binding.ReleaseID,
		Owner:           binding.Owner,
		CoreGeneration:  binding.CoreGeneration,
		LeaseGeneration: binding.LeaseGeneration,
		Now:             now,
		ContainerID:     resp.ContainerID,
		ContainerName:   resp.ContainerName,
		ImageID:         resp.ImageID,
		ManifestDigest:  resp.ManifestDigest,
		Artifact: appcontracts.StorageArtifactReceipt{
			StorageRef:    resp.StorageRef,
			ContentDigest: resp.ContentDigest,
			SizeBytes:     resp.SizeBytes,
		},
		HostPort:      resp.HostPort,
		ContainerPort: resp.ContainerPort,
		ObservedAt:    resp.ObservedAt,
	}, nil
}

func builtImportRequest(binding appcontracts.ImageExecutionBinding) (BuiltOCIImportRequest, error) {
	if binding.SourceArtifact == nil {
		return BuiltOCIImportRequest{}, appcontracts.ErrOutcomeUnknown
	}
	return BuiltOCIImportRequest{DeploymentID: binding.DeploymentID, OperationID: binding.OperationID, TaskID: binding.TaskID, Owner: binding.Owner, CoreGeneration: binding.CoreGeneration, LeaseGeneration: binding.LeaseGeneration, PlanDigest: binding.Plan.PlanDigest, Artifact: *binding.SourceArtifact}, nil
}

func builtReceipt(response BuiltOCIImportResponse, fact appcontracts.SourceBuiltArtifactFact) (appcontracts.SourceBuiltContainerReceipt, error) {
	if !response.Present || response.Image != fact.Image || response.StorageRef != fact.StorageRef || response.ContentDigest != fact.ArchiveSHA256 || response.SizeBytes != fact.SizeBytes || response.ManifestDigest != fact.Image.Digest || !contracts.IsSHA256Digest(response.ConfigDigest) {
		return appcontracts.SourceBuiltContainerReceipt{}, appcontracts.ErrOutcomeUnknown
	}
	return appcontracts.SourceBuiltContainerReceipt{Image: response.Image, StorageRef: response.StorageRef, ArchiveSHA256: response.ContentDigest, SizeBytes: response.SizeBytes, ManifestDigest: response.ManifestDigest, ConfigDigest: response.ConfigDigest}, nil
}

func (c *Client) ProbeBuiltOCI(ctx context.Context, binding appcontracts.ImageExecutionBinding) (appcontracts.SourceBuiltContainerReceipt, bool, error) {
	var zero appcontracts.SourceBuiltContainerReceipt
	req, err := builtImportRequest(binding)
	if err != nil {
		return zero, false, err
	}
	payload, err := json.Marshal(req)
	if err != nil {
		return zero, false, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://unix/v1/image/built-oci/probe", bytes.NewReader(payload))
	if err != nil {
		return zero, false, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, data, err := c.httpClient.Do(httpReq)
	if err != nil {
		return zero, false, fmt.Errorf("%w: destination OCI probe unavailable: %v", appcontracts.ErrOutcomeUnknown, err)
	}
	if resp.StatusCode != http.StatusOK {
		return zero, false, appcontracts.ErrOutcomeUnknown
	}
	var result BuiltOCIImportResponse
	if err := decodeStrictJSON(bytes.NewReader(data), &result); err != nil {
		return zero, false, appcontracts.ErrOutcomeUnknown
	}
	if !result.Present {
		return zero, false, nil
	}
	receipt, err := builtReceipt(result, req.Artifact)
	return receipt, err == nil, err
}

func (c *Client) ImportBuiltOCI(ctx context.Context, binding appcontracts.ImageExecutionBinding, archive io.Reader) (appcontracts.SourceBuiltContainerReceipt, error) {
	var zero appcontracts.SourceBuiltContainerReceipt
	req, err := builtImportRequest(binding)
	if err != nil || archive == nil {
		return zero, appcontracts.ErrOutcomeUnknown
	}
	payload, err := json.Marshal(req)
	if err != nil {
		return zero, err
	}
	// The worker owns the Source stream and must inspect its final Close result.
	// Keep net/http from closing that verified reader before the worker does.
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://unix/v1/image/built-oci/import", io.NopCloser(archive))
	if err != nil {
		return zero, err
	}
	httpReq.Header.Set("Content-Type", "application/vnd.oci.image.layout.v1.tar")
	httpReq.Header.Set("X-AcornFox-Built-OCI-Authority", base64.RawURLEncoding.EncodeToString(payload))
	resp, err := c.streamClient.DoStream(httpReq, 64<<10)
	if err != nil {
		return zero, fmt.Errorf("%w: destination OCI import unavailable: %v", appcontracts.ErrOutcomeUnknown, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return zero, appcontracts.ErrOutcomeUnknown
	}
	var result BuiltOCIImportResponse
	if err := decodeStrictJSON(resp.Body, &result); err != nil {
		return zero, appcontracts.ErrOutcomeUnknown
	}
	return builtReceipt(result, req.Artifact)
}

// ObserveDeployment queries the container state from the container role.
func (c *Client) ObserveDeployment(ctx context.Context, deploymentID domain.ID, operationID domain.ID) (appcontracts.ImageExecutionResult, error) {
	reqBody := ObserveRequest{
		DeploymentID: deploymentID,
		OperationID:  operationID,
	}
	payload, err := json.Marshal(reqBody)
	if err != nil {
		return appcontracts.ImageExecutionResult{}, fmt.Errorf("encode observe request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://unix/v1/image/observe", bytes.NewReader(payload))
	if err != nil {
		return appcontracts.ImageExecutionResult{}, fmt.Errorf("create observe request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	httpResp, body, err := c.httpClient.Do(httpReq)
	if err != nil {
		return appcontracts.ImageExecutionResult{}, fmt.Errorf("%w: dispatch observe failed: %v", appcontracts.ErrOutcomeUnknown, err)
	}
	if httpResp.StatusCode != http.StatusOK {
		return appcontracts.ImageExecutionResult{}, fmt.Errorf("observe returned status %d: %s", httpResp.StatusCode, string(body))
	}

	var resp ObserveResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return appcontracts.ImageExecutionResult{}, fmt.Errorf("%w: decode observe response: %v", appcontracts.ErrOutcomeUnknown, err)
	}
	if !resp.Success {
		return appcontracts.ImageExecutionResult{}, errors.New(resp.Error)
	}

	return appcontracts.ImageExecutionResult{
		Status:         resp.Status,
		Running:        resp.Running,
		ContainerID:    resp.ContainerID,
		ContainerName:  resp.ContainerName,
		ImageID:        resp.ImageID,
		ManifestDigest: resp.ManifestDigest,
		Artifact: appcontracts.StorageArtifactReceipt{
			StorageRef:    resp.StorageRef,
			ContentDigest: resp.ContentDigest,
			SizeBytes:     resp.SizeBytes,
		},
		HostPort:      resp.HostPort,
		ContainerPort: resp.ContainerPort,
		ObservedAt:    resp.ObservedAt,
	}, nil
}

func (c *Client) ReadManagedImageObservation(ctx context.Context, q appcontracts.ImageObservationRequest) (appcontracts.ImageObservationResult, error) {
	var out appcontracts.ImageObservationResult
	if !q.Valid(time.Now().UTC()) {
		return out, domain.ValidationError("invalid observation bounds")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	raw, err := json.Marshal(q)
	if err != nil {
		return out, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://unix/v1/image/managed-observation", bytes.NewReader(raw))
	if err != nil {
		return out, err
	}
	resp, data, err := c.httpClient.Do(req)
	if err != nil {
		return out, err
	}
	if resp.StatusCode != http.StatusOK {
		return out, errors.New("managed observation unavailable")
	}
	return decodeManagedObservationResult(data)
}

func (c *Client) ReadManagedImageMetrics(ctx context.Context, q appcontracts.ImageMetricsRequest) (appcontracts.ImageMetricsResult, error) {
	var out appcontracts.ImageMetricsResult
	if !q.Valid() {
		return out, domain.ValidationError("invalid managed metrics request")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	raw, err := json.Marshal(q)
	if err != nil {
		return out, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://unix/v1/image/managed-metrics", bytes.NewReader(raw))
	if err != nil {
		return out, err
	}
	resp, data, err := c.httpClient.Do(req)
	if err != nil {
		return out, err
	}
	if resp.StatusCode != http.StatusOK {
		return out, errors.New("managed metrics unavailable")
	}
	return decodeManagedMetricsResult(data)
}
