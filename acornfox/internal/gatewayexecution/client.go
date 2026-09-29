package gatewayexecution

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"time"

	appcontracts "github.com/acornfox/acornfox/internal/application/contracts"
	"github.com/acornfox/acornfox/internal/peer"
)

type ClientConfig struct {
	SocketPath string
	PeerUID    uint32 // account that must serve the socket
}

func validateClientConfig(c ClientConfig) error {
	if !filepath.IsAbs(c.SocketPath) || filepath.Clean(c.SocketPath) != c.SocketPath || c.PeerUID == 0 {
		return errors.New("Gateway client requires an absolute socket and a non-root peer uid")
	}
	return nil
}

type Client struct{ http *peer.Client }

func NewClient(c ClientConfig) (*Client, error) {
	if err := validateClientConfig(c); err != nil {
		return nil, err
	}
	return &Client{http: peer.NewClient(c.SocketPath, c.PeerUID, 30*time.Second)}, nil
}

func (c *Client) ExecuteImagePublicAccess(ctx context.Context, b appcontracts.ImagePublicAccessCommand, authority appcontracts.ImagePublicAccessAuthority) (appcontracts.ImagePublicAccessObservation, error) {
	var zero appcontracts.ImagePublicAccessObservation
	command := Command{Binding: b, Authority: authority}
	if !commandValid(command) {
		return zero, errors.New("Gateway command binding invalid")
	}
	raw, err := json.Marshal(command)
	if err != nil || len(raw) > maxCommandBytes {
		return zero, errors.New("Gateway command exceeds bound")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://unix/v1/gateway/execute", bytes.NewReader(raw))
	if err != nil {
		return zero, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, body, err := c.http.Do(req)
	if err != nil {
		return zero, fmt.Errorf("%w: Gateway reply lost: %v", appcontracts.ErrOutcomeUnknown, err)
	}
	var response ExecutionResponse
	if resp.StatusCode != http.StatusOK || strictDecode(body, maxCommandBytes, &response) != nil || response.OutcomeUnknown && response.Observation != nil {
		return zero, fmt.Errorf("%w: Gateway response unavailable or malformed", appcontracts.ErrOutcomeUnknown)
	}
	if response.OutcomeUnknown {
		return zero, fmt.Errorf("%w: Gateway effect requires reconciliation", appcontracts.ErrOutcomeUnknown)
	}
	if response.Error != "" {
		if response.Observation != nil {
			return zero, fmt.Errorf("%w: contradictory Gateway result", appcontracts.ErrOutcomeUnknown)
		}
		return zero, errors.New("Gateway rejected command before effect")
	}
	if response.Observation == nil || !response.Observation.RouteApplied || response.Observation.ObservedAt.IsZero() {
		return zero, fmt.Errorf("%w: missing actual Gateway route observation", appcontracts.ErrOutcomeUnknown)
	}
	return *response.Observation, nil
}

type AuthorityClient struct{ http *peer.Client }

func NewAuthorityClient(c ClientConfig) (*AuthorityClient, error) {
	if err := validateClientConfig(c); err != nil {
		return nil, err
	}
	return &AuthorityClient{http: peer.NewClient(c.SocketPath, c.PeerUID, 3*time.Second)}, nil
}

func (c *AuthorityClient) request(ctx context.Context, endpoint string, value any, maxResponse int) (int, []byte, error) {
	raw, err := json.Marshal(value)
	if err != nil || len(raw) > maxCommandBytes {
		return 0, nil, errors.New("Gateway authority request exceeds bound")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://unix"+endpoint, bytes.NewReader(raw))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if maxResponse <= maxCommandBytes {
		resp, body, err := c.http.Do(req)
		if err != nil {
			return 0, nil, err
		}
		return resp.StatusCode, body, nil
	}
	resp, err := c.http.DoStream(req, int64(maxResponse))
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, int64(maxResponse)+1))
	if err != nil || len(body) > maxResponse {
		return 0, nil, errors.New("Gateway authority response exceeds bound")
	}
	return resp.StatusCode, body, nil
}

func (c *AuthorityClient) Authorize(ctx context.Context, command Command) error {
	if !commandValid(command) {
		return errors.New("Gateway command invalid")
	}
	status, body, err := c.request(ctx, "/v1/gateway/authorize", command, maxCommandBytes)
	if err != nil || status != http.StatusOK {
		return errors.New("Core Gateway authority unavailable")
	}
	var reply AuthorityResponse
	if strictDecode(body, maxCommandBytes, &reply) != nil || !sameCommand(reply.Binding, command.Binding) {
		return errors.New("Core Gateway command differs")
	}
	return nil
}

func (c *AuthorityClient) List(ctx context.Context, command Command) ([]appcontracts.ImagePublicAccessRoute, error) {
	if !commandValid(command) {
		return nil, errors.New("Gateway command invalid")
	}
	status, body, err := c.request(ctx, "/v1/gateway/routes", command, maxInventoryBytes)
	if err != nil || status != http.StatusOK {
		return nil, errors.New("Core Gateway inventory unavailable")
	}
	var reply InventoryResponse
	if strictDecode(body, maxInventoryBytes, &reply) != nil || len(reply.Routes) > 1024 || !routeForCommand(reply.Routes, command.Binding) {
		return nil, errors.New("Core Gateway inventory differs from command")
	}
	return reply.Routes, nil
}

func (c *AuthorityClient) Check(ctx context.Context, command Command, digest string) error {
	if !commandValid(command) || digest == "" {
		return errors.New("Gateway pre-write fence incomplete")
	}
	status, body, err := c.request(ctx, "/v1/gateway/check", SnapshotCheck{Command: command, Digest: digest}, maxCommandBytes)
	if err != nil || status != http.StatusNoContent || len(body) != 0 {
		return errors.New("Core Gateway pre-write fence changed")
	}
	return nil
}
