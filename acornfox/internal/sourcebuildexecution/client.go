package sourcebuildexecution

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
	"github.com/acornfox/acornfox/internal/contracts"
	"github.com/acornfox/acornfox/internal/peer"
)

type ClientConfig struct {
	SocketPath string
	PeerUID    uint32 // account that must serve the socket
}
type Client struct{ http *peer.Client }

func NewClient(c ClientConfig) (*Client, error) {
	if !filepath.IsAbs(c.SocketPath) || c.PeerUID == 0 {
		return nil, errors.New("source-build client requires an absolute socket and a non-root peer uid")
	}
	// Execution timeout is the sealed Core deadline, not a shorter transport timer.
	return &Client{http: peer.NewClient(c.SocketPath, c.PeerUID, 0)}, nil
}
func strictMessage(raw []byte, v any) error {
	if len(raw) > peer.MaxMessageBytes {
		return errors.New("source-build message exceeds bound")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return errors.New("source-build message has trailing data")
	}
	return nil
}
func commandDeadline(c SourceBuildCommand) (time.Time, error) {
	switch c.Stage {
	case appcontracts.SourceBuildPrepare:
		if c.Prepare != nil && c.Build == nil && c.Cancel == nil && c.Release == nil {
			return c.Prepare.Operation.Deadline, nil
		}
	case appcontracts.SourceBuildBuild:
		if c.Build != nil && c.Prepare == nil && c.Cancel == nil && c.Release == nil && c.Build.Capacity == nil {
			return c.Build.Operation.Deadline, nil
		}
	}
	return time.Time{}, ErrBinding
}

type executionResponse struct {
	Receipt        *appcontracts.SourceBuildExecutionReceipt `json:"receipt,omitempty"`
	Error          string                                    `json:"error,omitempty"`
	OutcomeUnknown bool                                      `json:"outcome_unknown,omitempty"`
}

func (c *Client) ExecuteSourceBuild(ctx context.Context, raw []byte) (appcontracts.SourceBuildExecutionReceipt, error) {
	var zero appcontracts.SourceBuildExecutionReceipt
	var command SourceBuildCommand
	if err := strictMessage(raw, &command); err != nil {
		return zero, ErrBinding
	}
	deadline, err := commandDeadline(command)
	if err != nil || !deadline.After(time.Now()) {
		return zero, ErrBinding
	}
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://unix/v1/source-build/execute", bytes.NewReader(raw))
	if err != nil {
		return zero, err
	}
	request.Header.Set("Content-Type", "application/json")
	response, body, err := c.http.Do(request)
	if err != nil {
		return zero, &contracts.ProviderOutcomeUnknownError{Cause: err}
	}
	var wire executionResponse
	if err := strictMessage(body, &wire); err != nil {
		return zero, &contracts.ProviderOutcomeUnknownError{Cause: ErrBinding}
	}
	if response.StatusCode != http.StatusOK || wire.Receipt == nil || wire.Error != "" || wire.OutcomeUnknown {
		return zero, &contracts.ProviderOutcomeUnknownError{Cause: errors.New("source-build execution unavailable or requires reconciliation")}
	}
	sha, err := SourceBuildCommandDigest(command)
	if err != nil || wire.Receipt.Binding != command.Binding || wire.Receipt.Stage != command.Stage || wire.Receipt.CommandSHA256 != sha {
		return zero, &contracts.ProviderOutcomeUnknownError{Cause: ErrBinding}
	}
	return *wire.Receipt, nil
}

// CheckReady proves a peer responds with its composed execution interface; it
// never reports installed-worker or source/build business success.
func (c *Client) CheckReady(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	r, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://unix/v1/source-build/health", nil)
	resp, body, err := c.http.Do(r)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK || string(body) != `{"interface":"source-build-execution-v1"}` {
		return errors.New("source-build interface unavailable")
	}
	return nil
}

type AuthorityClient struct{ http *peer.Client }

func NewAuthorityClient(c ClientConfig) (*AuthorityClient, error) {
	if !filepath.IsAbs(c.SocketPath) || c.PeerUID == 0 {
		return nil, errors.New("source authority requires an absolute socket and a non-root Core uid")
	}
	return &AuthorityClient{peer.NewClient(c.SocketPath, c.PeerUID, 3*time.Second)}, nil
}
func (c *AuthorityClient) AuthorizeSourceBuild(ctx context.Context, command SourceBuildCommand) (appcontracts.SourceBuildPermit, error) {
	var zero appcontracts.SourceBuildPermit
	raw, err := json.Marshal(command)
	if err != nil {
		return zero, err
	}
	if len(raw) > peer.MaxMessageBytes {
		return zero, ErrBinding
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://unix/v1/source-build/authorize", bytes.NewReader(raw))
	if err != nil {
		return zero, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, body, err := c.http.Do(req)
	if err != nil {
		return zero, err
	}
	if resp.StatusCode != http.StatusOK {
		return zero, errors.New("Core source-build authority rejected command")
	}
	var permit appcontracts.SourceBuildPermit
	if err := strictMessage(body, &permit); err != nil {
		return zero, ErrBinding
	}
	sha, err := SourceBuildCommandDigest(command)
	if err != nil || permit.CommandSHA256 != sha {
		return zero, fmt.Errorf("%w: authority intent digest", ErrBinding)
	}
	return permit, nil
}

var _ appcontracts.SourceBuildExecutionClient = (*Client)(nil)
