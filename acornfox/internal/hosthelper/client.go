package hosthelper

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/acornfox/acornfox/internal/localpeer"
)

type Client struct {
	httpClient *http.Client
}

func NewClient(socketPath string, timeout time.Duration) *Client {
	return newClientWithExpectedServerUID(socketPath, 0, timeout)
}

func newClientWithExpectedServerUID(socketPath string, expectedUID uint32, timeout time.Duration) *Client {
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			conn, err := d.DialContext(ctx, "unix", socketPath)
			if err != nil {
				return nil, err
			}
			ident, err := localpeer.PeerIdentity(conn)
			if err != nil {
				_ = conn.Close()
				return nil, fmt.Errorf("verify helper peer identity failed: %w", err)
			}
			if ident.UID != expectedUID {
				_ = conn.Close()
				return nil, fmt.Errorf("helper server UID %d mismatch (expected %d)", ident.UID, expectedUID)
			}
			return conn, nil
		},
		DisableKeepAlives: true,
	}
	return &Client{
		httpClient: &http.Client{
			Transport: tr,
			Timeout:   timeout,
		},
	}
}

func doJSON[Req any, Resp any](ctx context.Context, c *Client, method, path string, req Req) (Resp, error) {
	var zero Resp
	raw, err := json.Marshal(req)
	if err != nil {
		return zero, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, method, "http://unix"+path, bytes.NewReader(raw))
	if err != nil {
		return zero, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return zero, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return zero, err
	}
	if resp.StatusCode != http.StatusOK {
		return zero, fmt.Errorf("helper rpc error %d: %s", resp.StatusCode, string(body))
	}
	var out Resp
	if err := json.Unmarshal(body, &out); err != nil {
		return zero, fmt.Errorf("unmarshal helper response: %w", err)
	}
	return out, nil
}

func (c *Client) RegisterCore(ctx context.Context, req RegisterCoreRequest) (RegisterCoreResponse, error) {
	return doJSON[RegisterCoreRequest, RegisterCoreResponse](ctx, c, http.MethodPost, "/v1/core/register", req)
}

func (c *Client) PrepareDirs(ctx context.Context, req PrepareDirsRequest) (PrepareDirsResponse, error) {
	return doJSON[PrepareDirsRequest, PrepareDirsResponse](ctx, c, http.MethodPost, "/v1/pack/prepare", req)
}

func (c *Client) PublishPack(ctx context.Context, req PublishPackRequest) (PublishPackResponse, error) {
	return doJSON[PublishPackRequest, PublishPackResponse](ctx, c, http.MethodPost, "/v1/pack/publish", req)
}

func (c *Client) StartPack(ctx context.Context, req StartPackRequest) (StartPackResponse, error) {
	return doJSON[StartPackRequest, StartPackResponse](ctx, c, http.MethodPost, "/v1/pack/start", req)
}

func (c *Client) ObservePack(ctx context.Context, req ObservePackRequest) (ObservePackResponse, error) {
	return doJSON[ObservePackRequest, ObservePackResponse](ctx, c, http.MethodPost, "/v1/pack/observe", req)
}

func (c *Client) StopPending(ctx context.Context, req StopPendingRequest) (StopPendingResponse, error) {
	return doJSON[StopPendingRequest, StopPendingResponse](ctx, c, http.MethodPost, "/v1/pack/stop", req)
}

func (c *Client) AbortPending(ctx context.Context, req AbortPendingRequest) (AbortPendingResponse, error) {
	return doJSON[AbortPendingRequest, AbortPendingResponse](ctx, c, http.MethodPost, "/v1/pack/abort", req)
}

func (c *Client) SwitchCurrent(ctx context.Context, req SwitchCurrentRequest) (SwitchCurrentResponse, error) {
	return doJSON[SwitchCurrentRequest, SwitchCurrentResponse](ctx, c, http.MethodPost, "/v1/pack/current", req)
}

func (c *Client) AttestRuntimePeer(ctx context.Context, req RuntimePeerAttestRequest) (RuntimePeerAttestResponse, error) {
	var zero RuntimePeerAttestResponse
	raw, err := json.Marshal(req)
	if err != nil {
		return zero, fmt.Errorf("marshal attest request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://unix/v1/runtime/peer/attest", bytes.NewReader(raw))
	if err != nil {
		return zero, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	copiedClient := *c.httpClient
	copiedClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	httpResp, err := copiedClient.Do(httpReq)
	if err != nil {
		return zero, fmt.Errorf("dial root helper for peer attestation: %w", err)
	}
	defer httpResp.Body.Close()

	bodyData, err := io.ReadAll(io.LimitReader(httpResp.Body, 16<<10+1))
	if err != nil {
		return zero, fmt.Errorf("read attest response: %w", err)
	}
	if len(bodyData) > 16<<10 {
		return zero, errors.New("attest response exceeds 16KB bound")
	}

	dec := json.NewDecoder(bytes.NewReader(bodyData))
	dec.DisallowUnknownFields()

	var resp RuntimePeerAttestResponse
	if err := dec.Decode(&resp); err != nil {
		return zero, fmt.Errorf("decode attest response: %w", err)
	}
	var trailing json.RawMessage
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return zero, errors.New("extraneous content in attest response")
	}

	if httpResp.StatusCode != http.StatusOK || !resp.Valid {
		errMsg := resp.Error
		if errMsg == "" {
			errMsg = fmt.Sprintf("runtime peer attestation rejected by root host helper (status %d)", httpResp.StatusCode)
		}
		return resp, errors.New(errMsg)
	}

	return resp, nil
}
