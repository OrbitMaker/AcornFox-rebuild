package runner

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

	"github.com/acornfox/acornfox/internal/peer"
)

// Response size bounds. Most replies are small typed JSON, but build failures
// carry a log excerpt and logs responses carry up to 1000 lines, so those two
// routes use a larger bound.
const (
	clientDefaultBound = peer.MaxMessageBytes
	clientLargeBound   = 4 << 20
)

// Timeouts. The peer.Client's own timeout bounds ordinary requests; builds are
// long-running and use their own per-request timeout.
const (
	clientDefaultTimeout = 60 * time.Second
	buildTimeout         = 25 * time.Minute
)

// Client implements API by calling a runner Server over a peer Unix socket.
type Client struct {
	socket   string
	peerUID  uint32
	standard *peer.Client // for ordinary short requests
	long     *peer.Client // for long build requests (25 min)
}

// NewClient returns a Client for the runner socket at path, whose server must
// run as peerUID.
func NewClient(path string, peerUID uint32) *Client {
	return &Client{
		socket:   path,
		peerUID:  peerUID,
		standard: peer.NewClient(path, peerUID, clientDefaultTimeout),
		long:     peer.NewClient(path, peerUID, buildTimeout),
	}
}

// call sends body to route and decodes the JSON reply into out. It maps
// transport failures to ErrUnavailable, 404 not_found to ErrNotFound, and any
// other non-2xx to *RemoteError.
func (c *Client) call(ctx context.Context, pc *peer.Client, route string, body any, bound int64, out any) error {
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			return err
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://unix"+route, &buf)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := pc.DoStream(req, bound)
	if err != nil {
		if isDialError(err) {
			return ErrUnavailable
		}
		return err
	}
	defer resp.Body.Close()

	payload, err := io.ReadAll(io.LimitReader(resp.Body, bound+1))
	if err != nil {
		if isDialError(err) {
			return ErrUnavailable
		}
		return err
	}

	if resp.StatusCode/100 != 2 {
		var er ErrorResponse
		_ = json.Unmarshal(payload, &er)
		if resp.StatusCode == http.StatusNotFound && er.Code == "not_found" {
			return ErrNotFound
		}
		if er.Code == "" {
			er.Message = fmt.Sprintf("runner returned status %d", resp.StatusCode)
		}
		return &RemoteError{Status: resp.StatusCode, ErrorResponse: er}
	}

	if out != nil && len(payload) > 0 {
		if err := json.Unmarshal(payload, out); err != nil {
			return err
		}
	}
	return nil
}

// isDialError reports whether err indicates the socket could not be reached.
func isDialError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, peer.ErrPeerMismatch) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return true
	}
	return false
}

// Ping implements API.
func (c *Client) Ping(ctx context.Context) (PingResponse, error) {
	var out PingResponse
	err := c.call(ctx, c.standard, PathPing, struct{}{}, clientDefaultBound, &out)
	return out, err
}

// Build implements API. It uses a 25 minute timeout and a large response bound.
func (c *Client) Build(ctx context.Context, req BuildRequest) (BuildResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, buildTimeout)
	defer cancel()
	var out BuildResponse
	err := c.call(ctx, c.long, PathBuild, req, clientLargeBound, &out)
	return out, err
}

// ImageInspect implements API.
func (c *Client) ImageInspect(ctx context.Context, app, ref string) (ImageInfo, error) {
	var out ImageInfo
	err := c.call(ctx, c.standard, PathImageInspect, ImageRef{App: app, Ref: ref}, clientDefaultBound, &out)
	return out, err
}

// ListImages implements API.
func (c *Client) ListImages(ctx context.Context, app string) ([]ImageInfo, error) {
	var out ImageListResponse
	err := c.call(ctx, c.standard, PathImageList, AppRef{App: app}, clientLargeBound, &out)
	return out.Images, err
}

// RemoveImage implements API.
func (c *Client) RemoveImage(ctx context.Context, app, ref string) error {
	return c.call(ctx, c.standard, PathImageRemove, ImageRef{App: app, Ref: ref}, clientDefaultBound, nil)
}

// EnsureContainer implements API.
func (c *Client) EnsureContainer(ctx context.Context, req EnsureContainerRequest) (ContainerInfo, error) {
	var out ContainerInfo
	err := c.call(ctx, c.standard, PathContainerEnsure, req, clientDefaultBound, &out)
	return out, err
}

// ListContainers implements API.
func (c *Client) ListContainers(ctx context.Context, app string) ([]ContainerInfo, error) {
	var out ContainerListResponse
	err := c.call(ctx, c.standard, PathContainerList, AppRef{App: app}, clientLargeBound, &out)
	return out.Containers, err
}

// StopContainer implements API.
func (c *Client) StopContainer(ctx context.Context, app, name string) error {
	return c.call(ctx, c.standard, PathContainerStop, ContainerRef{App: app, Name: name}, clientDefaultBound, nil)
}

// StartContainer implements API.
func (c *Client) StartContainer(ctx context.Context, app, name string) (ContainerInfo, error) {
	var out ContainerInfo
	err := c.call(ctx, c.standard, PathContainerStart, ContainerRef{App: app, Name: name}, clientDefaultBound, &out)
	return out, err
}

// RemoveContainer implements API.
func (c *Client) RemoveContainer(ctx context.Context, app, name string) error {
	return c.call(ctx, c.standard, PathContainerRemove, ContainerRef{App: app, Name: name}, clientDefaultBound, nil)
}

// Logs implements API. It uses a large response bound for up to 1000 lines.
func (c *Client) Logs(ctx context.Context, app, name string, tail int) ([]string, error) {
	var out LogsResponse
	err := c.call(ctx, c.standard, PathContainerLogs, LogsRequest{App: app, Name: name, Tail: tail}, clientLargeBound, &out)
	return out.Lines, err
}

// Diff implements API.
func (c *Client) Diff(ctx context.Context, app, name string) ([]string, error) {
	var out DiffResponse
	err := c.call(ctx, c.standard, PathContainerDiff, ContainerRef{App: app, Name: name}, clientLargeBound, &out)
	return out.DatabaseFiles, err
}

// EnsureVolume implements API.
func (c *Client) EnsureVolume(ctx context.Context, app, name string) error {
	return c.call(ctx, c.standard, PathVolumeEnsure, VolumeRef{App: app, Name: name}, clientDefaultBound, nil)
}

// ListVolumes implements API.
func (c *Client) ListVolumes(ctx context.Context, app string) ([]VolumeInfo, error) {
	var out VolumeListResponse
	err := c.call(ctx, c.standard, PathVolumeList, AppRef{App: app}, clientLargeBound, &out)
	return out.Volumes, err
}

// ensure Client and Docker satisfy API at compile time.
var (
	_ API = (*Client)(nil)
	_ API = (*Docker)(nil)
)
