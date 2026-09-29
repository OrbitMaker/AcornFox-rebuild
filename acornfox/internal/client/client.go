package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// Client talks to one acornfox server, either directly over HTTP (t.URL set) or
// through a single ssh + "acornfox proxy" connection. It implements API.
type Client struct {
	http    *http.Client
	baseURL string     // scheme://host used to build request URLs
	dialer  *sshDialer // nil in direct mode
}

var _ API = (*Client)(nil)

// Connect builds a *Client for t. In direct mode (t.URL != "") it uses a plain
// http.Client. In SSH mode it wires an http.Transport whose DialContext returns
// the single sshConn (started lazily on the first request), with keep-alive and
// MaxConnsPerHost=1 so one CLI command uses exactly one SSH session.
func Connect(ctx context.Context, t Target) (*Client, error) {
	if t.URL != "" {
		u, err := url.Parse(t.URL)
		if err != nil {
			return nil, connectError(codeConnectFailed, err.Error())
		}
		return &Client{
			http:    &http.Client{},
			baseURL: strings.TrimRight(u.Scheme+"://"+u.Host, "/"),
		}, nil
	}

	if t.SSH == "" {
		return nil, connectError(codeConnectFailed, "target 缺少 ssh 或 url")
	}

	dialer := &sshDialer{target: t}
	tr := &http.Transport{
		DialContext: func(dctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.dial(dctx)
		},
		MaxConnsPerHost:     1,
		DisableCompression:  true,
		DisableKeepAlives:   false,
		MaxIdleConnsPerHost: 1,
	}
	return &Client{
		http:    &http.Client{Transport: tr},
		baseURL: "http://acornfox", // host is irrelevant; DialContext ignores it
		dialer:  dialer,
	}, nil
}

// Close ends the SSH session (no-op in direct mode).
func (c *Client) Close() error {
	if c.dialer != nil {
		return c.dialer.close()
	}
	return nil
}

// doJSON performs a request whose response is decoded into out (may be nil).
// body, when non-nil, is JSON-encoded. It returns a classified *Error on
// connect failure and a server *Error on a non-2xx JSON error reply.
func (c *Client) doJSON(ctx context.Context, method, path string, body any, out any) (int, error) {
	var rdr io.Reader
	var contentType string
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return 0, err
		}
		rdr = bytes.NewReader(buf)
		contentType = "application/json"
	}
	return c.do(ctx, method, path, rdr, -1, contentType, out)
}

// do performs one HTTP request. size >= 0 sets Content-Length. It classifies a
// transport-level failure (no response bytes) as a connect *Error and a non-2xx
// response as a server *Error.
func (c *Client) do(ctx context.Context, method, path string, body io.Reader, size int64, contentType string, out any) (int, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return 0, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if size >= 0 {
		req.ContentLength = size
	}

	resp, err := c.http.Do(req)
	if err != nil {
		// Transport failure before any response byte: surface the connect
		// diagnosis when this is an SSH client.
		return 0, c.classifyTransport(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return resp.StatusCode, c.serverError(resp)
	}
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return resp.StatusCode, err
		}
	} else {
		_, _ = io.Copy(io.Discard, resp.Body)
	}
	return resp.StatusCode, nil
}

// classifyTransport converts a transport error into a connect *Error. In SSH
// mode it consults the dialer for the ssh exit/stderr classification.
func (c *Client) classifyTransport(err error) error {
	if c.dialer != nil {
		if e := c.dialer.classifyStartupFailure(); e != nil {
			return e
		}
	}
	return connectError(codeConnectFailed, err.Error())
}

// serverError reads a {"error":{code,message}} body into a server-stage *Error.
func (c *Client) serverError(resp *http.Response) error {
	var wire struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	_ = json.Unmarshal(data, &wire)
	code := wire.Error.Code
	msg := wire.Error.Message
	if code == "" {
		code = "http_" + strconv.Itoa(resp.StatusCode)
	}
	if msg == "" {
		msg = strings.TrimSpace(string(data))
		if msg == "" {
			msg = http.StatusText(resp.StatusCode)
		}
	}
	return &Error{
		Status: resp.StatusCode,
		Diag: Diagnosis{
			Stage:   "server",
			Code:    code,
			Message: msg,
		},
	}
}

// ---- API methods ----

// Status calls GET /v1/status and verifies api_version == APIVersion.
func (c *Client) Status(ctx context.Context) (Status, error) {
	var st Status
	if _, err := c.doJSON(ctx, http.MethodGet, "/v1/status", nil, &st); err != nil {
		return Status{}, err
	}
	if st.APIVersion != APIVersion {
		return st, connectError(codeVersionMismatch,
			fmt.Sprintf("server api_version=%d, cli=%d", st.APIVersion, APIVersion))
	}
	return st, nil
}

// Deploy calls POST /v1/apps/{app}/deployments. Exactly one of Upload, Image or
// Git in opt selects the source. Returns the deployment and whether it was
// newly created (202) versus a duplicate (200).
func (c *Client) Deploy(ctx context.Context, app string, opt DeployOptions) (Deployment, bool, error) {
	path := "/v1/apps/" + url.PathEscape(app) + "/deployments"
	q := url.Values{}
	if opt.Port != 0 {
		q.Set("port", strconv.Itoa(opt.Port))
	}
	if opt.HealthPath != "" {
		q.Set("health_path", opt.HealthPath)
	}
	if enc := q.Encode(); enc != "" {
		path += "?" + enc
	}

	var (
		body        io.Reader
		size        int64 = -1
		contentType string
	)
	switch {
	case opt.Upload != nil:
		body = opt.Upload
		contentType = "application/gzip"
		if opt.UploadSize > 0 {
			size = opt.UploadSize
		}
	case opt.Image != "":
		buf, _ := json.Marshal(map[string]string{"image": opt.Image})
		body = bytes.NewReader(buf)
		contentType = "application/json"
	case opt.Git != "":
		payload := map[string]string{"git": opt.Git}
		if opt.Ref != "" {
			payload["ref"] = opt.Ref
		}
		buf, _ := json.Marshal(payload)
		body = bytes.NewReader(buf)
		contentType = "application/json"
	default:
		return Deployment{}, false, fmt.Errorf("client: DeployOptions has no source")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, body)
	if err != nil {
		return Deployment{}, false, err
	}
	req.Header.Set("Content-Type", contentType)
	if size >= 0 {
		req.ContentLength = size
	}
	if opt.IdempotencyKey != "" {
		req.Header.Set("Idempotency-Key", opt.IdempotencyKey)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return Deployment{}, false, c.classifyTransport(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return Deployment{}, false, c.serverError(resp)
	}
	var dep Deployment
	if err := json.NewDecoder(resp.Body).Decode(&dep); err != nil {
		return Deployment{}, false, err
	}
	created := resp.StatusCode == http.StatusAccepted // 202 new, 200 duplicate
	return dep, created, nil
}

// Rollback calls POST /v1/apps/{app}/rollback.
func (c *Client) Rollback(ctx context.Context, app string) (Deployment, error) {
	var dep Deployment
	path := "/v1/apps/" + url.PathEscape(app) + "/rollback"
	if _, err := c.do(ctx, http.MethodPost, path, nil, -1, "", &dep); err != nil {
		return Deployment{}, err
	}
	return dep, nil
}

// Deployment calls GET /v1/deployments/{id}?after=N and returns the deployment
// plus its events.
func (c *Client) Deployment(ctx context.Context, id string, afterEvent int64) (Deployment, []Event, error) {
	path := "/v1/deployments/" + url.PathEscape(id)
	if afterEvent > 0 {
		path += "?after=" + strconv.FormatInt(afterEvent, 10)
	}
	var wrap struct {
		Deployment Deployment `json:"deployment"`
		Events     []Event    `json:"events"`
	}
	if _, err := c.do(ctx, http.MethodGet, path, nil, -1, "", &wrap); err != nil {
		return Deployment{}, nil, err
	}
	return wrap.Deployment, wrap.Events, nil
}

// Apps calls GET /v1/apps.
func (c *Client) Apps(ctx context.Context) ([]App, error) {
	var wrap struct {
		Apps []App `json:"apps"`
	}
	if _, err := c.do(ctx, http.MethodGet, "/v1/apps", nil, -1, "", &wrap); err != nil {
		return nil, err
	}
	return wrap.Apps, nil
}

// App calls GET /v1/apps/{app}.
func (c *Client) App(ctx context.Context, app string) (App, error) {
	var a App
	path := "/v1/apps/" + url.PathEscape(app)
	if _, err := c.do(ctx, http.MethodGet, path, nil, -1, "", &a); err != nil {
		return App{}, err
	}
	return a, nil
}

// UpdateApp calls PATCH /v1/apps/{app}.
func (c *Client) UpdateApp(ctx context.Context, app string, s AppSettings) (App, error) {
	var a App
	path := "/v1/apps/" + url.PathEscape(app)
	if _, err := c.doJSON(ctx, http.MethodPatch, path, s, &a); err != nil {
		return App{}, err
	}
	return a, nil
}

// Logs calls GET /v1/apps/{app}/logs?tail=N.
func (c *Client) Logs(ctx context.Context, app string, tail int) ([]string, error) {
	path := "/v1/apps/" + url.PathEscape(app) + "/logs"
	if tail > 0 {
		path += "?tail=" + strconv.Itoa(tail)
	}
	var wrap struct {
		Lines []string `json:"lines"`
	}
	if _, err := c.do(ctx, http.MethodGet, path, nil, -1, "", &wrap); err != nil {
		return nil, err
	}
	return wrap.Lines, nil
}

// SetEnv calls PUT /v1/apps/{app}/env/{key}.
func (c *Client) SetEnv(ctx context.Context, app, key, value string, secret bool) error {
	path := "/v1/apps/" + url.PathEscape(app) + "/env/" + url.PathEscape(key)
	body := map[string]any{"value": value, "secret": secret}
	_, err := c.doJSON(ctx, http.MethodPut, path, body, nil)
	return err
}

// UnsetEnv calls DELETE /v1/apps/{app}/env/{key}.
func (c *Client) UnsetEnv(ctx context.Context, app, key string) error {
	path := "/v1/apps/" + url.PathEscape(app) + "/env/" + url.PathEscape(key)
	_, err := c.do(ctx, http.MethodDelete, path, nil, -1, "", nil)
	return err
}

// AddVolume calls POST /v1/apps/{app}/volumes.
func (c *Client) AddVolume(ctx context.Context, app, path string) error {
	p := "/v1/apps/" + url.PathEscape(app) + "/volumes"
	_, err := c.doJSON(ctx, http.MethodPost, p, map[string]string{"path": path}, nil)
	return err
}

// Stop calls POST /v1/apps/{app}/stop.
func (c *Client) Stop(ctx context.Context, app string) error {
	path := "/v1/apps/" + url.PathEscape(app) + "/stop"
	_, err := c.do(ctx, http.MethodPost, path, nil, -1, "", nil)
	return err
}

// Start calls POST /v1/apps/{app}/start.
func (c *Client) Start(ctx context.Context, app string) error {
	path := "/v1/apps/" + url.PathEscape(app) + "/start"
	_, err := c.do(ctx, http.MethodPost, path, nil, -1, "", nil)
	return err
}
