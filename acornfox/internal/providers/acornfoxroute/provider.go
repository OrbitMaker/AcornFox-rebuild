package acornfoxroute

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/acornfox/acornfox/internal/contracts"
)

var errPolicy = errors.New("invalid AcornFox public route policy")

// RouteState contains an already persisted, owned route, including disabled
// records needed to prove ownership when removing a prior Caddy projection.
type RouteState struct {
	Intent   contracts.AcornFoxPublicRouteIntent
	Approval *contracts.AcornFoxApprovedHostnameRoute
	Enabled  bool
}

// Source serializes writers across processes for the entire callback. It must
// rebuild the snapshot from durable records while holding the shared route
// writer lock. The second callback argument rechecks that lock immediately
// before a Caddy write. No in-memory full-route cache is retained here.
type Source interface {
	WithRoutes(context.Context, func([]RouteState, func() error) error) error
}

type Config struct {
	AuthorizedRoot string
	CustomOnly     bool
	// AdminUnixSocket is trusted composition input, never a request field.
	// The expected non-root owner/group must match the protected socket.
	AdminUnixSocket string
	AdminSocketUID  uint32
	AdminSocketGID  uint32
	Source          Source
}
type Provider struct {
	root            string
	source          Source
	client          *http.Client
	mu              sync.Mutex
	adminSocketPath string
	adminSocketUID  uint32
	adminSocketGID  uint32
	adminSocketInfo os.FileInfo
}

func New(c Config) (*Provider, error) {
	root := c.AuthorizedRoot
	if c.CustomOnly {
		if root != "" {
			return nil, errPolicy
		}
	} else {
		validated, err := AuthorizedRoot("https://" + root)
		if err != nil || validated != root {
			return nil, errPolicy
		}
	}
	if c.Source == nil {
		return nil, errPolicy
	}
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	transport := &http.Transport{Proxy: nil, DialContext: dialer.DialContext, ResponseHeaderTimeout: 3 * time.Second, MaxResponseHeaderBytes: 8192}
	var adminSocketInfo os.FileInfo
	if c.AdminUnixSocket != "" {
		var err error
		adminSocketInfo, err = verifyAdminUnixSocket(c.AdminUnixSocket, c.AdminSocketUID, c.AdminSocketGID)
		if err != nil {
			return nil, errPolicy
		}
		transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			before, err := verifyAdminUnixSocket(c.AdminUnixSocket, c.AdminSocketUID, c.AdminSocketGID)
			if err != nil || !os.SameFile(adminSocketInfo, before) {
				return nil, errPolicy
			}
			conn, err := dialer.DialContext(ctx, "unix", c.AdminUnixSocket)
			if err != nil {
				return nil, err
			}
			after, err := verifyAdminUnixSocket(c.AdminUnixSocket, c.AdminSocketUID, c.AdminSocketGID)
			if err != nil || !os.SameFile(adminSocketInfo, after) || !os.SameFile(before, after) {
				conn.Close()
				return nil, errPolicy
			}
			return conn, nil
		}
	} else if c.AdminSocketUID != 0 || c.AdminSocketGID != 0 || c.CustomOnly {
		// The custom-only role must not silently use loopback TCP Admin.
		return nil, errPolicy
	}
	client := &http.Client{Timeout: 5 * time.Second, Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return errPolicy }}
	return &Provider{root: root, source: c.Source, client: client, adminSocketPath: c.AdminUnixSocket, adminSocketUID: c.AdminSocketUID, adminSocketGID: c.AdminSocketGID, adminSocketInfo: adminSocketInfo}, nil
}

func verifyAdminUnixSocket(path string, uid, gid uint32) (os.FileInfo, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || uid == 0 || gid == 0 {
		return nil, errPolicy
	}
	parent := filepath.Dir(path)
	for current := parent; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, errPolicy
		}
		owner, ok := info.Sys().(*syscall.Stat_t)
		if !ok || uint32(owner.Uid) != uid && owner.Uid != 0 || info.Mode().Perm()&0o022 != 0 && !(owner.Uid == 0 && info.Mode()&os.ModeSticky != 0) {
			return nil, errPolicy
		}
		if current == parent && (uint32(owner.Uid) != uid || uint32(owner.Gid) != gid || info.Mode().Perm() != 0o750 || info.Mode()&os.ModeSetgid == 0) {
			return nil, errPolicy
		}
		if current == "/" {
			break
		}
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSocket == 0 || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o660 {
		return nil, errPolicy
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || uint32(owner.Uid) != uid || uint32(owner.Gid) != gid {
		return nil, errPolicy
	}
	return info, nil
}
func (p *Provider) Close() { p.client.CloseIdleConnections() }

// ValidateIntent also excludes every fixed local control-plane/admin port.
// Application targets are accepted runtime-published endpoints, never arbitrary
// host URLs or caller supplied proxy destinations.
func ValidateIntent(root string, i contracts.AcornFoxPublicRouteIntent) error {
	host, err := contracts.AcornFoxPublicHostname(root, i.ApplicationID, i.DeploymentID)
	if err != nil || i.Validate() != nil || host != i.Hostname || i.Port < 1024 {
		return errPolicy
	}
	return validateLocalPort(i.Port)
}

// ValidateApprovedHostnameRoute is separate from the generated-host policy.
// The exact approval must also appear in the durable Source.WithRoutes row;
// this structural check alone never authorizes a Caddy write.
func ValidateApprovedHostnameRoute(root string, approval contracts.AcornFoxApprovedHostnameRoute) error {
	if approval.Validate() != nil || approval.Route.Port < 1024 || approval.Route.Hostname == root ||
		approval.Route.Hostname == "apps."+root ||
		strings.HasSuffix(approval.Route.Hostname, ".apps."+root) {
		return errPolicy
	}
	return validateLocalPort(approval.Route.Port)
}

func validateLocalPort(port int) error {
	switch port {
	case 2019, 2020, 5432, 8080, 8092, 18481, 18482:
		return errPolicy
	}
	return nil
}
func route(i contracts.AcornFoxPublicRouteIntent) object {
	sum := sha256.Sum256([]byte(i.ApplicationID.String() + "\x00" + i.DeploymentID.String()))
	return object{"@id": "acornfox-route-" + hex.EncodeToString(sum[:]), "match": []object{{"host": []string{i.Hostname}}}, "handle": []object{proxy(net.JoinHostPort("127.0.0.1", strconv.Itoa(i.Port)))}, "terminal": true}
}
func (p *Provider) EnsureAcornFoxPublicRoute(ctx context.Context, i contracts.AcornFoxPublicRouteIntent, key string) error {
	return p.project(ctx, &i, nil, true, key)
}
func (p *Provider) RemoveAcornFoxPublicRoute(ctx context.Context, i contracts.AcornFoxPublicRouteIntent, key string) error {
	return p.project(ctx, &i, nil, false, key)
}
func (p *Provider) EnsureAcornFoxApprovedHostnameRoute(ctx context.Context, approval contracts.AcornFoxApprovedHostnameRoute, key string) error {
	return p.project(ctx, &approval.Route, &approval, true, key)
}
func (p *Provider) RemoveAcornFoxApprovedHostnameRoute(ctx context.Context, approval contracts.AcornFoxApprovedHostnameRoute, key string) error {
	return p.project(ctx, &approval.Route, &approval, false, key)
}
func (p *Provider) Reconcile(ctx context.Context) error { return p.project(ctx, nil, nil, false, "") }

// ObserveApprovedHostnameRoute reads only the owned Caddy subtree. False is a
// verified absence of this exact Core-approved route, never a network error,
// foreign-route collision, malformed response, or missing durable approval.
func (p *Provider) ObserveApprovedHostnameRoute(ctx context.Context, approval contracts.AcornFoxApprovedHostnameRoute) (bool, error) {
	if ctx == nil || ctx.Err() != nil {
		return false, ErrPublicAccessUnavailable
	}
	if ValidateApprovedHostnameRoute(p.root, approval) != nil {
		return false, ErrPublicAccessOwnershipConflict
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	p.mu.Lock()
	defer p.mu.Unlock()
	if ctx.Err() != nil {
		return false, ErrPublicAccessUnavailable
	}
	present := false
	err := p.source.WithRoutes(ctx, func(states []RouteState, checkLock func() error) error {
		if checkLock == nil {
			return ErrPublicAccessConflict
		}
		if len(states) > 1024 {
			return ErrPublicAccessUnavailable
		}
		owned := map[string][]byte{}
		seen := map[string]bool{}
		found := false
		targetID := route(approval.Route)["@id"].(string)
		for _, state := range states {
			intent := state.Intent
			if state.Approval == nil && ValidateIntent(p.root, intent) != nil ||
				state.Approval != nil && (state.Approval.Route != intent || ValidateApprovedHostnameRoute(p.root, *state.Approval) != nil) ||
				seen[intent.Hostname] {
				return ErrPublicAccessOwnershipConflict
			}
			seen[intent.Hostname] = true
			item := route(intent)
			id := item["@id"].(string)
			if _, duplicate := owned[id]; duplicate {
				return ErrPublicAccessOwnershipConflict
			}
			raw, _ := json.Marshal(item)
			owned[id] = raw
			if state.Approval != nil && intent == approval.Route && *state.Approval == approval {
				found = true
			}
		}
		if !found {
			return ErrPublicAccessOwnershipConflict
		}
		body, tag, err := p.call(ctx, http.MethodGet, nil, "")
		if err != nil {
			return err
		}
		var current struct {
			ID      string            `json:"@id"`
			Handler string            `json:"handler"`
			Routes  []json.RawMessage `json:"routes"`
		}
		if tag == "" || decode(body, &current) != nil || current.ID != SubtreeID || current.Handler != "subroute" || current.Routes == nil {
			return ErrPublicAccessOwnershipConflict
		}
		seenIDs := map[string]bool{}
		for _, raw := range current.Routes {
			var item map[string]any
			if decode(raw, &item) != nil {
				return ErrPublicAccessOwnershipConflict
			}
			id, ok := item["@id"].(string)
			if !ok || seenIDs[id] {
				return ErrPublicAccessOwnershipConflict
			}
			seenIDs[id] = true
			normalized, _ := json.Marshal(item)
			if !bytes.Equal(normalized, owned[id]) {
				return ErrPublicAccessOwnershipConflict
			}
			if id == targetID {
				present = true
			}
		}
		if err := checkLock(); err != nil {
			return ErrPublicAccessConflict
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, ErrPublicAccessOwnershipConflict) || errors.Is(err, ErrPublicAccessConflict) {
			return false, err
		}
		return false, ErrPublicAccessUnavailable
	}
	return present, nil
}

func (p *Provider) project(ctx context.Context, requested *contracts.AcornFoxPublicRouteIntent, approved *contracts.AcornFoxApprovedHostnameRoute, enabled bool, key string) error {
	if ctx == nil || ctx.Err() != nil {
		return ErrPublicAccessUnavailable
	}
	if requested != nil {
		if strings.TrimSpace(key) == "" || approved == nil && ValidateIntent(p.root, *requested) != nil ||
			approved != nil && (approved.Route != *requested || ValidateApprovedHostnameRoute(p.root, *approved) != nil) {
			return ErrPublicAccessOwnershipConflict
		}
	} else if approved != nil {
		return ErrPublicAccessOwnershipConflict
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	p.mu.Lock()
	defer p.mu.Unlock()
	if ctx.Err() != nil {
		return ErrPublicAccessUnavailable
	}
	err := p.source.WithRoutes(ctx, func(states []RouteState, checkLock func() error) error {
		if checkLock == nil {
			return ErrPublicAccessConflict
		}
		if len(states) > 1024 {
			return ErrPublicAccessUnavailable
		}
		owned := map[string][]byte{}
		desired := []object{}
		seen := map[string]bool{}
		found := requested == nil
		states = append([]RouteState(nil), states...)
		sort.Slice(states, func(i, j int) bool { return states[i].Intent.Hostname < states[j].Intent.Hostname })
		for _, state := range states {
			i := state.Intent
			if state.Approval == nil && ValidateIntent(p.root, i) != nil ||
				state.Approval != nil && (state.Approval.Route != i || ValidateApprovedHostnameRoute(p.root, *state.Approval) != nil) ||
				seen[i.Hostname] {
				return ErrPublicAccessOwnershipConflict
			}
			seen[i.Hostname] = true
			item := route(i)
			raw, _ := json.Marshal(item)
			id := item["@id"].(string)
			if _, duplicate := owned[id]; duplicate {
				return ErrPublicAccessOwnershipConflict
			}
			owned[id] = raw
			if state.Enabled {
				desired = append(desired, item)
			}
			if requested != nil && i == *requested && state.Enabled == enabled &&
				(approved == nil && state.Approval == nil || approved != nil && state.Approval != nil && *approved == *state.Approval) {
				found = true
			}
		}
		if !found {
			return ErrPublicAccessOwnershipConflict
		}
		body, tag, err := p.call(ctx, http.MethodGet, nil, "")
		if err != nil {
			return err
		}
		var current struct {
			ID      string            `json:"@id"`
			Handler string            `json:"handler"`
			Routes  []json.RawMessage `json:"routes"`
		}
		if decode(body, &current) != nil || current.ID != SubtreeID || current.Handler != "subroute" || current.Routes == nil {
			return ErrPublicAccessOwnershipConflict
		}
		seenIDs := map[string]bool{}
		for _, raw := range current.Routes {
			var item map[string]any
			if decode(raw, &item) != nil {
				return ErrPublicAccessOwnershipConflict
			}
			id, ok := item["@id"].(string)
			if !ok || seenIDs[id] {
				return ErrPublicAccessOwnershipConflict
			}
			seenIDs[id] = true
			normalized, _ := json.Marshal(item)
			if !bytes.Equal(normalized, owned[id]) {
				return ErrPublicAccessOwnershipConflict
			}
		}
		next := object{"@id": SubtreeID, "handler": "subroute", "routes": desired}
		raw, _ := json.Marshal(next)
		// Even an empty initial subtree must have an ETag. No unconditional write
		// is permitted if another writer changed this part of the configuration.
		if tag == "" {
			return ErrPublicAccessConflict
		}
		var currentObject map[string]any
		if decode(body, &currentObject) != nil {
			return ErrPublicAccessOwnershipConflict
		}
		normalizedCurrent, _ := json.Marshal(currentObject)
		if bytes.Equal(raw, normalizedCurrent) {
			return nil
		}
		if err := checkLock(); err != nil {
			return ErrPublicAccessConflict
		}
		_, _, err = p.call(ctx, http.MethodPatch, raw, tag)
		return err
	})
	if err != nil {
		if errors.Is(err, ErrPublicAccessOwnershipConflict) || errors.Is(err, ErrPublicAccessConflict) {
			return err
		}
		return ErrPublicAccessUnavailable
	}
	return nil
}
func (p *Provider) call(ctx context.Context, method string, body []byte, tag string) ([]byte, string, error) {
	if p.adminSocketPath != "" {
		current, err := verifyAdminUnixSocket(p.adminSocketPath, p.adminSocketUID, p.adminSocketGID)
		if err != nil || !os.SameFile(p.adminSocketInfo, current) {
			return nil, "", ErrPublicAccessUnavailable
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, method, AdminURL+"/id/"+SubtreeID, bytes.NewReader(body))
	if err != nil {
		return nil, "", ErrPublicAccessUnavailable
	}
	request.Header.Set("Content-Type", "application/json")
	if tag != "" {
		request.Header.Set("If-Match", tag)
	}
	response, err := p.client.Do(request)
	if err != nil {
		return nil, "", ErrPublicAccessUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusPreconditionFailed {
		return nil, "", ErrPublicAccessConflict
	}
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return nil, "", ErrPublicAccessUnavailable
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	if err != nil || len(raw) > 1<<20 {
		return nil, "", ErrPublicAccessUnavailable
	}
	return raw, response.Header.Get("ETag"), nil
}

func decode(raw []byte, target any) error {
	if len(raw) > 1<<20 {
		return errPolicy
	}
	scan := json.NewDecoder(bytes.NewReader(raw))
	if scanValue(scan, 0) != nil {
		return errPolicy
	}
	var extra any
	if scan.Decode(&extra) != io.EOF {
		return errPolicy
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	if decoder.Decode(target) != nil {
		return errPolicy
	}
	return nil
}
func scanValue(d *json.Decoder, depth int) error {
	if depth > 64 {
		return errPolicy
	}
	v, e := d.Token()
	if e != nil {
		return e
	}
	delim, ok := v.(json.Delim)
	if !ok {
		return nil
	}
	seen := map[string]bool{}
	for d.More() {
		if delim == '{' {
			k, e := d.Token()
			if e != nil {
				return e
			}
			s, ok := k.(string)
			if !ok || seen[s] {
				return errPolicy
			}
			seen[s] = true
		}
		if scanValue(d, depth+1) != nil {
			return errPolicy
		}
	}
	_, e = d.Token()
	return e
}
