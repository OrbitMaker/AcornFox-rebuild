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
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/open-card/open-card/internal/application"
	"github.com/open-card/open-card/internal/contracts"
)

var errPolicy = errors.New("invalid AcornFox public route policy")

// RouteState contains an already persisted, owned route, including disabled
// records needed to prove ownership when removing a prior Caddy projection.
type RouteState struct {
	Intent  contracts.AcornFoxPublicRouteIntent
	Enabled bool
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
	Source         Source
}
type Provider struct {
	root   string
	source Source
	client *http.Client
	mu     sync.Mutex
}

func New(c Config) (*Provider, error) {
	root, err := AuthorizedRoot("https://" + c.AuthorizedRoot)
	if err != nil || root != c.AuthorizedRoot || c.Source == nil {
		return nil, errPolicy
	}
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 2 * time.Second}).DialContext, ResponseHeaderTimeout: 3 * time.Second, MaxResponseHeaderBytes: 8192}, CheckRedirect: func(*http.Request, []*http.Request) error { return errPolicy }}
	return &Provider{root: root, source: c.Source, client: client}, nil
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
	switch i.Port {
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
	return p.project(ctx, &i, true, key)
}
func (p *Provider) RemoveAcornFoxPublicRoute(ctx context.Context, i contracts.AcornFoxPublicRouteIntent, key string) error {
	return p.project(ctx, &i, false, key)
}
func (p *Provider) Reconcile(ctx context.Context) error { return p.project(ctx, nil, false, "") }

func (p *Provider) project(ctx context.Context, requested *contracts.AcornFoxPublicRouteIntent, enabled bool, key string) error {
	if ctx == nil || ctx.Err() != nil {
		return application.ErrAcornFoxPublicAccessUnavailable
	}
	if requested != nil && (strings.TrimSpace(key) == "" || ValidateIntent(p.root, *requested) != nil) {
		return application.ErrAcornFoxPublicAccessOwnershipConflict
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	p.mu.Lock()
	defer p.mu.Unlock()
	if ctx.Err() != nil {
		return application.ErrAcornFoxPublicAccessUnavailable
	}
	err := p.source.WithRoutes(ctx, func(states []RouteState, checkLock func() error) error {
		if checkLock == nil {
			return application.ErrAcornFoxPublicAccessConflict
		}
		if len(states) > 1024 {
			return application.ErrAcornFoxPublicAccessUnavailable
		}
		owned := map[string][]byte{}
		desired := []object{}
		seen := map[string]bool{}
		found := requested == nil
		states = append([]RouteState(nil), states...)
		sort.Slice(states, func(i, j int) bool { return states[i].Intent.Hostname < states[j].Intent.Hostname })
		for _, state := range states {
			i := state.Intent
			if ValidateIntent(p.root, i) != nil || seen[i.Hostname] {
				return application.ErrAcornFoxPublicAccessOwnershipConflict
			}
			seen[i.Hostname] = true
			item := route(i)
			raw, _ := json.Marshal(item)
			owned[item["@id"].(string)] = raw
			if state.Enabled {
				desired = append(desired, item)
			}
			if requested != nil && i == *requested && state.Enabled == enabled {
				found = true
			}
		}
		if !found {
			return application.ErrAcornFoxPublicAccessOwnershipConflict
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
			return application.ErrAcornFoxPublicAccessOwnershipConflict
		}
		seenIDs := map[string]bool{}
		for _, raw := range current.Routes {
			var item map[string]any
			if decode(raw, &item) != nil {
				return application.ErrAcornFoxPublicAccessOwnershipConflict
			}
			id, ok := item["@id"].(string)
			if !ok || seenIDs[id] {
				return application.ErrAcornFoxPublicAccessOwnershipConflict
			}
			seenIDs[id] = true
			normalized, _ := json.Marshal(item)
			if !bytes.Equal(normalized, owned[id]) {
				return application.ErrAcornFoxPublicAccessOwnershipConflict
			}
		}
		next := object{"@id": SubtreeID, "handler": "subroute", "routes": desired}
		raw, _ := json.Marshal(next)
		// Even an empty initial subtree must have an ETag. No unconditional write
		// is permitted if another writer changed this part of the configuration.
		if tag == "" {
			return application.ErrAcornFoxPublicAccessConflict
		}
		var currentObject map[string]any
		if decode(body, &currentObject) != nil {
			return application.ErrAcornFoxPublicAccessOwnershipConflict
		}
		normalizedCurrent, _ := json.Marshal(currentObject)
		if bytes.Equal(raw, normalizedCurrent) {
			return nil
		}
		if err := checkLock(); err != nil {
			return application.ErrAcornFoxPublicAccessConflict
		}
		_, _, err = p.call(ctx, http.MethodPatch, raw, tag)
		return err
	})
	if err != nil {
		if errors.Is(err, application.ErrAcornFoxPublicAccessOwnershipConflict) || errors.Is(err, application.ErrAcornFoxPublicAccessConflict) {
			return err
		}
		return application.ErrAcornFoxPublicAccessUnavailable
	}
	return nil
}
func (p *Provider) call(ctx context.Context, method string, body []byte, tag string) ([]byte, string, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, method, AdminURL+"/id/"+SubtreeID, bytes.NewReader(body))
	if err != nil {
		return nil, "", application.ErrAcornFoxPublicAccessUnavailable
	}
	request.Header.Set("Content-Type", "application/json")
	if tag != "" {
		request.Header.Set("If-Match", tag)
	}
	response, err := p.client.Do(request)
	if err != nil {
		return nil, "", application.ErrAcornFoxPublicAccessUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusPreconditionFailed {
		return nil, "", application.ErrAcornFoxPublicAccessConflict
	}
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return nil, "", application.ErrAcornFoxPublicAccessUnavailable
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	if err != nil || len(raw) > 1<<20 {
		return nil, "", application.ErrAcornFoxPublicAccessUnavailable
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
