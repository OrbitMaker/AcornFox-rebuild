package apiserver

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/acornfox/acornfox/internal/runner"
	"github.com/acornfox/acornfox/internal/state"
)

// fakeStore is an in-memory Store for tests. It implements only the behavior
// the API server relies on, matching the contract in state/types.go.
type fakeStore struct {
	mu          sync.Mutex
	apps        map[string]state.App
	deployments map[string]*state.Deployment
	order       []string // deployment IDs in insertion order
	seq         map[string]int
	env         map[string]map[string]state.EnvVar
	volumes     map[string][]state.Volume
	events      map[string][]state.Event
	nextPort    int
	nextEventID int64

	// N3 console + domains.
	tokens   map[string]time.Time // token digest -> expiry
	sessions map[string]*fakeSession
	domains  map[string]state.Domain // name -> domain
	clock    func() time.Time
}

// fakeSession mirrors the stored session, keyed by session secret digest.
type fakeSession struct {
	id         string
	secret     string
	csrfDigest string
	created    time.Time
	lastSeen   time.Time
	idle       time.Time
	absolute   time.Time
	revoked    bool
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		apps:        map[string]state.App{},
		deployments: map[string]*state.Deployment{},
		seq:         map[string]int{},
		env:         map[string]map[string]state.EnvVar{},
		volumes:     map[string][]state.Volume{},
		events:      map[string][]state.Event{},
		nextPort:    18810,
		tokens:      map[string]time.Time{},
		sessions:    map[string]*fakeSession{},
		domains:     map[string]state.Domain{},
	}
}

func (f *fakeStore) now() time.Time {
	if f.clock != nil {
		return f.clock().UTC()
	}
	return time.Now().UTC()
}

func (f *fakeStore) EnsureApp(_ context.Context, name string) (state.App, bool, error) {
	if !state.ValidAppName(name) {
		return state.App{}, false, state.ErrInvalid
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if a, ok := f.apps[name]; ok {
		return a, false, nil
	}
	now := time.Now().UTC()
	a := state.App{
		Name:       name,
		Desired:    state.DesiredRunning,
		HealthPath: state.DefaultHealthPath,
		PublicPort: f.nextPort,
		MemoryMB:   state.DefaultMemoryMB,
		CPUMilli:   state.DefaultCPUMilli,
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	f.nextPort++
	f.apps[name] = a
	return a, true, nil
}

func (f *fakeStore) GetApp(_ context.Context, name string) (state.App, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	a, ok := f.apps[name]
	if !ok {
		return state.App{}, state.ErrNotFound
	}
	return a, nil
}

func (f *fakeStore) ListApps(_ context.Context) ([]state.App, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]state.App, 0, len(f.apps))
	for _, a := range f.apps {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (f *fakeStore) UpdateApp(_ context.Context, name string, fn func(*state.App) error) (state.App, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	a, ok := f.apps[name]
	if !ok {
		return state.App{}, state.ErrNotFound
	}
	cp := a
	if err := fn(&cp); err != nil {
		return state.App{}, err
	}
	// Name/CreatedAt/PublicPort are immutable.
	cp.Name = a.Name
	cp.CreatedAt = a.CreatedAt
	cp.PublicPort = a.PublicPort
	cp.UpdatedAt = time.Now().UTC()
	f.apps[name] = cp
	return cp, nil
}

func randID() string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func (f *fakeStore) CreateDeployment(_ context.Context, in state.NewDeployment) (state.Deployment, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	// Duplicate by request key.
	if in.RequestKey != "" {
		for _, id := range f.order {
			d := f.deployments[id]
			if d.App == in.App && d.RequestKey == in.RequestKey {
				return *d, false, nil
			}
		}
	}
	// Duplicate by digest of the newest pending-or-live deployment.
	for i := len(f.order) - 1; i >= 0; i-- {
		d := f.deployments[f.order[i]]
		if d.App != in.App {
			continue
		}
		if state.IsPending(d.Status) || d.Status == state.StatusLive {
			if d.SourceDigest == in.SourceDigest {
				return *d, false, nil
			}
			break
		}
	}

	f.seq[in.App]++
	now := time.Now().UTC()
	d := &state.Deployment{
		ID:           randID(),
		App:          in.App,
		Seq:          f.seq[in.App],
		SourceKind:   in.SourceKind,
		SourceRef:    in.SourceRef,
		SourceDigest: in.SourceDigest,
		RequestKey:   in.RequestKey,
		Status:       state.StatusQueued,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	f.deployments[d.ID] = d
	f.order = append(f.order, d.ID)
	return *d, true, nil
}

func (f *fakeStore) GetDeployment(_ context.Context, id string) (state.Deployment, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	d, ok := f.deployments[id]
	if !ok {
		return state.Deployment{}, state.ErrNotFound
	}
	return *d, nil
}

func (f *fakeStore) ListDeployments(_ context.Context, app string, limit int) ([]state.Deployment, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []state.Deployment{}
	for i := len(f.order) - 1; i >= 0; i-- {
		d := f.deployments[f.order[i]]
		if d.App == app {
			out = append(out, *d)
			if limit > 0 && len(out) >= limit {
				break
			}
		}
	}
	return out, nil
}

func (f *fakeStore) UpdateDeployment(_ context.Context, id string, fn func(*state.Deployment) error) (state.Deployment, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	d, ok := f.deployments[id]
	if !ok {
		return state.Deployment{}, state.ErrNotFound
	}
	cp := *d
	if err := fn(&cp); err != nil {
		return state.Deployment{}, err
	}
	cp.UpdatedAt = time.Now().UTC()
	f.deployments[id] = &cp
	return cp, nil
}

func (f *fakeStore) SetEnv(_ context.Context, v state.EnvVar) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.env[v.App] == nil {
		f.env[v.App] = map[string]state.EnvVar{}
	}
	f.env[v.App][v.Key] = v
	return nil
}

func (f *fakeStore) DeleteEnv(_ context.Context, app, key string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.env[app] != nil {
		delete(f.env[app], key)
	}
	return nil
}

func (f *fakeStore) ListEnv(_ context.Context, app string) ([]state.EnvVar, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []state.EnvVar{}
	for _, v := range f.env[app] {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}

func (f *fakeStore) AddVolume(_ context.Context, app, path string, auto bool) (state.Volume, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, v := range f.volumes[app] {
		if v.Path == path {
			return v, false, nil
		}
	}
	n := len(f.volumes[app]) + 1
	v := state.Volume{
		App:        app,
		Path:       path,
		VolumeName: "af-" + app + "-" + itoa(n),
		Auto:       auto,
		CreatedAt:  time.Now().UTC(),
	}
	f.volumes[app] = append(f.volumes[app], v)
	return v, true, nil
}

func (f *fakeStore) ListVolumes(_ context.Context, app string) ([]state.Volume, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]state.Volume, len(f.volumes[app]))
	copy(out, f.volumes[app])
	return out, nil
}

func (f *fakeStore) AddEvent(_ context.Context, e state.Event) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nextEventID++
	e.ID = f.nextEventID
	f.events[e.DeploymentID] = append(f.events[e.DeploymentID], e)
	return nil
}

func (f *fakeStore) ListEvents(_ context.Context, app, deploymentID string, afterID int64, limit int) ([]state.Event, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []state.Event{}
	for _, e := range f.events[deploymentID] {
		if e.ID > afterID {
			out = append(out, e)
		}
	}
	return out, nil
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// fakeKicker records kicks.
type fakeKicker struct {
	mu    sync.Mutex
	kicks []string
}

func (k *fakeKicker) Kick(app string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.kicks = append(k.kicks, app)
}

// fakeRunner is a configurable read-only runner.
type fakeRunner struct {
	pingErr    error
	pingResp   runner.PingResponse
	listErr    error
	containers map[string][]runner.ContainerInfo
	logLines   map[string][]string // keyed by container name
	logsErr    error
}

func newFakeRunner() *fakeRunner {
	return &fakeRunner{
		pingResp:   runner.PingResponse{ServerVersion: "27.0.0", DockerAPIVersion: "1.47"},
		containers: map[string][]runner.ContainerInfo{},
		logLines:   map[string][]string{},
	}
}

func (r *fakeRunner) Ping(_ context.Context) (runner.PingResponse, error) {
	if r.pingErr != nil {
		return runner.PingResponse{}, r.pingErr
	}
	return r.pingResp, nil
}

func (r *fakeRunner) ListContainers(_ context.Context, app string) ([]runner.ContainerInfo, error) {
	if r.listErr != nil {
		return nil, r.listErr
	}
	return r.containers[app], nil
}

func (r *fakeRunner) Logs(_ context.Context, _, name string, _ int) ([]string, error) {
	if r.logsErr != nil {
		return nil, r.logsErr
	}
	return r.logLines[name], nil
}

var errRunnerDown = errors.New("runner down")

// -------- N3 console + domains (fake) --------

func (f *fakeStore) CreateConsoleToken(_ context.Context) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	token := randID() + randID() // 24 hex; enough for tests
	f.tokens[token] = f.now().Add(state.ConsoleTokenTTL)
	return token, nil
}

func (f *fakeStore) RedeemConsoleToken(_ context.Context, token string) (state.ConsoleSession, string, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	expiry, ok := f.tokens[token]
	if !ok {
		return state.ConsoleSession{}, "", "", state.ErrNotFound
	}
	delete(f.tokens, token) // single use
	now := f.now()
	if !now.Before(expiry) {
		return state.ConsoleSession{}, "", "", state.ErrNotFound
	}
	secret := randID() + randID()
	csrf := state.ConsoleCSRFToken(secret)
	fs := &fakeSession{
		id:         randID() + randID()[:4],
		secret:     secret,
		csrfDigest: state.CSRFDigest(csrf),
		created:    now,
		lastSeen:   now,
		idle:       now.Add(state.ConsoleSessionIdle),
		absolute:   now.Add(state.ConsoleSessionAbsolute),
	}
	f.sessions[secret] = fs
	return f.sessionView(fs), secret, csrf, nil
}

func (f *fakeStore) TouchConsoleSession(_ context.Context, secret string) (state.ConsoleSession, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fs, ok := f.sessions[secret]
	if !ok {
		return state.ConsoleSession{}, state.ErrNotFound
	}
	now := f.now()
	if fs.revoked || !now.Before(fs.idle) || !now.Before(fs.absolute) {
		return state.ConsoleSession{}, state.ErrNotFound
	}
	fs.lastSeen = now
	fs.idle = now.Add(state.ConsoleSessionIdle)
	if fs.idle.After(fs.absolute) {
		fs.idle = fs.absolute
	}
	return f.sessionView(fs), nil
}

func (f *fakeStore) RevokeConsoleSession(_ context.Context, secret string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if fs, ok := f.sessions[secret]; ok {
		fs.revoked = true
	}
	return nil
}

func (f *fakeStore) sessionView(fs *fakeSession) state.ConsoleSession {
	return state.ConsoleSession{
		ID:              fs.id,
		CSRFDigest:      fs.csrfDigest,
		CreatedAt:       fs.created,
		LastSeenAt:      fs.lastSeen,
		IdleExpiresAt:   fs.idle,
		AbsoluteExpires: fs.absolute,
	}
}

func (f *fakeStore) AddDomain(_ context.Context, app, name string) (state.Domain, bool, error) {
	if !state.ValidDomainName(name) {
		return state.Domain{}, false, state.ErrInvalid
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.apps[app]; !ok {
		return state.Domain{}, false, state.ErrNotFound
	}
	if d, ok := f.domains[name]; ok {
		if d.App != app {
			return state.Domain{}, false, state.ErrConflict
		}
		return d, false, nil
	}
	d := state.Domain{App: app, Name: name, Status: state.DomainPending, CreatedAt: f.now()}
	f.domains[name] = d
	return d, true, nil
}

func (f *fakeStore) RemoveDomain(_ context.Context, app, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	d, ok := f.domains[name]
	if !ok {
		return nil
	}
	if d.App != app {
		return state.ErrNotFound
	}
	delete(f.domains, name)
	return nil
}

func (f *fakeStore) ListDomains(_ context.Context, app string) ([]state.Domain, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []state.Domain{}
	for _, d := range f.domains {
		if app == "" || d.App == app {
			out = append(out, d)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// fakeHostProvider returns a fixed host view.
type fakeHostProvider struct{ view apiserverHostView }

// apiserverHostView aliases HostView so tests can build one without importing.
type apiserverHostView = HostView

func (p fakeHostProvider) Host(_ context.Context) HostView { return p.view }

// fakeResolver returns fixed addresses (or an error) for LookupIPAddr.
type fakeResolver struct {
	addrs map[string][]net.IPAddr
	err   error
}

func (r fakeResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	if r.err != nil {
		return nil, r.err
	}
	return r.addrs[host], nil
}
