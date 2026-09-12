//go:build linux

package desktopupdateguest

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/open-card/open-card/internal/desktopupdate"
	"github.com/open-card/open-card/internal/install"
)

const ExecutablePath = "/usr/local/libexec/acornfox-guest-update"
const PolicyPath = "/etc/acornfox-host/guest-update-policy.json"
const InstancePath = "/etc/acornfox-host/guest-instance.json"
const StatePath = "/var/lib/acornfox-host/guest-update"

type Policy struct {
	Schema          int      `json:"schema_version"`
	PublicKey       []byte   `json:"public_key"`
	HostOS          string   `json:"host_os"`
	HostArch        string   `json:"host_arch"`
	Channel         string   `json:"channel"`
	AllowedHosts    []string `json:"allowed_hosts"`
	MaxArtifactSize int64    `json:"max_artifact_size"`
}
type Instance struct {
	Schema               int    `json:"schema_version"`
	Kind                 string `json:"kind"`
	NativeID             string `json:"native_id"`
	InstanceID           string `json:"instance_id"`
	MarkerSHA256         string `json:"marker_sha256"`
	BootstrapHostVersion string `json:"bootstrap_host_version"`
}
type SubmitRequest struct {
	Intent      desktopupdate.HostUpgradeIntent `json:"intent"`
	Envelope    []byte                          `json:"envelope"`
	PayloadSize int64                           `json:"payload_size"`
}
type JobReceipt struct {
	Intent      desktopupdate.HostUpgradeIntent `json:"intent"`
	State       string                          `json:"state"`
	EnvelopeSHA string                          `json:"envelope_sha256"`
	AcceptedAt  time.Time                       `json:"accepted_at"`
	Sequence    uint64                          `json:"sequence"`
	Process     processIdentity                 `json:"process"`
	Reason      string                          `json:"reason,omitempty"`
}
type snapshot struct {
	Revision    uint64       `json:"revision"`
	PreviousSHA string       `json:"previous_sha256"`
	Schema      int          `json:"schema_version"`
	PolicySHA   string       `json:"policy_sha256"`
	InstanceSHA string       `json:"instance_sha256"`
	Floor       uint64       `json:"catalog_floor"`
	FloorSHA    string       `json:"catalog_payload_sha256"`
	Jobs        []JobReceipt `json:"jobs"`
	GC          *gcIntent    `json:"gc,omitempty"`
}
type processIdentity struct {
	PID   int    `json:"pid"`
	Group int    `json:"group"`
	Boot  string `json:"boot"`
	Start string `json:"start"`
}
type systemPaths struct{ anchor, policy, instance, state, executable, marker string }
type backend interface {
	Observe(context.Context) (desktopupdate.BackendObservation, error)
	Upgrade(context.Context, string, string, desktopupdate.HostUpgradeIntent) error
	Recover(context.Context) error
}
type Executor struct {
	paths    systemPaths
	policy   Policy
	instance Instance
	backend  backend
	now      func() time.Time
	spawn    func(string) error
	fault    func(string)
}

// Open has no caller-selected trust, executable, instance or filesystem paths.
// Production provisioning is separate; a missing policy does not create one.
func Open() (*Executor, error) {
	if os.Geteuid() != 0 {
		return nil, ErrConflict
	}
	p := systemPaths{"/", PolicyPath, InstancePath, StatePath, ExecutablePath, "/var/lib/acornfox-desktop/owner-marker"}
	x, e := open(p)
	if e != nil {
		return nil, e
	}
	x.backend = productionBackend{x: x}
	x.spawn = x.detach
	return x, nil
}
func open(p systemPaths) (*Executor, error) {
	x := &Executor{paths: p, now: func() time.Time { return time.Now().UTC() }}
	raw, e := readSafe(p.anchor, p.policy, 0600, 65536)
	if errors.Is(e, os.ErrNotExist) {
		return nil, ErrNotConfigured
	}
	if e != nil {
		return nil, e
	}
	if decode(raw, &x.policy) != nil || x.policy.Schema != 1 || len(x.policy.PublicKey) != ed25519.PublicKeySize || x.policy.MaxArtifactSize < 1 || x.policy.MaxArtifactSize > desktopupdate.MaxArtifactSizeBytes || len(x.policy.AllowedHosts) == 0 {
		return nil, ErrConflict
	}
	if _, _, e = desktopupdate.CanonicalizePlatform(x.policy.HostOS, x.policy.HostArch); e != nil || x.policy.HostArch != runtime.GOARCH || (x.policy.Channel != "stable" && x.policy.Channel != "beta") {
		return nil, ErrConflict
	}
	raw, e = readSafe(p.anchor, p.instance, 0600, 65536)
	if e != nil {
		return nil, e
	}
	if decode(raw, &x.instance) != nil || x.instance.Schema != 1 || !hexID.MatchString(x.instance.InstanceID) || !hexID.MatchString(x.instance.MarkerSHA256) {
		return nil, ErrConflict
	}
	if _, e := desktopupdate.ParseSemver(x.instance.BootstrapHostVersion); e != nil {
		return nil, ErrConflict
	}
	if e := x.verifyInstance(); e != nil {
		return nil, e
	}
	if e := checkParents(p.anchor, p.state); e != nil {
		return nil, e
	}
	return x, nil
}
func (x *Executor) verifyInstance() error {
	marker := x.paths.marker
	if x.instance.Kind == "linux-local" {
		marker = filepath.Join(filepath.Dir(x.paths.instance), "linux-owner-marker")
	}
	raw, e := readSafe(x.paths.anchor, marker, 0600, 65536)
	if e != nil || digest(raw) != x.instance.MarkerSHA256 {
		return ErrConflict
	}
	switch x.instance.Kind {
	case "mac-managed":
		var m struct {
			Product  string `json:"product"`
			Instance string `json:"instance"`
		}
		if !macID.MatchString(x.instance.NativeID) || jsonMarker(raw, &m) != nil || m.Product != "acornfox" || m.Instance != x.instance.NativeID || x.policy.HostOS != "darwin" {
			return ErrConflict
		}
	case "wsl-managed":
		var m struct {
			Product  string `json:"product"`
			HostUUID string `json:"host_uuid"`
		}
		if !windowsID.MatchString(x.instance.NativeID) || jsonMarker(raw, &m) != nil || m.Product != "acornfox" || m.HostUUID != x.instance.NativeID || x.policy.HostOS != "windows" {
			return ErrConflict
		}
	case "linux-local":
		var m struct {
			Product  string `json:"product"`
			Instance string `json:"instance"`
		}
		if !hexID.MatchString(x.instance.NativeID) || jsonMarker(raw, &m) != nil || m.Product != "acornfox" || m.Instance != x.instance.NativeID || x.policy.HostOS != "linux" {
			return ErrConflict
		}
	default:
		return ErrConflict
	}
	if x.instance.InstanceID != digest([]byte(x.instance.Kind+":"+x.instance.NativeID)) {
		return ErrConflict
	}
	return nil
}
func (x *Executor) options(now time.Time) desktopupdate.CheckUpdateOptions {
	return desktopupdate.CheckUpdateOptions{PublicKey: x.policy.PublicKey, TargetOS: x.policy.HostOS, TargetArch: x.policy.HostArch, AllowedChannel: x.policy.Channel, CurrentVersion: x.instance.BootstrapHostVersion, CurrentTime: now, AllowedHosts: x.policy.AllowedHosts, MaxArtifactSize: x.policy.MaxArtifactSize}
}
func (x *Executor) jobDir(id string) string { return filepath.Join(x.paths.state, "job-"+id) }
func (x *Executor) Observe(ctx context.Context, id string) (desktopupdate.BackendObservation, error) {
	if e := x.verifyInstance(); e != nil {
		return desktopupdate.BackendObservation{}, e
	}
	lock, e := x.lock()
	if e != nil {
		return desktopupdate.BackendObservation{}, e
	}
	s, e := x.load()
	lock.Close()
	if e != nil {
		return desktopupdate.BackendObservation{}, e
	}
	obs, e := x.backend.Observe(ctx)
	if e != nil {
		return obs, e
	}
	obs.InstanceID = x.instance.InstanceID
	obs.AttemptState = "absent"
	if id != "" {
		if !hexID.MatchString(id) {
			return obs, ErrConflict
		}
		if i := jobIndex(s, id); i >= 0 {
			j := s.Jobs[i]
			obs.AttemptState = j.State
			if j.State == "queued" || j.State == "recovering" {
				obs.AttemptState = "running"
			}
			if (j.State == "running" || j.State == "recovering") && !processAlive(j.Process) {
				obs.AttemptState = "unknown"
			}
		} else if retired, e := x.readRetired(id); e == nil {
			obs.AttemptState = retired.State
		} else if !errors.Is(e, os.ErrNotExist) {
			return obs, e
		}
	}
	return obs, nil
}
func (x *Executor) Status(id string) (JobReceipt, error) {
	if !hexID.MatchString(id) {
		return JobReceipt{}, ErrConflict
	}
	lock, e := x.lock()
	if e != nil {
		return JobReceipt{}, e
	}
	defer lock.Close()
	s, e := x.load()
	if e != nil {
		return JobReceipt{}, e
	}
	i := jobIndex(s, id)
	if i < 0 {
		retired, e := x.readRetired(id)
		if errors.Is(e, os.ErrNotExist) {
			return JobReceipt{State: "absent"}, nil
		}
		if e != nil {
			return JobReceipt{}, e
		}
		return JobReceipt{Intent: desktopupdate.HostUpgradeIntent{AttemptID: id, InstanceID: x.instance.InstanceID}, State: retired.State, EnvelopeSHA: retired.EnvelopeSHA, Sequence: retired.Sequence}, nil
	}
	return s.Jobs[i], nil
}

// Submit receives bytes, never a privileged path or an unsigned receipt. The
// original signed index and complete payload are independently reverified here.
func (x *Executor) Submit(ctx context.Context, r SubmitRequest, payload io.Reader) (JobReceipt, error) {
	if ctx == nil || ctx.Err() != nil || !hexID.MatchString(r.Intent.AttemptID) || r.Intent.InstanceID != x.instance.InstanceID || !hexID.MatchString(r.Intent.ArtifactSHA256) || len(r.Envelope) > desktopupdate.MaxIndexEnvelopeBytes {
		return JobReceipt{}, ErrConflict
	}
	if e := x.verifyInstance(); e != nil {
		return JobReceipt{}, e
	}
	lock, e := x.lock()
	if e != nil {
		return JobReceipt{}, e
	}
	defer lock.Close()
	s, e := x.load()
	if e != nil {
		return JobReceipt{}, e
	}
	if i := jobIndex(s, r.Intent.AttemptID); i >= 0 {
		j := s.Jobs[i]
		if j.Intent != r.Intent || j.EnvelopeSHA != digest(r.Envelope) {
			return j, ErrConflict
		}
		if j.State == "queued" {
			lock.Close()
			if e := x.spawn(j.Intent.AttemptID); e != nil {
				return j, e
			}
		}
		return j, nil
	}
	if retired, e := x.readRetired(r.Intent.AttemptID); e == nil {
		if retired.IntentSHA != digest(encoded(r.Intent)) || retired.EnvelopeSHA != digest(r.Envelope) {
			return JobReceipt{}, ErrConflict
		}
		return JobReceipt{Intent: r.Intent, State: retired.State, EnvelopeSHA: retired.EnvelopeSHA, Sequence: retired.Sequence}, nil
	} else if !errors.Is(e, os.ErrNotExist) {
		return JobReceipt{}, e
	}
	if s, e = x.collect(ctx, s); e != nil {
		return JobReceipt{}, e
	}
	for _, j := range s.Jobs {
		if j.State == "queued" || j.State == "running" || j.State == "recovering" || j.State == "unknown" {
			return JobReceipt{}, ErrBusy
		}
	}
	if len(s.Jobs) >= 32 {
		return JobReceipt{}, ErrCapacity
	}
	entries, e := os.ReadDir(x.paths.state)
	if e != nil {
		return JobReceipt{}, e
	}
	jobDirectories := 0
	for _, entry := range entries {
		if entry.Name() == "lock" || entry.Name() == "state.json" || entry.Name() == "state-quarantine" || entry.Name() == "quarantine-owner.json" || entry.Name() == "retired" {
			continue
		}
		if !strings.HasPrefix(entry.Name(), "job-") || !hexID.MatchString(strings.TrimPrefix(entry.Name(), "job-")) || !entry.IsDir() {
			return JobReceipt{}, ErrConflict
		}
		jobDirectories++
	}
	// Interrupted/invalid uploads are quarantined too; they cannot consume
	// unbounded disk simply because they never became executable job receipts.
	if jobDirectories >= 32 {
		if _, e := os.Lstat(x.jobDir(r.Intent.AttemptID)); e != nil {
			return JobReceipt{}, ErrCapacity
		}
	}
	now := x.now()
	candidate, e := desktopupdate.VerifyAndSelectUpdate(r.Envelope, x.options(now))
	if e != nil {
		return JobReceipt{}, e
	}
	if candidate.Artifact == nil || candidate.Artifact.Size != r.PayloadSize || r.PayloadSize < 1 || candidate.Artifact.SHA256 != r.Intent.ArtifactSHA256 || candidate.Artifact.BackendBinding != r.Intent.ToBinding {
		return JobReceipt{}, ErrConflict
	}
	floorSHA, e := indexPayloadSHA(r.Envelope)
	if e != nil {
		return JobReceipt{}, e
	}
	if candidate.Sequence < s.Floor || candidate.Sequence == s.Floor && floorSHA != s.FloorSHA {
		return JobReceipt{}, desktopupdate.ErrSequenceRollback
	}
	obs, e := x.backend.Observe(ctx)
	if e != nil || !eligible(obs, x.policy.HostArch) || obs.Binding != r.Intent.FromBinding {
		return JobReceipt{}, ErrConflict
	}
	dir := x.jobDir(r.Intent.AttemptID)
	created := false
	if e := os.Mkdir(dir, 0700); e == nil {
		created = true
	} else if !errors.Is(e, os.ErrExist) {
		return JobReceipt{}, e
	}
	if created {
		f, e := os.OpenFile(filepath.Join(dir, "payload"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return JobReceipt{}, e
		}
		n, e := io.Copy(f, io.LimitReader(payload, r.PayloadSize+1))
		if e == nil {
			e = f.Sync()
		}
		ce := f.Close()
		if e != nil || ce != nil || n != r.PayloadSize {
			return JobReceipt{}, ErrConflict
		}
	} else {
		// Only an explicitly retried exact ID/envelope can reuse a complete
		// intake left before its queued receipt was committed. Never scan or
		// promote unknown directories, and independently rehash both streams.
		if e := checkParents(x.paths.anchor, dir); e != nil {
			return JobReceipt{}, e
		}
		entries, e := os.ReadDir(dir)
		if e != nil || len(entries) != 4 {
			return JobReceipt{}, ErrConflict
		}
		allowed := map[string]bool{"payload": true, "envelope.json": true, "candidate": true, "successor": true}
		for _, entry := range entries {
			if !allowed[entry.Name()] {
				return JobReceipt{}, ErrConflict
			}
		}
		stored, e := readSafe(x.paths.anchor, filepath.Join(dir, "envelope.json"), 0600, desktopupdate.MaxIndexEnvelopeBytes)
		if e != nil || !bytes.Equal(stored, r.Envelope) {
			return JobReceipt{}, ErrConflict
		}
		h := sha256.New()
		n, e := io.Copy(h, io.LimitReader(payload, r.PayloadSize+1))
		if e != nil || n != r.PayloadSize || hex.EncodeToString(h.Sum(nil)) != r.Intent.ArtifactSHA256 {
			return JobReceipt{}, ErrConflict
		}
	}
	b, e := desktopupdate.VerifyHostBundle(ctx, filepath.Join(dir, "payload"), r.Envelope, x.options(now))
	if e != nil {
		return JobReceipt{}, e
	}
	defer b.Close()
	m := b.Manifest()
	if m.Backend.Mode != "candidate" || m.Backend.FromBinding != r.Intent.FromBinding || m.Backend.ToBinding != r.Intent.ToBinding {
		return JobReceipt{}, ErrConflict
	}
	if created {
		if e := extractCandidate(b, dir); e != nil {
			return JobReceipt{}, e
		}
		if e := writeNew(filepath.Join(dir, "envelope.json"), r.Envelope, 0600); e != nil {
			return JobReceipt{}, e
		}
	} else if e := verifyExtracted(x, b, dir); e != nil {
		return JobReceipt{}, e
	}
	if e := syncDir(dir); e != nil {
		return JobReceipt{}, e
	}
	j := JobReceipt{Intent: r.Intent, State: "queued", EnvelopeSHA: digest(r.Envelope), AcceptedAt: now, Sequence: candidate.Sequence}
	s.Floor = candidate.Sequence
	s.FloorSHA = floorSHA
	s.Jobs = append(s.Jobs, j)
	if e := x.save(s); e != nil {
		return JobReceipt{}, e
	}
	lock.Close()
	if e := x.spawn(j.Intent.AttemptID); e != nil {
		return j, e
	}
	return j, nil
}
func eligible(o desktopupdate.BackendObservation, arch string) bool {
	return o.Ready && o.Finalized && o.LocalLoopback && o.Architecture == arch && o.MigrationVersion == "0040" && hexID.MatchString(o.Binding)
}

// Run is called only by the fixed detached worker. A queued job may execute
// upgrade once; any later invocation can only observe or use backend recovery.
func (x *Executor) Run(ctx context.Context, id string, recoverOnly bool) error {
	if ctx == nil || !hexID.MatchString(id) {
		return ErrConflict
	}
	lock, e := x.workerLock(ctx)
	if e != nil {
		return e
	}
	s, e := x.load()
	if e != nil {
		lock.Close()
		return e
	}
	i := jobIndex(s, id)
	if i < 0 {
		lock.Close()
		return ErrConflict
	}
	j := s.Jobs[i]
	if j.State == "upgraded" || j.State == "rolled-back" || j.State == "rejected" {
		lock.Close()
		return nil
	}
	recovering := j.State != "queued"
	if recovering && processAlive(j.Process) {
		lock.Close()
		return ErrBusy
	}
	if !recovering && recoverOnly {
		lock.Close()
		return ErrConflict
	}
	if e := x.verifyInstance(); e != nil {
		lock.Close()
		return e
	}
	envelope, e := readSafe(x.paths.anchor, filepath.Join(x.jobDir(id), "envelope.json"), 0600, desktopupdate.MaxIndexEnvelopeBytes)
	if e != nil || digest(envelope) != j.EnvelopeSHA {
		lock.Close()
		return ErrConflict
	}
	verificationTime := x.now()
	if recovering {
		verificationTime = j.AcceptedAt
	}
	b, e := desktopupdate.VerifyHostBundle(ctx, filepath.Join(x.jobDir(id), "payload"), envelope, x.options(verificationTime))
	if e != nil {
		if !recovering && errors.Is(e, desktopupdate.ErrExpired) {
			j.State = "rejected"
			j.Reason = "expired-before-start"
			s.Jobs[i] = j
			if saveErr := x.save(s); saveErr != nil {
				lock.Close()
				return saveErr
			}
		}
		lock.Close()
		return e
	}
	defer b.Close()
	m := b.Manifest()
	if b.SHA256() != j.Intent.ArtifactSHA256 || m.Backend.ToBinding != j.Intent.ToBinding || m.Backend.FromBinding != j.Intent.FromBinding {
		lock.Close()
		return ErrConflict
	}
	if e := verifyExtracted(x, b, x.jobDir(id)); e != nil {
		lock.Close()
		return e
	}
	if !recovering {
		obs, e := x.backend.Observe(ctx)
		if e != nil || !eligible(obs, x.policy.HostArch) || obs.Binding != j.Intent.FromBinding {
			lock.Close()
			return ErrConflict
		}
	}
	if !recovering {
		// Observe can wait for readiness; expiration must be checked again at
		// the last authorization boundary, immediately before durable intent.
		if _, checkErr := desktopupdate.VerifyAndSelectUpdate(envelope, x.options(x.now())); checkErr != nil {
			j.State = "rejected"
			j.Reason = "authorization-expired-or-changed"
			s.Jobs[i] = j
			if saveErr := x.save(s); saveErr != nil {
				lock.Close()
				return saveErr
			}
			lock.Close()
			return checkErr
		}
	}
	j.Process, e = currentProcess()
	if e != nil {
		lock.Close()
		return e
	}
	j.State = "running"
	if recovering {
		j.State = "recovering"
	}
	s.Jobs[i] = j
	if e = x.save(s); e != nil {
		lock.Close()
		return e
	}
	lock.Close()
	if recovering {
		e = x.backend.Recover(ctx)
	} else {
		e = x.backend.Upgrade(ctx, x.jobDir(id), m.Backend.HelperSHA256, j.Intent)
	}
	obs, observeErr := x.backend.Observe(ctx)
	j.State = "unknown"
	j.Reason = "backend-outcome-unknown"
	if observeErr == nil && eligible(obs, x.policy.HostArch) {
		if obs.Binding == j.Intent.ToBinding {
			j.State = "upgraded"
			j.Reason = ""
		} else if obs.Binding == j.Intent.FromBinding && errors.Is(e, install.ErrAcornFoxUpgradeRolledBack) {
			j.State = "rolled-back"
			j.Reason = "recovered-old"
			if !recovering && e == nil {
				j.State = "unknown"
				j.Reason = "backend-outcome-unknown"
			}
		}
	}
	lock, err := x.workerLock(ctx)
	if err != nil {
		return err
	}
	defer lock.Close()
	s, err = x.load()
	if err != nil {
		return err
	}
	i = jobIndex(s, id)
	if i < 0 || s.Jobs[i].Process != j.Process {
		return ErrConflict
	}
	s.Jobs[i] = j
	if err = x.save(s); err != nil {
		return err
	}
	if j.State == "unknown" {
		return ErrBusy
	}
	if x.fault != nil {
		x.fault("job-terminal-committed")
	}
	if s, err = x.load(); err != nil {
		return err
	}
	_, err = x.collect(ctx, s)
	return err
}
func (x *Executor) detach(id string) error {
	f, e := openSafe(x.paths.anchor, x.paths.executable, 0755)
	if e != nil {
		return e
	}
	defer f.Close()
	devnull, e := os.OpenFile("/dev/null", os.O_RDWR, 0)
	if e != nil {
		return e
	}
	defer devnull.Close()
	cmd := exec.Command("/proc/self/fd/3", "run", id)
	cmd.ExtraFiles = []*os.File{f}
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	cmd.Stdin = devnull
	cmd.Stdout = devnull
	cmd.Stderr = devnull
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if e := cmd.Start(); e != nil {
		return e
	}
	go func() { _ = cmd.Wait() }()
	return nil
}

// Read-only status polling must not cause a detached accepted worker to exit
// before it acquires the store lock. Wait only for that lock; a live competing
// worker for the same job is still rejected by the persisted process identity.
func (x *Executor) workerLock(ctx context.Context) (*os.File, error) {
	for {
		lock, e := x.lock()
		if !errors.Is(e, ErrBusy) {
			return lock, e
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}
