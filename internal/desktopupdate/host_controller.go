package desktopupdate

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

var ErrHostSuppressed = errors.New("desktopupdate: candidate is suppressed pending explicit retry")
var ErrHostPending = errors.New("desktopupdate: an update needs reconciliation")

type BackendObservation struct {
	LocalLoopback    bool
	MigrationVersion string
	Architecture     string
	InstanceID       string
	Binding          string
	Ready            bool
	Finalized        bool
	AttemptState     string
}
type HostUpgradeIntent struct{ InstanceID, AttemptID, FromBinding, ToBinding, ArtifactSHA256 string }

// EnsureUpgrade is an idempotent transport operation keyed by AttemptID, not a
// second backend transaction. Observe must distinguish absent/running/terminal.
type BackendExecutor interface {
	Observe(context.Context, string) (BackendObservation, error)
	EnsureUpgrade(context.Context, HostUpgradeIntent, *VerifiedHostBundle) error
}
type HostRuntime interface {
	CollectInactive(context.Context, []string) error // verified slot inventories only; idempotent, preserves unknown data
	DiscardPrepared(context.Context, string) error   // exact inactive artifact only; never the active slot
	CurrentSlot(context.Context) (string, error)
	Prepare(context.Context, *VerifiedHostBundle, string) error // validates old/new runtime compatibility before backend work
	Activate(context.Context, string, string, string) error     // attempt, exact old slot, exact new slot; idempotent
	Probe(context.Context, string, string) error                // slot and freshly observed backend binding
}
type HostPolicy struct {
	PublicKey                   ed25519.PublicKey
	IndexURL, OS, Arch, Channel string
	AllowedHosts                []string
	MaxArtifactSize             int64
}
type HostControllerOptions struct {
	Root, InstanceID string
	Initial          HostInstallation
	Policy           *HostPolicy
	Backend          BackendExecutor
	Runtime          HostRuntime
	Now              func() time.Time
	HTTPClient       *http.Client
	DownloadTimeout  time.Duration
}
type HostController struct {
	options        HostControllerOptions
	fault          func(string) error
	diskSpaceCheck func(string) (uint64, error)
}
type HostUpdateStatus struct {
	State    string
	Snapshot *HostSnapshot `json:"-"`
}

func NewHostController(o HostControllerOptions) (*HostController, error) {
	if o.Policy != nil {
		p := *o.Policy
		p.PublicKey = append(ed25519.PublicKey(nil), p.PublicKey...)
		p.AllowedHosts = append([]string(nil), p.AllowedHosts...)
		o.Policy = &p
		if len(p.PublicKey) != ed25519.PublicKeySize || validateArtifactURL(p.IndexURL, p.AllowedHosts) != nil {
			return nil, ErrInvalidOptions
		}
		if _, _, e := CanonicalizePlatform(p.OS, p.Arch); e != nil {
			return nil, e
		}
		if p.Channel != "stable" && p.Channel != "beta" {
			return nil, ErrInvalidOptions
		}
	}
	if o.Policy != nil && (o.Backend == nil || o.Runtime == nil || !o.Initial.valid() || validateSHA256(o.InstanceID) != nil) {
		return nil, ErrInvalidOptions
	}
	if o.Now == nil {
		o.Now = func() time.Time { return time.Now().UTC() }
	}
	return &HostController{options: o}, nil
}
func (c *HostController) policySHA() string { return hostSHA(hostBytes(c.options.Policy)) }
func (c *HostController) indexOptions(s HostSnapshot, now time.Time) CheckUpdateOptions {
	p := c.options.Policy
	return CheckUpdateOptions{PublicKey: p.PublicKey, TargetOS: p.OS, TargetArch: p.Arch, AllowedChannel: p.Channel, CurrentSequence: s.Installed.AppliedSequence, CurrentVersion: s.Installed.Version, CurrentTime: now, AllowedHosts: p.AllowedHosts, MaxArtifactSize: p.MaxArtifactSize}
}
func (c *HostController) open(ctx context.Context) (*hostStore, HostSnapshot, error) {
	if ctx == nil {
		return nil, HostSnapshot{}, ErrInvalidOptions
	}
	if e := ctx.Err(); e != nil {
		return nil, HostSnapshot{}, e
	}
	s, e := openHostStore(ctx, c.options.Root, c.fault)
	if e != nil {
		return nil, HostSnapshot{}, e
	}
	state, e := s.load()
	if errors.Is(e, os.ErrNotExist) {
		if !c.options.Initial.valid() || validateSHA256(c.options.InstanceID) != nil || c.options.Backend == nil || c.options.Runtime == nil {
			s.close()
			return nil, state, ErrInvalidOptions
		}
		slot, err := c.options.Runtime.CurrentSlot(ctx)
		if err != nil || slot != c.options.Initial.SlotSHA256 {
			s.close()
			return nil, state, ErrHostConflict
		}
		obs, err := c.options.Backend.Observe(ctx, "")
		if err != nil || !obs.LocalLoopback || obs.MigrationVersion != "0040" || obs.Architecture != c.options.Policy.Arch || obs.InstanceID != c.options.InstanceID || obs.Binding != c.options.Initial.BackendBinding || !obs.Ready || !obs.Finalized {
			s.close()
			return nil, state, ErrHostConflict
		}
		state = HostSnapshot{SchemaVersion: 1, PolicySHA256: c.policySHA(), InstanceID: c.options.InstanceID, Installed: c.options.Initial, Outcome: "idle", Catalog: HostCatalogFloor{Sequence: c.options.Initial.AppliedSequence}}
		if state.Catalog.Sequence > 0 {
			s.close()
			return nil, state, ErrInvalidOptions
		} // provisioned bootstrap has no invented feed sequence
		e = s.save(&state)
	}
	if e != nil || state.PolicySHA256 != c.policySHA() || state.InstanceID != c.options.InstanceID {
		s.close()
		if e == nil {
			e = ErrHostConflict
		}
		return nil, state, e
	}
	return s, state, nil
}
func hostStatus(s HostSnapshot) HostUpdateStatus {
	state := s.Outcome
	if len(s.Cleanup) > 0 || s.CollectSlots {
		state = "cleanup-required"
	}
	if s.Pending != nil {
		state = s.Pending.Phase
	}
	return HostUpdateStatus{state, &s}
}
func (c *HostController) Status(ctx context.Context) (HostUpdateStatus, error) {
	if c.options.Policy == nil {
		return HostUpdateStatus{State: "not-configured"}, nil
	}
	s, state, e := c.open(ctx)
	if e != nil {
		return HostUpdateStatus{}, e
	}
	defer s.close()
	return hostStatus(state), nil
}
func payloadDigest(envelope []byte) (string, error) {
	var e IndexEnvelope
	if strictDecodeEnvelopeJSON(envelope, &e) != nil {
		return "", ErrInvalidEnvelope
	}
	raw, err := base64.StdEncoding.DecodeString(e.Payload)
	if err != nil {
		return "", err
	}
	return hostSHA(raw), nil
}

// Select durably binds the one accepted offer before any download or execution.
func (c *HostController) Select(ctx context.Context, envelope []byte, retryFailed bool) (HostUpdateStatus, error) {
	if c.options.Policy == nil {
		return HostUpdateStatus{State: "not-configured"}, nil
	}
	s, state, e := c.open(ctx)
	if e != nil {
		return HostUpdateStatus{}, e
	}
	defer s.close()
	if len(state.Cleanup) > 0 || state.CollectSlots {
		if e := c.collect(ctx, s, &state); e != nil {
			return hostStatus(state), e
		}
	}
	if state.Pending != nil {
		return hostStatus(state), ErrHostPending
	}
	result, e := VerifyAndSelectUpdate(envelope, c.indexOptions(state, c.options.Now()))
	if e != nil && !errors.Is(e, ErrNoUpdate) {
		return hostStatus(state), e
	}
	if result == nil {
		return hostStatus(state), ErrHostConflict
	}
	digest, e2 := payloadDigest(envelope)
	if e2 != nil {
		return hostStatus(state), e2
	}
	if result.Sequence < state.Catalog.Sequence || result.Sequence == state.Catalog.Sequence && digest != state.Catalog.PayloadSHA256 {
		return hostStatus(state), ErrSequenceRollback
	}
	state.Catalog = HostCatalogFloor{result.Sequence, digest}
	if errors.Is(e, ErrNoUpdate) {
		e = s.save(&state)
		return hostStatus(state), e
	}
	if result.Artifact == nil || validateSHA256(result.Artifact.BackendBinding) != nil {
		return hostStatus(state), ErrHostConflict
	}
	if !retryFailed {
		for _, f := range state.Failures {
			if f.Kind == "host" && f.CandidateSHA256 == result.Artifact.SHA256 || f.Kind == "backend" && f.CandidateSHA256 == result.Artifact.BackendBinding && f.FromBinding == state.Installed.BackendBinding {
				if e := s.save(&state); e != nil {
					return hostStatus(state), e
				}
				return hostStatus(state), ErrHostSuppressed
			}
		}
	}
	knownFailure := false
	for _, f := range state.Failures {
		if f.Kind == "host" && f.CandidateSHA256 == result.Artifact.SHA256 || f.Kind == "backend" && f.CandidateSHA256 == result.Artifact.BackendBinding && f.FromBinding == state.Installed.BackendBinding {
			knownFailure = true
		}
	}
	if len(state.Failures) >= 64 && (!retryFailed || !knownFailure) {
		if e := s.save(&state); e != nil {
			return hostStatus(state), e
		}
		return hostStatus(state), ErrHostSuppressed
	}
	random := make([]byte, 32)
	if _, e := io.ReadFull(rand.Reader, random); e != nil {
		return hostStatus(state), e
	}
	state.Pending = &HostPending{ID: hostSHA(random), Phase: "selected", Envelope: append([]byte(nil), envelope...), AcceptedAt: c.options.Now().UTC(), Candidate: *result, Previous: state.Installed}
	e = s.save(&state)
	return hostStatus(state), e
}
func (c *HostController) verifyPending(state HostSnapshot, fresh bool) (CandidateResult, error) {
	p := state.Pending
	if p == nil {
		return CandidateResult{}, ErrHostConflict
	}
	baseline := state
	baseline.Installed = p.Previous
	now := p.AcceptedAt
	if fresh {
		now = c.options.Now()
	}
	got, e := VerifyAndSelectUpdate(p.Envelope, c.indexOptions(baseline, now))
	if e != nil || got == nil {
		return CandidateResult{}, ErrHostConflict
	}
	digest, e := payloadDigest(p.Envelope)
	if e != nil || digest != state.Catalog.PayloadSHA256 || got.Sequence != state.Catalog.Sequence || !equalHostCandidate(*got, p.Candidate) {
		return CandidateResult{}, ErrHostConflict
	}
	return *got, nil
}
func equalHostCandidate(a, b CandidateResult) bool {
	return string(hostBytes(a)) == string(hostBytes(b))
}
func (c *HostController) download(ctx context.Context, s *hostStore, state *HostSnapshot) error {
	p := state.Pending
	if _, e := os.Lstat(s.stagePath(p.ID)); errors.Is(e, os.ErrNotExist) && p.StageIdentity != "" {
		p.StageIdentity = ""
		if e := s.save(state); e != nil {
			return e
		}
	}
	key, e := s.stageDirectory(p.ID)
	if e != nil {
		return e
	}
	dir := s.stagePath(p.ID)
	children, e := os.ReadDir(dir)
	if e != nil {
		return e
	}
	if p.StageIdentity == "" {
		if len(children) != 0 {
			return ErrHostConflict
		}
		p.StageIdentity = key
		if e = s.save(state); e != nil {
			return e
		}
	} else if p.StageIdentity != key {
		return ErrHostConflict
	}
	root, e := os.OpenRoot(dir)
	if e != nil {
		return e
	}
	defer root.Close()
	for _, child := range children {
		if child.Name() != StagePayloadFileName && child.Name() != StageTempFileName {
			return ErrHostConflict
		}
	}
	// A completed payload must have its exact signed identity. An incomplete
	// download.tmp is disposable only inside this recorded transaction directory.
	if info, e := root.Lstat(StagePayloadFileName); e == nil {
		if !info.Mode().IsRegular() {
			return ErrHostConflict
		}
		f, e := root.Open(StagePayloadFileName)
		if e != nil {
			return e
		}
		defer f.Close()
		if temp, e := root.Lstat(StageTempFileName); e == nil {
			if !os.SameFile(info, temp) || verifyHostPayloadLinks(f, filepath.Join(dir, StagePayloadFileName), *p.Candidate.Artifact, 2) != nil {
				return ErrHostConflict
			}
			if e := root.Remove(StageTempFileName); e != nil {
				return e
			}
			if e := hostSyncDirectory(dir); e != nil {
				return e
			}
		} else if !errors.Is(e, os.ErrNotExist) {
			return e
		} // Only the exact, fully hashed two-name publication can be reconciled.
		if e := verifyHostPayload(f, filepath.Join(dir, StagePayloadFileName), *p.Candidate.Artifact); e != nil {
			return e
		}
		p.Phase = "staged"
		return s.save(state)
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	if info, e := root.Lstat(StageTempFileName); e == nil {
		f, e := root.Open(StageTempFileName)
		if e != nil {
			return e
		}
		e = hostCheckFile(f, filepath.Join(dir, StageTempFileName))
		f.Close()
		if e != nil || info.Size() > p.Candidate.Artifact.Size+1 {
			return ErrHostConflict
		}
		if e = root.Remove(StageTempFileName); e != nil {
			return e
		}
		if e = hostSyncDirectory(dir); e != nil {
			return e
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	baseline := *state
	baseline.Installed = p.Previous
	_, _, e = StageVerifiedUpdate(ctx, p.Envelope, DownloadStagingOptions{IndexOptions: c.indexOptions(baseline, c.options.Now()), ParentDir: s.path, HTTPClient: c.options.HTTPClient, Timeout: c.options.DownloadTimeout, DiskSpaceCheck: c.diskSpaceCheck, hostStageName: s.stageName(p.ID), hostStageIdentity: p.StageIdentity})
	if e != nil {
		if _, statErr := os.Lstat(dir); errors.Is(statErr, os.ErrNotExist) {
			p.StageIdentity = ""
			_ = s.save(state)
		}
		return e
	}
	p.Phase = "staged"
	return s.save(state)
}

// Advance performs bounded work. Running/unknown backend jobs remain pending;
// neither repeated calls nor reboot can choose another candidate or bypass it.
func (c *HostController) Advance(ctx context.Context) (HostUpdateStatus, error) {
	if c.options.Policy == nil {
		return HostUpdateStatus{State: "not-configured"}, nil
	}
	s, state, e := c.open(ctx)
	if e != nil {
		return HostUpdateStatus{}, e
	}
	defer s.close()
	if state.Pending == nil {
		if len(state.Cleanup) > 0 || state.CollectSlots {
			e = c.collect(ctx, s, &state)
		}
		return hostStatus(state), e
	}
	p := state.Pending
	if p.Phase == "discarding" {
		e = c.discard(ctx, s, &state)
		return hostStatus(state), e
	}
	fresh := p.Phase == "selected" || p.Phase == "staged" || p.Phase == "host_prepared"
	candidate, e := c.verifyPending(state, fresh)
	if e != nil {
		return hostStatus(state), e
	}
	if p.Phase == "selected" {
		if e = c.download(ctx, s, &state); e != nil {
			return hostStatus(state), e
		}
		p = state.Pending
	}
	key, e := hostDirectoryKey(s.stagePath(p.ID))
	if e != nil || key != p.StageIdentity {
		return hostStatus(state), ErrHostConflict
	}
	bundle, e := verifyHostBundle(ctx, filepath.Join(s.stagePath(p.ID), StagePayloadFileName), candidate)
	if e != nil {
		return hostStatus(state), e
	}
	closeBundle := func() error {
		if bundle == nil {
			return nil
		}
		e := bundle.Close()
		bundle = nil
		return e
	}
	defer closeBundle()
	bundle.envelope = append([]byte(nil), p.Envelope...)
	m := bundle.manifest
	target := m.Backend.ToBinding
	nextSlot := bundle.SHA256()
	oldSlot := p.Previous.SlotSHA256
	if m.Backend.FromBinding != p.Previous.BackendBinding && target != p.Previous.BackendBinding {
		return hostStatus(state), ErrHostConflict
	}
	savePhase := func(phase string) error { p.Phase = phase; return s.save(&state) }
	if p.Phase == "staged" {
		if e = c.options.Runtime.Prepare(ctx, bundle, oldSlot); e != nil {
			return hostStatus(state), e
		}
		if e = savePhase("host_prepared"); e != nil {
			return hostStatus(state), e
		}
	}
	if p.Phase == "host_prepared" {
		if _, e = c.verifyPending(state, true); e != nil {
			return hostStatus(state), e
		}
		if e = savePhase("backend_applying"); e != nil {
			return hostStatus(state), e
		}
	}
	if p.Phase == "backend_applying" {
		obs, e := c.options.Backend.Observe(ctx, p.ID)
		if e != nil {
			return hostStatus(state), e
		}
		if !c.validObservation(state, obs) {
			return hostStatus(state), ErrHostConflict
		}
		if obs.Binding == target && obs.Ready && obs.Finalized && (obs.AttemptState == "upgraded" || obs.AttemptState == "absent") {
			state.Installed.BackendBinding = target
			if e = savePhase("backend_confirmed"); e != nil {
				return hostStatus(state), e
			}
		} else if obs.AttemptState == "rolled-back" && obs.Binding == p.Previous.BackendBinding && obs.Ready && obs.Finalized {
			if e := closeBundle(); e != nil {
				return hostStatus(state), e
			}
			return c.finishFailure(ctx, s, &state, "backend", target, "rolled-back")
		} else if obs.AttemptState == "rejected" && target != p.Previous.BackendBinding && obs.Binding == p.Previous.BackendBinding && obs.Ready && obs.Finalized {
			if e := closeBundle(); e != nil {
				return hostStatus(state), e
			}
			return c.finishFailure(ctx, s, &state, "backend", target, "rejected")
		} else if obs.AttemptState == "absent" && obs.Binding == p.Previous.BackendBinding && obs.Ready && obs.Finalized {
			if e = s.step("backend-before-ensure"); e != nil {
				return hostStatus(state), e
			}
			e = c.options.Backend.EnsureUpgrade(ctx, HostUpgradeIntent{state.InstanceID, p.ID, p.Previous.BackendBinding, target, nextSlot}, bundle)
			return hostStatus(state), e
		} else if obs.AttemptState == "running" || obs.AttemptState == "unknown" {
			return hostStatus(state), ErrHostPending
		} else {
			return hostStatus(state), ErrHostConflict
		}
	}
	// No later phase reads archive bytes. Release this verification handle
	// before success/failure cleanup: Windows cannot delete an open payload.
	// collect independently reopens and verifies its exact hash/size/identity.
	if e := closeBundle(); e != nil {
		return hostStatus(state), e
	}
	// A durable backend confirmation authorizes only host reconciliation. During
	// native handoff the same VM may be stopped; requiring a live backend before
	// starting either host slot would deadlock recovery. Fresh evidence is still
	// mandatory after the selected runtime has started and before final commit.
	if state.Installed.BackendBinding != target {
		return hostStatus(state), ErrHostConflict
	}
	if p.Phase == "backend_confirmed" {
		if e = savePhase("host_switch"); e != nil {
			return hostStatus(state), e
		}
	}
	slot, e := c.options.Runtime.CurrentSlot(ctx)
	if e != nil || slot != oldSlot && slot != nextSlot {
		return hostStatus(state), ErrHostConflict
	}
	if p.Phase == "host_switch" {
		if slot == oldSlot {
			if e = c.options.Runtime.Activate(ctx, p.ID, oldSlot, nextSlot); e != nil {
				current, inspectErr := c.options.Runtime.CurrentSlot(ctx)
				if inspectErr != nil || current != oldSlot && current != nextSlot {
					return hostStatus(state), ErrHostConflict
				}
				if e = savePhase("host_rollback"); e != nil {
					return hostStatus(state), e
				}
			}
		}
		if p.Phase == "host_switch" {
			if e = savePhase("host_trial"); e != nil {
				return hostStatus(state), e
			}
		}
	}
	if p.Phase == "host_trial" {
		slot, e = c.options.Runtime.CurrentSlot(ctx)
		if e != nil || slot != nextSlot {
			return hostStatus(state), ErrHostConflict
		}
		if e = c.options.Runtime.Probe(ctx, nextSlot, target); e != nil {
			if e = savePhase("host_rollback"); e != nil {
				return hostStatus(state), e
			}
		} else {
			if e := c.confirmBackend(ctx, state, target); e != nil {
				return hostStatus(state), e
			}
			state.PreviousSlot = oldSlot
			state.CollectSlots = true
			state.Installed = HostInstallation{Version: candidate.Version, SlotSHA256: nextSlot, BackendBinding: target, AppliedSequence: candidate.Sequence}
			kept := state.Failures[:0]
			for _, f := range state.Failures {
				if f.Kind == "backend" && f.FromBinding == target {
					kept = append(kept, f)
				}
			}
			state.Failures = kept
			state.Cleanup = []HostStageCleanup{{p.ID, p.StageIdentity, p.Candidate.Artifact.SHA256, p.Candidate.Artifact.Size}}
			state.Pending = nil
			state.Outcome = "updated"
			e = s.save(&state)
			if e == nil {
				e = c.collect(ctx, s, &state)
			}
			return hostStatus(state), e
		}
	}
	if p.Phase == "host_rollback" {
		slot, e = c.options.Runtime.CurrentSlot(ctx)
		if e != nil {
			return hostStatus(state), e
		}
		if slot == nextSlot {
			if e = c.options.Runtime.Activate(ctx, p.ID, nextSlot, oldSlot); e != nil {
				return hostStatus(state), e
			}
		} else if slot != oldSlot {
			return hostStatus(state), ErrHostConflict
		}
		if e = c.options.Runtime.Probe(ctx, oldSlot, target); e != nil {
			return hostStatus(state), e
		}
		if e := c.confirmBackend(ctx, state, target); e != nil {
			return hostStatus(state), e
		}
		return c.finishFailure(ctx, s, &state, "host", nextSlot, "rolled-back")
	}
	return hostStatus(state), ErrHostConflict
}
func (c *HostController) finishFailure(ctx context.Context, s *hostStore, state *HostSnapshot, kind, key, reason string) (HostUpdateStatus, error) {
	found := false
	for _, f := range state.Failures {
		if f.Kind == kind && f.CandidateSHA256 == key && f.FromBinding == state.Pending.Previous.BackendBinding {
			found = true
		}
	}
	if !found {
		if len(state.Failures) >= 64 {
			return hostStatus(*state), ErrHostSuppressed
		}
		state.Failures = append(state.Failures, HostFailure{kind, key, state.Pending.Previous.BackendBinding, reason})
	}
	p := state.Pending
	state.CollectSlots = true
	state.Cleanup = []HostStageCleanup{{p.ID, p.StageIdentity, p.Candidate.Artifact.SHA256, p.Candidate.Artifact.Size}}
	state.Pending = nil
	state.Outcome = kind + "-" + reason
	e := s.save(state)
	if e == nil {
		e = c.collect(ctx, s, state)
	}
	return hostStatus(*state), e
}

func (c *HostController) collect(ctx context.Context, s *hostStore, state *HostSnapshot) error {
	for _, g := range state.Cleanup {
		dir := s.stagePath(g.ID)
		key, e := hostDirectoryKey(dir)
		if errors.Is(e, os.ErrNotExist) {
			continue
		}
		if e != nil {
			if _, se := os.Lstat(dir); errors.Is(se, os.ErrNotExist) {
				continue
			}
			return e
		}
		if key != g.Identity {
			return ErrHostConflict
		}
		children, e := os.ReadDir(dir)
		if e != nil {
			return e
		}
		if len(children) > 1 || len(children) == 1 && children[0].Name() != StagePayloadFileName {
			return ErrHostConflict
		}
		if len(children) == 1 {
			p := filepath.Join(dir, StagePayloadFileName)
			f, e := os.Open(p)
			if e != nil {
				return e
			}
			e = verifyHostPayload(f, p, Artifact{SHA256: g.SHA256, Size: g.Size})
			f.Close()
			if e != nil {
				return e
			}
			root, e := os.OpenRoot(dir)
			if e != nil {
				return e
			}
			e = root.Remove(StagePayloadFileName)
			root.Close()
			if e != nil {
				return e
			}
			if e = s.step("stage-collected"); e != nil {
				return e
			}
		}
		if e = s.root.Remove(s.stageName(g.ID)); e != nil {
			return e
		}
		if e = hostSyncDirectory(s.path); e != nil {
			return e
		}
	}
	if state.CollectSlots {
		keep := []string{state.Installed.SlotSHA256}
		if state.PreviousSlot != "" {
			keep = append(keep, state.PreviousSlot)
		}
		if e := c.options.Runtime.CollectInactive(ctx, keep); e != nil {
			return e
		}
		state.CollectSlots = false
	}
	state.Cleanup = nil
	return s.save(state)
}

// Dismiss explicitly abandons only a pre-backend offer. It never cancels or
// guesses the outcome of an already-authorized backend job.
func (c *HostController) Dismiss(ctx context.Context) (HostUpdateStatus, error) {
	if c.options.Policy == nil {
		return HostUpdateStatus{State: "not-configured"}, nil
	}
	s, state, e := c.open(ctx)
	if e != nil {
		return HostUpdateStatus{}, e
	}
	defer s.close()
	if state.Pending == nil {
		return hostStatus(state), nil
	}
	p := state.Pending
	if p.Phase != "selected" && p.Phase != "staged" && p.Phase != "host_prepared" && p.Phase != "discarding" {
		return hostStatus(state), ErrHostPending
	}
	if _, e := c.verifyPending(state, false); e != nil {
		return hostStatus(state), e
	}
	if p.Phase != "discarding" {
		p.DiscardPrepared = p.Phase != "selected"
		p.Phase = "discarding"
		if e = s.save(&state); e != nil {
			return hostStatus(state), e
		}
	}
	e = c.discard(ctx, s, &state)
	return hostStatus(state), e
}
func (c *HostController) discard(ctx context.Context, s *hostStore, state *HostSnapshot) error {
	p := state.Pending
	if p == nil || p.Phase != "discarding" {
		return ErrHostConflict
	}
	if _, e := c.verifyPending(*state, false); e != nil {
		return e
	}
	slot, e := c.options.Runtime.CurrentSlot(ctx)
	if e != nil || slot != p.Previous.SlotSHA256 {
		return ErrHostConflict
	}
	obs, e := c.options.Backend.Observe(ctx, p.ID)
	if e != nil || obs.InstanceID != state.InstanceID || obs.Binding != p.Previous.BackendBinding || obs.AttemptState != "absent" || !obs.Ready || !obs.Finalized {
		return ErrHostConflict
	}
	dir := s.stagePath(p.ID)
	info, e := os.Lstat(dir)
	if e == nil {
		key, e := hostDirectoryKey(dir)
		if e != nil {
			return e
		}
		children, e := os.ReadDir(dir)
		if e != nil {
			return e
		}
		if p.StageIdentity == "" {
			if len(children) != 0 {
				return ErrHostConflict
			}
		} else if key != p.StageIdentity {
			return ErrHostConflict
		}
		for _, child := range children {
			if child.Name() != StageTempFileName && child.Name() != StagePayloadFileName {
				return ErrHostConflict
			}
		}
		if len(children) > 2 {
			return ErrHostConflict
		}
		// Validate the entire disposable set before deleting a byte.
		for _, child := range children {
			fp := filepath.Join(dir, child.Name())
			f, e := os.Open(fp)
			if e != nil {
				return e
			}
			links := uint64(1)
			if len(children) == 2 {
				a, _ := os.Lstat(filepath.Join(dir, StageTempFileName))
				b, _ := os.Lstat(filepath.Join(dir, StagePayloadFileName))
				if a == nil || b == nil || !os.SameFile(a, b) {
					f.Close()
					return ErrHostConflict
				}
				links = 2
			}
			if child.Name() == StagePayloadFileName {
				e = verifyHostPayloadLinks(f, fp, *p.Candidate.Artifact, links)
			} else {
				e = hostCheckLinkedFile(f, fp, links)
				fi, se := f.Stat()
				if se != nil || fi.Size() > p.Candidate.Artifact.Size+1 {
					e = ErrHostConflict
				}
			}
			f.Close()
			if e != nil {
				return e
			}
		}
		if p.DiscardPrepared {
			if e := c.options.Runtime.DiscardPrepared(ctx, p.Candidate.Artifact.SHA256); e != nil {
				return e
			}
		}
		root, e := os.OpenRoot(dir)
		if e != nil {
			return e
		}
		for _, name := range []string{StageTempFileName, StagePayloadFileName} {
			if e := root.Remove(name); e != nil && !errors.Is(e, os.ErrNotExist) {
				root.Close()
				return e
			}
		}
		root.Close()
		if !info.IsDir() {
			return ErrHostConflict
		}
		if e = s.root.Remove(s.stageName(p.ID)); e != nil {
			return e
		}
		if e = hostSyncDirectory(s.path); e != nil {
			return e
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	} else if p.DiscardPrepared {
		if e := c.options.Runtime.DiscardPrepared(ctx, p.Candidate.Artifact.SHA256); e != nil {
			return e
		}
	}
	state.Pending = nil
	state.Outcome = "idle"
	return s.save(state)
}

func (c *HostController) validObservation(s HostSnapshot, o BackendObservation) bool {
	return o.LocalLoopback && o.InstanceID == s.InstanceID && o.Architecture == c.options.Policy.Arch && o.MigrationVersion == "0040" && validateSHA256(o.Binding) == nil
}
func (c *HostController) confirmBackend(ctx context.Context, s HostSnapshot, target string) error {
	o, e := c.options.Backend.Observe(ctx, s.Pending.ID)
	if e != nil {
		return e
	}
	if !c.validObservation(s, o) || o.Binding != target || !o.Ready || !o.Finalized || (o.AttemptState != "upgraded" && o.AttemptState != "absent") {
		return ErrHostConflict
	}
	return nil
}

// Machine/UI status deliberately excludes download URLs, signed envelopes and
// filesystem identities. The full snapshot belongs only in protected storage.
func (s HostUpdateStatus) MarshalJSON() ([]byte, error) {
	out := struct {
		State    string `json:"state"`
		Version  string `json:"version,omitempty"`
		Binding  string `json:"backend_binding,omitempty"`
		Applied  uint64 `json:"applied_sequence,omitempty"`
		Target   string `json:"target_version,omitempty"`
		Attempt  string `json:"attempt_id,omitempty"`
		Failures int    `json:"failed_candidates,omitempty"`
	}{State: s.State}
	if s.Snapshot != nil {
		out.Version = s.Snapshot.Installed.Version
		out.Binding = s.Snapshot.Installed.BackendBinding
		out.Applied = s.Snapshot.Installed.AppliedSequence
		out.Failures = len(s.Snapshot.Failures)
		if p := s.Snapshot.Pending; p != nil {
			out.Target = p.Candidate.Version
			out.Attempt = p.ID
		}
	}
	return hostBytes(out), nil
}
func (s HostUpdateStatus) Format(f fmt.State, _ rune) {
	fmt.Fprintf(f, "host update status %s [private snapshot redacted]", s.State)
}
func (HostPolicy) Format(f fmt.State, _ rune) { fmt.Fprint(f, "host update policy [redacted]") }
