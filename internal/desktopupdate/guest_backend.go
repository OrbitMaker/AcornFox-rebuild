package desktopupdate

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"time"
)

var ErrGuestProtocol = errors.New("desktopupdate: invalid guest update protocol response")
var ErrGuestTransport = errors.New("desktopupdate: guest update transport interrupted")
var ErrGuestNotConfigured = errors.New("desktopupdate: guest update is not configured")
var ErrGuestCapacity = errors.New("desktopupdate: guest update retention is full")

type guestProcessRetainedError struct{}

func (guestProcessRetainedError) Error() string {
	return "desktopupdate: guest process termination retained"
}

func (guestProcessRetainedError) Unwrap() error {
	return ErrGuestTransport
}

var ErrGuestProcessRetained error = guestProcessRetainedError{}

const guestResponseLimit = 64 << 10

// GuestCommand can only be constructed by this adapter. A trusted native
// transport maps these fixed verbs to its provisioned executable/SSH/WSL entry;
// no request can provide an executable, shell fragment, trust key or destination.
type GuestCommand struct{ verb, attempt string }

func (c GuestCommand) Arguments() []string {
	if c.attempt == "" {
		return []string{c.verb}
	}
	return []string{c.verb, c.attempt}
}

// GuestTransport must stream stdin unchanged, capture stdout separately from
// stderr, honor ctx, and return only after its native child and all I/O finish.
// It must not retry commands itself. On failure its private error is redacted.
// The supplied streams are valid only during this callback; do not retain them.
type GuestTransport func(ctx context.Context, command GuestCommand, stdin io.Reader, stdout io.Writer) (exitCode int, err error)
type GuestBackendOptions struct {
	InstanceID, Architecture string
	Transport                GuestTransport
}
type GuestBackend struct{ options GuestBackendOptions }

var _ BackendExecutor = (*GuestBackend)(nil)

func NewGuestBackend(o GuestBackendOptions) (*GuestBackend, error) {
	if validateSHA256(o.InstanceID) != nil || (o.Architecture != "amd64" && o.Architecture != "arm64") || o.Transport == nil {
		return nil, ErrInvalidOptions
	}
	return &GuestBackend{options: o}, nil
}

type guestReply struct {
	OK     bool            `json:"ok"`
	Code   string          `json:"code"`
	Result json.RawMessage `json:"result,omitempty"`
}
type guestProcess struct {
	PID   int    `json:"pid"`
	Group int    `json:"group"`
	Boot  string `json:"boot"`
	Start string `json:"start"`
}

// Wire layout mirrors the root protocol, including its original exported intent
// fields. Importing the Linux-only root executor here would create a cycle.
type guestReceipt struct {
	Intent      HostUpgradeIntent `json:"intent"`
	State       string            `json:"state"`
	EnvelopeSHA string            `json:"envelope_sha256"`
	AcceptedAt  time.Time         `json:"accepted_at"`
	Sequence    uint64            `json:"sequence"`
	Process     guestProcess      `json:"process"`
	Reason      string            `json:"reason,omitempty"`
}
type guestSubmit struct {
	Intent      HostUpgradeIntent `json:"intent"`
	Envelope    []byte            `json:"envelope"`
	PayloadSize int64             `json:"payload_size"`
}
type guestExpected struct {
	intent      HostUpgradeIntent
	envelopeSHA string
	sequence    uint64
}

type guestOutput struct {
	buffer   bytes.Buffer
	overflow bool
}

func (w *guestOutput) Len() int      { return w.buffer.Len() }
func (w *guestOutput) Bytes() []byte { return w.buffer.Bytes() }

func (w *guestOutput) Write(p []byte) (int, error) {
	if len(p) > guestResponseLimit-w.Len() {
		w.overflow = true
		return 0, ErrGuestProtocol
	}
	return w.buffer.Write(p)
}
func guestDecode(raw []byte, value any) error {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || len(raw) > guestResponseLimit || hostJSON(raw, value) != nil || !bytes.Equal(raw, hostBytes(value)) {
		return ErrGuestProtocol
	}
	return nil
}
func (g *GuestBackend) call(ctx context.Context, verb, attempt string, input io.Reader, value any) error {
	if ctx == nil {
		return ErrInvalidOptions
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	switch verb {
	case "observe":
		if attempt != "" && validateSHA256(attempt) != nil {
			return ErrInvalidOptions
		}
	case "status", "recover":
		if validateSHA256(attempt) != nil {
			return ErrInvalidOptions
		}
	case "submit":
		if attempt != "" {
			return ErrInvalidOptions
		}
	default:
		return ErrInvalidOptions
	}
	if input == nil {
		input = bytes.NewReader(nil)
	}
	var output guestOutput
	exit, e := g.options.Transport(ctx, GuestCommand{verb, attempt}, input, &output)
	if errors.Is(e, ErrGuestProcessRetained) {
		return e
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if output.overflow {
		return ErrGuestProtocol
	}
	if e != nil {
		return ErrGuestTransport
	}
	var reply guestReply
	if guestDecode(output.Bytes(), &reply) != nil {
		return ErrGuestProtocol
	}
	if !reply.OK {
		switch reply.Code {
		case "not-configured":
			if exit == 0 {
				return ErrGuestNotConfigured
			}
		case "reconciliation-required":
			if exit == 1 {
				return ErrHostPending
			}
		case "retention-full":
			if exit == 1 {
				return ErrGuestCapacity
			}
		case "update-conflict":
			if exit == 1 {
				return ErrHostConflict
			}
		}
		return ErrGuestProtocol
	}
	if exit != 0 || reply.Code != "ok" || len(reply.Result) == 0 || bytes.Equal(reply.Result, []byte("null")) {
		return ErrGuestProtocol
	}
	return guestDecode(reply.Result, value)
}
func (g *GuestBackend) receipt(ctx context.Context, verb, attempt string) (guestReceipt, error) {
	var r guestReceipt
	e := g.call(ctx, verb, attempt, nil, &r)
	if e != nil {
		return r, e
	}
	if e = g.validateReceipt(r, attempt); e != nil {
		return guestReceipt{}, e
	}
	return r, nil
}
func (g *GuestBackend) validateReceipt(r guestReceipt, attempt string) error {
	if r.State == "absent" {
		if r != (guestReceipt{State: "absent"}) {
			return ErrGuestProtocol
		}
		return nil
	}
	if r.Intent.InstanceID != g.options.InstanceID || r.Intent.AttemptID != attempt || validateSHA256(r.Intent.FromBinding) != nil || validateSHA256(r.Intent.ToBinding) != nil || r.Intent.FromBinding == r.Intent.ToBinding || validateSHA256(r.Intent.ArtifactSHA256) != nil || validateSHA256(r.EnvelopeSHA) != nil || r.Sequence == 0 || r.AcceptedAt.IsZero() {
		return ErrGuestProtocol
	}
	switch r.State {
	case "queued", "running", "recovering", "unknown", "upgraded", "rolled-back", "rejected":
	default:
		return ErrGuestProtocol
	}
	switch r.Reason {
	case "", "expired-before-start", "authorization-expired-or-changed", "backend-outcome-unknown", "recovered-old":
	default:
		return ErrGuestProtocol
	}
	p := r.Process
	if p != (guestProcess{}) {
		if p.PID < 1 || p.Group < 1 || len(p.Boot) < 1 || len(p.Boot) > 128 || len(p.Start) < 1 || len(p.Start) > 32 {
			return ErrGuestProtocol
		}
		if _, e := strconv.ParseUint(p.Start, 10, 64); e != nil {
			return ErrGuestProtocol
		}
	}
	return nil
}
func (g *GuestBackend) expected(i HostUpgradeIntent, b *VerifiedHostBundle) (guestExpected, error) {
	if i.InstanceID != g.options.InstanceID || validateSHA256(i.AttemptID) != nil || validateSHA256(i.FromBinding) != nil || validateSHA256(i.ToBinding) != nil || i.FromBinding == i.ToBinding || validateSHA256(i.ArtifactSHA256) != nil || b == nil || b.payload == nil || b.SHA256() != i.ArtifactSHA256 {
		return guestExpected{}, ErrHostConflict
	}
	m := b.Manifest()
	if m.Backend.Mode != "candidate" || m.Backend.FromBinding != i.FromBinding || m.Backend.ToBinding != i.ToBinding || m.Backend.Architecture != g.options.Architecture || m.Backend.APIProtocol != 1 || verifyHostPayload(b.payload, b.payloadPath, b.artifact) != nil {
		return guestExpected{}, ErrHostConflict
	}
	envelope := b.SignedEnvelope()
	if len(envelope) == 0 || len(envelope) > MaxIndexEnvelopeBytes {
		return guestExpected{}, ErrHostConflict
	}
	var env IndexEnvelope
	if json.Unmarshal(envelope, &env) != nil {
		return guestExpected{}, ErrHostConflict
	}
	raw, e := base64.StdEncoding.DecodeString(env.Payload)
	if e != nil {
		return guestExpected{}, ErrHostConflict
	}
	var index IndexPayload
	if json.Unmarshal(raw, &index) != nil || index.Sequence == 0 {
		return guestExpected{}, ErrHostConflict
	}
	return guestExpected{i, hostSHA(envelope), index.Sequence}, nil
}
func (e guestExpected) match(r guestReceipt) error {
	if r.State == "absent" || r.Intent != e.intent || r.EnvelopeSHA != e.envelopeSHA || r.Sequence != e.sequence {
		return ErrGuestProtocol
	}
	return nil
}

// Observe never starts work or invents readiness. With an attempt, a separate
// status receipt binds the response to that exact root-owned attempt/instance.
// Compact retired receipts lacking a full intent fail closed; they are not fresh
// backend evidence and this adapter never reconstructs missing intent fields.
func (g *GuestBackend) Observe(ctx context.Context, attempt string) (BackendObservation, error) {
	// Status does not inspect the installation. Avoid taking its repository lock
	// while the accepted worker is preparing, applying, or recovering an update.
	if attempt != "" {
		r, e := g.receipt(ctx, "status", attempt)
		if e != nil {
			return BackendObservation{}, e
		}
		switch r.State {
		case "queued", "running", "recovering":
			return BackendObservation{}, ErrHostPending
		}
	}
	var obs BackendObservation
	if e := g.call(ctx, "observe", attempt, nil, &obs); e != nil {
		return BackendObservation{}, e
	}
	if obs.InstanceID != g.options.InstanceID || obs.Architecture != g.options.Architecture || !obs.LocalLoopback || obs.MigrationVersion != "0040" || validateSHA256(obs.Binding) != nil {
		return BackendObservation{}, ErrGuestProtocol
	}
	switch obs.AttemptState {
	case "absent", "running", "unknown", "upgraded", "rolled-back", "rejected":
	default:
		return BackendObservation{}, ErrGuestProtocol
	}
	if attempt == "" {
		if obs.AttemptState != "absent" {
			return BackendObservation{}, ErrGuestProtocol
		}
		return obs, nil
	}
	receipt, e := g.receipt(ctx, "status", attempt)
	if e != nil {
		return BackendObservation{}, e
	}
	if obs.AttemptState == "absent" {
		if receipt.State != "absent" {
			return BackendObservation{}, ErrHostPending
		}
		return obs, nil
	}
	if receipt.State == "absent" {
		return BackendObservation{}, ErrGuestProtocol
	}
	// A worker may advance between observe and status. Preserve a genuinely
	// observed running/unknown result instead of synthesizing terminal health.
	if obs.AttemptState == "running" || obs.AttemptState == "unknown" {
		return obs, nil
	}
	if receipt.State != obs.AttemptState {
		return BackendObservation{}, ErrGuestProtocol
	}
	binding := receipt.Intent.FromBinding
	if receipt.State == "upgraded" {
		binding = receipt.Intent.ToBinding
	}
	if obs.Binding != binding {
		return BackendObservation{}, ErrGuestProtocol
	}
	return obs, nil
}

// EnsureUpgrade accepts a durable root receipt, never interprets queued as a
// successful upgrade. A known exact receipt prevents resubmitting its payload.
func (g *GuestBackend) EnsureUpgrade(ctx context.Context, i HostUpgradeIntent, b *VerifiedHostBundle) error {
	expected, e := g.expected(i, b)
	if e != nil {
		return e
	}
	receipt, e := g.receipt(ctx, "status", i.AttemptID)
	if e != nil {
		return e
	}
	if receipt.State != "absent" {
		return expected.match(receipt)
	}
	header := hostBytes(guestSubmit{i, b.SignedEnvelope(), b.artifact.Size})
	reader, writer := io.Pipe()
	done := make(chan error, 1)
	go func() {
		_, e := writer.Write(append(header, '\n'))
		if e == nil {
			e = b.CopyPayload(writer)
		}
		writer.CloseWithError(e)
		done <- e
	}()
	var result guestReceipt
	e = g.call(ctx, "submit", "", reader, &result)
	// Stop a producer when the child disconnects or returns without consuming its
	// stdin. Always join it before returning so no file/pipe goroutine outlives us.
	reader.CloseWithError(ErrGuestTransport)
	streamErr := <-done
	if e != nil {
		return e
	}
	if streamErr != nil {
		return ErrGuestTransport
	}
	if e = g.validateReceipt(result, i.AttemptID); e != nil {
		return e
	}
	return expected.match(result)
}

// Resume explicitly wakes only a previously accepted matching attempt. It sends
// no new bundle and never calls EnsureUpgrade. nil means wake/terminal receipt
// accepted, not backend success: the driver must call Advance for fresh Observe.
// HostController.Advance intentionally returns ErrHostPending on "unknown";
// a future driver must choose this method explicitly and then retry Advance.
func (g *GuestBackend) Resume(ctx context.Context, i HostUpgradeIntent, b *VerifiedHostBundle) error {
	expected, e := g.expected(i, b)
	if e != nil {
		return e
	}
	receipt, e := g.receipt(ctx, "status", i.AttemptID)
	if e != nil {
		return e
	}
	if receipt.State == "absent" {
		return ErrHostPending
	}
	if e = expected.match(receipt); e != nil {
		return e
	}
	switch receipt.State {
	case "upgraded", "rolled-back", "rejected":
		return nil
	}
	result, e := g.receipt(ctx, "recover", i.AttemptID)
	if e != nil {
		return e
	}
	return expected.match(result)
}
