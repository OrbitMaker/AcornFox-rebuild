package desktopupdate

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type guestFixture struct {
	bundle            *VerifiedHostBundle
	payload, envelope []byte
	intent            HostUpgradeIntent
	receipt           guestReceipt
	observation       BackendObservation
}

func newGuestFixture(t *testing.T) guestFixture {
	t.Helper()
	payload, m := hostTestBundle(t, "1.1.0", strings.Repeat("a", 64))
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Date(2026, 9, 12, 0, 0, 0, 0, time.UTC)
	envelope := createTestEnvelope(t, key, IndexPayload{Channel: "stable", Sequence: 7, Version: m.Version, ExpiresAt: "2026-10-01T00:00:00Z", Artifacts: []Artifact{{OS: "linux", Arch: "amd64", URL: "https://downloads.example.com/bundle", SHA256: hostSHA(payload), Size: int64(len(payload)), BackendBinding: m.Backend.ToBinding}}})
	root, e := filepath.EvalSymlinks(createTestParentDir(t))
	if e != nil {
		t.Fatal(e)
	}
	file := filepath.Join(root, "payload")
	if e = os.WriteFile(file, payload, 0600); e != nil {
		t.Fatal(e)
	}
	b, e := VerifyHostBundle(context.Background(), file, envelope, CheckUpdateOptions{PublicKey: pub, TargetOS: "linux", TargetArch: "amd64", AllowedChannel: "stable", CurrentVersion: "1.0.0", CurrentTime: now, AllowedHosts: []string{"downloads.example.com"}})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { b.Close() })
	i := HostUpgradeIntent{strings.Repeat("e", 64), strings.Repeat("f", 64), m.Backend.FromBinding, m.Backend.ToBinding, b.SHA256()}
	r := guestReceipt{Intent: i, State: "queued", EnvelopeSHA: hostSHA(envelope), AcceptedAt: now, Sequence: 7}
	obs := BackendObservation{LocalLoopback: true, MigrationVersion: "0040", Architecture: "amd64", InstanceID: i.InstanceID, Binding: i.FromBinding, Ready: true, Finalized: true, AttemptState: "absent"}
	return guestFixture{b, payload, envelope, i, r, obs}
}
func guestWrite(out io.Writer, v any) (int, error) {
	_, e := out.Write(append(hostBytes(guestReply{true, "ok", hostBytes(v)}), '\n'))
	return 0, e
}
func guestAdapter(t *testing.T, f guestFixture, transport GuestTransport) *GuestBackend {
	t.Helper()
	g, e := NewGuestBackend(GuestBackendOptions{f.intent.InstanceID, "amd64", transport})
	if e != nil {
		t.Fatal(e)
	}
	return g
}
func TestGuestBackendOriginalPayloadAndIdempotentReceipt(t *testing.T) {
	f := newGuestFixture(t)
	accepted := false
	var verbs []string
	g := guestAdapter(t, f, func(_ context.Context, c GuestCommand, in io.Reader, out io.Writer) (int, error) {
		args := c.Arguments()
		verbs = append(verbs, args[0])
		switch args[0] {
		case "status":
			if len(args) != 2 || args[1] != f.intent.AttemptID {
				t.Fatal("wrong status target")
			}
			input, e := io.ReadAll(in)
			if e != nil || len(input) != 0 {
				t.Fatal("status stdin")
			}
			if accepted {
				return guestWrite(out, f.receipt)
			}
			return guestWrite(out, guestReceipt{State: "absent"})
		case "submit":
			if len(args) != 1 {
				t.Fatal("submit arguments")
			}
			raw, e := io.ReadAll(io.LimitReader(in, 2<<20))
			if e != nil {
				t.Fatal(e)
			}
			parts := bytes.SplitN(raw, []byte{'\n'}, 2)
			if len(parts) != 2 {
				t.Fatal("missing separator")
			}
			var request guestSubmit
			if guestDecode(parts[0], &request) != nil || request.Intent != f.intent || !bytes.Equal(request.Envelope, f.envelope) || request.PayloadSize != int64(len(f.payload)) || !bytes.Equal(parts[1], f.payload) {
				t.Fatal("changed signed protocol or payload")
			}
			accepted = true
			return guestWrite(out, f.receipt)
		default:
			t.Fatal("unexpected command", args)
			return 1, nil
		}
	})
	if e := g.EnsureUpgrade(context.Background(), f.intent, f.bundle); e != nil {
		t.Fatal(e)
	}
	if e := g.EnsureUpgrade(context.Background(), f.intent, f.bundle); e != nil {
		t.Fatal(e)
	}
	if strings.Join(verbs, ",") != "status,submit,status" {
		t.Fatal("duplicate submission", verbs)
	}
}
func TestGuestBackendObserveDoesNotResumeOrInventReadiness(t *testing.T) {
	for _, state := range []string{"absent", "running", "unknown", "upgraded", "rolled-back", "rejected"} {
		t.Run(state, func(t *testing.T) {
			f := newGuestFixture(t)
			obs := f.observation
			obs.AttemptState = state
			obs.Ready = false
			obs.Finalized = false
			r := f.receipt
			r.State = state
			if state == "upgraded" {
				obs.Binding = f.intent.ToBinding
			}
			var verbs []string
			g := guestAdapter(t, f, func(_ context.Context, c GuestCommand, in io.Reader, out io.Writer) (int, error) {
				args := c.Arguments()
				verbs = append(verbs, args[0])
				switch args[0] {
				case "observe":
					return guestWrite(out, obs)
				case "status":
					if state == "absent" {
						return guestWrite(out, guestReceipt{State: "absent"})
					}
					return guestWrite(out, r)
				default:
					t.Fatal("Observe mutated root", args)
					return 1, nil
				}
			})
			got, e := g.Observe(context.Background(), f.intent.AttemptID)
			if e != nil {
				t.Fatal(e)
			}
			if got != obs || strings.Join(verbs, ",") != "observe,status" {
				t.Fatal("observation changed", got, verbs)
			}
		})
	}
}
func TestGuestBackendResumeIsSeparateAndExact(t *testing.T) {
	for _, state := range []string{"absent", "queued", "running", "recovering", "unknown", "upgraded", "rolled-back", "rejected"} {
		t.Run(state, func(t *testing.T) {
			f := newGuestFixture(t)
			r := f.receipt
			r.State = state
			var verbs []string
			g := guestAdapter(t, f, func(_ context.Context, c GuestCommand, _ io.Reader, out io.Writer) (int, error) {
				args := c.Arguments()
				verbs = append(verbs, args[0])
				if len(args) != 2 || args[1] != f.intent.AttemptID || (args[0] != "status" && args[0] != "recover") {
					t.Fatal("wrong resume command", args)
				}
				if state == "absent" {
					return guestWrite(out, guestReceipt{State: "absent"})
				}
				return guestWrite(out, r)
			})
			e := g.Resume(context.Background(), f.intent, f.bundle)
			want := "status,recover"
			if state == "absent" {
				want = "status"
				if !errors.Is(e, ErrHostPending) {
					t.Fatal(e)
				}
			} else {
				if e != nil {
					t.Fatal(e)
				}
				if state == "upgraded" || state == "rolled-back" || state == "rejected" {
					want = "status"
				}
			}
			if strings.Join(verbs, ",") != want {
				t.Fatal(verbs)
			}
		})
	}
}
func TestGuestBackendRejectsForgedReceiptBeforeMutation(t *testing.T) {
	for _, kind := range []string{"instance", "attempt", "from", "to", "artifact", "envelope", "sequence", "missing", "unknown", "compact-retired"} {
		t.Run(kind, func(t *testing.T) {
			f := newGuestFixture(t)
			r := f.receipt
			switch kind {
			case "instance":
				r.Intent.InstanceID = strings.Repeat("1", 64)
			case "attempt":
				r.Intent.AttemptID = strings.Repeat("1", 64)
			case "from":
				r.Intent.FromBinding = strings.Repeat("1", 64)
			case "to":
				r.Intent.ToBinding = strings.Repeat("1", 64)
			case "artifact":
				r.Intent.ArtifactSHA256 = strings.Repeat("1", 64)
			case "envelope":
				r.EnvelopeSHA = strings.Repeat("1", 64)
			case "sequence":
				r.Sequence++
			case "missing":
				r.AcceptedAt = time.Time{}
			case "unknown":
				r.State = "success"
			case "compact-retired":
				r.State = "upgraded"
				r.Intent.FromBinding = ""
				r.Intent.ToBinding = ""
				r.Intent.ArtifactSHA256 = ""
			}
			calls := 0
			g := guestAdapter(t, f, func(_ context.Context, c GuestCommand, _ io.Reader, out io.Writer) (int, error) {
				calls++
				if c.Arguments()[0] != "status" {
					t.Fatal("mutated foreign attempt")
				}
				return guestWrite(out, r)
			})
			if e := g.EnsureUpgrade(context.Background(), f.intent, f.bundle); !errors.Is(e, ErrGuestProtocol) {
				t.Fatal("Ensure accepted", e)
			}
			if e := g.Resume(context.Background(), f.intent, f.bundle); !errors.Is(e, ErrGuestProtocol) {
				t.Fatal("Resume accepted", e)
			}
			if calls != 2 {
				t.Fatal(calls)
			}
		})
	}
}
func TestGuestBackendBoundedStrictResponses(t *testing.T) {
	f := newGuestFixture(t)
	good := hostBytes(guestReply{true, "ok", hostBytes(f.observation)})
	for _, kind := range []string{"extra-json", "unknown-top", "unknown-result", "missing-ready", "duplicate-top", "case-field", "oversize", "exit-mismatch", "contradictory-ok", "null-result", "empty", "transport-error"} {
		t.Run(kind, func(t *testing.T) {
			raw := append([]byte(nil), good...)
			exit := 0
			var transportErr error
			switch kind {
			case "extra-json":
				raw = append(raw, []byte("{}")...)
			case "unknown-top":
				raw = append([]byte(`{"foreign":true,`), raw[1:]...)
			case "unknown-result":
				raw = bytes.Replace(raw, []byte(`"LocalLoopback":true`), []byte(`"foreign":true,"LocalLoopback":true`), 1)
			case "missing-ready":
				raw = bytes.Replace(raw, []byte(`"Ready":true,`), nil, 1)
			case "duplicate-top":
				raw = append([]byte(`{"ok":true,`), raw[1:]...)
			case "case-field":
				raw = bytes.Replace(raw, []byte(`"Ready"`), []byte(`"ready"`), 1)
			case "oversize":
				raw = bytes.Repeat([]byte("x"), guestResponseLimit+1)
			case "exit-mismatch":
				exit = 1
			case "contradictory-ok":
				raw = []byte(`{"ok":false,"code":"ok"}`)
			case "null-result":
				raw = []byte(`{"ok":true,"code":"ok","result":null}`)
			case "empty":
				raw = nil
			case "transport-error":
				transportErr = errors.New("private transport stderr secret fixture")
			}
			g := guestAdapter(t, f, func(context.Context, GuestCommand, io.Reader, io.Writer) (int, error) {
				return 1, errors.New("replaced below")
			})
			g.options.Transport = func(_ context.Context, _ GuestCommand, _ io.Reader, out io.Writer) (int, error) {
				out.Write(raw)
				return exit, transportErr
			}
			_, e := g.Observe(context.Background(), "")
			if e == nil {
				t.Fatal("accepted malformed response")
			}
			if kind == "transport-error" {
				if !errors.Is(e, ErrGuestTransport) || strings.Contains(e.Error(), "secret") {
					t.Fatal("leaked error", e)
				}
			} else if !errors.Is(e, ErrGuestProtocol) {
				t.Fatal(e)
			}
		})
	}
}
func TestGuestBackendErrorCodesAndNoMutation(t *testing.T) {
	for _, c := range []struct {
		code string
		exit int
		want error
	}{{"not-configured", 0, ErrGuestNotConfigured}, {"reconciliation-required", 1, ErrHostPending}, {"retention-full", 1, ErrGuestCapacity}, {"update-conflict", 1, ErrHostConflict}, {"not-configured", 1, ErrGuestProtocol}, {"new-code", 1, ErrGuestProtocol}} {
		t.Run(c.code+string(rune('0'+c.exit)), func(t *testing.T) {
			f := newGuestFixture(t)
			g := guestAdapter(t, f, func(_ context.Context, _ GuestCommand, _ io.Reader, out io.Writer) (int, error) {
				out.Write(hostBytes(guestReply{Code: c.code}))
				return c.exit, nil
			})
			if _, e := g.Observe(context.Background(), ""); !errors.Is(e, c.want) {
				t.Fatal(e)
			}
		})
	}
}
func TestGuestBackendDisconnectedSubmissionAndCancellation(t *testing.T) {
	for _, kind := range []string{"disconnect", "early-success", "cancel"} {
		t.Run(kind, func(t *testing.T) {
			f := newGuestFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			g := guestAdapter(t, f, func(_ context.Context, c GuestCommand, in io.Reader, out io.Writer) (int, error) {
				if c.Arguments()[0] == "status" {
					return guestWrite(out, guestReceipt{State: "absent"})
				}
				prefix := make([]byte, 8)
				io.ReadFull(in, prefix)
				if kind == "cancel" {
					cancel()
					return 1, nil
				}
				if kind == "early-success" {
					return guestWrite(out, f.receipt)
				}
				return 1, io.ErrUnexpectedEOF
			})
			done := make(chan error, 1)
			go func() { done <- g.EnsureUpgrade(ctx, f.intent, f.bundle) }()
			select {
			case e := <-done:
				want := ErrGuestTransport
				if kind == "cancel" {
					want = context.Canceled
				}
				if !errors.Is(e, want) {
					t.Fatal(e)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("stdin producer was not reclaimed")
			}
		})
	}
}
func TestGuestBackendWrongIntentAndTamperedBundleNeverCallsTransport(t *testing.T) {
	f := newGuestFixture(t)
	g := guestAdapter(t, f, func(context.Context, GuestCommand, io.Reader, io.Writer) (int, error) {
		t.Fatal("transport called for invalid intent/payload")
		return 1, nil
	})
	bad := f.intent
	bad.ToBinding = strings.Repeat("1", 64)
	if e := g.EnsureUpgrade(context.Background(), bad, f.bundle); !errors.Is(e, ErrHostConflict) {
		t.Fatal(e)
	}
	if e := os.WriteFile(f.bundle.payloadPath, []byte("changed"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := g.EnsureUpgrade(context.Background(), f.intent, f.bundle); !errors.Is(e, ErrHostConflict) {
		t.Fatal(e)
	}
}
func TestGuestBackendObservationIdentityAndConcurrentProgress(t *testing.T) {
	for _, kind := range []string{"foreign-instance", "wrong-binding", "missing-status", "progress"} {
		t.Run(kind, func(t *testing.T) {
			f := newGuestFixture(t)
			obs := f.observation
			obs.AttemptState = "upgraded"
			obs.Binding = f.intent.ToBinding
			r := f.receipt
			r.State = "upgraded"
			switch kind {
			case "foreign-instance":
				obs.InstanceID = strings.Repeat("1", 64)
			case "wrong-binding":
				obs.Binding = f.intent.FromBinding
			case "missing-status":
				r = guestReceipt{State: "absent"}
			case "progress":
				obs.AttemptState = "running"
				obs.Binding = f.intent.FromBinding
			}
			g := guestAdapter(t, f, func(_ context.Context, c GuestCommand, _ io.Reader, out io.Writer) (int, error) {
				if c.Arguments()[0] == "observe" {
					return guestWrite(out, obs)
				}
				return guestWrite(out, r)
			})
			actual, e := g.Observe(context.Background(), f.intent.AttemptID)
			if kind == "progress" {
				if e != nil || actual != obs {
					t.Fatal("synthesized terminal observation", actual, e)
				}
			} else if !errors.Is(e, ErrGuestProtocol) {
				t.Fatal("accepted forged observation", e)
			}
		})
	}
}

// Ensure the copied protocol uses the root's actual current JSON field spelling.
func TestGuestBackendSubmitIntentJSON(t *testing.T) {
	raw := hostBytes(guestSubmit{Intent: HostUpgradeIntent{InstanceID: "i", AttemptID: "a"}, Envelope: []byte("e"), PayloadSize: 1})
	var value map[string]json.RawMessage
	if json.Unmarshal(raw, &value) != nil || len(value) != 3 {
		t.Fatal("submit schema")
	}
	if !bytes.Contains(value["intent"], []byte(`"InstanceID":"i","AttemptID":"a"`)) {
		t.Fatal("intent was renamed")
	}
}

func TestGuestBackendControllerUnknownNeedsExplicitResume(t *testing.T) {
	f := newHostFixture(t)
	var receipt guestReceipt
	submits, recovers := 0, 0
	g, e := NewGuestBackend(GuestBackendOptions{InstanceID: f.c.options.InstanceID, Architecture: "amd64", Transport: func(_ context.Context, c GuestCommand, in io.Reader, out io.Writer) (int, error) {
		args := c.Arguments()
		switch args[0] {
		case "observe":
			world := f.world.read()
			state := "absent"
			if len(args) == 2 && receipt.State != "" {
				state = receipt.State
				if state == "queued" {
					state = "running"
				}
			}
			return guestWrite(out, BackendObservation{LocalLoopback: true, MigrationVersion: "0040", Architecture: "amd64", InstanceID: f.c.options.InstanceID, Binding: world.Binding, Ready: true, Finalized: true, AttemptState: state})
		case "status":
			if receipt.State == "" {
				return guestWrite(out, guestReceipt{State: "absent"})
			}
			return guestWrite(out, receipt)
		case "submit":
			raw, err := io.ReadAll(in)
			if err != nil {
				return 1, err
			}
			parts := bytes.SplitN(raw, []byte{'\n'}, 2)
			if len(parts) != 2 || !bytes.Equal(parts[1], f.payload) {
				t.Fatal("controller changed signed payload")
			}
			var request guestSubmit
			if guestDecode(parts[0], &request) != nil {
				t.Fatal("header")
			}
			submits++
			receipt = guestReceipt{Intent: request.Intent, State: "queued", EnvelopeSHA: hostSHA(request.Envelope), Sequence: 1, AcceptedAt: f.c.options.Now()}
			return guestWrite(out, receipt)
		case "recover":
			if args[1] != receipt.Intent.AttemptID {
				t.Fatal("different attempt")
			}
			recovers++
			before := receipt
			receipt.State = "upgraded"
			world := f.world.read()
			world.Binding = receipt.Intent.ToBinding
			f.world.write(world)
			return guestWrite(out, before)
		default:
			t.Fatal("unexpected command", args)
			return 1, nil
		}
	}})
	if e != nil {
		t.Fatal(e)
	}
	f.c.options.Backend = g
	if _, e = f.c.Select(context.Background(), f.envelope, false); e != nil {
		t.Fatal(e)
	}
	for n := 0; n < 4 && submits == 0; n++ {
		if _, e = f.c.Advance(context.Background()); e != nil {
			t.Fatal(e)
		}
	}
	if submits != 1 || f.world.read().Slot != f.c.options.Initial.SlotSHA256 {
		t.Fatal("queued receipt caused host handoff")
	}
	receipt.State = "unknown"
	if _, e = f.c.Advance(context.Background()); !errors.Is(e, ErrHostPending) {
		t.Fatal("unknown was not pending", e)
	}
	if recovers != 0 || submits != 1 {
		t.Fatal("Advance implicitly retried/recovered")
	}
	// A future driver receives the original verified pending bundle through a
	// controller-owned entry; this fixture independently reopens the same bytes.
	root, err := filepath.EvalSymlinks(createTestParentDir(t))
	if err != nil {
		t.Fatal(err)
	}
	payload := filepath.Join(root, "payload")
	if err = os.WriteFile(payload, f.payload, 0600); err != nil {
		t.Fatal(err)
	}
	bundle, err := VerifyHostBundle(context.Background(), payload, f.envelope, f.c.indexOptions(HostSnapshot{Installed: f.c.options.Initial}, f.c.options.Now()))
	if err != nil {
		t.Fatal(err)
	}
	defer bundle.Close()
	if e = g.Resume(context.Background(), receipt.Intent, bundle); e != nil {
		t.Fatal(e)
	}
	result := finishHost(t, f.c)
	if result.State != "updated" || recovers != 1 || submits != 1 {
		t.Fatal("explicit same-attempt reconciliation failed", result.State, recovers, submits)
	}
}

// Deliberately exposes only Read: io.Copy must not take a source WriterTo
// shortcut, which would miss the destination's promoted ReadFrom bypass.
type guestReadOnly struct{ reader io.Reader }

func (r guestReadOnly) Read(p []byte) (int, error) { return r.reader.Read(p) }
func TestGuestBackendIOCopyCaptureIsBounded(t *testing.T) {
	var output guestOutput
	if _, ok := any(&output).(io.ReaderFrom); ok {
		t.Fatal("capture exposes an unbounded ReaderFrom")
	}
	n, e := io.Copy(&output, guestReadOnly{bytes.NewReader(bytes.Repeat([]byte("x"), guestResponseLimit*4))})
	if !errors.Is(e, ErrGuestProtocol) || n > guestResponseLimit || output.Len() > guestResponseLimit || !output.overflow {
		t.Fatal("io.Copy bypassed capture bound", n, output.Len(), e)
	}
	f := newGuestFixture(t)
	producerDone := make(chan error, 1)
	g := guestAdapter(t, f, func(_ context.Context, _ GuestCommand, _ io.Reader, out io.Writer) (int, error) {
		reader, writer := io.Pipe()
		go func() {
			_, e := writer.Write(bytes.Repeat([]byte("x"), guestResponseLimit*4))
			writer.CloseWithError(e)
			producerDone <- e
		}()
		_, e := io.Copy(out, guestReadOnly{reader})
		reader.CloseWithError(e)
		// A trusted child transport must stop/reap its producer after stdout failure.
		select {
		case <-producerDone:
		case <-time.After(5 * time.Second):
			t.Fatal("stdout producer not reclaimed")
		}
		return 1, e
	})
	if _, e = g.Observe(context.Background(), ""); !errors.Is(e, ErrGuestProtocol) {
		t.Fatal("overflow was not rejected", e)
	}
}

func TestGuestBackendRetainedProcessFatalPreserved(t *testing.T) {
	f := newGuestFixture(t)
	var callCount int
	g := guestAdapter(t, f, func(_ context.Context, _ GuestCommand, _ io.Reader, _ io.Writer) (int, error) {
		callCount++
		return 0, ErrGuestProcessRetained
	})

	// 1. Observe preserves ErrGuestProcessRetained
	_, err := g.Observe(context.Background(), "")
	if !errors.Is(err, ErrGuestProcessRetained) {
		t.Fatalf("expected ErrGuestProcessRetained from Observe, got %v", err)
	}
	if !errors.Is(err, ErrGuestTransport) {
		t.Fatalf("expected ErrGuestProcessRetained to wrap ErrGuestTransport, got %v", err)
	}

	// 2. EnsureUpgrade preserves ErrGuestProcessRetained
	callCountBefore := callCount
	err = g.EnsureUpgrade(context.Background(), f.intent, f.bundle)
	if !errors.Is(err, ErrGuestProcessRetained) {
		t.Fatalf("expected ErrGuestProcessRetained from EnsureUpgrade, got %v", err)
	}
	if callCount-callCountBefore != 1 {
		t.Fatalf("expected exactly 1 call (no second submit), got %d", callCount-callCountBefore)
	}
}

func TestGuestBackendSubmitProducerStoppedAndJoinedOnRetainedFatal(t *testing.T) {
	for _, withCancel := range []bool{false, true} {
		t.Run(fmt.Sprintf("withCancel=%v", withCancel), func(t *testing.T) {
			f := newGuestFixture(t)
			var statusCalls, submitCalls int
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			g := guestAdapter(t, f, func(_ context.Context, cmd GuestCommand, in io.Reader, out io.Writer) (int, error) {
				switch cmd.verb {
				case "status":
					statusCalls++
					return guestWrite(out, guestReceipt{State: "absent"})
				case "submit":
					submitCalls++
					if withCancel {
						cancel()
					}
					// Consume partial stdin
					buf := make([]byte, 16)
					_, _ = in.Read(buf)
					return 0, ErrGuestProcessRetained
				default:
					t.Fatalf("unexpected verb %s", cmd.verb)
					return 1, nil
				}
			})

			start := time.Now()
			err := g.EnsureUpgrade(ctx, f.intent, f.bundle)
			elapsed := time.Since(start)

			if elapsed > 2*time.Second {
				t.Fatalf("EnsureUpgrade took too long: %v", elapsed)
			}
			if !errors.Is(err, ErrGuestProcessRetained) {
				t.Fatalf("expected ErrGuestProcessRetained, got %v", err)
			}
			if !errors.Is(err, ErrGuestTransport) {
				t.Fatalf("expected ErrGuestProcessRetained to wrap ErrGuestTransport, got %v", err)
			}
			if statusCalls != 1 {
				t.Errorf("expected 1 status call, got %d", statusCalls)
			}
			if submitCalls != 1 {
				t.Errorf("expected exactly 1 submit call (no second submit), got %d", submitCalls)
			}
		})
	}
}

func TestGuestBackendCallRetainedFatalPrecedenceOverOverflowAndCancel(t *testing.T) {
	f := newGuestFixture(t)

	// Subtest 1: output overflow + ErrGuestProcessRetained -> returns ErrGuestProcessRetained
	t.Run("overflow_and_retained", func(t *testing.T) {
		g := guestAdapter(t, f, func(_ context.Context, _ GuestCommand, _ io.Reader, out io.Writer) (int, error) {
			// Write > 64KB to trigger overflow
			_, _ = out.Write(bytes.Repeat([]byte("A"), guestResponseLimit+1024))
			return 0, ErrGuestProcessRetained
		})
		_, err := g.Observe(context.Background(), "")
		if !errors.Is(err, ErrGuestProcessRetained) {
			t.Fatalf("expected ErrGuestProcessRetained to take precedence over overflow, got %v", err)
		}
	})

	// Subtest 2: cancelled ctx + ErrGuestProcessRetained -> returns ErrGuestProcessRetained
	t.Run("cancel_and_retained", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		g := guestAdapter(t, f, func(_ context.Context, _ GuestCommand, _ io.Reader, _ io.Writer) (int, error) {
			cancel()
			return 0, ErrGuestProcessRetained
		})
		_, err := g.Observe(ctx, "")
		if !errors.Is(err, ErrGuestProcessRetained) {
			t.Fatalf("expected ErrGuestProcessRetained to take precedence over ctx.Err(), got %v", err)
		}
	})
}
