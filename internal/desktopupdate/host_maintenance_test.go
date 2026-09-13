package desktopupdate

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type mockMaintenanceSession struct {
	stopped  bool
	closed   bool
	stopErr  error
	closeErr error
}

func (s *mockMaintenanceSession) Stop(_ context.Context) error {
	s.stopped = true
	return s.stopErr
}

func (s *mockMaintenanceSession) Close() error {
	s.closed = true
	return s.closeErr
}

type countedFailOnceSession struct {
	mu         sync.Mutex
	stopCalls  int
	closeCalls int
	failStop   bool
	failClose  bool
	stopErr    error
	closeErr   error
}

func (s *countedFailOnceSession) Stop(_ context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stopCalls++
	if s.failStop {
		s.failStop = false
		return s.stopErr
	}
	return nil
}

func (s *countedFailOnceSession) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closeCalls++
	if s.failClose {
		s.failClose = false
		return s.closeErr
	}
	return nil
}

func TestHostMaintenanceBasisPendingPhases(t *testing.T) {
	f := newHostFixture(t)
	ctx := context.Background()

	// Initial select to enter pending state
	status, err := f.c.Select(ctx, f.envelope, false)
	if err != nil {
		t.Fatal(err)
	}
	if status.Snapshot.Pending == nil {
		t.Fatal("expected pending state after select")
	}

	oldSlot := status.Snapshot.Pending.Previous.SlotSHA256
	nextSlot := status.Snapshot.Pending.Candidate.Artifact.SHA256

	phases := []struct {
		phase    string
		allowOld bool
		allowNew bool
	}{
		{"selected", true, false},
		{"staged", true, false},
		{"host_prepared", true, false},
		{"backend_applying", true, false},
		{"backend_confirmed", true, false},
		{"host_switch", true, true},
		{"host_trial", false, true},
		{"host_rollback", true, true},
		{"discarding", true, false},
	}

	for _, tc := range phases {
		t.Run("phase_"+tc.phase, func(t *testing.T) {
			// Update pending phase
			s, state, err := f.c.open(ctx)
			if err != nil {
				t.Fatal(err)
			}
			state.Pending.Phase = tc.phase
			if err := s.save(&state); err != nil {
				s.close()
				t.Fatal(err)
			}
			s.close()

			// Test with oldSlot
			w := f.world.read()
			w.Slot = oldSlot
			f.world.write(w)

			basis, err := f.c.ReadMaintenanceBasis(ctx)
			if tc.allowOld {
				if err != nil {
					t.Fatalf("phase %s expected old slot success, got %v", tc.phase, err)
				}
				if basis.SlotSHA256() != oldSlot {
					t.Fatalf("expected slot %s, got %s", oldSlot, basis.SlotSHA256())
				}
				if !basis.Valid() {
					t.Fatal("expected valid basis")
				}
				basis.Close()
			} else {
				if !errors.Is(err, ErrHostConflict) {
					t.Fatalf("phase %s expected old slot conflict, got %v", tc.phase, err)
				}
			}

			// Test with nextSlot
			w = f.world.read()
			w.Slot = nextSlot
			f.world.write(w)

			basis, err = f.c.ReadMaintenanceBasis(ctx)
			if tc.allowNew {
				if err != nil {
					t.Fatalf("phase %s expected new slot success, got %v", tc.phase, err)
				}
				if basis.SlotSHA256() != nextSlot {
					t.Fatalf("expected slot %s, got %s", nextSlot, basis.SlotSHA256())
				}
				if !basis.Valid() {
					t.Fatal("expected valid basis")
				}
				basis.Close()
			} else {
				if !errors.Is(err, ErrHostConflict) {
					t.Fatalf("phase %s expected new slot conflict, got %v", tc.phase, err)
				}
			}

			// Test with invalid foreign slot
			w = f.world.read()
			w.Slot = strings.Repeat("f", 64)
			f.world.write(w)

			_, err = f.c.ReadMaintenanceBasis(ctx)
			if !errors.Is(err, ErrHostConflict) {
				t.Fatalf("phase %s expected foreign slot conflict, got %v", tc.phase, err)
			}
		})
	}
}

func TestHostMaintenanceBasisDenyNonPendingAndCleanupOnly(t *testing.T) {
	f := newHostFixture(t)
	ctx := context.Background()

	// 1. Idle state (no pending)
	if _, err := f.c.Status(ctx); err != nil {
		t.Fatal(err)
	}
	basis, err := f.c.ReadMaintenanceBasis(ctx)
	if !errors.Is(err, ErrHostConflict) {
		t.Fatalf("expected ErrHostConflict for idle state, got %v", err)
	}
	if basis != nil {
		t.Fatal("expected nil basis")
	}

	// 2. Cleanup-only state (no pending, but Cleanup entries present)
	s, state, err := f.c.open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	state.Pending = nil
	state.CollectSlots = true
	state.Cleanup = []HostStageCleanup{
		{
			ID:       strings.Repeat("c", 64),
			Identity: "identity",
			SHA256:   strings.Repeat("a", 64),
			Size:     1024,
		},
	}
	if err := s.save(&state); err != nil {
		s.close()
		t.Fatal(err)
	}
	s.close()

	basis, err = f.c.ReadMaintenanceBasis(ctx)
	if !errors.Is(err, ErrHostConflict) {
		t.Fatalf("expected ErrHostConflict for cleanup-only state, got %v", err)
	}
	if basis != nil {
		t.Fatal("expected nil basis")
	}
}

func TestHostMaintenanceBasisJSONClosedCancelDrift(t *testing.T) {
	f := newHostFixture(t)
	ctx := context.Background()

	// Enter pending state
	if _, err := f.c.Select(ctx, f.envelope, false); err != nil {
		t.Fatal(err)
	}

	// 1. JSON Marshal & Unmarshal rejected
	basis, err := f.c.ReadMaintenanceBasis(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := json.Marshal(basis); !errors.Is(err, ErrHostConflict) {
		t.Fatalf("expected ErrHostConflict on json.Marshal, got %v", err)
	}
	var dummy HostMaintenanceBasis
	if err := json.Unmarshal([]byte("{}"), &dummy); !errors.Is(err, ErrHostConflict) {
		t.Fatalf("expected ErrHostConflict on json.Unmarshal, got %v", err)
	}

	// 2. Protocol getters when valid
	if basis.ControllerProtocol() != 1 || basis.InstanceProtocol() != 1 || basis.BackendAPIProtocol() != 1 {
		t.Fatalf("expected protocol 1, got c=%d i=%d b=%d",
			basis.ControllerProtocol(), basis.InstanceProtocol(), basis.BackendAPIProtocol())
	}
	if basis.InstanceID() != f.c.options.InstanceID {
		t.Fatalf("expected instance %s, got %s", f.c.options.InstanceID, basis.InstanceID())
	}

	// 3. Close() invalidates lease and getters
	if err := basis.Close(); err != nil {
		t.Fatal(err)
	}
	if basis.Valid() {
		t.Fatal("expected Valid() false after Close")
	}
	if basis.InstanceID() != "" {
		t.Fatalf("expected empty InstanceID after Close, got %s", basis.InstanceID())
	}
	if basis.SlotSHA256() != "" {
		t.Fatalf("expected empty SlotSHA256 after Close, got %s", basis.SlotSHA256())
	}
	if basis.ControllerProtocol() != 0 || basis.InstanceProtocol() != 0 || basis.BackendAPIProtocol() != 0 {
		t.Fatal("expected protocol 0 after Close")
	}
	// Close() is idempotent
	if err := basis.Close(); err != nil {
		t.Fatal(err)
	}

	// 4. Context cancellation invalidates lease
	cancelCtx, cancel := context.WithCancel(context.Background())
	basis2, err := f.c.ReadMaintenanceBasis(cancelCtx)
	if err != nil {
		t.Fatal(err)
	}
	if !basis2.Valid() {
		t.Fatal("expected basis2 valid initially")
	}
	cancel()
	time.Sleep(20 * time.Millisecond)
	if basis2.Valid() {
		t.Fatal("expected basis2 invalid after context cancellation")
	}

	// 5. State drift (state.json change) invalidates lease
	basis3, err := f.c.ReadMaintenanceBasis(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !basis3.Valid() {
		t.Fatal("expected basis3 valid")
	}
	stateFile := filepath.Join(f.c.options.Root, "state.json")
	raw, err := os.ReadFile(stateFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stateFile, append(raw, ' '), 0600); err != nil {
		t.Fatal(err)
	}
	if basis3.Valid() {
		t.Fatal("expected basis3 invalid after state drift")
	}
	basis3.Close()
}

func TestHostMaintenanceBasisExactInventoryDrift(t *testing.T) {
	f := newHostFixture(t)
	ctx := context.Background()

	// Enter pending state
	if _, err := f.c.Select(ctx, f.envelope, false); err != nil {
		t.Fatal(err)
	}

	basis, err := f.c.ReadMaintenanceBasis(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer basis.Close()

	if !basis.Valid() {
		t.Fatal("expected basis valid")
	}

	// Add a newly created stage directory into root (even though stage- prefix is valid format)
	newStage := filepath.Join(f.c.options.Root, "stage-"+strings.Repeat("a", 64))
	if err := os.Mkdir(newStage, 0700); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(newStage)

	// Basis must immediately be invalid due to inventory drift!
	if basis.Valid() {
		t.Fatal("expected basis invalid after new stage directory was added")
	}
}

func TestHostSlotsStartMaintenance(t *testing.T) {
	sf := newSlotFixture(t)
	b, err := PinHostBootstrap(context.Background(), sf.Spec)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { b.Close() })

	maintenanceCalled := false
	probeCalled := false
	startCalled := false
	var capturedView HostSlotView
	activeSession := &mockMaintenanceSession{}

	hooks := HostSlotHooks{
		Stop:  func(context.Context, string, string, HostSlotView) error { return nil },
		Start: func(context.Context, string, HostSlotView) error { startCalled = true; return nil },
		Probe: func(context.Context, string, HostSlotView, string) error { probeCalled = true; return nil },
		StartMaintenance: func(ctx context.Context, instance string, v HostSlotView) (HostMaintenanceSession, error) {
			maintenanceCalled = true
			capturedView = v
			return activeSession, nil
		},
	}

	slots, err := NewHostSlots(HostSlotOptions{
		Root:       sf.Root,
		InstanceID: sf.ID,
		Bootstrap:  b,
		Hooks:      hooks,
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	bootSlot, err := slots.CurrentSlot(ctx)
	if err != nil {
		t.Fatal(err)
	}

	hf := newHostFixture(t)
	s, state, err := hf.c.open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	state.InstanceID = sf.ID
	state.Installed.SlotSHA256 = bootSlot
	if err := s.save(&state); err != nil {
		s.close()
		t.Fatal(err)
	}
	s.close()

	hf.c.options.InstanceID = sf.ID
	w := hf.world.read()
	w.Instance = sf.ID
	w.Slot = bootSlot
	hf.world.write(w)

	if _, err := hf.c.Select(ctx, hf.envelope, false); err != nil {
		t.Fatal(err)
	}

	basis, err := hf.c.ReadMaintenanceBasis(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// 1. Normal StartMaintenance returns owned session
	session, err := slots.StartMaintenance(ctx, basis)
	if err != nil {
		t.Fatalf("StartMaintenance failed: %v", err)
	}
	if !maintenanceCalled {
		t.Fatal("StartMaintenance hook was not called")
	}
	if probeCalled {
		t.Fatal("Probe hook was unexpectedly called during maintenance")
	}
	if startCalled {
		t.Fatal("normal Start hook was unexpectedly called during maintenance")
	}
	if capturedView.ID() != bootSlot {
		t.Fatalf("expected view slot %s, got %s", bootSlot, capturedView.ID())
	}
	// Caller stops session
	if err := session.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if !activeSession.stopped {
		t.Fatal("expected mock session to be stopped")
	}

	// 2. WithMaintenanceStart alias works
	maintenanceCalled = false
	session2, err := slots.WithMaintenanceStart(ctx, basis)
	if err != nil {
		t.Fatalf("WithMaintenanceStart failed: %v", err)
	}
	if !maintenanceCalled {
		t.Fatal("WithMaintenanceStart did not call hook")
	}
	session2.Close()

	// 3. Forged basis rejected
	forged := &HostMaintenanceBasis{
		instance: sf.ID,
		slot:     bootSlot,
	}
	if _, err = slots.StartMaintenance(ctx, forged); !errors.Is(err, ErrHostConflict) {
		t.Fatalf("expected ErrHostConflict for forged basis, got %v", err)
	}

	basis.Close()

	// 4. Closed basis rejected
	closedBasis, err := hf.c.ReadMaintenanceBasis(ctx)
	if err != nil {
		t.Fatal(err)
	}
	closedBasis.Close()
	if _, err = slots.StartMaintenance(ctx, closedBasis); !errors.Is(err, ErrHostConflict) {
		t.Fatalf("expected ErrHostConflict for closed basis, got %v", err)
	}

	// 5. Mismatched slot rejected
	w.Slot = strings.Repeat("9", 64)
	hf.world.write(w)
	s, state, err = hf.c.open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	state.Pending.Phase = "host_switch"
	state.Pending.Candidate.Artifact.SHA256 = strings.Repeat("9", 64)
	if err = s.save(&state); err != nil {
		s.close()
		t.Fatal(err)
	}
	s.close()

	diffSlotBasis, err := hf.c.ReadMaintenanceBasis(ctx)
	if err != nil {
		t.Fatal(err)
	}

	if _, err = slots.StartMaintenance(ctx, diffSlotBasis); !errors.Is(err, ErrHostConflict) {
		diffSlotBasis.Close()
		t.Fatalf("expected ErrHostConflict for mismatched slot, got %v", err)
	}
	diffSlotBasis.Close()

	// 6. Nil StartMaintenance hook fails explicitly without fallback
	noMaintenanceHooks := hooks
	noMaintenanceHooks.StartMaintenance = nil
	slotsNoMaint, err := NewHostSlots(HostSlotOptions{
		Root:       sf.Root,
		InstanceID: sf.ID,
		Bootstrap:  b,
		Hooks:      noMaintenanceHooks,
	})
	if err != nil {
		t.Fatal(err)
	}

	w.Slot = bootSlot
	hf.world.write(w)
	s, state, err = hf.c.open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	state.Pending.Phase = "selected"
	state.Pending.Candidate.Artifact.SHA256 = strings.Repeat("2", 64)
	if err = s.save(&state); err != nil {
		s.close()
		t.Fatal(err)
	}
	s.close()

	liveBasis, err := hf.c.ReadMaintenanceBasis(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer liveBasis.Close()

	startCalled = false
	probeCalled = false
	_, err = slotsNoMaint.StartMaintenance(ctx, liveBasis)
	if !errors.Is(err, ErrHostMaintenanceUnsupported) {
		t.Fatalf("expected ErrHostMaintenanceUnsupported for nil hook, got %v", err)
	}
	if startCalled || probeCalled {
		t.Fatal("normal Start or Probe hook was called when StartMaintenance was nil")
	}

	// 7. Hook returns (session, error): StartMaintenance cleans up session and returns error
	cleanedSession := &mockMaintenanceSession{}
	failingHooks := hooks
	failingHooks.StartMaintenance = func(ctx context.Context, instance string, v HostSlotView) (HostMaintenanceSession, error) {
		return cleanedSession, errors.New("hook failed after partial start")
	}
	slotsFailing, _ := NewHostSlots(HostSlotOptions{
		Root:       sf.Root,
		InstanceID: sf.ID,
		Bootstrap:  b,
		Hooks:      failingHooks,
	})
	_, err = slotsFailing.StartMaintenance(ctx, liveBasis)
	if err == nil {
		t.Fatal("expected error from failing hook")
	}
	if !cleanedSession.stopped {
		t.Fatal("expected partial session to be stopped upon hook failure")
	}
	if !cleanedSession.closed {
		t.Fatal("expected partial session to be closed upon hook failure after Stop succeeded")
	}

	// 8. Hook returns (session, error) and session Stop fails:
	// Caller receives session along with composite error to retain ownership.
	// Returned session must be opaque wrapper rejecting JSON.
	// Calling Stop again retries inner Stop and succeeds; subsequent Stop does not touch inner.
	failOnceStop := &countedFailOnceSession{
		failStop: true,
		stopErr:  errors.New("cannot stop VM yet"),
	}
	uncleanHooks := hooks
	uncleanHooks.StartMaintenance = func(ctx context.Context, instance string, v HostSlotView) (HostMaintenanceSession, error) {
		return failOnceStop, errors.New("hook failed")
	}
	slotsUnclean, _ := NewHostSlots(HostSlotOptions{
		Root:       sf.Root,
		InstanceID: sf.ID,
		Bootstrap:  b,
		Hooks:      uncleanHooks,
	})
	retSession, err := slotsUnclean.StartMaintenance(ctx, liveBasis)
	if err == nil {
		t.Fatal("expected error")
	}
	if retSession == nil {
		t.Fatal("expected session ownership to be returned when stop failed")
	}
	if _, ok := retSession.(*OpaqueMaintenanceSession); !ok {
		t.Fatalf("expected opaque wrapper returned, got %T", retSession)
	}
	if _, jerr := json.Marshal(retSession); !errors.Is(jerr, ErrHostConflict) {
		t.Fatalf("expected ErrHostConflict on json.Marshal, got %v", jerr)
	}
	if failOnceStop.stopCalls != 1 {
		t.Fatalf("expected 1 stop call during cleanup, got %d", failOnceStop.stopCalls)
	}
	// Retry Stop on returned wrapper: inner Stop called second time and succeeds
	if err := retSession.Stop(ctx); err != nil {
		t.Fatalf("expected retry Stop to succeed, got %v", err)
	}
	if failOnceStop.stopCalls != 2 {
		t.Fatalf("expected 2 stop calls after retry, got %d", failOnceStop.stopCalls)
	}
	// Subsequent Stop call is a no-op on wrapper (does not touch inner)
	if err := retSession.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if failOnceStop.stopCalls != 2 {
		t.Fatalf("expected stopCalls to remain 2, got %d", failOnceStop.stopCalls)
	}
	// Caller closes session: inner Close called once and succeeds
	if err := retSession.Close(); err != nil {
		t.Fatal(err)
	}
	if failOnceStop.closeCalls != 1 {
		t.Fatalf("expected 1 close call, got %d", failOnceStop.closeCalls)
	}
	// Subsequent Close or Stop do not touch inner
	if err := retSession.Close(); err != nil {
		t.Fatal(err)
	}
	if err := retSession.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if failOnceStop.closeCalls != 1 || failOnceStop.stopCalls != 2 {
		t.Fatal("subsequent calls touched inner after close")
	}

	// 9. Nil session returned on hook success is rejected
	nilSessionHooks := hooks
	nilSessionHooks.StartMaintenance = func(ctx context.Context, instance string, v HostSlotView) (HostMaintenanceSession, error) {
		return nil, nil
	}
	slotsNilSession, _ := NewHostSlots(HostSlotOptions{
		Root:       sf.Root,
		InstanceID: sf.ID,
		Bootstrap:  b,
		Hooks:      nilSessionHooks,
	})
	_, err = slotsNilSession.StartMaintenance(ctx, liveBasis)
	if !errors.Is(err, ErrHostConflict) {
		t.Fatalf("expected ErrHostConflict for nil session, got %v", err)
	}

	// 10. Context cancellation inside/before post-hook verification cleans up session
	cancelCtx, cancel := context.WithCancel(context.Background())
	cancelSession := &mockMaintenanceSession{}
	cancelHooks := hooks
	cancelHooks.StartMaintenance = func(ctx context.Context, instance string, v HostSlotView) (HostMaintenanceSession, error) {
		cancel() // cancel context during hook!
		return cancelSession, nil
	}
	slotsCancel, _ := NewHostSlots(HostSlotOptions{
		Root:       sf.Root,
		InstanceID: sf.ID,
		Bootstrap:  b,
		Hooks:      cancelHooks,
	})
	_, err = slotsCancel.StartMaintenance(cancelCtx, liveBasis)
	if err == nil {
		t.Fatal("expected error when context cancelled during hook")
	}
	if !cancelSession.stopped || !cancelSession.closed {
		t.Fatal("expected session to be stopped and closed when context was cancelled during hook")
	}

	// 11. Close fails after Stop succeeds: ownership retained, returned wrapper opaque.
	// Calling Close again retries inner Close and succeeds; subsequent calls do not touch inner.
	failOnceClose := &countedFailOnceSession{
		failClose: true,
		closeErr:  errors.New("cannot close VM handle yet"),
	}
	closeFailHooks := hooks
	closeFailHooks.StartMaintenance = func(ctx context.Context, instance string, v HostSlotView) (HostMaintenanceSession, error) {
		return failOnceClose, errors.New("hook failed")
	}
	slotsCloseFail, _ := NewHostSlots(HostSlotOptions{
		Root:       sf.Root,
		InstanceID: sf.ID,
		Bootstrap:  b,
		Hooks:      closeFailHooks,
	})
	retCloseSession, err := slotsCloseFail.StartMaintenance(ctx, liveBasis)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "cannot close VM handle yet") {
		t.Fatalf("expected close error joined, got %v", err)
	}
	if retCloseSession == nil {
		t.Fatal("expected session ownership to be returned when close failed")
	}
	if _, ok := retCloseSession.(*OpaqueMaintenanceSession); !ok {
		t.Fatalf("expected opaque wrapper returned, got %T", retCloseSession)
	}
	if _, jerr := json.Marshal(retCloseSession); !errors.Is(jerr, ErrHostConflict) {
		t.Fatalf("expected ErrHostConflict on json.Marshal, got %v", jerr)
	}
	if failOnceClose.stopCalls != 1 || failOnceClose.closeCalls != 1 {
		t.Fatalf("expected 1 stop and 1 close call during cleanup, got stop=%d close=%d", failOnceClose.stopCalls, failOnceClose.closeCalls)
	}
	// Retry Close on returned wrapper: inner Close called second time and succeeds
	if err := retCloseSession.Close(); err != nil {
		t.Fatalf("expected retry Close to succeed, got %v", err)
	}
	if failOnceClose.closeCalls != 2 {
		t.Fatalf("expected 2 close calls after retry, got %d", failOnceClose.closeCalls)
	}
	// Subsequent Close or Stop do not touch inner
	if err := retCloseSession.Close(); err != nil {
		t.Fatal(err)
	}
	if err := retCloseSession.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if failOnceClose.closeCalls != 2 || failOnceClose.stopCalls != 1 {
		t.Fatal("subsequent calls touched inner after close")
	}

	// 12. OpaqueMaintenanceSession Stop and Close concurrent serialization
	concurrentSession := &countedFailOnceSession{}
	concurrentWrapper := &OpaqueMaintenanceSession{inner: concurrentSession}
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			_ = concurrentWrapper.Stop(ctx)
		}()
		go func() {
			defer wg.Done()
			_ = concurrentWrapper.Close()
		}()
	}
	wg.Wait()
	if concurrentSession.closeCalls > 1 {
		t.Fatalf("expected at most 1 close call to inner, got %d", concurrentSession.closeCalls)
	}
}
