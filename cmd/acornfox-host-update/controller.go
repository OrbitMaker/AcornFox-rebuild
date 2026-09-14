package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"time"

	"github.com/open-card/open-card/internal/desktopupdate"
	"github.com/open-card/open-card/internal/hostconfig"
	"github.com/open-card/open-card/internal/hostlifecycle"
)

var (
	ErrAdmissionRejected = errors.New("hostcontroller: admission verification failed")
	ErrSlotMismatch      = errors.New("hostcontroller: active slot does not match admission target")
)

type ControllerOptions struct {
	ConfigPath     string
	SlotsRoot      string
	ControllerRoot string
	BootstrapRoot  string
	AllowNonRoot   bool
	GuestTransport desktopupdate.GuestTransport // test override
	Now            func() time.Time             // test override
	HTTPClient     *http.Client                 // test override
	AdvanceTimeout time.Duration
}

func RunManagedChild(ctx context.Context, lifecycleConn io.ReadWriter, opts ControllerOptions) error {
	// 1. Send pre-core hello BEFORE opening any core roots or loading config
	hello := &hostlifecycle.HelloFrame{
		Type:          hostlifecycle.FrameTypeHello,
		SchemaVersion: hostlifecycle.ProtocolVersion1,
	}
	helloBytes, err := hostlifecycle.EncodeHello(hello)
	if err != nil {
		return err
	}
	if err := hostlifecycle.WriteFrame(lifecycleConn, helloBytes); err != nil {
		return fmt.Errorf("failed to send pre-core hello: %w", err)
	}

	// 2. Wait for admission frame before opening core roots
	admitBytes, err := hostlifecycle.ReadFrame(lifecycleConn)
	if err != nil {
		return fmt.Errorf("failed to receive admission: %w", err)
	}
	admit, err := hostlifecycle.DecodeAdmit(admitBytes)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrAdmissionRejected, err)
	}

	traceAdmittedMarker(admit.Operation)

	// 3. Now admitted: open and validate static host-runtime.json config
	cfg, err := hostconfig.ReadAndValidateConfigFile(opts.ConfigPath, opts.BootstrapRoot, opts.AllowNonRoot)
	if err != nil {
		return err
	}
	defer cfg.Close()

	if cfg.InstanceID != admit.InstanceID {
		return fmt.Errorf("%w: instance ID mismatch", ErrAdmissionRejected)
	}

	// 4. Pin bootstrap
	bootstrapSpec := convertBootstrapSpec(cfg.BootstrapSpec)
	pinned, err := desktopupdate.PinHostBootstrap(ctx, bootstrapSpec)
	if err != nil {
		return err
	}
	defer pinned.Close()

	// 5. Construct GuestBackend
	transport := opts.GuestTransport
	if transport == nil {
		transport = defaultGuestTransport()
	}
	guestBackend, err := desktopupdate.NewGuestBackend(desktopupdate.GuestBackendOptions{
		InstanceID:   cfg.InstanceID,
		Architecture: runtime.GOARCH,
		Transport:    transport,
	})
	if err != nil {
		return err
	}

	// 6. Define Linux lifecycle hooks using WithLauncherFD directly on HostSlotView
	hooks := desktopupdate.HostSlotHooks{
		Stop: func(hookCtx context.Context, instanceID, attemptID string, oldView desktopupdate.HostSlotView) error {
			return oldView.WithLauncherFD(hookCtx, func(launcherFD *os.File, id desktopupdate.HostSlotExecutableIdentity) error {
				return executeLauncherSubcommand(hookCtx, launcherFD, "slot-stop")
			})
		},
		Start: func(hookCtx context.Context, instanceID string, targetView desktopupdate.HostSlotView) error {
			return targetView.WithLauncherFD(hookCtx, func(launcherFD *os.File, id desktopupdate.HostSlotExecutableIdentity) error {
				return executeLauncherSubcommand(hookCtx, launcherFD, "slot-start")
			})
		},
		Probe: func(hookCtx context.Context, instanceID string, targetView desktopupdate.HostSlotView, targetBinding string) error {
			if err := targetView.WithLauncherFD(hookCtx, func(launcherFD *os.File, id desktopupdate.HostSlotExecutableIdentity) error {
				return executeLauncherSubcommand(hookCtx, launcherFD, "slot-probe")
			}); err != nil {
				return err
			}
			// Fresh Observe on GuestBackend to verify full observation contract
			obs, err := guestBackend.Observe(hookCtx, "")
			if err != nil {
				return err
			}
			if !obs.LocalLoopback || obs.MigrationVersion != "0040" || obs.InstanceID != instanceID ||
				obs.Architecture != runtime.GOARCH || obs.Binding != targetBinding || !obs.Ready || !obs.Finalized {
				return desktopupdate.ErrHostConflict
			}
			return nil
		},
		StartMaintenance: nil,
	}

	// 7. Construct HostSlots
	slotsRoot := opts.SlotsRoot
	if slotsRoot == "" {
		slotsRoot = hostconfig.DefaultSlotsRoot
	}
	slots, err := desktopupdate.NewHostSlots(desktopupdate.HostSlotOptions{
		Root:       slotsRoot,
		InstanceID: cfg.InstanceID,
		Bootstrap:  pinned,
		Hooks:      hooks,
	})
	if err != nil {
		return fmt.Errorf("step 7 slots: %w", err)
	}

	// 8. Construct HostController
	controllerRoot := opts.ControllerRoot
	if controllerRoot == "" {
		controllerRoot = hostconfig.DefaultControllerRoot
	}
	pubKeyBytes, err := hex.DecodeString(cfg.Policy.PublicKeyHex)
	if err != nil {
		return fmt.Errorf("step 8 key: %w", err)
	}
	policy := &desktopupdate.HostPolicy{
		PublicKey:       ed25519.PublicKey(pubKeyBytes),
		IndexURL:        cfg.Policy.IndexURL,
		OS:              cfg.Policy.OS,
		Arch:            cfg.Policy.Arch,
		Channel:         cfg.Policy.Channel,
		AllowedHosts:    cfg.Policy.AllowedHosts,
		MaxArtifactSize: cfg.Policy.MaxArtifactSize,
	}
	initial := desktopupdate.HostInstallation{
		Version:         cfg.BootstrapSpec.Version,
		SlotSHA256:      pinned.ID(),
		BackendBinding:  cfg.BootstrapBackendBinding,
		AppliedSequence: 0,
	}
	controllerOpts := desktopupdate.HostControllerOptions{
		Root:            controllerRoot,
		InstanceID:      cfg.InstanceID,
		Initial:         initial,
		Policy:          policy,
		Backend:         guestBackend,
		Runtime:         slots,
		Now:             opts.Now,
		HTTPClient:      opts.HTTPClient,
		DownloadTimeout: 60 * time.Second,
	}
	controller, err := desktopupdate.NewHostController(controllerOpts)
	if err != nil {
		return fmt.Errorf("step 8 controller: %w", err)
	}

	// 9. Check active slot vs admit
	activeSlot, err := slots.CurrentSlot(ctx)
	if err != nil {
		return fmt.Errorf("step 9 CurrentSlot: %w", err)
	}

	if admit.Role == hostlifecycle.RoleRecovery {
		if activeSlot != admit.SlotID {
			reselect := &hostlifecycle.ReselectFrame{
				Type:          hostlifecycle.FrameTypeReselect,
				SchemaVersion: hostlifecycle.ProtocolVersion1,
				Nonce:         admit.Nonce,
				ReasonCode:    "active_slot_repaired",
				ActiveSlotID:  activeSlot,
			}
			reselectBytes, err := hostlifecycle.EncodeReselect(reselect)
			if err != nil {
				return err
			}
			return hostlifecycle.WriteFrame(lifecycleConn, reselectBytes)
		}
	} else {
		if activeSlot != admit.SlotID {
			return ErrSlotMismatch
		}
	}

	// 10. Execute operation
	var statusState string
	var reasonCode string
	currentVersion := cfg.BootstrapSpec.Version

	switch admit.Operation {
	case hostlifecycle.OpStatus:
		st, err := controller.Status(ctx)
		if err != nil {
			return fmt.Errorf("step 10 status: %w", err)
		}
		statusState = st.State
		reasonCode = "ok"
		if st.Snapshot != nil {
			currentVersion = st.Snapshot.Installed.Version
			activeSlot = st.Snapshot.Installed.SlotSHA256
		}

	case hostlifecycle.OpCheck:
		st, err := controller.CheckAndSelect(ctx)
		if err != nil {
			if errors.Is(err, desktopupdate.ErrNoUpdate) {
				statusState = "idle"
				reasonCode = "no_update"
			} else {
				return err
			}
		} else {
			statusState = st.State
			reasonCode = "ok"
		}
		if st.Snapshot != nil {
			currentVersion = st.Snapshot.Installed.Version
			activeSlot = st.Snapshot.Installed.SlotSHA256
		}

	case hostlifecycle.OpAdvance:
		timeout := opts.AdvanceTimeout
		if timeout == 0 {
			timeout = 60 * time.Second
		}
		deadline := time.Now().Add(timeout)
		for {
			st, err := controller.Advance(ctx)
			if err != nil {
				if errors.Is(err, desktopupdate.ErrHostPending) {
					if time.Now().After(deadline) {
						statusState = "pending"
						reasonCode = "pending"
						break
					}
					time.Sleep(200 * time.Millisecond)
					continue
				}
				return err
			}
			if st.Snapshot != nil {
				currentVersion = st.Snapshot.Installed.Version
				activeSlot = st.Snapshot.Installed.SlotSHA256
			}
			if st.Snapshot == nil || (st.Snapshot.Pending == nil && len(st.Snapshot.Cleanup) == 0 && !st.Snapshot.CollectSlots) {
				statusState = st.State
				reasonCode = "ok"
				break
			}
			if time.Now().After(deadline) {
				statusState = st.State
				reasonCode = "pending"
				break
			}
			time.Sleep(100 * time.Millisecond)
		}

	case hostlifecycle.OpResumeBackend:
		st, err := controller.ResumeBackend(ctx)
		if err != nil && !errors.Is(err, desktopupdate.ErrHostPending) {
			return err
		}
		if st.Snapshot != nil {
			currentVersion = st.Snapshot.Installed.Version
			activeSlot = st.Snapshot.Installed.SlotSHA256
		}
		timeout := opts.AdvanceTimeout
		if timeout == 0 {
			timeout = 60 * time.Second
		}
		deadline := time.Now().Add(timeout)
		for {
			st, err := controller.Advance(ctx)
			if err != nil {
				if errors.Is(err, desktopupdate.ErrHostPending) {
					if time.Now().After(deadline) {
						statusState = "pending"
						reasonCode = "pending"
						break
					}
					time.Sleep(200 * time.Millisecond)
					continue
				}
				return err
			}
			if st.Snapshot != nil {
				currentVersion = st.Snapshot.Installed.Version
				activeSlot = st.Snapshot.Installed.SlotSHA256
			}
			if st.Snapshot == nil || (st.Snapshot.Pending == nil && len(st.Snapshot.Cleanup) == 0 && !st.Snapshot.CollectSlots) {
				statusState = st.State
				reasonCode = "ok"
				break
			}
			if time.Now().After(deadline) {
				statusState = st.State
				reasonCode = "pending"
				break
			}
			time.Sleep(100 * time.Millisecond)
		}

	case hostlifecycle.OpDismiss:
		st, err := controller.Dismiss(ctx)
		if err != nil {
			return err
		}
		statusState = st.State
		reasonCode = "ok"
		if st.Snapshot != nil {
			currentVersion = st.Snapshot.Installed.Version
			activeSlot = st.Snapshot.Installed.SlotSHA256
		}

	case hostlifecycle.OpStart:
		st, err := controller.Status(ctx)
		if err != nil {
			return err
		}
		basis, err := controller.ReadStartupBasis(ctx)
		if err != nil {
			return err
		}
		defer basis.Close()

		if !basis.Valid() || basis.SlotSHA256() != activeSlot || basis.ControllerProtocol() != 1 ||
			basis.InstanceProtocol() != 1 || basis.BackendAPIProtocol() != 1 {
			return desktopupdate.ErrHostConflict
		}
		if err := slots.Probe(ctx, basis.SlotSHA256(), basis.BackendBinding()); err != nil {
			return err
		}
		if !basis.Valid() {
			return desktopupdate.ErrHostConflict
		}
		statusState = "ready"
		reasonCode = "ok"
		if st.Snapshot != nil {
			currentVersion = st.Snapshot.Installed.Version
		}

	default:
		return fmt.Errorf("unsupported operation %q", admit.Operation)
	}

	statusState, reasonCode = lifecycleOutcome(statusState, reasonCode)

	// 11. Send bounded desensitized result echoing the admit nonce
	result := &hostlifecycle.ResultFrame{
		Type:          hostlifecycle.FrameTypeResult,
		SchemaVersion: hostlifecycle.ProtocolVersion1,
		Nonce:         admit.Nonce,
		Operation:     admit.Operation,
		State:         statusState,
		ReasonCode:    reasonCode,
		Version:       currentVersion,
		SlotID:        activeSlot,
	}

	resultBytes, err := hostlifecycle.EncodeResult(result)
	if err != nil {
		return err
	}

	return hostlifecycle.WriteFrame(lifecycleConn, resultBytes)
}

// Keep internal durable outcomes separate from the fixed lifecycle wire vocabulary.
func lifecycleOutcome(state, reason string) (string, string) {
	switch state {
	case "backend-rolled-back", "host-rolled-back":
		return "idle", "failed"
	case "backend-rejected":
		return "idle", "ineligible"
	default:
		return state, reason
	}
}
