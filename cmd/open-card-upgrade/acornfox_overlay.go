package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/open-card/open-card/internal/desktopupdate"
	"github.com/open-card/open-card/internal/hostconfig"
	"github.com/open-card/open-card/internal/hostoverlay"
	"github.com/open-card/open-card/internal/hostprovision"
)

const (
	overlayMemberBootstrap     = "launcher/acornfox-host-bootstrap"
	overlayMemberLauncher      = "launcher/acornfox-host-launcher"
	overlayMemberController    = "controller/acornfox-host-update"
	overlayMemberHostPolicy    = "controller/host-update-policy.json"
	overlayMemberGuestWorker   = "launcher/acornfox-guest-update"
	overlayMemberGuestPolicy   = "controller/guest-update-policy.json"
	overlayMemberCanonicalUnit = "controller/acornfox-host-bootstrap.service"
)

type overlayGuestProvisionRequest struct {
	Kind                 string
	BootstrapHostVersion string
	WorkerSourcePath     string
	ExpectedWorkerSHA256 string
	PolicySourcePath     string
	ExpectedPolicySHA256 string
}

type overlayGuestProvisionReceipt struct {
	Kind                 string `json:"kind"`
	InstanceID           string `json:"instance_id"`
	NativeID             string `json:"native_id"`
	WorkerSHA256         string `json:"worker_sha256"`
	PolicySHA256         string `json:"policy_sha256"`
	InstanceSHA256       string `json:"instance_sha256"`
	MarkerSHA256         string `json:"marker_sha256"`
	BootstrapHostVersion string `json:"bootstrap_host_version"`
}

type overlayGuestPolicy struct {
	Schema          int      `json:"schema_version"`
	PublicKey       []byte   `json:"public_key"`
	HostOS          string   `json:"host_os"`
	HostArch        string   `json:"host_arch"`
	Channel         string   `json:"channel"`
	AllowedHosts    []string `json:"allowed_hosts"`
	MaxArtifactSize int64    `json:"max_artifact_size"`
}

type verifiedOverlayPlan struct {
	bundle            *desktopupdate.VerifiedHostBundle
	manifest          desktopupdate.HostBundleManifest
	bootstrapPath     string
	bootstrapFile     desktopupdate.HostBundleFile
	launcherPath      string
	launcherFile      desktopupdate.HostBundleFile
	controllerPath    string
	controllerFile    desktopupdate.HostBundleFile
	hostPolicyPath    string
	hostPolicyFile    desktopupdate.HostBundleFile
	guestWorkerPath   string
	guestWorkerFile   desktopupdate.HostBundleFile
	guestPolicyPath   string
	guestPolicyFile   desktopupdate.HostBundleFile
	canonicalUnitPath string
	canonicalUnitFile desktopupdate.HostBundleFile
}

var testOverlayTargetOS string

func overlayTargetOS() string {
	if testOverlayTargetOS != "" {
		return testOverlayTargetOS
	}
	return "linux"
}

func verifyInitialHostOverlay(ctx context.Context, config upgradeCommandConfig) (*verifiedOverlayPlan, error) {
	if ctx == nil {
		return nil, errors.New("context must not be nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	pubKeyBytes, err := hex.DecodeString(config.publicKey)
	if err != nil || len(pubKeyBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid trusted public key hex: %v", err)
	}

	if config.channel != "stable" && config.channel != "beta" {
		return nil, fmt.Errorf("invalid channel %q", config.channel)
	}

	rawHosts := strings.Split(config.allowedHosts, ",")
	var allowedHosts []string
	seenHosts := make(map[string]bool)
	for _, h := range rawHosts {
		trimmed := strings.TrimSpace(h)
		if trimmed == "" || seenHosts[trimmed] {
			return nil, fmt.Errorf("invalid or duplicate allowed host %q", h)
		}
		seenHosts[trimmed] = true
		allowedHosts = append(allowedHosts, trimmed)
	}
	if len(allowedHosts) == 0 {
		return nil, errors.New("allowed hosts list must not be empty")
	}

	if !filepath.IsAbs(config.envelope) || filepath.Clean(config.envelope) != config.envelope {
		return nil, fmt.Errorf("envelope path must be clean absolute: %s", config.envelope)
	}
	envInfo, err := os.Lstat(config.envelope)
	if err != nil || !envInfo.Mode().IsRegular() || envInfo.Mode()&os.ModeSymlink != 0 || envInfo.Size() > 1<<20 {
		return nil, fmt.Errorf("cannot stat envelope file: %v", err)
	}
	envelopeBytes, err := os.ReadFile(config.envelope)
	if err != nil {
		return nil, fmt.Errorf("failed to read envelope: %v", err)
	}

	if !filepath.IsAbs(config.hostBundle) || filepath.Clean(config.hostBundle) != config.hostBundle {
		return nil, fmt.Errorf("host bundle path must be clean absolute: %s", config.hostBundle)
	}

	targetOS := overlayTargetOS()
	opts := desktopupdate.CheckUpdateOptions{
		PublicKey:       pubKeyBytes,
		TargetOS:        targetOS,
		TargetArch:      runtime.GOARCH,
		AllowedChannel:  config.channel,
		CurrentSequence: 0,
		CurrentVersion:  "",
		CurrentTime:     time.Now().UTC(),
		AllowedHosts:    allowedHosts,
		MaxArtifactSize: desktopupdate.MaxArtifactSizeBytes,
	}

	bundle, err := desktopupdate.VerifyHostBundle(ctx, config.hostBundle, envelopeBytes, opts)
	if err != nil {
		return nil, fmt.Errorf("host bundle verification failed: %w", err)
	}

	manifest := bundle.Manifest()

	// Initial overlay requires Backend.Mode == "unchanged", reject candidate mode
	if manifest.Backend.Mode != "unchanged" {
		_ = bundle.Close()
		return nil, fmt.Errorf("initial native overlay requires backend mode 'unchanged', got %q", manifest.Backend.Mode)
	}
	if manifest.Backend.FromBinding != manifest.Backend.ToBinding {
		_ = bundle.Close()
		return nil, errors.New("unchanged backend mode requires FromBinding == ToBinding")
	}
	if manifest.Backend.ToBinding != config.bindingSHA256 {
		_ = bundle.Close()
		return nil, fmt.Errorf("bundle backend binding %q does not match expected %q", manifest.Backend.ToBinding, config.bindingSHA256)
	}

	// Locate and classify fixed required members
	files := make(map[string]desktopupdate.HostBundleFile, len(manifest.Files))
	for _, f := range manifest.Files {
		files[f.Path] = f
	}

	findMember := func(paths ...string) (string, desktopupdate.HostBundleFile, bool) {
		for _, p := range paths {
			if f, ok := files[p]; ok {
				return p, f, true
			}
		}
		return "", desktopupdate.HostBundleFile{}, false
	}

	bootstrapPath, bootstrapFile, ok := findMember("controller/installer/acornfox-host-bootstrap", overlayMemberBootstrap)
	if !ok || bootstrapFile.Mode != 0755 || bootstrapFile.Size < 1 {
		_ = bundle.Close()
		return nil, fmt.Errorf("missing or invalid stable bootstrap member %q", overlayMemberBootstrap)
	}

	launcherPath := manifest.Launcher
	if launcherPath == "" {
		launcherPath = overlayMemberLauncher
	}
	launcherFile, ok := files[launcherPath]
	if !ok || launcherFile.Mode != 0755 || launcherFile.Size < 1 {
		_ = bundle.Close()
		return nil, fmt.Errorf("missing or invalid launcher member %q", launcherPath)
	}

	controllerPath := manifest.Controller
	if controllerPath == "" {
		controllerPath = overlayMemberController
	}
	controllerFile, ok := files[controllerPath]
	if !ok || controllerFile.Mode != 0755 || controllerFile.Size < 1 {
		_ = bundle.Close()
		return nil, fmt.Errorf("missing or invalid controller member %q", overlayMemberController)
	}

	// Equal C0 requirement: launcher and controller hashes must be identical
	if launcherFile.SHA256 != controllerFile.SHA256 {
		_ = bundle.Close()
		return nil, fmt.Errorf("equal C0 source contract violation: launcher SHA %s != controller SHA %s", launcherFile.SHA256, controllerFile.SHA256)
	}

	hostPolicyPath, hostPolicyFile, ok := findMember("controller/installer/host-update-policy.json", overlayMemberHostPolicy)
	if !ok || hostPolicyFile.Mode != 0644 || hostPolicyFile.Size < 1 {
		_ = bundle.Close()
		return nil, fmt.Errorf("missing or invalid host policy member %q", overlayMemberHostPolicy)
	}

	guestWorkerPath, guestWorkerFile, ok := findMember("controller/installer/acornfox-guest-update", overlayMemberGuestWorker)
	if !ok || guestWorkerFile.Mode != 0755 || guestWorkerFile.Size < 1 {
		_ = bundle.Close()
		return nil, fmt.Errorf("missing or invalid guest worker member %q", overlayMemberGuestWorker)
	}

	guestPolicyPath, guestPolicyFile, ok := findMember("controller/installer/guest-update-policy.json", overlayMemberGuestPolicy)
	if !ok || guestPolicyFile.Mode != 0644 || guestPolicyFile.Size < 1 {
		_ = bundle.Close()
		return nil, fmt.Errorf("missing or invalid guest policy member %q", overlayMemberGuestPolicy)
	}

	canonicalUnitPath, canonicalUnitFile, ok := findMember("controller/installer/acornfox-host-bootstrap.service", overlayMemberCanonicalUnit)
	if !ok || canonicalUnitFile.Mode != 0644 || canonicalUnitFile.Size != int64(len(hostoverlay.BootstrapUnitBytes())) {
		_ = bundle.Close()
		return nil, fmt.Errorf("missing or invalid canonical unit member %q", overlayMemberCanonicalUnit)
	}
	if canonicalUnitFile.SHA256 != hostoverlay.BootstrapUnitSHA256() {
		_ = bundle.Close()
		return nil, fmt.Errorf("canonical unit manifest hash mismatch: got %s, want %s", canonicalUnitFile.SHA256, hostoverlay.BootstrapUnitSHA256())
	}

	// Compare canonical unit raw bytes from hostoverlay
	var unitBuf bytes.Buffer
	if err := bundle.ReadFile(canonicalUnitPath, &unitBuf); err != nil {
		_ = bundle.Close()
		return nil, fmt.Errorf("failed to read unit member bytes: %w", err)
	}
	if !bytes.Equal(unitBuf.Bytes(), hostoverlay.BootstrapUnitBytes()) {
		_ = bundle.Close()
		return nil, errors.New("unit member bytes do not match canonical hostoverlay bytes")
	}

	// Validate host policy member against trusted inputs
	var hpBuf bytes.Buffer
	if err := bundle.ReadFile(hostPolicyPath, &hpBuf); err != nil {
		_ = bundle.Close()
		return nil, fmt.Errorf("failed to read host policy member: %w", err)
	}
	var hp hostconfig.ConfigPolicyFile
	decHP := json.NewDecoder(bytes.NewReader(hpBuf.Bytes()))
	decHP.DisallowUnknownFields()
	if err := decHP.Decode(&hp); err != nil {
		_ = bundle.Close()
		return nil, fmt.Errorf("failed to decode host policy JSON: %w", err)
	}
	var trailingHP any
	if err := decHP.Decode(&trailingHP); !errors.Is(err, io.EOF) {
		_ = bundle.Close()
		return nil, errors.New("unexpected trailing data in host policy JSON")
	}
	canonicalHP, err := json.Marshal(hp)
	if err != nil || !bytes.Equal(hpBuf.Bytes(), canonicalHP) {
		_ = bundle.Close()
		return nil, errors.New("host policy JSON must be strictly canonical")
	}
	if hp.OS != targetOS || hp.Arch != runtime.GOARCH || hp.Channel != config.channel ||
		hp.PublicKeyHex != strings.ToLower(config.publicKey) || !slices.Equal(hp.AllowedHosts, allowedHosts) ||
		hp.MaxArtifactSize < 1 || hp.MaxArtifactSize > desktopupdate.MaxArtifactSizeBytes {
		_ = bundle.Close()
		return nil, errors.New("host policy content does not match trusted inputs")
	}

	parsedIndexURL, err := url.Parse(hp.IndexURL)
	if err != nil {
		_ = bundle.Close()
		return nil, errors.New("invalid host policy index URL")
	}
	indexHostname := strings.ToLower(parsedIndexURL.Hostname())
	if parsedIndexURL.Scheme != "https" || indexHostname == "" ||
		!slices.Contains(allowedHosts, indexHostname) || parsedIndexURL.User != nil ||
		parsedIndexURL.Fragment != "" || parsedIndexURL.RawQuery != "" ||
		(parsedIndexURL.Port() != "" && parsedIndexURL.Port() != "443") {
		_ = bundle.Close()
		return nil, errors.New("host policy index URL does not match trusted inputs")
	}

	// Validate guest policy member against trusted inputs
	var gpBuf bytes.Buffer
	if err := bundle.ReadFile(guestPolicyPath, &gpBuf); err != nil {
		_ = bundle.Close()
		return nil, fmt.Errorf("failed to read guest policy member: %w", err)
	}
	var gp overlayGuestPolicy
	decGP := json.NewDecoder(bytes.NewReader(gpBuf.Bytes()))
	decGP.DisallowUnknownFields()
	if err := decGP.Decode(&gp); err != nil {
		_ = bundle.Close()
		return nil, fmt.Errorf("failed to decode guest policy JSON: %w", err)
	}
	var trailingGP any
	if err := decGP.Decode(&trailingGP); !errors.Is(err, io.EOF) {
		_ = bundle.Close()
		return nil, errors.New("unexpected trailing data in guest policy JSON")
	}
	if gp.Schema != 1 || gp.HostOS != targetOS || gp.HostArch != runtime.GOARCH || gp.Channel != config.channel ||
		!bytes.Equal(gp.PublicKey, pubKeyBytes) || !slices.Equal(gp.AllowedHosts, allowedHosts) ||
		gp.MaxArtifactSize < 1 || gp.MaxArtifactSize > desktopupdate.MaxArtifactSizeBytes {
		_ = bundle.Close()
		return nil, errors.New("guest policy content does not match trusted inputs")
	}

	return &verifiedOverlayPlan{
		bundle:            bundle,
		manifest:          manifest,
		bootstrapPath:     bootstrapPath,
		bootstrapFile:     bootstrapFile,
		launcherPath:      launcherPath,
		launcherFile:      launcherFile,
		controllerPath:    controllerPath,
		controllerFile:    controllerFile,
		hostPolicyPath:    hostPolicyPath,
		hostPolicyFile:    hostPolicyFile,
		guestWorkerPath:   guestWorkerPath,
		guestWorkerFile:   guestWorkerFile,
		guestPolicyPath:   guestPolicyPath,
		guestPolicyFile:   guestPolicyFile,
		canonicalUnitPath: canonicalUnitPath,
		canonicalUnitFile: canonicalUnitFile,
	}, nil
}

func stageVerifiedMember(bundle *desktopupdate.VerifiedHostBundle, memberName, destPath string, mode os.FileMode, expectedSHA string) error {
	f, err := os.OpenFile(destPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, mode)
	if err != nil {
		return err
	}
	h := sha256.New()
	w := io.MultiWriter(f, h)
	if err := bundle.ReadFile(memberName, w); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if hex.EncodeToString(h.Sum(nil)) != expectedSHA {
		return errors.New("staged member SHA256 mismatch")
	}
	return nil
}

func runInitialHostOverlayPreflight(ctx context.Context, config upgradeCommandConfig, stdout io.Writer, role string, deps acornFoxCleanDependencies) int {
	plan, err := verifyInitialHostOverlay(ctx, config)
	if err != nil {
		return writeAcornFoxCleanError(stdout, exitIneligible, "overlay_ineligible")
	}
	defer plan.bundle.Close()

	return writeUpgradeJSON(stdout, exitOK, map[string]any{
		"ok":      true,
		"command": config.command,
		"receipt": map[string]any{
			"schema_version":          1,
			"bootstrap_version":       plan.manifest.Version,
			"binding_sha256":          config.bindingSHA256,
			"stable_bootstrap_sha256": plan.bootstrapFile.SHA256,
			"c0_sha256":               plan.controllerFile.SHA256,
			"unit_sha256":             plan.canonicalUnitFile.SHA256,
			"host_policy_sha256":      plan.hostPolicyFile.SHA256,
			"guest_worker_sha256":     plan.guestWorkerFile.SHA256,
			"guest_policy_sha256":     plan.guestPolicyFile.SHA256,
		},
	})
}

func runInitialHostOverlayApply(ctx context.Context, config upgradeCommandConfig, stdout io.Writer, role string, deps acornFoxCleanDependencies) int {
	plan, err := verifyInitialHostOverlay(ctx, config)
	if err != nil {
		return writeAcornFoxCleanError(stdout, exitIneligible, "overlay_ineligible")
	}
	defer plan.bundle.Close()

	// Stage verified members into root-private temporary directory
	stageDir, err := os.MkdirTemp("", ".acornfox-overlay-stage-")
	if err != nil {
		return writeAcornFoxCleanError(stdout, exitInternal, "staging_failed")
	}
	_ = os.Chmod(stageDir, 0700)
	defer os.RemoveAll(stageDir)

	stagedStableBootstrap := filepath.Join(stageDir, "acornfox-host-bootstrap")
	if err := stageVerifiedMember(plan.bundle, plan.bootstrapPath, stagedStableBootstrap, 0755, plan.bootstrapFile.SHA256); err != nil {
		return writeAcornFoxCleanError(stdout, exitInternal, "staging_failed")
	}

	stagedC0 := filepath.Join(stageDir, "acornfox-host-update")
	if err := stageVerifiedMember(plan.bundle, plan.controllerPath, stagedC0, 0755, plan.controllerFile.SHA256); err != nil {
		return writeAcornFoxCleanError(stdout, exitInternal, "staging_failed")
	}

	stagedHostPolicy := filepath.Join(stageDir, "host-update-policy.json")
	if err := stageVerifiedMember(plan.bundle, plan.hostPolicyPath, stagedHostPolicy, 0600, plan.hostPolicyFile.SHA256); err != nil {
		return writeAcornFoxCleanError(stdout, exitInternal, "staging_failed")
	}

	stagedGuestWorker := filepath.Join(stageDir, "acornfox-guest-update")
	if err := stageVerifiedMember(plan.bundle, plan.guestWorkerPath, stagedGuestWorker, 0755, plan.guestWorkerFile.SHA256); err != nil {
		return writeAcornFoxCleanError(stdout, exitInternal, "staging_failed")
	}

	stagedGuestPolicy := filepath.Join(stageDir, "guest-update-policy.json")
	if err := stageVerifiedMember(plan.bundle, plan.guestPolicyPath, stagedGuestPolicy, 0600, plan.guestPolicyFile.SHA256); err != nil {
		return writeAcornFoxCleanError(stdout, exitInternal, "staging_failed")
	}

	// 1. Call guest provision IN-PROCESS
	guestReq := overlayGuestProvisionRequest{
		Kind:                 "linux-local",
		BootstrapHostVersion: plan.manifest.Version,
		WorkerSourcePath:     stagedGuestWorker,
		ExpectedWorkerSHA256: plan.guestWorkerFile.SHA256,
		PolicySourcePath:     stagedGuestPolicy,
		ExpectedPolicySHA256: plan.guestPolicyFile.SHA256,
	}
	if deps.guestProvision == nil {
		return writeAcornFoxCleanError(stdout, exitIneligible, "guest_provision_unavailable")
	}
	_, err = deps.guestProvision(ctx, guestReq)
	if err != nil {
		return writeAcornFoxCleanError(stdout, exitRecovery, "guest_provision_failed")
	}

	// 2. Call host provision IN-PROCESS
	hostReq := hostprovision.ProvisionRequest{
		BootstrapVersion:        plan.manifest.Version,
		BootstrapBackendBinding: plan.manifest.Backend.ToBinding,
		StableBootstrapSource:   stagedStableBootstrap,
		ExpectedBootstrapSHA256: plan.bootstrapFile.SHA256,
		ManagedC0Source:         stagedC0,
		ExpectedC0SHA256:        plan.controllerFile.SHA256,
		PolicySourcePath:        stagedHostPolicy,
		ExpectedPolicySHA256:    plan.hostPolicyFile.SHA256,
	}
	if deps.hostProvision == nil {
		return writeAcornFoxCleanError(stdout, exitIneligible, "host_provision_unavailable")
	}
	hostReceipt, err := deps.hostProvision(ctx, hostReq)
	if err != nil {
		return writeAcornFoxCleanOverlayHostError(stdout, err)
	}

	return writeUpgradeJSON(stdout, exitOK, map[string]any{
		"ok":      true,
		"command": config.command,
		"receipt": map[string]any{
			"schema_version":            1,
			"bootstrap_version":         hostReceipt.BootstrapVersion,
			"bootstrap_backend_binding": hostReceipt.BootstrapBackendBinding,
			"instance_id":               hostReceipt.InstanceID,
			"bootstrap_id":              hostReceipt.BootstrapID,
			"stable_bootstrap_sha256":   hostReceipt.StableBootstrapSHA256,
			"launcher_sha256":           hostReceipt.LauncherSHA256,
			"controller_sha256":         hostReceipt.ControllerSHA256,
			"config_sha256":             hostReceipt.ConfigSHA256,
			"policy_sha256":             hostReceipt.PolicySHA256,
		},
	})
}

func writeAcornFoxCleanOverlayHostError(stdout io.Writer, err error) int {
	switch {
	case errors.Is(err, hostprovision.ErrPrivilegeRequired):
		return writeAcornFoxCleanError(stdout, exitIneligible, "root_ineligible")
	case errors.Is(err, hostprovision.ErrInvalidRequest):
		return writeAcornFoxCleanError(stdout, exitArgs, "invalid_arguments")
	case errors.Is(err, hostprovision.ErrProvisionConflict):
		return writeAcornFoxCleanError(stdout, exitConflict, "host_provision_conflict")
	case errors.Is(err, hostprovision.ErrObserveFailed):
		return writeAcornFoxCleanError(stdout, exitRecovery, "host_observe_failed")
	case errors.Is(err, hostprovision.ErrInsecurePath):
		return writeAcornFoxCleanError(stdout, exitConflict, "host_insecure_path")
	default:
		return writeAcornFoxCleanError(stdout, exitRecovery, "host_provision_unknown")
	}
}
