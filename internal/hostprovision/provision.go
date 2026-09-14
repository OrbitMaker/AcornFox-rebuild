package hostprovision

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"

	"github.com/open-card/open-card/internal/desktopupdate"
	"github.com/open-card/open-card/internal/hostconfig"
	"github.com/open-card/open-card/internal/hostoverlay"
)

type guestInstanceFile struct {
	SchemaVersion        int    `json:"schema_version"`
	Kind                 string `json:"kind"`
	NativeID             string `json:"native_id"`
	InstanceID           string `json:"instance_id"`
	MarkerSHA256         string `json:"marker_sha256"`
	BootstrapHostVersion string `json:"bootstrap_host_version"`
}

// Provision is the sole production entry point. It always enforces root privileges,
// immutable compile-time production paths, and the privileged local guest transport.
// There is zero runtime or environment test bypass surface.
func Provision(ctx context.Context, req ProvisionRequest) (*ProvisionReceipt, error) {
	if os.Geteuid() != 0 {
		return nil, ErrPrivilegeRequired
	}
	return provisionWithOptions(ctx, req, defaultProductionOptions())
}

// provisionWithOptions is unexported for internal package and fixture testing.
func provisionWithOptions(ctx context.Context, req ProvisionRequest, opts provisionOptions) (*ProvisionReceipt, error) {
	// 1. Privilege check
	if !opts.allowNonRoot && os.Geteuid() != 0 {
		return nil, ErrPrivilegeRequired
	}

	// 2. Request validation
	if ctx == nil {
		return nil, ErrInvalidRequest
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if _, err := desktopupdate.ParseSemver(req.BootstrapVersion); err != nil {
		return nil, fmt.Errorf("%w: invalid bootstrap semver %q: %v", ErrInvalidRequest, req.BootstrapVersion, err)
	}
	if !isValidHexSHA256(req.BootstrapBackendBinding) {
		return nil, fmt.Errorf("%w: invalid bootstrap backend binding sha256 hex", ErrInvalidRequest)
	}
	if !isValidHexSHA256(req.ExpectedBootstrapSHA256) {
		return nil, fmt.Errorf("%w: invalid expected bootstrap sha256 hex", ErrInvalidRequest)
	}
	if !isValidHexSHA256(req.ExpectedC0SHA256) {
		return nil, fmt.Errorf("%w: invalid expected C0 sha256 hex", ErrInvalidRequest)
	}
	if !isValidHexSHA256(req.ExpectedPolicySHA256) {
		return nil, fmt.Errorf("%w: invalid expected policy sha256 hex", ErrInvalidRequest)
	}

	// 3. Resolve target paths
	paths := opts.paths
	if paths.BootstrapExecutable == "" {
		paths = DefaultProductionPaths()
	}
	if paths.UnitPath == "" {
		paths.UnitPath = hostoverlay.BootstrapUnitPath
	}
	if paths.EnableLinkPath == "" {
		paths.EnableLinkPath = hostoverlay.BootstrapEnableLinkPath
	}
	if err := validateTargetPaths(paths); err != nil {
		return nil, err
	}

	targetOS := "linux"
	if opts.allowNonRoot {
		targetOS = runtime.GOOS
	}

	// 4. Read, pin, and verify source files
	// a) Stable bootstrap binary
	bootstrapBytes, err := readSourceFile(req.StableBootstrapSource, 64<<20, opts.allowNonRoot)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to read bootstrap source: %v", ErrInvalidRequest, err)
	}
	if sha256Hex(bootstrapBytes) != req.ExpectedBootstrapSHA256 {
		return nil, fmt.Errorf("%w: bootstrap source SHA256 mismatch", ErrInvalidRequest)
	}
	if err := verifyExecutableBinary(bootstrapBytes, targetOS, runtime.GOARCH); err != nil {
		return nil, err
	}

	// b) Managed C0 binary
	c0Bytes, err := readSourceFile(req.ManagedC0Source, 64<<20, opts.allowNonRoot)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to read C0 source: %v", ErrInvalidRequest, err)
	}
	if sha256Hex(c0Bytes) != req.ExpectedC0SHA256 {
		return nil, fmt.Errorf("%w: C0 source SHA256 mismatch", ErrInvalidRequest)
	}
	if err := verifyExecutableBinary(c0Bytes, targetOS, runtime.GOARCH); err != nil {
		return nil, err
	}

	// c) Host policy JSON with strict canonical byte equality (NO TrimSpace)
	policyBytes, err := readSourceFile(req.PolicySourcePath, hostconfig.MaxConfigSize, opts.allowNonRoot)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to read policy source: %v", ErrInvalidRequest, err)
	}

	var policy hostconfig.ConfigPolicyFile
	dec := json.NewDecoder(bytes.NewReader(policyBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&policy); err != nil {
		return nil, fmt.Errorf("%w: policy JSON decode failed: %v", ErrInvalidRequest, err)
	}
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: unexpected trailing data in policy JSON", ErrInvalidRequest)
	}

	canonicalPolicy, err := json.Marshal(policy)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to marshal canonical policy: %v", ErrInvalidRequest, err)
	}
	// Require EXACT raw byte equality without leading/trailing whitespace or newlines
	if !bytes.Equal(policyBytes, canonicalPolicy) {
		return nil, fmt.Errorf("%w: policy source JSON must be strictly canonical without leading/trailing whitespace, newlines, key reordering, or duplicate keys", ErrInvalidRequest)
	}
	if sha256Hex(policyBytes) != req.ExpectedPolicySHA256 {
		return nil, fmt.Errorf("%w: policy source SHA256 mismatch", ErrInvalidRequest)
	}

	if policy.OS != targetOS || policy.Arch != runtime.GOARCH {
		return nil, fmt.Errorf("%w: policy OS/Arch mismatch: %s/%s vs %s/%s", ErrInvalidRequest, policy.OS, policy.Arch, targetOS, runtime.GOARCH)
	}
	if policy.Channel != "stable" && policy.Channel != "beta" {
		return nil, fmt.Errorf("%w: invalid policy channel %q", ErrInvalidRequest, policy.Channel)
	}
	if !isValidHexSHA256(policy.PublicKeyHex) {
		return nil, fmt.Errorf("%w: invalid policy public key length or format", ErrInvalidRequest)
	}
	if !strings.HasPrefix(policy.IndexURL, "https://") {
		return nil, fmt.Errorf("%w: policy index URL must use https", ErrInvalidRequest)
	}
	if len(policy.AllowedHosts) == 0 {
		return nil, fmt.Errorf("%w: policy allowed hosts cannot be empty", ErrInvalidRequest)
	}
	if policy.MaxArtifactSize < 1 || policy.MaxArtifactSize > desktopupdate.MaxArtifactSizeBytes {
		return nil, fmt.Errorf("%w: invalid policy max artifact size %d", ErrInvalidRequest, policy.MaxArtifactSize)
	}

	// 5. Read and validate fixed guest-instance.json
	guestRaw, err := readSourceFile(paths.GuestInstancePath, 64<<10, opts.allowNonRoot)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to read guest instance %q: %v", ErrProvisionConflict, paths.GuestInstancePath, err)
	}
	var guestInst guestInstanceFile
	gDec := json.NewDecoder(bytes.NewReader(guestRaw))
	gDec.DisallowUnknownFields()
	if err := gDec.Decode(&guestInst); err != nil {
		return nil, fmt.Errorf("%w: guest instance decode failed: %v", ErrProvisionConflict, err)
	}
	if guestInst.SchemaVersion != 1 || guestInst.Kind != "linux-local" || !isValidHexSHA256(guestInst.InstanceID) {
		return nil, fmt.Errorf("%w: guest instance invalid schema/kind/instance_id", ErrProvisionConflict)
	}
	if guestInst.BootstrapHostVersion != req.BootstrapVersion {
		return nil, fmt.Errorf("%w: guest instance bootstrap version %q mismatch requested %q", ErrProvisionConflict, guestInst.BootstrapHostVersion, req.BootstrapVersion)
	}

	// 6. PRE-MUTATION CLASSIFICATION BEFORE ANY MKDIR OR LOCKFILE CREATION
	cfgInfo, cfgErr := os.Lstat(paths.ConfigPath)
	if cfgErr == nil {
		if !cfgInfo.Mode().IsRegular() || cfgInfo.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("%w: existing config is not a regular file", ErrProvisionConflict)
		}
		// Config exists -> CONFIGURED RE-ENTRY
		// Strictly require all dependencies to exist beforehand without mutating anything
		return validateConfiguredReentryPreclassified(
			ctx, paths, req, opts, guestInst.InstanceID, bootstrapBytes, c0Bytes, policy, canonicalPolicy,
		)
	} else if !errors.Is(cfgErr, os.ErrNotExist) {
		return nil, cfgErr
	}

	// Config is absent -> FRESH / RESUME PROVISIONING
	// Strictly inspect existing inventory BEFORE creating any directories or lockfile
	return freshOrResumeProvisioningPreclassified(
		ctx, paths, req, opts, guestInst.InstanceID, bootstrapBytes, c0Bytes, policy, canonicalPolicy,
	)
}

func validateConfiguredReentryPreclassified(
	ctx context.Context,
	paths ProvisionPaths,
	req ProvisionRequest,
	opts provisionOptions,
	expectedInstanceID string,
	bootstrapBytes, c0Bytes []byte,
	expectedPolicy hostconfig.ConfigPolicyFile,
	canonicalPolicy []byte,
) (*ProvisionReceipt, error) {
	// 1. In configured re-entry, ALL dependencies must pre-exist with exact modes and root ownership.
	// Missing dependencies must fail closed without repairing state or creating new locks.
	sInfo, err := os.Lstat(paths.SlotsRoot)
	if err != nil || !sInfo.IsDir() || sInfo.Mode()&os.ModeSymlink != 0 || sInfo.Mode().Perm() != 0700 {
		return nil, fmt.Errorf("%w: slots root missing or invalid during reentry: %v", ErrProvisionConflict, err)
	}
	lInfo, err := os.Lstat(paths.SlotsLock)
	if err != nil || !lInfo.Mode().IsRegular() || lInfo.Mode()&os.ModeSymlink != 0 || lInfo.Mode().Perm() != 0600 {
		return nil, fmt.Errorf("%w: slots lock missing or invalid during reentry: %v", ErrProvisionConflict, err)
	}
	cInfo, err := os.Lstat(paths.ControllerRoot)
	if err != nil || !cInfo.IsDir() || cInfo.Mode()&os.ModeSymlink != 0 || cInfo.Mode().Perm() != 0700 {
		return nil, fmt.Errorf("%w: controller root missing or invalid during reentry: %v", ErrProvisionConflict, err)
	}
	bInfo, err := os.Lstat(paths.BootstrapExecutable)
	if err != nil || !bInfo.Mode().IsRegular() || bInfo.Mode()&os.ModeSymlink != 0 || bInfo.Mode().Perm() != 0755 {
		return nil, fmt.Errorf("%w: bootstrap executable missing or invalid during reentry: %v", ErrProvisionConflict, err)
	}
	brInfo, err := os.Lstat(paths.BootstrapRoot)
	if err != nil || !brInfo.IsDir() || brInfo.Mode()&os.ModeSymlink != 0 || brInfo.Mode().Perm() != 0755 {
		return nil, fmt.Errorf("%w: bootstrap root missing or invalid during reentry: %v", ErrProvisionConflict, err)
	}
	lpInfo, err := os.Lstat(paths.LauncherPath)
	if err != nil || !lpInfo.Mode().IsRegular() || lpInfo.Mode()&os.ModeSymlink != 0 || lpInfo.Mode().Perm() != 0755 {
		return nil, fmt.Errorf("%w: launcher binary missing or invalid during reentry: %v", ErrProvisionConflict, err)
	}
	cpInfo, err := os.Lstat(paths.ControllerPath)
	if err != nil || !cpInfo.Mode().IsRegular() || cpInfo.Mode()&os.ModeSymlink != 0 || cpInfo.Mode().Perm() != 0755 {
		return nil, fmt.Errorf("%w: controller binary missing or invalid during reentry: %v", ErrProvisionConflict, err)
	}
	uInfo, err := os.Lstat(paths.UnitPath)
	if err != nil || !uInfo.Mode().IsRegular() || uInfo.Mode()&os.ModeSymlink != 0 || uInfo.Mode().Perm() != 0644 {
		return nil, fmt.Errorf("%w: bootstrap unit missing or invalid during reentry: %v", ErrProvisionConflict, err)
	}

	if !opts.allowNonRoot {
		for _, info := range []os.FileInfo{sInfo, lInfo, cInfo, bInfo, brInfo, lpInfo, cpInfo, uInfo} {
			st, ok := info.Sys().(*syscall.Stat_t)
			if !ok || st.Uid != 0 || st.Gid != 0 {
				return nil, fmt.Errorf("%w: target dependency not owned by root:root", ErrInsecurePath)
			}
		}
	}

	// 2. Open existing lockfile WITHOUT O_CREATE and retain lockOwner through entire reentry
	lockOwner, err := acquireProvisionLock(paths.SlotsLock, false, opts.allowNonRoot)
	if err != nil {
		return nil, err
	}
	defer lockOwner.Close()

	if err := lockOwner.Validate(); err != nil {
		return nil, err
	}

	if opts.ancestorHook != nil {
		if err := opts.ancestorHook("after-lock-return", paths.SlotsLock); err != nil {
			return nil, err
		}
		if err := lockOwner.Validate(); err != nil {
			return nil, err
		}
	}

	// 3. Read and validate existing config file fail-closed
	cfg, err := hostconfig.ReadAndValidateConfigFile(paths.ConfigPath, paths.BootstrapRoot, opts.allowNonRoot)
	if err != nil {
		return nil, fmt.Errorf("%w: config validation failed on reentry: %v", ErrProvisionConflict, err)
	}
	defer cfg.Close()

	// Strict equality check with inputs
	if cfg.InstanceID != expectedInstanceID {
		return nil, fmt.Errorf("%w: config instance ID %q mismatch expected %q", ErrProvisionConflict, cfg.InstanceID, expectedInstanceID)
	}
	if cfg.BootstrapBackendBinding != req.BootstrapBackendBinding {
		return nil, fmt.Errorf("%w: config binding mismatch", ErrProvisionConflict)
	}
	if cfg.BootstrapSpec.Version != req.BootstrapVersion {
		return nil, fmt.Errorf("%w: config bootstrap spec version mismatch", ErrProvisionConflict)
	}
	if cfg.BootstrapSpec.Root != paths.BootstrapRoot {
		return nil, fmt.Errorf("%w: config bootstrap root mismatch", ErrProvisionConflict)
	}
	if cfg.BootstrapSpec.Launcher != "launcher/acornfox-host-launcher" || cfg.BootstrapSpec.Controller != "controller/acornfox-host-update" {
		return nil, fmt.Errorf("%w: config launcher/controller path mismatch", ErrProvisionConflict)
	}

	expectedC0SHA := req.ExpectedC0SHA256
	expectedC0Size := int64(len(c0Bytes))
	if len(cfg.BootstrapSpec.Files) != 2 {
		return nil, fmt.Errorf("%w: config bootstrap files count mismatch", ErrProvisionConflict)
	}
	var sawLauncher, sawController bool
	for _, f := range cfg.BootstrapSpec.Files {
		if f.SHA256 != expectedC0SHA || f.Size != expectedC0Size || f.Mode != 0755 {
			return nil, fmt.Errorf("%w: config bootstrap file %q content mismatch", ErrProvisionConflict, f.Path)
		}
		if f.Path == "launcher/acornfox-host-launcher" {
			sawLauncher = true
		}
		if f.Path == "controller/acornfox-host-update" {
			sawController = true
		}
	}
	if !sawLauncher || !sawController {
		return nil, fmt.Errorf("%w: config bootstrap files missing launcher or controller", ErrProvisionConflict)
	}

	// Canonical policy bytes comparison to eliminate hash drift
	cfgPolBytes, err := json.Marshal(cfg.Policy)
	if err != nil || !bytes.Equal(cfgPolBytes, canonicalPolicy) {
		return nil, fmt.Errorf("%w: config policy byte mismatch on reentry", ErrProvisionConflict)
	}

	// Verify stable bootstrap on disk
	if err := checkExistingTarget(paths.BootstrapExecutable, bootstrapBytes, 0755, opts.allowNonRoot); err != nil {
		return nil, fmt.Errorf("%w: stable bootstrap on disk mismatch: %v", ErrProvisionConflict, err)
	}

	// Verify launcher and controller on disk
	if err := checkExistingTarget(paths.LauncherPath, c0Bytes, 0755, opts.allowNonRoot); err != nil {
		return nil, fmt.Errorf("%w: launcher on disk mismatch: %v", ErrProvisionConflict, err)
	}
	if err := checkExistingTarget(paths.ControllerPath, c0Bytes, 0755, opts.allowNonRoot); err != nil {
		return nil, fmt.Errorf("%w: controller on disk mismatch: %v", ErrProvisionConflict, err)
	}

	// Verify stable bootstrap unit on disk
	if err := checkExistingTarget(paths.UnitPath, hostoverlay.BootstrapUnitBytes(), 0644, opts.allowNonRoot); err != nil {
		return nil, fmt.Errorf("%w: bootstrap unit on disk mismatch: %v", ErrProvisionConflict, err)
	}

	// Verify distinct inodes
	if err := checkDistinctInodes(paths.LauncherPath, paths.ControllerPath); err != nil {
		return nil, err
	}

	// Verify bootstrap tree via desktopupdate.PinHostBootstrap
	bootstrapSpec := convertBootstrapSpec(cfg.BootstrapSpec)
	pinned, err := desktopupdate.PinHostBootstrap(ctx, bootstrapSpec)
	if err != nil {
		return nil, fmt.Errorf("%w: pin host bootstrap failed on reentry: %v", ErrProvisionConflict, err)
	}
	defer pinned.Close()

	configRaw, err := readSafeFileContent(paths.ConfigPath, hostconfig.MaxConfigSize)
	if err != nil {
		return nil, err
	}

	// Final validation before returning success
	if err := lockOwner.Validate(); err != nil {
		return nil, err
	}

	// Verify or complete canonical enable link on reentry
	_, linkErr := os.Lstat(paths.EnableLinkPath)
	if linkErr == nil {
		if err := checkExistingEnableLink(paths.EnableLinkPath, hostoverlay.BootstrapEnableLinkTarget, opts.allowNonRoot); err != nil {
			return nil, fmt.Errorf("%w: bootstrap enable link invalid on reentry: %v", ErrProvisionConflict, err)
		}
	} else if errors.Is(linkErr, os.ErrNotExist) {
		// Valid resume: publish canonical enable link
		if err := publishSafeSymlink(paths.EnableLinkPath, hostoverlay.BootstrapEnableLinkTarget, opts.allowNonRoot); err != nil {
			return nil, err
		}
	} else {
		return nil, linkErr
	}

	return &ProvisionReceipt{
		InstanceID:              expectedInstanceID,
		BootstrapID:             pinned.ID(),
		BootstrapVersion:        req.BootstrapVersion,
		BootstrapBackendBinding: req.BootstrapBackendBinding,
		StableBootstrapSHA256:   req.ExpectedBootstrapSHA256,
		LauncherSHA256:          req.ExpectedC0SHA256,
		ControllerSHA256:        req.ExpectedC0SHA256,
		ConfigSHA256:            sha256Hex(configRaw),
		PolicySHA256:            sha256Hex(canonicalPolicy),
	}, nil
}

func freshOrResumeProvisioningPreclassified(
	ctx context.Context,
	paths ProvisionPaths,
	req ProvisionRequest,
	opts provisionOptions,
	expectedInstanceID string,
	bootstrapBytes, c0Bytes []byte,
	policy hostconfig.ConfigPolicyFile,
	canonicalPolicy []byte,
) (*ProvisionReceipt, error) {
	// 1. Pre-inspection: controller root must be absent or completely empty.
	// If it contains state.json or foreign files, FAIL CLOSED immediately without creating slots/lock!
	cInfo, cErr := os.Lstat(paths.ControllerRoot)
	if cErr == nil {
		if !cInfo.IsDir() || cInfo.Mode()&os.ModeSymlink != 0 || cInfo.Mode().Perm() != 0700 {
			return nil, fmt.Errorf("%w: controller root %q has invalid mode or is symlink", ErrProvisionConflict, paths.ControllerRoot)
		}
		if !opts.allowNonRoot {
			st, ok := cInfo.Sys().(*syscall.Stat_t)
			if !ok || st.Uid != 0 || st.Gid != 0 {
				return nil, fmt.Errorf("%w: controller root %q not owned by root:root", ErrInsecurePath, paths.ControllerRoot)
			}
		}
		cRoot, err := os.OpenRoot(paths.ControllerRoot)
		if err != nil {
			return nil, err
		}
		cf, err := cRoot.Open(".")
		if err != nil {
			_ = cRoot.Close()
			return nil, err
		}
		entries, err := cf.ReadDir(-1)
		_ = cf.Close()
		_ = cRoot.Close()
		if err != nil || len(entries) > 0 {
			return nil, fmt.Errorf("%w: controller root %q must be empty when config is absent (unknown state present)", ErrProvisionConflict, paths.ControllerRoot)
		}
	} else if !errors.Is(cErr, os.ErrNotExist) {
		return nil, cErr
	}

	// 2. Pre-inspection: slots root must be absent, empty, or contain only "lock".
	// If it contains ledger.json or foreign files, FAIL CLOSED immediately without creating locks!
	sInfo, sErr := os.Lstat(paths.SlotsRoot)
	if sErr == nil {
		if !sInfo.IsDir() || sInfo.Mode()&os.ModeSymlink != 0 || sInfo.Mode().Perm() != 0700 {
			return nil, fmt.Errorf("%w: slots root %q has invalid mode or is symlink", ErrProvisionConflict, paths.SlotsRoot)
		}
		if !opts.allowNonRoot {
			st, ok := sInfo.Sys().(*syscall.Stat_t)
			if !ok || st.Uid != 0 || st.Gid != 0 {
				return nil, fmt.Errorf("%w: slots root %q not owned by root:root", ErrInsecurePath, paths.SlotsRoot)
			}
		}
		sRoot, err := os.OpenRoot(paths.SlotsRoot)
		if err != nil {
			return nil, err
		}
		sf, err := sRoot.Open(".")
		if err != nil {
			_ = sRoot.Close()
			return nil, err
		}
		sEntries, err := sf.ReadDir(-1)
		_ = sf.Close()
		_ = sRoot.Close()
		if err != nil {
			return nil, err
		}
		for _, e := range sEntries {
			if e.Name() != "lock" {
				return nil, fmt.Errorf("%w: slots root contains unexpected file %q when config is absent", ErrProvisionConflict, e.Name())
			}
		}
	} else if !errors.Is(sErr, os.ErrNotExist) {
		return nil, sErr
	}

	// 3. Pre-inspection: stable bootstrap executable must match or be absent
	if _, err := os.Lstat(paths.BootstrapExecutable); err == nil {
		if err := checkExistingTarget(paths.BootstrapExecutable, bootstrapBytes, 0755, opts.allowNonRoot); err != nil {
			return nil, fmt.Errorf("%w: existing stable bootstrap binary mismatch: %v", ErrProvisionConflict, err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	// 4. Pre-inspection: external C0 tree must match or be absent
	if _, err := os.Lstat(paths.LauncherPath); err == nil {
		if err := checkExistingTarget(paths.LauncherPath, c0Bytes, 0755, opts.allowNonRoot); err != nil {
			return nil, fmt.Errorf("%w: existing launcher binary mismatch: %v", ErrProvisionConflict, err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if _, err := os.Lstat(paths.ControllerPath); err == nil {
		if err := checkExistingTarget(paths.ControllerPath, c0Bytes, 0755, opts.allowNonRoot); err != nil {
			return nil, fmt.Errorf("%w: existing controller binary mismatch: %v", ErrProvisionConflict, err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	// 5. Pre-inspection: stable bootstrap unit must match or be absent
	if _, err := os.Lstat(paths.UnitPath); err == nil {
		if err := checkExistingTarget(paths.UnitPath, hostoverlay.BootstrapUnitBytes(), 0644, opts.allowNonRoot); err != nil {
			return nil, fmt.Errorf("%w: existing bootstrap unit mismatch: %v", ErrProvisionConflict, err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	// 6. Pre-inspection: enable link must NOT exist when config is absent
	if _, err := os.Lstat(paths.EnableLinkPath); err == nil {
		return nil, fmt.Errorf("%w: bootstrap enable link exists before config", ErrProvisionConflict)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	// ALL PRE-EXISTING ITEMS HAVE BEEN VERIFIED ADMISSIBLE. NOW MUTATE.

	// 5. Ensure controller root and slots root exist with exact 0700
	if err := ensureDirSafeExact(paths.ControllerRoot, 0700, opts.allowNonRoot); err != nil {
		return nil, err
	}
	if err := ensureDirSafeExact(paths.SlotsRoot, 0700, opts.allowNonRoot); err != nil {
		return nil, err
	}

	// 6. Precreate / open slots lock with descriptor-relative validation and flock;
	// lockOwner retains slotsRoot and ancestor directory pins throughout whole provision.
	lockOwner, err := acquireProvisionLock(paths.SlotsLock, true, opts.allowNonRoot)
	if err != nil {
		return nil, err
	}
	defer lockOwner.Close()

	if err := lockOwner.Validate(); err != nil {
		return nil, err
	}

	if opts.ancestorHook != nil {
		if err := opts.ancestorHook("after-lock-return", paths.SlotsLock); err != nil {
			return nil, err
		}
		if err := lockOwner.Validate(); err != nil {
			return nil, err
		}
	}

	// 7. Install stable bootstrap executable if absent
	if _, err := os.Lstat(paths.BootstrapExecutable); errors.Is(err, os.ErrNotExist) {
		if err := ensureDirSafeExact(filepath.Dir(paths.BootstrapExecutable), 0755, opts.allowNonRoot); err != nil {
			return nil, err
		}
		if err := writeSafeFileRoot(paths.BootstrapExecutable, bootstrapBytes, 0755, opts.allowNonRoot, opts.ancestorHook); err != nil {
			return nil, err
		}
	}

	// 8. Ensure bootstrap directories exist with exact 0755
	if err := ensureDirSafeExact(paths.BootstrapRoot, 0755, opts.allowNonRoot); err != nil {
		return nil, err
	}
	if err := ensureDirSafeExact(filepath.Dir(paths.LauncherPath), 0755, opts.allowNonRoot); err != nil {
		return nil, err
	}
	if err := ensureDirSafeExact(filepath.Dir(paths.ControllerPath), 0755, opts.allowNonRoot); err != nil {
		return nil, err
	}

	// 9. Install launcher and controller if absent using descriptor-relative writeSafeFileRoot
	if _, err := os.Lstat(paths.LauncherPath); errors.Is(err, os.ErrNotExist) {
		if err := writeSafeFileRoot(paths.LauncherPath, c0Bytes, 0755, opts.allowNonRoot, opts.ancestorHook); err != nil {
			return nil, err
		}
	}
	if _, err := os.Lstat(paths.ControllerPath); errors.Is(err, os.ErrNotExist) {
		if err := writeSafeFileRoot(paths.ControllerPath, c0Bytes, 0755, opts.allowNonRoot, opts.ancestorHook); err != nil {
			return nil, err
		}
	}

	// Verify distinct inodes
	if err := checkDistinctInodes(paths.LauncherPath, paths.ControllerPath); err != nil {
		return nil, err
	}

	// Verify bootstrap tree has no unknown entries
	if err := verifyBootstrapDirTree(paths.BootstrapRoot, paths.LauncherPath, paths.ControllerPath); err != nil {
		return nil, err
	}

	// 10. Fresh Observe on GuestBackend before publishing config
	transport := opts.guestTransport
	if transport == nil {
		transport = defaultTransport()
	}
	if transport == nil {
		return nil, fmt.Errorf("%w: guest transport is unavailable", ErrObserveFailed)
	}

	guestBackend, err := desktopupdate.NewGuestBackend(desktopupdate.GuestBackendOptions{
		InstanceID:   expectedInstanceID,
		Architecture: runtime.GOARCH,
		Transport:    transport,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: failed to construct guest backend: %v", ErrProvisionConflict, err)
	}

	obs, err := guestBackend.Observe(ctx, "")
	if err != nil {
		return nil, fmt.Errorf("%w: guest backend observation failed: %v", ErrObserveFailed, err)
	}
	if !obs.LocalLoopback || obs.MigrationVersion != "0040" || obs.InstanceID != expectedInstanceID ||
		obs.Architecture != runtime.GOARCH || obs.Binding != req.BootstrapBackendBinding ||
		!obs.Ready || !obs.Finalized {
		return nil, fmt.Errorf("%w: guest backend observation contract violation or unready", ErrObserveFailed)
	}

	// Optional fault injection hook before publish
	if opts.beforePublishHook != nil {
		if err := opts.beforePublishHook(); err != nil {
			return nil, err
		}
	}

	// Publish canonical host unit BEFORE config
	if _, err := os.Lstat(paths.UnitPath); errors.Is(err, os.ErrNotExist) {
		if err := ensureDirSafeExact(filepath.Dir(paths.UnitPath), 0755, opts.allowNonRoot); err != nil {
			return nil, err
		}
		if err := writeSafeFileRoot(paths.UnitPath, hostoverlay.BootstrapUnitBytes(), 0644, opts.allowNonRoot, opts.ancestorHook); err != nil {
			return nil, err
		}
	}

	// 11. Construct canonical HostConfigFile
	files := []hostconfig.HostBundleFileConfig{
		{
			Path:   "controller/acornfox-host-update",
			SHA256: req.ExpectedC0SHA256,
			Size:   int64(len(c0Bytes)),
			Mode:   0755,
		},
		{
			Path:   "launcher/acornfox-host-launcher",
			SHA256: req.ExpectedC0SHA256,
			Size:   int64(len(c0Bytes)),
			Mode:   0755,
		},
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })

	targetOS := "linux"
	if opts.allowNonRoot {
		targetOS = runtime.GOOS
	}

	cfgObj := hostconfig.HostConfigFile{
		SchemaVersion:           1,
		InstanceID:              expectedInstanceID,
		BootstrapBackendBinding: req.BootstrapBackendBinding,
		BootstrapSpec: hostconfig.HostBootstrapSpecConfig{
			Root:               paths.BootstrapRoot,
			OS:                 targetOS,
			Architecture:       runtime.GOARCH,
			Version:            req.BootstrapVersion,
			Launcher:           "launcher/acornfox-host-launcher",
			Controller:         "controller/acornfox-host-update",
			ControllerProtocol: 1,
			InstanceProtocol:   1,
			BackendAPIProtocol: 1,
			Files:              files,
		},
		Policy: policy,
	}

	canonicalBytes, err := json.Marshal(cfgObj)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal host config: %w", err)
	}

	// Validate lock owner identity before publishing host-runtime.json
	if err := lockOwner.Validate(); err != nil {
		return nil, err
	}

	// 12. Publish host-runtime.json policy-last via descriptor-relative writeSafeFileRoot
	if err := ensureDirSafeExact(filepath.Dir(paths.ConfigPath), 0755, opts.allowNonRoot); err != nil {
		return nil, err
	}
	if err := writeSafeFileRoot(paths.ConfigPath, canonicalBytes, 0600, opts.allowNonRoot, opts.ancestorHook); err != nil {
		return nil, err
	}

	// 13. Post-publication readback via production loaders
	cfgRead, err := hostconfig.ReadAndValidateConfigFile(paths.ConfigPath, paths.BootstrapRoot, opts.allowNonRoot)
	if err != nil {
		return nil, fmt.Errorf("%w: post-publish ReadAndValidateConfigFile failed: %v", ErrProvisionConflict, err)
	}
	defer cfgRead.Close()

	bootstrapSpec := convertBootstrapSpec(cfgRead.BootstrapSpec)
	pinned, err := desktopupdate.PinHostBootstrap(ctx, bootstrapSpec)
	if err != nil {
		return nil, fmt.Errorf("%w: post-publish PinHostBootstrap failed: %v", ErrProvisionConflict, err)
	}
	defer pinned.Close()

	// 14. Publish canonical enable link AFTER config
	if err := publishSafeSymlink(paths.EnableLinkPath, hostoverlay.BootstrapEnableLinkTarget, opts.allowNonRoot); err != nil {
		return nil, err
	}

	// Final validation before returning success
	if err := lockOwner.Validate(); err != nil {
		return nil, err
	}

	return &ProvisionReceipt{
		InstanceID:              expectedInstanceID,
		BootstrapID:             pinned.ID(),
		BootstrapVersion:        req.BootstrapVersion,
		BootstrapBackendBinding: req.BootstrapBackendBinding,
		StableBootstrapSHA256:   req.ExpectedBootstrapSHA256,
		LauncherSHA256:          req.ExpectedC0SHA256,
		ControllerSHA256:        req.ExpectedC0SHA256,
		ConfigSHA256:            sha256Hex(canonicalBytes),
		PolicySHA256:            sha256Hex(canonicalPolicy),
	}, nil
}

func convertBootstrapSpec(c hostconfig.HostBootstrapSpecConfig) desktopupdate.HostBootstrapSpec {
	files := make([]desktopupdate.HostBundleFile, len(c.Files))
	for i, f := range c.Files {
		files[i] = desktopupdate.HostBundleFile{
			Path:   f.Path,
			SHA256: f.SHA256,
			Size:   f.Size,
			Mode:   f.Mode,
		}
	}
	return desktopupdate.HostBootstrapSpec{
		Root:               c.Root,
		OS:                 c.OS,
		Architecture:       c.Architecture,
		Version:            c.Version,
		Launcher:           c.Launcher,
		Controller:         c.Controller,
		ControllerProtocol: c.ControllerProtocol,
		InstanceProtocol:   c.InstanceProtocol,
		BackendAPIProtocol: c.BackendAPIProtocol,
		Files:              files,
	}
}

func validateTargetPaths(p ProvisionPaths) error {
	for name, path := range map[string]string{
		"BootstrapExecutable": p.BootstrapExecutable,
		"BootstrapRoot":       p.BootstrapRoot,
		"LauncherPath":        p.LauncherPath,
		"ControllerPath":      p.ControllerPath,
		"ConfigPath":          p.ConfigPath,
		"GuestInstancePath":   p.GuestInstancePath,
		"SlotsRoot":           p.SlotsRoot,
		"SlotsLock":           p.SlotsLock,
		"ControllerRoot":      p.ControllerRoot,
		"UnitPath":            p.UnitPath,
		"EnableLinkPath":      p.EnableLinkPath,
	} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return fmt.Errorf("%w: target path %s (%q) must be clean absolute", ErrInsecurePath, name, path)
		}
	}
	return nil
}

func verifyBootstrapDirTree(bootstrapRoot, launcherPath, controllerPath string) error {
	root, err := os.OpenRoot(bootstrapRoot)
	if err != nil {
		return err
	}
	defer root.Close()

	rf, err := root.Open(".")
	if err != nil {
		return err
	}
	entries, err := rf.ReadDir(-1)
	_ = rf.Close()
	if err != nil {
		return err
	}

	for _, e := range entries {
		if e.Name() != "launcher" && e.Name() != "controller" {
			return fmt.Errorf("%w: unexpected entry %q in bootstrap root", ErrProvisionConflict, e.Name())
		}
	}

	lf, err := root.Open("launcher")
	if err != nil {
		return err
	}
	lEntries, err := lf.ReadDir(-1)
	_ = lf.Close()
	if err != nil {
		return err
	}
	for _, e := range lEntries {
		if e.Name() != filepath.Base(launcherPath) {
			return fmt.Errorf("%w: unexpected entry %q in launcher dir", ErrProvisionConflict, e.Name())
		}
	}

	cf, err := root.Open("controller")
	if err != nil {
		return err
	}
	cEntries, err := cf.ReadDir(-1)
	_ = cf.Close()
	if err != nil {
		return err
	}
	for _, e := range cEntries {
		if e.Name() != filepath.Base(controllerPath) {
			return fmt.Errorf("%w: unexpected entry %q in controller dir", ErrProvisionConflict, e.Name())
		}
	}

	return nil
}
