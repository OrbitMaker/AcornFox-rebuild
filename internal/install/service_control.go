package install

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const productionServerUnitPath = "/etc/systemd/system/open-card-server.service"

const (
	productionCaddyPrivilegeDropPath = "/usr/bin/setpriv"
	productionCaddyUser              = "opencard-edge"
	productionEdgeEnvPath            = "/etc/open-card/open-card-edge.env"
	edgeConfigArtifactName           = "open-card-edge.Caddyfile"
	edgeCaddyRelativePath            = "bin/caddy"
	edgeTemplateRelativePath         = "caddy/open-card-edge.Caddyfile.example"
	edgeRuntimeHome                  = "/var/lib/open-card-edge/home"
	edgeRuntimeData                  = "/var/lib/open-card-edge/data"
	edgeRuntimeConfig                = "/var/lib/open-card-edge/config"
	edgeRuntimeLog                   = "/var/log/open-card-edge"
	edgeEnvCanonicalComment          = "# Edge runtime state; no domain, certificate, password, token, or cloud credential belongs here."
)

type ServiceUnit string

const (
	ServiceEdge     ServiceUnit = "open-card-edge"
	ServiceAgent    ServiceUnit = "open-card-agent"
	ServiceServer   ServiceUnit = "open-card-server"
	ServiceCaddy    ServiceUnit = "open-card-caddy"
	ServiceBuildKit ServiceUnit = "open-card-buildkit"
)

var ErrServiceOutcomeUnknown = errors.New("service control outcome is unknown")
var ErrEdgeMarkerPresent = errors.New("edge start is blocked by upgrade marker")

var serviceUnits = []ServiceUnit{ServiceEdge, ServiceAgent, ServiceServer, ServiceCaddy, ServiceBuildKit}

type ServiceState struct{ Active, Enabled bool }
type ServiceSnapshot map[ServiceUnit]ServiceState
type CommandResult struct {
	ExitCode int
	Output   string
	Err      error
}
type ServiceRunner interface {
	Run(context.Context, ...string) CommandResult
}
type markerProbe func() (bool, error)

// EdgeConfigCommand is deliberately data-only and is passed only to a
// fixed-runner boundary. Callers cannot select a privilege-drop program,
// executable, environment, or command shape.
type EdgeConfigCommand struct {
	Executable  string
	Arguments   []string
	User        string
	UID         int
	GID         int
	Environment []string
}

type EdgeConfigRunner interface {
	RunEdgeConfig(context.Context, EdgeConfigCommand) CommandResult
}

// edgeConfigValidationInput is private to the fixed execution boundary. It
// keeps every physical path derived from typed identities and never accepts a
// caller-selected filename or argv.
type edgeConfigValidationInput struct {
	Transition   EdgeConfigTransitionV1
	ConfigSHA256 string
}

type edgeConfigValidationResult struct {
	ConfigSHA256         string
	CandidateCaddySHA256 string
	EvidenceSHA256       string
}

// EdgeConfigValidator validates a prepared candidate Edge config using only
// descriptor-rooted release/artifact paths. It does not bind a listener,
// alter a unit, or persist tool output.
type EdgeConfigValidator struct {
	activeRoot  string
	dataRoot    string
	ownerUID    int
	ownerGID    int
	edgeUID     int
	edgeGID     int
	edgeEnvPath string
	runtime     edgeRuntimePaths
	runner      EdgeConfigRunner
	timeout     time.Duration
}

type edgeRuntimePaths struct{ home, data, config, log string }

var productionEdgeRuntimePaths = edgeRuntimePaths{
	home: edgeRuntimeHome, data: edgeRuntimeData, config: edgeRuntimeConfig, log: edgeRuntimeLog,
}

type productionEdgeConfigRunner struct {
	command productionCommandFactory
	verify  func(string) (os.FileInfo, error)
}

func (r productionEdgeConfigRunner) RunEdgeConfig(ctx context.Context, request EdgeConfigCommand) CommandResult {
	if request.User != productionCaddyUser || request.UID < 0 || request.GID < 0 || request.Executable == "" || len(request.Arguments) == 0 {
		return CommandResult{ExitCode: -1, Err: errors.New("unsafe edge config command")}
	}
	if !productionEdgeConfigEnvironmentValid(request.Environment) {
		return CommandResult{ExitCode: -1, Err: errors.New("unsafe edge config environment")}
	}
	verify := r.verify
	if verify == nil {
		verify = safeProductionExecutable
	}
	if _, err := verify(productionCaddyPrivilegeDropPath); err != nil {
		return CommandResult{ExitCode: -1, Err: errors.New("unsafe edge config privilege boundary")}
	}
	commandFactory := r.command
	if commandFactory == nil {
		commandFactory = exec.CommandContext
	}
	args := []string{
		"--reuid=" + strconv.Itoa(request.UID),
		"--regid=" + strconv.Itoa(request.GID),
		"--clear-groups",
		"--",
		request.Executable,
	}
	args = append(args, request.Arguments...)
	command := commandFactory(ctx, productionCaddyPrivilegeDropPath, args...)
	command.Env = append([]string(nil), request.Environment...)
	output, err := command.CombinedOutput()
	if err == nil {
		return CommandResult{Output: string(output)}
	}
	if exit, ok := err.(*exec.ExitError); ok {
		return CommandResult{ExitCode: exit.ExitCode(), Output: string(output), Err: err}
	}
	return CommandResult{ExitCode: -1, Output: string(output), Err: err}
}

func ProductionEdgeConfigValidator() (*EdgeConfigValidator, error) {
	tool, err := safeProductionExecutable(productionCaddyPrivilegeDropPath)
	if err != nil || tool == nil {
		return nil, errors.New("production caddy privilege boundary is unsafe")
	}
	edge, err := user.Lookup(productionCaddyUser)
	if err != nil {
		return nil, errors.New("production caddy user is unavailable")
	}
	uid, err := strconv.Atoi(edge.Uid)
	if err != nil {
		return nil, errors.New("production caddy user is unavailable")
	}
	gid, err := strconv.Atoi(edge.Gid)
	if err != nil {
		return nil, errors.New("production caddy user is unavailable")
	}
	return newEdgeConfigValidator(productionActiveRoot, DefaultDataDir, productionEdgeEnvPath, 0, 0, uid, gid, productionEdgeRuntimePaths, productionEdgeConfigRunner{}, 15*time.Second)
}

// TaskEdgeConfigValidator is a test-only constructor. It requires explicit
// roots, ownership and runner; production callers cannot replace any of them.
func TaskEdgeConfigValidator(activeRoot, dataRoot string, uid, gid, edgeUID, edgeGID int, runner EdgeConfigRunner) (*EdgeConfigValidator, error) {
	runtimeRoot := filepath.Join(dataRoot, "edge-runtime")
	return newEdgeConfigValidator(activeRoot, dataRoot, filepath.Join(dataRoot, "open-card-edge.env"), uid, gid, edgeUID, edgeGID, edgeRuntimePaths{home: filepath.Join(runtimeRoot, "home"), data: filepath.Join(runtimeRoot, "data"), config: filepath.Join(runtimeRoot, "config"), log: filepath.Join(runtimeRoot, "log")}, runner, time.Second)
}

func newEdgeConfigValidator(activeRoot, dataRoot, edgeEnvPath string, uid, gid, edgeUID, edgeGID int, runtime edgeRuntimePaths, runner EdgeConfigRunner, timeout time.Duration) (*EdgeConfigValidator, error) {
	if !safeAbsPath(activeRoot) || !safeAbsPath(dataRoot) || !safeAbsPath(edgeEnvPath) || !runtime.valid() || uid < 0 || gid < 0 || edgeUID < 0 || edgeGID < 0 || runner == nil || timeout <= 0 {
		return nil, ErrServiceOutcomeUnknown
	}
	return &EdgeConfigValidator{activeRoot: activeRoot, dataRoot: dataRoot, edgeEnvPath: edgeEnvPath, ownerUID: uid, ownerGID: gid, edgeUID: edgeUID, edgeGID: edgeGID, runtime: runtime, runner: runner, timeout: timeout}, nil
}

func (p edgeRuntimePaths) valid() bool {
	return safeAbsPath(p.home) && safeAbsPath(p.data) && safeAbsPath(p.config) && safeAbsPath(p.log)
}

// ServiceUnitFileReader supplies the canonical unit file to task-scoped
// controllers. ReloadServerUnit still rejects every path but the fixed one.
type ServiceUnitFileReader func(string) ([]byte, os.FileInfo, error)

// ServiceUnitDescriptor is an already-opened canonical unit file. Metadata
// and bytes are read from the same descriptor, avoiding path re-resolution.
type ServiceUnitDescriptor interface {
	io.Reader
	Stat() (os.FileInfo, error)
	Close() error
}

type ServiceUnitDescriptorOpener func() (ServiceUnitDescriptor, error)

type ServiceController struct {
	runner         ServiceRunner
	marker         markerProbe
	client         *http.Client
	serverUnitPath string
	readUnit       ServiceUnitFileReader
	openUnit       ServiceUnitDescriptorOpener
	unitWriter     *DurableWriter
}

type productionServiceRunner struct{ command productionCommandFactory }

func (r productionServiceRunner) Run(ctx context.Context, argv ...string) CommandResult {
	if len(argv) == 0 || argv[0] != "systemctl" {
		return CommandResult{ExitCode: -1, Err: errors.New("unsafe command")}
	}
	commandFactory := r.command
	if commandFactory == nil {
		commandFactory = exec.CommandContext
	}
	result := commandFactory(ctx, "/usr/bin/systemctl", argv[1:]...)
	result.Env = append([]string(nil), productionSubprocessBaseEnv...)
	output, err := result.CombinedOutput()
	if err == nil {
		return CommandResult{Output: string(output)}
	}
	if exit, ok := err.(*exec.ExitError); ok {
		return CommandResult{ExitCode: exit.ExitCode(), Output: string(output), Err: err}
	}
	return CommandResult{ExitCode: -1, Output: string(output), Err: err}
}

// Close releases the pinned unit-root descriptor at most once. The controller
// deliberately detaches it before closing so callers may safely defer Close.
func (c *ServiceController) Close() error {
	if c == nil {
		return nil
	}
	writer := c.unitWriter
	c.unitWriter = nil
	if writer == nil {
		return nil
	}
	if err := writer.Close(); err != nil {
		return ErrServiceOutcomeUnknown
	}
	return nil
}

func ProductionServiceController() (*ServiceController, error) {
	if _, err := safeProductionExecutable("/usr/bin/systemctl"); err != nil {
		return nil, errors.New("production systemctl is unsafe")
	}
	unitWriter, err := ProductionDurableWriter("/etc/systemd/system")
	if err != nil {
		return nil, errors.New("production server-unit root is unsafe")
	}
	return &ServiceController{runner: productionServiceRunner{}, marker: func() (bool, error) {
		_, err := os.Lstat("/var/lib/open-card/upgrade-in-progress")
		if os.IsNotExist(err) {
			return false, nil
		}
		return err == nil, err
	}, client: &http.Client{Timeout: 5 * time.Second}, serverUnitPath: productionServerUnitPath, unitWriter: unitWriter}, nil
}

func safeProductionExecutable(path string) (os.FileInfo, error) {
	return safeExecutablePath(path, 0, 0, os.Lstat)
}

type executableLstat func(string) (os.FileInfo, error)

// safeExecutablePath verifies every pathname component before trusting an
// executable. A secure leaf under a writable or symlinked parent is not a
// production trust boundary: exec would resolve that parent again later.
func safeExecutablePath(path string, uid, gid int, lstat executableLstat) (os.FileInfo, error) {
	if !safeAbsPath(path) || uid < 0 || gid < 0 || lstat == nil {
		return nil, errors.New("production executable is unsafe")
	}
	parts := strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator))
	if len(parts) == 0 || parts[0] == "" {
		return nil, errors.New("production executable is unsafe")
	}
	current := string(filepath.Separator)
	if err := safeExecutableDirectory(current, uid, gid, lstat); err != nil {
		return nil, err
	}
	for _, part := range parts[:len(parts)-1] {
		if part == "" || part == "." || part == ".." {
			return nil, errors.New("production executable is unsafe")
		}
		current = filepath.Join(current, part)
		if err := safeExecutableDirectory(current, uid, gid, lstat); err != nil {
			return nil, err
		}
	}
	info, err := lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 || info.Mode().Perm()&0o111 == 0 || verifyOwner(info, uid, gid) != nil {
		return nil, errors.New("production executable is unsafe")
	}
	return info, nil
}

func safeExecutableDirectory(path string, uid, gid int, lstat executableLstat) error {
	info, err := lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 || verifyOwner(info, uid, gid) != nil {
		return errors.New("production executable is unsafe")
	}
	return nil
}

func TaskServiceController(runner ServiceRunner, marker markerProbe, client *http.Client) (*ServiceController, error) {
	if runner == nil || marker == nil {
		return nil, errors.New("task service controller dependencies are required")
	}
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	return &ServiceController{runner: runner, marker: marker, client: client}, nil
}

// TaskServiceControllerWithServerUnit supplies a fixed server-unit reader for
// local tests. ReloadServerUnit still accepts no caller-controlled unit path.
func TaskServiceControllerWithServerUnit(runner ServiceRunner, marker markerProbe, client *http.Client, serverUnitPath string, readUnit ServiceUnitFileReader) (*ServiceController, error) {
	controller, err := TaskServiceController(runner, marker, client)
	if err != nil || serverUnitPath == "" || readUnit == nil {
		return nil, ErrServiceOutcomeUnknown
	}
	controller.serverUnitPath = serverUnitPath
	controller.readUnit = readUnit
	return controller, nil
}

// TaskServiceControllerWithServerUnitDescriptor supplies an already-opened
// descriptor seam for reload trust tests without exposing an arbitrary path.
func TaskServiceControllerWithServerUnitDescriptor(runner ServiceRunner, marker markerProbe, client *http.Client, serverUnitPath string, openUnit ServiceUnitDescriptorOpener) (*ServiceController, error) {
	controller, err := TaskServiceController(runner, marker, client)
	if err != nil || serverUnitPath == "" || openUnit == nil {
		return nil, ErrServiceOutcomeUnknown
	}
	controller.serverUnitPath = serverUnitPath
	controller.openUnit = openUnit
	return controller, nil
}

// TaskServiceControllerWithPinnedUnitRoot is a test-only equivalent of the
// production unit-root pin. The fixed unit name is retained while the caller
// supplies an explicitly owned task root.
func TaskServiceControllerWithPinnedUnitRoot(runner ServiceRunner, marker markerProbe, client *http.Client, root string, uid, gid int) (*ServiceController, error) {
	controller, err := TaskServiceController(runner, marker, client)
	if err != nil {
		return nil, err
	}
	writer, err := TaskDurableWriter(root, uid, gid)
	if err != nil {
		return nil, ErrServiceOutcomeUnknown
	}
	controller.serverUnitPath = productionServerUnitPath
	controller.unitWriter = writer
	return controller, nil
}

func serviceName(unit ServiceUnit) string { return string(unit) + ".service" }
func known(unit ServiceUnit) bool {
	for _, value := range serviceUnits {
		if value == unit {
			return true
		}
	}
	return false
}

func (c *ServiceController) state(ctx context.Context, unit ServiceUnit, action string) (bool, error) {
	if c == nil || c.runner == nil || !known(unit) {
		return false, ErrServiceOutcomeUnknown
	}
	result := c.runner.Run(ctx, "systemctl", action, "--quiet", serviceName(unit))
	var exitError *exec.ExitError
	knownProcessExit := result.Err != nil && errors.As(result.Err, &exitError) && exitError.ExitCode() == result.ExitCode
	allowedInactive := action == "is-active" && result.ExitCode == 3 && knownProcessExit
	allowedDisabled := action == "is-enabled" && result.ExitCode == 1 && knownProcessExit
	// systemctl reports inactive/disabled through documented non-zero exit
	// statuses, which exec.Command necessarily represents as *exec.ExitError.
	// Accept the exact state codes while continuing to reject every other
	// command error or exit status.
	if (result.ExitCode == 0 && result.Err != nil) || (result.ExitCode != 0 && !allowedInactive && !allowedDisabled) {
		return false, fmt.Errorf("%w: %s", ErrServiceOutcomeUnknown, action)
	}
	return result.ExitCode == 0, nil
}

func (c *ServiceController) CaptureSnapshot(ctx context.Context) (ServiceSnapshot, error) {
	snapshot := make(ServiceSnapshot, len(serviceUnits))
	for _, unit := range serviceUnits {
		active, err := c.state(ctx, unit, "is-active")
		if err != nil {
			return nil, err
		}
		enabled, err := c.state(ctx, unit, "is-enabled")
		if err != nil {
			return nil, err
		}
		snapshot[unit] = ServiceState{Active: active, Enabled: enabled}
	}
	return snapshot, nil
}

func (c *ServiceController) action(ctx context.Context, action string, unit ServiceUnit) error {
	if c == nil || c.runner == nil || !known(unit) {
		return ErrServiceOutcomeUnknown
	}
	result := c.runner.Run(ctx, "systemctl", action, serviceName(unit))
	if result.Err != nil || result.ExitCode != 0 {
		return fmt.Errorf("%w: %s", ErrServiceOutcomeUnknown, action)
	}
	return nil
}

func (c *ServiceController) stop(ctx context.Context, unit ServiceUnit) error {
	active, err := c.state(ctx, unit, "is-active")
	if err != nil {
		return err
	}
	if active {
		if err := c.action(ctx, "stop", unit); err != nil {
			return err
		}
	}
	active, err = c.state(ctx, unit, "is-active")
	if err != nil {
		return err
	}
	if active {
		return fmt.Errorf("%w: stop remained active", ErrServiceOutcomeUnknown)
	}
	return nil
}

func (c *ServiceController) start(ctx context.Context, unit ServiceUnit) error {
	active, err := c.state(ctx, unit, "is-active")
	if err != nil {
		return err
	}
	if !active {
		if err := c.action(ctx, "start", unit); err != nil {
			return err
		}
	}
	active, err = c.state(ctx, unit, "is-active")
	if err != nil || !active {
		return fmt.Errorf("%w: start did not become active", ErrServiceOutcomeUnknown)
	}
	return nil
}

func (c *ServiceController) Quiesce(ctx context.Context, keepRouteCaddy, keepBuildKit bool) error {
	for _, unit := range []ServiceUnit{ServiceEdge, ServiceAgent, ServiceServer} {
		if err := c.stop(ctx, unit); err != nil {
			return err
		}
	}
	if !keepRouteCaddy {
		if err := c.stop(ctx, ServiceCaddy); err != nil {
			return err
		}
	}
	if !keepBuildKit {
		if err := c.stop(ctx, ServiceBuildKit); err != nil {
			return err
		}
	}
	return nil
}

func (c *ServiceController) StartInternal(ctx context.Context) error {
	for _, unit := range []ServiceUnit{ServiceBuildKit, ServiceCaddy, ServiceServer, ServiceAgent} {
		if err := c.start(ctx, unit); err != nil {
			return err
		}
	}
	return nil
}

func (c *ServiceController) StartEdge(ctx context.Context) error {
	present, err := c.marker()
	if err != nil || present {
		return ErrEdgeMarkerPresent
	}
	return c.start(ctx, ServiceEdge)
}

func (c *ServiceController) RestoreSnapshot(ctx context.Context, snapshot ServiceSnapshot) error {
	for _, unit := range []ServiceUnit{ServiceEdge, ServiceAgent, ServiceServer, ServiceCaddy, ServiceBuildKit} {
		state, ok := snapshot[unit]
		if !ok {
			return ErrServiceOutcomeUnknown
		}
		if !state.Active {
			if err := c.stop(ctx, unit); err != nil {
				return err
			}
		}
		if state.Enabled {
			if err := c.action(ctx, "enable", unit); err != nil {
				return err
			}
		} else if err := c.action(ctx, "disable", unit); err != nil {
			return err
		}
	}
	for _, unit := range []ServiceUnit{ServiceBuildKit, ServiceCaddy, ServiceServer, ServiceAgent} {
		if snapshot[unit].Active {
			if err := c.start(ctx, unit); err != nil {
				return err
			}
		}
	}
	if snapshot[ServiceEdge].Active {
		return c.StartEdge(ctx)
	}
	return nil
}

func (c *ServiceController) DaemonReload(ctx context.Context) error {
	if c == nil || c.runner == nil {
		return ErrServiceOutcomeUnknown
	}
	result := c.runner.Run(ctx, "systemctl", "daemon-reload")
	if result.Err != nil || result.ExitCode != 0 {
		return fmt.Errorf("%w: daemon-reload", ErrServiceOutcomeUnknown)
	}
	return nil
}

type serverUnitProperties struct {
	fragmentPath     string
	dropInPaths      string
	needDaemonReload string
}

// ReloadServerUnit verifies the canonical server unit before and after the
// fixed daemon-reload. It deliberately has no arbitrary unit/path surface.
func (c *ServiceController) ReloadServerUnit(ctx context.Context, expectedFragmentSHA256 string) error {
	if c == nil || c.runner == nil || c.serverUnitPath != productionServerUnitPath || (c.readUnit == nil && c.openUnit == nil && c.unitWriter == nil) {
		return ErrServiceOutcomeUnknown
	}
	if err := c.verifyUnitRoot(); err != nil {
		return ErrServiceOutcomeUnknown
	}
	before, err := c.serverUnitProperties(ctx)
	if err != nil || !before.valid(false) {
		return ErrServiceOutcomeUnknown
	}
	beforeDigest, err := c.serverUnitDigest(expectedFragmentSHA256)
	if err != nil {
		return ErrServiceOutcomeUnknown
	}
	if err := c.DaemonReload(ctx); err != nil {
		return err
	}
	after, err := c.serverUnitProperties(ctx)
	if err != nil || !after.valid(true) {
		return ErrServiceOutcomeUnknown
	}
	afterDigest, err := c.serverUnitDigest(expectedFragmentSHA256)
	if err != nil || afterDigest != beforeDigest {
		return ErrServiceOutcomeUnknown
	}
	if err := c.verifyUnitRoot(); err != nil {
		return ErrServiceOutcomeUnknown
	}
	return nil
}

func (c *ServiceController) verifyUnitRoot() error {
	if c == nil || c.unitWriter == nil {
		return nil
	}
	return c.unitWriter.VerifyLiveRoot()
}

func (c *ServiceController) serverUnitProperties(ctx context.Context) (serverUnitProperties, error) {
	result := c.runner.Run(ctx, "systemctl", "show", serviceName(ServiceServer), "--property=FragmentPath", "--property=DropInPaths", "--property=NeedDaemonReload")
	if result.Err != nil || result.ExitCode != 0 {
		return serverUnitProperties{}, ErrServiceOutcomeUnknown
	}
	properties := serverUnitProperties{}
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSuffix(result.Output, "\n"), "\n") {
		name, value, ok := strings.Cut(line, "=")
		if !ok || seen[name] {
			return serverUnitProperties{}, ErrServiceOutcomeUnknown
		}
		seen[name] = true
		switch name {
		case "FragmentPath":
			properties.fragmentPath = value
		case "DropInPaths":
			properties.dropInPaths = value
		case "NeedDaemonReload":
			properties.needDaemonReload = value
		default:
			return serverUnitProperties{}, ErrServiceOutcomeUnknown
		}
	}
	if len(seen) != 3 {
		return serverUnitProperties{}, ErrServiceOutcomeUnknown
	}
	return properties, nil
}

func (p serverUnitProperties) valid(afterReload bool) bool {
	if p.fragmentPath != productionServerUnitPath || p.dropInPaths != "" {
		return false
	}
	if afterReload {
		return p.needDaemonReload == "no"
	}
	return p.needDaemonReload == "yes" || p.needDaemonReload == "no"
}

func (c *ServiceController) serverUnitDigest(expected string) (string, error) {
	if len(expected) != sha256.Size*2 {
		return "", ErrServiceOutcomeUnknown
	}
	if _, err := hex.DecodeString(expected); err != nil {
		return "", ErrServiceOutcomeUnknown
	}
	raw, err := c.readServerUnit()
	if err != nil {
		return "", ErrServiceOutcomeUnknown
	}
	digest := sha256.Sum256(raw)
	actual := hex.EncodeToString(digest[:])
	if actual != expected {
		return "", ErrServiceOutcomeUnknown
	}
	return actual, nil
}

func (c *ServiceController) readServerUnit() ([]byte, error) {
	if c.unitWriter != nil {
		if err := c.unitWriter.VerifyLiveRoot(); err != nil {
			return nil, ErrServiceOutcomeUnknown
		}
		raw, err := c.unitWriter.ReadSystemdServerUnit()
		if err != nil || c.unitWriter.VerifyLiveRoot() != nil {
			return nil, ErrServiceOutcomeUnknown
		}
		return raw, nil
	}
	if c.openUnit == nil {
		raw, info, err := c.readUnit(productionServerUnitPath)
		if err != nil || !safeServerUnitInfo(info) {
			return nil, ErrServiceOutcomeUnknown
		}
		return raw, nil
	}
	descriptor, err := c.openUnit()
	if err != nil || descriptor == nil {
		return nil, ErrServiceOutcomeUnknown
	}
	defer descriptor.Close()
	info, err := descriptor.Stat()
	if err != nil || !safeServerUnitInfo(info) {
		return nil, ErrServiceOutcomeUnknown
	}
	raw, err := io.ReadAll(descriptor)
	if err != nil {
		return nil, ErrServiceOutcomeUnknown
	}
	return raw, nil
}

func safeServerUnitInfo(info os.FileInfo) bool {
	if info == nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o644 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == 0 && stat.Gid == 0
}

func safeServerUnitDirectoryInfo(info os.FileInfo) bool {
	if info == nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == 0 && stat.Gid == 0
}

type HealthResult struct{ Code string }

func (c *ServiceController) ProbeHealth(ctx context.Context, rawURL string) (HealthResult, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme != "http" || parsed.User != nil || parsed.RawQuery != "" || (parsed.Path != "/healthz" && parsed.Path != "/readyz" && parsed.Path != "/config/") {
		return HealthResult{Code: "invalid_target"}, errors.New("health target is not approved")
	}
	host := parsed.Hostname()
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() || parsed.Port() == "" {
		return HealthResult{Code: "invalid_target"}, errors.New("health target is not loopback")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return HealthResult{Code: "invalid_target"}, errors.New("health request is invalid")
	}
	response, err := c.client.Do(request)
	if err != nil {
		return HealthResult{Code: "unhealthy"}, errors.New("health request failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return HealthResult{Code: "unhealthy"}, errors.New("health response was not ready")
	}
	return HealthResult{Code: "healthy"}, nil
}

func (v *EdgeConfigValidator) validate(ctx context.Context, input edgeConfigValidationInput) (edgeConfigValidationResult, error) {
	if v == nil || v.runner == nil || !input.Transition.valid() || !validSHA(input.ConfigSHA256) || input.ConfigSHA256 != input.Transition.InstalledAfterSHA256 {
		return edgeConfigValidationResult{}, ErrServiceOutcomeUnknown
	}
	if err := v.verifyRoots(); err != nil {
		return edgeConfigValidationResult{}, ErrServiceOutcomeUnknown
	}
	releaseRel := filepath.ToSlash(filepath.Join("releases", input.Transition.CandidateReleaseID))
	manifestRaw, err := v.readOwnedFile(v.activeRoot, filepath.ToSlash(filepath.Join(releaseRel, "manifest.json")), 0o644, v.ownerUID, v.ownerGID, false)
	if err != nil {
		return edgeConfigValidationResult{}, ErrServiceOutcomeUnknown
	}
	manifest, err := parseReleaseManifest(manifestRaw)
	if err != nil || manifest.ReleaseID != input.Transition.CandidateReleaseID || ValidateProductionCandidate(manifest) != nil {
		return edgeConfigValidationResult{}, ErrServiceOutcomeUnknown
	}
	if err := edgeManifestFileDigest(manifest, edgeCaddyRelativePath, 0o755, input.Transition.CandidateCaddySHA256); err != nil {
		return edgeConfigValidationResult{}, ErrServiceOutcomeUnknown
	}
	if err := edgeManifestFileDigest(manifest, edgeTemplateRelativePath, 0o644, input.Transition.CandidateTemplateSHA256); err != nil {
		return edgeConfigValidationResult{}, ErrServiceOutcomeUnknown
	}
	caddyPath := filepath.Join(v.activeRoot, filepath.FromSlash(releaseRel), filepath.FromSlash(edgeCaddyRelativePath))
	caddyRaw, err := v.readOwnedFile(v.activeRoot, filepath.ToSlash(filepath.Join(releaseRel, edgeCaddyRelativePath)), 0o755, v.ownerUID, v.ownerGID, false)
	if err != nil || sha256Bytes(caddyRaw) != input.Transition.CandidateCaddySHA256 {
		return edgeConfigValidationResult{}, ErrServiceOutcomeUnknown
	}
	// The template is read through the same pinned root even though only its
	// digest enters the command evidence. This prevents a valid manifest from
	// being paired with a different candidate release tree after verification.
	templateRaw, err := v.readOwnedFile(v.activeRoot, filepath.ToSlash(filepath.Join(releaseRel, edgeTemplateRelativePath)), 0o644, v.ownerUID, v.ownerGID, false)
	if err != nil || sha256Bytes(templateRaw) != input.Transition.CandidateTemplateSHA256 {
		return edgeConfigValidationResult{}, ErrServiceOutcomeUnknown
	}
	configRel := filepath.ToSlash(filepath.Join("upgrade-artifacts", input.Transition.TransactionID, edgeConfigArtifactName))
	configPath := filepath.Join(v.dataRoot, filepath.FromSlash(configRel))
	configRaw, err := v.readOwnedFile(v.dataRoot, configRel, 0o640, v.ownerUID, v.edgeGID, true)
	if err != nil || sha256Bytes(configRaw) != input.ConfigSHA256 {
		return edgeConfigValidationResult{}, ErrServiceOutcomeUnknown
	}
	edgeEnvironment, err := v.readEdgeServiceEnvironment()
	if err != nil {
		return edgeConfigValidationResult{}, ErrServiceOutcomeUnknown
	}

	commandCtx, cancel := context.WithTimeout(ctx, v.timeout)
	defer cancel()
	if err := v.run(commandCtx, caddyPath, []string{"validate", "--config", configPath, "--adapter", "caddyfile"}, edgeEnvironment); err != nil {
		return edgeConfigValidationResult{}, ErrServiceOutcomeUnknown
	}
	if err := v.run(commandCtx, caddyPath, []string{"adapt", "--config", configPath, "--adapter", "caddyfile", "--validate"}, edgeEnvironment); err != nil {
		return edgeConfigValidationResult{}, ErrServiceOutcomeUnknown
	}
	if commandCtx.Err() != nil {
		return edgeConfigValidationResult{}, ErrServiceOutcomeUnknown
	}
	// Re-read every command input after execution. A renamed root or altered
	// file is an unknown outcome, never a successful validation.
	if raw, e := v.readOwnedFile(v.activeRoot, filepath.ToSlash(filepath.Join(releaseRel, edgeCaddyRelativePath)), 0o755, v.ownerUID, v.ownerGID, false); e != nil || sha256Bytes(raw) != input.Transition.CandidateCaddySHA256 {
		return edgeConfigValidationResult{}, ErrServiceOutcomeUnknown
	}
	if raw, e := v.readOwnedFile(v.activeRoot, filepath.ToSlash(filepath.Join(releaseRel, edgeTemplateRelativePath)), 0o644, v.ownerUID, v.ownerGID, false); e != nil || sha256Bytes(raw) != input.Transition.CandidateTemplateSHA256 {
		return edgeConfigValidationResult{}, ErrServiceOutcomeUnknown
	}
	if raw, e := v.readOwnedFile(v.dataRoot, configRel, 0o640, v.ownerUID, v.edgeGID, true); e != nil || sha256Bytes(raw) != input.ConfigSHA256 {
		return edgeConfigValidationResult{}, ErrServiceOutcomeUnknown
	}
	if after, e := v.readEdgeServiceEnvironment(); e != nil || !sameStringSlice(after, edgeEnvironment) {
		return edgeConfigValidationResult{}, ErrServiceOutcomeUnknown
	}
	evidence := edgeConfigEvidenceSHA256(input)
	return edgeConfigValidationResult{ConfigSHA256: input.ConfigSHA256, CandidateCaddySHA256: input.Transition.CandidateCaddySHA256, EvidenceSHA256: evidence}, nil
}

func (v *EdgeConfigValidator) run(ctx context.Context, executable string, args, environment []string) error {
	if ctx.Err() != nil || !safeAbsPath(executable) || len(args) == 0 {
		return ErrServiceOutcomeUnknown
	}
	result := v.runner.RunEdgeConfig(ctx, EdgeConfigCommand{Executable: executable, Arguments: append([]string(nil), args...), User: productionCaddyUser, UID: v.edgeUID, GID: v.edgeGID, Environment: append([]string(nil), environment...)})
	if ctx.Err() != nil || result.Err != nil || result.ExitCode != 0 {
		return ErrServiceOutcomeUnknown
	}
	return nil
}

func (p edgeRuntimePaths) environment() []string {
	return append(append([]string(nil), productionSubprocessBaseEnv...),
		"HOME="+p.home,
		"XDG_DATA_HOME="+p.data,
		"XDG_CONFIG_HOME="+p.config,
		"OPEN_CARD_EDGE_LOG_DIR="+p.log,
	)
}

func productionEdgeConfigEnvironmentValid(environment []string) bool {
	return sameStringSlice(environment, productionEdgeRuntimePaths.environment())
}

func sameStringSlice(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func (v *EdgeConfigValidator) readEdgeServiceEnvironment() ([]string, error) {
	if v == nil || !safeAbsPath(v.edgeEnvPath) || filepath.Base(v.edgeEnvPath) != "open-card-edge.env" {
		return nil, ErrServiceOutcomeUnknown
	}
	parent := filepath.Dir(v.edgeEnvPath)
	if err := edgeSecureDirectory(parent, v.ownerUID, v.ownerGID, false); err != nil {
		return nil, ErrServiceOutcomeUnknown
	}
	file, err := os.OpenFile(v.edgeEnvPath, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrServiceOutcomeUnknown
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o640 || verifyOwner(info, v.ownerUID, v.edgeGID) != nil {
		return nil, ErrServiceOutcomeUnknown
	}
	raw, err := io.ReadAll(file)
	if err != nil {
		return nil, ErrServiceOutcomeUnknown
	}
	environment, err := parseEdgeServiceEnvironment(raw, v.runtime)
	if err != nil || !sameStringSlice(environment, v.runtime.environment()) {
		return nil, ErrServiceOutcomeUnknown
	}
	if err := edgeSecureDirectory(parent, v.ownerUID, v.ownerGID, false); err != nil {
		return nil, ErrServiceOutcomeUnknown
	}
	info, err = file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o640 || verifyOwner(info, v.ownerUID, v.edgeGID) != nil {
		return nil, ErrServiceOutcomeUnknown
	}
	if err := verifyEdgeRuntimeDirectories(v); err != nil {
		return nil, ErrServiceOutcomeUnknown
	}
	return environment, nil
}

func parseEdgeServiceEnvironment(raw []byte, runtime edgeRuntimePaths) ([]string, error) {
	if len(raw) == 0 || raw[len(raw)-1] != '\n' || strings.ContainsAny(string(raw), "\x00\r") {
		return nil, ErrServiceOutcomeUnknown
	}
	values := map[string]string{}
	commentSeen := false
	for index, line := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
		if line == edgeEnvCanonicalComment {
			if index != 0 || commentSeen {
				return nil, ErrServiceOutcomeUnknown
			}
			commentSeen = true
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || key == "" || value == "" || strings.ContainsAny(key+value, " \t\\\"'$") {
			return nil, ErrServiceOutcomeUnknown
		}
		if _, exists := values[key]; exists {
			return nil, ErrServiceOutcomeUnknown
		}
		values[key] = value
	}
	expected := []string{
		"HOME=" + runtime.home,
		"XDG_DATA_HOME=" + runtime.data,
		"XDG_CONFIG_HOME=" + runtime.config,
		"OPEN_CARD_EDGE_LOG_DIR=" + runtime.log,
	}
	if len(values) != len(expected) {
		return nil, ErrServiceOutcomeUnknown
	}
	for _, entry := range expected {
		key, value, _ := strings.Cut(entry, "=")
		if values[key] != value {
			return nil, ErrServiceOutcomeUnknown
		}
	}
	return runtime.environment(), nil
}

func verifyEdgeRuntimeDirectories(v *EdgeConfigValidator) error {
	if v == nil {
		return ErrServiceOutcomeUnknown
	}
	for _, path := range []string{v.runtime.home, v.runtime.data, v.runtime.config, v.runtime.log} {
		if err := edgeRuntimeDirectory(path, v.edgeUID, v.edgeGID); err != nil {
			return err
		}
	}
	return nil
}

func edgeRuntimeDirectory(path string, uid, gid int) error {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm()&0o022 != 0 || info.Mode().Perm()&0o100 == 0 || verifyOwner(info, uid, gid) != nil {
		return ErrServiceOutcomeUnknown
	}
	return nil
}

func edgeManifestFileDigest(manifest Manifest, path string, mode uint32, expectedSHA256 string) error {
	for _, file := range manifest.Files {
		if file.Path == path && file.Mode == mode && file.SHA256 == expectedSHA256 {
			return nil
		}
	}
	return ErrServiceOutcomeUnknown
}

func edgeConfigEvidenceSHA256(input edgeConfigValidationInput) string {
	// This intentionally binds the two exact command identities but omits all
	// paths: their only values are fixed derivations from the transaction and
	// release IDs, while persisting paths would expand the public API surface.
	raw := strings.Join([]string{
		"edge-config-validation-v1",
		input.Transition.TransactionID,
		input.Transition.SourceReleaseID,
		input.Transition.CandidateReleaseID,
		input.Transition.ConsoleHostname,
		input.Transition.SourceTemplateSHA256,
		input.Transition.CandidateTemplateSHA256,
		input.Transition.InstalledBeforeSHA256,
		input.Transition.InstalledAfterSHA256,
		input.Transition.CandidateCaddySHA256,
		input.ConfigSHA256,
		"caddy validate --config --adapter caddyfile",
		"caddy adapt --config --adapter caddyfile --validate",
	}, "\n")
	return sha256Bytes([]byte(raw))
}

func (v *EdgeConfigValidator) verifyRoots() error {
	if v == nil || !safeAbsPath(v.activeRoot) || !safeAbsPath(v.dataRoot) {
		return ErrServiceOutcomeUnknown
	}
	if err := edgeSecureDirectory(v.activeRoot, v.ownerUID, v.ownerGID, false); err != nil {
		return err
	}
	return edgeSecureDirectory(v.dataRoot, v.ownerUID, v.ownerGID, false)
}

func edgeSecureDirectory(path string, uid, gid int, requireTraverse bool) error {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm()&0o022 != 0 || verifyOwner(info, uid, gid) != nil {
		return ErrServiceOutcomeUnknown
	}
	if requireTraverse && info.Mode().Perm()&0o001 == 0 {
		return ErrServiceOutcomeUnknown
	}
	return nil
}

func (v *EdgeConfigValidator) readOwnedFile(rootPath, relative string, mode os.FileMode, uid, gid int, edgeReadable bool) ([]byte, error) {
	if err := cleanRelative(relative); err != nil || strings.Contains(relative, "\\") {
		return nil, ErrServiceOutcomeUnknown
	}
	if err := edgeSecureDirectory(rootPath, v.ownerUID, v.ownerGID, edgeReadable); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return nil, ErrServiceOutcomeUnknown
	}
	defer root.Close()
	parts := strings.Split(filepath.ToSlash(relative), "/")
	current := ""
	for _, part := range parts[:len(parts)-1] {
		if part == "" || part == "." || part == ".." {
			return nil, ErrServiceOutcomeUnknown
		}
		current = filepath.ToSlash(filepath.Join(current, part))
		info, err := root.Lstat(current)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm()&0o022 != 0 || verifyOwner(info, v.ownerUID, v.ownerGID) != nil || edgeReadable && info.Mode().Perm()&0o001 == 0 {
			return nil, ErrServiceOutcomeUnknown
		}
	}
	file, err := root.OpenFile(relative, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrServiceOutcomeUnknown
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != mode || verifyOwner(info, uid, gid) != nil {
		return nil, ErrServiceOutcomeUnknown
	}
	if edgeReadable && info.Mode().Perm()&0o040 == 0 {
		return nil, ErrServiceOutcomeUnknown
	}
	raw, err := io.ReadAll(file)
	if err != nil {
		return nil, ErrServiceOutcomeUnknown
	}
	// Descriptor and named root are both revalidated after bytes are read.
	if err := edgeSecureDirectory(rootPath, v.ownerUID, v.ownerGID, edgeReadable); err != nil {
		return nil, ErrServiceOutcomeUnknown
	}
	info, err = file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != mode || verifyOwner(info, uid, gid) != nil {
		return nil, ErrServiceOutcomeUnknown
	}
	return raw, nil
}
