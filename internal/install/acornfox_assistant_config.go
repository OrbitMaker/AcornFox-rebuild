package install

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var ErrAcornFoxAssistantConfigConflict = errors.New("AcornFox assistant configuration conflicts with installed state")
var ErrAcornFoxAssistantConfigUnknown = errors.New("AcornFox assistant configuration outcome is unknown")

const (
	acornFoxAssistantDirectory = "etc/acornfox/pi"
	acornFoxAssistantConfig    = acornFoxAssistantDirectory + "/worker.json"
	acornFoxAssistantKey       = acornFoxAssistantDirectory + "/deepseek-api-key"
	acornFoxAssistantConfigNew = acornFoxAssistantDirectory + "/.worker.json.new"
	acornFoxAssistantKeyNew    = acornFoxAssistantDirectory + "/.deepseek-api-key.new"
	acornFoxAssistantUnit      = "acornfox-pi-worker.service"
	acornFoxAssistantSocket    = "/run/acornfox-pi/worker.sock"
	acornFoxAssistantMaxKey    = 4096
)

type AcornFoxAssistantConfigReceiptV1 struct {
	SchemaVersion int    `json:"schema_version"`
	State         string `json:"state"`
	Configured    bool   `json:"configured"`
	Enabled       bool   `json:"enabled"`
}

func (r AcornFoxAssistantConfigReceiptV1) Validate() error {
	if r.SchemaVersion != 1 {
		return ErrAcornFoxAssistantConfigConflict
	}
	switch r.State {
	case "ASSISTANT_ENABLED":
		if !r.Configured || !r.Enabled {
			return ErrAcornFoxAssistantConfigConflict
		}
	case "ASSISTANT_DISABLED":
		if !r.Configured || r.Enabled {
			return ErrAcornFoxAssistantConfigConflict
		}
	case "ASSISTANT_UNCONFIGURED":
		if r.Configured || r.Enabled {
			return ErrAcornFoxAssistantConfigConflict
		}
	default:
		return ErrAcornFoxAssistantConfigConflict
	}
	return nil
}

func MarshalAcornFoxAssistantConfigReceiptV1(r AcornFoxAssistantConfigReceiptV1) ([]byte, error) {
	if r.Validate() != nil {
		return nil, ErrAcornFoxAssistantConfigConflict
	}
	return json.Marshal(r)
}

// This private wire shape is kept field-for-field compatible with
// piworker.Config without importing the worker implementation into the host
// installer. It carries no credential material.
type acornFoxAssistantWorkerConfig struct {
	SchemaVersion          int      `json:"schema_version"`
	SocketPath             string   `json:"socket_path"`
	SocketMode             string   `json:"socket_mode"`
	PiBinaryPath           string   `json:"pi_binary_path"`
	WorkingDirectory       string   `json:"working_directory"`
	AgentDirectory         string   `json:"agent_directory"`
	PersistSessions        bool     `json:"persist_sessions"`
	SessionRoot            string   `json:"session_root"`
	CredentialName         string   `json:"credential_name"`
	Provider               string   `json:"provider"`
	Model                  string   `json:"model"`
	Thinking               string   `json:"thinking"`
	TrustedExtensions      []string `json:"trusted_extensions"`
	EnabledTools           []string `json:"enabled_tools"`
	ToolCallbackSocket     string   `json:"tool_callback_socket"`
	HandshakeTimeoutSecond int      `json:"handshake_timeout_seconds"`
	RunTimeoutSecond       int      `json:"run_timeout_seconds"`
	ShutdownTimeoutSecond  int      `json:"shutdown_timeout_seconds"`
}

func acornFoxAssistantCanonicalConfig() []byte {
	raw, err := json.Marshal(acornFoxAssistantWorkerConfig{
		SchemaVersion: 1, SocketPath: acornFoxAssistantSocket, SocketMode: "0660",
		PiBinaryPath: "/opt/acornfox/current/pi/pi", WorkingDirectory: "/var/lib/acornfox/pi/work",
		AgentDirectory: "/var/lib/acornfox/pi/agent", PersistSessions: true,
		SessionRoot: "/var/lib/acornfox/pi/sessions", CredentialName: "deepseek_api_key",
		Provider: "deepseek", Model: "deepseek-v4-flash", Thinking: "off",
		TrustedExtensions: []string{"/opt/acornfox/current/pi/extensions/acornfox-tools.ts"},
		EnabledTools: []string{
			"acornfox_host_metrics", "acornfox_list_apps", "acornfox_app", "acornfox_sources", "acornfox_deliveries",
			"acornfox_delivery_status", "acornfox_logs", "acornfox_operation_result", "acornfox_public_access", "acornfox_access_observation", "acornfox_probe", "acornfox_propose_restart", "acornfox_propose_redeploy",
		},
		ToolCallbackSocket:     "/run/acornfox-assistant/tools.sock",
		HandshakeTimeoutSecond: 5, RunTimeoutSecond: 300, ShutdownTimeoutSecond: 10,
	})
	if err != nil {
		panic("AcornFox assistant canonical config is not serializable")
	}
	return append(raw, '\n')
}

func validAcornFoxAssistantKey(raw []byte) bool {
	if len(raw) < 16 || len(raw) > acornFoxAssistantMaxKey {
		return false
	}
	for _, value := range raw {
		if value < 0x21 || value > 0x7e {
			return false
		}
	}
	return true
}

type acornFoxAssistantServices struct {
	stop                 func(context.Context) error
	disable              func(context.Context) error
	enable               func(context.Context) error
	start                func(context.Context) error
	verifyEnabled        func(context.Context) error
	verifyDisabled       func(context.Context) error
	restartServer        func(context.Context) error
	verifyServerEnabled  func(context.Context) error
	verifyServerDisabled func(context.Context) error
}

type acornFoxAssistantConfigurator struct {
	layout    acornFoxInstallLayout
	ownership acornFoxOwnershipEdge
	services  acornFoxAssistantServices
	readKey   func(string) ([]byte, error)
}

func ConfigureAcornFoxAssistantV1(ctx context.Context, keyFile string) (AcornFoxAssistantConfigReceiptV1, error) {
	layout, err := newProductionAcornFoxLayout()
	if err != nil {
		return AcornFoxAssistantConfigReceiptV1{}, ErrAcornFoxAssistantConfigConflict
	}
	return newAcornFoxAssistantConfigurator(layout).configure(ctx, keyFile)
}

func DisableAcornFoxAssistantV1(ctx context.Context) (AcornFoxAssistantConfigReceiptV1, error) {
	layout, err := newProductionAcornFoxLayout()
	if err != nil {
		return AcornFoxAssistantConfigReceiptV1{}, ErrAcornFoxAssistantConfigConflict
	}
	return newAcornFoxAssistantConfigurator(layout).disable(ctx)
}

func InspectProductionAcornFoxAssistantConfigurationV1() (bool, error) {
	layout, err := newProductionAcornFoxLayout()
	if err != nil {
		return false, ErrAcornFoxAssistantConfigConflict
	}
	store, err := newAcornFoxRepoStoreForLayout(layout)
	if err != nil {
		return false, ErrAcornFoxAssistantConfigConflict
	}
	defer store.Close()
	return acornFoxAssistantConfigurationState(store.hostRoot, store)
}

func newAcornFoxAssistantConfigurator(layout acornFoxInstallLayout) *acornFoxAssistantConfigurator {
	return &acornFoxAssistantConfigurator{layout: layout, ownership: newAcornFoxRealOwnershipEdge(), services: productionAcornFoxAssistantServices(), readKey: readProductionAcornFoxAssistantKey}
}

func (c *acornFoxAssistantConfigurator) configure(ctx context.Context, keyFile string) (AcornFoxAssistantConfigReceiptV1, error) {
	empty := AcornFoxAssistantConfigReceiptV1{}
	if c == nil || ctx == nil || ctx.Err() != nil || c.layout.mode != acornFoxInstallLayoutProduction || c.layout.validate() != nil || c.readKey == nil || !completeAcornFoxAssistantServices(c.services) {
		return empty, ErrAcornFoxAssistantConfigConflict
	}
	key, err := c.readKey(keyFile)
	if err != nil || !validAcornFoxAssistantKey(key) {
		return empty, ErrAcornFoxAssistantConfigConflict
	}
	defer clear(key)
	store, err := newAcornFoxRepoStoreForLayout(c.layout)
	if err != nil {
		return empty, ErrAcornFoxAssistantConfigConflict
	}
	defer store.Close()
	store.ownership = c.ownership
	lock, err := store.Acquire(ctx)
	if err != nil {
		return empty, err
	}
	defer lock.Release()
	root := store.hostRoot
	rootPrincipal, ok := c.layout.owner(AcornFoxLiveRootRole)
	if !ok || acornFoxAssistantPrepareDirectory(root, store, rootPrincipal) != nil || acornFoxAssistantValidateConfigurePrefix(root, store, rootPrincipal, key) != nil {
		return empty, ErrAcornFoxAssistantConfigConflict
	}
	config := acornFoxAssistantCanonicalConfig()
	if err := acornFoxAssistantStage(root, store, acornFoxAssistantKeyNew, key, rootPrincipal); err != nil {
		return empty, err
	}
	if err := acornFoxAssistantStage(root, store, acornFoxAssistantConfigNew, config, rootPrincipal); err != nil {
		return empty, err
	}
	// A configured worker is stopped before either canonical file can change.
	// A crash between renames therefore leaves an inert, recoverable prefix.
	if err := c.services.stop(ctx); err != nil {
		return empty, ErrAcornFoxAssistantConfigUnknown
	}
	if err := root.Rename(acornFoxAssistantKeyNew, acornFoxAssistantKey); err != nil {
		return empty, ErrAcornFoxAssistantConfigUnknown
	}
	if err := acornFoxLiveSyncDir(root, acornFoxAssistantDirectory); err != nil {
		return empty, ErrAcornFoxAssistantConfigUnknown
	}
	if err := root.Rename(acornFoxAssistantConfigNew, acornFoxAssistantConfig); err != nil {
		return empty, ErrAcornFoxAssistantConfigUnknown
	}
	if err := acornFoxLiveSyncDir(root, acornFoxAssistantDirectory); err != nil {
		return empty, ErrAcornFoxAssistantConfigUnknown
	}
	if configured, err := acornFoxAssistantConfigurationState(root, store); err != nil || !configured {
		return empty, ErrAcornFoxAssistantConfigUnknown
	}
	if err := c.services.enable(ctx); err != nil || c.services.start(ctx) != nil || c.services.verifyEnabled(ctx) != nil {
		return empty, ErrAcornFoxAssistantConfigUnknown
	}
	if c.services.restartServer(ctx) != nil || c.services.verifyServerEnabled(ctx) != nil {
		return empty, ErrAcornFoxAssistantConfigUnknown
	}
	return AcornFoxAssistantConfigReceiptV1{1, "ASSISTANT_ENABLED", true, true}, nil
}

func (c *acornFoxAssistantConfigurator) disable(ctx context.Context) (AcornFoxAssistantConfigReceiptV1, error) {
	empty := AcornFoxAssistantConfigReceiptV1{}
	if c == nil || ctx == nil || ctx.Err() != nil || c.layout.mode != acornFoxInstallLayoutProduction || c.layout.validate() != nil || !completeAcornFoxAssistantServices(c.services) {
		return empty, ErrAcornFoxAssistantConfigConflict
	}
	store, err := newAcornFoxRepoStoreForLayout(c.layout)
	if err != nil {
		return empty, ErrAcornFoxAssistantConfigConflict
	}
	defer store.Close()
	store.ownership = c.ownership
	lock, err := store.Acquire(ctx)
	if err != nil {
		return empty, err
	}
	defer lock.Release()
	configured, err := acornFoxAssistantConfigurationState(store.hostRoot, store)
	if c.services.stop(ctx) != nil || c.services.disable(ctx) != nil || c.services.verifyDisabled(ctx) != nil {
		return empty, ErrAcornFoxAssistantConfigUnknown
	}
	if c.services.restartServer(ctx) != nil || c.services.verifyServerDisabled(ctx) != nil {
		return empty, ErrAcornFoxAssistantConfigUnknown
	}
	if err != nil {
		return empty, ErrAcornFoxAssistantConfigConflict
	}
	state := "ASSISTANT_UNCONFIGURED"
	if configured {
		state = "ASSISTANT_DISABLED"
	}
	return AcornFoxAssistantConfigReceiptV1{1, state, configured, false}, nil
}

func completeAcornFoxAssistantServices(s acornFoxAssistantServices) bool {
	return s.stop != nil && s.disable != nil && s.enable != nil && s.start != nil && s.verifyEnabled != nil && s.verifyDisabled != nil && s.restartServer != nil && s.verifyServerEnabled != nil && s.verifyServerDisabled != nil
}

func acornFoxAssistantPrepareDirectory(root *os.Root, store *TaskAcornFoxRepoStore, principal acornFoxInstallPrincipal) error {
	info, err := root.Lstat(acornFoxAssistantDirectory)
	if errors.Is(err, os.ErrNotExist) {
		if err := acornFoxLiveEnsureDirOwned(root, store, acornFoxAssistantDirectory, 0700, principal, func() {}); err != nil {
			return err
		}
		info, err = root.Lstat(acornFoxAssistantDirectory)
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 || !acornFoxLiveObservedOwner(store, info, principal) {
		return ErrAcornFoxAssistantConfigConflict
	}
	return nil
}

func acornFoxAssistantValidateConfigurePrefix(root *os.Root, store *TaskAcornFoxRepoStore, principal acornFoxInstallPrincipal, key []byte) error {
	dir, err := root.OpenFile(acornFoxAssistantDirectory, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	children, readErr := dir.ReadDir(-1)
	closeErr := dir.Close()
	if readErr != nil || closeErr != nil || len(children) > 4 {
		return ErrAcornFoxAssistantConfigConflict
	}
	allowed := map[string]bool{"worker.json": true, "deepseek-api-key": true, ".worker.json.new": true, ".deepseek-api-key.new": true}
	for _, child := range children {
		if !allowed[child.Name()] {
			return ErrAcornFoxAssistantConfigConflict
		}
	}
	config := acornFoxAssistantCanonicalConfig()
	for _, pair := range []struct {
		path string
		raw  []byte
	}{{acornFoxAssistantConfig, config}, {acornFoxAssistantConfigNew, config}, {acornFoxAssistantKeyNew, key}} {
		if _, statErr := root.Lstat(pair.path); statErr == nil && !acornFoxLiveExactFileOwned(root, store, pair.path, pair.raw, 0600, principal, false) {
			return ErrAcornFoxAssistantConfigConflict
		} else if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
			return ErrAcornFoxAssistantConfigConflict
		}
	}
	if _, statErr := root.Lstat(acornFoxAssistantKey); statErr == nil {
		existing, readErr := acornFoxAssistantReadManagedKey(root, store, principal)
		clear(existing)
		if readErr != nil {
			return ErrAcornFoxAssistantConfigConflict
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return ErrAcornFoxAssistantConfigConflict
	}
	return nil
}

func acornFoxAssistantStage(root *os.Root, store *TaskAcornFoxRepoStore, path string, raw []byte, principal acornFoxInstallPrincipal) error {
	if acornFoxLiveExactFileOwned(root, store, path, raw, 0600, principal, false) {
		return nil
	}
	file, err := root.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return ErrAcornFoxAssistantConfigConflict
	}
	opened, statErr := file.Stat()
	stageErr := statErr
	if stageErr == nil {
		stageErr = writeFull(file, raw)
	}
	if stageErr == nil {
		stageErr = file.Chmod(0600)
	}
	if stageErr == nil {
		stageErr = acornFoxLiveApplyOwner(store, file, principal)
	}
	if stageErr == nil {
		stageErr = file.Sync()
	}
	closeErr := file.Close()
	if stageErr != nil || closeErr != nil {
		if current, currentErr := root.Lstat(path); currentErr == nil && opened != nil && os.SameFile(opened, current) {
			_ = root.Remove(path)
			_ = acornFoxLiveSyncDir(root, acornFoxAssistantDirectory)
		}
		return ErrAcornFoxAssistantConfigUnknown
	}
	if acornFoxLiveSyncDir(root, acornFoxAssistantDirectory) != nil || !acornFoxLiveExactFileOwned(root, store, path, raw, 0600, principal, false) {
		return ErrAcornFoxAssistantConfigUnknown
	}
	return nil
}

func writeFull(writer io.Writer, raw []byte) error {
	for len(raw) > 0 {
		n, err := writer.Write(raw)
		if err != nil {
			return err
		}
		if n <= 0 || n > len(raw) {
			return io.ErrShortWrite
		}
		raw = raw[n:]
	}
	return nil
}

func acornFoxAssistantConfigurationState(root *os.Root, store *TaskAcornFoxRepoStore) (bool, error) {
	entries, err := acornFoxAssistantConfigScope(root, store)
	if err != nil {
		return false, err
	}
	return len(entries) != 0, nil
}

// acornFoxAssistantConfigScope is the only dynamic host-scope extension for
// optional model configuration. Absence is valid; every present child is
// closed-list validated and no prefix exemption is granted.
func acornFoxAssistantConfigScope(root *os.Root, store *TaskAcornFoxRepoStore) ([]SubstrateEntry, error) {
	principal, ok := store.layout.owner(AcornFoxLiveRootRole)
	if !ok {
		return nil, ErrAcornFoxAssistantConfigConflict
	}
	info, err := root.Lstat(acornFoxAssistantDirectory)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 || !acornFoxLiveObservedOwner(store, info, principal) {
		return nil, ErrAcornFoxAssistantConfigConflict
	}
	dir, err := root.OpenFile(acornFoxAssistantDirectory, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrAcornFoxAssistantConfigConflict
	}
	children, readErr := dir.ReadDir(-1)
	closeErr := dir.Close()
	if readErr != nil || closeErr != nil || len(children) != 2 {
		return nil, ErrAcornFoxAssistantConfigConflict
	}
	config := acornFoxAssistantCanonicalConfig()
	if !acornFoxLiveExactFileOwned(root, store, acornFoxAssistantConfig, config, 0600, principal, false) {
		return nil, ErrAcornFoxAssistantConfigConflict
	}
	key, err := acornFoxAssistantReadManagedKey(root, store, principal)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	return []SubstrateEntry{
		{Path: acornFoxAssistantDirectory, Kind: SubstrateEntryDirectory, Mode: 0700, Role: OwnerRoleRoot, Group: GroupRoleRoot},
		{Path: acornFoxAssistantConfig, Kind: SubstrateEntryFile, Mode: 0600, Role: OwnerRoleRoot, Group: GroupRoleRoot, Size: int64(len(config)), SHA256: sha256Hex(config)},
		{Path: acornFoxAssistantKey, Kind: SubstrateEntryFile, Mode: 0600, Role: OwnerRoleRoot, Group: GroupRoleRoot, Size: int64(len(key)), SHA256: sha256Hex(key)},
	}, nil
}

func acornFoxAssistantReadManagedKey(root *os.Root, store *TaskAcornFoxRepoStore, principal acornFoxInstallPrincipal) ([]byte, error) {
	info, err := root.Lstat(acornFoxAssistantKey)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0600 || info.Size() < 16 || info.Size() > acornFoxAssistantMaxKey || acornFoxRepoNlink(info) != 1 || !acornFoxLiveObservedOwner(store, info, principal) {
		return nil, ErrAcornFoxAssistantConfigConflict
	}
	file, err := root.OpenFile(acornFoxAssistantKey, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrAcornFoxAssistantConfigConflict
	}
	opened, statErr := file.Stat()
	raw, readErr := io.ReadAll(io.LimitReader(file, acornFoxAssistantMaxKey+1))
	closeErr := file.Close()
	if statErr != nil || readErr != nil || closeErr != nil || !os.SameFile(info, opened) || !validAcornFoxAssistantKey(raw) {
		clear(raw)
		return nil, ErrAcornFoxAssistantConfigConflict
	}
	return raw, nil
}

func readProductionAcornFoxAssistantKey(path string) ([]byte, error) {
	if path == "" || !strings.HasPrefix(path, "/") || path == "/" {
		return nil, ErrAcornFoxAssistantConfigConflict
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || (info.Mode().Perm() != 0400 && info.Mode().Perm() != 0600) || info.Size() < 16 || info.Size() > acornFoxAssistantMaxKey || acornFoxRepoNlink(info) != 1 {
		return nil, ErrAcornFoxAssistantConfigConflict
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || stat.Gid != 0 {
		return nil, ErrAcornFoxAssistantConfigConflict
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrAcornFoxAssistantConfigConflict
	}
	opened, statErr := file.Stat()
	raw, readErr := io.ReadAll(io.LimitReader(file, acornFoxAssistantMaxKey+1))
	closeErr := file.Close()
	if statErr != nil || readErr != nil || closeErr != nil || !os.SameFile(info, opened) || !validAcornFoxAssistantKey(raw) {
		clear(raw)
		return nil, ErrAcornFoxAssistantConfigConflict
	}
	return raw, nil
}

func productionAcornFoxAssistantServices() acornFoxAssistantServices {
	run := func(ctx context.Context, verb, unit string) error {
		if !acornFoxAssistantSystemctlAllowed(verb, unit) {
			return ErrAcornFoxAssistantConfigConflict
		}
		command := exec.CommandContext(ctx, "/usr/bin/systemctl", verb, unit)
		command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
		command.Stdin, command.Stdout, command.Stderr = nil, nil, nil
		return command.Run()
	}
	return acornFoxAssistantServices{
		stop:                 func(ctx context.Context) error { return run(ctx, "stop", acornFoxAssistantUnit) },
		disable:              func(ctx context.Context) error { return run(ctx, "disable", acornFoxAssistantUnit) },
		enable:               func(ctx context.Context) error { return run(ctx, "enable", acornFoxAssistantUnit) },
		start:                func(ctx context.Context) error { return run(ctx, "start", acornFoxAssistantUnit) },
		verifyEnabled:        func(ctx context.Context) error { return verifyProductionAcornFoxAssistantService(ctx, true) },
		verifyDisabled:       func(ctx context.Context) error { return verifyProductionAcornFoxAssistantService(ctx, false) },
		restartServer:        func(ctx context.Context) error { return run(ctx, "restart", "acornfox-server.service") },
		verifyServerEnabled:  func(ctx context.Context) error { return verifyProductionAcornFoxAssistantServer(ctx, true) },
		verifyServerDisabled: func(ctx context.Context) error { return verifyProductionAcornFoxAssistantServer(ctx, false) },
	}
}

func acornFoxAssistantSystemctlAllowed(verb, unit string) bool {
	return unit == acornFoxAssistantUnit && (verb == "stop" || verb == "disable" || verb == "enable" || verb == "start") || unit == "acornfox-server.service" && verb == "restart"
}

func verifyProductionAcornFoxAssistantServer(ctx context.Context, enabled bool) error {
	deadline := time.Now().Add(5 * time.Second)
	for {
		if acornFoxAssistantServerState(ctx, enabled) == nil {
			return nil
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			return ErrAcornFoxAssistantConfigUnknown
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func acornFoxAssistantServerState(ctx context.Context, enabled bool) error {
	requestCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, http.MethodGet, "http://127.0.0.1:18481/readyz", nil)
	if err != nil {
		return ErrAcornFoxAssistantConfigUnknown
	}
	client := &http.Client{
		Transport:     &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: time.Second}).DialContext, DisableKeepAlives: true, ResponseHeaderTimeout: time.Second, MaxResponseHeaderBytes: 4096},
		Timeout:       time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return ErrAcornFoxAssistantConfigUnknown },
	}
	defer client.CloseIdleConnections()
	response, err := client.Do(request)
	if err != nil {
		return ErrAcornFoxAssistantConfigUnknown
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 4097))
	if err != nil || len(body) > 4096 {
		return ErrAcornFoxAssistantConfigUnknown
	}
	var readiness struct {
		Status string `json:"status"`
		Ready  bool   `json:"ready"`
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if response.StatusCode != http.StatusOK || decoder.Decode(&readiness) != nil || readiness.Status != "ok" || !readiness.Ready {
		return ErrAcornFoxAssistantConfigUnknown
	}
	var trailing any
	if !errors.Is(decoder.Decode(&trailing), io.EOF) {
		return ErrAcornFoxAssistantConfigUnknown
	}
	if !enabled {
		if _, err := os.Lstat("/run/acornfox-assistant/tools.sock"); !errors.Is(err, os.ErrNotExist) {
			return ErrAcornFoxAssistantConfigUnknown
		}
		return nil
	}
	account, err := user.Lookup("acornfox")
	if err != nil {
		return ErrAcornFoxAssistantConfigUnknown
	}
	uid, uidErr := strconv.Atoi(account.Uid)
	gid, gidErr := strconv.Atoi(account.Gid)
	info, statErr := os.Lstat("/run/acornfox-assistant/tools.sock")
	stat, ok := infoSysStat(info)
	if uidErr != nil || gidErr != nil || statErr != nil || !ok || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0660 || int(stat.Uid) != uid || int(stat.Gid) != gid {
		return ErrAcornFoxAssistantConfigUnknown
	}
	return nil
}

func verifyProductionAcornFoxAssistantService(ctx context.Context, enabled bool) error {
	deadline := time.Now().Add(5 * time.Second)
	for {
		if acornFoxAssistantServiceState(ctx, enabled) == nil {
			return nil
		}
		if !enabled || time.Now().After(deadline) || ctx.Err() != nil {
			return ErrAcornFoxAssistantConfigUnknown
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func acornFoxAssistantServiceState(ctx context.Context, enabled bool) error {
	command := exec.CommandContext(ctx, "/usr/bin/systemctl", "show", "--no-pager", "--property=Id,LoadState,UnitFileState,ActiveState,SubState", acornFoxAssistantUnit)
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	raw, err := command.Output()
	if err != nil || len(raw) > 4096 {
		return ErrAcornFoxAssistantConfigUnknown
	}
	properties := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		name, value, ok := strings.Cut(line, "=")
		if !ok {
			return ErrAcornFoxAssistantConfigUnknown
		}
		if _, exists := properties[name]; exists {
			return ErrAcornFoxAssistantConfigUnknown
		}
		properties[name] = value
	}
	if len(properties) != 5 || properties["Id"] != acornFoxAssistantUnit || properties["LoadState"] != "loaded" {
		return ErrAcornFoxAssistantConfigUnknown
	}
	if !enabled {
		if properties["UnitFileState"] != "disabled" || properties["ActiveState"] != "inactive" || properties["SubState"] != "dead" {
			return ErrAcornFoxAssistantConfigUnknown
		}
		if _, err := os.Lstat(acornFoxAssistantSocket); !errors.Is(err, os.ErrNotExist) {
			return ErrAcornFoxAssistantConfigUnknown
		}
		return nil
	}
	if properties["UnitFileState"] != "enabled" || properties["ActiveState"] != "active" || properties["SubState"] != "running" {
		return ErrAcornFoxAssistantConfigUnknown
	}
	return verifyProductionAcornFoxAssistantSocket()
}

func verifyProductionAcornFoxAssistantSocket() error {
	piAccount, err := user.Lookup("acornfox-pi")
	if err != nil {
		return ErrAcornFoxAssistantConfigUnknown
	}
	serverGroup, err := user.LookupGroup("acornfox")
	if err != nil {
		return ErrAcornFoxAssistantConfigUnknown
	}
	uid, uidErr := strconv.Atoi(piAccount.Uid)
	gid, gidErr := strconv.Atoi(serverGroup.Gid)
	info, statErr := os.Lstat(acornFoxAssistantSocket)
	stat, ok := infoSysStat(info)
	if uidErr != nil || gidErr != nil || statErr != nil || !ok || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0660 || int(stat.Uid) != uid || int(stat.Gid) != gid {
		return ErrAcornFoxAssistantConfigUnknown
	}
	return nil
}

func infoSysStat(info os.FileInfo) (*syscall.Stat_t, bool) {
	if info == nil {
		return nil, false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return stat, ok
}

func (acornFoxAssistantWorkerConfig) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "assistant worker config")
}
