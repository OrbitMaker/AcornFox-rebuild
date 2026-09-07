package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/open-card/open-card/internal/install"
)

const acornFoxDataRoot = "/var/lib/acornfox"
const acornFoxUpgradeMarker = acornFoxDataRoot + "/upgrade-in-progress"

var acornFoxHealthUnits = []string{
	"docker.service", "acornfox-build-network.service", "acornfox-buildkit.service", "acornfox-runtime-network.service",
	"acornfox-caddy.service", "acornfox-server.service", "acornfox-agent.service", "acornfox-edge.service",
}

type acornFoxHealthDependencies struct {
	environ func() []string
	verify  func(install.AcornFoxBuildIdentityV1) install.AcornFoxHelperContractResultV1
	probe   func(context.Context) []acornFoxLocalCheck
}

type acornFoxLocalCheck struct {
	Name string `json:"name"`
	OK   bool   `json:"ok"`
}

type acornFoxHealthOutput struct {
	Schema  int                  `json:"schema"`
	OK      bool                 `json:"ok"`
	Healthy bool                 `json:"healthy"`
	Code    string               `json:"code"`
	Scope   string               `json:"scope"`
	Checks  []acornFoxLocalCheck `json:"checks,omitempty"`
}

func productionAcornFoxHealthDependencies() acornFoxHealthDependencies {
	return acornFoxHealthDependencies{
		environ: os.Environ,
		verify:  install.VerifyProductionAcornFoxHelperContract,
		probe: func(ctx context.Context) []acornFoxLocalCheck {
			client := acornFoxHealthHTTPClient()
			defer client.CloseIdleConnections()
			return probeAcornFoxLocal(ctx, acornFoxLocalDependencies{
				command: acornFoxHealthCommand, client: client, lstat: os.Lstat,
				dataSpace: acornFoxDataSpaceAvailable,
				assistant: func(ctx context.Context) bool {
					return acornFoxAssistantHealthy(ctx, acornFoxHealthCommand, install.InspectProductionAcornFoxAssistantConfigurationV1, os.Lstat, user.Lookup, user.LookupGroup)
				},
			})
		},
	}
}

func acornFoxHealthHTTPClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			Proxy:                  nil,
			DialContext:            (&net.Dialer{Timeout: 2 * time.Second}).DialContext,
			DisableKeepAlives:      true,
			ResponseHeaderTimeout:  2 * time.Second,
			MaxResponseHeaderBytes: 8192,
		},
		Timeout:       3 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect refused") },
	}
}

func runAcornFoxHealth(ctx context.Context, stdout io.Writer, euid func() int, deps acornFoxHealthDependencies) int {
	result := acornFoxHealthOutput{Schema: 1, Code: "local_health_failed", Scope: "local_services_only"}
	finish := func(code string) int {
		result.Code = code
		if stdout == nil {
			return exitFailure
		}
		if err := json.NewEncoder(stdout).Encode(result); err != nil {
			return exitFailure
		}
		if result.OK && result.Healthy {
			return exitSuccess
		}
		return exitFailure
	}
	if euid == nil || euid() != 0 {
		return finish("root_required")
	}
	identity := install.AcornFoxBuildIdentityV1{
		SchemaVersion: 1, Product: "acornfox", LayoutVersion: 1, Role: helperRole,
		Version: buildVersion, ReleaseID: "release-" + buildVersion, SourceCommit: buildSourceCommit,
	}
	if buildLayoutSchema != "1" || identity.Validate() != nil {
		return finish("identity_mismatch")
	}
	if deps.environ == nil || !acornFoxHealthEnvironment(deps.environ()) {
		return finish("environment_rejected")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if ctx.Err() != nil {
		return finish("context_canceled")
	}
	if deps.verify == nil || deps.probe == nil {
		return finish("construction_failed")
	}
	// No service, HTTP or data probe precedes the installed executable contract.
	proof := deps.verify(identity)
	if proof.Validate() != nil || !proof.OK || proof.Identity == nil || *proof.Identity != identity {
		return finish("helper_contract_failed")
	}
	runCtx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	checks := deps.probe(runCtx)
	names := acornFoxLocalCheckNames()
	if len(checks) != len(names) {
		return finish("local_health_failed")
	}
	healthy := runCtx.Err() == nil
	for i, check := range checks {
		if check.Name != names[i] {
			return finish("local_health_failed")
		}
		healthy = healthy && check.OK
	}
	result.Checks = checks
	result.OK, result.Healthy = healthy, healthy
	if healthy {
		return finish("ok")
	}
	return finish("local_health_failed")
}

func acornFoxHealthEnvironment(env []string) bool {
	mode := false
	for _, entry := range env {
		name, value, ok := strings.Cut(entry, "=")
		if !ok {
			return false
		}
		if name == "ACORNFOX_RUNTIME_MODE" {
			if mode || value != "clean" {
				return false
			}
			mode = true
		} else if strings.HasPrefix(name, "ACORNFOX_") || strings.HasPrefix(name, "OPEN_CARD_") {
			return false
		}
	}
	return mode
}

func acornFoxLocalCheckNames() []string {
	names := []string{"upgrade_not_pending", "data_space_available"}
	names = append(names, acornFoxHealthUnits...)
	return append(names, "assistant_worker", "control_plane_health", "control_plane_ready", "edge_loopback_health")
}

type acornFoxLocalDependencies struct {
	command   func(context.Context, string, ...string) ([]byte, error)
	client    *http.Client
	lstat     func(string) (os.FileInfo, error)
	dataSpace func() bool
	assistant func(context.Context) bool
}

func probeAcornFoxLocal(ctx context.Context, deps acornFoxLocalDependencies) []acornFoxLocalCheck {
	names := acornFoxLocalCheckNames()
	checks := make([]acornFoxLocalCheck, len(names))
	for i, name := range names {
		checks[i].Name = name
	}
	if ctx == nil || ctx.Err() != nil || deps.command == nil || deps.client == nil || deps.lstat == nil || deps.dataSpace == nil || deps.assistant == nil {
		return checks
	}
	_, markerErr := deps.lstat(acornFoxUpgradeMarker)
	checks[0].OK = errors.Is(markerErr, os.ErrNotExist)
	if !checks[0].OK {
		return checks
	}
	checks[1].OK = deps.dataSpace()
	for i, unit := range acornFoxHealthUnits {
		if ctx.Err() != nil {
			return checks
		}
		probeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		raw, err := deps.command(probeCtx, "/usr/bin/systemctl", "show", "--no-pager", "--property=Id,LoadState,ActiveState,SubState", unit)
		cancel()
		checks[i+2].OK = err == nil && acornFoxUnitRunning(raw, unit)
	}
	start := 2 + len(acornFoxHealthUnits)
	checks[start].OK = deps.assistant(ctx)
	start++
	for i, target := range []string{"http://127.0.0.1:18481/healthz", "http://127.0.0.1:18481/readyz", "http://127.0.0.1:18482/healthz"} {
		checks[start+i].OK = acornFoxHTTPHealthy(ctx, deps.client, target, i < 2)
	}
	_, markerErr = deps.lstat(acornFoxUpgradeMarker)
	checks[0].OK = errors.Is(markerErr, os.ErrNotExist)
	return checks
}

func acornFoxAssistantHealthy(ctx context.Context, command func(context.Context, string, ...string) ([]byte, error), inspect func() (bool, error), lstat func(string) (os.FileInfo, error), lookupUser func(string) (*user.User, error), lookupGroup func(string) (*user.Group, error)) bool {
	if ctx == nil || ctx.Err() != nil || command == nil || inspect == nil || lstat == nil || lookupUser == nil || lookupGroup == nil {
		return false
	}
	configured, err := inspect()
	if err != nil {
		return false
	}
	raw, err := command(ctx, "/usr/bin/systemctl", "show", "--no-pager", "--property=Id,LoadState,UnitFileState,ActiveState,SubState", "acornfox-pi-worker.service")
	if err != nil || len(raw) > 4096 {
		return false
	}
	properties := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		name, value, ok := strings.Cut(line, "=")
		if !ok {
			return false
		}
		if _, exists := properties[name]; exists {
			return false
		}
		properties[name] = value
	}
	if len(properties) != 5 || properties["Id"] != "acornfox-pi-worker.service" || properties["LoadState"] != "loaded" {
		return false
	}
	disabled := properties["UnitFileState"] == "disabled" && properties["ActiveState"] == "inactive" && properties["SubState"] == "dead"
	if disabled {
		_, socketErr := lstat(acornFoxPIWorkerSocket)
		return errors.Is(socketErr, os.ErrNotExist)
	}
	if !configured || properties["UnitFileState"] != "enabled" || properties["ActiveState"] != "active" || properties["SubState"] != "running" {
		return false
	}
	account, accountErr := lookupUser("acornfox-pi")
	group, groupErr := lookupGroup("acornfox")
	uid, uidErr := strconv.Atoi(userField(account, true))
	gid, gidErr := strconv.Atoi(groupField(group))
	info, socketErr := lstat(acornFoxPIWorkerSocket)
	stat, ok := healthStat(info)
	return accountErr == nil && groupErr == nil && uidErr == nil && gidErr == nil && socketErr == nil && ok && info.Mode()&os.ModeSocket != 0 && info.Mode().Perm() == 0660 && int(stat.Uid) == uid && int(stat.Gid) == gid
}

const acornFoxPIWorkerSocket = "/run/acornfox-pi/worker.sock"

func userField(account *user.User, uid bool) string {
	if account == nil {
		return ""
	}
	if uid {
		return account.Uid
	}
	return account.Gid
}

func groupField(group *user.Group) string {
	if group == nil {
		return ""
	}
	return group.Gid
}

func healthStat(info os.FileInfo) (*syscall.Stat_t, bool) {
	if info == nil {
		return nil, false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return stat, ok
}

func acornFoxUnitRunning(raw []byte, unit string) bool {
	if len(raw) > 4096 {
		return false
	}
	got := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return false
		}
		if _, exists := got[key]; exists {
			return false
		}
		got[key] = value
	}
	substate := "running"
	if unit == "acornfox-runtime-network.service" {
		substate = "exited"
	} // successful RemainAfterExit oneshot
	return len(got) == 4 && got["Id"] == unit && got["LoadState"] == "loaded" && got["ActiveState"] == "active" && got["SubState"] == substate
}

func acornFoxHTTPHealthy(ctx context.Context, client *http.Client, target string, control bool) bool {
	probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(probeCtx, http.MethodGet, target, nil)
	if err != nil {
		return false
	}
	response, err := client.Do(request)
	if err != nil {
		return false
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return false
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 4097))
	if err != nil || len(body) > 4096 {
		return false
	}
	// The fixed Caddy edge health route deliberately returns an empty 200.
	if !control {
		return len(bytes.TrimSpace(body)) == 0
	}
	var reply struct {
		Status string `json:"status"`
		Ready  bool   `json:"ready"`
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&reply) != nil || reply.Status != "ok" || !reply.Ready {
		return false
	}
	var extra any
	return errors.Is(decoder.Decode(&extra), io.EOF)
}

type acornFoxBoundedOutput struct{ buffer bytes.Buffer }

func (b *acornFoxBoundedOutput) Write(p []byte) (int, error) {
	if len(p) > 4096-b.buffer.Len() {
		return 0, errors.New("service response too large")
	}
	return b.buffer.Write(p)
}

func acornFoxHealthCommand(ctx context.Context, path string, args ...string) ([]byte, error) {
	if runtime.GOOS != "linux" {
		return nil, errors.New("Linux required")
	}
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C"}
	var output acornFoxBoundedOutput
	cmd.Stdout, cmd.Stderr = &output, io.Discard
	err := cmd.Run()
	return output.buffer.Bytes(), err
}

func acornFoxDataSpaceAvailable() bool {
	info, err := os.Lstat(acornFoxDataRoot)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
		return false
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != 0 {
		return false
	}
	var stat syscall.Statfs_t
	if err := syscall.Statfs(acornFoxDataRoot, &stat); err != nil {
		return false
	}
	return stat.Blocks > 0 && stat.Bavail > 0 && stat.Bavail <= stat.Blocks && stat.Files > 0 && stat.Ffree > 0 && stat.Ffree <= stat.Files
}
