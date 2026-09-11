package install

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"github.com/open-card/open-card/internal/acornfoxsetup"
)

type acornFoxUpgradeServices interface {
	Run(context.Context, string, string) error
	Healthy(context.Context, acornFoxUpgradeImage) error
	EdgeHealthy(context.Context) error
}
type acornFoxRealUpgradeServices struct{}

var _ acornFoxUpgradePIState = acornFoxRealUpgradeServices{}
var _ acornFoxUpgradeRecoveryHelperHealth = acornFoxRealUpgradeServices{}
var _ acornFoxUpgradeLegacyPIState = acornFoxRealUpgradeServices{}

func (acornFoxRealUpgradeServices) PILegacyAbsent(ctx context.Context) (bool, error) {
	raw, err := acornFoxUpgradeCommand(ctx, "/usr/bin/systemctl", "show", "acornfox-pi-worker.service", "--property=LoadState", "--value")
	if err != nil {
		return false, ErrAcornFoxUpgradeUnknown
	}
	state := strings.TrimSpace(string(raw))
	if state == "not-found" {
		return true, nil
	}
	if state == "loaded" {
		return false, nil
	}
	return false, ErrAcornFoxUpgradeUnknown
}

func (acornFoxRealUpgradeServices) PIEnabled(ctx context.Context) (bool, error) {
	enabled, err := acornFoxUpgradePIUnitEnabled(ctx)
	if err != nil {
		return false, err
	}
	raw, err := acornFoxUpgradeCommand(ctx, "/usr/bin/systemctl", "show", "acornfox-pi-worker.service", "--property=Id,LoadState,UnitFileState,ActiveState,SubState")
	if err != nil {
		return false, ErrAcornFoxUpgradeUnknown
	}
	return parseAcornFoxPIServiceState(enabled, raw)
}

func acornFoxUpgradePIUnitEnabled(ctx context.Context) (bool, error) {
	bounded, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	command := exec.CommandContext(bounded, "/usr/bin/systemctl", "is-enabled", "acornfox-pi-worker.service")
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	raw, err := command.Output()
	if len(raw) > 128 {
		return false, ErrAcornFoxUpgradeUnknown
	}
	state := strings.TrimSpace(string(raw))
	if err == nil && state == "enabled" {
		return true, nil
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.ExitCode() == 1 && state == "disabled" {
		return false, nil
	}
	return false, ErrAcornFoxUpgradeUnknown
}

func parseAcornFoxPIServiceState(enabled bool, raw []byte) (bool, error) {
	if len(raw) == 0 || len(raw) > 4096 {
		return false, ErrAcornFoxUpgradeUnknown
	}
	values := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return false, ErrAcornFoxUpgradeUnknown
		}
		if _, exists := values[key]; exists {
			return false, ErrAcornFoxUpgradeUnknown
		}
		values[key] = value
	}
	if len(values) != 5 || values["Id"] != "acornfox-pi-worker.service" || values["LoadState"] != "loaded" {
		return false, ErrAcornFoxUpgradeUnknown
	}
	if enabled != (values["UnitFileState"] == "enabled") || !enabled && values["UnitFileState"] != "disabled" {
		return false, ErrAcornFoxUpgradeConflict
	}
	running := values["ActiveState"] == "active" && values["SubState"] == "running"
	inactive := values["ActiveState"] == "inactive" && values["SubState"] == "dead"
	if enabled && running {
		return true, nil
	}
	if !enabled && inactive {
		return false, nil
	}
	return false, ErrAcornFoxUpgradeConflict
}

func acornFoxUpgradeCommand(ctx context.Context, path string, args ...string) ([]byte, error) {
	bounded, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	cmd := exec.CommandContext(bounded, path, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	raw, e := cmd.Output()
	if e != nil || len(raw) > 1<<20 {
		return nil, ErrAcornFoxUpgradeUnknown
	}
	return raw, nil
}
func (acornFoxRealUpgradeServices) Run(ctx context.Context, verb, unit string) error {
	switch verb {
	case "daemon-reload":
		if unit != "" {
			return ErrAcornFoxUpgradeConflict
		}
		_, e := acornFoxUpgradeCommand(ctx, "/usr/bin/systemctl", verb)
		return e
	case "start", "stop":
	case "disable":
		if unit != "acornfox-pi-worker.service" {
			return ErrAcornFoxUpgradeConflict
		}
	default:
		return ErrAcornFoxUpgradeConflict
	}
	switch unit {
	case "acornfox-edge.service", "acornfox-agent.service", "acornfox-server.service", "acornfox-caddy.service", "acornfox-buildkit.service", "acornfox-build-network.service", "acornfox-pi-worker.service":
	default:
		return ErrAcornFoxUpgradeConflict
	}
	if verb == "stop" && unit == acornFoxEdgeUnit {
		legacy, err := acornFoxEdgeLegacyStopAuthority()
		if err != nil {
			return err
		}
		return stopAcornFoxEdge(ctx, acornFoxUpgradeCommand, legacy, acornFoxEdgeStopBudget, 200*time.Millisecond)
	}
	_, e := acornFoxUpgradeCommand(ctx, "/usr/bin/systemctl", verb, unit)
	return e
}
func (services acornFoxRealUpgradeServices) Healthy(ctx context.Context, image acornFoxUpgradeImage) error {
	return services.HealthyWithRecoveryHelper(ctx, image, image)
}

func (acornFoxRealUpgradeServices) HealthyWithRecoveryHelper(ctx context.Context, image, recovery acornFoxUpgradeImage) error {
	raw, e := acornFoxUpgradeCommand(ctx, "/"+AcornFoxUpgradeHelperPath, "contract-check", "--product", "acornfox", "--layout-schema", "1")
	if e != nil {
		return e
	}
	var result AcornFoxHelperContractResultV1
	if json.Unmarshal(raw, &result) != nil || !result.OK || result.Identity == nil || *result.Identity != recovery.identity() || result.BindingSHA256 != recovery.Repo.BindingSHA256 || result.ExecutableSHA256 != recovery.Substrate.UpgradeHelperSHA256 {
		return ErrAcornFoxUpgradeUnknown
	}
	units, unitErr := acornFoxUpgradeHealthyUnits(image)
	if unitErr != nil {
		return unitErr
	}
	for _, unit := range units {
		if e := acornFoxUpgradeServiceActive(ctx, unit); e != nil {
			return e
		}
	}
	if image.Runtime.Inputs.Origin == acornfoxsetup.ExactLocalLoopbackOrigin {
		return VerifyAcornFoxLocalReadyV1(ctx)
	}
	return acornFoxUpgradeHTTP(ctx, []string{"http://127.0.0.1:18481/healthz", "http://127.0.0.1:18481/readyz"})
}

func acornFoxUpgradeHealthyUnits(image acornFoxUpgradeImage) ([]string, error) {
	units := []string{"docker.service", "acornfox-build-network.service", "acornfox-buildkit.service", "acornfox-caddy.service", "acornfox-server.service", "acornfox-agent.service"}
	switch image.Substrate.CandidateReceipt.MigrationVersion {
	case AcornFoxLegacyPredecessorMigration:
		return units, nil
	case acornFoxRecentPredecessorMigration, AcornFoxV1MigrationVersion:
		return []string{"docker.service", "acornfox-runtime-network.service", "acornfox-build-network.service", "acornfox-buildkit.service", "acornfox-caddy.service", "acornfox-server.service", "acornfox-agent.service"}, nil
	default:
		return nil, ErrAcornFoxUpgradeConflict
	}
}
func (acornFoxRealUpgradeServices) EdgeHealthy(ctx context.Context) error {
	if e := acornFoxUpgradeServiceActive(ctx, "acornfox-edge.service"); e != nil {
		return e
	}
	return acornFoxUpgradeHTTP(ctx, []string{"http://127.0.0.1:18482/healthz"})
}
func acornFoxUpgradeServiceActive(ctx context.Context, unit string) error {
	raw, e := acornFoxUpgradeCommand(ctx, "/usr/bin/systemctl", "show", unit, "--property=Id,LoadState,ActiveState,SubState")
	if e != nil {
		return e
	}
	values := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok || values[k] != "" {
			return ErrAcornFoxUpgradeUnknown
		}
		values[k] = v
	}
	sub := "running"
	if unit == "acornfox-runtime-network.service" {
		sub = "exited"
	}
	if len(values) != 4 || values["Id"] != unit || values["LoadState"] != "loaded" || values["ActiveState"] != "active" || values["SubState"] != sub {
		return ErrAcornFoxUpgradeUnknown
	}
	return nil
}
func acornFoxUpgradeHTTP(ctx context.Context, targets []string) error {
	bounded, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	for _, target := range targets {
		for {
			req, e := http.NewRequestWithContext(bounded, http.MethodGet, target, nil)
			if e != nil {
				return ErrAcornFoxUpgradeUnknown
			}
			resp, e := client.Do(req)
			ok := e == nil && resp.StatusCode == 200
			if resp != nil {
				_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
				resp.Body.Close()
			}
			if ok {
				break
			}
			select {
			case <-bounded.Done():
				return ErrAcornFoxUpgradeUnknown
			case <-time.After(200 * time.Millisecond):
			}
		}
	}
	return nil
}

var localReadyHTTPClient = &http.Client{
	Timeout: 3 * time.Second,
	Transport: &http.Transport{
		Proxy: nil,
	},
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// VerifyAcornFoxLocalReadyV1 performs a bounded, strict health check on local loopback:
// 1. http://127.0.0.1:18481/healthz (200 OK)
// 2. http://127.0.0.1:18481/readyz (200 OK)
// 3. http://127.0.0.1:8080/api/v1/acornfox/setup (200 OK, JSON state == "initialized" or "uninitialized")
func VerifyAcornFoxLocalReadyV1(ctx context.Context) error {
	return verifyLocalReadyWithTimeout(ctx, 45*time.Second, "http://127.0.0.1:18481", "http://127.0.0.1:8080")
}

func verifyLocalReadyWithTimeout(ctx context.Context, timeout time.Duration, direct18481Base, caddy8080Base string) error {
	bounded, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// 1. Direct healthz and readyz on server port 18481
	for _, path := range []string{"/healthz", "/readyz"} {
		target := direct18481Base + path
		for {
			req, err := http.NewRequestWithContext(bounded, http.MethodGet, target, nil)
			if err != nil {
				return ErrAcornFoxUpgradeUnknown
			}
			resp, err := localReadyHTTPClient.Do(req)
			ok := err == nil && resp.StatusCode == http.StatusOK
			if resp != nil {
				_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
				_ = resp.Body.Close()
			}
			if ok {
				break
			}
			select {
			case <-bounded.Done():
				return ErrAcornFoxUpgradeUnknown
			case <-time.After(200 * time.Millisecond):
			}
		}
	}

	// 2. Local Caddy setup API on port 8080
	setupTarget := caddy8080Base + "/api/v1/acornfox/setup"
	for {
		req, err := http.NewRequestWithContext(bounded, http.MethodGet, setupTarget, nil)
		if err != nil {
			return ErrAcornFoxUpgradeUnknown
		}
		resp, err := localReadyHTTPClient.Do(req)
		var ok bool
		if err == nil && resp.StatusCode == http.StatusOK {
			body, readErr := io.ReadAll(io.LimitReader(resp.Body, 4096))
			if readErr == nil && len(body) < 4096 {
				ok = isValidStrictSetupPayload(body)
			}
		}
		if resp != nil {
			_ = resp.Body.Close()
		}
		if ok {
			break
		}
		select {
		case <-bounded.Done():
			return ErrAcornFoxUpgradeUnknown
		case <-time.After(200 * time.Millisecond):
		}
	}

	return nil
}

func isValidStrictSetupPayload(data []byte) bool {
	dec := json.NewDecoder(bytes.NewReader(data))
	// 1. Must start with '{'
	t, err := dec.Token()
	if err != nil || t != json.Delim('{') {
		return false
	}
	stateVal := ""
	stateFound := false

	// 2. Iterate object tokens: must contain only "state": "initialized"|"uninitialized"
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return false
		}
		key, ok := keyTok.(string)
		if !ok || key != "state" || stateFound {
			return false // unexpected or duplicate key
		}
		valTok, err := dec.Token()
		if err != nil {
			return false
		}
		val, ok := valTok.(string)
		if !ok {
			return false
		}
		stateVal = val
		stateFound = true
	}

	// 3. Must end with '}'
	t, err = dec.Token()
	if err != nil || t != json.Delim('}') {
		return false
	}

	// 4. Must not have trailing JSON tokens
	if _, err := dec.Token(); err != io.EOF {
		return false
	}

	return stateVal == "initialized" || stateVal == "uninitialized"
}
