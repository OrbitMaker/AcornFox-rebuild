package install

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os/exec"
	"strings"
	"time"
)

type acornFoxUpgradeServices interface {
	Run(context.Context, string, string) error
	Healthy(context.Context, acornFoxUpgradeImage) error
	EdgeHealthy(context.Context) error
}
type acornFoxRealUpgradeServices struct{}

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
	default:
		return ErrAcornFoxUpgradeConflict
	}
	switch unit {
	case "acornfox-edge.service", "acornfox-agent.service", "acornfox-server.service", "acornfox-caddy.service", "acornfox-buildkit.service", "acornfox-build-network.service":
	default:
		return ErrAcornFoxUpgradeConflict
	}
	_, e := acornFoxUpgradeCommand(ctx, "/usr/bin/systemctl", verb, unit)
	return e
}
func (acornFoxRealUpgradeServices) Healthy(ctx context.Context, image acornFoxUpgradeImage) error {
	raw, e := acornFoxUpgradeCommand(ctx, "/"+AcornFoxUpgradeHelperPath, "contract-check", "--product", "acornfox", "--layout-schema", "1")
	if e != nil {
		return e
	}
	var result AcornFoxHelperContractResultV1
	if json.Unmarshal(raw, &result) != nil || !result.OK || result.Identity == nil || *result.Identity != image.identity() || result.BindingSHA256 != image.Repo.BindingSHA256 || result.ExecutableSHA256 != image.Substrate.UpgradeHelperSHA256 {
		return ErrAcornFoxUpgradeUnknown
	}
	for _, unit := range []string{"docker.service", "acornfox-runtime-network.service", "acornfox-build-network.service", "acornfox-buildkit.service", "acornfox-caddy.service", "acornfox-server.service", "acornfox-agent.service"} {
		if e := acornFoxUpgradeServiceActive(ctx, unit); e != nil {
			return e
		}
	}
	return acornFoxUpgradeHTTP(ctx, []string{"http://127.0.0.1:18481/healthz", "http://127.0.0.1:18481/readyz"})
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
