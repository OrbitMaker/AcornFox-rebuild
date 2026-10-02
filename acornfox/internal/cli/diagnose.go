package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
)

const lastDeploymentsFileName = "last-deployments.json"

// lastDeploymentKey identifies an app on a target in last-deployments.json.
func lastDeploymentKey(targetName, app string) string { return targetName + "/" + app }

// loadLastDeployments reads <UserConfigDir>/acornfox/last-deployments.json, a
// map of "target/app" to the most recent deployment id submitted from this
// machine. It lives outside .acornfox so deploys do not churn the project repo.
func loadLastDeployments(configDir string) (map[string]string, error) {
	dir, _, err := configPaths(configDir)
	if err != nil {
		return nil, err
	}
	m := map[string]string{}
	data, err := os.ReadFile(filepath.Join(dir, lastDeploymentsFileName))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return m, nil
		}
		return nil, err
	}
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// rememberDeployment records id as the latest deployment of app on target.
// Failures are ignored: this is a convenience for `diagnose` without an id.
func (a *app) rememberDeployment(targetName, app, id string) {
	if id == "" {
		return
	}
	m, err := loadLastDeployments(a.configDir)
	if err != nil {
		m = map[string]string{}
	}
	m[lastDeploymentKey(targetName, app)] = id
	dir, _, err := configPaths(a.configDir)
	if err != nil {
		return
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return
	}
	file := filepath.Join(dir, lastDeploymentsFileName)
	tmp := file + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return
	}
	_ = os.Rename(tmp, file)
}

// cmdDiagnose implements `diagnose [DEPLOYMENT_ID]`: the status and diagnosis
// of one deployment, by default the latest one submitted from this machine
// for the resolved app.
func (a *app) cmdDiagnose(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("diagnose", flag.ContinueOnError)
	fs.SetOutput(a.out.stderr)
	rest, err := parseFlags(fs, args)
	if err != nil {
		return exitUsage
	}
	if len(rest) > 1 {
		return a.out.usageError("diagnose 最多接受一个部署 ID")
	}

	res, err := a.resolveTargetAndApp()
	if err != nil {
		return a.out.usageError("%s", err.Error())
	}
	id := ""
	if len(rest) == 1 {
		id = rest[0]
	} else {
		m, lerr := loadLastDeployments(a.configDir)
		if lerr == nil {
			id = m[lastDeploymentKey(res.targetName, res.app)]
		}
		if id == "" {
			return a.out.usageError("本机没有应用 %s 的部署记录；用 acornfox diagnose DEPLOYMENT_ID 指定部署", res.app)
		}
	}

	api, derr := a.dial(ctx, res.target)
	if derr != nil {
		return a.out.fail(derr)
	}
	defer api.Close()
	return a.statusDeployment(ctx, api, id)
}
