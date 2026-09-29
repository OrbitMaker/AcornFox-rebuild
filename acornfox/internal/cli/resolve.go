package cli

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/acornfox/acornfox/internal/client"
)

// errNeedValue is a small usage error for a flag missing its value.
func errNeedValue(flag string) error {
	return fmt.Errorf("%s 需要一个值", flag)
}

// resolution is the outcome of selection: which target entry and app name to
// use, plus whether they came from a .acornfox already present.
type resolution struct {
	target      client.Target
	targetName  string
	app         string
	appExplicit bool // app came from --app or .acornfox (not just directory default)
}

// resolveTarget picks the target following priority: --target > .acornfox >
// targets.json default. It returns a usage-style error message when nothing is
// selectable.
func (a *app) resolveTarget() (client.Target, string, error) {
	tf, err := loadTargets(a.configDir)
	if err != nil {
		return client.Target{}, "", fmt.Errorf("读取 targets.json 失败：%v", err)
	}

	name := a.flagTarget
	if name == "" {
		if pf, _, perr := loadProject(a.workDir); perr == nil && pf != nil {
			name = pf.Target
		}
	}
	if name == "" {
		name = tf.Default
	}
	if name == "" {
		return client.Target{}, "", fmt.Errorf("未选择服务器；先运行 acornfox target add，或用 --target 指定")
	}

	t, ok := tf.Targets[name]
	if !ok {
		return client.Target{}, "", fmt.Errorf("找不到服务器 %q；用 acornfox target list 查看", name)
	}
	out := *t
	out.Name = name
	if out.RemoteCommand == "" {
		out.RemoteCommand = defaultRemote
	}
	return out, name, nil
}

// resolveApp picks the app name following priority: --app > .acornfox > the
// working directory name normalized. The second return reports whether the app
// name was explicit (flag or .acornfox), the third the normalized-but-invalid
// name for error hints.
func (a *app) resolveApp() (name string, explicit bool, err error) {
	if a.flagApp != "" {
		n, ok := normalizeAppName(a.flagApp)
		if !ok {
			return "", true, fmt.Errorf("应用名 %q 不合法；只能用小写字母、数字和连字符，用 --app 指定一个合法名称", a.flagApp)
		}
		return n, true, nil
	}
	if pf, _, perr := loadProject(a.workDir); perr == nil && pf != nil && pf.App != "" {
		return pf.App, true, nil
	}
	// Default from directory name.
	base := filepath.Base(a.workDir)
	n, ok := normalizeAppName(base)
	if !ok {
		return "", false, fmt.Errorf("无法从目录名 %q 推断应用名；用 --app 指定", base)
	}
	return n, false, nil
}

// resolveTargetAndApp resolves both. Errors are usage errors.
func (a *app) resolveTargetAndApp() (resolution, error) {
	t, name, err := a.resolveTarget()
	if err != nil {
		return resolution{}, err
	}
	appName, explicit, err := a.resolveApp()
	if err != nil {
		return resolution{}, err
	}
	return resolution{target: t, targetName: name, app: appName, appExplicit: explicit}, nil
}

// dial opens a client.API for the resolved target using the injected connector.
// A nil connector is a programming error.
func (a *app) dial(ctx context.Context, t client.Target) (client.API, error) {
	if a.connect == nil {
		return nil, &client.Error{Diag: client.Diagnosis{Stage: "connect", Code: "server_down", Message: "内部错误：未配置连接器"}}
	}
	return a.connect(ctx, t)
}
