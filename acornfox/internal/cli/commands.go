package cli

import (
	"context"
	"flag"
	"strings"
	"time"

	"github.com/acornfox/acornfox/internal/client"
)

// cmdStatus implements `status [DEPLOYMENT_ID]`.
func (a *app) cmdStatus(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	fs.SetOutput(a.out.stderr)
	rest, err := parseFlags(fs, args)
	if err != nil {
		return exitUsage
	}
	if len(rest) > 1 {
		return a.out.usageError("status 最多接受一个部署 ID")
	}

	res, err := a.resolveTargetAndApp()
	if err != nil {
		return a.out.usageError("%s", err.Error())
	}
	api, derr := a.dial(ctx, res.target)
	if derr != nil {
		return a.out.fail(derr)
	}
	defer api.Close()

	if len(rest) == 1 {
		return a.statusDeployment(ctx, api, rest[0])
	}
	return a.statusApp(ctx, api, res.app)
}

func (a *app) statusDeployment(ctx context.Context, api client.API, id string) int {
	dep, events, err := api.Deployment(ctx, id, 0)
	if err != nil {
		return a.out.fail(err)
	}
	if a.out.json {
		evs := make([]map[string]any, 0, len(events))
		for _, ev := range events {
			evs = append(evs, map[string]any{"id": ev.ID, "at": ev.At, "stage": ev.Stage, "message": ev.Message})
		}
		fields := map[string]any{
			"deployment_id": dep.ID,
			"app":           dep.App,
			"version":       dep.Seq,
			"status":        dep.Status,
			"source_kind":   dep.SourceKind,
			"events":        evs,
		}
		if dep.Diagnosis != nil {
			fields["diagnosis"] = map[string]any{
				"stage": dep.Diagnosis.Stage, "code": dep.Diagnosis.Code,
				"message": dep.Diagnosis.Message, "log_excerpt": dep.Diagnosis.LogExcerpt, "hint": dep.Diagnosis.Hint,
			}
		}
		a.out.emitJSON(fields)
		return exitOK
	}
	a.out.human("部署 %s（应用 %s，版本 %d）状态：%s", dep.ID, dep.App, dep.Seq, dep.Status)
	for _, ev := range events {
		a.out.human("[%s] %s", ev.Stage, ev.Message)
	}
	if dep.Diagnosis != nil {
		a.out.printDiagnosis(*dep.Diagnosis)
	}
	return exitOK
}

func (a *app) statusApp(ctx context.Context, api client.API, appName string) int {
	app, err := api.App(ctx, appName)
	if err != nil {
		return a.out.fail(err)
	}
	envKeys := make([]map[string]any, 0, len(app.Env))
	for _, e := range app.Env {
		// Values for secrets are never returned by the server; do not print
		// any value here regardless.
		envKeys = append(envKeys, map[string]any{"key": e.Key, "secret": e.Secret})
	}
	volumes := make([]string, 0, len(app.Volumes))
	for _, v := range app.Volumes {
		volumes = append(volumes, v.Path)
	}
	if a.out.json {
		a.out.emitJSON(map[string]any{
			"app":                app.Name,
			"url":                app.URL,
			"desired":            app.Desired,
			"observed_state":     app.ObservedState,
			"current_deployment": app.CurrentDeployment,
			"port":               app.Port,
			"memory_mb":          app.MemoryMB,
			"cpu_milli":          app.CPUMilli,
			"health_path":        app.HealthPath,
			"volumes":            volumes,
			"env":                envKeys,
		})
		return exitOK
	}
	a.out.human("应用 %s", app.Name)
	if app.URL != "" {
		a.out.human("网址：%s", app.URL)
	}
	a.out.human("期望状态：%s；观察状态：%s", app.Desired, app.ObservedState)
	a.out.human("当前版本：%s", app.CurrentDeployment)
	if len(volumes) > 0 {
		a.out.human("数据卷：%s", strings.Join(volumes, ", "))
	}
	if len(app.Env) > 0 {
		keys := make([]string, 0, len(app.Env))
		for _, e := range app.Env {
			if e.Secret {
				keys = append(keys, e.Key+"(密钥)")
			} else {
				keys = append(keys, e.Key)
			}
		}
		a.out.human("环境变量：%s", strings.Join(keys, ", "))
	}
	return exitOK
}

// cmdApps implements `apps`.
func (a *app) cmdApps(ctx context.Context, args []string) int {
	if len(args) != 0 {
		return a.out.usageError("apps 不接受参数")
	}
	// apps does not need an app name, only a target.
	t, _, err := a.resolveTarget()
	if err != nil {
		return a.out.usageError("%s", err.Error())
	}
	api, derr := a.dial(ctx, t)
	if derr != nil {
		return a.out.fail(derr)
	}
	defer api.Close()

	apps, serr := api.Apps(ctx)
	if serr != nil {
		return a.out.fail(serr)
	}
	if a.out.json {
		list := make([]map[string]any, 0, len(apps))
		for _, ap := range apps {
			list = append(list, map[string]any{
				"app": ap.Name, "url": ap.URL, "desired": ap.Desired,
				"observed_state": ap.ObservedState,
			})
		}
		a.out.emitJSON(map[string]any{"apps": list})
		return exitOK
	}
	if len(apps) == 0 {
		a.out.human("服务器上还没有应用。")
		return exitOK
	}
	for _, ap := range apps {
		a.out.human("%s\t%s\t%s", ap.Name, ap.ObservedState, ap.URL)
	}
	return exitOK
}

// cmdLogs implements `logs [--tail N]`.
func (a *app) cmdLogs(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("logs", flag.ContinueOnError)
	fs.SetOutput(a.out.stderr)
	tail := fs.Int("tail", 100, "返回最近 N 行（最多 1000）")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *tail < 1 {
		*tail = 100
	}
	if *tail > 1000 {
		*tail = 1000
	}
	res, err := a.resolveTargetAndApp()
	if err != nil {
		return a.out.usageError("%s", err.Error())
	}
	api, derr := a.dial(ctx, res.target)
	if derr != nil {
		return a.out.fail(derr)
	}
	defer api.Close()

	lines, serr := api.Logs(ctx, res.app, *tail)
	if serr != nil {
		return a.out.fail(serr)
	}
	if a.out.json {
		a.out.emitJSON(map[string]any{"lines": lines})
		return exitOK
	}
	for _, l := range lines {
		a.out.human("%s", l)
	}
	return exitOK
}

// cmdEnv implements `env set KEY=VALUE [--secret]` / `env unset KEY` /
// `env list`.
func (a *app) cmdEnv(ctx context.Context, args []string) int {
	if len(args) == 0 {
		return a.out.usageError("env 需要子命令：set / unset / list")
	}
	sub, rest := args[0], args[1:]
	res, err := a.resolveTargetAndApp()
	if err != nil {
		return a.out.usageError("%s", err.Error())
	}

	switch sub {
	case "set":
		fs := flag.NewFlagSet("env set", flag.ContinueOnError)
		fs.SetOutput(a.out.stderr)
		secret := fs.Bool("secret", false, "标记为密钥（值永不回显）")
		pairs, perr := parseFlags(fs, rest)
		if perr != nil {
			return exitUsage
		}
		if len(pairs) != 1 {
			return a.out.usageError("用法：env set KEY=VALUE [--secret]")
		}
		key, value, ok := strings.Cut(pairs[0], "=")
		if !ok || key == "" {
			return a.out.usageError("环境变量格式应为 KEY=VALUE")
		}
		// Register the value as a secret so it is never printed in any output.
		if *secret {
			a.out.addSecret(value)
		}
		api, derr := a.dial(ctx, res.target)
		if derr != nil {
			return a.out.fail(derr)
		}
		defer api.Close()
		if serr := api.SetEnv(ctx, res.app, key, value, *secret); serr != nil {
			return a.out.fail(serr)
		}
		if a.out.json {
			// Never include the value.
			a.out.emitJSON(map[string]any{"key": key, "secret": *secret, "note": "下次部署生效"})
			return exitOK
		}
		a.out.human("已设置 %s，下次部署生效。", key)
		return exitOK

	case "unset":
		if len(rest) != 1 {
			return a.out.usageError("用法：env unset KEY")
		}
		key := rest[0]
		api, derr := a.dial(ctx, res.target)
		if derr != nil {
			return a.out.fail(derr)
		}
		defer api.Close()
		if serr := api.UnsetEnv(ctx, res.app, key); serr != nil {
			return a.out.fail(serr)
		}
		if a.out.json {
			a.out.emitJSON(map[string]any{"key": key, "note": "下次部署生效"})
			return exitOK
		}
		a.out.human("已删除 %s，下次部署生效。", key)
		return exitOK

	case "list":
		api, derr := a.dial(ctx, res.target)
		if derr != nil {
			return a.out.fail(derr)
		}
		defer api.Close()
		app, serr := api.App(ctx, res.app)
		if serr != nil {
			return a.out.fail(serr)
		}
		if a.out.json {
			keys := make([]map[string]any, 0, len(app.Env))
			for _, e := range app.Env {
				// Never emit secret values.
				item := map[string]any{"key": e.Key, "secret": e.Secret}
				if !e.Secret {
					item["value"] = e.Value
				}
				keys = append(keys, item)
			}
			a.out.emitJSON(map[string]any{"env": keys})
			return exitOK
		}
		if len(app.Env) == 0 {
			a.out.human("还没有环境变量。")
			return exitOK
		}
		for _, e := range app.Env {
			if e.Secret {
				a.out.human("%s=（密钥，已隐藏）", e.Key)
			} else {
				a.out.human("%s=%s", e.Key, e.Value)
			}
		}
		return exitOK

	default:
		return a.out.usageError("未知的 env 子命令：%s", sub)
	}
}

// cmdVolume implements `volume add PATH` / `volume list`.
func (a *app) cmdVolume(ctx context.Context, args []string) int {
	if len(args) == 0 {
		return a.out.usageError("volume 需要子命令：add / list")
	}
	sub, rest := args[0], args[1:]
	res, err := a.resolveTargetAndApp()
	if err != nil {
		return a.out.usageError("%s", err.Error())
	}
	api, derr := a.dial(ctx, res.target)
	if derr != nil {
		return a.out.fail(derr)
	}
	defer api.Close()

	switch sub {
	case "add":
		if len(rest) != 1 {
			return a.out.usageError("用法：volume add PATH")
		}
		path := rest[0]
		if !strings.HasPrefix(path, "/") {
			return a.out.usageError("卷路径必须是绝对路径")
		}
		if serr := api.AddVolume(ctx, res.app, path); serr != nil {
			return a.out.fail(serr)
		}
		if a.out.json {
			a.out.emitJSON(map[string]any{"path": path, "note": "下次部署生效"})
			return exitOK
		}
		a.out.human("已添加数据卷 %s，下次部署生效。", path)
		return exitOK

	case "list":
		if len(rest) != 0 {
			return a.out.usageError("volume list 不接受参数")
		}
		app, serr := api.App(ctx, res.app)
		if serr != nil {
			return a.out.fail(serr)
		}
		if a.out.json {
			vols := make([]map[string]any, 0, len(app.Volumes))
			for _, v := range app.Volumes {
				vols = append(vols, map[string]any{"path": v.Path, "auto": v.Auto})
			}
			a.out.emitJSON(map[string]any{"volumes": vols})
			return exitOK
		}
		if len(app.Volumes) == 0 {
			a.out.human("还没有数据卷。")
			return exitOK
		}
		for _, v := range app.Volumes {
			auto := ""
			if v.Auto {
				auto = "（自动）"
			}
			a.out.human("%s%s", v.Path, auto)
		}
		return exitOK

	default:
		return a.out.usageError("未知的 volume 子命令：%s", sub)
	}
}

// cmdApp implements `app set [--memory MB] [--cpu CORES] [--port N]
// [--health-path P]`.
func (a *app) cmdApp(ctx context.Context, args []string) int {
	if len(args) == 0 || args[0] != "set" {
		return a.out.usageError("用法：app set [--memory MB] [--cpu CORES] [--port N] [--health-path P]")
	}
	fs := flag.NewFlagSet("app set", flag.ContinueOnError)
	fs.SetOutput(a.out.stderr)
	var (
		memory     = fs.Int("memory", -1, "内存上限 MB（64..16384）")
		cpu        = fs.Float64("cpu", -1, "CPU 核数（小数，如 0.5）")
		port       = fs.Int("port", -1, "容器端口")
		healthPath = fs.String("health-path", "\x00", "健康检查路径")
	)
	if err := fs.Parse(args[1:]); err != nil {
		return exitUsage
	}

	var s client.AppSettings
	set := false
	if *memory >= 0 {
		if *memory < 64 || *memory > 16384 {
			return a.out.usageError("内存必须在 64..16384 MB 之间")
		}
		m := *memory
		s.MemoryMB = &m
		set = true
	}
	if *cpu >= 0 {
		milli := int(*cpu*1000 + 0.5)
		if milli < 100 || milli > 16000 {
			return a.out.usageError("CPU 必须在 0.1..16 核之间")
		}
		s.CPUMilli = &milli
		set = true
	}
	if *port >= 0 {
		p := *port
		s.Port = &p
		set = true
	}
	if *healthPath != "\x00" {
		hp := *healthPath
		s.HealthPath = &hp
		set = true
	}
	if !set {
		return a.out.usageError("至少提供一个设置：--memory / --cpu / --port / --health-path")
	}

	res, err := a.resolveTargetAndApp()
	if err != nil {
		return a.out.usageError("%s", err.Error())
	}
	api, derr := a.dial(ctx, res.target)
	if derr != nil {
		return a.out.fail(derr)
	}
	defer api.Close()

	updated, serr := api.UpdateApp(ctx, res.app, s)
	if serr != nil {
		return a.out.fail(serr)
	}
	if a.out.json {
		a.out.emitJSON(map[string]any{
			"app": updated.Name, "memory_mb": updated.MemoryMB, "cpu_milli": updated.CPUMilli,
			"port": updated.Port, "health_path": updated.HealthPath, "note": "下次部署生效",
		})
		return exitOK
	}
	a.out.human("已更新应用设置，下次部署生效。")
	return exitOK
}

// cmdRollback implements `rollback` and waits to a terminal status.
func (a *app) cmdRollback(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("rollback", flag.ContinueOnError)
	fs.SetOutput(a.out.stderr)
	var (
		noWait  = fs.Bool("no-wait", false, "提交后不等待终态")
		timeout = fs.Duration("timeout", 20*time.Minute, "等待终态的超时时间")
	)
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	res, err := a.resolveTargetAndApp()
	if err != nil {
		return a.out.usageError("%s", err.Error())
	}
	api, derr := a.dial(ctx, res.target)
	if derr != nil {
		return a.out.fail(derr)
	}
	defer api.Close()

	dep, serr := api.Rollback(ctx, res.app)
	if serr != nil {
		return a.out.fail(serr)
	}
	if *noWait {
		return a.reportDeployment(ctx, api, res.app, dep, nil)
	}
	return a.waitDeployment(ctx, api, res.app, dep, *timeout)
}

// cmdStop implements `stop`.
func (a *app) cmdStop(ctx context.Context, args []string) int {
	return a.simpleAppAction(ctx, args, "stop")
}

// cmdStart implements `start`.
func (a *app) cmdStart(ctx context.Context, args []string) int {
	return a.simpleAppAction(ctx, args, "start")
}

func (a *app) simpleAppAction(ctx context.Context, args []string, action string) int {
	if len(args) != 0 {
		return a.out.usageError("%s 不接受参数", action)
	}
	res, err := a.resolveTargetAndApp()
	if err != nil {
		return a.out.usageError("%s", err.Error())
	}
	api, derr := a.dial(ctx, res.target)
	if derr != nil {
		return a.out.fail(derr)
	}
	defer api.Close()

	var serr error
	if action == "stop" {
		serr = api.Stop(ctx, res.app)
	} else {
		serr = api.Start(ctx, res.app)
	}
	if serr != nil {
		return a.out.fail(serr)
	}
	if a.out.json {
		a.out.emitJSON(map[string]any{"app": res.app, "action": action})
		return exitOK
	}
	if action == "stop" {
		a.out.human("已停止应用 %s。", res.app)
	} else {
		a.out.human("已启动应用 %s。", res.app)
	}
	return exitOK
}
