package cli

import (
	"context"
	"flag"

	"github.com/acornfox/acornfox/internal/client"
)

// cmdVersion prints the client and API versions.
func (a *app) cmdVersion() int {
	if a.out.json {
		a.out.emitJSON(map[string]any{
			"version":     version,
			"api_version": client.APIVersion,
		})
		return exitOK
	}
	a.out.human("acornfox 客户端版本 %s，API 版本 %d", version, client.APIVersion)
	return exitOK
}

// cmdTarget dispatches the target subcommands.
func (a *app) cmdTarget(ctx context.Context, args []string) int {
	if len(args) == 0 {
		return a.out.usageError("target 需要子命令：add / list / remove / use")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "add":
		return a.cmdTargetAdd(ctx, rest)
	case "list":
		return a.cmdTargetList(rest)
	case "remove":
		return a.cmdTargetRemove(rest)
	case "use":
		return a.cmdTargetUse(rest)
	default:
		return a.out.usageError("未知的 target 子命令：%s", sub)
	}
}

// cmdTargetAdd writes a new target then tests the connection via GET
// /v1/status. On success it becomes the default when none is set yet.
func (a *app) cmdTargetAdd(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("target add", flag.ContinueOnError)
	fs.SetOutput(a.out.stderr)
	var (
		ssh      = fs.String("ssh", "", "USER@HOST 或 ~/.ssh/config 中的 Host 别名")
		port     = fs.Int("port", 0, "SSH 端口（0 为默认）")
		identity = fs.String("identity", "", "私钥路径（可选）")
		url      = fs.String("url", "", "直连 URL（开发用，绕过 SSH）")
	)
	names, err := parseFlags(fs, args)
	if err != nil {
		return exitUsage
	}
	if len(names) != 1 {
		return a.out.usageError("用法：target add NAME --ssh USER@HOST [--port N] [--identity PATH] [--url URL]")
	}
	name := names[0]
	if *ssh == "" && *url == "" {
		return a.out.usageError("必须提供 --ssh 或 --url")
	}

	tf, err := loadTargets(a.configDir)
	if err != nil {
		return a.out.usageError("读取 targets.json 失败：%v", err)
	}
	t := &client.Target{
		Name:          name,
		SSH:           *ssh,
		Port:          *port,
		Identity:      *identity,
		RemoteCommand: defaultRemote,
		URL:           *url,
	}
	tf.Targets[name] = t

	// Test the connection before persisting the default choice.
	dialT := *t
	api, derr := a.dial(ctx, dialT)
	if derr != nil {
		return a.out.fail(derr)
	}
	defer api.Close()
	if _, serr := api.Status(ctx); serr != nil {
		return a.out.fail(serr)
	}

	wasDefault := tf.Default != ""
	if !wasDefault {
		tf.Default = name
	}
	if err := saveTargets(a.configDir, tf); err != nil {
		return a.out.usageError("写入 targets.json 失败：%v", err)
	}

	if a.out.json {
		a.out.emitJSON(map[string]any{
			"target":     name,
			"is_default": tf.Default == name,
		})
		return exitOK
	}
	a.out.human("已添加服务器 %s，连接测试通过。", name)
	if tf.Default == name {
		a.out.human("已设为默认服务器。")
	}
	return exitOK
}

// cmdTargetList lists the configured targets.
func (a *app) cmdTargetList(args []string) int {
	if len(args) != 0 {
		return a.out.usageError("target list 不接受参数")
	}
	tf, err := loadTargets(a.configDir)
	if err != nil {
		return a.out.usageError("读取 targets.json 失败：%v", err)
	}
	if a.out.json {
		list := make([]map[string]any, 0, len(tf.Targets))
		for name, t := range tf.Targets {
			list = append(list, map[string]any{
				"name":       name,
				"ssh":        t.SSH,
				"port":       t.Port,
				"url":        t.URL,
				"is_default": name == tf.Default,
			})
		}
		a.out.emitJSON(map[string]any{
			"default": tf.Default,
			"targets": list,
		})
		return exitOK
	}
	if len(tf.Targets) == 0 {
		a.out.human("还没有配置服务器，用 acornfox target add 添加。")
		return exitOK
	}
	for name, t := range tf.Targets {
		marker := "  "
		if name == tf.Default {
			marker = "* "
		}
		addr := t.SSH
		if addr == "" {
			addr = t.URL
		}
		a.out.human("%s%s\t%s", marker, name, addr)
	}
	return exitOK
}

// cmdTargetRemove removes a target and clears the default if it pointed there.
func (a *app) cmdTargetRemove(args []string) int {
	if len(args) != 1 {
		return a.out.usageError("用法：target remove NAME")
	}
	name := args[0]
	tf, err := loadTargets(a.configDir)
	if err != nil {
		return a.out.usageError("读取 targets.json 失败：%v", err)
	}
	if _, ok := tf.Targets[name]; !ok {
		return a.out.usageError("找不到服务器 %q", name)
	}
	delete(tf.Targets, name)
	if tf.Default == name {
		tf.Default = ""
	}
	if err := saveTargets(a.configDir, tf); err != nil {
		return a.out.usageError("写入 targets.json 失败：%v", err)
	}
	if a.out.json {
		a.out.emitJSON(map[string]any{"removed": name})
		return exitOK
	}
	a.out.human("已删除服务器 %s。", name)
	return exitOK
}

// cmdTargetUse sets the default target.
func (a *app) cmdTargetUse(args []string) int {
	if len(args) != 1 {
		return a.out.usageError("用法：target use NAME")
	}
	name := args[0]
	tf, err := loadTargets(a.configDir)
	if err != nil {
		return a.out.usageError("读取 targets.json 失败：%v", err)
	}
	if _, ok := tf.Targets[name]; !ok {
		return a.out.usageError("找不到服务器 %q", name)
	}
	tf.Default = name
	if err := saveTargets(a.configDir, tf); err != nil {
		return a.out.usageError("写入 targets.json 失败：%v", err)
	}
	if a.out.json {
		a.out.emitJSON(map[string]any{"default": name})
		return exitOK
	}
	a.out.human("已切换默认服务器为 %s。", name)
	return exitOK
}
