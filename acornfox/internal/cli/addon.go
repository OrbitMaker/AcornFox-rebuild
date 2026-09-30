package cli

import (
	"context"
	"flag"
	"strings"

	"github.com/acornfox/acornfox/internal/client"
)

// addonKinds are the kinds the server accepts; checked locally for a clear
// usage error before connecting.
var addonKinds = []string{"postgres", "mysql", "redis"}

func validAddonKind(kind string) bool {
	for _, k := range addonKinds {
		if k == kind {
			return true
		}
	}
	return false
}

// cmdAdd implements `add postgres|mysql|redis [--app NAME]`.
func (a *app) cmdAdd(ctx context.Context, args []string) int {
	if len(args) != 1 || !validAddonKind(args[0]) {
		return a.out.usageError("用法：add %s [--app NAME]", strings.Join(addonKinds, "|"))
	}
	kind := args[0]
	res, err := a.resolveTargetAndApp()
	if err != nil {
		return a.out.usageError("%s", err.Error())
	}
	api, derr := a.dial(ctx, res.target)
	if derr != nil {
		return a.out.fail(derr)
	}
	defer api.Close()

	r, serr := api.AddAddon(ctx, res.app, kind)
	if serr != nil {
		return a.out.fail(serr)
	}
	if a.out.json {
		a.out.emitJSON(map[string]any{
			"app":           res.app,
			"addon":         addonJSON(r.Addon),
			"deployment_id": r.DeploymentID,
			"reused":        r.Reused,
			"note":          r.Note,
		})
		return exitOK
	}
	if r.Reused {
		a.out.human("已恢复 %s 的 %s，沿用保留的凭据和数据（连接变量 %s）。", res.app, kind, r.Addon.EnvVar)
	} else {
		a.out.human("已为 %s 添加 %s（%s，仅应用网络内可访问：%s:%d；连接变量 %s）。", res.app, kind, r.Addon.Image, r.Addon.Host, r.Addon.Port, r.Addon.EnvVar)
	}
	if r.DeploymentID != "" {
		a.out.human("已触发重新部署以注入连接变量，部署 ID: %s", r.DeploymentID)
	} else {
		a.out.human("%s", r.Note)
	}
	return exitOK
}

// cmdRemove implements `remove postgres|mysql|redis [--app NAME] [--volumes]`.
func (a *app) cmdRemove(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("remove", flag.ContinueOnError)
	fs.SetOutput(a.out.stderr)
	deleteVolume := fs.Bool("volumes", false, "同时删除附加服务的数据卷（默认保留）")
	pos, perr := parseFlags(fs, args)
	if perr != nil {
		return exitUsage
	}
	if len(pos) != 1 || !validAddonKind(pos[0]) {
		return a.out.usageError("用法：remove %s [--app NAME] [--volumes]", strings.Join(addonKinds, "|"))
	}
	kind := pos[0]
	res, err := a.resolveTargetAndApp()
	if err != nil {
		return a.out.usageError("%s", err.Error())
	}
	api, derr := a.dial(ctx, res.target)
	if derr != nil {
		return a.out.fail(derr)
	}
	defer api.Close()

	r, serr := api.RemoveAddon(ctx, res.app, kind, *deleteVolume)
	if serr != nil {
		return a.out.fail(serr)
	}
	if a.out.json {
		a.out.emitJSON(map[string]any{
			"app":            res.app,
			"kind":           kind,
			"removed":        r.Removed,
			"deployment_id":  r.DeploymentID,
			"volume_deleted": r.VolumeDeleted,
			"volume_name":    r.VolumeName,
		})
		return exitOK
	}
	if r.VolumeDeleted {
		a.out.human("已删除 %s 的 %s 及其数据卷。", res.app, kind)
	} else {
		a.out.human("已删除 %s 的 %s，数据卷 %s 已保留（加 --volumes 可一并删除）。", res.app, kind, r.VolumeName)
	}
	if r.DeploymentID != "" {
		a.out.human("已触发重新部署以移除连接变量，部署 ID: %s", r.DeploymentID)
	}
	return exitOK
}

// cmdAddons implements `addons [--app NAME]`.
func (a *app) cmdAddons(ctx context.Context, args []string) int {
	if len(args) != 0 {
		return a.out.usageError("addons 不接受参数")
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

	list, serr := api.Addons(ctx, res.app)
	if serr != nil {
		return a.out.fail(serr)
	}
	if a.out.json {
		out := make([]map[string]any, 0, len(list))
		for _, ad := range list {
			out = append(out, addonJSON(ad))
		}
		a.out.emitJSON(map[string]any{"app": res.app, "addons": out})
		return exitOK
	}
	if len(list) == 0 {
		a.out.human("还没有附加服务。")
		return exitOK
	}
	for _, ad := range list {
		a.out.human("%s\t%s\t%s\t%s", ad.Kind, ad.ObservedState, ad.EnvVar, ad.Image)
	}
	return exitOK
}

func addonJSON(ad client.Addon) map[string]any {
	return map[string]any{
		"kind":           ad.Kind,
		"image":          ad.Image,
		"env_var":        ad.EnvVar,
		"host":           ad.Host,
		"port":           ad.Port,
		"volume_name":    ad.VolumeName,
		"observed_state": ad.ObservedState,
	}
}
