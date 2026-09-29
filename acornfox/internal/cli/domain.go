package cli

import (
	"context"

	"github.com/acornfox/acornfox/internal/client"
)

// icpNotice is always printed on `domain add`: mainland China servers must have
// completed ICP filing or 80/443 traffic is blocked.
const icpNotice = "中国大陆服务器的域名须已完成 ICP 备案，否则无法通过 80/443 访问。"

// cmdDomain implements `domain add NAME` / `domain remove NAME` / `domain list`.
func (a *app) cmdDomain(ctx context.Context, args []string) int {
	if len(args) == 0 {
		return a.out.usageError("domain 需要子命令：add / remove / list")
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
			return a.out.usageError("用法：domain add NAME")
		}
		return a.domainAdd(ctx, api, res.app, rest[0])
	case "remove":
		if len(rest) != 1 {
			return a.out.usageError("用法：domain remove NAME")
		}
		return a.domainRemove(ctx, api, res.app, rest[0])
	case "list":
		if len(rest) != 0 {
			return a.out.usageError("domain list 不接受参数")
		}
		return a.domainList(ctx, api, res.app)
	default:
		return a.out.usageError("未知的 domain 子命令：%s", sub)
	}
}

func (a *app) domainAdd(ctx context.Context, api client.API, appName, name string) int {
	d, err := api.AddDomain(ctx, appName, name)
	if err != nil {
		return a.out.fail(err)
	}
	if a.out.json {
		a.out.emitJSON(map[string]any{"domain": domainJSON(d)})
		return exitOK
	}
	a.out.human("已添加域名 %s（状态：%s）。", d.Name, d.Status)
	a.out.human("%s", icpNotice)
	// dns_mismatch (and any other) warnings are printed after the notice.
	for _, w := range d.Warnings {
		a.out.human("警告：%s", w.Message)
		if w.Hint != "" {
			a.out.human("  建议：%s", w.Hint)
		}
	}
	return exitOK
}

func (a *app) domainRemove(ctx context.Context, api client.API, appName, name string) int {
	if err := api.RemoveDomain(ctx, appName, name); err != nil {
		return a.out.fail(err)
	}
	if a.out.json {
		a.out.emitJSON(map[string]any{"removed": name})
		return exitOK
	}
	a.out.human("已删除域名 %s。", name)
	return exitOK
}

func (a *app) domainList(ctx context.Context, api client.API, appName string) int {
	domains, err := api.Domains(ctx, appName)
	if err != nil {
		return a.out.fail(err)
	}
	if a.out.json {
		list := make([]map[string]any, 0, len(domains))
		for _, d := range domains {
			list = append(list, domainJSON(d))
		}
		a.out.emitJSON(map[string]any{"domains": list})
		return exitOK
	}
	if len(domains) == 0 {
		a.out.human("还没有域名。")
		return exitOK
	}
	for _, d := range domains {
		a.out.human("%s\t%s", d.Name, d.Status)
		if d.Diagnosis != nil {
			a.out.human("  诊断：%s", d.Diagnosis.Message)
		}
	}
	return exitOK
}

// domainJSON renders a Domain for --json output.
func domainJSON(d client.Domain) map[string]any {
	m := map[string]any{
		"app":    d.App,
		"name":   d.Name,
		"status": d.Status,
	}
	if d.Diagnosis != nil {
		m["diagnosis"] = map[string]any{
			"stage": d.Diagnosis.Stage, "code": d.Diagnosis.Code,
			"message": d.Diagnosis.Message, "hint": d.Diagnosis.Hint,
		}
	}
	if len(d.Warnings) > 0 {
		ws := make([]map[string]any, 0, len(d.Warnings))
		for _, w := range d.Warnings {
			ws = append(ws, map[string]any{
				"stage": w.Stage, "code": w.Code, "message": w.Message, "hint": w.Hint,
			})
		}
		m["warnings"] = ws
	}
	return m
}
