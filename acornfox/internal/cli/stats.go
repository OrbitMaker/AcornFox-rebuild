package cli

import (
	"context"
	"flag"
)

// cmdStats implements `stats [APP]`: show host or app resource metrics.
func (a *app) cmdStats(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("stats", flag.ContinueOnError)
	fs.SetOutput(a.out.stderr)
	rest, err := parseFlags(fs, args)
	if err != nil {
		return exitUsage
	}
	if len(rest) > 1 {
		return a.out.usageError("stats 最多接受一个应用名参数")
	}

	// stats without app name = host metrics
	if len(rest) == 0 {
		return a.statsHost(ctx)
	}

	// stats APP = app metrics
	return a.statsApp(ctx, rest[0])
}

func (a *app) statsHost(ctx context.Context) int {
	t, _, err := a.resolveTarget()
	if err != nil {
		return a.out.usageError("%s", err.Error())
	}
	api, derr := a.dial(ctx, t)
	if derr != nil {
		return a.out.fail(derr)
	}
	defer api.Close()

	metrics, serr := api.HostMetrics(ctx)
	if serr != nil {
		return a.out.fail(serr)
	}

	if a.out.json {
		a.out.emitJSON(map[string]any{
			"available":      metrics.Available,
			"cpu_percent":    metrics.CPUPercent,
			"memory_used":    metrics.MemoryUsed,
			"memory_total":   metrics.MemoryTotal,
			"disk_used":      metrics.DiskUsed,
			"disk_total":     metrics.DiskTotal,
			"load1":          metrics.Load1,
			"uptime_seconds": metrics.UptimeSeconds,
		})
		return exitOK
	}

	if !metrics.Available {
		a.out.human("主机指标不可用")
		return exitOK
	}

	a.out.human("=== 主机资源使用情况 ===")
	if metrics.CPUPercent != nil {
		a.out.human("CPU 使用率：%.2f%%", *metrics.CPUPercent)
	}
	if metrics.MemoryUsed != nil && metrics.MemoryTotal != nil {
		usedGB := float64(*metrics.MemoryUsed) / (1024 * 1024 * 1024)
		totalGB := float64(*metrics.MemoryTotal) / (1024 * 1024 * 1024)
		percent := float64(*metrics.MemoryUsed) / float64(*metrics.MemoryTotal) * 100
		a.out.human("内存使用：%.2f GB / %.2f GB (%.1f%%)", usedGB, totalGB, percent)
	}
	if metrics.DiskUsed != nil && metrics.DiskTotal != nil {
		usedGB := float64(*metrics.DiskUsed) / (1024 * 1024 * 1024)
		totalGB := float64(*metrics.DiskTotal) / (1024 * 1024 * 1024)
		percent := float64(*metrics.DiskUsed) / float64(*metrics.DiskTotal) * 100
		a.out.human("磁盘使用：%.2f GB / %.2f GB (%.1f%%)", usedGB, totalGB, percent)
	}
	if metrics.Load1 != nil {
		a.out.human("负载（1分钟）：%.2f", *metrics.Load1)
	}
	if metrics.UptimeSeconds != nil {
		hours := *metrics.UptimeSeconds / 3600
		a.out.human("系统运行时间：%.1f 小时", hours)
	}

	return exitOK
}

func (a *app) statsApp(ctx context.Context, appName string) int {
	// The positional app name always wins over .acornfox / the working dir.
	t, _, err := a.resolveTarget()
	if err != nil {
		return a.out.usageError("%s", err.Error())
	}

	api, derr := a.dial(ctx, t)
	if derr != nil {
		return a.out.fail(derr)
	}
	defer api.Close()

	metrics, serr := api.AppMetrics(ctx, appName)
	if serr != nil {
		return a.out.fail(serr)
	}

	if a.out.json {
		a.out.emitJSON(map[string]any{
			"app":             metrics.App,
			"available":       metrics.Available,
			"observed_state":  metrics.ObservedState,
			"cpu_available":   metrics.CPUAvailable,
			"cpu_percent":     metrics.CPUPercent,
			"memory_usage_mb": metrics.MemoryUsageMB,
			"memory_limit_mb": metrics.MemoryLimitMB,
			"network_rx_mb":   metrics.NetworkRxMB,
			"network_tx_mb":   metrics.NetworkTxMB,
			"pids":            metrics.PIDs,
		})
		return exitOK
	}

	if metrics.Available != nil && !*metrics.Available {
		a.out.human("应用 %s 指标不可用（状态：%s）", metrics.App, metrics.ObservedState)
		return exitOK
	}
	a.out.human("=== 应用 %s 资源使用情况 ===", metrics.App)
	if metrics.CPUAvailable == nil || *metrics.CPUAvailable {
		a.out.human("CPU 使用率：%.2f%%", metrics.CPUPercent)
	} else {
		a.out.human("CPU 使用率：采样中")
	}
	if metrics.MemoryLimitMB > 0 {
		a.out.human("内存使用：%.2f MB / %.2f MB (%.1f%%)",
			metrics.MemoryUsageMB,
			metrics.MemoryLimitMB,
			metrics.MemoryUsageMB/metrics.MemoryLimitMB*100)
	} else {
		a.out.human("内存使用：%.2f MB（无限制）", metrics.MemoryUsageMB)
	}
	a.out.human("网络接收：%.2f MB", metrics.NetworkRxMB)
	a.out.human("网络发送：%.2f MB", metrics.NetworkTxMB)
	a.out.human("进程数：%d", metrics.PIDs)

	return exitOK
}
