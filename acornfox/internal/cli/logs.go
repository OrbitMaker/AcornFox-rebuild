package cli

import (
	"context"
	"errors"
	"flag"
	"time"

	"github.com/acornfox/acornfox/internal/client"
)

// cmdLogs implements logs [APP] [--tail N] [--since RFC3339] [-f].
// A boundary cursor preserves identical log records; no text-based deduping.
func (a *app) cmdLogs(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("logs", flag.ContinueOnError)
	fs.SetOutput(a.out.stderr)
	tail := fs.Int("tail", 100, "返回最近 N 行（最多 1000）")
	follow := fs.Bool("follow", false, "持续跟随新日志，Ctrl+C 停止")
	fs.BoolVar(follow, "f", false, "持续跟随新日志")
	since := fs.String("since", "", "起始时间（RFC3339）")
	pos, err := parseFlags(fs, args)
	if err != nil {
		return exitUsage
	}
	if len(pos) > 1 {
		return a.out.usageError("用法：logs [APP] [--tail N] [--since RFC3339] [-f]")
	}
	if *tail < 1 {
		return a.out.usageError("tail 必须是正整数")
	}
	if *tail > 1000 {
		*tail = 1000
	}
	if *since != "" {
		if _, err := time.Parse(time.RFC3339Nano, *since); err != nil {
			return a.out.usageError("since 必须是 RFC3339 时间")
		}
	}
	target, _, err := a.resolveTarget()
	if err != nil {
		return a.out.usageError("%s", err.Error())
	}
	name := ""
	if len(pos) == 1 {
		var valid bool
		name, valid = normalizeAppName(pos[0])
		if !valid {
			return a.out.usageError("应用名不合法")
		}
	} else {
		name, _, err = a.resolveApp()
		if err != nil {
			return a.out.usageError("%s", err.Error())
		}
	}
	api, derr := a.dial(ctx, target)
	if derr != nil {
		return a.out.fail(derr)
	}
	defer api.Close()
	if !*follow && *since == "" {
		lines, err := api.Logs(ctx, name, *tail)
		if err != nil {
			return a.out.fail(err)
		}
		a.printLogBatch(client.LogBatch{Lines: lines})
		return exitOK
	}
	reader, ok := api.(client.LogBatchAPI)
	if !ok {
		return a.out.usageError("当前客户端不支持日志跟随，请升级后重试")
	}
	cursor := ""
	first := true
	for {
		if ctx.Err() != nil {
			return exitOK
		}
		batch, err := reader.LogBatch(ctx, name, *tail, *since, cursor)
		if err != nil {
			if errors.Is(err, context.Canceled) || ctx.Err() != nil {
				return exitOK
			}
			return a.out.fail(err)
		}
		if first || len(batch.Lines) > 0 {
			a.printLogBatch(batch)
		}
		first = false
		if !*follow {
			return exitOK
		}
		cursor = batch.Cursor
		if batch.HasMore {
			continue
		}
		timer := time.NewTimer(time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return exitOK
		case <-timer.C:
		}
	}
}

func (a *app) printLogBatch(batch client.LogBatch) {
	if a.out.json {
		a.out.emitJSON(map[string]any{"lines": batch.Lines, "cursor": batch.Cursor, "has_more": batch.HasMore, "reset": batch.Reset})
		return
	}
	for _, line := range batch.Lines {
		a.out.human("%s", line)
	}
}
