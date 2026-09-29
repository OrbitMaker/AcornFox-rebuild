package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/acornfox/acornfox/internal/client"
	"github.com/acornfox/acornfox/internal/pack"
)

// pollInterval is how often the deploy/rollback wait loop polls Deployment.
const pollInterval = time.Second

// terminalStatuses are the deployment statuses that end the wait loop.
func isTerminal(status string) bool {
	switch status {
	case "live", "failed", "superseded":
		return true
	}
	return false
}

// cmdDeploy implements `deploy [DIR]`, `deploy --image REF` and
// `deploy --git URL [--ref R]`.
func (a *app) cmdDeploy(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("deploy", flag.ContinueOnError)
	fs.SetOutput(a.out.stderr)
	var (
		image      = fs.String("image", "", "部署现成镜像，如 nginx:1.27-alpine")
		git        = fs.String("git", "", "部署公开 Git 仓库 URL")
		ref        = fs.String("ref", "", "Git 分支或提交")
		port       = fs.Int("port", 0, "容器端口")
		healthPath = fs.String("health-path", "", "健康检查路径")
		noWait     = fs.Bool("no-wait", false, "提交后不等待终态")
		timeout    = fs.Duration("timeout", 20*time.Minute, "等待终态的超时时间")
	)
	positional, err := parseFlags(fs, args)
	if err != nil {
		return exitUsage
	}

	// Determine the source: exactly one of upload(dir)/image/git.
	sources := 0
	if *image != "" {
		sources++
	}
	if *git != "" {
		sources++
	}
	var dir string
	if len(positional) > 1 {
		return a.out.usageError("deploy 最多接受一个目录参数")
	}
	if len(positional) == 1 {
		dir = positional[0]
	}
	if (*image != "" || *git != "") && dir != "" {
		return a.out.usageError("--image/--git 不能与目录参数同时使用")
	}
	if sources > 1 {
		return a.out.usageError("--image 与 --git 只能选一个")
	}

	res, err := a.resolveTargetAndApp()
	if err != nil {
		return a.out.usageError("%s", err.Error())
	}

	opt := client.DeployOptions{
		Port:       *port,
		HealthPath: *healthPath,
	}

	// Build the source. For upload, pack locally first (Dockerfile check +
	// size + idempotency key) before connecting.
	switch {
	case *image != "":
		opt.Image = *image
	case *git != "":
		opt.Git = *git
		opt.Ref = *ref
	default:
		pr, code, done := a.packDir(dir)
		if done {
			return code
		}
		defer os.Remove(pr.Path)
		f, ferr := os.Open(pr.Path)
		if ferr != nil {
			return a.out.usageError("打开打包文件失败：%v", ferr)
		}
		defer f.Close()
		opt.Upload = f
		opt.UploadSize = pr.Bytes
		opt.IdempotencyKey = idempotencyKey(pr.SHA256)
	}

	api, derr := a.dial(ctx, res.target)
	if derr != nil {
		return a.out.fail(derr)
	}
	defer api.Close()

	dep, _, serr := api.Deploy(ctx, res.app, opt)
	if serr != nil {
		return a.out.fail(serr)
	}

	// Persist .acornfox on first successful submission (write into workDir if
	// no existing project file).
	a.persistProject(res)

	if *noWait {
		return a.reportDeployment(ctx, api, res.app, dep, nil)
	}
	return a.waitDeployment(ctx, api, res.app, dep, *timeout)
}

// packDir packs the given directory (default workDir). It returns the result,
// or (code, true) when it already produced terminal output (dockerfile
// missing, too large, or a pack error).
func (a *app) packDir(dir string) (pack.Result, int, bool) {
	root := dir
	if root == "" {
		root = a.workDir
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return pack.Result{}, a.out.usageError("解析目录失败：%v", err), true
	}

	// Local Dockerfile check before uploading.
	if _, err := os.Stat(filepath.Join(abs, "Dockerfile")); err != nil {
		diag := client.Diagnosis{
			Stage:   "upload",
			Code:    "dockerfile_missing",
			Message: "项目根目录没有 Dockerfile",
			Hint:    "在项目根目录创建 Dockerfile 后重试",
		}
		return pack.Result{}, a.failDiag(diag, exitOpFailed), true
	}

	pr, err := pack.Dir(abs)
	if err != nil {
		switch {
		case errors.Is(err, pack.ErrDockerfileMissing):
			diag := client.Diagnosis{
				Stage:   "upload",
				Code:    "dockerfile_missing",
				Message: "项目根目录没有 Dockerfile",
				Hint:    "在项目根目录创建 Dockerfile 后重试",
			}
			return pack.Result{}, a.failDiag(diag, exitOpFailed), true
		case errors.Is(err, pack.ErrTooLarge):
			diag := client.Diagnosis{
				Stage:   "upload",
				Code:    "too_large",
				Message: "打包体积超过 200 MB",
				Hint:    "检查 .dockerignore，排除依赖、构建产物和大文件",
			}
			return pack.Result{}, a.failDiag(diag, exitOpFailed), true
		default:
			return pack.Result{}, a.out.usageError("打包失败：%v", err), true
		}
	}
	return pr, exitOK, false
}

// failDiag renders a diagnosis (human or json) and returns the code.
func (a *app) failDiag(d client.Diagnosis, code int) int {
	if a.out.json {
		a.out.emitDiagnosisJSON(d)
	} else {
		a.out.printDiagnosis(d)
	}
	return code
}

// idempotencyKey is the first 16 hex characters of the pack SHA256.
func idempotencyKey(sha string) string {
	if len(sha) >= 16 {
		return sha[:16]
	}
	return sha
}

// persistProject writes .acornfox into workDir if none is found upward, so the
// next deploy needs no arguments.
func (a *app) persistProject(res resolution) {
	if findProjectFile(a.workDir) != "" {
		return
	}
	_ = saveProject(a.workDir, &projectFile{Target: res.targetName, App: res.app})
}

// waitDeployment polls Deployment every second, printing new events (human
// mode), until the deployment reaches a terminal status or the timeout fires.
func (a *app) waitDeployment(ctx context.Context, api client.API, appName string, dep client.Deployment, timeout time.Duration) int {
	start := time.Now()
	var afterEvent int64
	deadline := time.Now().Add(timeout)

	if isTerminal(dep.Status) {
		return a.reportDeployment(ctx, api, appName, dep, &start)
	}

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			d := client.Diagnosis{Stage: "deploy", Code: "cancelled", Message: "已取消等待"}
			return a.failDiag(d, exitOpFailed)
		case <-ticker.C:
		}

		latest, events, err := api.Deployment(ctx, dep.ID, afterEvent)
		if err != nil {
			return a.out.fail(err)
		}
		for _, ev := range events {
			if ev.ID > afterEvent {
				afterEvent = ev.ID
			}
			if !a.out.json {
				a.out.human("[%s] %s", ev.Stage, ev.Message)
			}
		}
		dep = latest
		if isTerminal(dep.Status) {
			return a.reportDeployment(ctx, api, appName, dep, &start)
		}
		if time.Now().After(deadline) {
			d := client.Diagnosis{
				Stage:   "deploy",
				Code:    "timeout",
				Message: fmt.Sprintf("等待部署超时（%s）", timeout),
				Hint:    "用 acornfox status " + dep.ID + " 查看后续状态，或用 --timeout 延长等待",
			}
			return a.failDiag(d, exitOpFailed)
		}
	}
}

// reportDeployment renders the terminal outcome of a deployment. When start is
// non-nil the elapsed seconds are included. On success it fetches the app URL.
func (a *app) reportDeployment(ctx context.Context, api client.API, appName string, dep client.Deployment, start *time.Time) int {
	// Failure: print diagnosis and exit 1.
	if dep.Status == "failed" {
		diag := client.Diagnosis{Stage: "deploy", Code: "failed", Message: "部署失败"}
		if dep.Diagnosis != nil {
			diag = *dep.Diagnosis
		}
		return a.failDiag(diag, exitOpFailed)
	}
	if dep.Status == "superseded" {
		diag := client.Diagnosis{
			Stage:   "deploy",
			Code:    "superseded",
			Message: "该部署已被更新的提交取代",
			Hint:    "查看最新部署：acornfox status",
		}
		return a.failDiag(diag, exitOpFailed)
	}

	// Success (live, or non-terminal under --no-wait).
	warnings := make([]map[string]any, 0, len(dep.Warnings))
	for _, w := range dep.Warnings {
		warnings = append(warnings, map[string]any{
			"stage": w.Stage, "code": w.Code, "message": w.Message, "hint": w.Hint,
		})
	}
	// The URL lives on the App view; fetch it when live.
	var url string
	if dep.Status == "live" {
		if app, err := api.App(ctx, appName); err == nil {
			url = app.URL
		}
	}

	if a.out.json {
		fields := map[string]any{
			"app":           dep.App,
			"deployment_id": dep.ID,
			"version":       dep.Seq,
			"url":           url,
			"warnings":      warnings,
		}
		if start != nil {
			fields["seconds"] = int(time.Since(*start).Seconds())
		} else {
			fields["seconds"] = 0
		}
		a.out.emitJSON(fields)
		return exitOK
	}

	for _, w := range dep.Warnings {
		a.out.human("警告：%s", w.Message)
		if w.Hint != "" {
			a.out.human("  建议：%s", w.Hint)
		}
	}
	if dep.Status != "live" {
		a.out.human("已提交部署 %s（版本 %d），未等待终态。", dep.ID, dep.Seq)
		return exitOK
	}
	if url != "" {
		a.out.human("部署成功：%s", url)
	} else {
		a.out.human("部署成功（版本 %d）。", dep.Seq)
	}
	return exitOK
}
