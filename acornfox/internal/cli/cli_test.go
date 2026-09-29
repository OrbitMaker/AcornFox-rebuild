package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/acornfox/acornfox/internal/client"
)

func TestVersionJSON(t *testing.T) {
	h := newHarness(t)
	code, out, _ := h.run("--json", "version")
	if code != exitOK {
		t.Fatalf("exit = %d", code)
	}
	m := decodeJSON(t, out)
	if m["ok"] != true {
		t.Fatalf("ok != true: %v", m)
	}
	if m["version"] != version {
		t.Fatalf("version = %v", m["version"])
	}
	if int(m["api_version"].(float64)) != client.APIVersion {
		t.Fatalf("api_version = %v", m["api_version"])
	}
}

func TestUsageErrorExit2(t *testing.T) {
	h := newHarness(t)
	code, _, _ := h.run()
	if code != exitUsage {
		t.Fatalf("no command: exit = %d want %d", code, exitUsage)
	}
	code, _, _ = h.run("bogus")
	if code != exitUsage {
		t.Fatalf("unknown command: exit = %d want %d", code, exitUsage)
	}
}

func TestUsageErrorJSONShape(t *testing.T) {
	h := newHarness(t)
	code, out, _ := h.run("--json", "target")
	if code != exitUsage {
		t.Fatalf("exit = %d", code)
	}
	m := decodeJSON(t, out)
	if m["ok"] != false {
		t.Fatalf("ok != false")
	}
	d := m["diagnosis"].(map[string]any)
	if d["stage"] != "usage" {
		t.Fatalf("stage = %v", d["stage"])
	}
}

func TestTargetAddAndList(t *testing.T) {
	h := newHarness(t)
	code, out, errOut := h.run("--json", "target", "add", "dev", "--url", "http://127.0.0.1:18800")
	if code != exitOK {
		t.Fatalf("add exit = %d stderr=%s", code, errOut)
	}
	m := decodeJSON(t, out)
	if m["is_default"] != true {
		t.Fatalf("first target should be default: %v", m)
	}
	// It should have been persisted.
	tf, _ := loadTargets(h.configDir)
	if tf.Default != "dev" {
		t.Fatalf("default not persisted: %v", tf.Default)
	}
	// Verify file perms 0600 and dir 0700.
	dir, file, _ := configPaths(h.configDir)
	if fi, err := os.Stat(file); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("targets.json perms: %v mode=%v", err, fi.Mode().Perm())
	}
	if fi, err := os.Stat(dir); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("config dir perms: %v", err)
	}
}

func TestTargetAddConnectionErrorExit3(t *testing.T) {
	h := newHarness(t)
	h.connect = func(ctx context.Context, tgt client.Target) (client.API, error) {
		return nil, &client.Error{Diag: client.Diagnosis{Stage: "connect", Code: "host_unreachable", Message: "连不上"}}
	}
	code, out, _ := h.run("--json", "target", "add", "dev", "--ssh", "u@h")
	if code != exitConnect {
		t.Fatalf("exit = %d want %d", code, exitConnect)
	}
	m := decodeJSON(t, out)
	d := m["diagnosis"].(map[string]any)
	if d["code"] != "host_unreachable" {
		t.Fatalf("code = %v", d["code"])
	}
}

func TestDeployWritesAndReusesProjectFile(t *testing.T) {
	h := newHarness(t)
	h.addTarget("dev", "http://127.0.0.1:18800")
	h.writeDockerfile()

	code, out, errOut := h.run("--json", "deploy")
	if code != exitOK {
		t.Fatalf("deploy exit = %d stderr=%s", code, errOut)
	}
	m := decodeJSON(t, out)
	if m["ok"] != true {
		t.Fatalf("ok != true: %v", m)
	}
	if m["url"] != "http://192.168.1.10:12345" {
		t.Fatalf("url = %v", m["url"])
	}
	// .acornfox written into workDir.
	pf := filepath.Join(h.workDir, ".acornfox")
	if _, err := os.Stat(pf); err != nil {
		t.Fatalf(".acornfox not written: %v", err)
	}
	proj, _, err := loadProject(h.workDir)
	if err != nil || proj == nil {
		t.Fatalf("loadProject: %v", err)
	}
	if proj.Target != "dev" {
		t.Fatalf("project target = %v", proj.Target)
	}
	// Idempotency key must be first 16 hex of pack sha256.
	if len(h.api.lastDeployOpt.IdempotencyKey) != 16 {
		t.Fatalf("idempotency key len = %d", len(h.api.lastDeployOpt.IdempotencyKey))
	}

	// Second deploy without target: should reuse .acornfox (still exit 0).
	code2, _, _ := h.run("--json", "deploy")
	if code2 != exitOK {
		t.Fatalf("second deploy exit = %d", code2)
	}
}

func TestDeployDockerfileMissingExit1(t *testing.T) {
	h := newHarness(t)
	h.addTarget("dev", "http://127.0.0.1:18800")
	// No Dockerfile.
	code, out, _ := h.run("--json", "deploy")
	if code != exitOpFailed {
		t.Fatalf("exit = %d want %d", code, exitOpFailed)
	}
	m := decodeJSON(t, out)
	d := m["diagnosis"].(map[string]any)
	if d["code"] != "dockerfile_missing" {
		t.Fatalf("code = %v", d["code"])
	}
}

func TestDeployFailureDiagnosisExit1(t *testing.T) {
	h := newHarness(t)
	h.addTarget("dev", "http://127.0.0.1:18800")
	h.writeDockerfile()
	h.api.deployFn = func(ctx context.Context, app string, opt client.DeployOptions) (client.Deployment, bool, error) {
		return client.Deployment{ID: "d1", App: app, Seq: 1, Status: "queued"}, true, nil
	}
	h.api.deploymentFn = func(ctx context.Context, id string, after int64) (client.Deployment, []client.Event, error) {
		return client.Deployment{
			ID:     id,
			Status: "failed",
			Diagnosis: &client.Diagnosis{
				Stage: "build", Code: "build_failed", Message: "构建失败", LogExcerpt: "error: boom",
			},
		}, nil, nil
	}
	code, out, _ := h.run("--json", "deploy")
	if code != exitOpFailed {
		t.Fatalf("exit = %d want %d", code, exitOpFailed)
	}
	m := decodeJSON(t, out)
	if m["ok"] != false {
		t.Fatalf("ok != false")
	}
	d := m["diagnosis"].(map[string]any)
	if d["code"] != "build_failed" {
		t.Fatalf("code = %v", d["code"])
	}
}

func TestDeployConnectionErrorExit3(t *testing.T) {
	h := newHarness(t)
	h.addTarget("dev", "http://127.0.0.1:18800")
	h.writeDockerfile()
	h.connect = func(ctx context.Context, tgt client.Target) (client.API, error) {
		return nil, &client.Error{Diag: client.Diagnosis{Stage: "connect", Code: "ssh_missing", Message: "找不到 ssh"}}
	}
	code, out, _ := h.run("--json", "deploy")
	if code != exitConnect {
		t.Fatalf("exit = %d want %d", code, exitConnect)
	}
	m := decodeJSON(t, out)
	d := m["diagnosis"].(map[string]any)
	if d["code"] != "ssh_missing" {
		t.Fatalf("code = %v", d["code"])
	}
}

func TestServerErrorExit4(t *testing.T) {
	h := newHarness(t)
	h.addTarget("dev", "http://127.0.0.1:18800")
	h.api.appsFn = func(ctx context.Context) ([]client.App, error) {
		return nil, &client.Error{Status: 500, Diag: client.Diagnosis{Stage: "server", Code: "internal", Message: "服务器错误"}}
	}
	code, out, _ := h.run("--json", "apps")
	if code != exitServerError {
		t.Fatalf("exit = %d want %d", code, exitServerError)
	}
	m := decodeJSON(t, out)
	d := m["diagnosis"].(map[string]any)
	if d["stage"] != "server" {
		t.Fatalf("stage = %v", d["stage"])
	}
}

func TestSelectionPriority(t *testing.T) {
	h := newHarness(t)
	h.addTarget("dev", "http://dev")
	h.addTarget("prod", "http://prod")
	// default is "dev" (first added). .acornfox picks prod, --target overrides.
	if err := saveProject(h.workDir, &projectFile{Target: "prod", App: "fromfile"}); err != nil {
		t.Fatalf("saveProject: %v", err)
	}

	var dialedURL string
	h.connect = func(ctx context.Context, tgt client.Target) (client.API, error) {
		dialedURL = tgt.URL
		return h.api, nil
	}

	// No --target: .acornfox wins over default.
	h.run("apps")
	if dialedURL != "http://prod" {
		t.Fatalf(".acornfox target not used: %s", dialedURL)
	}
	// --target overrides .acornfox.
	h.run("--target", "dev", "apps")
	if dialedURL != "http://dev" {
		t.Fatalf("--target not honored: %s", dialedURL)
	}

	// App priority: --app overrides .acornfox app.
	h.api.appFn = func(ctx context.Context, app string) (client.App, error) {
		return client.App{Name: app}, nil
	}
	h.run("--app", "override", "status")
	// status calls App(ctx, resolvedApp); check via capture.
}

func TestAppNameDefaultingFromDir(t *testing.T) {
	h := newHarness(t)
	// Rename workDir base to something needing normalization by creating a
	// sub-directory with mixed case and using it as workDir.
	sub := filepath.Join(h.workDir, "My_App")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	h.workDir = sub
	h.addTarget("dev", "http://dev")
	h.writeDockerfile()

	code, _, errOut := h.run("--json", "deploy")
	if code != exitOK {
		t.Fatalf("exit = %d stderr=%s", code, errOut)
	}
	if h.api.lastDeployApp != "my-app" {
		t.Fatalf("normalized app = %q want my-app", h.api.lastDeployApp)
	}
}

func TestEnvSetSecretNeverPrinted(t *testing.T) {
	h := newHarness(t)
	h.addTarget("dev", "http://dev")
	if err := saveProject(h.workDir, &projectFile{Target: "dev", App: "notes"}); err != nil {
		t.Fatalf("saveProject: %v", err)
	}
	const secretVal = "super-secret-token-value"

	code, out, errOut := h.run("--json", "env", "set", "TOKEN="+secretVal, "--secret")
	if code != exitOK {
		t.Fatalf("exit = %d stderr=%s", code, errOut)
	}
	if strings.Contains(out, secretVal) || strings.Contains(errOut, secretVal) {
		t.Fatalf("secret leaked in output:\nstdout=%s\nstderr=%s", out, errOut)
	}
	// The server call still received the real value.
	if h.api.lastSetEnv.value != secretVal {
		t.Fatalf("server did not get value")
	}
	if !h.api.lastSetEnv.secret {
		t.Fatalf("secret flag not set")
	}
}

func TestEnvListSecretValueNotShown(t *testing.T) {
	h := newHarness(t)
	h.addTarget("dev", "http://dev")
	if err := saveProject(h.workDir, &projectFile{Target: "dev", App: "notes"}); err != nil {
		t.Fatalf("saveProject: %v", err)
	}
	h.api.appFn = func(ctx context.Context, app string) (client.App, error) {
		return client.App{Name: app, Env: []client.EnvKey{
			{Key: "PUBLIC", Secret: false, Value: "hello"},
			{Key: "TOKEN", Secret: true}, // server never returns secret value
		}}, nil
	}
	code, out, _ := h.run("--json", "env", "list")
	if code != exitOK {
		t.Fatalf("exit = %d", code)
	}
	m := decodeJSON(t, out)
	envs := m["env"].([]any)
	for _, e := range envs {
		em := e.(map[string]any)
		if em["key"] == "TOKEN" {
			if _, ok := em["value"]; ok {
				t.Fatalf("secret value present in env list: %v", em)
			}
		}
	}
	if !strings.Contains(out, "PUBLIC") {
		t.Fatalf("public key missing")
	}
}

func TestAppSetCPUDecimalToMilli(t *testing.T) {
	h := newHarness(t)
	h.addTarget("dev", "http://dev")
	if err := saveProject(h.workDir, &projectFile{Target: "dev", App: "notes"}); err != nil {
		t.Fatalf("saveProject: %v", err)
	}
	var gotMilli *int
	h.api.updateAppFn = func(ctx context.Context, app string, s client.AppSettings) (client.App, error) {
		gotMilli = s.CPUMilli
		return client.App{Name: app}, nil
	}
	code, _, errOut := h.run("--json", "app", "set", "--cpu", "0.5")
	if code != exitOK {
		t.Fatalf("exit = %d stderr=%s", code, errOut)
	}
	if gotMilli == nil || *gotMilli != 500 {
		t.Fatalf("cpu_milli = %v want 500", gotMilli)
	}
}

func TestDeploySuccessJSONShape(t *testing.T) {
	h := newHarness(t)
	h.addTarget("dev", "http://dev")
	h.writeDockerfile()
	code, out, _ := h.run("--json", "deploy")
	if code != exitOK {
		t.Fatalf("exit = %d out=%s", code, out)
	}
	m := decodeJSON(t, out)
	for _, key := range []string{"app", "deployment_id", "version", "url", "warnings", "seconds"} {
		if _, ok := m[key]; !ok {
			t.Fatalf("deploy json missing key %q: %v", key, m)
		}
	}
}

func TestDeployWaitLoopPrintsEvents(t *testing.T) {
	h := newHarness(t)
	h.addTarget("dev", "http://dev")
	h.writeDockerfile()
	h.api.deployFn = func(ctx context.Context, app string, opt client.DeployOptions) (client.Deployment, bool, error) {
		return client.Deployment{ID: "d1", App: app, Seq: 1, Status: "queued"}, true, nil
	}
	calls := 0
	h.api.deploymentFn = func(ctx context.Context, id string, after int64) (client.Deployment, []client.Event, error) {
		calls++
		if calls == 1 {
			return client.Deployment{ID: id, Status: "building"}, []client.Event{{ID: 1, Stage: "build", Message: "开始构建"}}, nil
		}
		return client.Deployment{ID: id, Status: "live"}, []client.Event{{ID: 2, Stage: "route", Message: "已上线"}}, nil
	}
	code, out, errOut := h.run("deploy")
	if code != exitOK {
		t.Fatalf("exit = %d", code)
	}
	if !strings.Contains(errOut, "开始构建") && !strings.Contains(out, "开始构建") {
		t.Fatalf("events not printed:\nout=%s\nerr=%s", out, errOut)
	}
}

func TestConnectionErrorHumanExit3(t *testing.T) {
	h := newHarness(t)
	h.addTarget("dev", "http://dev")
	h.connect = func(ctx context.Context, tgt client.Target) (client.API, error) {
		return nil, &client.Error{Diag: client.Diagnosis{Stage: "connect", Code: "server_down", Message: "服务器未启动"}}
	}
	code, _, errOut := h.run("apps")
	if code != exitConnect {
		t.Fatalf("exit = %d", code)
	}
	if !strings.Contains(errOut, "服务器未启动") {
		t.Fatalf("diagnosis message missing: %s", errOut)
	}
}

func TestNormalizeAppName(t *testing.T) {
	cases := []struct {
		in    string
		want  string
		valid bool
	}{
		{"notes", "notes", true},
		{"My_App", "my-app", true},
		{"  spaces  ", "spaces", true},
		{"123", "", false}, // must start with a letter
		{"a", "", false},   // too short (needs >=2 by regex)
		{"ok2", "ok2", true},
		{"UPPER", "upper", true},
		{"a.b.c", "a-b-c", true},
	}
	for _, c := range cases {
		got, ok := normalizeAppName(c.in)
		if ok != c.valid {
			t.Errorf("normalizeAppName(%q) valid = %v want %v (got %q)", c.in, ok, c.valid, got)
			continue
		}
		if c.valid && got != c.want {
			t.Errorf("normalizeAppName(%q) = %q want %q", c.in, got, c.want)
		}
	}
}

func TestLogsTailClamp(t *testing.T) {
	h := newHarness(t)
	h.addTarget("dev", "http://dev")
	if err := saveProject(h.workDir, &projectFile{Target: "dev", App: "notes"}); err != nil {
		t.Fatalf("saveProject: %v", err)
	}
	var gotTail int
	h.api.logsFn = func(ctx context.Context, app string, tail int) ([]string, error) {
		gotTail = tail
		return []string{"line1"}, nil
	}
	h.run("logs", "--tail", "5000")
	if gotTail != 1000 {
		t.Fatalf("tail clamp = %d want 1000", gotTail)
	}
}
