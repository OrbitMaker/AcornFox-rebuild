package acornfoxrelease

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestBuildWebAssetsV1UsesTrustedNode(t *testing.T) {
	root, cache, witness, policy, tool := syntheticGoReleaseRepository(t)
	plan, err := PrepareGoBuildPlanV1(context.Background(), witness, policy, tool, root, cache, localNPMCLIPath(t))
	if err != nil {
		t.Fatal(err)
	}
	task, npmCache := buildTaskRoot(t), buildTaskRoot(t)
	stage, err := buildWebAssetsV1(context.Background(), plan, task, npmCache, fakeWebNode(t, plan))
	if err != nil || stage == nil {
		t.Fatalf("stage=%#v err=%v", stage, err)
	}
	receipt, err := stage.Receipt()
	if err != nil || receipt.Validate() != nil || len(receipt.Files) != 2 {
		t.Fatalf("receipt=%#v err=%v", receipt, err)
	}
	if err := stage.Close(); err != nil {
		t.Fatal(err)
	}
	if err := stage.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestBuildWebAssetsV1CleansFailure(t *testing.T) {
	root, cache, witness, policy, tool := syntheticGoReleaseRepository(t)
	plan, err := PrepareGoBuildPlanV1(context.Background(), witness, policy, tool, root, cache, localNPMCLIPath(t))
	if err != nil {
		t.Fatal(err)
	}
	task, npmCache := buildTaskRoot(t), buildTaskRoot(t)
	runner := fakeWebNode(t, plan)
	if stage, err := buildWebAssetsV1(context.Background(), plan, task, npmCache, func(ctx context.Context, name string, args []string, dir string, env []string) ([]byte, error) {
		if len(args) > 1 && args[1] == "ci" {
			return nil, errors.New("fail")
		}
		return runner(ctx, name, args, dir, env)
	}); err == nil || stage != nil {
		t.Fatal("failed ci accepted")
	}
	if entries, err := os.ReadDir(task); err != nil || len(entries) != 0 {
		t.Fatalf("left stage: %v %v", entries, err)
	}
}

func fakeWebNode(t *testing.T, plan GoBuildPlanV1) goCommandRunner {
	t.Helper()
	return func(_ context.Context, name string, args []string, dir string, env []string) ([]byte, error) {
		if name != plan.nodeExecutable.path {
			t.Fatalf("ambient executable %q", name)
		}
		for _, required := range []string{"HTTP_PROXY=", "HTTPS_PROXY=", "ALL_PROXY=", "npm_config_offline=true", "npm_config_ignore_scripts=true", "VITE_API_MODE=live", "VITE_API_BASE_URL=/api/v1"} {
			if !containsString(env, required) {
				t.Fatalf("missing env %q", required)
			}
		}
		if len(args) == 1 && args[0] == "--version" {
			return []byte(plan.toolchain.NodeVersion + "\n"), nil
		}
		if len(args) > 0 && args[0] == plan.npmCLI.path {
			if len(args) == 2 && args[1] == "--version" {
				return []byte(plan.toolchain.NPMVersion + "\n"), nil
			}
			if len(args) == 3 && args[1] == "cache" && args[2] == "verify" {
				return []byte("verified\n"), nil
			}
			if len(args) == 6 && args[1] == "ci" {
				return []byte("installed\n"), nil
			}
		}
		if len(args) == 2 && args[1] == "--noEmit" {
			return []byte("checked\n"), nil
		}
		if len(args) == 4 && args[1] == "build" && args[2] == "--mode" && args[3] == "acornfox-release" {
			dist := filepath.Join(dir, "dist")
			if err := os.MkdirAll(filepath.Join(dist, "assets"), 0o700); err != nil {
				t.Fatal(err)
			}
			metadata, _ := json.Marshal(map[string]string{"apiBaseUrl": "/api/v1", "mode": "acornfox-release", "releaseId": "release-" + plan.releaseVersion, "schemaVersion": "acornfox-release-build-attestation.v1", "sourceCommit": plan.sourceCommit, "sourceRepository": plan.sourceRepositoryURL, "version": plan.releaseVersion})
			if err := os.WriteFile(filepath.Join(dist, "build-metadata.json"), metadata, 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dist, "assets", "app.js"), []byte("asset"), 0o644); err != nil {
				t.Fatal(err)
			}
			return []byte("built\n"), nil
		}
		return nil, errors.New("unexpected node command")
	}
}
