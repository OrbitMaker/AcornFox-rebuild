package acornfoxrelease

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestBuildWebAssetsV1UsesTrustedNode(t *testing.T) {
	root, cache, witness, policy, tool := syntheticGoReleaseRepository(t)
	plan, err := PrepareGoBuildPlanV1(context.Background(), witness, policy, tool, root, cache, localNPMCLIPath(t))
	defer plan.Close()
	if err != nil {
		t.Fatal(err)
	}
	task, npmCache := buildTaskRoot(t), buildTaskRoot(t)
	if err := os.Mkdir(filepath.Join(npmCache, "_cacache"), 0o700); err != nil {
		t.Fatal(err)
	}
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
	defer plan.Close()
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

func TestBuildWebAssetsV1ProducesIdenticalReceiptsForIndependentStages(t *testing.T) {
	root, cache, witness, policy, tool := syntheticGoReleaseRepository(t)
	plan, err := PrepareGoBuildPlanV1(context.Background(), witness, policy, tool, root, cache, localNPMCLIPath(t))
	defer plan.Close()
	if err != nil {
		t.Fatal(err)
	}
	build := func() (*WebAssetStageV1, WebBuildReceiptV1) {
		task, npmCache := buildTaskRoot(t), buildTaskRoot(t)
		if err := os.Mkdir(filepath.Join(npmCache, "_cacache"), 0o700); err != nil {
			t.Fatal(err)
		}
		stage, err := buildWebAssetsV1(context.Background(), plan, task, npmCache, fakeWebNode(t, plan))
		if err != nil {
			t.Fatal(err)
		}
		receipt, err := stage.Receipt()
		if err != nil {
			t.Fatal(err)
		}
		return stage, receipt
	}
	first, firstReceipt := build()
	second, secondReceipt := build()
	if !reflect.DeepEqual(firstReceipt, secondReceipt) {
		t.Fatalf("independent stages differ:\n%#v\n%#v", firstReceipt, secondReceipt)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestWebBuildReceiptRejectsIdentityTamperAndCopiesFiles(t *testing.T) {
	root, cache, witness, policy, tool := syntheticGoReleaseRepository(t)
	plan, err := PrepareGoBuildPlanV1(context.Background(), witness, policy, tool, root, cache, localNPMCLIPath(t))
	defer plan.Close()
	if err != nil {
		t.Fatal(err)
	}
	task, npmCache := buildTaskRoot(t), buildTaskRoot(t)
	stage, err := buildWebAssetsV1(context.Background(), plan, task, npmCache, fakeWebNode(t, plan))
	if err != nil {
		t.Fatal(err)
	}
	defer stage.Close()
	receipt, err := stage.Receipt()
	if err != nil {
		t.Fatal(err)
	}
	receipt.Files[0].Path = "tampered.js"
	if _, err := stage.Receipt(); err != nil {
		t.Fatalf("returned receipt mutated stage: %v", err)
	}
	for _, tamper := range []func(*WebBuildReceiptV1){
		func(r *WebBuildReceiptV1) { r.Version = "not-semver" },
		func(r *WebBuildReceiptV1) { r.ReleaseID = "release-0.0.0" },
		func(r *WebBuildReceiptV1) { r.SourceRepository = "https://example.test/acornfox" },
		func(r *WebBuildReceiptV1) { r.SourceCommit = "A" + r.SourceCommit[1:] },
		func(r *WebBuildReceiptV1) { r.TreeSHA256 = "0" + r.TreeSHA256[1:] },
	} {
		copy := receipt
		copy.Files = append([]FileEntryV1(nil), receipt.Files...)
		tamper(&copy)
		if copy.Validate() == nil {
			t.Fatal("tampered receipt accepted")
		}
	}
	metadataPath := filepath.Join(stage.dist, "build-metadata.json")
	raw, err := os.ReadFile(metadataPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(metadataPath, append(raw[:len(raw)-1], []byte(`,"unknown":true}`)...), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := stage.Receipt(); err == nil {
		t.Fatal("stage receipt accepted metadata with an unknown field")
	}
}

func TestBuildWebAssetsV1RejectsReplacedCacheWithoutDeletingReplacement(t *testing.T) {
	root, cache, witness, policy, tool := syntheticGoReleaseRepository(t)
	plan, err := PrepareGoBuildPlanV1(context.Background(), witness, policy, tool, root, cache, localNPMCLIPath(t))
	defer plan.Close()
	if err != nil {
		t.Fatal(err)
	}
	task, npmCache := buildTaskRoot(t), buildTaskRoot(t)
	runner := fakeWebNode(t, plan)
	if stage, err := buildWebAssetsV1(context.Background(), plan, task, npmCache, func(ctx context.Context, name string, args []string, dir string, env []string) ([]byte, error) {
		if len(args) == 6 && args[1] == "ci" {
			moved := npmCache + "-old"
			if err := os.Rename(npmCache, moved); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(npmCache, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(npmCache, "foreign"), []byte("keep"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		return runner(ctx, name, args, dir, env)
	}); err == nil || stage != nil {
		t.Fatal("replaced cache accepted")
	}
	if body, err := os.ReadFile(filepath.Join(npmCache, "foreign")); err != nil || string(body) != "keep" {
		t.Fatalf("foreign cache replacement removed: %q %v", body, err)
	}
	if entries, err := os.ReadDir(task); err != nil || len(entries) != 0 {
		t.Fatalf("left stage: %v %v", entries, err)
	}
}

func TestPinNPMCacheAllowsPopulatedPinnedDirectory(t *testing.T) {
	cache := buildTaskRoot(t)
	if err := os.Mkdir(filepath.Join(cache, "_cacache"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cache, "_cacache", "index"), []byte("cached"), 0o600); err != nil {
		t.Fatal(err)
	}
	pinned, err := pinNPMCache(cache)
	defer pinned.pin.close()
	if err != nil || !pinned.valid() {
		t.Fatalf("populated cache not pinned: %#v %v", pinned, err)
	}
}

func TestInspectWebDistRejectsUnsafeAndOversizedEntries(t *testing.T) {
	plan := testWebPlan()
	for name, mutate := range map[string]func(t *testing.T, root string){
		"symlink": func(t *testing.T, root string) {
			if err := os.Symlink("assets/app.js", filepath.Join(root, "link.js")); err != nil {
				t.Fatal(err)
			}
		},
		"hardlink": func(t *testing.T, root string) {
			if err := os.Link(filepath.Join(root, "assets", "app.js"), filepath.Join(root, "copy.js")); err != nil {
				t.Fatal(err)
			}
		},
		"hidden": func(t *testing.T, root string) {
			if err := os.Mkdir(filepath.Join(root, ".hidden"), 0o755); err != nil {
				t.Fatal(err)
			}
		},
		"member limit": func(t *testing.T, root string) {
			file, err := os.OpenFile(filepath.Join(root, "large.js"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
			if err != nil || file.Truncate(maxWebDistMemberBytes+1) != nil || file.Close() != nil {
				t.Fatal("cannot create sparse oversized member")
			}
		},
		"metadata limit": func(t *testing.T, root string) {
			file, err := os.OpenFile(filepath.Join(root, "build-metadata.json"), os.O_WRONLY|os.O_TRUNC, 0o644)
			if err != nil || file.Truncate(maxWebMetadataBytes+1) != nil || file.Close() != nil {
				t.Fatal("cannot create sparse oversized metadata")
			}
		},
		"aggregate limit": func(t *testing.T, root string) {
			for index := 0; index < 9; index++ {
				file, err := os.OpenFile(filepath.Join(root, "asset-"+string(rune('a'+index))+".js"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
				if err != nil || file.Truncate(maxWebDistMemberBytes) != nil || file.Close() != nil {
					t.Fatal("cannot create sparse aggregate member")
				}
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			writeValidWebDist(t, root, plan)
			mutate(t, root)
			if _, err := inspectWebDist(root, plan); err == nil {
				t.Fatal("unsafe dist accepted")
			}
		})
	}
}

func TestInspectWebDistRejectsMetadataTamperAndTrailingValue(t *testing.T) {
	plan := testWebPlan()
	for name, rewrite := range map[string]func([]byte) []byte{
		"unknown":        func(raw []byte) []byte { return append(raw[:len(raw)-1], []byte(`,"unexpected":true}`)...) },
		"duplicate":      func(raw []byte) []byte { return append(raw[:len(raw)-1], []byte(`,"mode":"live"}`)...) },
		"trailing value": func(raw []byte) []byte { return append(raw, []byte(" {}")...) },
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			writeValidWebDist(t, root, plan)
			metadataPath := filepath.Join(root, "build-metadata.json")
			raw, err := os.ReadFile(metadataPath)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(metadataPath, rewrite(raw), 0o644); err != nil {
				t.Fatal(err)
			}
			if _, err := inspectWebDist(root, plan); err == nil {
				t.Fatal("invalid metadata accepted")
			}
		})
	}
}

func TestWebAssetStageRejectsReplacedStageRootAndClosedReceipt(t *testing.T) {
	root, cache, witness, policy, tool := syntheticGoReleaseRepository(t)
	plan, err := PrepareGoBuildPlanV1(context.Background(), witness, policy, tool, root, cache, localNPMCLIPath(t))
	defer plan.Close()
	if err != nil {
		t.Fatal(err)
	}
	task, npmCache := buildTaskRoot(t), buildTaskRoot(t)
	stage, err := buildWebAssetsV1(context.Background(), plan, task, npmCache, fakeWebNode(t, plan))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(npmCache, npmCache+"-moved"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(npmCache, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := stage.Receipt(); err == nil {
		t.Fatal("receipt accepted replaced npm cache")
	}
	moved := stage.root + "-moved"
	if err := os.Rename(stage.root, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(stage.root, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := stage.Receipt(); err == nil {
		t.Fatal("replaced stage accepted")
	}
	if err := stage.Close(); err == nil {
		t.Fatal("replaced stage close accepted")
	}
}

func testWebPlan() GoBuildPlanV1 {
	return GoBuildPlanV1{releaseVersion: "1.2.3-rc.1", sourceRepositoryURL: "https://github.com/acme/acornfox-fixture", sourceCommit: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
}

func writeValidWebDist(t *testing.T, root string, plan GoBuildPlanV1) {
	t.Helper()
	if err := os.Mkdir(filepath.Join(root, "assets"), 0o755); err != nil {
		t.Fatal(err)
	}
	metadata, err := json.Marshal(map[string]string{
		"apiBaseUrl":       "/api/v1",
		"mode":             "live",
		"product":          Product,
		"releaseId":        "release-" + plan.releaseVersion,
		"schemaVersion":    webReleaseSchemaVersion,
		"sourceCommit":     plan.sourceCommit,
		"sourceRepository": plan.sourceRepositoryURL,
		"version":          plan.releaseVersion,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "build-metadata.json"), metadata, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "assets", "app.js"), []byte("asset"), 0o644); err != nil {
		t.Fatal(err)
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
			metadata, _ := json.Marshal(map[string]string{"apiBaseUrl": "/api/v1", "mode": "live", "product": Product, "releaseId": "release-" + plan.releaseVersion, "schemaVersion": webReleaseSchemaVersion, "sourceCommit": plan.sourceCommit, "sourceRepository": plan.sourceRepositoryURL, "version": plan.releaseVersion})
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
