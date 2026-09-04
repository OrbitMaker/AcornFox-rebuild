package acornfoxrelease

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildGoBinariesV1BuildsAndClosesSyntheticStage(t *testing.T) {
	root, cacheRoot, witness, policy, toolchain := syntheticGoReleaseRepository(t)
	plan, err := PrepareGoBuildPlanV1(context.Background(), witness, policy, toolchain, root, cacheRoot)
	if err != nil || !plan.Valid() {
		t.Fatalf("plan=%#v err=%v", plan, err)
	}
	if stage, err := BuildGoBinariesV1(context.Background(), plan, t.TempDir()); err == nil || stage != nil {
		t.Fatal("unsafe task root accepted")
	}
	taskRoot := buildTaskRoot(t)
	var calls [][]string
	stage, err := buildGoBinariesV1(context.Background(), plan, taskRoot, func(ctx context.Context, name string, args []string, dir string, env []string) ([]byte, error) {
		calls = append(calls, append([]string(nil), args...))
		return plan.goExecutable.run(ctx, name, args, dir, env)
	}, nil)
	if err != nil || stage == nil {
		t.Fatalf("stage=%#v err=%v", stage, err)
	}
	if len(calls) != len(fixedTargets)+3 || calls[0][0] != "version" || !sameStrings(calls[1], []string{"mod", "verify"}) || !sameStrings(calls[len(calls)-1], []string{"mod", "verify"}) {
		t.Fatalf("unexpected command sequence: %q", calls)
	}
	for index, target := range plan.Targets() {
		args := calls[index+2]
		if len(args) != 9 || args[0] != "build" || args[1] != "-mod=readonly" || args[2] != "-trimpath" || args[3] != "-buildvcs=false" || args[4] != "-ldflags" || args[5] != strings.Join(target.Ldflags, " ") || args[6] != "-o" || !strings.HasPrefix(args[7], stage.root+string(filepath.Separator)+"bin"+string(filepath.Separator)) || args[8] != target.Package {
			t.Fatalf("unexpected build args: %q", args)
		}
	}
	receipt, err := stage.Receipt()
	if err != nil || receipt.Validate() != nil || len(receipt.Files) != len(fixedTargets) {
		t.Fatalf("receipt=%#v err=%v", receipt, err)
	}
	copy := receipt
	copy.Files[0].Path = "changed"
	again, err := stage.Receipt()
	if err != nil || again.Files[0].Path == "changed" {
		t.Fatal("receipt leaked mutable files")
	}
	upgrade := plan.Targets()[8]
	upgradePath := filepath.Join(stage.root, filepath.FromSlash(upgrade.Output))
	wrong := upgrade
	wrong.Ldflags = append([]string(nil), upgrade.Ldflags...)
	wrong.Ldflags[1] = "-X=main.processIdentity=not-acornfox"
	if _, err := inspectOneBinary(upgradePath, wrong, plan); err == nil {
		t.Fatal("raw acornfox bytes substituted for exact linker symbol")
	}
	defaultOutput := filepath.Join(taskRoot, "default-build")
	if _, err := plan.goExecutable.Run(context.Background(), []string{"build", "-o", defaultOutput, upgrade.Package}, root, plan.Environment()); err != nil {
		t.Fatal(err)
	}
	if _, err := inspectOneBinary(defaultOutput, upgrade, plan); err == nil {
		t.Fatal("default build ID or missing linker flags accepted")
	}
	if err := os.Remove(defaultOutput); err != nil {
		t.Fatal(err)
	}
	stagePath := stagePath(stage)
	if err := stage.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stagePath); !os.IsNotExist(err) {
		t.Fatalf("stage remained after close: %v", err)
	}
	if err := stage.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := stage.Receipt(); err == nil {
		t.Fatal("closed stage returned receipt")
	}
}

func TestBuildGoBinariesV1IsDeterministicAndFailsClosed(t *testing.T) {
	firstRoot, firstCache, firstWitness, firstPolicy, firstToolchain := syntheticGoReleaseRepository(t)
	secondRoot, secondCache, secondWitness, secondPolicy, secondToolchain := syntheticGoReleaseRepository(t)
	firstPlan, err := PrepareGoBuildPlanV1(context.Background(), firstWitness, firstPolicy, firstToolchain, firstRoot, firstCache)
	if err != nil {
		t.Fatal(err)
	}
	secondPlan, err := PrepareGoBuildPlanV1(context.Background(), secondWitness, secondPolicy, secondToolchain, secondRoot, secondCache)
	if err != nil {
		t.Fatal(err)
	}
	firstStage, err := BuildGoBinariesV1(context.Background(), firstPlan, buildTaskRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	defer firstStage.Close()
	secondStage, err := BuildGoBinariesV1(context.Background(), secondPlan, buildTaskRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	defer secondStage.Close()
	firstReceipt, err := firstStage.Receipt()
	if err != nil {
		t.Fatal(err)
	}
	secondReceipt, err := secondStage.Receipt()
	if err != nil {
		t.Fatal(err)
	}
	if firstReceipt.TreeSHA256 != secondReceipt.TreeSHA256 || !sameFileEntries(firstReceipt.Files, secondReceipt.Files) {
		t.Fatalf("non-deterministic trees: %q %q", firstReceipt.TreeSHA256, secondReceipt.TreeSHA256)
	}

	root, cacheRoot, witness, policy, toolchain := syntheticGoReleaseRepository(t)
	plan, err := PrepareGoBuildPlanV1(context.Background(), witness, policy, toolchain, root, cacheRoot)
	if err != nil {
		t.Fatal(err)
	}
	writeReleaseFile(t, filepath.Join(root, policy.Files[0].Path), "changed\n")
	commands := 0
	if stage, err := buildGoBinariesV1(context.Background(), plan, buildTaskRoot(t), func(context.Context, string, []string, string, []string) ([]byte, error) {
		commands++
		return nil, errors.New("must not run")
	}, nil); err == nil || stage != nil || commands != 0 {
		t.Fatal("source drift accepted")
	}
}

func TestBuildGoBinariesV1CleansFailureAndProtectsReplacement(t *testing.T) {
	root, cacheRoot, witness, policy, toolchain := syntheticGoReleaseRepository(t)
	plan, err := PrepareGoBuildPlanV1(context.Background(), witness, policy, toolchain, root, cacheRoot)
	if err != nil {
		t.Fatal(err)
	}
	taskRoot := buildTaskRoot(t)
	builds := 0
	stage, err := buildGoBinariesV1(context.Background(), plan, taskRoot, func(ctx context.Context, name string, args []string, dir string, env []string) ([]byte, error) {
		if args[0] == "build" {
			builds++
			if builds == 3 {
				return nil, errors.New("injected build failure")
			}
		}
		return plan.goExecutable.run(ctx, name, args, dir, env)
	}, nil)
	if err == nil || stage != nil || builds != 3 {
		t.Fatalf("stage=%#v builds=%d err=%v", stage, builds, err)
	}
	entries, err := os.ReadDir(taskRoot)
	if err != nil || len(entries) != 0 {
		t.Fatalf("failure left stage: %v %v", entries, err)
	}
	outputTask := buildTaskRoot(t)
	if stage, err := buildGoBinariesV1(context.Background(), plan, outputTask, plan.goExecutable.run, func(string) error { return errors.New("injected inspect failure") }); err == nil || stage != nil {
		t.Fatal("output inspection failure accepted")
	}
	if entries, err := os.ReadDir(outputTask); err != nil || len(entries) != 0 {
		t.Fatalf("inspect failure left stage: %v %v", entries, err)
	}
	postVerifyTask := buildTaskRoot(t)
	verifies := 0
	if stage, err := buildGoBinariesV1(context.Background(), plan, postVerifyTask, func(ctx context.Context, name string, args []string, dir string, env []string) ([]byte, error) {
		if args[0] == "mod" {
			verifies++
			if verifies == 2 {
				return nil, errors.New("injected post verify failure")
			}
		}
		return plan.goExecutable.run(ctx, name, args, dir, env)
	}, nil); err == nil || stage != nil || verifies != 2 {
		t.Fatalf("post verify accepted: stage=%#v verifies=%d err=%v", stage, verifies, err)
	}
	if entries, err := os.ReadDir(postVerifyTask); err != nil || len(entries) != 0 {
		t.Fatalf("post verify left stage: %v %v", entries, err)
	}

	stage, err = BuildGoBinariesV1(context.Background(), plan, buildTaskRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	foreign := stage.root
	if err := os.RemoveAll(foreign); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(foreign, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := stage.Close(); err == nil {
		t.Fatal("replaced stage closed")
	}
	if _, err := os.Stat(foreign); err != nil {
		t.Fatalf("foreign replacement removed: %v", err)
	}
}

func TestPinnedBinaryRejectsOversizeAndReplacement(t *testing.T) {
	root := buildTaskRoot(t)
	oversize := filepath.Join(root, "oversize")
	file, err := os.OpenFile(oversize, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o755)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(maxGoBinaryOutputBytes + 1); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := openPinnedBinary(oversize, false); err == nil {
		t.Fatal("oversized binary accepted")
	}
	path := filepath.Join(root, "replacement")
	if err := os.WriteFile(path, []byte("first"), 0o755); err != nil {
		t.Fatal(err)
	}
	binary, err := openPinnedBinary(path, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("second"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := binary.Close(); err == nil {
		t.Fatal("replacement accepted after descriptor inspection")
	}
}

func buildTaskRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	return root
}
