package acornfoxrelease

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestPrepareGoBuildPlanV1SealsRealDetachedRepository(t *testing.T) {
	root, cacheRoot, witness, policy, toolchain := syntheticGoReleaseRepository(t)
	if err := VerifyGitSourceV1(context.Background(), root, witness, policy); err != nil {
		t.Fatalf("precondition git verification: %v", err)
	}
	plan, err := PrepareGoBuildPlanV1(context.Background(), witness, policy, toolchain, root, cacheRoot)
	if err != nil || !plan.Valid() {
		t.Fatalf("plan=%#v err=%v", plan, err)
	}
	if got, want := plan.Packages(), fixedPackagePaths(policy.ModulePath); !sameStrings(got, want) {
		t.Fatalf("packages=%q want=%q", got, want)
	}
	if got := plan.BaseFlags(); !sameStrings(got, []string{"-trimpath", "-buildvcs=false"}) {
		t.Fatalf("base flags=%q", got)
	}
	if len(plan.Targets()) != len(fixedTargets) || plan.DecisionSHA256() == "" || plan.SourcePolicySHA256() == "" || plan.ToolchainSHA256() == "" || plan.Module() != policy.ModulePath || plan.SourceCommit() != witness.decision.SourceCommit {
		t.Fatalf("unsealed plan: %#v", plan)
	}
	for _, target := range plan.Targets() {
		if target.Output != "bin/"+target.Name || len(target.Ldflags) == 0 || target.Ldflags[0] != "-buildid=" {
			t.Fatalf("unsealed target: %#v", target)
		}
		if target.Name == "acornfox-server" || target.Name == "acornfox-agent" || target.Name == "acornfox-upgrade" || target.Name == "acornfox-healthcheck" {
			if !containsString(target.Ldflags, "-X=main.processIdentity=acornfox") {
				t.Fatalf("missing process identity: %#v", target)
			}
		}
		if target.Name == "acornfox-upgrade" || target.Name == "acornfox-healthcheck" {
			if !containsString(target.Ldflags, "-X=main.buildVersion="+witness.decision.Version) || !containsString(target.Ldflags, "-X=main.buildSourceCommit="+witness.decision.SourceCommit) || !containsString(target.Ldflags, "-X=main.buildLayoutSchema=1") {
				t.Fatalf("missing recovery build binding: %#v", target)
			}
		}
	}
	targets := plan.Targets()
	targets[0].Ldflags[0] = "changed"
	if plan.Targets()[0].Ldflags[0] == "changed" {
		t.Fatal("plan leaked mutable target")
	}
	env := plan.Environment()
	env[0] = "changed"
	if plan.Environment()[0] == "changed" {
		t.Fatal("plan leaked mutable environment")
	}
	if entries, err := os.ReadDir(root); err != nil || containsName(entries, "bin") {
		t.Fatalf("preparation created release output: %v %v", entries, err)
	}
}

func TestPrepareGoBuildPlanV1UsesOnlySealedGoList(t *testing.T) {
	root, cacheRoot, witness, policy, toolchain := syntheticGoReleaseRepository(t)
	if err := VerifyGitSourceV1(context.Background(), root, witness, policy); err != nil {
		t.Fatalf("precondition git verification: %v", err)
	}
	var calls [][]string
	runner := func(_ context.Context, name string, args []string, dir string, env []string) ([]byte, error) {
		if !filepath.IsAbs(name) {
			t.Fatalf("untrusted go command %q", name)
		}
		if !containsString(env, "GOSUMDB=off") {
			t.Fatalf("missing offline sumdb policy: %q", env)
		}
		calls = append(calls, append([]string(nil), args...))
		switch args[0] {
		case "version":
			return []byte("go version " + toolchain.GoVersion + " linux/amd64\n"), nil
		case "mod":
			if !sameStrings(args, []string{"mod", "verify"}) {
				t.Fatalf("verify args=%q", args)
			}
			return []byte("all modules verified\n"), nil
		case "list":
			want := append([]string{"list", "-mod=readonly", "-buildvcs=false", "-deps", "-json"}, fixedPackagePaths(policy.ModulePath)...)
			if !sameStrings(args, want) {
				t.Fatalf("list args=%q want=%q", args, want)
			}
			return syntheticGoListJSON(t, policy, dir), nil
		default:
			t.Fatalf("go command %q is forbidden", args[0])
			return nil, nil
		}
	}
	plan, err := prepareGoBuildPlanV1(context.Background(), witness, policy, toolchain, root, cacheRoot, runner)
	if err != nil || !plan.Valid() || len(calls) != 3 {
		if verifyErr := VerifyGitSourceV1(context.Background(), root, witness, policy); verifyErr != nil {
			t.Fatalf("postcondition git verification: %v", verifyErr)
		}
		t.Fatalf("plan=%#v calls=%q err=%v", plan, calls, err)
	}
	if calls[0][0] != "version" || calls[1][0] != "mod" || calls[2][0] != "list" {
		t.Fatalf("unexpected command order: %q", calls)
	}
	for _, call := range calls {
		if call[0] == "build" {
			t.Fatal("go build was invoked")
		}
	}
}

func TestPrepareGoBuildPlanV1PinsGoExecutableAndStopsOnVerifyFailure(t *testing.T) {
	root, cacheRoot, witness, policy, toolchain := syntheticGoReleaseRepository(t)
	goPath := filepath.Join(t.TempDir(), "go")
	if err := os.WriteFile(goPath, []byte("fixture-go"), 0o755); err != nil {
		t.Fatal(err)
	}
	resolvedGoPath, err := resolveTrustedExecutable("go", func(string) (string, error) { return goPath, nil })
	if err != nil {
		t.Fatal(err)
	}
	goPath = resolvedGoPath
	digest, err := hashTrustedExecutable(goPath)
	if err != nil {
		t.Fatal(err)
	}
	toolchain.GoBinarySHA256 = digest
	witness = witnessForToolchain(t, witness, toolchain)
	var calls [][]string
	runner := func(_ context.Context, name string, args []string, dir string, _ []string) ([]byte, error) {
		if name != goPath {
			t.Fatalf("untrusted executable %q", name)
		}
		calls = append(calls, append([]string(nil), args...))
		switch args[0] {
		case "version":
			return []byte("go version " + toolchain.GoVersion + " linux/amd64\n"), nil
		case "mod":
			return nil, errors.New("tampered module cache")
		case "list":
			t.Fatal("go list ran after failed mod verify")
		}
		return nil, errors.New("unexpected command")
	}
	plan, err := prepareGoBuildPlanWithDependencies(context.Background(), witness, policy, toolchain, root, cacheRoot, runner, func(string) (string, error) { return goPath, nil }, hashTrustedExecutable)
	if err == nil || plan.Valid() || len(calls) != 2 || calls[1][0] != "mod" {
		t.Fatalf("plan=%#v calls=%q err=%v", plan, calls, err)
	}
	toolchain.GoBinarySHA256 = strings.Repeat("0", 64)
	witness = witnessForToolchain(t, witness, toolchain)
	if plan, err := prepareGoBuildPlanWithDependencies(context.Background(), witness, policy, toolchain, root, cacheRoot, runner, func(string) (string, error) { return goPath, nil }, hashTrustedExecutable); err == nil || plan.Valid() {
		t.Fatal("digest drift accepted")
	}
}

func TestSealedGoEnvironmentRequiresCallerCreatedCacheRoot(t *testing.T) {
	root, _, _, _, _ := syntheticGoReleaseRepository(t)
	missing := filepath.Join(t.TempDir(), "not-created")
	if _, _, _, err := sealedGoEnvironment(root, missing); err == nil {
		t.Fatal("created caller task cache root")
	}
}

func TestVerifyGoListClosureRejectsUnsafeObservations(t *testing.T) {
	root, cacheRoot, _, policy, _ := syntheticGoReleaseRepository(t)
	valid := syntheticGoListJSON(t, policy, root)
	if !verifyGoListClosure(valid, policy, root, cacheRoot) {
		t.Fatal("valid closure rejected")
	}
	for name, mutate := range map[string]func([]map[string]any){
		"error":      func(rows []map[string]any) { rows[0]["Error"] = map[string]any{"Err": "bad"} },
		"incomplete": func(rows []map[string]any) { rows[0]["Incomplete"] = true },
		"replace": func(rows []map[string]any) {
			rows[0]["Module"].(map[string]any)["Replace"] = map[string]any{"Path": "bad"}
		},
		"root escape":   func(rows []map[string]any) { rows[0]["Dir"] = t.TempDir() },
		"closure drift": func(rows []map[string]any) { rows[0]["ImportPath"] = "github.com/acme/other" },
	} {
		t.Run(name, func(t *testing.T) {
			rows := syntheticGoListRows(policy, root)
			mutate(rows)
			raw := marshalGoListRows(t, rows)
			if verifyGoListClosure(raw, policy, root, cacheRoot) {
				t.Fatal("accepted unsafe " + name)
			}
		})
	}
}

func TestVerifyGoListClosureRequiresExistingCachedThirdPartyModule(t *testing.T) {
	root, cacheRoot, _, policy, _ := syntheticGoReleaseRepository(t)
	modCache, err := pinnedCacheChild(cacheRoot, "go-mod-cache")
	if err != nil {
		t.Fatal(err)
	}
	moduleDir := filepath.Join(modCache, "example.com", "module@v1.2.3")
	packageDir := filepath.Join(moduleDir, "pkg")
	if err := os.MkdirAll(packageDir, 0o700); err != nil {
		t.Fatal(err)
	}
	rows := syntheticGoListRows(policy, root)
	rows = append(rows, map[string]any{"ImportPath": "example.com/module/pkg", "Dir": packageDir, "Module": map[string]any{"Path": "example.com/module", "Version": "v1.2.3", "Dir": moduleDir}})
	raw := marshalGoListRows(t, rows)
	if !verifyGoListClosure(raw, policy, root, modCache) {
		t.Fatal("cached third-party module rejected")
	}
	if err := os.RemoveAll(moduleDir); err != nil {
		t.Fatal(err)
	}
	if verifyGoListClosure(raw, policy, root, modCache) {
		t.Fatal("missing third-party module accepted")
	}
	if err := os.MkdirAll(packageDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := pinnedCacheChild(cacheRoot, "go-cache"); err != nil {
		t.Fatal(err)
	}
	if verifyGoListClosure(raw, policy, root, filepath.Join(cacheRoot, "go-cache")) {
		t.Fatal("sibling cache accepted")
	}
}

func TestPrepareGoBuildPlanV1RejectsSourcePackageDrift(t *testing.T) {
	root, cacheRoot, witness, policy, toolchain := syntheticGoReleaseRepository(t)
	for name, mutate := range map[string]func(*SourcePolicyV1){
		"missing": func(policy *SourcePolicyV1) { policy.GoPackages = append([]string(nil), policy.GoPackages[1:]...) },
		"extra": func(policy *SourcePolicyV1) {
			policy.GoPackages = append(policy.GoPackages, policy.ModulePath+"/extra")
			sort.Strings(policy.GoPackages)
		},
		"order": func(policy *SourcePolicyV1) {
			policy.GoPackages[0], policy.GoPackages[1] = policy.GoPackages[1], policy.GoPackages[0]
		},
		"cross module": func(policy *SourcePolicyV1) { policy.GoPackages[0] = "github.com/acme/other/cmd" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := policy
			candidate.GoPackages = append([]string(nil), policy.GoPackages...)
			mutate(&candidate)
			candidateWitness := witnessForPolicy(t, witness, candidate)
			candidateCache := filepath.Join(cacheRoot, name)
			if err := os.Mkdir(candidateCache, 0o700); err != nil {
				t.Fatal(err)
			}
			plan, err := prepareGoBuildPlanV1(context.Background(), candidateWitness, candidate, toolchain, root, candidateCache, func(_ context.Context, _ string, args []string, dir string, _ []string) ([]byte, error) {
				if args[0] == "version" {
					return []byte("go version " + toolchain.GoVersion + " linux/amd64\n"), nil
				}
				if args[0] == "mod" {
					return []byte("all modules verified\n"), nil
				}
				return syntheticGoListJSON(t, policy, dir), nil
			})
			if err == nil || plan.Valid() {
				t.Fatalf("accepted package drift %s: %#v", name, plan)
			}
		})
	}
}

func syntheticGoReleaseRepository(t *testing.T) (string, string, Witness, SourcePolicyV1, ToolchainInputsV1) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "source")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	module := "github.com/acme/acornfox-fixture"
	writeReleaseFile(t, filepath.Join(root, "go.mod"), "module "+module+"\n\ngo 1.25.13\n")
	for _, target := range fixedTargets {
		writeReleaseFile(t, filepath.Join(root, strings.TrimPrefix(target.path, "./"), "main.go"), "package main\nfunc main() {}\n")
	}
	gitRun(t, root, "init", "-q")
	gitRun(t, root, "config", "user.email", "fixture@example.test")
	gitRun(t, root, "config", "user.name", "fixture")
	gitRun(t, root, "remote", "add", "origin", "https://github.com/acme/acornfox-fixture")
	gitRun(t, root, "add", ".")
	gitRun(t, root, "commit", "-qm", "fixture")
	commit := gitRun(t, root, "rev-parse", "HEAD")
	gitRun(t, root, "checkout", "-q", "--detach")
	policy := policyForTree(t, root, module)
	toolchain := ToolchainInputsV1{SchemaVersion: 1, Product: Product, Architecture: Architecture, GoVersion: localGoVersion(t), GoBinarySHA256: localGoBinaryDigest(t), NodeVersion: "v22.0.0", NPMVersion: "10.0.0", BuildPolicy: append([]string(nil), fixedBuildPolicy...)}
	runtime := RuntimeInputsV1{SchemaVersion: 1, Product: Product, Architecture: Architecture, Files: []FileEntryV1{{Path: "runtime", SHA256: strings.Repeat("a", 64), Mode: 0o644}}}
	license := LicenseInputsV1{SchemaVersion: 1, Product: Product, Files: []FileEntryV1{{Path: "LICENSE", SHA256: strings.Repeat("b", 64), Mode: 0o644}}}
	witness := witnessForInputs(t, policy, toolchain, runtime, license)
	witness.decision.SourceCommit = commit
	raw, err := CanonicalDecisionV1(witness.decision)
	if err != nil {
		t.Fatal(err)
	}
	witness, err = ParseDecisionV1(raw, sha256Text(raw))
	if err != nil {
		t.Fatal(err)
	}
	cacheRoot := filepath.Join(t.TempDir(), "cache")
	if err := os.Mkdir(cacheRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	return root, cacheRoot, witness, policy, toolchain
}

func policyForTree(t *testing.T, root, module string) SourcePolicyV1 {
	t.Helper()
	var files []FileEntryV1
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil || rel == "." || rel == ".git" || strings.HasPrefix(rel, ".git"+string(filepath.Separator)) {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		files = append(files, FileEntryV1{Path: filepath.ToSlash(rel), SHA256: sha256Text(body), Mode: uint32(info.Mode().Perm())})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	packages := fixedPackagePaths(module)
	sort.Strings(packages)
	policy := SourcePolicyV1{SchemaVersion: 1, Product: Product, ModulePath: module, GoPackages: packages, Files: files}
	if err := policy.Validate(); err != nil {
		t.Fatal(err)
	}
	return policy
}
func syntheticGoListJSON(t *testing.T, policy SourcePolicyV1, root string) []byte {
	return marshalGoListRows(t, syntheticGoListRows(policy, root))
}

func syntheticGoListRows(policy SourcePolicyV1, root string) []map[string]any {
	rows := make([]map[string]any, 0, len(policy.GoPackages))
	for _, importPath := range policy.GoPackages {
		dir := filepath.Join(root, strings.TrimPrefix(importPath, policy.ModulePath+"/"))
		rows = append(rows, map[string]any{"ImportPath": importPath, "Dir": dir, "Module": map[string]any{"Path": policy.ModulePath, "Main": true, "Dir": root}})
	}
	return rows
}

func marshalGoListRows(t *testing.T, rows []map[string]any) []byte {
	t.Helper()
	var raw []byte
	for _, row := range rows {
		encoded, err := json.Marshal(row)
		if err != nil {
			t.Fatal(err)
		}
		raw = append(raw, encoded...)
		raw = append(raw, '\n')
	}
	return raw
}
func localGoVersion(t *testing.T) string {
	t.Helper()
	raw, err := exec.Command("go", "version").Output()
	if err != nil {
		t.Fatal(err)
	}
	version := goVersionFromOutput(raw)
	if version == "" {
		t.Fatalf("unexpected go version %q", raw)
	}
	return version
}
func localGoBinaryDigest(t *testing.T) string {
	t.Helper()
	path, err := resolveTrustedExecutable("go", exec.LookPath)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := hashTrustedExecutable(path)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}
func writeReleaseFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}
func gitRun(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	raw, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %q: %v: %s", args, err, raw)
	}
	return strings.TrimSpace(string(raw))
}
func sameStrings(got, want []string) bool {
	return strings.Join(got, "\x00") == strings.Join(want, "\x00")
}
func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
func containsName(entries []os.DirEntry, name string) bool {
	for _, entry := range entries {
		if entry.Name() == name {
			return true
		}
	}
	return false
}

func witnessForPolicy(t *testing.T, witness Witness, policy SourcePolicyV1) Witness {
	t.Helper()
	raw, err := CanonicalSourcePolicyV1(policy)
	if err != nil {
		return Witness{}
	}
	decision := witness.decision
	decision.SourcePolicySHA256 = sha256Text(raw)
	encoded, err := CanonicalDecisionV1(decision)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseDecisionV1(encoded, sha256Text(encoded))
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func witnessForToolchain(t *testing.T, witness Witness, toolchain ToolchainInputsV1) Witness {
	t.Helper()
	raw, err := CanonicalToolchainInputsV1(toolchain)
	if err != nil {
		t.Fatal(err)
	}
	decision := witness.decision
	decision.ToolchainSHA256 = sha256Text(raw)
	encoded, err := CanonicalDecisionV1(decision)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseDecisionV1(encoded, sha256Text(encoded))
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}
