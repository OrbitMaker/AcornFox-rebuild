package acornfoxrelease

import (
	"sort"
	"strings"
	"testing"
)

func TestPrepareGoBuildPlanV1IsSealed(t *testing.T) {
	p := sourcePolicyFixture()
	p.GoPackages = nil
	for _, target := range fixedTargets {
		p.GoPackages = append(p.GoPackages, p.ModulePath+"/"+strings.TrimPrefix(target.path, "./"))
	}
	sort.Strings(p.GoPackages)
	raw, _ := CanonicalSourcePolicyV1(p)
	tool := ToolchainInputsV1{SchemaVersion: 1, Product: Product, Architecture: Architecture, GoVersion: "go1.25.0", NodeVersion: "v22.0.0", NPMVersion: "10.0.0", BuildPolicy: []string{"build_id_empty", "build_vcs_disabled", "cgo_disabled", "trimpath"}}
	runtime := RuntimeInputsV1{SchemaVersion: 1, Product: Product, Architecture: Architecture, Files: []FileEntryV1{{Path: "runtime", SHA256: strings.Repeat("a", 64), Mode: 0o644}}}
	license := LicenseInputsV1{SchemaVersion: 1, Product: Product, Files: []FileEntryV1{{Path: "LICENSE", SHA256: strings.Repeat("b", 64), Mode: 0o644}}}
	w := witnessForInputs(t, p, tool, runtime, license)
	if _, e := ParseSourcePolicyV1(w, raw); e != nil {
		t.Fatal(e)
	}
	plan, e := PrepareGoBuildPlanV1(w, p)
	if e != nil || !plan.Valid() || len(plan.Targets()) != 10 {
		t.Fatalf("plan=%#v err=%v", plan, e)
	}
	targets := plan.Targets()
	targets[0].Ldflags[0] = "changed"
	if plan.Targets()[0].Ldflags[0] == "changed" {
		t.Fatal("plan leaked mutable target")
	}
}
