package acornfoxrelease

import (
	"context"
	"strings"
	"testing"
)

func TestPublishedForkKeepsExplicitOriginalModuleIdentity(t *testing.T) {
	root, cache, witness, policy, toolchain := syntheticGoReleaseRepository(t)
	witness.decision.SourceRepository = "https://github.com/acme/published-fork"
	gitRun(t, root, "remote", "set-url", "origin", witness.decision.SourceRepository)
	seal := func(policy SourcePolicyV1) Witness {
		t.Helper()
		raw, err := CanonicalSourcePolicyV1(policy)
		if err != nil {
			t.Fatal(err)
		}
		decision := witness.decision
		decision.SourcePolicySHA256 = sha256Text(raw)
		body, err := CanonicalDecisionV1(decision)
		if err != nil {
			t.Fatal(err)
		}
		sealed, err := ParseDecisionV1(body, sha256Text(body))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ParseSourcePolicyV1(sealed, raw); err != nil {
			t.Fatal(err)
		}
		return sealed
	}
	witness = seal(policy)
	if err := VerifyGitSourceV1(context.Background(), root, witness, policy, toolchain); err != nil {
		t.Fatal(err)
	}
	plan, err := PrepareGoBuildPlanV1(context.Background(), witness, policy, toolchain, root, cache, localNPMCLIPath(t))
	defer plan.Close()
	if err != nil || !plan.Valid() || plan.Module() != policy.ModulePath || plan.sourceRepositoryURL != witness.decision.SourceRepository {
		t.Fatalf("fork binding failed: %v", err)
	}
	wrong := cloneSourcePolicy(policy)
	wrong.ModulePath = "github.com/acme/wrong-declaration"
	for i, pkg := range wrong.GoPackages {
		wrong.GoPackages[i] = strings.Replace(pkg, policy.ModulePath, wrong.ModulePath, 1)
	}
	rejected, err := PrepareGoBuildPlanV1(context.Background(), seal(wrong), wrong, toolchain, root, buildTaskRoot(t), localNPMCLIPath(t))
	defer rejected.Close()
	if err == nil || rejected.Valid() {
		t.Fatal("declared module differing from actual Go module was accepted")
	}
}
