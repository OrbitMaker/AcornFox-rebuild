package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/open-card/open-card/internal/install"
)

func TestAcornFoxVerifyPreparedDispatchNeverRunsUpgradeRecovery(t *testing.T) {
	withAcornFoxIdentity(t)
	for _, recoveryState := range []string{"UPGRADED", "ROLLED_BACK", "RECOVERY_PREPARED", "error"} {
		t.Run(recoveryState, func(t *testing.T) {
			calls := map[string]int{}
			recovery := func(context.Context, install.AcornFoxBuildIdentityV1) (install.AcornFoxUpgradeReceiptV1, bool, error) {
				calls["upgrade-recovery"]++
				if recoveryState == "error" {
					return install.AcornFoxUpgradeReceiptV1{}, true, install.ErrAcornFoxUpgradeUnknown
				}
				return cleanUpgradeReceipt(recoveryState), true, nil
			}
			deps := upgradeDependencies{acornFoxClean: acornFoxCleanDependencies{
				euid: func() int { calls["euid"]++; return 0 },
				verifyPrepared: func(ctx context.Context) (install.AcornFoxHostBootstrapReceiptV1, error) {
					calls["verify-prepared"]++
					if ctx == nil {
						t.Fatal("context lost")
					}
					return cleanReceipt(), nil
				},
				prepareUpgradeRecovery: recovery, finalizeUpgradeRecovery: recovery,
				recover: func(context.Context) (install.AcornFoxHostBootstrapReceiptV1, error) {
					calls["bootstrap-recovery"]++
					return cleanReceipt(), nil
				},
				recoverRuntime: func(context.Context, install.AcornFoxBuildIdentityV1) error { calls["runtime-recovery"]++; return nil },
			}}
			var stdout, stderr bytes.Buffer
			code := runWithDependencies(context.Background(), []string{"verify-prepared"}, &stdout, &stderr, deps)
			if code != exitOK || stderr.Len() != 0 || calls["euid"] != 1 || calls["verify-prepared"] != 1 || calls["upgrade-recovery"] != 0 || calls["bootstrap-recovery"] != 0 || calls["runtime-recovery"] != 0 {
				t.Fatalf("code=%d calls=%v stdout=%s stderr=%s", code, calls, &stdout, &stderr)
			}
			var got struct {
				OK      bool                                   `json:"ok"`
				Command string                                 `json:"command"`
				Receipt install.AcornFoxHostBootstrapReceiptV1 `json:"receipt"`
			}
			decoder := json.NewDecoder(&stdout)
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&got); err != nil {
				t.Fatal(err)
			}
			if !got.OK || got.Command != "verify-prepared" || got.Receipt != cleanReceipt() || got.Receipt.Validate() != nil {
				t.Fatalf("prepared receipt changed: %+v", got)
			}
		})
	}
}

func TestAcornFoxVerifyPreparedRejectsEveryArgumentBeforeDependencies(t *testing.T) {
	withAcornFoxIdentity(t)
	calls := 0
	deps := upgradeDependencies{acornFoxClean: acornFoxCleanDependencies{euid: func() int { calls++; return 0 }, verifyPrepared: func(context.Context) (install.AcornFoxHostBootstrapReceiptV1, error) {
		calls++
		return cleanReceipt(), nil
	}}}
	for _, args := range [][]string{{"verify-prepared", "--pending"}, {"verify-prepared", "/candidate"}, {"verify-prepared", "--candidate-dir", "/candidate"}, {"verify-prepared", "--binding-sha256", strings.Repeat("a", 64)}, {"verify-prepared", "--help"}, {"verify-prepared", "verify-prepared"}} {
		var stdout, stderr bytes.Buffer
		if code := runWithDependencies(context.Background(), args, &stdout, &stderr, deps); code != exitArgs || stderr.Len() != 0 {
			t.Fatalf("args=%q code=%d output=%s", args, code, &stdout)
		}
		if got := cleanJSON(t, stdout.Bytes()); got["ok"] != false || got["code"] != "invalid_arguments" {
			t.Fatalf("args=%q output=%v", args, got)
		}
	}
	if calls != 0 {
		t.Fatalf("hostile args reached dependencies: %d", calls)
	}
}

func TestAcornFoxVerifyPreparedRetainsRootAndBuildIdentityGates(t *testing.T) {
	for _, mode := range []string{"non-root", "missing-root-check", "invalid-version", "invalid-role"} {
		t.Run(mode, func(t *testing.T) {
			withAcornFoxIdentity(t)
			role := helperRole
			euidCalls, verifyCalls := 0, 0
			deps := acornFoxCleanDependencies{euid: func() int { euidCalls++; return 0 }, verifyPrepared: func(context.Context) (install.AcornFoxHostBootstrapReceiptV1, error) {
				verifyCalls++
				return cleanReceipt(), nil
			}}
			want := "root_ineligible"
			switch mode {
			case "non-root":
				deps.euid = func() int { euidCalls++; return 501 }
			case "missing-root-check":
				deps.euid = nil
			case "invalid-version":
				buildVersion = ""
				want = "helper_identity_ineligible"
			case "invalid-role":
				role = "healthcheck"
				want = "helper_identity_ineligible"
			}
			var stdout, stderr bytes.Buffer
			code := runAcornFoxClean(context.Background(), []string{"verify-prepared"}, &stdout, role, deps)
			if code != exitIneligible || verifyCalls != 0 || stderr.Len() != 0 {
				t.Fatalf("code=%d verify=%d output=%s", code, verifyCalls, &stdout)
			}
			if want == "helper_identity_ineligible" && euidCalls != 0 {
				t.Fatal("invalid embedded identity reached dependencies")
			}
			if got := cleanJSON(t, stdout.Bytes()); got["code"] != want {
				t.Fatalf("mode=%s output=%v", mode, got)
			}
		})
	}
}

func TestAcornFoxVerifyPreparedRejectsUnverifiedReceipts(t *testing.T) {
	withAcornFoxIdentity(t)
	for _, mode := range []string{"missing-verifier", "locked", "invalid-receipt", "wrong-release", "wrong-source"} {
		t.Run(mode, func(t *testing.T) {
			receipt := cleanReceipt()
			var verifyErr error
			want, code := "candidate_ineligible", exitIneligible
			switch mode {
			case "missing-verifier":
				want, code = "recovery_unknown", exitRecovery
			case "locked":
				verifyErr = errors.Join(install.ErrAcornFoxRepoLocked, errors.New("private helper detail"))
				want, code = "repository_locked", exitLocked
			case "invalid-receipt":
				receipt.State = "UPGRADED"
			case "wrong-release":
				receipt.ReleaseID = "release-9.9.9"
				want = "helper_identity_ineligible"
			case "wrong-source":
				receipt.SourceCommit = strings.Repeat("b", 40)
				want = "helper_identity_ineligible"
			}
			deps := acornFoxCleanDependencies{euid: func() int { return 0 }, verifyPrepared: func(context.Context) (install.AcornFoxHostBootstrapReceiptV1, error) { return receipt, verifyErr }, finalizeUpgradeRecovery: func(context.Context, install.AcornFoxBuildIdentityV1) (install.AcornFoxUpgradeReceiptV1, bool, error) {
				t.Fatal("verification failure fell through to recovery")
				return install.AcornFoxUpgradeReceiptV1{}, false, nil
			}}
			if mode == "missing-verifier" {
				deps.verifyPrepared = nil
			}
			var stdout, stderr bytes.Buffer
			got := runWithDependencies(context.Background(), []string{"verify-prepared"}, &stdout, &stderr, upgradeDependencies{acornFoxClean: deps})
			if got != code || stderr.Len() != 0 || strings.Contains(stdout.String(), "private helper detail") {
				t.Fatalf("code=%d output=%s", got, &stdout)
			}
			result := cleanJSON(t, stdout.Bytes())
			if result["code"] != want || result["ok"] != false {
				t.Fatalf("mode=%s result=%v", mode, result)
			}
		})
	}
}
