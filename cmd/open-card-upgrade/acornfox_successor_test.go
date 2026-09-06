package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/open-card/open-card/internal/install"
)

func TestAcornFoxSuccessorArgumentsBindBothCandidates(t *testing.T) {
	next, current, helper := strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64)
	args := []string{"repository-upgrade", "--candidate-dir", "/candidate", "--binding-sha256", next, "--current-binding-sha256", current, "--self-sha256", helper}
	got, err := parseAcornFoxCleanArgs(args)
	if err != nil || got.bindingSHA256 != next || got.currentBindingSHA256 != current || got.selfSHA256 != helper {
		t.Fatalf("successor identities were not retained: %v", err)
	}
	for _, name := range []string{"missing-predecessor", "same-binding", "invalid-predecessor", "duplicate-flag", "bootstrap-with-predecessor"} {
		t.Run(name, func(t *testing.T) {
			bad := append([]string(nil), args...)
			switch name {
			case "missing-predecessor":
				bad = append(bad[:5], bad[7:]...)
			case "same-binding":
				bad[6] = next
			case "invalid-predecessor":
				bad[6] = "unbound"
			case "duplicate-flag":
				bad[5] = "--binding-sha256"
			case "bootstrap-with-predecessor":
				bad[0] = "repository-bootstrap"
			}
			if _, err := parseAcornFoxCleanArgs(bad); err == nil {
				t.Fatal("unbound or ambiguous predecessor accepted")
			}
		})
	}
}

func cleanUpgradeReceipt(state string) install.AcornFoxUpgradeReceiptV1 {
	r := install.AcornFoxUpgradeReceiptV1{SchemaVersion: 1, State: state, BindingSHA256: strings.Repeat("a", 64), PreviousBindingSHA256: strings.Repeat("b", 64), ReleaseID: "release-1.2.3-test.1", SourceCommit: "0123456789abcdef0123456789abcdef01234567", LayoutSHA256: strings.Repeat("d", 64)}
	if state != "UPGRADED" {
		r.BindingSHA256 = r.PreviousBindingSHA256
		r.ReleaseID = "release-1.2.3-test.0"
		r.SourceCommit = strings.Repeat("e", 40)
	}
	return r
}

func TestAcornFoxSuccessorReportsForwardAndRollbackOutcomes(t *testing.T) {
	withAcornFoxIdentity(t)
	for _, state := range []string{"UPGRADED", "ROLLED_BACK", "unverified-rollback", "unknown", "wrong-binding"} {
		t.Run(state, func(t *testing.T) {
			var out bytes.Buffer
			deps := acornFoxCleanDependencies{euid: func() int { return 0 }, upgrade: func(_ context.Context, req install.AcornFoxUpgradeRequestV1) (install.AcornFoxUpgradeReceiptV1, error) {
				if req.Directory != "/candidate" || req.CurrentBindingSHA256 != strings.Repeat("b", 64) || req.SelfSHA256 != strings.Repeat("c", 64) {
					t.Fatal("unbound upgrade request")
				}
				r := cleanUpgradeReceipt(state)
				if state == "ROLLED_BACK" {
					return r, errors.Join(install.ErrAcornFoxUpgradeRolledBack, errors.New("private failure detail must not be printed"))
				}
				if state == "unverified-rollback" {
					return cleanUpgradeReceipt("ROLLED_BACK"), install.ErrAcornFoxUpgradeUnknown
				}
				if state == "unknown" {
					return install.AcornFoxUpgradeReceiptV1{}, install.ErrAcornFoxUpgradeUnknown
				}
				if state == "wrong-binding" {
					r = cleanUpgradeReceipt("UPGRADED")
					r.BindingSHA256 = strings.Repeat("f", 64)
				}
				return r, nil
			}}
			code := runAcornFoxClean(context.Background(), []string{"repository-upgrade", "--candidate-dir", "/candidate", "--binding-sha256", strings.Repeat("a", 64), "--current-binding-sha256", strings.Repeat("b", 64), "--self-sha256", strings.Repeat("c", 64)}, &out, helperRole, deps)
			want := exitRecovery
			if state == "UPGRADED" {
				want = exitOK
			}
			if code != want || strings.Contains(out.String(), "private failure") {
				t.Fatalf("code=%d output=%s", code, out.String())
			}
			if state == "unverified-rollback" && strings.Contains(out.String(), "upgrade_rolled_back") {
				t.Fatal("unverified rollback was reported as recovered")
			}
			if state == "ROLLED_BACK" && !strings.Contains(out.String(), "upgrade_rolled_back") {
				t.Fatal("successful rollback outcome was lost")
			}
		})
	}
}

func TestAcornFoxUpgradeRecoveryPrecedesCurrentVersionChecks(t *testing.T) {
	withAcornFoxIdentity(t)
	for _, command := range []string{"recover-prepare", "recover-finalize"} {
		for _, state := range []string{"ROLLED_BACK", "RECOVERY_PREPARED"} {
			t.Run(command+"/"+state, func(t *testing.T) {
				var out bytes.Buffer
				called := 0
				recover := func(_ context.Context, id install.AcornFoxBuildIdentityV1) (install.AcornFoxUpgradeReceiptV1, bool, error) {
					called++
					if id.ReleaseID != "release-1.2.3-test.1" {
						t.Fatal("wrong executing identity")
					}
					return cleanUpgradeReceipt(state), true, nil
				}
				deps := acornFoxCleanDependencies{euid: func() int { return 0 }, prepareUpgradeRecovery: recover, finalizeUpgradeRecovery: recover,
					recoverRuntime: func(context.Context, install.AcornFoxBuildIdentityV1) error {
						t.Fatal("bootstrap config recovery crossed upgrade boundary")
						return nil
					},
					recover: func(context.Context) (install.AcornFoxHostBootstrapReceiptV1, error) {
						t.Fatal("bootstrap recovery crossed upgrade boundary")
						return install.AcornFoxHostBootstrapReceiptV1{}, nil
					},
				}
				got := runAcornFoxClean(context.Background(), []string{command, "--pending"}, &out, helperRole, deps)
				want := exitOK
				if command == "recover-finalize" && state == "RECOVERY_PREPARED" {
					want = exitRecovery
				}
				if got != want || called != 1 {
					t.Fatalf("code=%d calls=%d output=%s", got, called, out.String())
				}
			})
		}
	}
}
