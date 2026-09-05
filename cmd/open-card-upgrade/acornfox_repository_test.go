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

func TestAcornFoxCleanRejectsHostileArgumentsBeforeDependencies(t *testing.T) {
	withAcornFoxIdentity(t)
	called := 0
	deps := upgradeDependencies{acornFoxClean: acornFoxCleanDependencies{
		euid: func() int { called++; return 0 },
		bootstrap: func(context.Context, install.AcornFoxCandidateSetRequestV1) (install.AcornFoxHostBootstrapReceiptV1, error) {
			called++
			return cleanReceipt(), nil
		},
	}}
	sha := strings.Repeat("a", 64)
	for _, args := range [][]string{
		nil,
		{"repository-bootstrap"},
		{"repository-bootstrap", "--candidate-dir", "/candidate", "--binding-sha256", sha, "--binding-sha256", sha, "--self-sha256", sha},
		{"repository-bootstrap", "--candidate-dir", "candidate", "--binding-sha256", sha, "--self-sha256", sha},
		{"repository-bootstrap", "--candidate-dir", "/", "--binding-sha256", sha, "--self-sha256", sha},
		{"repository-bootstrap", "--candidate-dir", "/candidate", "--binding-sha256", strings.ToUpper(sha), "--self-sha256", sha},
		{"repository-bootstrap", "--candidate-dir", "/candidate", "--binding-sha256", sha, "--self-sha256", sha, "trailing"},
		{"repository-bootstrap", "--candidate-dir", "/candidate", "--binding-sha256", sha, "--unknown", sha},
		{"recover-prepare"},
		{"recover-finalize", "--pending", "extra"},
		{"migrate-control-plane", "--wrong"},
		{"migrate-control-plane", "--pending", "extra"},
		{"run", "--transaction-id", "legacy"},
		{"repository-upgrade"},
		{"migrate-control-plane"},
		{"bootstrap-native"},
		{"preflight"},
		{"backup-create"},
		{"restore-run"},
		{"recover"},
		{"status"},
		{"allow-downgrade"},
	} {
		var stdout, stderr bytes.Buffer
		if code := runWithDependencies(context.Background(), args, &stdout, &stderr, deps); code != exitArgs {
			t.Fatalf("args=%q code=%d stdout=%q stderr=%q", args, code, stdout.String(), stderr.String())
		}
		result := cleanJSON(t, stdout.Bytes())
		if result["ok"] != false || result["code"] != "invalid_arguments" || stderr.Len() != 0 {
			t.Fatalf("args=%q result=%#v stderr=%q", args, result, stderr.String())
		}
	}
	if called != 0 {
		t.Fatalf("dependency calls=%d", called)
	}
}

func TestAcornFoxCleanDispatchesOnlyOneInjectedBridgeOperation(t *testing.T) {
	withAcornFoxIdentity(t)
	sha := strings.Repeat("a", 64)
	selfSHA := strings.Repeat("b", 64)
	for _, test := range []struct {
		name    string
		args    []string
		command string
		callKey string
	}{
		{"bootstrap", []string{"repository-bootstrap", "--self-sha256", selfSHA, "--candidate-dir", "/candidate", "--binding-sha256", sha}, "repository-bootstrap", "bootstrap"},
		{"prepare", []string{"recover-prepare", "--pending"}, "recover-prepare", "recover"},
		{"finalize", []string{"recover-finalize", "--pending"}, "recover-finalize", "finalize"},
		{"migrate", []string{"migrate-control-plane", "--pending"}, "migrate-control-plane", "migrate"},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls := map[string]int{}
			deps := upgradeDependencies{acornFoxClean: acornFoxCleanDependencies{
				euid: func() int { calls["euid"]++; return 0 },
				bootstrap: func(_ context.Context, request install.AcornFoxCandidateSetRequestV1) (install.AcornFoxHostBootstrapReceiptV1, error) {
					calls["bootstrap"]++
					if request.Directory != "/candidate" || request.BindingSHA256 != sha || request.SelfSHA256 != selfSHA {
						t.Fatalf("request=%#v", request)
					}
					return cleanReceipt(), nil
				},
				recover: func(context.Context) (install.AcornFoxHostBootstrapReceiptV1, error) {
					calls["recover"]++
					return cleanReceipt(), nil
				},
				verifyPrepared: func(context.Context) (install.AcornFoxHostBootstrapReceiptV1, error) {
					calls["finalize"]++
					return cleanReceipt(), nil
				},
				migrateControlPlane: func(_ context.Context, identity install.AcornFoxBuildIdentityV1) (install.AcornFoxControlPlaneMigrationReceiptV1, error) {
					calls["migrate"]++
					if identity.Validate() != nil || identity.Role != "upgrade" || identity.ReleaseID != "release-1.2.3-test.1" || identity.SourceCommit != "0123456789abcdef0123456789abcdef01234567" {
						t.Fatalf("identity=%#v", identity)
					}
					return cleanControlPlaneReceipt(), nil
				},
			}}
			var stdout, stderr bytes.Buffer
			if code := runWithDependencies(context.Background(), test.args, &stdout, &stderr, deps); code != exitOK {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
			}
			result := cleanJSON(t, stdout.Bytes())
			if result["ok"] != true || result["command"] != test.command || stderr.Len() != 0 || strings.Contains(stdout.String(), "/candidate") || strings.Contains(stdout.String(), selfSHA) {
				t.Fatalf("result=%#v stdout=%q stderr=%q", result, stdout.String(), stderr.String())
			}
			if calls["euid"] != 1 || calls[test.callKey] != 1 || calls["bootstrap"]+calls["recover"]+calls["finalize"]+calls["migrate"] != 1 {
				t.Fatalf("calls=%#v", calls)
			}
		})
	}
}

func TestAcornFoxCleanMigrateControlPlaneOrderingReceiptAndErrors(t *testing.T) {
	t.Run("identity-before-root-and-dependency", func(t *testing.T) {
		withAcornFoxIdentity(t)
		buildVersion = ""
		calls := 0
		var stdout bytes.Buffer
		code := runAcornFoxClean(context.Background(), []string{"migrate-control-plane", "--pending"}, &stdout, helperRole, acornFoxCleanDependencies{
			euid: func() int { calls++; return 0 },
			migrateControlPlane: func(context.Context, install.AcornFoxBuildIdentityV1) (install.AcornFoxControlPlaneMigrationReceiptV1, error) {
				calls++
				return cleanControlPlaneReceipt(), nil
			},
		})
		if code != exitIneligible || calls != 0 || cleanJSON(t, stdout.Bytes())["code"] != "helper_identity_ineligible" {
			t.Fatalf("code=%d calls=%d stdout=%q", code, calls, stdout.String())
		}
	})
	t.Run("root-before-dependency", func(t *testing.T) {
		withAcornFoxIdentity(t)
		called := false
		var stdout bytes.Buffer
		code := runAcornFoxClean(context.Background(), []string{"migrate-control-plane", "--pending"}, &stdout, helperRole, acornFoxCleanDependencies{
			euid: func() int { return 501 },
			migrateControlPlane: func(context.Context, install.AcornFoxBuildIdentityV1) (install.AcornFoxControlPlaneMigrationReceiptV1, error) {
				called = true
				return cleanControlPlaneReceipt(), nil
			},
		})
		if code != exitIneligible || called || cleanJSON(t, stdout.Bytes())["code"] != "root_ineligible" {
			t.Fatalf("code=%d called=%t stdout=%q", code, called, stdout.String())
		}
	})
	t.Run("unavailable-dependency", func(t *testing.T) {
		withAcornFoxIdentity(t)
		var stdout bytes.Buffer
		code := runAcornFoxClean(context.Background(), []string{"migrate-control-plane", "--pending"}, &stdout, helperRole, acornFoxCleanDependencies{euid: func() int { return 0 }})
		if code != exitIneligible || cleanJSON(t, stdout.Bytes())["code"] != "control_plane_ineligible" {
			t.Fatalf("code=%d stdout=%q", code, stdout.String())
		}
	})
	t.Run("receipt-and-error-map", func(t *testing.T) {
		for _, test := range []struct {
			name    string
			receipt install.AcornFoxControlPlaneMigrationReceiptV1
			err     error
			code    int
			want    string
		}{
			{"valid", cleanControlPlaneReceipt(), nil, exitOK, ""},
			{"invalid", install.AcornFoxControlPlaneMigrationReceiptV1{}, nil, exitIneligible, "control_plane_ineligible"},
			{"release-mismatch", func() install.AcornFoxControlPlaneMigrationReceiptV1 {
				r := cleanControlPlaneReceipt()
				r.ReleaseID = "release-other"
				return r
			}(), nil, exitIneligible, "helper_identity_ineligible"},
			{"source-mismatch", func() install.AcornFoxControlPlaneMigrationReceiptV1 {
				r := cleanControlPlaneReceipt()
				r.SourceCommit = strings.Repeat("f", 40)
				return r
			}(), nil, exitIneligible, "helper_identity_ineligible"},
			{"locked", install.AcornFoxControlPlaneMigrationReceiptV1{}, install.ErrAcornFoxRepoLocked, exitLocked, "repository_locked"},
			{"conflict", install.AcornFoxControlPlaneMigrationReceiptV1{}, install.ErrAcornFoxControlPlaneConflict, exitConflict, "control_plane_conflict"},
			{"unknown", install.AcornFoxControlPlaneMigrationReceiptV1{}, install.ErrAcornFoxControlPlaneUnknown, exitRecovery, "control_plane_recovery_unknown"},
			{"cancelled", install.AcornFoxControlPlaneMigrationReceiptV1{}, context.Canceled, exitRecovery, "control_plane_recovery_unknown"},
		} {
			t.Run(test.name, func(t *testing.T) {
				withAcornFoxIdentity(t)
				calls := 0
				var stdout, stderr bytes.Buffer
				code := runWithDependencies(context.Background(), []string{"migrate-control-plane", "--pending"}, &stdout, &stderr, upgradeDependencies{acornFoxClean: acornFoxCleanDependencies{
					euid: func() int { return 0 },
					migrateControlPlane: func(context.Context, install.AcornFoxBuildIdentityV1) (install.AcornFoxControlPlaneMigrationReceiptV1, error) {
						calls++
						return test.receipt, test.err
					},
				}})
				if code != test.code || calls != 1 || stderr.Len() != 0 {
					t.Fatalf("code=%d calls=%d stdout=%q stderr=%q", code, calls, stdout.String(), stderr.String())
				}
				result := cleanJSON(t, stdout.Bytes())
				if test.want != "" && result["code"] != test.want {
					t.Fatalf("result=%#v", result)
				}
				if test.want == "" && (result["ok"] != true || result["command"] != "migrate-control-plane" || strings.Contains(stdout.String(), "postgresql://")) {
					t.Fatalf("result=%#v stdout=%q", result, stdout.String())
				}
			})
		}
	})
}

func TestAcornFoxCleanRefusesNonRootBeforeBridge(t *testing.T) {
	withAcornFoxIdentity(t)
	called := false
	var stdout, stderr bytes.Buffer
	code := runWithDependencies(context.Background(), []string{"recover-prepare", "--pending"}, &stdout, &stderr, upgradeDependencies{acornFoxClean: acornFoxCleanDependencies{
		euid: func() int { return 501 },
		recover: func(context.Context) (install.AcornFoxHostBootstrapReceiptV1, error) {
			called = true
			return cleanReceipt(), nil
		},
	}})
	if code != exitIneligible || called || stderr.Len() != 0 {
		t.Fatalf("code=%d called=%t stdout=%q stderr=%q", code, called, stdout.String(), stderr.String())
	}
	result := cleanJSON(t, stdout.Bytes())
	if result["code"] != "root_ineligible" {
		t.Fatalf("result=%#v", result)
	}
}

func TestAcornFoxCleanRefusesInvalidEmbeddedIdentityBeforeDependencies(t *testing.T) {
	for _, test := range []struct {
		name   string
		role   string
		mutate func()
	}{
		{"blank-version", "upgrade", func() { buildVersion = "" }},
		{"bad-source", "upgrade", func() { buildSourceCommit = "not-a-commit" }},
		{"bad-layout", "upgrade", func() { buildLayoutSchema = "2" }},
		{"wrong-role", "healthcheck", func() {}},
		{"wrong-process-identity", "upgrade", func() { processIdentity = "not-acornfox" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			withAcornFoxIdentity(t)
			test.mutate()
			calls := 0
			var stdout bytes.Buffer
			code := runAcornFoxClean(context.Background(), []string{"recover-prepare", "--pending"}, &stdout, test.role, acornFoxCleanDependencies{
				euid: func() int { calls++; return 0 },
				recover: func(context.Context) (install.AcornFoxHostBootstrapReceiptV1, error) {
					calls++
					return cleanReceipt(), nil
				},
			})
			if code != exitIneligible || calls != 0 {
				t.Fatalf("code=%d calls=%d stdout=%q", code, calls, stdout.String())
			}
			if result := cleanJSON(t, stdout.Bytes()); result["code"] != "helper_identity_ineligible" {
				t.Fatalf("result=%#v", result)
			}
		})
	}
}

func TestAcornFoxCleanRefusesReceiptIdentityMismatch(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*install.AcornFoxHostBootstrapReceiptV1)
	}{
		{"release", func(receipt *install.AcornFoxHostBootstrapReceiptV1) { receipt.ReleaseID = "release-9.9.9" }},
		{"source", func(receipt *install.AcornFoxHostBootstrapReceiptV1) {
			receipt.SourceCommit = "abcdefabcdefabcdefabcdefabcdefabcdefabcd"
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			withAcornFoxIdentity(t)
			calls := 0
			var stdout, stderr bytes.Buffer
			code := runWithDependencies(context.Background(), []string{"recover-finalize", "--pending"}, &stdout, &stderr, upgradeDependencies{acornFoxClean: acornFoxCleanDependencies{
				euid: func() int { calls++; return 0 },
				verifyPrepared: func(context.Context) (install.AcornFoxHostBootstrapReceiptV1, error) {
					calls++
					receipt := cleanReceipt()
					test.mutate(&receipt)
					return receipt, nil
				},
			}})
			if code != exitIneligible || calls != 2 || stderr.Len() != 0 {
				t.Fatalf("code=%d calls=%d stdout=%q stderr=%q", code, calls, stdout.String(), stderr.String())
			}
			if result := cleanJSON(t, stdout.Bytes()); result["code"] != "helper_identity_ineligible" {
				t.Fatalf("result=%#v", result)
			}
		})
	}
}

func TestAcornFoxCleanMapsBridgeErrors(t *testing.T) {
	withAcornFoxIdentity(t)
	for _, test := range []struct {
		name string
		err  error
		code int
		want string
	}{
		{"locked", install.ErrAcornFoxRepoLocked, exitLocked, "repository_locked"},
		{"conflict", install.ErrAcornFoxRepoConflict, exitConflict, "repository_conflict"},
		{"recovery", install.ErrAcornFoxRepoRecoveryUnknown, exitRecovery, "recovery_unknown"},
		{"cancelled", context.Canceled, exitRecovery, "recovery_unknown"},
		{"substrate-conflict", install.ErrAcornFoxSubstrateConflict, exitConflict, "repository_conflict"},
		{"substrate-recovery", install.ErrAcornFoxSubstrateRecoveryRequired, exitRecovery, "recovery_unknown"},
		{"stage-cleanup", install.ErrAcornFoxStageCleanupUnknown, exitRecovery, "recovery_unknown"},
		{"input", errors.New("untrusted candidate"), exitIneligible, "candidate_ineligible"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := runWithDependencies(context.Background(), []string{"recover-finalize", "--pending"}, &stdout, &stderr, upgradeDependencies{acornFoxClean: acornFoxCleanDependencies{
				euid: func() int { return 0 },
				verifyPrepared: func(context.Context) (install.AcornFoxHostBootstrapReceiptV1, error) {
					return install.AcornFoxHostBootstrapReceiptV1{}, test.err
				},
			}})
			if code != test.code || stderr.Len() != 0 {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
			}
			if result := cleanJSON(t, stdout.Bytes()); result["code"] != test.want {
				t.Fatalf("result=%#v", result)
			}
		})
	}
}

func withAcornFoxIdentity(t *testing.T) {
	t.Helper()
	oldIdentity, oldVersion, oldCommit, oldLayout := processIdentity, buildVersion, buildSourceCommit, buildLayoutSchema
	t.Cleanup(func() {
		processIdentity, buildVersion, buildSourceCommit, buildLayoutSchema = oldIdentity, oldVersion, oldCommit, oldLayout
	})
	processIdentity, buildVersion, buildSourceCommit, buildLayoutSchema = "acornfox", "1.2.3-test.1", "0123456789abcdef0123456789abcdef01234567", "1"
}

func cleanReceipt() install.AcornFoxHostBootstrapReceiptV1 {
	digest := strings.Repeat("a", 64)
	return install.AcornFoxHostBootstrapReceiptV1{SchemaVersion: 1, State: "REPO_PREPARED", BindingSHA256: digest, ReleaseID: "release-1.2.3-test.1", SourceCommit: "0123456789abcdef0123456789abcdef01234567", LayoutSHA256: digest, SubstrateReceiptSHA256: digest, FinalEvidenceSHA256: digest}
}

func cleanControlPlaneReceipt() install.AcornFoxControlPlaneMigrationReceiptV1 {
	digest := strings.Repeat("a", 64)
	return install.AcornFoxControlPlaneMigrationReceiptV1{SchemaVersion: 1, State: "CONTROL_PLANE_MIGRATED", BindingSHA256: digest, ReleaseID: "release-1.2.3-test.1", SourceCommit: "0123456789abcdef0123456789abcdef01234567", MigrationVersion: install.AcornFoxV1MigrationVersion, MigrationRowsSHA256: digest, DatabaseEnvSHA256: digest, DatabaseIdentitySHA256: digest}
}

func cleanJSON(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	if strings.Count(string(raw), "\n") != 1 || !strings.HasSuffix(string(raw), "\n") {
		t.Fatalf("not one JSON line: %q", raw)
	}
	var value map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(raw), &value); err != nil {
		t.Fatalf("json=%q err=%v", raw, err)
	}
	return value
}
