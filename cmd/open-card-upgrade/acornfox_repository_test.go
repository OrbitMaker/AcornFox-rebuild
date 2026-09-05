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
			}}
			var stdout, stderr bytes.Buffer
			if code := runWithDependencies(context.Background(), test.args, &stdout, &stderr, deps); code != exitOK {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
			}
			result := cleanJSON(t, stdout.Bytes())
			if result["ok"] != true || result["command"] != test.command || stderr.Len() != 0 || strings.Contains(stdout.String(), "/candidate") || strings.Contains(stdout.String(), selfSHA) {
				t.Fatalf("result=%#v stdout=%q stderr=%q", result, stdout.String(), stderr.String())
			}
			if calls["euid"] != 1 || calls[test.callKey] != 1 || calls["bootstrap"]+calls["recover"]+calls["finalize"] != 1 {
				t.Fatalf("calls=%#v", calls)
			}
		})
	}
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
