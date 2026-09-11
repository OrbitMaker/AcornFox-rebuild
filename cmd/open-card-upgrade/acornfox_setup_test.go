package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/open-card/open-card/internal/install"
	"github.com/open-card/open-card/internal/runtimenetwork"
)

func TestAcornFoxRuntimeInputCheckHasNoHostEffects(t *testing.T) {
	withAcornFoxIdentity(t)
	called := false
	deps := upgradeDependencies{acornFoxClean: acornFoxCleanDependencies{euid: func() int { return 0 }, bootstrap: func(context.Context, install.AcornFoxCandidateSetRequestV1) (install.AcornFoxHostBootstrapReceiptV1, error) {
		called = true
		return cleanReceipt(), nil
	}}}
	for _, tc := range []struct {
		origin, resolvers string
		ok                bool
	}{
		{"https://console.example.org", "223.5.5.5:53,223.6.6.6:53", true},
		{"http://console.example.org", "223.5.5.5:53,223.6.6.6:53", false},
		{"https://user:secret@console.example.org", "223.5.5.5:53,223.6.6.6:53", false},
		{"https://console.example.org", "127.0.0.1:53,223.5.5.5:53", false},
		{"https://console.example.org", "223.5.5.5:53", false},
	} {
		var out, diagnostic bytes.Buffer
		code := runWithDependencies(context.Background(), []string{"validate-runtime-inputs", "--public-origin", tc.origin, "--git-resolvers", tc.resolvers}, &out, &diagnostic, deps)
		if (code == exitOK) != tc.ok {
			t.Fatalf("accepted=%v code=%d", tc.ok, code)
		}
		if bytes.Contains(out.Bytes(), []byte("secret")) || diagnostic.Len() != 0 {
			t.Fatal("invalid input echoed")
		}
	}
	if called {
		t.Fatal("input validation reached host mutation")
	}
}

func TestAcornFoxLocalRuntimeInputCheck(t *testing.T) {
	withAcornFoxIdentity(t)
	called := false
	deps := upgradeDependencies{acornFoxClean: acornFoxCleanDependencies{
		euid: func() int { return 0 },
		configureLocalRuntime: func(context.Context, install.AcornFoxBuildIdentityV1, []string) (install.AcornFoxRuntimeConfigReceiptV1, error) {
			called = true
			return install.AcornFoxRuntimeConfigReceiptV1{SchemaVersion: 1, State: "RUNTIME_CONFIGURED", BindingSHA256: strings.Repeat("a", 64), ReleaseID: "release-1.2.3-test.1", SourceCommit: "0123456789abcdef0123456789abcdef01234567", IntentSHA256: strings.Repeat("c", 64)}, nil
		},
	}}

	// 1. validate-local-runtime-inputs with empty args succeeds
	var out, diagnostic bytes.Buffer
	code := runWithDependencies(context.Background(), []string{"validate-local-runtime-inputs"}, &out, &diagnostic, deps)
	if code != exitOK {
		t.Fatalf("expected exitOK, got %d, out=%s, diag=%s", code, out.String(), diagnostic.String())
	}

	// 2. validate-local-runtime-inputs with valid resolvers succeeds
	out.Reset()
	diagnostic.Reset()
	code = runWithDependencies(context.Background(), []string{"validate-local-runtime-inputs", "--git-resolvers", "1.1.1.1:53,8.8.8.8:53"}, &out, &diagnostic, deps)
	if code != exitOK {
		t.Fatalf("expected exitOK, got %d, out=%s, diag=%s", code, out.String(), diagnostic.String())
	}

	// 3. validate-local-runtime-inputs with invalid resolvers fails
	out.Reset()
	diagnostic.Reset()
	code = runWithDependencies(context.Background(), []string{"validate-local-runtime-inputs", "--git-resolvers", "127.0.0.1:53"}, &out, &diagnostic, deps)
	if code == exitOK {
		t.Fatalf("expected failure for loopback resolver, got exitOK")
	}

	// 4. validate-local-runtime-inputs rejects --public-origin
	out.Reset()
	diagnostic.Reset()
	code = runWithDependencies(context.Background(), []string{"validate-local-runtime-inputs", "--public-origin", "http://127.0.0.1:8080"}, &out, &diagnostic, deps)
	if code == exitOK {
		t.Fatalf("expected failure when passing --public-origin to local command, got exitOK")
	}

	// 5. configure-local-runtime executes successfully
	out.Reset()
	diagnostic.Reset()
	code = runWithDependencies(context.Background(), []string{"configure-local-runtime"}, &out, &diagnostic, deps)
	if code != exitOK || !called {
		t.Fatalf("configure-local-runtime failed or did not invoke dependency: code=%d called=%v", code, called)
	}

	// 6. wait-local-ready executes successfully and rejects extra arguments
	waitCalled := false
	deps.acornFoxClean.waitLocalReady = func(context.Context) error {
		waitCalled = true
		return nil
	}
	out.Reset()
	diagnostic.Reset()
	code = runWithDependencies(context.Background(), []string{"wait-local-ready"}, &out, &diagnostic, deps)
	if code != exitOK || !waitCalled {
		t.Fatalf("wait-local-ready failed: code=%d called=%v", code, waitCalled)
	}

	out.Reset()
	diagnostic.Reset()
	code = runWithDependencies(context.Background(), []string{"wait-local-ready", "--unexpected-arg"}, &out, &diagnostic, deps)
	if code == exitOK {
		t.Fatalf("wait-local-ready accepted unexpected arguments")
	}
}

func TestAcornFoxConfigRecoveryPrecedesRepositoryRecovery(t *testing.T) {
	withAcornFoxIdentity(t)
	for _, fail := range []bool{false, true} {
		calls := []string{}
		deps := upgradeDependencies{acornFoxClean: acornFoxCleanDependencies{euid: func() int { return 0 }, recoverRuntime: func(context.Context, install.AcornFoxBuildIdentityV1) error {
			calls = append(calls, "config")
			if fail {
				return errors.New("private error")
			}
			return nil
		}, recover: func(context.Context) (install.AcornFoxHostBootstrapReceiptV1, error) {
			calls = append(calls, "repository")
			return cleanReceipt(), nil
		}}}
		var out, diagnostic bytes.Buffer
		code := runWithDependencies(context.Background(), []string{"recover-prepare", "--pending"}, &out, &diagnostic, deps)
		if (code == exitOK) == fail || len(calls) != (map[bool]int{false: 2, true: 1})[fail] || calls[0] != "config" {
			t.Fatalf("code=%d order=%v", code, calls)
		}
		if bytes.Contains(out.Bytes(), []byte("private error")) {
			t.Fatal("private error echoed")
		}
	}
}

func TestAcornFoxRuntimeNetworkRequiresInstalledHelperIdentity(t *testing.T) {
	withAcornFoxIdentity(t)
	for _, valid := range []bool{false, true} {
		calls := 0
		sha := strings.Repeat("a", 64)
		deps := upgradeDependencies{acornFoxClean: acornFoxCleanDependencies{euid: func() int { return 0 }, verifyHelper: func(install.AcornFoxBuildIdentityV1) bool { return valid }, prepareRuntimeNetwork: func(context.Context) (runtimenetwork.Receipt, error) {
			calls++
			return runtimenetwork.Receipt{SchemaVersion: 1, PolicySHA256: sha, NetworkID: sha, FirewallSHA256: sha}, nil
		}}}
		var out, diagnostic bytes.Buffer
		code := runWithDependencies(context.Background(), []string{"runtime-network-prepare"}, &out, &diagnostic, deps)
		if (code == exitOK) != valid || (calls == 1) != valid {
			t.Fatalf("valid=%v code=%d calls=%d", valid, code, calls)
		}
	}
}
