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
