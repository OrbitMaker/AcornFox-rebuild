package install

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/open-card/open-card/internal/acornfoxsetup"
	"github.com/open-card/open-card/internal/providers/acornfoxroute"
)

func TestAcornFoxUpgradeKeepsLegacyRuntimeAndPromotesEdgeGrace(t *testing.T) {
	u, p, request, services := upgradeFixture(t)
	s, err := u.openStore()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	lock, err := s.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(p.state, acornFoxRuntimeIntentName))
	if err != nil {
		t.Fatal(err)
	}
	var runtime acornFoxRuntimeIntent
	if json.Unmarshal(raw, &runtime) != nil {
		t.Fatal("runtime")
	}
	legacy, err := acornfoxroute.LegacyInitialConfig(runtime.Inputs.Origin, runtime.Inputs.ResolverEndpoints)
	if err != nil {
		t.Fatal(err)
	}
	for index := range runtime.Files {
		if runtime.Files[index].Path == acornfoxsetup.EdgeConfiguration {
			runtime.Files[index].Data = legacy
		}
	}
	if runtime.validateExisting(true) != nil {
		t.Fatal("legacy runtime invalid")
	}
	if runtime.validate() == nil {
		t.Fatal("new runtime intent accepted legacy profile")
	}
	if _, err := parseAcornFoxRuntimeIntent(acornFoxUpgradeJSON(runtime)); err == nil {
		t.Fatal("new runtime parser accepted legacy profile")
	}

	for path, data := range map[string][]byte{filepath.Join(p.state, acornFoxRuntimeIntentName): acornFoxUpgradeJSON(runtime), filepath.Join(p.state, acornFoxRuntimeReceiptName): acornFoxUpgradeJSON(runtime.receipt(acornFoxUpgradeJSON(runtime))), filepath.Join(p.host, strings.TrimPrefix(acornfoxsetup.EdgeConfiguration, "/")): legacy} {
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(filepath.Join(p.host, strings.TrimPrefix(acornfoxsetup.EdgeConfiguration, "/")), 0644); err != nil {
		t.Fatal(err)
	}
	lock.Release()
	oldRuntime := acornFoxUpgradeJSON(runtime)
	services.failNext = true
	failed, failErr := u.upgrade(context.Background(), request)
	if !errors.Is(failErr, ErrAcornFoxUpgradeRolledBack) || failed.State != "ROLLED_BACK" {
		t.Fatal("legacy runtime rollback", failErr)
	}
	restored, readErr := os.ReadFile(filepath.Join(p.host, strings.TrimPrefix(acornfoxsetup.EdgeConfiguration, "/")))
	if readErr != nil || !bytes.Equal(restored, legacy) {
		t.Fatal("rollback rewrote legacy edge profile")
	}
	services.failNext = false
	result, err := u.upgrade(context.Background(), request)
	if err != nil || result.State != "UPGRADED" {
		t.Fatal("legacy edge upgrade", err)
	}
	j, err := u.load(s)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(acornFoxUpgradeJSON(j.Old.Runtime), oldRuntime) {
		t.Fatal("old snapshot rewritten")
	}
	found := false
	for _, file := range j.Next.Runtime.Files {
		if file.Path == acornfoxsetup.EdgeConfiguration {
			found = bytes.Contains(file.Data, []byte(`"grace_period":"5s"`))
		}
	}
	if !found {
		t.Fatal("next runtime grace not bounded")
	}
	if j.validate(u.layout) != nil {
		t.Fatal("controlled edge transition rejected")
	}
}
