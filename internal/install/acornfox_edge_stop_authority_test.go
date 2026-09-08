package install

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/open-card/open-card/internal/acornfoxsetup"
	"github.com/open-card/open-card/internal/providers/acornfoxroute"
)

func TestAcornFoxEdgeLegacyQuitRequiresBoundConfigMarkerAndGuard(t *testing.T) {
	host := t.TempDir()
	state := filepath.Join(host, "var/lib/acornfox/install")
	if err := os.MkdirAll(state, 0700); err != nil {
		t.Fatal(err)
	}
	layout, err := newTestProductionAcornFoxLayout(state, host, os.Getuid(), os.Getgid(), acornFoxTestLayoutPrincipals())
	if err != nil {
		t.Fatal(err)
	}
	store, err := newAcornFoxRepoStoreForLayout(layout)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	u := newAcornFoxUpgrade(layout)
	legacy, _ := acornfoxroute.LegacyInitialConfig("https://console.example.com", []string{"1.1.1.1:53"})
	bounded, _ := acornfoxroute.InitialConfig("https://console.example.com", []string{"1.1.1.1:53"})
	oldSHA, nextSHA := strings.Repeat("a", 64), strings.Repeat("b", 64)
	guardPath := "etc/systemd/system/acornfox-edge.service.d/10-upgrade-marker.conf"
	guard := []byte("[Unit]\nConditionPathExists=!/var/lib/acornfox/upgrade-in-progress\n")
	j := acornFoxUpgradeJournal{Old: acornFoxUpgradeImage{Repo: AcornFoxRepoJournalV1{BindingSHA256: oldSHA}, Runtime: acornFoxRuntimeIntent{Files: []acornFoxRuntimeFileWire{{Path: acornfoxsetup.EdgeConfiguration, Mode: 0644, Data: legacy}}}, Substrate: InactiveSubstrateReceiptV1{Entries: []SubstrateEntry{{Path: guardPath, SHA256: sha256Hex(guard)}}}}, Next: acornFoxUpgradeImage{Repo: AcornFoxRepoJournalV1{BindingSHA256: nextSHA}, Runtime: acornFoxRuntimeIntent{Files: []acornFoxRuntimeFileWire{{Path: acornfoxsetup.EdgeConfiguration, Mode: 0644, Data: bounded}}}}}
	write := func(path string, data []byte, mode os.FileMode) {
		t.Helper()
		path = filepath.Join(host, strings.TrimPrefix(path, "/"))
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, mode); err != nil {
			t.Fatal(err)
		}
	}
	write(guardPath, guard, 0644)
	write(acornfoxsetup.EdgeConfiguration, legacy, 0644)
	if _, err := u.edgeLegacyStopAuthority(store, j); err == nil {
		t.Fatal("QUIT admitted without marker")
	}
	write(acornFoxUpgradeMarkerPath, []byte(oldSHA+"\n"+nextSHA+"\n"), 0600)
	if old, err := u.edgeLegacyStopAuthority(store, j); err != nil || !old {
		t.Fatal("bound legacy rejected", err)
	}
	write(acornfoxsetup.EdgeConfiguration, bounded, 0644)
	if old, err := u.edgeLegacyStopAuthority(store, j); err != nil || old {
		t.Fatal("bounded config requested legacy QUIT", err)
	}
	write(acornfoxsetup.EdgeConfiguration, []byte(`{"apps":{"http":{}}}`), 0644)
	if _, err := u.edgeLegacyStopAuthority(store, j); err == nil {
		t.Fatal("unbound config admitted")
	}
	write(acornfoxsetup.EdgeConfiguration, legacy, 0644)
	write(guardPath, []byte("[Unit]\n"), 0644)
	if _, err := u.edgeLegacyStopAuthority(store, j); err == nil {
		t.Fatal("changed restart guard admitted")
	}
}
