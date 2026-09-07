package install

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestAcornFoxAssistantCanonicalToolsIncludeFixCandidateLane(t *testing.T) {
	var config acornFoxAssistantWorkerConfig
	if err := json.Unmarshal(acornFoxAssistantCanonicalConfig(), &config); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"acornfox_host_metrics", "acornfox_list_apps", "acornfox_app", "acornfox_sources", "acornfox_deliveries",
		"acornfox_delivery_status", "acornfox_logs", "acornfox_operation_result", "acornfox_public_access", "acornfox_access_observation", "acornfox_probe", "acornfox_propose_restart", "acornfox_propose_redeploy",
		"acornfox_read_fix_source", "acornfox_create_fix_candidate",
	}
	if !reflect.DeepEqual(config.EnabledTools, want) {
		t.Fatalf("enabled tools=%q", config.EnabledTools)
	}
	if config.HandshakeTimeoutSecond != 5 || config.RunTimeoutSecond != 300 || config.ShutdownTimeoutSecond != 10 {
		t.Fatalf("assistant timeouts=%d/%d/%d", config.HandshakeTimeoutSecond, config.RunTimeoutSecond, config.ShutdownTimeoutSecond)
	}
}

func TestAcornFoxAssistantLegacy0039ConfigRemainsClosedAndAccepted(t *testing.T) {
	var legacy acornFoxAssistantWorkerConfig
	if err := json.Unmarshal(acornFoxAssistantLegacy0039Config(), &legacy); err != nil || len(legacy.EnabledTools) != 13 || legacy.RunTimeoutSecond != 300 || legacy.ShutdownTimeoutSecond != 10 {
		t.Fatalf("legacy=%#v err=%v", legacy, err)
	}
	var current acornFoxAssistantWorkerConfig
	if err := json.Unmarshal(acornFoxAssistantCanonicalConfig(), &current); err != nil || reflect.DeepEqual(current.EnabledTools, legacy.EnabledTools) {
		t.Fatalf("current=%#v err=%v", current, err)
	}
	f := newAcornFoxProductionPreparedFixture(t)
	root, err := f.store.openHostRoot()
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	principal, ok := f.layout.owner(AcornFoxLiveRootRole)
	if !ok || acornFoxAssistantPrepareDirectory(root, f.store, principal) != nil {
		t.Fatal("assistant directory unavailable")
	}
	key := []byte("sk-legacy-0039-0123456789abcdefghijkl")
	if acornFoxAssistantStage(root, f.store, acornFoxAssistantConfig, acornFoxAssistantLegacy0039Config(), principal) != nil || acornFoxAssistantStage(root, f.store, acornFoxAssistantKey, key, principal) != nil {
		t.Fatal("legacy assistant config was not staged")
	}
	if _, err := acornFoxAssistantConfigScope(root, f.store); !errors.Is(err, ErrAcornFoxAssistantConfigConflict) {
		t.Fatalf("ordinary 0040 scope accepted legacy config: %v", err)
	}
	entries, err := acornFoxAssistantConfigScopeExpected(root, f.store, acornFoxAssistantLegacy0039Config())
	if err != nil || len(entries) != 3 || entries[1].SHA256 != sha256Hex(acornFoxAssistantLegacy0039Config()) {
		t.Fatalf("entries=%#v err=%v", entries, err)
	}
}

func TestAcornFoxConfigureAssistantExplicitlyUpgradesLegacy0039Config(t *testing.T) {
	f, configurator, _ := assistantConfigFixture(t)
	root, err := f.store.openHostRoot()
	if err != nil {
		t.Fatal(err)
	}
	principal, ok := f.layout.owner(AcornFoxLiveRootRole)
	if !ok || acornFoxAssistantPrepareDirectory(root, f.store, principal) != nil {
		t.Fatal("assistant directory unavailable")
	}
	oldKey := []byte("sk-legacy-reconfigure-0123456789abcdefgh")
	if acornFoxAssistantStage(root, f.store, acornFoxAssistantConfig, acornFoxAssistantLegacy0039Config(), principal) != nil || acornFoxAssistantStage(root, f.store, acornFoxAssistantKey, oldKey, principal) != nil {
		t.Fatal("legacy configuration unavailable")
	}
	if err := root.Close(); err != nil {
		t.Fatal(err)
	}
	if receipt, err := configurator.configure(context.Background(), "/root/deepseek-key"); err != nil || receipt.State != "ASSISTANT_ENABLED" {
		t.Fatalf("receipt=%#v err=%v", receipt, err)
	}
	raw, err := os.ReadFile(filepath.Join(f.host, acornFoxAssistantConfig))
	if err != nil || !bytes.Equal(raw, acornFoxAssistantCanonicalConfig()) {
		t.Fatalf("canonical config err=%v", err)
	}
}

func assistantConfigFixture(t *testing.T) (acornFoxProductionPreparedFixture, *acornFoxAssistantConfigurator, *[]string) {
	t.Helper()
	f := newAcornFoxProductionPreparedFixture(t)
	calls := []string{}
	record := func(name string) func(context.Context) error {
		return func(context.Context) error { calls = append(calls, name); return nil }
	}
	configurator := &acornFoxAssistantConfigurator{
		layout: f.layout, ownership: f.owners.edge(),
		readKey: func(path string) ([]byte, error) {
			if path != "/root/deepseek-key" {
				return nil, errors.New("unexpected path")
			}
			return []byte("sk-test-0123456789abcdefghijklmnop"), nil
		},
		services: acornFoxAssistantServices{
			stop: record("stop"), disable: record("disable"), enable: record("enable"), start: record("start"),
			verifyEnabled: record("verify-enabled"), verifyDisabled: record("verify-disabled"),
			restartServer: record("restart-server"), verifyServerEnabled: record("verify-server-enabled"), verifyServerDisabled: record("verify-server-disabled"),
		},
	}
	return f, configurator, &calls
}

func TestAcornFoxAssistantConfigureWritesOnlyCanonicalPrivateNamespace(t *testing.T) {
	f, configurator, calls := assistantConfigFixture(t)
	receipt, err := configurator.configure(context.Background(), "/root/deepseek-key")
	if err != nil || receipt.Validate() != nil || receipt.State != "ASSISTANT_ENABLED" {
		t.Fatalf("receipt=%#v err=%v", receipt, err)
	}
	if !reflect.DeepEqual(*calls, []string{"stop", "enable", "start", "verify-enabled", "restart-server", "verify-server-enabled"}) {
		t.Fatalf("service order=%q", *calls)
	}
	directory := filepath.Join(f.host, filepath.FromSlash(acornFoxAssistantDirectory))
	children, err := os.ReadDir(directory)
	if err != nil || len(children) != 2 || children[0].Name() != "deepseek-api-key" || children[1].Name() != "worker.json" {
		t.Fatalf("children=%v err=%v", children, err)
	}
	for _, name := range []string{"worker.json", "deepseek-api-key"} {
		info, err := os.Lstat(filepath.Join(directory, name))
		if err != nil || info.Mode().Perm() != 0600 || acornFoxRepoNlink(info) != 1 {
			t.Fatalf("%s info=%v err=%v", name, info, err)
		}
	}
	raw, err := os.ReadFile(filepath.Join(directory, "worker.json"))
	if err != nil || !bytes.Equal(raw, acornFoxAssistantCanonicalConfig()) {
		t.Fatal("worker config is not canonical")
	}
	key, _ := os.ReadFile(filepath.Join(directory, "deepseek-api-key"))
	for _, value := range []any{receipt, acornFoxAssistantWorkerConfig{}} {
		if strings.Contains(fmt.Sprintf("%+v", value), string(key)) {
			t.Fatal("fmt output leaked key")
		}
	}
	f.assertExternalSentinel(t)
}

func TestAcornFoxAssistantDisableKeepsConfiguration(t *testing.T) {
	f, configurator, calls := assistantConfigFixture(t)
	if _, err := configurator.configure(context.Background(), "/root/deepseek-key"); err != nil {
		t.Fatal(err)
	}
	*calls = nil
	receipt, err := configurator.disable(context.Background())
	if err != nil || receipt.Validate() != nil || receipt.State != "ASSISTANT_DISABLED" || !reflect.DeepEqual(*calls, []string{"stop", "disable", "verify-disabled", "restart-server", "verify-server-disabled"}) {
		t.Fatalf("receipt=%#v calls=%q err=%v", receipt, *calls, err)
	}
	root, err := f.store.openHostRoot()
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if configured, err := acornFoxAssistantConfigurationState(root, f.store); err != nil || !configured {
		t.Fatalf("configured=%t err=%v", configured, err)
	}
}

func TestAcornFoxAssistantServerRestartFailuresAreUnknown(t *testing.T) {
	t.Run("configure-restart", func(t *testing.T) {
		_, configurator, calls := assistantConfigFixture(t)
		configurator.services.restartServer = func(context.Context) error {
			*calls = append(*calls, "restart-server")
			return errors.New("private")
		}
		if _, err := configurator.configure(context.Background(), "/root/deepseek-key"); !errors.Is(err, ErrAcornFoxAssistantConfigUnknown) {
			t.Fatalf("err=%v", err)
		}
		want := []string{"stop", "enable", "start", "verify-enabled", "restart-server"}
		if !reflect.DeepEqual(*calls, want) {
			t.Fatalf("calls=%q want=%q", *calls, want)
		}
	})
	t.Run("disable-post-restart-verification", func(t *testing.T) {
		_, configurator, calls := assistantConfigFixture(t)
		if _, err := configurator.configure(context.Background(), "/root/deepseek-key"); err != nil {
			t.Fatal(err)
		}
		*calls = nil
		configurator.services.verifyServerDisabled = func(context.Context) error {
			*calls = append(*calls, "verify-server-disabled")
			return errors.New("private")
		}
		if _, err := configurator.disable(context.Background()); !errors.Is(err, ErrAcornFoxAssistantConfigUnknown) {
			t.Fatalf("err=%v", err)
		}
		want := []string{"stop", "disable", "verify-disabled", "restart-server", "verify-server-disabled"}
		if !reflect.DeepEqual(*calls, want) {
			t.Fatalf("calls=%q want=%q", *calls, want)
		}
	})
}

func TestAcornFoxAssistantSystemctlAllowlistIsExact(t *testing.T) {
	for _, allowed := range [][2]string{{"stop", acornFoxAssistantUnit}, {"disable", acornFoxAssistantUnit}, {"enable", acornFoxAssistantUnit}, {"start", acornFoxAssistantUnit}, {"restart", "acornfox-server.service"}} {
		if !acornFoxAssistantSystemctlAllowed(allowed[0], allowed[1]) {
			t.Fatalf("rejected %q", allowed)
		}
	}
	for _, rejected := range [][2]string{{"restart", acornFoxAssistantUnit}, {"start", "acornfox-server.service"}, {"restart", "acornfox-agent.service"}, {"reload", "acornfox-server.service"}, {"", ""}} {
		if acornFoxAssistantSystemctlAllowed(rejected[0], rejected[1]) {
			t.Fatalf("accepted %q", rejected)
		}
	}
}

func TestAcornFoxAssistantConfigureRecoversStoppedRenamePrefix(t *testing.T) {
	f, configurator, _ := assistantConfigFixture(t)
	root, err := f.store.openHostRoot()
	if err != nil {
		t.Fatal(err)
	}
	principal, _ := f.layout.owner(AcornFoxLiveRootRole)
	key := []byte("sk-test-0123456789abcdefghijklmnop")
	if err := acornFoxAssistantPrepareDirectory(root, f.store, principal); err != nil {
		t.Fatal(err)
	}
	if err := acornFoxAssistantStage(root, f.store, acornFoxAssistantKeyNew, key, principal); err != nil {
		t.Fatal(err)
	}
	if err := acornFoxAssistantStage(root, f.store, acornFoxAssistantConfigNew, acornFoxAssistantCanonicalConfig(), principal); err != nil {
		t.Fatal(err)
	}
	if err := root.Rename(acornFoxAssistantKeyNew, acornFoxAssistantKey); err != nil {
		t.Fatal(err)
	}
	if err := root.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := configurator.configure(context.Background(), "/root/deepseek-key"); err != nil {
		t.Fatalf("recover configure: %v", err)
	}
	directory := filepath.Join(f.host, filepath.FromSlash(acornFoxAssistantDirectory))
	children, err := os.ReadDir(directory)
	if err != nil || len(children) != 2 {
		t.Fatalf("children=%v err=%v", children, err)
	}
}

func TestAcornFoxAssistantScopeFailsClosedOnPartialExtraAndLinks(t *testing.T) {
	for _, scenario := range []string{"partial", "extra", "symlink", "hardlink"} {
		t.Run(scenario, func(t *testing.T) {
			f, configurator, _ := assistantConfigFixture(t)
			if _, err := configurator.configure(context.Background(), "/root/deepseek-key"); err != nil {
				t.Fatal(err)
			}
			directory := filepath.Join(f.host, filepath.FromSlash(acornFoxAssistantDirectory))
			switch scenario {
			case "partial":
				if err := os.Remove(filepath.Join(directory, "worker.json")); err != nil {
					t.Fatal(err)
				}
			case "extra":
				if err := os.WriteFile(filepath.Join(directory, "foreign"), []byte("x"), 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Remove(filepath.Join(directory, "worker.json")); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("deepseek-api-key", filepath.Join(directory, "worker.json")); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(filepath.Join(directory, "worker.json"), filepath.Join(directory, "foreign")); err != nil {
					t.Fatal(err)
				}
			}
			root, err := f.store.openHostRoot()
			if err != nil {
				t.Fatal(err)
			}
			_, scopeErr := acornFoxAssistantConfigScope(root, f.store)
			_ = root.Close()
			if !errors.Is(scopeErr, ErrAcornFoxAssistantConfigConflict) {
				t.Fatalf("scope error=%v", scopeErr)
			}
		})
	}
}

func TestAcornFoxAssistantRejectsInvalidKeyBeforeHostEffects(t *testing.T) {
	_, configurator, calls := assistantConfigFixture(t)
	for _, raw := range [][]byte{nil, []byte("short"), []byte("sk-valid-value-with-newline\n"), bytes.Repeat([]byte("x"), acornFoxAssistantMaxKey+1)} {
		configurator.readKey = func(string) ([]byte, error) { return append([]byte(nil), raw...), nil }
		if _, err := configurator.configure(context.Background(), "/root/deepseek-key"); !errors.Is(err, ErrAcornFoxAssistantConfigConflict) || len(*calls) != 0 {
			t.Fatalf("len=%d err=%v calls=%q", len(raw), err, *calls)
		}
	}
}

func TestAcornFoxAssistantHostScriptsProvisionAccountAndKeepWorkerOptional(t *testing.T) {
	for _, name := range []string{"install-host.sh", "host-preflight.sh"} {
		raw, err := os.ReadFile(filepath.Join("..", "..", "scripts", "acornfox", name))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(raw, []byte("acornfox-pi")) {
			t.Fatalf("%s does not require the PI account", name)
		}
		if !bytes.Contains(raw, []byte(`service_uids != *" $uid "*`)) {
			t.Fatalf("%s does not reject a PI alias with a shared service UID", name)
		}
	}
	raw, err := os.ReadFile(filepath.Join("..", "..", "scripts", "acornfox", "install-host.sh"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, required := range []string{"systemctl disable --now acornfox-pi-worker.service", "systemctl is-enabled --quiet acornfox-pi-worker.service", "systemctl is-active --quiet acornfox-pi-worker.service", "! -e /run/acornfox-pi/worker.sock"} {
		if !strings.Contains(text, required) {
			t.Fatalf("install-host is missing %q", required)
		}
	}
	if strings.Contains(text, "enable acornfox-pi-worker.service") || strings.Contains(text, "start acornfox-pi-worker.service") {
		t.Fatal("fresh host install starts the optional worker")
	}
}
