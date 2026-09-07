package install

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func acornFoxUpgradeAssistantFixture(t *testing.T) (acornFoxProductionPreparedFixture, *TaskAcornFoxRepoStore, acornFoxUpgradeJournal, []byte, os.FileInfo) {
	t.Helper()
	f := newAcornFoxProductionPreparedFixture(t)
	lock, err := f.store.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lock.Release() })
	root := f.store.hostRoot
	principal, ok := f.layout.owner(AcornFoxLiveRootRole)
	if !ok || acornFoxAssistantPrepareDirectory(root, f.store, principal) != nil {
		t.Fatal("assistant directory unavailable")
	}
	key := []byte("sk-upgrade-0039-0123456789abcdefghijkl")
	if acornFoxAssistantStage(root, f.store, acornFoxAssistantConfig, acornFoxAssistantLegacy0039Config(), principal) != nil || acornFoxAssistantStage(root, f.store, acornFoxAssistantKey, key, principal) != nil {
		t.Fatal("assistant state unavailable")
	}
	keyInfo, err := os.Lstat(filepath.Join(f.host, acornFoxAssistantKey))
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := captureAcornFoxUpgradeAssistantConfig(f.store)
	if err != nil || evidence == nil || evidence.validate() != nil {
		t.Fatalf("evidence=%#v err=%v", evidence, err)
	}
	journal := acornFoxUpgradeJournal{CrossSchema: &acornFoxCrossSchemaUpgradeV1{Assistant: evidence}}
	return f, f.store, journal, bytes.Clone(key), keyInfo
}

func TestAcornFoxUpgradeAssistantConfigSwitchAndRollbackPreserveKey(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "disabled", true: "enabled"}[enabled], func(t *testing.T) {
			f, store, journal, key, keyInfo := acornFoxUpgradeAssistantFixture(t)
			journal.PIEnabled = enabled
			principal, _ := f.layout.owner(AcornFoxLiveRootRole)
			if enabled && acornFoxAssistantStage(store.hostRoot, store, acornFoxAssistantConfigNew, acornFoxAssistantCanonicalConfig(), principal) != nil {
				t.Fatal("forward crash prefix unavailable")
			}
			if err := applyAcornFoxUpgradeAssistantConfig(store, journal, true); err != nil || verifyAcornFoxUpgradeAssistantConfig(store, journal, true) != nil {
				t.Fatalf("forward err=%v", err)
			}
			if _, err := os.Lstat(filepath.Join(f.host, acornFoxAssistantConfigNew)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("forward left temp: %v", err)
			}
			assertAcornFoxUpgradeAssistantKeyUnchanged(t, f, key, keyInfo)
			if err := applyAcornFoxUpgradeAssistantConfig(store, journal, true); err != nil {
				t.Fatalf("forward replay err=%v", err)
			}
			if enabled && acornFoxAssistantStage(store.hostRoot, store, acornFoxAssistantConfigNew, acornFoxAssistantLegacy0039Config(), principal) != nil {
				t.Fatal("rollback crash prefix unavailable")
			}
			if err := applyAcornFoxUpgradeAssistantConfig(store, journal, false); err != nil || verifyAcornFoxUpgradeAssistantConfig(store, journal, false) != nil {
				t.Fatalf("rollback err=%v", err)
			}
			assertAcornFoxUpgradeAssistantKeyUnchanged(t, f, key, keyInfo)
		})
	}
}

func assertAcornFoxUpgradeAssistantKeyUnchanged(t *testing.T, f acornFoxProductionPreparedFixture, want []byte, before os.FileInfo) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(f.host, acornFoxAssistantKey))
	after, statErr := os.Lstat(filepath.Join(f.host, acornFoxAssistantKey))
	if err != nil || statErr != nil || !bytes.Equal(raw, want) || !os.SameFile(before, after) {
		t.Fatalf("key changed err=%v stat=%v", err, statErr)
	}
}

func TestAcornFoxUpgradeAssistantConfigRejectsKeyOrConfigDrift(t *testing.T) {
	t.Run("key-digest", func(t *testing.T) {
		f, store, journal, _, _ := acornFoxUpgradeAssistantFixture(t)
		journal.CrossSchema.Assistant.KeySHA256 = strings.Repeat("f", 64)
		if err := applyAcornFoxUpgradeAssistantConfig(store, journal, true); !errors.Is(err, ErrAcornFoxUpgradeConflict) {
			t.Fatalf("err=%v", err)
		}
		raw, _ := os.ReadFile(filepath.Join(f.host, acornFoxAssistantConfig))
		if !bytes.Equal(raw, acornFoxAssistantLegacy0039Config()) {
			t.Fatal("key mismatch changed config")
		}
	})
	t.Run("foreign-config", func(t *testing.T) {
		f, store, journal, _, _ := acornFoxUpgradeAssistantFixture(t)
		if err := os.WriteFile(filepath.Join(f.host, acornFoxAssistantConfig), []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := applyAcornFoxUpgradeAssistantConfig(store, journal, true); !errors.Is(err, ErrAcornFoxUpgradeConflict) {
			t.Fatalf("err=%v", err)
		}
	})
}

func TestAcornFoxUpgradeAssistantConfigAbsenceIsExplicit(t *testing.T) {
	f := newAcornFoxProductionPreparedFixture(t)
	lock, err := f.store.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Release()
	evidence, err := captureAcornFoxUpgradeAssistantConfig(f.store)
	if err != nil || evidence != nil {
		t.Fatalf("evidence=%#v err=%v", evidence, err)
	}
}
