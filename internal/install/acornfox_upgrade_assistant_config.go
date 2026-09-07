package install

import (
	"errors"
	"os"
)

type acornFoxUpgradeAssistantConfig struct {
	SchemaVersion int    `json:"schema_version"`
	OldSHA256     string `json:"old_sha256"`
	NextSHA256    string `json:"next_sha256"`
	KeySHA256     string `json:"key_sha256"`
}

func (c acornFoxUpgradeAssistantConfig) validate() error {
	if c.SchemaVersion != 1 || c.OldSHA256 != sha256Bytes(acornFoxAssistantLegacy0039Config()) || c.NextSHA256 != sha256Bytes(acornFoxAssistantCanonicalConfig()) || c.OldSHA256 == c.NextSHA256 || !validSHA(c.KeySHA256) {
		return ErrAcornFoxUpgradeConflict
	}
	return nil
}

func captureAcornFoxUpgradeAssistantConfig(store *TaskAcornFoxRepoStore) (*acornFoxUpgradeAssistantConfig, error) {
	if store == nil || !store.ownsLock() || store.layout.validate() != nil {
		return nil, ErrAcornFoxUpgradeConflict
	}
	configured, err := acornFoxAssistantLegacy0039ConfigurationState(store.hostRoot, store)
	if err != nil {
		return nil, ErrAcornFoxUpgradeConflict
	}
	if !configured {
		return nil, nil
	}
	principal, ok := store.layout.owner(AcornFoxLiveRootRole)
	legacy := acornFoxAssistantLegacy0039Config()
	if !ok || !acornFoxLiveExactFileOwned(store.hostRoot, store, acornFoxAssistantConfig, legacy, 0600, principal, false) {
		return nil, ErrAcornFoxUpgradeConflict
	}
	key, err := acornFoxAssistantReadManagedKey(store.hostRoot, store, principal)
	if err != nil {
		return nil, ErrAcornFoxUpgradeConflict
	}
	defer clear(key)
	evidence := &acornFoxUpgradeAssistantConfig{SchemaVersion: 1, OldSHA256: sha256Bytes(legacy), NextSHA256: sha256Bytes(acornFoxAssistantCanonicalConfig()), KeySHA256: sha256Bytes(key)}
	return evidence, evidence.validate()
}

func applyAcornFoxUpgradeAssistantConfig(store *TaskAcornFoxRepoStore, journal acornFoxUpgradeJournal, next bool) error {
	if journal.CrossSchema == nil || journal.CrossSchema.Assistant == nil {
		return nil
	}
	evidence := journal.CrossSchema.Assistant
	if evidence.validate() != nil || store == nil || !store.ownsLock() {
		return ErrAcornFoxUpgradeConflict
	}
	principal, ok := store.layout.owner(AcornFoxLiveRootRole)
	if !ok {
		return ErrAcornFoxUpgradeConflict
	}
	key, err := acornFoxAssistantReadManagedKey(store.hostRoot, store, principal)
	if err != nil || sha256Bytes(key) != evidence.KeySHA256 {
		clear(key)
		return ErrAcornFoxUpgradeConflict
	}
	clear(key)
	want := acornFoxAssistantLegacy0039Config()
	other := acornFoxAssistantCanonicalConfig()
	if next {
		want, other = other, want
	}
	if _, statErr := store.hostRoot.Lstat(acornFoxAssistantConfigNew); statErr == nil {
		if !acornFoxLiveExactFileOwned(store.hostRoot, store, acornFoxAssistantConfigNew, want, 0600, principal, false) && !acornFoxLiveExactFileOwned(store.hostRoot, store, acornFoxAssistantConfigNew, other, 0600, principal, false) {
			return ErrAcornFoxUpgradeConflict
		}
		if store.hostRoot.Remove(acornFoxAssistantConfigNew) != nil || acornFoxLiveSyncDir(store.hostRoot, acornFoxAssistantDirectory) != nil {
			return ErrAcornFoxUpgradeUnknown
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return ErrAcornFoxUpgradeUnknown
	}
	if acornFoxLiveExactFileOwned(store.hostRoot, store, acornFoxAssistantConfig, want, 0600, principal, false) {
		if acornFoxLiveSyncDir(store.hostRoot, acornFoxAssistantDirectory) != nil {
			return ErrAcornFoxUpgradeUnknown
		}
		return nil
	}
	if !acornFoxLiveExactFileOwned(store.hostRoot, store, acornFoxAssistantConfig, other, 0600, principal, false) {
		return ErrAcornFoxUpgradeConflict
	}
	if err := acornFoxAssistantStage(store.hostRoot, store, acornFoxAssistantConfigNew, want, principal); err != nil {
		return err
	}
	if err := store.hostRoot.Rename(acornFoxAssistantConfigNew, acornFoxAssistantConfig); err != nil || acornFoxLiveSyncDir(store.hostRoot, acornFoxAssistantDirectory) != nil {
		return ErrAcornFoxUpgradeUnknown
	}
	if !acornFoxLiveExactFileOwned(store.hostRoot, store, acornFoxAssistantConfig, want, 0600, principal, false) {
		return ErrAcornFoxUpgradeUnknown
	}
	return nil
}

func verifyAcornFoxUpgradeAssistantConfig(store *TaskAcornFoxRepoStore, journal acornFoxUpgradeJournal, next bool) error {
	if journal.CrossSchema == nil || journal.CrossSchema.Assistant == nil {
		return nil
	}
	evidence := journal.CrossSchema.Assistant
	if evidence.validate() != nil || store == nil || !store.ownsLock() {
		return ErrAcornFoxUpgradeConflict
	}
	principal, ok := store.layout.owner(AcornFoxLiveRootRole)
	want := acornFoxAssistantLegacy0039Config()
	if next {
		want = acornFoxAssistantCanonicalConfig()
	}
	if !ok || !acornFoxLiveExactFileOwned(store.hostRoot, store, acornFoxAssistantConfig, want, 0600, principal, false) {
		return ErrAcornFoxUpgradeConflict
	}
	key, err := acornFoxAssistantReadManagedKey(store.hostRoot, store, principal)
	if err != nil || sha256Bytes(key) != evidence.KeySHA256 {
		clear(key)
		return ErrAcornFoxUpgradeConflict
	}
	clear(key)
	return nil
}
