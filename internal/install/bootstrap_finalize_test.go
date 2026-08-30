package install

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"strings"
	"testing"
)

type bootstrapFinalizeRemoveUnknownOps struct {
	durableOps
	target  string
	removed bool
	failed  bool
}

func (o *bootstrapFinalizeRemoveUnknownOps) Remove(name string) error {
	err := o.durableOps.Remove(name)
	if err == nil && name == o.target {
		o.removed = true
	}
	return err
}

func (o *bootstrapFinalizeRemoveUnknownOps) Sync(file *os.File) error {
	if o.removed && !o.failed {
		o.failed = true
		return errors.New("injected post-unlink sync failure")
	}
	return o.durableOps.Sync(file)
}

func committedBootstrapStore(t *testing.T) (*BootstrapStore, BootstrapRequest, string, func()) {
	t.Helper()
	store, activationWritten, activation, activeEnv, root, cleanup := bootstrapRC2Store(t)
	activeURL, err := url.Parse(mustDatabaseURL(t, activeEnv))
	if err != nil {
		cleanup()
		t.Fatal(err)
	}
	_, ok := activeURL.User.Password()
	if !ok {
		cleanup()
		t.Fatal("fixture database password is missing")
	}
	activeURL.User = url.UserPassword("opencard", strings.Repeat("S", 43))
	activeEnv, err = FormatDatabaseEnv(activeURL.String())
	if err != nil {
		cleanup()
		t.Fatal(err)
	}
	activation.DatabaseEnvSHA256 = sha256Bytes(activeEnv)
	activationWritten.ActivationJSONSHA256, err = CanonicalActivationJSONSHA256(activation)
	if err != nil {
		cleanup()
		t.Fatal(err)
	}
	persistBootstrapActivationWritten(t, store, activationWritten, activation, activeEnv)
	pointer, err := store.PublishInitialPointers(context.Background(), activationWritten, activation)
	if err != nil {
		cleanup()
		t.Fatal(err)
	}
	full := bootstrapJournalAt(t, BootstrapCommitted)
	full.TransactionID, full.MarkerTransactionID = activationWritten.TransactionID, activationWritten.TransactionID
	full.InstallationIDSHA256, full.Release = activationWritten.InstallationIDSHA256, activationWritten.Release
	full.CandidateActivationID, full.CandidateDatabaseName = activationWritten.CandidateActivationID, activationWritten.CandidateDatabaseName
	full.CandidateDatabaseSchemaSHA256, full.ActivationJSONSHA256, full.PointerStateSHA256 = activationWritten.CandidateDatabaseSchemaSHA256, activationWritten.ActivationJSONSHA256, pointer
	for revision := int64(5); revision <= full.Revision; revision++ {
		next := bootstrapJournalRevision(t, full, revision)
		if err := store.Save(context.Background(), next); err != nil {
			cleanup()
			t.Fatal(err)
		}
	}
	if err := store.Marker(context.Background(), false); err != nil {
		cleanup()
		t.Fatal(err)
	}
	parsed, err := url.Parse(mustDatabaseURL(t, activeEnv))
	if err != nil {
		cleanup()
		t.Fatal(err)
	}
	parsed.Path, parsed.RawPath = "/postgres", ""
	bootstrapEnv, err := FormatDatabaseEnv(parsed.String())
	if err != nil {
		cleanup()
		t.Fatal(err)
	}
	if err := store.upgrade.configDurable.CreateMetadata(bootstrapRuntimeDatabaseEnvName, bootstrapEnv); err != nil {
		cleanup()
		t.Fatal(err)
	}
	request := BootstrapRequest{TransactionID: full.TransactionID, InstallationIDSHA256: full.InstallationIDSHA256, CandidateActivationID: full.CandidateActivationID, Release: full.Release}
	return store, request, root, cleanup
}

func mustDatabaseURL(t *testing.T, raw []byte) string {
	t.Helper()
	value, err := ParseDatabaseEnv(raw)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func TestBootstrapEnvironmentFinalizationRequiresCommittedExactBindingAndReplays(t *testing.T) {
	store, request, root, cleanup := committedBootstrapStore(t)
	defer cleanup()
	if _, err := store.verifyCommittedLocked(context.Background(), request, false); err != nil {
		journal, loadErr := store.Load(context.Background(), request.TransactionID)
		state, stateErr := store.ReadInitialPointerState(context.Background(), request.CandidateActivationID)
		t.Fatalf("committed verification failed: %v journal=%+v load=%v state=%+v stateErr=%v request=%+v", err, journal, loadErr, state, stateErr, request)
	}
	receipt, err := store.finalizeEnvironmentLocked(context.Background(), request)
	if err != nil || receipt.Validate() != nil || !receipt.BootstrapEnvWasPresent || !validSHA(receipt.BootstrapEnvSHA256) {
		t.Fatalf("receipt=%+v err=%v", receipt, err)
	}
	if _, err := os.Lstat(root + "/etc/open-card/" + bootstrapRuntimeDatabaseEnvName); !os.IsNotExist(err) {
		t.Fatalf("bootstrap env remained: %v", err)
	}
	replay, err := store.finalizeEnvironmentLocked(context.Background(), request)
	if err != nil || replay.Validate() != nil || replay.BootstrapEnvWasPresent || replay.BootstrapEnvSHA256 != "" {
		t.Fatalf("replay=%+v err=%v", replay, err)
	}
}

func TestBootstrapEnvironmentFinalizationRejectsStatePointerAndEnvironmentDrift(t *testing.T) {
	for name, mutate := range map[string]func(*testing.T, *BootstrapStore, *BootstrapRequest, string){
		"request": func(_ *testing.T, _ *BootstrapStore, request *BootstrapRequest, _ string) {
			request.InstallationIDSHA256 = strings.Repeat("f", 64)
		},
		"marker": func(t *testing.T, store *BootstrapStore, request *BootstrapRequest, _ string) {
			t.Helper()
			if err := store.EnsureMarker(context.Background(), request.TransactionID); err != nil {
				t.Fatal(err)
			}
		},
		"environment": func(t *testing.T, _ *BootstrapStore, _ *BootstrapRequest, root string) {
			t.Helper()
			path := root + "/etc/open-card/" + bootstrapRuntimeDatabaseEnvName
			raw, err := FormatDatabaseEnv("postgresql://user:other@127.0.0.1:5432/postgres?sslmode=disable")
			if err != nil || os.WriteFile(path, raw, 0o600) != nil {
				t.Fatal("could not drift environment")
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			store, request, root, cleanup := committedBootstrapStore(t)
			defer cleanup()
			mutate(t, store, &request, root)
			if _, err := store.finalizeEnvironmentLocked(context.Background(), request); !errors.Is(err, ErrBootstrapFinalization) {
				t.Fatalf("drift accepted: %v", err)
			}
			if _, err := os.Lstat(root + "/etc/open-card/" + bootstrapRuntimeDatabaseEnvName); err != nil {
				t.Fatalf("drift removed bootstrap env: %v", err)
			}
		})
	}
}

func TestBootstrapFinalizationReceiptIsSecretFree(t *testing.T) {
	store, request, root, cleanup := committedBootstrapStore(t)
	defer cleanup()
	receipt, err := store.finalizeEnvironmentLocked(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(receipt)
	if strings.Contains(string(raw), "postgresql://") || strings.Contains(string(raw), "password") || strings.Contains(string(raw), root) {
		t.Fatalf("receipt leaked: %s", raw)
	}
}

func TestBootstrapEnvironmentFinalizationReconcilesPostUnlinkUnknown(t *testing.T) {
	store, request, root, cleanup := committedBootstrapStore(t)
	defer cleanup()
	original := store.upgrade.configDurable.ops
	store.upgrade.configDurable.ops = &bootstrapFinalizeRemoveUnknownOps{durableOps: original, target: bootstrapRuntimeDatabaseEnvName}
	receipt, err := store.finalizeEnvironmentLocked(context.Background(), request)
	if err != nil || !receipt.BootstrapEnvWasPresent || !validSHA(receipt.BootstrapEnvSHA256) {
		t.Fatalf("receipt=%+v err=%v", receipt, err)
	}
	if _, err := os.Lstat(root + "/etc/open-card/" + bootstrapRuntimeDatabaseEnvName); !os.IsNotExist(err) {
		t.Fatalf("post-unlink unknown left env: %v", err)
	}
	replay, err := store.finalizeEnvironmentLocked(context.Background(), request)
	if err != nil || replay.BootstrapEnvWasPresent {
		t.Fatalf("replay=%+v err=%v", replay, err)
	}
}
