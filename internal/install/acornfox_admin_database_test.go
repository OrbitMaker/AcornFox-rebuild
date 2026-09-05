package install

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAcornFoxAdminDatabaseUsesBoundActiveIdentity(t *testing.T) {
	service, f := newAcornFoxControlPlanePrepared(t, &acornFoxControlPlaneLedgerFake{}, &acornFoxControlPlaneProvisionerFake{})
	if _, err := service.migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	store, err := newAcornFoxRepoStoreForLayout(f.layout)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	store.ownership = f.owners.edge()
	if _, err := store.Acquire(context.Background()); err != nil {
		t.Fatal(err)
	}
	identity := service.expectedIdentity
	resolve := func() (*AcornFoxAdminDatabase, error) {
		return resolveAcornFoxAdminDatabase(context.Background(), store, identity.Version, identity.SourceCommit)
	}
	database, err := resolve()
	if err != nil || database == nil {
		t.Fatalf("resolve: %v", err)
	}
	if database.MigrationRowsSHA256 == "" || database.adminSHA256 == "" || !strings.HasPrefix(database.DatabaseURL, "postgresql://acornfox:") {
		t.Fatal("incomplete private database identity")
	}
	encoded, _ := json.Marshal(database)
	if strings.Contains(string(encoded), "postgresql") {
		t.Fatal("DSN serialized")
	}
	if _, err := resolveAcornFoxAdminDatabase(context.Background(), store, identity.Version, strings.Repeat("0", 40)); err == nil {
		t.Fatal("foreign source accepted")
	}
	id, _ := AcornFoxRepoActivationID(f.binding)
	activationPath := filepath.Join(f.host, "opt/acornfox/activations", id, "repo-activation.json")
	activationRaw, err := os.ReadFile(activationPath)
	if err != nil {
		t.Fatal(err)
	}
	activation, err := ParseAcornFoxRepoActivationV1(activationRaw)
	if err != nil {
		t.Fatal(err)
	}
	activation.LiveTreeSHA256 = strings.Repeat("0", 64)
	altered, err := MarshalAcornFoxRepoActivationV1(activation)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, path string
		mode       os.FileMode
		content    []byte
	}{
		{"state env", filepath.Join(f.state, acornFoxControlPlaneStateEnv), 0o600, []byte("ACORNFOX_DATABASE_URL=postgresql://other\n")},
		{"receipt", filepath.Join(f.state, acornFoxControlPlaneReceipt), 0o600, []byte("{}")},
		{"activation", filepath.Join(f.host, "opt/acornfox/activations", id, "repo-activation.json"), 0o600, []byte("{}")},
		{"valid activation with foreign tree", activationPath, 0o600, altered},
	} {
		t.Run(tc.name, func(t *testing.T) {
			original, err := os.ReadFile(tc.path)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(tc.path, tc.content, tc.mode); err != nil {
				t.Fatal(err)
			}
			defer os.WriteFile(tc.path, original, tc.mode)
			if _, err := resolve(); err == nil {
				t.Fatal("altered identity accepted")
			}
		})
	}
	envPath := filepath.Join(f.host, "opt/acornfox/activations", id, "database.env")
	if err := os.Chmod(envPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := resolve(); err == nil {
		t.Fatal("public database secret accepted")
	}
	os.Chmod(envPath, 0o600)
	current := filepath.Join(f.host, "opt/acornfox/current")
	if err := os.Remove(current); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("releases/"+identity.ReleaseID, current); err != nil {
		t.Fatal(err)
	}
	if _, err := resolve(); err == nil {
		t.Fatal("unbound current pointer accepted")
	}
}
