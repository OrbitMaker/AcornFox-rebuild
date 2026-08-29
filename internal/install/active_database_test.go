package install

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func activeDatabaseFixture(t *testing.T) (*ActiveDatabaseResolver, string, string) {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	activationID, releaseID := "activation-1", "release-1"
	for _, directory := range []string{"activations", "releases", filepath.Join("activations", activationID), filepath.Join("releases", releaseID)} {
		if err := os.Mkdir(filepath.Join(root, directory), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	dsn := "postgresql://admin:secret@127.0.0.1:5432/open_card?sslmode=disable"
	databaseEnv, err := FormatDatabaseEnv(dsn)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(databaseEnv)
	activation := ActivationV1{
		SchemaVersion:          ActivationSchemaVersion,
		ActivationID:           activationID,
		Origin:                 "install",
		Release:                ReleaseV1{ID: releaseID, Version: "0.8.0-rc.1", SourceCommit: strings.Repeat("a", 40), Architecture: "arm64", ManifestSHA256: sha("b")},
		Database:               DatabaseV1{Name: "open_card", Migration: "0024", SchemaMigrationsSHA256: sha("c")},
		DatabaseEnvSHA256:      hex.EncodeToString(sum[:]),
		CreatedAt:              time.Unix(1, 0).UTC(),
		CreatedByTransactionID: "txn-1",
	}
	activationRaw, err := MarshalActivationV1(activation)
	if err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(root, "activations", activationID)
	if err := os.WriteFile(filepath.Join(base, "activation.json"), activationRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "database.env"), databaseEnv, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../../releases/"+releaseID, filepath.Join(base, "release")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("activations/"+activationID, filepath.Join(root, "active")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("active/release", filepath.Join(root, "current")); err != nil {
		t.Fatal(err)
	}
	resolver, err := TaskActiveDatabaseResolver(root, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	return resolver, root, dsn
}

func TestActiveDatabaseResolverReturnsOnlyCoherentActiveIdentity(t *testing.T) {
	resolver, _, dsn := activeDatabaseFixture(t)
	resolved, err := resolver.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	if resolved.Activation.ActivationID != "activation-1" || resolved.Activation.Release.ID != "release-1" || resolved.DatabaseURL != dsn {
		t.Fatalf("resolved unexpected active identity: %+v", resolved.Activation)
	}
	if _, err := resolver.ResolveActivation("activation-1"); err != nil {
		t.Fatal(err)
	}
}

func TestActiveDatabaseResolverFailsClosedForPointersAndMetadata(t *testing.T) {
	for _, mutation := range []string{"active", "current", "release", "database-digest", "database-mode", "activation-mode", "activation-corrupt"} {
		t.Run(mutation, func(t *testing.T) {
			resolver, root, _ := activeDatabaseFixture(t)
			base := filepath.Join(root, "activations", "activation-1")
			switch mutation {
			case "active":
				if err := os.Remove(filepath.Join(root, "active")); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("../outside", filepath.Join(root, "active")); err != nil {
					t.Fatal(err)
				}
			case "current":
				if err := os.Remove(filepath.Join(root, "current")); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("releases/release-1", filepath.Join(root, "current")); err != nil {
					t.Fatal(err)
				}
			case "release":
				if err := os.Remove(filepath.Join(base, "release")); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("../../releases/other", filepath.Join(base, "release")); err != nil {
					t.Fatal(err)
				}
			case "database-digest":
				if err := os.WriteFile(filepath.Join(base, "database.env"), []byte("OPEN_CARD_DATABASE_URL=postgresql://admin:other@127.0.0.1:5432/open_card?sslmode=disable\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "database-mode":
				if err := os.Chmod(filepath.Join(base, "database.env"), 0o640); err != nil {
					t.Fatal(err)
				}
			case "activation-mode":
				if err := os.Chmod(filepath.Join(base, "activation.json"), 0o644); err != nil {
					t.Fatal(err)
				}
			case "activation-corrupt":
				if err := os.WriteFile(filepath.Join(base, "activation.json"), []byte(`{"schema_version":1}`), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := resolver.Resolve(); err == nil {
				t.Fatal("unsafe active identity was accepted")
			}
		})
	}
}

func TestActiveDatabaseResolverRejectsRootOwnerMismatch(t *testing.T) {
	_, root, _ := activeDatabaseFixture(t)
	if _, err := TaskActiveDatabaseResolver(root, os.Getuid()+1, os.Getgid()); err == nil {
		t.Fatal("resolver accepted an unexpected root owner")
	}
}
