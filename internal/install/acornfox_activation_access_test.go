package install

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestAcornFoxActivationIsTraversableWhileMetadataStaysPrivate(t *testing.T) {
	s, f := newAcornFoxControlPlanePrepared(t, &acornFoxControlPlaneLedgerFake{}, &acornFoxControlPlaneProvisionerFake{})
	if _, err := s.migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	id, err := AcornFoxRepoActivationID(f.binding)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"opt/acornfox/activations", "opt/acornfox/activations/" + id} {
		info, err := os.Stat(filepath.Join(f.host, path))
		if err != nil || info.Mode().Perm() != 0o711 {
			t.Fatalf("activation traversal mode: %s %v", path, err)
		}
	}
	for _, name := range []string{"repo-activation.json", "database.env"} {
		info, err := os.Stat(filepath.Join(f.host, "opt/acornfox/activations", id, name))
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("private metadata mode: %s %v", name, err)
		}
	}
	if (acornFoxInstallLayout{mode: acornFoxInstallLayoutTask}).activationDirectoryMode() != 0o700 {
		t.Fatal("task-root model lost its private directory boundary")
	}
}

func TestAcornFoxActivationRecoversOnlyEmptyPrivateCreationPrefix(t *testing.T) {
	for _, which := range []string{"parent", "slot", "foreign"} {
		t.Run(which, func(t *testing.T) {
			f := newAcornFoxProductionPreparedFixture(t)
			id, _ := AcornFoxRepoActivationID(f.binding)
			parent := filepath.Join(f.host, "opt/acornfox/activations")
			path := parent
			if which != "parent" {
				if err := os.Mkdir(parent, 0o711); err != nil {
					t.Fatal(err)
				}
				info, _ := os.Lstat(parent)
				f.owners.set(info, acornFoxInstallPrincipal{})
				path = filepath.Join(parent, id)
			}
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
			info, _ := os.Lstat(path)
			f.owners.set(info, acornFoxInstallPrincipal{})
			if which == "foreign" {
				if err := os.WriteFile(filepath.Join(path, "foreign"), []byte("preserve"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			err := prepareAcornFoxRepository(context.Background(), f.store, f.published, f.binding)
			if which == "foreign" {
				if err == nil {
					t.Fatal("nonempty private directory adopted")
				}
				info, _ = os.Stat(path)
				if info.Mode().Perm() != 0o700 {
					t.Fatal("foreign directory mode changed")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			info, _ = os.Stat(path)
			if info.Mode().Perm() != 0o711 {
				t.Fatal("private prefix not completed")
			}
			if err := os.Chmod(path, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := prepareAcornFoxRepository(context.Background(), f.store, f.published, f.binding); err == nil {
				t.Fatal("active directory permission change was silently healed")
			}
		})
	}
}
