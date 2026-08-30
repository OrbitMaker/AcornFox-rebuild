package install

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

type bootstrapOwnerMismatchOps struct {
	durableOps
	target string
}

func (o *bootstrapOwnerMismatchOps) Lstat(name string) (os.FileInfo, error) {
	info, err := o.durableOps.Lstat(name)
	if err != nil || name != o.target {
		return info, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, ErrBootstrapConflict
	}
	copyStat := *stat
	copyStat.Uid++
	return ownerMismatchFileInfo{FileInfo: info, stat: copyStat}, nil
}

func bootstrapCLIInput(t *testing.T) (ReleaseV1, string, string, string) {
	t.Helper()
	release, activeRoot := bootstrapRC2Release(t)
	dataRoot := filepath.Join(t.TempDir(), "open-card-data")
	if err := os.MkdirAll(dataRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	writer, err := TaskDurableWriter(dataRoot, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	id := strings.Repeat("a", 48)
	if err := writer.WriteMetadata(productionInstallationIDName, []byte(id+"\n")); err != nil {
		t.Fatal(err)
	}
	return release, activeRoot, dataRoot, id
}

func TestDeriveBootstrapRequestForTaskBindsFixedReleaseAndInstallationIdentity(t *testing.T) {
	release, activeRoot, dataRoot, id := bootstrapCLIInput(t)
	first, err := deriveProductionBootstrapRequestForTask(activeRoot, dataRoot, os.Getuid(), os.Getgid(), release.ManifestSHA256, "BOOTSTRAP:"+id)
	if err != nil || first.Validate() != nil || first.Release != release {
		t.Fatalf("derive bootstrap request: %#v %v", first, err)
	}
	second, err := deriveProductionBootstrapRequestForTask(activeRoot, dataRoot, os.Getuid(), os.Getgid(), release.ManifestSHA256, "BOOTSTRAP:"+id)
	if err != nil || first != second || !strings.HasPrefix(first.TransactionID, "bootstrap-") || !strings.HasPrefix(first.CandidateActivationID, "activation-") || first.TransactionID == first.CandidateActivationID || strings.TrimPrefix(first.TransactionID, "bootstrap-") == strings.TrimPrefix(first.CandidateActivationID, "activation-") {
		t.Fatalf("bootstrap derivation is not deterministic and domain-separated: %#v %v", second, err)
	}
	raw, _ := json.Marshal(first)
	if strings.Contains(string(raw), id) || strings.Contains(first.InstallationIDSHA256, id) {
		t.Fatal("bootstrap request exposed raw installation identity")
	}
}

func TestDeriveBootstrapRequestRejectsInstallationFileAndOwnerDrift(t *testing.T) {
	release, activeRoot, dataRoot, id := bootstrapCLIInput(t)
	installationPath := filepath.Join(dataRoot, productionInstallationIDName)
	if err := os.Chmod(installationPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := deriveProductionBootstrapRequestForTask(activeRoot, dataRoot, os.Getuid(), os.Getgid(), release.ManifestSHA256, "BOOTSTRAP:"+id); err == nil {
		t.Fatal("non-0600 installation identity accepted")
	}
	if _, err := deriveProductionBootstrapRequestForTask(activeRoot, dataRoot, os.Getuid()+1, os.Getgid(), release.ManifestSHA256, "BOOTSTRAP:"+id); err == nil {
		t.Fatal("foreign owner accepted")
	}
	release, activeRoot, dataRoot, id = bootstrapCLIInput(t)
	installationPath = filepath.Join(dataRoot, productionInstallationIDName)
	if err := os.Rename(installationPath, installationPath+".real"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(productionInstallationIDName+".real", installationPath); err != nil {
		t.Fatal(err)
	}
	if _, err := deriveProductionBootstrapRequestForTask(activeRoot, dataRoot, os.Getuid(), os.Getgid(), release.ManifestSHA256, "BOOTSTRAP:"+id); err == nil {
		t.Fatal("symlink installation identity accepted")
	}
}

func TestDeriveBootstrapRequestRejectsMalformedInstallationIdentityWithoutLeak(t *testing.T) {
	for name, raw := range map[string][]byte{
		"uppercase":  []byte(strings.Repeat("A", 48) + "\n"),
		"short":      []byte(strings.Repeat("a", 47) + "\n"),
		"no-newline": []byte(strings.Repeat("a", 48)),
		"extra-line": []byte(strings.Repeat("a", 48) + "\nextra\n"),
	} {
		t.Run(name, func(t *testing.T) {
			release, activeRoot, dataRoot, id := bootstrapCLIInput(t)
			if err := os.WriteFile(filepath.Join(dataRoot, productionInstallationIDName), raw, 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := deriveProductionBootstrapRequestForTask(activeRoot, dataRoot, os.Getuid(), os.Getgid(), release.ManifestSHA256, "BOOTSTRAP:"+id)
			if err == nil || strings.Contains(err.Error(), id) || strings.Contains(err.Error(), string(raw)) {
				t.Fatalf("malformed identity accepted or leaked: %v", err)
			}
		})
	}
}

func TestSelectBootstrapReleaseRejectsAmbiguousUnsafeAndForeignEntries(t *testing.T) {
	for name, arrange := range map[string]func(*testing.T, string, ReleaseV1){
		"same-manifest-other-entry": func(t *testing.T, activeRoot string, release ReleaseV1) {
			t.Helper()
			source := filepath.Join(activeRoot, "releases", release.ID)
			target := filepath.Join(activeRoot, "releases", "duplicate-release")
			if err := os.CopyFS(target, os.DirFS(source)); err != nil {
				t.Fatal(err)
			}
		},
		"unrelated-symlink": func(t *testing.T, activeRoot string, release ReleaseV1) {
			t.Helper()
			if err := os.Symlink(release.ID, filepath.Join(activeRoot, "releases", "unrelated-link")); err != nil {
				t.Fatal(err)
			}
		},
		"unrelated-file": func(t *testing.T, activeRoot string, _ ReleaseV1) {
			t.Helper()
			if err := os.WriteFile(filepath.Join(activeRoot, "releases", "unrelated-file"), []byte("x\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			release, activeRoot := bootstrapRC2Release(t)
			arrange(t, activeRoot, release)
			writer, err := TaskDurableWriter(activeRoot, os.Getuid(), os.Getgid())
			if err != nil {
				t.Fatal(err)
			}
			defer writer.Close()
			if _, err := selectBootstrapRC2Release(writer, release.ManifestSHA256); err == nil {
				t.Fatalf("%s entry accepted", name)
			}
		})
	}
	release, activeRoot := bootstrapRC2Release(t)
	writer, err := TaskDurableWriter(activeRoot, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	original := writer.ops
	writer.ops = &bootstrapOwnerMismatchOps{durableOps: original, target: filepath.ToSlash(filepath.Join("releases", release.ID))}
	if _, err := selectBootstrapRC2Release(writer, release.ManifestSHA256); err == nil {
		t.Fatal("foreign-owned release entry accepted")
	}
}

func TestDeriveBootstrapRequestRejectsRC2ManifestAndPayloadDrift(t *testing.T) {
	for name, mutate := range map[string]func(*testing.T, string, ReleaseV1) string{
		"payload": func(t *testing.T, activeRoot string, release ReleaseV1) string {
			t.Helper()
			path := filepath.Join(activeRoot, "releases", release.ID, "bin/open-card-admin")
			if err := os.WriteFile(path, []byte("tampered\n"), 0o755); err != nil {
				t.Fatal(err)
			}
			return release.ManifestSHA256
		},
		"rc1": func(t *testing.T, activeRoot string, release ReleaseV1) string {
			t.Helper()
			manifestPath := filepath.Join(activeRoot, "releases", release.ID, "manifest.json")
			manifest, err := LoadManifest(manifestPath)
			if err != nil {
				t.Fatal(err)
			}
			manifest.Version = ProductionCandidateVersion
			raw, _ := json.Marshal(manifest)
			if err := os.WriteFile(manifestPath, raw, 0o644); err != nil {
				t.Fatal(err)
			}
			digest, _ := SHA256File(manifestPath)
			return digest
		},
		"architecture": func(t *testing.T, activeRoot string, release ReleaseV1) string {
			t.Helper()
			manifestPath := filepath.Join(activeRoot, "releases", release.ID, "manifest.json")
			manifest, err := LoadManifest(manifestPath)
			if err != nil {
				t.Fatal(err)
			}
			if manifest.Architecture == "amd64" {
				manifest.Architecture = "arm64"
			} else {
				manifest.Architecture = "amd64"
			}
			raw, _ := json.Marshal(manifest)
			if err := os.WriteFile(manifestPath, raw, 0o644); err != nil {
				t.Fatal(err)
			}
			digest, _ := SHA256File(manifestPath)
			return digest
		},
	} {
		t.Run(name, func(t *testing.T) {
			release, activeRoot, dataRoot, id := bootstrapCLIInput(t)
			expected := mutate(t, activeRoot, release)
			if _, err := deriveProductionBootstrapRequestForTask(activeRoot, dataRoot, os.Getuid(), os.Getgid(), expected, "BOOTSTRAP:"+id); err == nil || strings.Contains(err.Error(), id) {
				t.Fatalf("%s drift accepted or leaked identity: %v", name, err)
			}
		})
	}
}

func TestDeriveBootstrapRequestForTaskRejectsReleaseAndConfirmationDrift(t *testing.T) {
	release, activeRoot, dataRoot, id := bootstrapCLIInput(t)
	for _, input := range []struct{ hash, confirmation string }{
		{"", "BOOTSTRAP:" + id}, {release.ManifestSHA256, "BOOTSTRAP:" + id + " "}, {strings.Repeat("0", 64), "BOOTSTRAP:" + id},
	} {
		if _, err := deriveProductionBootstrapRequestForTask(activeRoot, dataRoot, os.Getuid(), os.Getgid(), input.hash, input.confirmation); err == nil {
			t.Fatal("bootstrap accepted invalid confirmation or manifest identity")
		}
	}
	if err := os.Symlink("manifest.json", filepath.Join(activeRoot, "releases", release.ID, "manifest-copy.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := deriveProductionBootstrapRequestForTask(activeRoot, dataRoot, os.Getuid(), os.Getgid(), release.ManifestSHA256, "BOOTSTRAP:"+id); err == nil {
		t.Fatal("bootstrap accepted release tree symlink")
	}
}
