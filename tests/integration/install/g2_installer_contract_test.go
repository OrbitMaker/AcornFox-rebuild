package install_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/open-card/open-card/internal/install"
)

func writeG2CandidateBundle(t *testing.T, directory string, includeEdge bool) string {
	t.Helper()
	bundle := filepath.Join(directory, "candidate")
	files := []struct {
		path string
		mode os.FileMode
	}{
		{"bin/open-card-server", 0o755}, {"bin/open-card-agent", 0o755}, {"bin/open-card-buildkit", 0o755}, {"bin/open-card-caddy", 0o755}, {"bin/open-card-admin", 0o755},
		{"caddy/open-card-edge.Caddyfile.example", 0o644}, {"caddy/open-card-edge.env.example", 0o640}, {"migrations/control-plane/0023_source_uploads.sql", 0o644}, {"web/dist/index.html", 0o644}, {"docs/licenses/licenses-manifest.json", 0o644}, {"sbom.spdx.json", 0o644}, {"source-manifest.sha256", 0o640},
	}
	for _, item := range files {
		path := filepath.Join(bundle, filepath.FromSlash(item.path))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(item.path+"\n"), item.mode); err != nil {
			t.Fatal(err)
		}
	}
	_, sourceFile, _, _ := runtime.Caller(0)
	repo := filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "..", "..", ".."))
	units := []string{"open-card-server.service", "open-card-agent.service", "open-card-buildkit.service", "open-card-caddy.service"}
	if includeEdge {
		units = append(units, "open-card-edge.service")
	}
	entries := make([]install.FileDigest, 0, len(files)+len(units))
	for _, item := range files {
		path := filepath.Join(bundle, filepath.FromSlash(item.path))
		digest, err := install.SHA256File(path)
		if err != nil {
			t.Fatal(err)
		}
		entries = append(entries, install.FileDigest{Path: item.path, SHA256: digest, Mode: uint32(item.mode)})
	}
	for _, unit := range units {
		data, err := os.ReadFile(filepath.Join(repo, "deploy", "systemd", unit))
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(bundle, "systemd", unit)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatal(err)
		}
		digest, err := install.SHA256File(path)
		if err != nil {
			t.Fatal(err)
		}
		entries = append(entries, install.FileDigest{Path: "systemd/" + unit, SHA256: digest, Mode: 0o644})
	}
	manifest := install.Manifest{SchemaVersion: install.ManifestSchemaVersion, Product: install.ManifestProduct, Version: install.ProductionCandidateVersion, ReleaseID: "release-0.8.0-rc.1", Architecture: install.RuntimeArchitecture(), MigrationVersion: install.CurrentMigrationVersion, Protocol: install.AgentProtocolVersion, ConfigDir: install.DefaultConfigDir, DataDir: install.DefaultDataDir, Compatibility: install.Compatibility{MinDataVersion: 1, MaxDataVersion: 23, MinAgentProtocol: install.PreviousAgentProtocol, MaxAgentProtocol: install.AgentProtocolVersion}, Files: entries}
	if err := install.SaveManifest(filepath.Join(bundle, "manifest.json"), manifest); err != nil {
		t.Fatal(err)
	}
	return bundle
}

func TestG2CandidateStagesEdgeAndRequires0023WithoutActivation(t *testing.T) {
	directory := t.TempDir()
	bundle := writeG2CandidateBundle(t, directory, true)
	migrations := filepath.Join(directory, "migrations")
	if err := os.MkdirAll(migrations, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(migrations, "0023_source_uploads.sql"), []byte("-- fixture\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	migrate := filepath.Join(directory, "migrate.sh")
	if err := os.WriteFile(migrate, []byte("#!/usr/bin/env bash\nprintf '0023_source_uploads.sql\\tfixture\\n'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	_, sourceFile, _, _ := runtime.Caller(0)
	repo := filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "..", "..", ".."))
	root := filepath.Join(directory, "root")
	command := exec.Command("bash", filepath.Join(repo, "scripts/mvp/install.sh"), "--root", root, "--bundle", bundle, "--migration-command", migrate, "--migration-dir", migrations, "--test-safe-prefix", directory)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("install candidate: %v\n%s", err, output)
	}
	for _, relative := range []string{"etc/systemd/system/open-card-edge.service", "opt/open-card/current/bin/open-card-admin", "opt/open-card/current/migrations/control-plane/0023_source_uploads.sql", "opt/open-card/current/web/dist/index.html"} {
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(relative))); err != nil {
			t.Fatalf("missing staged %s: %v", relative, err)
		}
	}
	if value, err := os.ReadFile(filepath.Join(root, "var/lib/open-card/migration.version")); err != nil || string(value) != "0023\n" {
		t.Fatalf("migration state=%q err=%v", value, err)
	}
}

func TestG2CandidateRejectsMissingEdgeUnit(t *testing.T) {
	directory := t.TempDir()
	bundle := writeG2CandidateBundle(t, directory, false)
	_, sourceFile, _, _ := runtime.Caller(0)
	repo := filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "..", "..", ".."))
	command := exec.Command("bash", filepath.Join(repo, "scripts/mvp/install.sh"), "--root", filepath.Join(directory, "root"), "--bundle", bundle, "--test-safe-prefix", directory)
	output, err := command.CombinedOutput()
	if err == nil || !strings.Contains(string(output), "open-card-edge.service") {
		t.Fatalf("missing Edge unit was accepted: %v\n%s", err, output)
	}
}
