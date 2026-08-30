package install

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type bootstrapConcurrentWinnerOps struct {
	durableOps
	winner []byte
	once   bool
}

func (o *bootstrapConcurrentWinnerOps) Link(oldName, newName string) error {
	if newName != bootstrapRuntimeDatabaseEnvName || o.once {
		return o.durableOps.Link(oldName, newName)
	}
	o.once = true
	file, err := o.durableOps.OpenFile(newName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err = o.durableOps.Write(file, o.winner); err == nil {
		err = o.durableOps.Sync(file)
	}
	if err == nil {
		err = o.durableOps.Chmod(file, 0o600)
	}
	if err == nil {
		err = o.durableOps.Chown(file, os.Getuid(), os.Getgid())
	}
	closeErr := o.durableOps.CloseFile(file)
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.ErrExist
}

type bootstrapOneShotRenameFailureOps struct {
	durableOps
	target string
	failed bool
}

func (o *bootstrapOneShotRenameFailureOps) Rename(oldName, newName string) error {
	if newName == o.target && !o.failed {
		o.failed = true
		return errors.New("injected bootstrap Edge write failure")
	}
	return o.durableOps.Rename(oldName, newName)
}

func newTaskBootstrapRuntimePreparer(t *testing.T, random []byte, runner *upgradeControlRunnerFake) (*BootstrapRuntimePreparer, *DurableWriter, string, ReleaseV1) {
	t.Helper()
	release, activeRoot := bootstrapRC2Release(t)
	configRoot := t.TempDir()
	if err := os.Chmod(configRoot, durableDirMode); err != nil {
		t.Fatal(err)
	}
	config, err := TaskDurableWriter(configRoot, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	active, err := TaskDurableWriter(activeRoot, os.Getuid(), os.Getgid())
	if err != nil {
		_ = config.Close()
		t.Fatal(err)
	}
	p, err := NewTaskBootstrapRuntimePreparer(config, active, os.Getuid(), os.Getgid(), os.Getgid(), bytes.NewReader(random), runner, selectBootstrapRC2Release)
	if err != nil {
		_ = config.Close()
		_ = active.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = config.Close(); _ = active.Close() })
	return p, config, configRoot, release
}

func TestBootstrapRuntimePrepareCreatesExactFilesBeforeRoleSQLAndReplays(t *testing.T) {
	runner := &upgradeControlRunnerFake{}
	p, _, root, release := newTaskBootstrapRuntimePreparer(t, bytes.Repeat([]byte{9}, 32), runner)
	runner.onRun = func() {
		raw, err := os.ReadFile(filepath.Join(root, bootstrapRuntimeDatabaseEnvName))
		if err != nil || validateBootstrapRuntimeDatabaseEnvOnly(raw) != nil {
			t.Fatalf("SQL preceded durable runtime env: %v", err)
		}
	}
	first, err := p.Prepare(context.Background(), release.ManifestSHA256)
	if err != nil || first.Validate() != nil || first.ReleaseID != release.ID || runner.calls != 1 {
		t.Fatalf("first=%#v err=%v calls=%d", first, err, runner.calls)
	}
	databaseRaw, err := os.ReadFile(filepath.Join(root, bootstrapRuntimeDatabaseEnvName))
	if err != nil {
		t.Fatal(err)
	}
	secret, err := validateBootstrapRuntimeDatabaseEnv(databaseRaw)
	if err != nil {
		t.Fatal(err)
	}
	if info, err := os.Lstat(filepath.Join(root, bootstrapRuntimeDatabaseEnvName)); err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("database env=%v %v", info, err)
	}
	if !equalStringSlice(runner.argv[0], bootstrapRuntimePSQLCommand()) || strings.Contains(strings.Join(runner.argv[0], "\n"), secret) {
		t.Fatalf("unsafe argv=%v", runner.argv)
	}
	sql := string(runner.stdin[0])
	for _, want := range []string{"CREATE ROLE opencard LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS INHERIT", "ALTER ROLE opencard LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS INHERIT", "ALTER ROLE opencard PASSWORD '" + secret + "'"} {
		if !strings.Contains(sql, want) {
			t.Fatalf("role SQL missing %q", want)
		}
	}
	if strings.Contains(strings.ToUpper(sql), "CREATE DATABASE") || strings.Contains(strings.ToUpper(sql), "DROP ") {
		t.Fatalf("role SQL expanded scope: %s", sql)
	}
	configRaw, err := os.ReadFile(filepath.Join(root, bootstrapSafeEdgeConfigName))
	if err != nil {
		t.Fatal(err)
	}
	envRaw, err := os.ReadFile(filepath.Join(root, bootstrapSafeEdgeEnvName))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(configRaw, bootstrapSafeEdgeConfig()) || !bytes.Equal(envRaw, bootstrapSafeEdgeEnv()) || strings.Contains(string(configRaw), "reverse_proxy") || strings.Contains(string(configRaw), "tls") || strings.Contains(string(configRaw), "file_server") || strings.Contains(string(configRaw), "log") {
		t.Fatal("safe Edge templates drifted into public configuration")
	}
	for _, name := range []string{bootstrapSafeEdgeConfigName, bootstrapSafeEdgeEnvName} {
		info, statErr := os.Lstat(filepath.Join(root, name))
		if statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o640 {
			t.Fatalf("%s=%v %v", name, info, statErr)
		}
	}
	encoded, err := json.Marshal(first)
	if err != nil || strings.Contains(string(encoded), secret) || strings.Contains(string(encoded), root) || strings.Contains(string(encoded), "postgresql://") {
		t.Fatalf("receipt leaked secret/path: %s %v", encoded, err)
	}
	second, err := p.Prepare(context.Background(), release.ManifestSHA256)
	if err != nil || second != first || runner.calls != 2 || !bytes.Equal(runner.stdin[0], runner.stdin[1]) {
		t.Fatalf("replay=%#v err=%v calls=%d", second, err, runner.calls)
	}
}

func TestBootstrapRuntimePrepareRejectsWrongReleaseAndUnsafeExistingFiles(t *testing.T) {
	for name, arrange := range map[string]func(*testing.T, string, ReleaseV1){
		"wrong_release": func(_ *testing.T, _ string, _ ReleaseV1) {},
		"database_symlink": func(t *testing.T, root string, _ ReleaseV1) {
			if err := os.Symlink("elsewhere", filepath.Join(root, bootstrapRuntimeDatabaseEnvName)); err != nil {
				t.Fatal(err)
			}
		},
		"database_mode": func(t *testing.T, root string, _ ReleaseV1) {
			raw, _ := bootstrapRuntimeDatabaseEnv(strings.Repeat("A", 43))
			if err := os.WriteFile(filepath.Join(root, bootstrapRuntimeDatabaseEnvName), raw, 0o644); err != nil {
				t.Fatal(err)
			}
		},
		"edge_mode": func(t *testing.T, root string, _ ReleaseV1) {
			if err := os.WriteFile(filepath.Join(root, bootstrapSafeEdgeEnvName), bootstrapSafeEdgeEnv(), 0o644); err != nil {
				t.Fatal(err)
			}
		},
		"edge_symlink": func(t *testing.T, root string, _ ReleaseV1) {
			if err := os.Symlink("elsewhere", filepath.Join(root, bootstrapSafeEdgeConfigName)); err != nil {
				t.Fatal(err)
			}
		},
		"edge_conflict": func(t *testing.T, root string, _ ReleaseV1) {
			if err := os.WriteFile(filepath.Join(root, bootstrapSafeEdgeConfigName), []byte("public.example { reverse_proxy 127.0.0.1:1 }\n"), 0o640); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			runner := &upgradeControlRunnerFake{}
			p, _, root, release := newTaskBootstrapRuntimePreparer(t, bytes.Repeat([]byte{3}, 32), runner)
			arrange(t, root, release)
			expected := release.ManifestSHA256
			if name == "wrong_release" {
				expected = strings.Repeat("0", 64)
			}
			if _, err := p.Prepare(context.Background(), expected); !errors.Is(err, ErrBootstrapRuntimePreparation) {
				t.Fatalf("err=%v", err)
			}
			if name == "wrong_release" && runner.calls != 0 {
				t.Fatal("wrong release invoked role SQL")
			}
			if name == "wrong_release" {
				entries, readErr := os.ReadDir(root)
				if readErr != nil || len(entries) != 0 {
					t.Fatalf("wrong release published files: %v %v", entries, readErr)
				}
			}
		})
	}
}

func TestBootstrapRuntimePrepareAcceptsOnlyValidConcurrentEnvWinner(t *testing.T) {
	for name, valid := range map[string]bool{"valid": true, "invalid": false} {
		t.Run(name, func(t *testing.T) {
			runner := &upgradeControlRunnerFake{}
			p, config, _, release := newTaskBootstrapRuntimePreparer(t, bytes.Repeat([]byte{3}, 32), runner)
			winner, err := bootstrapRuntimeDatabaseEnv(strings.Repeat("B", 43))
			if err != nil {
				t.Fatal(err)
			}
			if !valid {
				winner = []byte("invalid\n")
			}
			original := config.ops
			config.ops = &bootstrapConcurrentWinnerOps{durableOps: original, winner: winner}
			receipt, err := p.Prepare(context.Background(), release.ManifestSHA256)
			if valid {
				if err != nil || receipt.BootstrapDatabaseEnvSHA256 != sha256Bytes(winner) || runner.calls != 1 {
					t.Fatalf("valid winner receipt=%+v err=%v calls=%d", receipt, err, runner.calls)
				}
				secret, _ := validateBootstrapRuntimeDatabaseEnv(winner)
				if !strings.Contains(string(runner.stdin[0]), secret) {
					t.Fatal("SQL did not use concurrent winner secret")
				}
			} else if !errors.Is(err, ErrBootstrapRuntimePreparation) || runner.calls != 0 {
				t.Fatalf("invalid winner err=%v calls=%d", err, runner.calls)
			}
		})
	}
}

func TestBootstrapRuntimePrepareRetriesEdgeWriteWithSameRuntimeSecret(t *testing.T) {
	runner := &upgradeControlRunnerFake{}
	p, config, root, release := newTaskBootstrapRuntimePreparer(t, bytes.Repeat([]byte{4}, 32), runner)
	original := config.ops
	config.ops = &bootstrapOneShotRenameFailureOps{durableOps: original, target: bootstrapSafeEdgeConfigName}
	if _, err := p.Prepare(context.Background(), release.ManifestSHA256); !errors.Is(err, ErrBootstrapRuntimePreparation) || runner.calls != 1 {
		t.Fatalf("first failure err=%v calls=%d", err, runner.calls)
	}
	databaseBefore, err := os.ReadFile(filepath.Join(root, bootstrapRuntimeDatabaseEnvName))
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := p.Prepare(context.Background(), release.ManifestSHA256)
	if err != nil || runner.calls != 2 || !bytes.Equal(runner.stdin[0], runner.stdin[1]) {
		t.Fatalf("retry receipt=%+v err=%v calls=%d", receipt, err, runner.calls)
	}
	databaseAfter, err := os.ReadFile(filepath.Join(root, bootstrapRuntimeDatabaseEnvName))
	if err != nil || !bytes.Equal(databaseBefore, databaseAfter) {
		t.Fatalf("runtime secret changed across retry: %v", err)
	}
	if configRaw, err := os.ReadFile(filepath.Join(root, bootstrapSafeEdgeConfigName)); err != nil || !bytes.Equal(configRaw, bootstrapSafeEdgeConfig()) {
		t.Fatalf("safe config did not converge: %q %v", configRaw, err)
	}
	if envRaw, err := os.ReadFile(filepath.Join(root, bootstrapSafeEdgeEnvName)); err != nil || !bytes.Equal(envRaw, bootstrapSafeEdgeEnv()) {
		t.Fatalf("safe env did not converge: %q %v", envRaw, err)
	}
}

func TestBootstrapRuntimePrepareSourceIsBoundedAndSecretFree(t *testing.T) {
	raw, err := os.ReadFile("bootstrap_prepare.go")
	if err != nil {
		t.Fatal(err)
	}
	source := strings.ToUpper(string(raw))
	for _, forbidden := range []string{"DROP DATABASE", "DELETE DATABASE", "OPEN_CARD_DATABASE_URL=", "--DBNAME="} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("forbidden source surface %q", forbidden)
		}
	}
	if !strings.Contains(string(raw), "http://127.0.0.1:18482") || !strings.Contains(string(raw), "admin 127.0.0.1:2020") {
		t.Fatal("safe Edge listener is not fixed loopback-only")
	}
}
