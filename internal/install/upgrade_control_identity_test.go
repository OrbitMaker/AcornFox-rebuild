package install

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

type upgradeControlRunnerFake struct {
	calls  int
	argv   [][]string
	stdin  [][]byte
	result UpgradeControlRunResult
	onRun  func()
}

func (f *upgradeControlRunnerFake) Run(_ context.Context, argv []string, stdin []byte) UpgradeControlRunResult {
	f.calls++
	f.argv = append(f.argv, append([]string(nil), argv...))
	f.stdin = append(f.stdin, append([]byte(nil), stdin...))
	if f.onRun != nil {
		f.onRun()
	}
	return f.result
}

func newTaskUpgradeControlProvisioner(t *testing.T, random []byte, runner *upgradeControlRunnerFake) (*UpgradeControlProvisioner, string) {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, durableDirMode); err != nil {
		t.Fatal(err)
	}
	p, err := NewTaskUpgradeControlProvisioner(root, os.Getuid(), os.Getgid(), bytes.NewReader(random), runner)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p, root
}

func TestUpgradeControlProvisionCreatesFileBeforeFixedRoleSQLAndReplays(t *testing.T) {
	runner := &upgradeControlRunnerFake{}
	p, root := newTaskUpgradeControlProvisioner(t, bytes.Repeat([]byte{7}, 32), runner)
	runner.onRun = func() {
		raw, err := os.ReadFile(filepath.Join(root, upgradeControlEnvironmentName))
		if err != nil {
			t.Fatalf("SQL ran before durable control file: %v", err)
		}
		if _, err := validateUpgradeControlDatabaseEnv(raw); err != nil {
			t.Fatalf("file was not valid before SQL: %v", err)
		}
	}
	first, err := p.Provision(context.Background())
	if err != nil || len(first) != 64 || runner.calls != 1 {
		t.Fatalf("first=%q err=%v calls=%d", first, err, runner.calls)
	}
	raw, err := os.ReadFile(filepath.Join(root, upgradeControlEnvironmentName))
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(filepath.Join(root, upgradeControlEnvironmentName))
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != durableFileMode {
		t.Fatalf("control file=%v err=%v", info, err)
	}
	secret, err := validateUpgradeControlDatabaseEnv(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !equalStringSlice(runner.argv[0], upgradeControlPSQLCommand()) {
		t.Fatalf("argv=%q", runner.argv[0])
	}
	if strings.Contains(strings.Join(runner.argv[0], " "), secret) {
		t.Fatal("secret was placed in argv")
	}
	sql := string(runner.stdin[0])
	for _, required := range []string{
		"rolname = 'opencard' AND rolcanlogin AND NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolreplication AND NOT rolbypassrls",
		"CREATE ROLE open_card_upgrade_control LOGIN CREATEDB NOSUPERUSER NOCREATEROLE NOREPLICATION NOBYPASSRLS INHERIT",
		"ALTER ROLE open_card_upgrade_control LOGIN CREATEDB NOSUPERUSER NOCREATEROLE NOREPLICATION NOBYPASSRLS INHERIT",
		"ALTER ROLE open_card_upgrade_control PASSWORD '" + secret + "'",
		"REVOKE open_card_upgrade_control FROM opencard",
		"GRANT opencard TO open_card_upgrade_control",
		"GRANT pg_read_all_stats TO open_card_upgrade_control",
		"member.rolname = 'open_card_upgrade_control' AND granted.rolname NOT IN ('opencard', 'pg_read_all_stats')",
		"member.rolname = 'opencard' AND granted.rolname IN ('open_card_upgrade_control', 'pg_read_all_stats')",
	} {
		if !strings.Contains(sql, required) {
			t.Fatalf("SQL lacks fixed statement %q", required)
		}
	}
	if strings.Contains(sql, "CREATE DATABASE") || strings.Contains(sql, "DROP ") {
		t.Fatalf("SQL has out-of-scope database privilege: %s", sql)
	}
	second, err := p.Provision(context.Background())
	if err != nil || second != first || runner.calls != 2 || !bytes.Equal(runner.stdin[0], runner.stdin[1]) {
		t.Fatalf("second=%q first=%q err=%v calls=%d", second, first, err, runner.calls)
	}
}

func TestProductionPostgresToolsUseUbuntuVersionedRegularPaths(t *testing.T) {
	if upgradeControlPSQL != "/usr/lib/postgresql/16/bin/psql" ||
		productionPostgresDumpTool != "/usr/lib/postgresql/16/bin/pg_dump" ||
		productionPostgresRestoreTool != "/usr/lib/postgresql/16/bin/pg_restore" {
		t.Fatal("production PostgreSQL tools are not pinned to Ubuntu 24.04 regular binaries")
	}
}

func TestUpgradeControlConcurrentFirstProvisionUsesOneDurableWinner(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, durableDirMode); err != nil {
		t.Fatal(err)
	}
	firstRunner := &upgradeControlRunnerFake{}
	secondRunner := &upgradeControlRunnerFake{}
	first, err := NewTaskUpgradeControlProvisioner(root, os.Getuid(), os.Getgid(), bytes.NewReader(bytes.Repeat([]byte{1}, 32)), firstRunner)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := NewTaskUpgradeControlProvisioner(root, os.Getuid(), os.Getgid(), bytes.NewReader(bytes.Repeat([]byte{2}, 32)), secondRunner)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()

	start := make(chan struct{})
	results := make(chan struct {
		digest string
		err    error
	}, 2)
	var group sync.WaitGroup
	for _, p := range []*UpgradeControlProvisioner{first, second} {
		group.Add(1)
		go func(p *UpgradeControlProvisioner) {
			defer group.Done()
			<-start
			digest, err := p.Provision(context.Background())
			results <- struct {
				digest string
				err    error
			}{digest, err}
		}(p)
	}
	close(start)
	group.Wait()
	close(results)
	raw, err := os.ReadFile(filepath.Join(root, upgradeControlEnvironmentName))
	if err != nil {
		t.Fatal(err)
	}
	secret, err := validateUpgradeControlDatabaseEnv(raw)
	if err != nil {
		t.Fatal(err)
	}
	wantDigest := sha256Bytes(raw)
	for result := range results {
		if result.err != nil || result.digest != wantDigest {
			t.Fatalf("digest=%q want=%q err=%v", result.digest, wantDigest, result.err)
		}
	}
	for _, runner := range []*upgradeControlRunnerFake{firstRunner, secondRunner} {
		if runner.calls != 1 || len(runner.stdin) != 1 || !strings.Contains(string(runner.stdin[0]), "PASSWORD '"+secret+"'") {
			t.Fatalf("calls=%d sql=%q", runner.calls, runner.stdin)
		}
	}
}

func TestUpgradeControlProvisionRejectsUnsafeIdentityWithoutRunningSQL(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, root string)
	}{
		{"symlink", func(t *testing.T, root string) {
			if err := os.Symlink("other", filepath.Join(root, upgradeControlEnvironmentName)); err != nil {
				t.Fatal(err)
			}
		}},
		{"mode", func(t *testing.T, root string) {
			raw, err := upgradeControlDatabaseEnv(strings.Repeat("A", 43))
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(root, upgradeControlEnvironmentName)
			if err := os.WriteFile(path, raw, 0o644); err != nil {
				t.Fatal(err)
			}
		}},
		{"identity-drift", func(t *testing.T, root string) {
			if err := os.WriteFile(filepath.Join(root, upgradeControlEnvironmentName), []byte("OPEN_CARD_DATABASE_URL=postgresql://opencard:secret@127.0.0.1:5432/postgres?sslmode=disable\n"), durableFileMode); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runner := &upgradeControlRunnerFake{}
			p, root := newTaskUpgradeControlProvisioner(t, bytes.Repeat([]byte{8}, 32), runner)
			tc.setup(t, root)
			_, err := p.Provision(context.Background())
			if !errors.Is(err, ErrUpgradeControlProvisioning) || runner.calls != 0 {
				t.Fatalf("err=%v calls=%d", err, runner.calls)
			}
		})
	}
}

func TestUpgradeControlProvisionSanitizesRunnerFailureAndDurableFailure(t *testing.T) {
	secret := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
	runner := &upgradeControlRunnerFake{result: UpgradeControlRunResult{ExitCode: 1, Err: errors.New("psql output " + secret)}}
	p, _ := newTaskUpgradeControlProvisioner(t, bytes.Repeat([]byte{9}, 32), runner)
	_, err := p.Provision(context.Background())
	if !errors.Is(err, ErrUpgradeControlProvisioning) || strings.Contains(err.Error(), secret) || runner.calls != 1 {
		t.Fatalf("err=%v calls=%d", err, runner.calls)
	}

	writer, _ := faultWriter(t, "fsync1", false)
	defer writer.Close()
	noSQL := &upgradeControlRunnerFake{}
	faulty := &UpgradeControlProvisioner{writer: writer, random: bytes.NewReader(bytes.Repeat([]byte{10}, 32)), runner: noSQL}
	_, err = faulty.Provision(context.Background())
	if !errors.Is(err, ErrUpgradeControlProvisioning) || noSQL.calls != 0 {
		t.Fatalf("durable err=%v calls=%d", err, noSQL.calls)
	}
}

func TestUpgradeControlDatabaseEnvironmentIsExactAndSecretSafe(t *testing.T) {
	raw, err := upgradeControlDatabaseEnv(strings.Repeat("z", 43))
	if err != nil {
		t.Fatal(err)
	}
	secret, err := validateUpgradeControlDatabaseEnv(raw)
	if err != nil || secret != strings.Repeat("z", 43) {
		t.Fatalf("secret=%q err=%v", secret, err)
	}
	for _, bad := range [][]byte{
		[]byte("OPEN_CARD_DATABASE_URL=postgresql://open_card_upgrade_control:bad@localhost:5432/postgres?sslmode=disable\n"),
		[]byte("OPEN_CARD_DATABASE_URL=postgresql://open_card_upgrade_control:bad@127.0.0.1:5432/open_card?sslmode=disable\n"),
		[]byte("OPEN_CARD_DATABASE_URL=postgresql://open_card_upgrade_control:bad@127.0.0.1:5432/postgres?sslmode=require\n"),
		[]byte("OPEN_CARD_DATABASE_URL=postgresql://opencard:bad@127.0.0.1:5432/postgres?sslmode=disable\n"),
	} {
		if _, err := validateUpgradeControlDatabaseEnv(bad); err == nil {
			t.Fatalf("accepted drift %q", bad)
		}
	}
}

func TestUpgradeControlProductionPathChecksRejectUnsafeToolsAndParents(t *testing.T) {
	if err := verifyUpgradeControlTool("relative-tool"); !errors.Is(err, ErrUpgradeControlProvisioning) {
		t.Fatalf("relative tool err=%v", err)
	}
	root := t.TempDir()
	if err := os.Symlink("target", filepath.Join(root, "tool")); err != nil {
		t.Fatal(err)
	}
	if err := verifyUpgradeControlTool(filepath.Join(root, "tool")); !errors.Is(err, ErrUpgradeControlProvisioning) {
		t.Fatalf("symlink tool err=%v", err)
	}
	if err := os.Chmod(root, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := verifyUpgradeControlSecureDirectory(root); !errors.Is(err, ErrUpgradeControlProvisioning) {
		t.Fatalf("writable directory err=%v", err)
	}
}
