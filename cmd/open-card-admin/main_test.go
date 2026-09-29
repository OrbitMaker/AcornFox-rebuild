package main

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/open-card/open-card/internal/auth"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/install"
	"github.com/open-card/open-card/internal/persistence/postgres"
	"github.com/open-card/open-card/internal/persistence/sqlite"
)

type adminFailReader struct{}

func (adminFailReader) Read([]byte) (int, error) { return 0, errors.New("entropy unavailable") }

type ownerOverrideInfo struct {
	os.FileInfo
	stat syscall.Stat_t
}

func (i ownerOverrideInfo) Sys() any { return &i.stat }

type candidateValidationResult struct{}

func (candidateValidationResult) LastInsertId() (int64, error) { return 0, nil }
func (candidateValidationResult) RowsAffected() (int64, error) { return 1, nil }

type candidateValidationTestRow struct {
	value string
	err   error
}

func (r candidateValidationTestRow) Scan(destinations ...any) error {
	if r.err != nil {
		return r.err
	}
	if len(destinations) != 1 {
		return errors.New("unexpected destination count")
	}
	value, ok := destinations[0].(*string)
	if !ok {
		return errors.New("unexpected destination")
	}
	*value = r.value
	return nil
}

func secureTaskRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	return root
}

func testResolve(calls *int) adminResolveFunc {
	return func(config commandConfig) (install.ActiveDatabase, error) {
		*calls++
		return install.ActiveDatabase{Activation: install.ActivationV1{ActivationID: config.activationID}}, nil
	}
}

func TestNonRootPrivilegeGateRejectsUnsafeCommandsBeforeDatabaseResolution(t *testing.T) {
	for _, args := range [][]string{{"bootstrap", "--password-file", "/tmp/password"}, {"candidate", "validate", "--activation-id", "activation-1"}, {"activation", "validate", "--activation-id", "activation-1", "--task-root", "/opt/open-card"}} {
		if err := runWithEUID(args, io.Discard, func() int { return 501 }); err == nil {
			t.Fatalf("non-root accepted %v", args)
		}
	}
}

func TestNonRootSecureTaskRootReachesResolverAndValidator(t *testing.T) {
	for _, command := range [][]string{{"candidate", "validate", "--activation-id", "activation-1"}, {"activation", "validate", "--activation-id", "activation-1"}} {
		t.Run(command[0], func(t *testing.T) {
			root := secureTaskRoot(t)
			args := append(append([]string{}, command...), "--task-root", root)
			resolved, validated := 0, 0
			err := runWithDependencies(args, io.Discard, func() int { return 501 }, os.Lstat, testResolve(&resolved), func(config commandConfig, active install.ActiveDatabase) error {
				validated++
				if config.taskRoot != root || active.Activation.ActivationID != "activation-1" {
					t.Fatal("task-root validation did not preserve parsed identity")
				}
				return nil
			})
			if err != nil || resolved != 1 || validated != 1 {
				t.Fatalf("err=%v resolver=%d validator=%d", err, resolved, validated)
			}
		})
	}
}

func TestNonRootTaskRootRejectsUnsafePathsModesLinksAndOwners(t *testing.T) {
	root := secureTaskRoot(t)
	base := []string{"candidate", "validate", "--activation-id", "activation-1", "--task-root"}
	for _, taskRoot := range []string{"relative", root + "/../" + filepath.Base(root), "/opt/open-card"} {
		args := append(append([]string{}, base...), taskRoot)
		resolved := 0
		if err := runWithDependencies(args, io.Discard, func() int { return 501 }, os.Lstat, testResolve(&resolved), nil); err == nil || resolved != 0 {
			t.Fatalf("non-root accepted unsafe task root %q", taskRoot)
		}
	}
	for _, mode := range []os.FileMode{0o770, 0o755} {
		t.Run(mode.String(), func(t *testing.T) {
			root := t.TempDir()
			if err := os.Chmod(root, mode); err != nil {
				t.Fatal(err)
			}
			args := append(append([]string{}, base...), root)
			if err := runWithDependencies(args, io.Discard, func() int { return 501 }, os.Lstat, testResolve(new(int)), nil); err == nil {
				t.Fatal("non-root accepted unsafe task-root mode")
			}
		})
	}
	link := filepath.Join(t.TempDir(), "task-root-link")
	if err := os.Symlink(root, link); err != nil {
		t.Fatal(err)
	}
	if err := runWithDependencies(append(append([]string{}, base...), link), io.Discard, func() int { return 501 }, os.Lstat, testResolve(new(int)), nil); err == nil {
		t.Fatal("non-root accepted task-root symlink")
	}
	info, err := os.Lstat(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*syscall.Stat_t){func(stat *syscall.Stat_t) { stat.Uid++ }, func(stat *syscall.Stat_t) { stat.Gid++ }} {
		stat := *info.Sys().(*syscall.Stat_t)
		mutate(&stat)
		lstat := func(string) (os.FileInfo, error) { return ownerOverrideInfo{FileInfo: info, stat: stat}, nil }
		if err := runWithDependencies(append(append([]string{}, base...), root), io.Discard, func() int { return 501 }, lstat, testResolve(new(int)), nil); err == nil {
			t.Fatal("non-root accepted mismatched task-root owner")
		}
	}
}

func TestRootPrivilegeRetainsCredentialAndValidationRoutes(t *testing.T) {
	validated, resolved := 0, 0
	if err := runWithDependencies([]string{"candidate", "validate", "--activation-id", "activation-1"}, io.Discard, func() int { return 0 }, os.Lstat, testResolve(&resolved), func(commandConfig, install.ActiveDatabase) error { validated++; return nil }); err != nil || resolved != 1 || validated != 1 {
		t.Fatalf("root validation route err=%v resolver=%d validator=%d", err, resolved, validated)
	}
	for _, command := range []string{"bootstrap", "reset-password"} {
		resolved = 0
		err := runWithDependencies([]string{command, "--password-file", "/tmp/missing-password"}, io.Discard, func() int { return 0 }, os.Lstat, testResolve(&resolved), nil)
		if err == nil || strings.Contains(err.Error(), "root is required") || resolved != 1 {
			t.Fatalf("root %s route was not retained: err=%v resolver=%d", command, err, resolved)
		}
	}
}

func TestValidationSeamNeverLeaksAmbientDatabaseURL(t *testing.T) {
	t.Setenv("OPEN_CARD_DATABASE_URL", "postgresql://admin:ambient-secret@db.example/open_card")
	root := secureTaskRoot(t)
	err := runWithDependencies(
		[]string{"candidate", "validate", "--activation-id", "activation-1", "--task-root", root},
		io.Discard,
		func() int { return 501 },
		os.Lstat,
		func(commandConfig) (install.ActiveDatabase, error) {
			return install.ActiveDatabase{Activation: install.ActivationV1{ActivationID: "activation-1"}, DatabaseURL: "postgresql://admin:resolver-secret@db.example/open_card"}, nil
		},
		func(commandConfig, install.ActiveDatabase) error { return errors.New("validation failed") },
	)
	if err == nil || strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "postgres") {
		t.Fatalf("validation error leaked a database URL: %v", err)
	}
}

func TestParseArgsRejectsPasswordArgumentsAndEnvironment(t *testing.T) {
	for _, args := range [][]string{{"bootstrap"}, {"bootstrap", "--password", "secret"}, {"reset-password", "--password-file", "relative"}, {"bootstrap", "--password-file", "/tmp/password", "--server-env", "/etc/open-card/server.env"}, {"activation", "validate"}, {"candidate", "validate", "--activation-id", "../../escape"}, {"candidate", "validate", "--activation-id", "activation-1", "--task-root", "/tmp/a/../b"}, {"candidate", "validate", "--activation-id", "activation-1", "--password-file", "/tmp/password"}} {
		if _, err := parseArgs(args); err == nil {
			t.Fatalf("expected rejected arguments: %#v", args)
		}
	}
	config, err := parseArgs([]string{"bootstrap", "--password-file", "/etc/open-card/bootstrap-password"})
	if err != nil || config.command != "bootstrap" || config.taskRoot != "" {
		t.Fatalf("config=%#v err=%v", config, err)
	}
	candidate, err := parseArgs([]string{"candidate", "validate", "--activation-id", "activation-1", "--task-root", "/tmp/open-card-task-root"})
	if err != nil || candidate.command != "candidate-validate" || candidate.activationID != "activation-1" || candidate.taskRoot != "/tmp/open-card-task-root" {
		t.Fatalf("candidate=%#v err=%v", candidate, err)
	}
}

func TestRuntimeUnitsPutActiveDatabaseAfterGlobalConfigAndGateEdge(t *testing.T) {
	server, err := os.ReadFile(filepath.Join("..", "..", "deploy", "systemd", "open-card-server.service"))
	if err != nil {
		t.Fatal(err)
	}
	global := strings.Index(string(server), "EnvironmentFile=-/etc/open-card/server.env")
	active := strings.Index(string(server), "EnvironmentFile=/opt/open-card/active/database.env")
	if global < 0 || active < 0 || global >= active {
		t.Fatal("server unit does not load mandatory active database.env after global config")
	}
	edge, err := os.ReadFile(filepath.Join("..", "..", "deploy", "systemd", "open-card-edge.service.d", "10-upgrade-marker.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if string(edge) != string(install.ProductionUpgradeEdgeMarkerDropInBytes()) {
		t.Fatal("edge marker drop-in drifted from the fixed upgrade contract")
	}
}

func TestAdminRejectsLegacyServerEnvAndRedactsActiveResolutionErrors(t *testing.T) {
	t.Setenv("OPEN_CARD_DATABASE_URL", "postgresql://admin:secret@db.example/open_card")
	if _, err := parseArgs([]string{"bootstrap", "--password-file", "/tmp/password", "--server-env", "/etc/open-card/server.env"}); err == nil {
		t.Fatal("legacy server.env fallback flag was accepted")
	}
	_, err := resolveActiveDatabase(commandConfig{command: "activation-validate", activationID: "activation-1", taskRoot: "/definitely/missing/open-card"})
	if err == nil || strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "postgres") {
		t.Fatalf("active resolution error leaked a DSN: %v", err)
	}
}

func TestCandidateValidationWriteIsTransactionalAndSanitized(t *testing.T) {
	var statements []string
	err := validateCandidateRollbackWrite(
		context.Background(),
		func(_ context.Context, statement string, _ ...any) (sql.Result, error) {
			statements = append(statements, statement)
			return candidateValidationResult{}, nil
		},
		func(_ context.Context, statement string, _ ...any) candidateValidationRow {
			statements = append(statements, statement)
			return candidateValidationTestRow{value: "candidate-validation"}
		},
	)
	if err != nil || len(statements) != 3 || !strings.Contains(statements[0], "CREATE TEMPORARY TABLE") || !strings.Contains(statements[1], "INSERT INTO") || !strings.Contains(statements[2], "SELECT value") {
		t.Fatalf("err=%v statements=%#v", err, statements)
	}
	err = validateCandidateRollbackWrite(
		context.Background(),
		func(context.Context, string, ...any) (sql.Result, error) {
			return nil, errors.New("postgresql://candidate:never-log-this@db.example/open_card")
		},
		func(context.Context, string, ...any) candidateValidationRow { return candidateValidationTestRow{} },
	)
	if err == nil || strings.Contains(err.Error(), "never-log-this") || strings.Contains(err.Error(), "postgres") {
		t.Fatalf("candidate validation leaked driver error: %v", err)
	}
}

func TestAdminBootstrapAndResetOnTaskScopedPostgres(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("OPEN_CARD_ADMIN_TEST_DATABASE_URL"))
	if dsn == "" {
		t.Skip("OPEN_CARD_ADMIN_TEST_DATABASE_URL is required for task-scoped PostgreSQL")
	}
	database, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	ctx := context.Background()
	if _, err := database.ExecContext(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public`); err != nil {
		t.Fatal(err)
	}
	migration, err := os.ReadFile(filepath.Join("..", "..", "migrations", "control-plane", "0022_admin_auth.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, string(migration)); err != nil {
		t.Fatal(err)
	}
	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateCandidateRollbackWrite(ctx, tx.ExecContext, func(ctx context.Context, query string, args ...any) candidateValidationRow {
		return tx.QueryRowContext(ctx, query, args...)
	}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	var probeExists bool
	if err := database.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'open_card_candidate_validation_probe')`).Scan(&probeExists); err != nil {
		t.Fatal(err)
	}
	if probeExists {
		t.Fatal("candidate validation left a persistent probe table")
	}
	store := postgres.NewStore(database)
	now := time.Unix(1_700_000_000, 0).UTC()
	if err := applyCredential(ctx, store, "bootstrap", []byte("bootstrap correct horse battery staple 123"), now); err != nil {
		t.Fatal(err)
	}
	originalService := newAdminAuthService
	newAdminAuthService = func(store auth.Store) (*auth.Service, error) {
		return auth.NewService(auth.Config{Store: store, Random: adminFailReader{}})
	}
	t.Cleanup(func() { newAdminAuthService = originalService })
	if err := applyCredential(ctx, store, "bootstrap", []byte("bootstrap correct horse battery staple 123"), now.Add(time.Second)); err != nil {
		t.Fatalf("exact bootstrap replay failed: %v", err)
	}
	if err := applyCredential(ctx, store, "bootstrap", []byte("another correct horse battery staple 456"), now); err == nil {
		t.Fatal("second bootstrap was accepted")
	}
	credential, err := store.ActiveAdminCredential(ctx)
	if err != nil || credential.CredentialVersion != 1 {
		t.Fatalf("credential=%+v err=%v", credential, err)
	}
	service, err := auth.NewService(auth.Config{Store: store, Origin: "https://console.example.test", Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	login, err := service.Login(ctx, "https://console.example.test", "bootstrap correct horse battery staple 123", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if err := applyCredential(ctx, store, "reset-password", []byte("rotated correct horse battery staple 789"), now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := service.Session(ctx, login.SessionToken); !errors.Is(err, auth.ErrAuthenticationFailed) {
		t.Fatalf("old session remained valid after reset: %v", err)
	}
	credential, err = store.ActiveAdminCredential(ctx)
	if err != nil || credential.CredentialVersion != 2 {
		t.Fatalf("rotated credential=%+v err=%v", credential, err)
	}
	if _, err := database.ExecContext(ctx, `UPDATE admin_credentials SET disabled_at = now()`); err != nil {
		t.Fatal(err)
	}
	if err := applyCredential(ctx, store, "bootstrap", []byte("disabled record still blocks bootstrap 999"), now.Add(2*time.Minute)); err == nil {
		t.Fatal("bootstrap accepted a disabled historical administrator")
	}
}

func TestReadRootOnlyPasswordRejectsSymlinkAndOpenPermissions(t *testing.T) {
	directory := t.TempDir()
	plain := filepath.Join(directory, "password")
	if err := os.WriteFile(plain, []byte("correct horse battery staple\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readRootOnlyPassword(plain); err == nil {
		t.Fatal("world-readable password file was accepted")
	}
	link := filepath.Join(directory, "password-link")
	if err := os.Symlink(plain, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readRootOnlyPassword(link); err == nil {
		t.Fatal("password symlink was accepted")
	}
}

type fakeAdminCredentialStore struct {
	exists     bool
	credential domain.AdminCredential
}

func (f *fakeAdminCredentialStore) AdministratorExists(context.Context) (bool, error) {
	return f.exists, nil
}

func (f *fakeAdminCredentialStore) ActiveAdminCredential(context.Context) (domain.AdminCredential, error) {
	if !f.exists || f.credential.DisabledAt != nil {
		return domain.AdminCredential{}, auth.ErrNotFound
	}
	return f.credential, nil
}

func (f *fakeAdminCredentialStore) CreateAdminCredential(_ context.Context, c domain.AdminCredential) error {
	if f.exists {
		return errors.New("admin already exists")
	}
	f.exists = true
	f.credential = c
	return nil
}

func (f *fakeAdminCredentialStore) RotateAdminCredential(_ context.Context, id domain.ID, expectedVersion int64, scheme, hash string, now time.Time) (domain.AdminCredential, error) {
	if !f.exists || f.credential.ID != id || f.credential.CredentialVersion != expectedVersion {
		return domain.AdminCredential{}, auth.ErrCredentialVersionConflict
	}
	f.credential.PasswordHashScheme = scheme
	f.credential.PasswordHash = hash
	f.credential.CredentialVersion++
	f.credential.UpdatedAt = now
	return f.credential, nil
}

func (f *fakeAdminCredentialStore) CreateAdminSession(context.Context, domain.AdminSession) error {
	return errors.New("unexpected call to CreateAdminSession in credential test")
}
func (f *fakeAdminCredentialStore) ActiveAdminSessionByDigest(context.Context, domain.AuthDigest, time.Time) (domain.AdminSession, error) {
	return domain.AdminSession{}, errors.New("unexpected call to ActiveAdminSessionByDigest in credential test")
}
func (f *fakeAdminCredentialStore) TouchAdminSession(context.Context, domain.ID, int64, time.Time) (domain.AdminSession, error) {
	return domain.AdminSession{}, errors.New("unexpected call to TouchAdminSession in credential test")
}
func (f *fakeAdminCredentialStore) RevokeAdminSession(context.Context, domain.ID, time.Time) error {
	return errors.New("unexpected call to RevokeAdminSession in credential test")
}
func (f *fakeAdminCredentialStore) UpsertAdminLoginRateLimit(context.Context, domain.AdminLoginRateLimit) error {
	return errors.New("unexpected call to UpsertAdminLoginRateLimit in credential test")
}
func (f *fakeAdminCredentialStore) AdminLoginRateLimit(context.Context, domain.ID, domain.AuthDigest) (domain.AdminLoginRateLimit, error) {
	return domain.AdminLoginRateLimit{}, errors.New("unexpected call to AdminLoginRateLimit in credential test")
}
func (f *fakeAdminCredentialStore) RecordAdminLoginFailure(context.Context, domain.ID, domain.AuthDigest, time.Time) (domain.AdminLoginRateLimit, error) {
	return domain.AdminLoginRateLimit{}, errors.New("unexpected call to RecordAdminLoginFailure in credential test")
}
func (f *fakeAdminCredentialStore) CreateAdminSessionIfLoginAllowed(context.Context, domain.AdminSession, domain.AuthDigest, time.Time) error {
	return errors.New("unexpected call to CreateAdminSessionIfLoginAllowed in credential test")
}

func TestApplyCredentialWithNarrowStoreWithoutDB(t *testing.T) {
	ctx := context.Background()
	store := &fakeAdminCredentialStore{}
	now := time.Date(2026, 9, 26, 10, 0, 0, 0, time.UTC)

	// Reset before bootstrap must fail with administrator does not exist
	if err := applyCredential(ctx, store, "reset-password", []byte("valid-length-password-12345"), now); err == nil || !strings.Contains(err.Error(), "bootstrap first") {
		t.Fatalf("expected bootstrap first error, got: %v", err)
	}

	// Bootstrap creates initial administrator with version 1
	pass := []byte("first-bootstrap-password-12345")
	if err := applyCredential(ctx, store, "bootstrap", pass, now); err != nil {
		t.Fatalf("bootstrap failed: %v", err)
	}
	if !store.exists || store.credential.CredentialVersion != 1 || store.credential.PasswordHash == "" {
		t.Fatalf("unexpected state after bootstrap: exists=%v version=%d", store.exists, store.credential.CredentialVersion)
	}

	// Reset password rotates to version 2 and updates password hash
	oldHash := store.credential.PasswordHash
	newPass := []byte("second-rotated-password-12345")
	if err := applyCredential(ctx, store, "reset-password", newPass, now.Add(time.Minute)); err != nil {
		t.Fatalf("reset password failed: %v", err)
	}
	if store.credential.CredentialVersion != 2 || store.credential.PasswordHash == oldHash {
		t.Fatalf("expected version 2 with updated hash after reset, got version=%d sameHash=%v", store.credential.CredentialVersion, store.credential.PasswordHash == oldHash)
	}
}

func secureTestDir(t *testing.T, sub ...string) string {
	t.Helper()
	temp := t.TempDir()
	if err := os.Chmod(temp, 0o700); err != nil {
		t.Fatal(err)
	}
	if len(sub) > 0 {
		full := filepath.Join(append([]string{temp}, sub...)...)
		if err := os.MkdirAll(full, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(full, 0o700); err != nil {
			t.Fatal(err)
		}
		return full
	}
	return temp
}

func TestAdminApplyCredentialWithRealSQLiteStore(t *testing.T) {
	dataDir := secureTestDir(t, "sqlite_admin_test")
	store, err := sqlite.Open(sqlite.Config{
		DataDirectory: dataDir,
		DBName:        "acornfox.db",
	})
	if err != nil {
		t.Fatalf("Open sqlite store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)

	// 1. Initial bootstrap
	initialPass := []byte("sqlite-admin-initial-password-12345")
	if err := applyCredential(ctx, store, "bootstrap", initialPass, now); err != nil {
		t.Fatalf("bootstrap against sqlite store failed: %v", err)
	}

	exists, err := store.AdministratorExists(ctx)
	if err != nil || !exists {
		t.Fatalf("expected administrator to exist after bootstrap: exists=%v err=%v", exists, err)
	}

	cred, err := store.ActiveAdminCredential(ctx)
	if err != nil || cred.CredentialVersion != 1 {
		t.Fatalf("unexpected cred after bootstrap: %+v err=%v", cred, err)
	}

	// 2. Reset password
	newPass := []byte("sqlite-admin-rotated-password-67890")
	if err := applyCredential(ctx, store, "reset-password", newPass, now.Add(time.Minute)); err != nil {
		t.Fatalf("reset-password against sqlite store failed: %v", err)
	}

	credRotated, err := store.ActiveAdminCredential(ctx)
	if err != nil || credRotated.CredentialVersion != 2 {
		t.Fatalf("expected credential version 2 after reset: %+v err=%v", credRotated, err)
	}

	// 3. Close and reopen to verify persistence
	_ = store.Close()

	reopenedStore, err := sqlite.Open(sqlite.Config{
		DataDirectory: dataDir,
		DBName:        "acornfox.db",
	})
	if err != nil {
		t.Fatalf("reopen sqlite store: %v", err)
	}
	defer reopenedStore.Close()

	credReopened, err := reopenedStore.ActiveAdminCredential(ctx)
	if err != nil || credReopened.CredentialVersion != 2 {
		t.Fatalf("expected credential version 2 after reopen: %+v err=%v", credReopened, err)
	}
}
