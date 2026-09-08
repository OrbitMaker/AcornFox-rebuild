//go:build integration

package install

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func TestAcornFoxPostCrossPGFixture(t *testing.T) {
	pg := startAcornFoxPostCrossPG(t)
	shadow := "acornfox_upg_" + strings.Repeat("a", 20)
	environment := []byte("ACORNFOX_DATABASE_URL=postgresql://acornfox:" + strings.Repeat("A", 43) + "@127.0.0.1:5432/" + shadow + "?sslmode=disable\n")
	if !validAcornFoxControlPlaneEnvironmentForDatabase(environment, shadow) {
		t.Fatal("isolated fixture environment is invalid")
	}
	dsn, err := parseAcornFoxControlPlaneEnvironment(environment)
	if err != nil {
		t.Fatal("isolated fixture environment parsing failed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	pg.createShadow(t, ctx, dsn, shadow)
	db, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal("isolated fixture canonical connection failed")
	}
	defer db.Close(context.Background())
	var name, role string
	if db.QueryRow(ctx, "SELECT current_database(), current_user").Scan(&name, &role) != nil || name != shadow || role != "acornfox" {
		t.Fatal("isolated fixture selected the wrong database or role")
	}
	wrong, err := url.Parse(dsn)
	if err != nil {
		t.Fatal("isolated fixture negative connection setup failed")
	}
	wrong.User = url.UserPassword("acornfox", "incorrect-test-password")
	unexpected, err := pgx.Connect(ctx, wrong.String())
	if err == nil {
		unexpected.Close(context.Background())
		t.Fatal("isolated fixture did not enforce the synthetic password")
	}
	t.Log("private PostgreSQL fixture: canonical relay, database identity, and SCRAM password checks passed")
}

// This is a real-database preservation test after a synthetic 0039 -> 0040
// transition. The business tables below are explicit test fixtures, not proof
// that the complete production schema or the cross-schema migration ran on PG.
func TestAcornFoxPostCrossSameSchemaRealPostgres(t *testing.T) {
	pg := startAcornFoxPostCrossPG(t)
	u, p, origin := newAcornFoxPostCrossFixture(t)
	if origin.Phase != "UPGRADED" || origin.CrossSchema == nil || origin.Next.ControlPlane.MigrationVersion != "0040" {
		t.Fatal("fixture did not reach the upgraded cross-schema origin")
	}
	shadow := origin.CrossSchema.Database.ShadowDatabase
	dsn, err := parseAcornFoxControlPlaneEnvironment(origin.Next.DatabaseEnv)
	if err != nil || !validAcornFoxControlPlaneEnvironmentForDatabase(origin.Next.DatabaseEnv, shadow) {
		t.Fatal("invalid synthetic shadow environment")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	pg.createShadow(t, ctx, dsn, shadow)
	// All business and ledger access uses the exact DSN from the upgrade image;
	// only cluster administration uses the private cluster's Unix socket.
	db, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal("could not connect using the current shadow environment")
	}
	defer db.Close(context.Background())
	s, err := u.openStore()
	if err != nil {
		t.Fatal("open task store failed")
	}
	defer s.Close()
	binding, err := ParseAcornFoxCandidateBindingV1(origin.Next.Binding, origin.Next.Repo.BindingSHA256)
	if err != nil {
		t.Fatal("parse current binding failed")
	}
	migrations, err := loadAcornFoxControlPlaneMigrations(s.layout, binding.binding)
	if err != nil || len(migrations.rows) != 40 || acornFoxMigrationRowsSHA256(migrations.rows) != origin.Next.ControlPlane.MigrationRowsSHA256 {
		t.Fatal("current fixture migration ledger does not match its receipt")
	}
	postCrossPGExec(t, ctx, db, `CREATE TABLE schema_migrations (version text PRIMARY KEY, checksum text NOT NULL, applied_at timestamptz NOT NULL);
CREATE TABLE preservation_accounts (id bigint PRIMARY KEY, label text NOT NULL, balance numeric(18,4) NOT NULL, metadata jsonb NOT NULL, optional_note text, payload bytea NOT NULL);
CREATE TABLE preservation_events (id bigint PRIMARY KEY, account_id bigint NOT NULL REFERENCES preservation_accounts(id), happened_at timestamptz NOT NULL, enabled boolean NOT NULL, detail text NOT NULL);
INSERT INTO preservation_accounts VALUES
 (1, '保留账户', 12345.6789, '{"nested":{"value":7},"tags":["a","b"]}', NULL, decode('0001feff','hex')),
 (2, 'quotes '' and newline' || chr(10) || 'tail', -0.0100, '{"empty":[],"flag":false}', '', decode('41420043','hex'));
INSERT INTO preservation_events VALUES
 (11, 1, '2025-01-02T03:04:05.123456Z', true, 'first event'),
 (12, 2, '2026-09-08T00:00:00Z', false, '第二条事件');`)
	for _, row := range migrations.rows {
		postCrossPGExec(t, ctx, db, "INSERT INTO schema_migrations VALUES ($1, $2, '2026-01-01T00:00:00Z')", row.Version, row.Checksum)
	}
	before := snapshotAcornFoxPostCrossPG(t, ctx, db)
	if before.database != shadow || before.businessCount != 4 || before.migrationCount != 40 {
		t.Fatal("real PostgreSQL baseline is incomplete")
	}
	factoryCalls := 0
	u.database = func(acornFoxInstallLayout, string, string, string, []byte, acornFoxControlPlaneMigrations, int) (acornFoxCrossSchemaDatabase, error) {
		factoryCalls++
		return nil, errors.New("same-schema migration factory is forbidden")
	}
	current := origin.Next
	for _, version := range []string{"1.2.6-test.1", "1.2.7-test.1"} {
		request := postCrossRequestForTest(t, u, current, version)
		receipt, err := u.upgrade(ctx, request)
		if err != nil || receipt.State != "UPGRADED" {
			t.Fatal("same-schema upgrade did not succeed")
		}
		j, err := u.load(s)
		if err != nil || j.PostCross == nil || j.CrossSchema != nil || !bytes.Equal(j.Next.DatabaseEnv, origin.Next.DatabaseEnv) {
			t.Fatal("same-schema upgrade did not retain the shadow environment")
		}
		func() {
			lock, err := s.Acquire(ctx)
			if err != nil {
				t.Fatal("acquire authority verification lock failed")
			}
			defer lock.Release()
			name, err := acornFoxExpectedCurrentDatabase(s, j.Next.Repo.BindingSHA256)
			if err != nil || name != shadow {
				t.Fatal("current database authority changed")
			}
			_, identity, err := acornFoxRuntimeAuthority(ctx, s, s.hostRoot)
			if err != nil || identity.Version != version {
				t.Fatal("runtime authority did not advance to the hotfix")
			}
			admin, err := resolveAcornFoxAdminDatabase(ctx, s, identity.Version, identity.SourceCommit)
			if err != nil || admin.DatabaseURL != dsn || admin.MigrationRowsSHA256 != origin.Next.ControlPlane.MigrationRowsSHA256 {
				t.Fatal("admin authority did not retain the current shadow database")
			}
			if err := u.verifyImage(s, j, true); err != nil {
				t.Fatal("current image verification failed")
			}
		}()
		// Reconnect from the new image too: a surviving pre-upgrade connection
		// alone cannot prove that fresh clients still select the same database.
		nextDSN, err := parseAcornFoxControlPlaneEnvironment(j.Next.DatabaseEnv)
		if err != nil {
			t.Fatal("parse inherited environment failed")
		}
		fresh, err := pgx.Connect(ctx, nextDSN)
		if err != nil {
			t.Fatal("fresh current-database connection failed")
		}
		after := snapshotAcornFoxPostCrossPG(t, ctx, fresh)
		fresh.Close(context.Background())
		if after != before || factoryCalls != 0 {
			t.Fatal("hotfix changed database identity, complete business rows, or migration ledger; or called migration factory")
		}
		t.Logf("hotfix=%s state=UPGRADED business_rows=%d business_sha256=%s migration_rows=%d migration_sha256=%s factory_calls=%d", version, after.businessCount, sha256Bytes([]byte(after.business)), after.migrationCount, sha256Bytes([]byte(after.migrations)), factoryCalls)
		current = j.Next
	}
	p.assertExternalSentinel(t)
}

type acornFoxPostCrossPGSnapshot struct {
	database, business, migrations string
	businessCount, migrationCount  int
}

func snapshotAcornFoxPostCrossPG(t *testing.T, ctx context.Context, db *pgx.Conn) acornFoxPostCrossPGSnapshot {
	t.Helper()
	var s acornFoxPostCrossPGSnapshot
	// JSONB provides a deterministic object representation; explicit row order
	// preserves every column, NULL, bytea, numeric precision, and timestamp.
	err := db.QueryRow(ctx, `SELECT current_database(),
 jsonb_build_object('accounts', (SELECT jsonb_agg(to_jsonb(a) ORDER BY id) FROM preservation_accounts a),
 'events', (SELECT jsonb_agg(to_jsonb(e) ORDER BY id) FROM preservation_events e))::text,
 (SELECT jsonb_agg(to_jsonb(m) ORDER BY version)::text FROM schema_migrations m),
 (SELECT count(*) FROM preservation_accounts) + (SELECT count(*) FROM preservation_events),
 (SELECT count(*) FROM schema_migrations)`).Scan(&s.database, &s.business, &s.migrations, &s.businessCount, &s.migrationCount)
	if err != nil {
		t.Fatal("complete real PostgreSQL snapshot failed")
	}
	return s
}

func postCrossPGExec(t *testing.T, ctx context.Context, db *pgx.Conn, query string, args ...any) {
	t.Helper()
	if _, err := db.Exec(ctx, query, args...); err != nil {
		t.Fatal("private PostgreSQL fixture SQL failed")
	}
}

type acornFoxPostCrossPG struct {
	socket string
	port   uint16
}

func (pg *acornFoxPostCrossPG) createShadow(t *testing.T, ctx context.Context, dsn, shadow string) {
	t.Helper()
	u, err := url.Parse(dsn)
	if err != nil || u.User == nil || !acornFoxUpgradeShadowName.MatchString(shadow) {
		t.Fatal("invalid synthetic database identity")
	}
	password, ok := u.User.Password()
	if !ok || strings.ContainsAny(password, "'\\\x00") {
		t.Fatal("invalid synthetic password")
	}
	cfg, err := pgx.ParseConfig("")
	if err != nil {
		t.Fatal("private admin configuration failed")
	}
	cfg.Host, cfg.User, cfg.Database, cfg.Password, cfg.Port = pg.socket, "postcrossadmin", "postgres", "", pg.port
	cfg.TLSConfig, cfg.Fallbacks = nil, nil
	admin, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal("private cluster administration connection failed")
	}
	defer admin.Close(context.Background())
	postCrossPGExec(t, ctx, admin, "CREATE ROLE acornfox LOGIN PASSWORD '"+password+"' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS")
	postCrossPGExec(t, ctx, admin, "CREATE DATABASE "+pgx.Identifier{shadow}.Sanitize()+" OWNER acornfox")
}

func startAcornFoxPostCrossPG(t *testing.T) *acornFoxPostCrossPG {
	t.Helper()
	unavailable := func(reason string) {
		if os.Getenv("OPEN_CARD_POST_CROSS_REQUIRE_PG") == "1" {
			t.Fatal(reason)
		}
		t.Skip(reason)
	}
	const bin = "/opt/homebrew/opt/postgresql@16/bin"
	for _, name := range []string{"initdb", "pg_ctl", "postgres"} {
		if info, err := os.Stat(filepath.Join(bin, name)); err != nil || info.Mode()&0o111 == 0 {
			unavailable("private PostgreSQL 16 binaries unavailable")
		}
	}
	listener, err := net.Listen("tcp", "127.0.0.1:5432")
	if err != nil {
		unavailable("canonical loopback port is occupied; existing service was not touched")
	}
	t.Cleanup(func() { listener.Close() })
	root, err := os.MkdirTemp("/tmp", "acornfox-postcross-pg-")
	if err != nil {
		t.Fatal("private PostgreSQL directory creation failed")
	}
	data, socket := filepath.Join(root, "data"), filepath.Join(root, "socket")
	started := false
	t.Cleanup(func() {
		if started {
			ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
			defer cancel()
			if exec.CommandContext(ctx, filepath.Join(bin, "pg_ctl"), "-D", data, "-m", "immediate", "-w", "-t", "30", "stop").Run() != nil {
				t.Error("private PostgreSQL cleanup failed; retaining its directory")
				return
			}
			if _, err := os.Stat(filepath.Join(data, "postmaster.pid")); !os.IsNotExist(err) {
				t.Error("private PostgreSQL process shutdown could not be verified")
				return
			}
		}
		if err := os.RemoveAll(root); err != nil {
			t.Error("private PostgreSQL directory cleanup failed")
		}
	})
	if os.Mkdir(socket, 0o700) != nil {
		t.Fatal("private PostgreSQL socket directory creation failed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if exec.CommandContext(ctx, filepath.Join(bin, "initdb"), "-D", data, "--auth-local=trust", "--auth-host=scram-sha-256", "--no-locale", "--encoding=UTF8", "-U", "postcrossadmin").Run() != nil {
		t.Fatal("private PostgreSQL initialization failed")
	}
	portListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("private PostgreSQL port reservation failed")
	}
	port := portListener.Addr().(*net.TCPAddr).Port
	portListener.Close()
	// The server TCP port is random. Its private socket also uses that port.
	options := fmt.Sprintf("-h 127.0.0.1 -k %s -p %d", socket, port)
	startErr := exec.CommandContext(ctx, filepath.Join(bin, "pg_ctl"), "-D", data, "-l", filepath.Join(root, "postgres.log"), "-o", options, "-w", "-t", "30", "start").Run()
	_, pidErr := os.Stat(filepath.Join(data, "postmaster.pid"))
	started = pidErr == nil
	if startErr != nil || !started {
		t.Fatal("private PostgreSQL startup failed")
	}
	startAcornFoxPostCrossRelay(t, listener, fmt.Sprintf("127.0.0.1:%d", port))
	return &acornFoxPostCrossPG{socket: socket, port: uint16(port)}
}

func startAcornFoxPostCrossRelay(t *testing.T, listener net.Listener, destination string) {
	t.Helper()
	var mu sync.Mutex
	var workers sync.WaitGroup
	connections := make(map[net.Conn]bool)
	stopping := false
	workers.Add(1)
	go func() {
		defer workers.Done()
		for {
			client, err := listener.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			if stopping {
				mu.Unlock()
				client.Close()
				return
			}
			connections[client] = true
			workers.Add(1)
			mu.Unlock()
			go func() {
				defer workers.Done()
				defer client.Close()
				server, err := net.DialTimeout("tcp", destination, 5*time.Second)
				if err != nil {
					return
				}
				defer server.Close()
				mu.Lock()
				if stopping {
					mu.Unlock()
					return
				}
				connections[server] = true
				mu.Unlock()
				done := make(chan struct{})
				go func() { io.Copy(server, client); server.Close(); close(done) }()
				io.Copy(client, server)
				client.Close()
				<-done
				mu.Lock()
				delete(connections, client)
				delete(connections, server)
				mu.Unlock()
			}()
		}
	}()
	t.Cleanup(func() {
		mu.Lock()
		stopping = true
		listener.Close()
		for conn := range connections {
			conn.Close()
		}
		mu.Unlock()
		workers.Wait()
	})
}
