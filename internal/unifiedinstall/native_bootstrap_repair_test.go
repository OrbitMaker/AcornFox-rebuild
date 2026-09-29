package unifiedinstall

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/acornfoxrelease"
	"github.com/open-card/open-card/internal/corelaunch"
	"github.com/open-card/open-card/internal/install"
	"github.com/open-card/open-card/internal/persistence/sqlite"
)

// The repair admission check runs against a private schema-13 database. It
// must never infer that an installed Core database is empty from its age or
// from the absence of an administrator HTTP session.
func TestNativeBootstrapRepairEmptyUserFactsUsesPrivateDatabase(t *testing.T) {
	ctx := context.Background()
	data := filepath.Join(t.TempDir(), "core")
	if err := os.Mkdir(data, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := sqlite.Open(sqlite.Config{DataDirectory: data, DBName: "acornfox.db"})
	if err != nil {
		t.Fatal(err)
	}
	generation := store.CoreGeneration()
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(data, "acornfox.db")
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("database inode unavailable")
	}
	if err := repairEmptyUserFactsAt(ctx, data, stat.Ino, generation, os.Getuid(), os.Getgid()); err != nil {
		t.Fatalf("empty schema-13 database refused: %v", err)
	}
	if err := repairEmptyUserFactsAt(ctx, data, stat.Ino+1, generation, os.Getuid(), os.Getgid()); err == nil {
		t.Fatal("wrong database inode accepted")
	}
	db, err := sql.Open("sqlite", "file:"+url.PathEscape(path)+"?_pragma=journal_mode(WAL)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_, err = db.ExecContext(ctx, `INSERT INTO admin_credentials(id,password_hash_scheme,password_hash,created_at,updated_at) VALUES('admin','argon2id-v1','$x$hash','2026-09-29T00:00:00.000000000Z','2026-09-29T00:00:00.000000000Z')`)
	if err != nil {
		t.Fatal(err)
	}
	if err := repairEmptyUserFactsAt(ctx, data, stat.Ino, generation, os.Getuid(), os.Getgid()); err == nil {
		t.Fatal("administrator fact accepted")
	}
}

func TestNativeBootstrapRepairTypedSystemdConditionReadback(t *testing.T) {
	goodObject := []byte(`{"type":"o","data":["/org/freedesktop/systemd1/unit/acornfox_2dcore_2eservice"]}` + "\n")
	if err := repairValidateCoreUnitObject(goodObject); err != nil {
		t.Fatalf("actual GetUnit object rejected: %v", err)
	}
	for _, raw := range []string{
		`{"type":"s","data":["/org/freedesktop/systemd1/unit/acornfox_2dcore_2eservice"]}`,
		`{"type":"o","data":["/org/freedesktop/systemd1/unit/foreign_2eservice"]}`,
		`{"type":"o","data":["/org/freedesktop/systemd1/unit/acornfox_2dcore_2eservice","/org/freedesktop/systemd1/unit/foreign_2eservice"]}`,
	} {
		if err := repairValidateCoreUnitObject([]byte(raw)); err == nil {
			t.Fatalf("foreign Unit object accepted: %s", raw)
		}
	}
	good := `{"type":"a(sbbsi)","data":[["ConditionPathExists",false,false,"` + bootstrapRepairAuthorizedPath + `",0]]}`
	if err := repairValidateCoreConditions([]byte(good + "\n")); err != nil {
		t.Fatalf("actual Ubuntu systemd255 condition JSON rejected: %v", err)
	}
	for _, result := range []string{"-1", "1"} {
		if err := repairValidateCoreConditions([]byte(strings.Replace(good, `,0]]}`, `,`+result+`]]}`, 1))); err != nil {
			t.Fatalf("legal historical tristate refused: %v", err)
		}
	}
	bad := []string{
		strings.Replace(good, `"a(sbbsi)"`, `"a(ss)"`, 1),
		strings.Replace(good, `"ConditionPathExists",false,false`, `"ConditionPathExists",true,false`, 1),
		strings.Replace(good, `"ConditionPathExists",false,false`, `"ConditionPathExists",false,true`, 1),
		strings.Replace(good, bootstrapRepairAuthorizedPath, "/tmp/foreign-authorization", 1),
		strings.Replace(good, `"ConditionPathExists",false,false`, `"ConditionPathExists","false",false`, 1),
		strings.Replace(good, `"ConditionPathExists",false,false`, `"ConditionPathExists",null,false`, 1),
		strings.Replace(good, `"ConditionPathExists",false,false`, `"ConditionPathExists",false,null`, 1),
		strings.Replace(good, `,0]]}`, `,null]]}`, 1),
		strings.Replace(good, `,0]]}`, `,9]]}`, 1),
		strings.Replace(good, `]]}`, `],["ConditionPathExists",false,false,"`+bootstrapRepairAuthorizedPath+`",0]]}`, 1),
		strings.Replace(good, `,0]]}`, `,0,"extra"]]}`, 1),
	}
	for _, raw := range bad {
		if err := repairValidateCoreConditions([]byte(raw)); err == nil {
			t.Fatalf("unsafe condition readback accepted: %s", raw)
		}
	}
}

func TestNativeBootstrapRepairCoreUIDTicketWALBackupRestore(t *testing.T) {
	if operation := os.Getenv("ACORNFOX_BOOTSTRAP_REPAIR_TEST_CHILD"); operation != "" {
		uid, err := strconv.Atoi(os.Getenv("ACORNFOX_BOOTSTRAP_REPAIR_TEST_UID"))
		if err != nil {
			t.Fatal(err)
		}
		gid, err := strconv.Atoi(os.Getenv("ACORNFOX_BOOTSTRAP_REPAIR_TEST_GID"))
		if err != nil {
			t.Fatal(err)
		}
		check := func(_ context.Context, unitSHA string) error {
			if unitSHA != strings.Repeat("a", 64) {
				return ErrIncomplete
			}
			return nil
		}
		if err := runNativeBootstrapRepairChildAt(context.Background(), operation, os.Stdout, repairChildEnvironment{
			coreUID: uid, coreGID: gid, dataDirectory: os.Getenv("ACORNFOX_BOOTSTRAP_REPAIR_TEST_DATA"),
			backupDirectory: os.Getenv("ACORNFOX_BOOTSTRAP_REPAIR_TEST_BACKUPS"), verifyStopped: check,
		}); err != nil {
			t.Fatal(err)
		}
		// The parent decodes one bounded JSON receipt. The testing package's
		// trailing PASS line is not part of that child protocol.
		os.Exit(0)
	}
	if os.Geteuid() != 0 || os.Getegid() != 0 {
		t.Skip("root-only private Core UID protocol fixture")
	}
	root := os.Getenv("ACORNFOX_BOOTSTRAP_REPAIR_TEST_ROOT")
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		t.Skip("protected task-only executable fixture root not configured")
	}
	rootInfo, err := os.Lstat(root)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode().Perm() != 0o755 {
		t.Fatal("task executable root missing")
	}
	rootStat, ok := rootInfo.Sys().(*syscall.Stat_t)
	if !ok || rootStat.Uid != 0 || rootStat.Gid != 0 {
		t.Fatal("task executable root owner changed")
	}
	account, err := user.Lookup("nobody")
	if err != nil {
		t.Fatal(err)
	}
	uid, e1 := strconv.Atoi(account.Uid)
	gid, e2 := strconv.Atoi(account.Gid)
	if e1 != nil || e2 != nil || uid <= 0 || gid <= 0 {
		t.Fatal("unprivileged fixture identity invalid")
	}
	private, err := os.MkdirTemp(root, "owned-bootstrap-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(private); err != nil {
			t.Errorf("remove exact task fixture: %v", err)
		}
	})
	if err := os.Chmod(private, 0o755); err != nil {
		t.Fatal(err)
	}
	data, backups := filepath.Join(private, "core"), filepath.Join(private, "backups")
	for _, path := range []string{data, backups} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	store, err := sqlite.Open(sqlite.Config{DataDirectory: data, DBName: "acornfox.db"})
	if err != nil {
		t.Fatal(err)
	}
	generation := store.CoreGeneration()
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(data, "acornfox.db")
	db, err := sql.Open("sqlite", "file:"+url.PathEscape(dbPath)+"?_pragma=journal_mode(WAL)&_pragma=synchronous(FULL)")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	defer db.Close()
	if _, err := db.Exec(`INSERT INTO idempotency_records(scope,idempotency_key,request_digest,status,created_at,updated_at) VALUES('repair-fixture','committed-wal','digest','in_progress','2026-09-29T00:00:00.000000000Z','2026-09-29T00:00:00.000000000Z')`); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(dbPath + "-wal"); err != nil || info.Size() == 0 {
		t.Fatal("committed WAL sidecar missing", err)
	}
	for _, path := range []string{data, backups, dbPath, dbPath + "-wal", dbPath + "-shm", filepath.Join(data, "acornfox.lock")} {
		if err := os.Chown(path, uid, gid); err != nil {
			t.Fatal(err)
		}
	}
	info, err := os.Lstat(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("database inode absent")
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	selfBytes, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	helper := filepath.Join(private, "repair-child.test")
	if err := os.WriteFile(helper, selfBytes, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(helper, 0o755); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(selfBytes)
	exeSHA := hex.EncodeToString(sum[:])
	const nonce = "aabbccddeeff00112233445566778899"
	backupName := "backup-" + nonce + ".db"
	call := func(operation string, sourceInode uint64, backup sqlite.NativeOfflineBackupReceipt) []byte {
		t.Helper()
		baseWriter, baseReader, baseCleanup, err := repairTestRootTicket(private, "base-")
		if err != nil {
			t.Fatal(err)
		}
		defer baseCleanup()
		metaWriter, metaReader, metaCleanup, err := repairTestRootTicket(private, "meta-")
		if err != nil {
			t.Fatal(err)
		}
		defer metaCleanup()
		signalRead, signalWrite, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		defer signalRead.Close()
		defer signalWrite.Close()
		challengeRead, challengeWrite, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		defer challengeRead.Close()
		defer challengeWrite.Close()
		replyRead, replyWrite, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		defer replyRead.Close()
		defer replyWrite.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, helper, "-test.run=^TestNativeBootstrapRepairCoreUIDTicketWALBackupRestore$")
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: []uint32{uint32(gid)}}}
		cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C", "ACORNFOX_BOOTSTRAP_REPAIR_TEST_CHILD=" + operation,
			"ACORNFOX_BOOTSTRAP_REPAIR_TEST_UID=" + strconv.Itoa(uid), "ACORNFOX_BOOTSTRAP_REPAIR_TEST_GID=" + strconv.Itoa(gid),
			"ACORNFOX_BOOTSTRAP_REPAIR_TEST_DATA=" + data, "ACORNFOX_BOOTSTRAP_REPAIR_TEST_BACKUPS=" + backups}
		cmd.ExtraFiles = []*os.File{baseReader, signalRead, metaReader, challengeWrite, replyRead}
		var output, stderr bytes.Buffer
		cmd.Stdout = &output
		cmd.Stderr = &stderr
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if cmd.ProcessState == nil {
				_ = cmd.Process.Kill()
				_ = cmd.Wait()
			}
		}()
		_ = baseReader.Close()
		_ = signalRead.Close()
		_ = metaReader.Close()
		_ = challengeWrite.Close()
		_ = replyRead.Close()
		base := corelaunch.Ticket{InstallationID: "fixture-install", ReleaseID: "fixture-new", ManifestSHA256: strings.Repeat("b", 64), ExecutableSHA256: exeSHA,
			DataDirectory: data, DatabaseInode: sourceInode, ChildPID: cmd.Process.Pid, ParentPID: os.Getpid(), CoreUID: uid, Generation: generation}
		metadata := repairChildTicket{Operation: operation, InstallationID: base.InstallationID, Nonce: nonce, NewReleaseID: base.ReleaseID,
			NewManifestSHA256: base.ManifestSHA256, ExpectedUnitSHA256: strings.Repeat("a", 64), DatabaseInode: sourceInode, DatabaseGeneration: generation,
			ChildSHA256: exeSHA, ChildPID: int32(cmd.Process.Pid), ParentPID: int32(os.Getpid()), CoreUID: uid, BackupName: backupName}
		if operation == "restore" {
			metadata.BackupSHA256 = backup.SHA256
			metadata.BackupSizeBytes = backup.SizeBytes
			metadata.BackupGeneration = backup.Generation
			metadata.LaunchHighWater = generation
		}
		for _, item := range []struct {
			file  *os.File
			value any
		}{{baseWriter, base}, {metaWriter, metadata}} {
			raw, err := json.Marshal(item.value)
			if err != nil {
				t.Fatal(err)
			}
			if n, err := item.file.WriteAt(raw, 0); err != nil || n != len(raw) {
				t.Fatal("ticket write failed", err)
			}
			if err := item.file.Sync(); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := signalWrite.Write([]byte{1}); err != nil {
			t.Fatal(err)
		}
		_ = signalWrite.Close()
		decoder := json.NewDecoder(io.LimitReader(challengeRead, 16384))
		encoder := json.NewEncoder(replyWrite)
		want := 2
		if operation == "restore" {
			want = 4
		}
		approved := false
		for i := 1; i <= want; i++ {
			var challenge repairChallenge
			if err := decoder.Decode(&challenge); err != nil || challenge.Sequence != i {
				t.Fatalf("challenge %d missing: %v; stderr=%q", i, err, stderr.String())
			}
			if challenge.Kind == "approve_restore" {
				if operation != "restore" || approved || challenge.Prepared == nil || challenge.Prepared.BackupSHA256 != backup.SHA256 {
					t.Fatal("unbound restore approval")
				}
				preparedRaw, err := json.Marshal(challenge.Prepared)
				if err != nil {
					t.Fatal(err)
				}
				if err := publishHostFile(filepath.Join(private, "restore-quarantined.json"), preparedRaw, 0o600, 0, 0); err != nil {
					t.Fatal(err)
				}
				approved = true
			} else if challenge.Kind != "maintenance" || challenge.Prepared != nil {
				t.Fatal("unexpected maintenance challenge")
			}
			reply := repairChallengeReply{Digest: repairChallengeDigest(nonce, challenge.Nonce, i), Commit: challenge.Kind == "approve_restore"}
			if err := encoder.Encode(reply); err != nil {
				t.Fatal(err)
			}
		}
		_ = replyWrite.Close()
		if err := cmd.Wait(); err != nil {
			t.Fatalf("Core UID %s child failed: %v; stderr=%q", operation, err, stderr.String())
		}
		if operation == "restore" && !approved {
			t.Fatal("restore lacked durable approval challenge")
		}
		return output.Bytes()
	}
	backupRaw := call("backup", stat.Ino, sqlite.NativeOfflineBackupReceipt{})
	var backup sqlite.NativeOfflineBackupReceipt
	if err := json.Unmarshal(backupRaw, &backup); err != nil || backup.SourceDBInode != stat.Ino || backup.Generation != generation {
		t.Fatalf("Core UID backup missing: %v", err)
	}
	backupDB, err := sql.Open("sqlite", "file:"+url.PathEscape(backup.BackupPath)+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer backupDB.Close()
	var count int
	if err := backupDB.QueryRow(`SELECT count(*) FROM idempotency_records WHERE scope='repair-fixture' AND idempotency_key='committed-wal'`).Scan(&count); err != nil || count != 1 {
		t.Fatal("committed WAL row absent from Core UID backup", err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := backupDB.Close(); err != nil {
		t.Fatal(err)
	}
	current, err := os.Lstat(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	currentStat := current.Sys().(*syscall.Stat_t)
	preapproval := bootstrapRepairPhase{DatabaseInode: currentStat.Ino, DatabaseGeneration: generation}
	classifyRoot := filepath.Join(private, "classify")
	if err := os.Mkdir(classifyRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	classifyIntent := bootstrapRepairIntent{Nonce: nonce}
	if classification := repairClassifyUnfinishedRestoreAt(classifyRoot, data, backups, classifyIntent, preapproval, currentStat.Ino, generation); !errors.Is(classification, ErrBootstrapRepairRestoreUnapproved) {
		t.Fatalf("unchanged preapproval state misclassified: %v", classification)
	}
	restoreRaw := call("restore", currentStat.Ino, backup)
	var restored sqlite.NativeOfflineRestoreReceipt
	if err := json.Unmarshal(restoreRaw, &restored); err != nil || restored.OriginalDBInode != currentStat.Ino || restored.SeedGeneration < generation {
		t.Fatalf("Core UID restore missing: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(backups, "quarantine-"+nonce)); err != nil {
		t.Fatal("original SQLite data was not retained in quarantine", err)
	}
	if classification := repairClassifyUnfinishedRestoreAt(classifyRoot, data, backups, classifyIntent, preapproval, currentStat.Ino, generation); !errors.Is(classification, ErrBootstrapRepairRestoreUncertain) {
		t.Fatalf("quarantined replacement misclassified as safe retry: %v", classification)
	}
	intent := bootstrapRepairIntent{InstallationID: "fixture-install", Nonce: nonce, NewManifestSHA256: strings.Repeat("b", 64), LaunchHighWater: generation}
	if err := repairWritePhaseAt(private, intent, "restore-complete", restored.RestoredDBSHA256); err != nil {
		t.Fatal(err)
	}
	recovered, present, err := repairReadCompletedRestoreAt(context.Background(), private, data, backups, intent, uid, gid, NativeBackupProtectedReceipt{Backup: backup})
	if err != nil || !present || recovered.RestoredDBSHA256 != restored.RestoredDBSHA256 || recovered.SeedGeneration != restored.SeedGeneration {
		t.Fatalf("committed restore phase could not be read back safely: %v", err)
	}
}

func repairTestRootTicket(directory, prefix string) (*os.File, *os.File, func(), error) {
	writer, err := os.CreateTemp(directory, prefix)
	if err != nil {
		return nil, nil, nil, err
	}
	if err := writer.Chmod(0o600); err != nil {
		writer.Close()
		return nil, nil, nil, err
	}
	reader, err := os.Open(writer.Name())
	if err != nil {
		writer.Close()
		return nil, nil, nil, err
	}
	cleanup := func() { _ = reader.Close(); _ = writer.Close(); _ = os.Remove(writer.Name()) }
	return writer, reader, cleanup, nil
}

func TestNativeBootstrapRepairResumesExactInactiveReleaseAfterPhaseGap(t *testing.T) {
	ctx := context.Background()
	input, _ := intakeFixture(t)
	stageRoot := filepath.Join(t.TempDir(), "stages")
	if err := os.Mkdir(stageRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	staged, err := stageCandidate(ctx, input, stageRoot, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	stage, err := verifyStagedRelease(ctx, staged.Path, stageRoot, input.TrustedPin, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	d := fixtureNativeHostDeps(t, stageRoot)
	release, err := install.ReleaseDirectory(install.UnifiedReleasesDir, stage.manifest.ReleaseID)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(d.path(install.UnifiedReleasesDir), 0o755); err != nil {
		t.Fatal(err)
	}
	phaseRoot := filepath.Join(t.TempDir(), "phases")
	if err := os.Mkdir(phaseRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	intent := bootstrapRepairIntent{InstallationID: "fixture-install", OldManifestSHA256: strings.Repeat("d", 64), NewReleaseID: stage.manifest.ReleaseID, NewManifestSHA256: stage.sha256}
	if err := repairWritePhaseAt(phaseRoot, intent, "release-install-planned", intent.NewManifestSHA256); err != nil {
		t.Fatal(err)
	}
	// This is the exact interruption point: real immutable copy committed,
	// while the durable release-installed phase has not yet been published.
	if err := installNativeRelease(ctx, d, staged.Path, stage, release); err != nil {
		t.Fatal(err)
	}
	if err := repairInstallInactiveRelease(ctx, intent, staged.Path, stage, release, d, phaseRoot); err != nil {
		t.Fatalf("same intent could not reconcile committed release: %v", err)
	}
	if ok, err := repairReadPhaseAt(phaseRoot, intent, "release-installed", intent.NewManifestSHA256); err != nil || !ok {
		t.Fatal("reconciled phase missing", err)
	}
	if err := repairInstallInactiveRelease(ctx, intent, staged.Path, stage, release, d, phaseRoot); err != nil {
		t.Fatalf("exact replay failed: %v", err)
	}
	if _, err := os.Lstat(d.path(install.UnifiedCurrentSymlink)); !os.IsNotExist(err) {
		t.Fatal("inactive reconciliation changed current")
	}
	if _, err := os.Lstat(d.path(filepath.Join(install.UnifiedCoreDataDir, install.UnifiedDefaultDBName))); !os.IsNotExist(err) {
		t.Fatal("inactive reconciliation touched Core DB")
	}
	oldUnit := []byte("[Service]\nExecStart=/old/core\n")
	newUnit := []byte("[Service]\nExecStart=/new/core\n")
	oldSum := sha256.Sum256(oldUnit)
	newSum := sha256.Sum256(newUnit)
	oldSHA, newSHA := hex.EncodeToString(oldSum[:]), hex.EncodeToString(newSum[:])
	intent.OldUnitSHA256 = oldSHA
	for _, gap := range []string{"backup-complete-old-unit", "unit-committed-old-current"} {
		t.Run(gap, func(t *testing.T) {
			boundary := t.TempDir()
			unitPath := filepath.Join(boundary, "acornfox-core.service")
			unitTemp := filepath.Join(boundary, ".unit.tmp")
			currentPath := filepath.Join(boundary, "current")
			currentTemp := filepath.Join(boundary, ".current.tmp")
			phases := filepath.Join(boundary, "phases")
			if err := os.Mkdir(phases, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := repairWritePhaseAt(phases, intent, "backup-complete", strings.Repeat("c", 64)); err != nil {
				t.Fatal(err)
			}
			initial := oldUnit
			if gap == "unit-committed-old-current" {
				initial = newUnit
				if err := repairWritePhaseAt(phases, intent, "unit-switch-planned", newSHA); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(unitPath, initial, 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("/opt/acornfox/releases/old", currentPath); err != nil {
				t.Fatal(err)
			}
			if err := repairSwitchCoreUnitAndCurrentAt(intent, phases, unitPath, unitTemp, currentPath, currentTemp,
				oldSHA, newUnit, newSHA, "/opt/acornfox/releases/old", "/opt/acornfox/releases/new", os.Getuid()); err != nil {
				t.Fatalf("known phase gap failed to reconcile: %v", err)
			}
			if actual, err := repairFileSHAAt(unitPath, 0o644, os.Getuid(), os.Getgid()); err != nil || actual != newSHA {
				t.Fatal("unit not exact after reconciliation", err)
			}
			if target, err := os.Readlink(currentPath); err != nil || target != "/opt/acornfox/releases/new" {
				t.Fatal("current target not exact", err)
			}
			if err := repairSwitchCoreUnitAndCurrentAt(intent, phases, unitPath, unitTemp, currentPath, currentTemp,
				oldSHA, newUnit, newSHA, "/opt/acornfox/releases/old", "/opt/acornfox/releases/new", os.Getuid()); err != nil {
				t.Fatalf("same intent switch replay failed: %v", err)
			}
			oldPin := input.TrustedPin
			oldPinRaw, err := json.Marshal(oldPin)
			if err != nil {
				t.Fatal(err)
			}
			newPinRaw := []byte(`{"fixture":"new-trusted-pin"}`)
			oldPinSum := sha256.Sum256(oldPinRaw)
			newPinSum := sha256.Sum256(newPinRaw)
			intent.OldPinSHA256 = hex.EncodeToString(oldPinSum[:])
			intent.NewPinSHA256 = hex.EncodeToString(newPinSum[:])
			pinPath := filepath.Join(boundary, "active-pin.json")
			oldPinPath := filepath.Join(boundary, "old-pin.json")
			if err := os.WriteFile(oldPinPath, oldPinRaw, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(pinPath, newPinRaw, 0o600); err != nil {
				t.Fatal(err)
			}
			rollback := repairRollbackPaths{phaseRoot: phases, unit: unitPath, unitTemp: unitTemp, current: currentPath, currentTemp: currentTemp,
				pin: pinPath, pinTemp: filepath.Join(boundary, ".pin.tmp"), oldPin: oldPinPath}
			if gap == "unit-committed-old-current" {
				if err := repairWritePhaseAt(phases, intent, "rollback-unit-planned", oldSHA); err != nil {
					t.Fatal(err)
				}
				if err := repairReplaceCoreUnitAt(unitPath, unitTemp, newSHA, oldUnit, oldSHA, os.Getuid()); err != nil {
					t.Fatal(err)
				}
			}
			if err := repairRollbackOwnedStateAt(intent, rollback, oldUnit, newSHA, "/opt/acornfox/releases/old", "/opt/acornfox/releases/new", oldPin, os.Getuid()); err != nil {
				t.Fatalf("known rollback gap failed: %v", err)
			}
			if err := repairRollbackOwnedStateAt(intent, rollback, oldUnit, newSHA, "/opt/acornfox/releases/old", "/opt/acornfox/releases/new", oldPin, os.Getuid()); err != nil {
				t.Fatalf("completed stopped rollback did not replay: %v", err)
			}
			if actual, err := repairFileSHAAt(unitPath, 0o644, os.Getuid(), os.Getgid()); err != nil || actual != oldSHA {
				t.Fatal("old unit not retained", err)
			}
			if target, err := os.Readlink(currentPath); err != nil || target != "/opt/acornfox/releases/old" {
				t.Fatal("old current not retained", err)
			}
			if actual, err := repairFileSHAAt(pinPath, 0o600, os.Getuid(), os.Getgid()); err != nil || actual != intent.OldPinSHA256 {
				t.Fatal("old trust pin not retained", err)
			}
			if _, err := os.Lstat(d.path(filepath.Join(install.UnifiedCoreDataDir, install.UnifiedDefaultDBName))); !os.IsNotExist(err) {
				t.Fatal("switch gap touched Core DB")
			}
		})
	}
}

func TestNativeBootstrapRepairStagesOnlyTrustedBytesWithPendingRuntimeEvidence(t *testing.T) {
	ctx := context.Background()
	input, _ := intakeFixture(t)
	manifest, err := input.Witness.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	digest, err := input.Witness.ManifestSHA256()
	if err != nil {
		t.Fatal(err)
	}
	intent := bootstrapRepairIntent{BundleID: "acornfox-repair-fixture", NewManifestSHA256: digest, NewReleaseID: manifest.ReleaseID}
	if err := repairStageIntentMatches(intent, "foreign-bundle", digest, manifest.ReleaseID); err == nil {
		t.Fatal("wrong repair intent accepted")
	}
	if err := repairStageIntentMatches(intent, intent.BundleID, digest, manifest.ReleaseID); err != nil {
		t.Fatal(err)
	}
	next, err := input.Witness.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if err := repairSameDependencyRuntime(manifest, next); err != nil {
		t.Fatal("unchanged dependency policy rejected", err)
	}
	member := ""
	for _, dependency := range next.Dependencies {
		if dependency.Name == acornfoxrelease.DependencyBuildKit && len(dependency.RuntimeArtifactIDs) > 0 {
			member = dependency.RuntimeArtifactIDs[0]
		}
	}
	if member == "" {
		t.Fatal("fixture missing BuildKit runtime policy")
	}
	found := false
	for i := range next.Artifacts {
		if next.Artifacts[i].ID == member {
			next.Artifacts[i].SHA256 = strings.Repeat("f", 64)
			found = true
		}
	}
	if !found {
		t.Fatal("fixture referenced runtime artifact missing")
	}
	if err := repairSameDependencyRuntime(manifest, next); err == nil {
		t.Fatal("changed runtime artifact bytes accepted")
	}
	input.Facts.Dependencies = nil
	input.Facts.Roles = nil
	input.Facts.HostUpdate = RoleFact{}
	unit := filepath.Join(t.TempDir(), "acornfox-buildkit.service")
	if err := os.WriteFile(unit, []byte("old owned inactive unit"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := absentOrUnprovedNativeDependency("buildkit", nil, unit); err == nil {
		t.Fatal("ordinary dependency observer accepted installed old unit")
	}
	stageRoot := filepath.Join(t.TempDir(), "stages")
	if err := os.Mkdir(stageRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := stageCandidate(ctx, input, stageRoot, os.Getuid(), os.Getgid()); err == nil {
		t.Fatal("ordinary stage accepted missing actual dependency observations")
	}
	if entries, err := os.ReadDir(stageRoot); err != nil || len(entries) != 0 {
		t.Fatal("ordinary refusal wrote staged bytes", err)
	}
	pre, err := inspectRepairArtifactCandidate(ctx, input)
	if err != nil || len(pre.Dependencies) != 0 {
		t.Fatal("repair preflight invented dependency reuse", err)
	}
	staged, err := stageCandidateWithPreflight(ctx, input, stageRoot, os.Getuid(), os.Getgid(), inspectRepairArtifactCandidate)
	if err != nil || staged.ManifestSHA256 != digest || staged.ReleaseID != manifest.ReleaseID {
		t.Fatal("trusted repair bytes were not staged", err)
	}
	for _, name := range []string{"incoming-old", "backup-receipts", "stage-attempt-result"} {
		if err := os.WriteFile(filepath.Join(stageRoot, name), []byte("retained evidence"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := repairStageReadyAbsentAt(stageRoot, staged.Path); err != nil {
		t.Fatal("unrelated retained stage evidence blocked repair", err)
	}
	extraReady := filepath.Join(stageRoot, "ready-0123456789abcdef0123456789abcdef")
	if err := os.Mkdir(extraReady, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := repairStageReadyAbsentAt(stageRoot, staged.Path); err == nil {
		t.Fatal("second ready directory accepted")
	}
	if err := os.Remove(extraReady); err != nil {
		t.Fatal(err)
	}
	partial := filepath.Join(stageRoot, ".partial-foreign")
	if err := os.Mkdir(partial, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := repairStageReadyAbsentAt(stageRoot, staged.Path); err == nil {
		t.Fatal("retained partial directory accepted")
	}
	if _, err := os.Lstat(filepath.Join(stageRoot, "current")); !os.IsNotExist(err) {
		t.Fatal("byte stage activated a release")
	}
	tamperedRoot := filepath.Join(t.TempDir(), "tampered-stages")
	if err := os.Mkdir(tamperedRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	path := input.Inventory[0].File.Name()
	original, err := os.ReadFile(path)
	if err != nil || len(original) == 0 {
		t.Fatal("fixture artifact unavailable", err)
	}
	mutated := append([]byte(nil), original...)
	mutated[0] ^= 0x1
	if err := os.WriteFile(path, mutated, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := stageCandidateWithPreflight(ctx, input, tamperedRoot, os.Getuid(), os.Getgid(), inspectRepairArtifactCandidate); err == nil {
		t.Fatal("tampered repair artifact accepted")
	}
	if entries, err := os.ReadDir(tamperedRoot); err != nil || len(entries) != 0 {
		t.Fatal("tampered input wrote staged bytes", err)
	}
}
