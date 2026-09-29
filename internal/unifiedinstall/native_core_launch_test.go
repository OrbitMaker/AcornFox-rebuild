package unifiedinstall

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/open-card/open-card/internal/acornfoxsetup"
	"github.com/open-card/open-card/internal/corehttp"
)

func TestNativeCoreCredentialReaderChild(t *testing.T) {
	if os.Getenv("ACORNFOX_CREDENTIAL_READER_CHILD") != "1" {
		return
	}
	credential := corehttp.AcornFoxSetupCredential(os.Getenv("ACORNFOX_CREDENTIAL_READER_DIR"))
	defer clear(credential)
	switch os.Getenv("ACORNFOX_CREDENTIAL_READER_EXPECT") {
	case "present":
		sum := sha256.Sum256(credential)
		if len(credential) != 44 || hex.EncodeToString(sum[:]) != os.Getenv("ACORNFOX_CREDENTIAL_READER_SHA") {
			t.Fatal("Core credential reader did not return the expected private bytes")
		}
	case "absent":
		if len(credential) != 0 {
			t.Fatal("unrelated role read the Core credential")
		}
	default:
		t.Fatal("invalid credential reader expectation")
	}
}

func TestNativeCoreCredentialProjectionReadableOnlyByCoreGroup(t *testing.T) {
	if os.Geteuid() != 0 || os.Getegid() != 0 {
		t.Skip("root-only real credential projection fixture")
	}
	core, err := user.Lookup("nobody")
	if err != nil {
		t.Skip("nobody account unavailable")
	}
	other, err := user.Lookup("ubuntu")
	if err != nil {
		t.Skip("separate unprivileged account unavailable")
	}
	coreUID, e1 := strconv.ParseUint(core.Uid, 10, 32)
	coreGID, e2 := strconv.ParseUint(core.Gid, 10, 32)
	otherUID, e3 := strconv.ParseUint(other.Uid, 10, 32)
	otherGID, e4 := strconv.ParseUint(other.Gid, 10, 32)
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || coreUID == otherUID || coreGID == otherGID {
		t.Skip("distinct fixture account IDs unavailable")
	}
	projectionRoot := os.Getenv("ACORNFOX_CORE_CREDENTIAL_TEST_ROOT")
	if projectionRoot == "" {
		projectionRoot = "/run"
	}
	rootInfo, err := os.Lstat(projectionRoot)
	if err != nil {
		t.Fatal("credential fixture parent unavailable")
	}
	rootStat, ok := rootInfo.Sys().(*syscall.Stat_t)
	if !filepath.IsAbs(projectionRoot) || filepath.Clean(projectionRoot) != projectionRoot ||
		!rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 || rootInfo.Mode().Perm() != 0o755 || !ok || rootStat.Uid != 0 || rootStat.Gid != 0 {
		t.Fatal("credential fixture parent is not an exact protected root directory")
	}
	parent, err := os.MkdirTemp(projectionRoot, "acornfox-core-credential-test-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(parent, 0, int(otherGID)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0o750); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Remove(parent); err != nil {
			t.Errorf("remove task credential parent: %v", err)
		}
	})
	token, err := acornfoxsetup.GenerateSetupToken(bytes.NewReader(bytes.Repeat([]byte{0x42}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	directory, cleanup, err := projectNativeCoreCredentialAt(token, uint32(coreGID), uint32(otherGID), filepath.Join(parent, "core-credential"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := cleanup(); err != nil {
			t.Errorf("remove exact task credential: %v", err)
		}
	})
	path := filepath.Join(directory, nativeCoreCredentialName)
	dirInfo, err := os.Lstat(directory)
	if err != nil || dirInfo.Mode().Perm() != 0o750 {
		t.Fatal("Core credential projection must give its private group read and search")
	}
	fileInfo, err := os.Lstat(path)
	if err != nil || fileInfo.Mode().Perm() != 0o440 {
		t.Fatal("Core credential file permissions changed")
	}
	testBinary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	execDir, err := os.MkdirTemp(os.TempDir(), "acornfox-core-reader-test-")
	if err != nil {
		t.Fatal(err)
	}
	readerBinary := filepath.Join(execDir, "credential-reader.test")
	t.Cleanup(func() {
		if _, err := os.Lstat(readerBinary); err == nil {
			if err := os.Remove(readerBinary); err != nil {
				t.Errorf("remove exact credential reader test executable: %v", err)
			}
		}
		if err := os.Remove(execDir); err != nil {
			t.Errorf("remove exact credential reader test directory: %v", err)
		}
	})
	if err := os.Chmod(execDir, 0o755); err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(testBinary)
	if err != nil {
		t.Fatal(err)
	}
	target, err := os.OpenFile(readerBinary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o755)
	if err != nil {
		_ = source.Close()
		t.Fatal(err)
	}
	_, copyErr := io.Copy(target, source)
	syncErr := target.Sync()
	closeTargetErr := target.Close()
	closeSourceErr := source.Close()
	if copyErr != nil || syncErr != nil || closeTargetErr != nil || closeSourceErr != nil {
		t.Fatal("copy fixed credential reader test executable")
	}
	if err := os.Chmod(readerBinary, 0o755); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(token)
	read := func(uid, gid uint64, groups []uint32, expectation string) error {
		command := exec.Command(readerBinary, "-test.run=^TestNativeCoreCredentialReaderChild$")
		command.Env = []string{
			"ACORNFOX_CREDENTIAL_READER_CHILD=1",
			"ACORNFOX_CREDENTIAL_READER_DIR=" + directory,
			"ACORNFOX_CREDENTIAL_READER_EXPECT=" + expectation,
			"ACORNFOX_CREDENTIAL_READER_SHA=" + hex.EncodeToString(sum[:]),
		}
		command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: groups}}
		_, err := command.Output()
		return err
	}
	if err := read(coreUID, coreGID, []uint32{uint32(coreGID), uint32(otherGID)}, "present"); err != nil {
		t.Fatal("actual Core credential reader could not read the projection")
	}
	if err := read(otherUID, otherGID, []uint32{uint32(otherGID)}, "absent"); err != nil {
		t.Fatal("unrelated IPC role did not remain excluded from the Core credential")
	}
}

func TestFailedLaunchReservationOutlivesRestoredDatabase(t *testing.T) {
	if os.Geteuid() != 0 || os.Getegid() != 0 {
		t.Skip("root-owned durable reservation fixture requires root; a skipped run is not acceptance")
	}
	directory, err := os.MkdirTemp("/root", "acornfox-core-launch-reservation-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(directory); err != nil {
			t.Errorf("remove root fixture: %v", err)
		}
	})
	const installation = "fixture-installation"
	first, err := nextCoreLaunchGeneration(9, 0)
	if err != nil || first != 10 {
		t.Fatalf("first reservation = %d, %v", first, err)
	}
	if err := saveCoreReservation(directory, nativeCoreReservation{
		InstallationID: installation,
		ReleaseID:      "fixture-release",
		ManifestSHA256: strings.Repeat("a", 64),
		Generation:     first,
		DatabaseInode:  42,
	}); err != nil {
		t.Fatal(err)
	}
	// The child dies before or after Store.Open. An older physical backup
	// restores generation 9. The root journal must be read again from disk;
	// no in-memory high-water is carried into the second reservation.
	highWater, err := readCoreLaunchHighWater(directory, installation)
	if err != nil || highWater != first {
		t.Fatalf("durable reservation readback = %d, %v", highWater, err)
	}
	second, err := nextCoreLaunchGeneration(9, highWater)
	if err != nil || second != 11 {
		t.Fatalf("restored database reused reserved generation: %d, %v", second, err)
	}
	if err := saveCoreReservation(directory, nativeCoreReservation{
		InstallationID: installation,
		ReleaseID:      "fixture-release",
		ManifestSHA256: strings.Repeat("a", 64),
		Generation:     second,
		DatabaseInode:  43,
	}); err != nil {
		t.Fatal(err)
	}
	highWater, err = readCoreLaunchHighWater(directory, installation)
	if err != nil || highWater != second {
		t.Fatalf("second durable reservation readback = %d, %v", highWater, err)
	}
}

func TestPrepareCoreJournalCreatesAndReopensFixedShape(t *testing.T) {
	journal := filepath.Join(t.TempDir(), "core-launch")
	uid, gid := os.Getuid(), os.Getgid()
	if err := prepareCoreJournalAt(journal, uid, gid); err != nil {
		t.Fatalf("first absent journal preparation: %v", err)
	}
	first, err := os.Lstat(journal)
	if err != nil || !first.IsDir() || first.Mode().Perm() != 0o700 {
		t.Fatalf("created journal identity: %v, %v", first, err)
	}
	if err := prepareCoreJournalAt(journal, uid, gid); err != nil {
		t.Fatalf("existing journal readback: %v", err)
	}
	second, err := os.Lstat(journal)
	if err != nil || !os.SameFile(first, second) {
		t.Fatalf("existing journal was replaced: %v", err)
	}
	entries, err := os.ReadDir(journal)
	if err != nil || len(entries) != 0 {
		t.Fatalf("journal readback added unexpected entries: %v, %v", entries, err)
	}
}
