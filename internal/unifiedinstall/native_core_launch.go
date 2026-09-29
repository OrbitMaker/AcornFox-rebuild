package unifiedinstall

import (
	"bytes"
	"context"
	"crypto/rand"
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

	"github.com/open-card/open-card/internal/acornfoxrelease"
	"github.com/open-card/open-card/internal/acornfoxsetup"
	"github.com/open-card/open-card/internal/artifactio"
	"github.com/open-card/open-card/internal/corelaunch"
	"github.com/open-card/open-card/internal/install"
	"github.com/open-card/open-card/internal/localpeer"
	"github.com/open-card/open-card/internal/persistence/sqlite"
	"golang.org/x/sys/unix"
)

const nativeCoreJournal = UnifiedPrivateStageRoot + "/core-launch"

var ErrNativeCoreLaunchUnknown = errors.New("Native Core launch reservation outcome is unknown")

type nativeCoreReservation struct {
	InstallationID string `json:"installation_id"`
	ReleaseID      string `json:"release_id"`
	ManifestSHA256 string `json:"manifest_sha256"`
	Generation     int64  `json:"generation"`
	DatabaseInode  uint64 `json:"database_inode"`
}

// LaunchNativeCore is an explicit root-owned Native entrypoint, not the legacy
// PostgreSQL managed-child path. It supervises exactly the trusted Core binary.
// There is presently no installed Native systemd unit to invoke it.
func LaunchNativeCore(ctx context.Context, stagePath string, receipt io.Writer) (returnedErr error) {
	if ctx == nil || os.Geteuid() != 0 || os.Getegid() != 0 || filepath.Dir(stagePath) != UnifiedPrivateStageRoot || filepath.Clean(stagePath) != stagePath {
		return ErrIncomplete
	}
	if receipt == nil {
		return ErrIncomplete
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	var pin acornfoxrelease.TrustedReleasePinV1
	if err := readProtectedPublisherJSON(UnifiedTrustedPinPath, 4096, &pin); err != nil {
		return err
	}
	var installation struct {
		ID string `json:"installation_id"`
	}
	if err := readProtectedPublisherJSON(UnifiedInstallationIDPath, 1024, &installation); err != nil || len(installation.ID) < 8 || len(installation.ID) > 128 || strings.ContainsAny(installation.ID, "/\\\x00 \t\r\n") {
		return ErrIncomplete
	}
	stage, err := reopenProductionStage(ctx, stagePath, pin)
	if err != nil {
		return err
	}
	updater, err := componentArtifact(stage.manifest, stage.manifest.Components.HostUpdate.ArtifactID)
	if err != nil || updater.RelativePath != "bin/acornfox-host-update" {
		return ErrIncomplete
	}
	self, err := localpeer.AttestLinuxProcess(int32(os.Getpid()))
	if err != nil {
		return err
	}
	updaterPath := filepath.Join(install.UnifiedReleasesDir, stage.manifest.ReleaseID, updater.RelativePath)
	if self.UID != 0 || self.ExecutablePath != updaterPath || self.ExecutableSHA256 != updater.SHA256 {
		return ErrIncomplete
	}
	core, err := componentArtifact(stage.manifest, stage.manifest.Components.Core.ArtifactID)
	if err != nil || core.RelativePath != "bin/acornfox-core" {
		return ErrIncomplete
	}
	compiled := sqlite.CompiledNativeMigrationPins()
	if len(stage.manifest.SQLiteCompatibility.RequiredMigrations) != len(compiled) {
		return ErrIncompatible
	}
	for i, p := range compiled {
		if stage.manifest.SQLiteCompatibility.RequiredMigrations[i].Version != p.Version || stage.manifest.SQLiteCompatibility.RequiredMigrations[i].Checksum != p.Checksum {
			return ErrIncompatible
		}
	}
	release, err := install.ReleaseDirectory(install.UnifiedReleasesDir, stage.manifest.ReleaseID)
	if err != nil {
		return err
	}
	currentPointer, err := os.Lstat(install.UnifiedCurrentSymlink)
	if err != nil || currentPointer.Mode()&os.ModeSymlink == 0 || artifactio.CheckFileOwner(currentPointer, 0, 0) != nil {
		return ErrIncomplete
	}
	link, err := os.Readlink(install.UnifiedCurrentSymlink)
	if err != nil {
		return err
	}
	if !filepath.IsAbs(link) {
		link = filepath.Join(filepath.Dir(install.UnifiedCurrentSymlink), link)
	}
	if filepath.Clean(link) != release {
		return ErrIncomplete
	}
	executable := filepath.Join(release, core.RelativePath)
	if err := verifyNativeCoreBinary(executable, core.SHA256); err != nil {
		return err
	}
	uid, gid, err := resolvedRoleOwner(install.AccountCore)
	if err != nil {
		return err
	}
	setupToken, err := readNativeCoreSystemdCredential()
	if err != nil {
		return err
	}
	defer clear(setupToken)
	ipcGroup, err := user.LookupGroup(install.AccountPeerIPC)
	if err != nil {
		return err
	}
	ipcNumber, err := strconv.ParseUint(ipcGroup.Gid, 10, 32)
	if err != nil || ipcNumber == 0 {
		return ErrIncomplete
	}
	ipcGID := uint32(ipcNumber)
	if err := verifyRootRunAncestor(UnifiedPrivateStageRoot); err != nil {
		return err
	}
	if err := prepareCoreJournal(); err != nil {
		return err
	}
	lock, err := os.OpenFile(filepath.Join(nativeCoreJournal, "launch.lock"), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if info, err := lock.Stat(); err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || artifactio.CheckFileOwner(info, 0, 0) != nil {
		return ErrIncomplete
	}
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return ErrIncomplete
	}
	defer unix.Flock(int(lock.Fd()), unix.LOCK_UN)
	current, inode, err := readCoreGenerationOnly(ctx, compiled, uid, gid)
	if err != nil {
		return err
	}
	high, err := readCoreLaunchHighWater(nativeCoreJournal, installation.ID)
	if err != nil {
		return err
	}
	reserved, err := nextCoreLaunchGeneration(current, high)
	if err != nil {
		return err
	}
	record := nativeCoreReservation{installation.ID, stage.manifest.ReleaseID, stage.sha256, reserved, inode}
	if err := saveCoreReservation(nativeCoreJournal, record); err != nil {
		return errors.Join(ErrNativeCoreLaunchUnknown, err)
	}
	credentialDir, removeCredential, err := projectNativeCoreCredential(setupToken, gid, ipcGID)
	if err != nil {
		return errors.Join(ErrNativeCoreLaunchUnknown, err)
	}
	defer func() {
		if cleanupErr := removeCredential(); cleanupErr != nil {
			returnedErr = errors.Join(returnedErr, ErrNativeCoreLaunchUnknown, cleanupErr)
		}
	}()
	// A failed child never removes this reservation. Future launches must pass it.
	ticketFile, err := os.CreateTemp(nativeCoreJournal, "ticket-")
	if err != nil {
		return errors.Join(ErrNativeCoreLaunchUnknown, err)
	}
	defer func() { ticketFile.Close(); os.Remove(ticketFile.Name()) }()
	if err := ticketFile.Chmod(0600); err != nil {
		return errors.Join(ErrNativeCoreLaunchUnknown, err)
	}
	childTicket, err := os.OpenFile(ticketFile.Name(), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return errors.Join(ErrNativeCoreLaunchUnknown, err)
	}
	defer childTicket.Close()
	readyRead, readyWrite, err := os.Pipe()
	if err != nil {
		return errors.Join(ErrNativeCoreLaunchUnknown, err)
	}
	defer readyRead.Close()
	defer readyWrite.Close()
	cmd := exec.CommandContext(ctx, executable,
		"-data-dir", install.UnifiedCoreDataDir,
		"-db-name", install.UnifiedDefaultDBName,
		"-credentials-dir", credentialDir,
		"-web-root", filepath.Join(release, "web"),
		"-container-binding", UnifiedRuntimeBindingPath,
		"-socket-gid", strconv.FormatUint(uint64(ipcGID), 10),
		"-native-launch-ticket-fd", "3",
		"-native-launch-signal-fd", "4")
	cmd.ExtraFiles = []*os.File{childTicket, readyRead}
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	cmd.Dir = "/"
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: gid, Groups: []uint32{gid, ipcGID}}}
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return errors.Join(ErrNativeCoreLaunchUnknown, err)
	}
	_ = readyRead.Close()
	ticket := corelaunch.Ticket{InstallationID: installation.ID, ReleaseID: stage.manifest.ReleaseID, ManifestSHA256: stage.sha256, ExecutableSHA256: core.SHA256, DataDirectory: install.UnifiedCoreDataDir, DatabaseInode: inode, ChildPID: cmd.Process.Pid, ParentPID: os.Getpid(), CoreUID: int(uid), Generation: reserved}
	raw, err := json.Marshal(ticket)
	if err == nil && len(raw) <= 4096 {
		_, err = ticketFile.WriteAt(raw, 0)
		if err == nil {
			err = ticketFile.Sync()
		}
	} else if err == nil {
		err = ErrIncomplete
	}
	if err != nil {
		readyWrite.Close()
		_ = cmd.Wait()
		return errors.Join(ErrNativeCoreLaunchUnknown, err)
	}
	if err := json.NewEncoder(receipt).Encode(struct {
		CorePID            int    `json:"core_pid"`
		ReservedGeneration int64  `json:"reserved_generation"`
		ReleaseID          string `json:"release_id"`
	}{cmd.Process.Pid, reserved, stage.manifest.ReleaseID}); err != nil {
		readyWrite.Close()
		_ = cmd.Wait()
		return errors.Join(ErrNativeCoreLaunchUnknown, err)
	}
	if _, err := readyWrite.Write([]byte{1}); err != nil {
		readyWrite.Close()
		_ = cmd.Wait()
		return errors.Join(ErrNativeCoreLaunchUnknown, err)
	}
	_ = readyWrite.Close()
	if err := cmd.Wait(); err != nil {
		return errors.Join(ErrNativeCoreLaunchUnknown, err)
	}
	return nil
}

const nativeCoreCredentialDirectory = "/run/acornfox/core-credential"
const nativeCoreCredentialName = "acornfox-setup-token"

// systemd gives the root launcher a private credential. Core runs under a
// different UID, so the launcher must make a narrower, short-lived projection.
func readNativeCoreSystemdCredential() ([]byte, error) {
	const directory = "/run/credentials/acornfox-core.service"
	if os.Getenv("CREDENTIALS_DIRECTORY") != directory || verifyRootRunAncestor(filepath.Join(directory, nativeCoreCredentialName)) != nil {
		return nil, ErrIncomplete
	}
	path := filepath.Join(directory, nativeCoreCredentialName)
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm() != 0o400 && before.Mode().Perm() != 0o440 || before.Size() != 44 || artifactio.CheckFileOwner(before, 0, 0) != nil {
		return nil, ErrIncomplete
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return nil, ErrIncomplete
	}
	token, err := io.ReadAll(io.LimitReader(file, 45))
	if err != nil || len(token) != 44 || acornfoxsetup.ValidateSetupToken(token) != nil {
		clear(token)
		return nil, ErrIncomplete
	}
	return token, nil
}

func projectNativeCoreCredential(token []byte, coreGID, ipcGID uint32) (string, func() error, error) {
	return projectNativeCoreCredentialAt(token, coreGID, ipcGID, nativeCoreCredentialDirectory)
}

// The private test path exercises the same file operations. Production can
// select only nativeCoreCredentialDirectory and refuses any existing leaf.
func projectNativeCoreCredentialAt(token []byte, coreGID, ipcGID uint32, directory string) (out string, cleanup func() error, returnedErr error) {
	parent := filepath.Dir(directory)
	if coreGID == 0 || ipcGID == 0 || coreGID == ipcGID || acornfoxsetup.ValidateSetupToken(token) != nil || !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || verifyRootRunAncestor(parent) != nil {
		return "", nil, ErrIncomplete
	}
	parentInfo, err := os.Lstat(parent)
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 || parentInfo.Mode().Perm() != 0o750 || artifactio.CheckFileOwner(parentInfo, 0, int(ipcGID)) != nil {
		return "", nil, ErrIncomplete
	}
	if _, err := os.Lstat(directory); err == nil || !os.IsNotExist(err) {
		return "", nil, ErrIncomplete
	}
	if err := os.Mkdir(directory, 0o700); err != nil {
		return "", nil, err
	}
	createdDir, err := os.Lstat(directory)
	if err != nil {
		return "", nil, ErrNativeCoreLaunchUnknown
	}
	path := filepath.Join(directory, nativeCoreCredentialName)
	var createdFile os.FileInfo
	defer func() {
		if returnedErr == nil {
			return
		}
		if createdFile != nil {
			if current, e := os.Lstat(path); e == nil && os.SameFile(current, createdFile) {
				_ = os.Remove(path)
			}
		}
		if current, e := os.Lstat(directory); e == nil && os.SameFile(current, createdDir) {
			_ = os.Remove(directory)
		}
	}()
	if err := os.Chown(directory, 0, int(coreGID)); err != nil {
		return "", nil, errors.Join(ErrNativeCoreLaunchUnknown, err)
	}
	// Core's credential reader opens the directory read-only before opening
	// the file, so its private group needs read and search on this directory.
	if err := os.Chmod(directory, 0o750); err != nil {
		return "", nil, errors.Join(ErrNativeCoreLaunchUnknown, err)
	}
	dirInfo, err := os.Lstat(directory)
	if err != nil || !dirInfo.IsDir() || dirInfo.Mode().Perm() != 0o750 || artifactio.CheckFileOwner(dirInfo, 0, int(coreGID)) != nil {
		return "", nil, ErrNativeCoreLaunchUnknown
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return "", nil, errors.Join(ErrNativeCoreLaunchUnknown, err)
	}
	createdFile, _ = file.Stat()
	if err := file.Chown(0, int(coreGID)); err != nil {
		_ = file.Close()
		return "", nil, errors.Join(ErrNativeCoreLaunchUnknown, err)
	}
	if err := file.Chmod(0o440); err != nil {
		_ = file.Close()
		return "", nil, errors.Join(ErrNativeCoreLaunchUnknown, err)
	}
	if n, err := file.Write(token); err != nil || n != len(token) {
		_ = file.Close()
		return "", nil, errors.Join(ErrNativeCoreLaunchUnknown, err, io.ErrShortWrite)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return "", nil, errors.Join(ErrNativeCoreLaunchUnknown, err)
	}
	fileInfo, err := file.Stat()
	closeErr := file.Close()
	if err != nil || closeErr != nil || !fileInfo.Mode().IsRegular() || fileInfo.Mode().Perm() != 0o440 || artifactio.CheckFileOwner(fileInfo, 0, int(coreGID)) != nil {
		return "", nil, ErrNativeCoreLaunchUnknown
	}
	if err := artifactio.SyncDirectory(directory); err != nil {
		return "", nil, errors.Join(ErrNativeCoreLaunchUnknown, err)
	}
	if err := artifactio.SyncDirectory(filepath.Dir(directory)); err != nil {
		return "", nil, errors.Join(ErrNativeCoreLaunchUnknown, err)
	}
	observed, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return "", nil, ErrNativeCoreLaunchUnknown
	}
	readback, readErr := io.ReadAll(io.LimitReader(observed, 45))
	opened, statErr := observed.Stat()
	closeErr = observed.Close()
	validReadback := readErr == nil && statErr == nil && closeErr == nil && os.SameFile(fileInfo, opened) && bytes.Equal(readback, token)
	clear(readback)
	if !validReadback {
		return "", nil, ErrNativeCoreLaunchUnknown
	}
	remove := func() error {
		currentDir, err := os.Lstat(directory)
		if err != nil || !os.SameFile(dirInfo, currentDir) {
			return ErrNativeCoreLaunchUnknown
		}
		currentFile, err := os.Lstat(path)
		if err != nil || !os.SameFile(fileInfo, currentFile) {
			return ErrNativeCoreLaunchUnknown
		}
		if err := os.Remove(path); err != nil {
			return errors.Join(ErrNativeCoreLaunchUnknown, err)
		}
		if err := os.Remove(directory); err != nil {
			return errors.Join(ErrNativeCoreLaunchUnknown, err)
		}
		if err := artifactio.SyncDirectory(filepath.Dir(directory)); err != nil {
			return errors.Join(ErrNativeCoreLaunchUnknown, err)
		}
		return nil
	}
	return directory, remove, nil
}

func nextCoreLaunchGeneration(current, high int64) (int64, error) {
	if current < 0 || high < 0 || current >= 9223372036854775806 || high >= 9223372036854775806 {
		return 0, ErrIncomplete
	}
	if current > high {
		high = current
	}
	return high + 1, nil
}

func verifyNativeCoreBinary(path, digest string) error {
	if err := verifyRootRunAncestor(path); err != nil {
		return err
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm()&0111 == 0 || artifactio.CheckFileOwner(before, 0, 0) != nil {
		return ErrIncomplete
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return ErrIncomplete
	}
	h := sha256.New()
	if _, err := io.Copy(h, file); err != nil || hex.EncodeToString(h.Sum(nil)) != digest {
		return ErrIncomplete
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(before, after) || artifactio.CheckFileOwner(after, 0, 0) != nil {
		return ErrIncomplete
	}
	return nil
}

func prepareCoreJournal() error {
	return prepareCoreJournalAt(nativeCoreJournal, 0, 0)
}

func prepareCoreJournalAt(path string, uid, gid int) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		if err := os.Mkdir(path, 0700); err != nil {
			return err
		}
		parent, openErr := os.Open(filepath.Dir(path))
		if openErr != nil {
			return openErr
		}
		defer parent.Close()
		if syncErr := parent.Sync(); syncErr != nil {
			return syncErr
		}
		info, err = os.Lstat(path)
	}
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 || artifactio.CheckFileOwner(info, uid, gid) != nil {
		return ErrIncomplete
	}
	return nil
}

func readCoreGenerationOnly(ctx context.Context, pins []sqlite.NativeMigrationPin, uid, gid uint32) (int64, uint64, error) {
	if err := verifyRootRunAncestor(install.UnifiedCoreDataDir); err != nil {
		return 0, 0, err
	}
	directory, err := os.Lstat(install.UnifiedCoreDataDir)
	if err != nil || !directory.IsDir() || directory.Mode()&os.ModeSymlink != 0 || directory.Mode().Perm() != 0700 || artifactio.CheckFileOwner(directory, int(uid), int(gid)) != nil {
		return 0, 0, ErrIncomplete
	}
	path := filepath.Join(install.UnifiedCoreDataDir, install.UnifiedDefaultDBName)
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		for _, suffix := range []string{"-wal", "-shm"} {
			if _, sidecarErr := os.Lstat(path + suffix); !os.IsNotExist(sidecarErr) {
				return 0, 0, ErrIncomplete
			}
		}
		return 0, 0, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return 0, 0, ErrIncomplete
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, ErrIncomplete
	}
	core, err := user.Lookup(install.AccountCore)
	if err != nil {
		return 0, 0, err
	}
	parsedUID, err := strconv.ParseUint(core.Uid, 10, 32)
	if err != nil || stat.Uid != uint32(parsedUID) || uint32(parsedUID) != uid {
		return 0, 0, ErrIncomplete
	}
	lockPath := filepath.Join(install.UnifiedCoreDataDir, "acornfox.lock")
	lockFD, err := unix.Open(lockPath, unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return 0, 0, ErrIncomplete
	}
	defer unix.Close(lockFD)
	var lockStat unix.Stat_t
	if unix.Fstat(lockFD, &lockStat) != nil || lockStat.Mode&unix.S_IFMT != unix.S_IFREG || lockStat.Mode&0777 != 0600 || lockStat.Uid != uint32(uid) || lockStat.Nlink != 1 {
		return 0, 0, ErrIncomplete
	}
	if err := unix.Flock(lockFD, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return 0, 0, ErrIncomplete
	}
	defer unix.Flock(lockFD, unix.LOCK_UN)
	db, err := sql.Open("sqlite", "file:"+url.PathEscape(path)+"?mode=ro&_pragma=query_only(ON)")
	if err != nil {
		return 0, 0, err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	var gen int64
	if err := db.QueryRowContext(ctx, "SELECT generation FROM core_generation WHERE singleton=1").Scan(&gen); err != nil || gen < 0 {
		return 0, 0, ErrIncompatible
	}
	rows, err := db.QueryContext(ctx, "SELECT version,checksum FROM _schema_migrations ORDER BY version")
	if err != nil {
		return 0, 0, err
	}
	defer rows.Close()
	for _, pin := range pins {
		if !rows.Next() {
			return 0, 0, ErrIncompatible
		}
		var version, checksum string
		if rows.Scan(&version, &checksum) != nil || version != pin.Version || checksum != pin.Checksum {
			return 0, 0, ErrIncompatible
		}
	}
	if rows.Next() || rows.Err() != nil {
		return 0, 0, ErrIncompatible
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(info, after) {
		return 0, 0, ErrIncomplete
	}
	return gen, stat.Ino, nil
}

func readCoreLaunchHighWater(directory, installationID string) (int64, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return 0, err
	}
	var high int64
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), "reservation-") {
			continue
		}
		if len(entry.Name()) != len("reservation-")+32 || entry.IsDir() {
			return 0, ErrIncomplete
		}
		var record nativeCoreReservation
		if err := readProtectedPublisherJSON(filepath.Join(directory, entry.Name()), 4096, &record); err != nil {
			return 0, err
		}
		if record.InstallationID != installationID || record.Generation < 1 || record.Generation >= 9223372036854775807 || len(record.ManifestSHA256) != 64 {
			return 0, ErrIncomplete
		}
		if record.Generation > high {
			high = record.Generation
		}
	}
	return high, nil
}

func saveCoreReservation(directory string, record nativeCoreReservation) error {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	raw, err := json.Marshal(record)
	if err != nil {
		return err
	}
	dir, err := os.OpenRoot(directory)
	if err != nil {
		return err
	}
	defer dir.Close()
	temp := "pending-" + hex.EncodeToString(nonce[:])
	final := "reservation-" + hex.EncodeToString(nonce[:])
	file, err := dir.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	if _, err := file.Write(raw); err != nil {
		file.Close()
		dir.Remove(temp)
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		dir.Remove(temp)
		return err
	}
	if err := file.Close(); err != nil {
		dir.Remove(temp)
		return err
	}
	if err := dir.Link(temp, final); err != nil {
		dir.Remove(temp)
		return err
	}
	if err := dir.Remove(temp); err != nil {
		return err
	}
	directoryFile, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer directoryFile.Close()
	if err := directoryFile.Sync(); err != nil {
		return err
	}
	return nil
}
