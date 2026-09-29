package unifiedinstall

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/open-card/open-card/internal/acornfoxrelease"
	"github.com/open-card/open-card/internal/artifactio"
)

// UnifiedPrivateStageRoot is separate from active releases and the legacy installer.
// Host setup must create this existing directory as root:root 0700.
const UnifiedPrivateStageRoot = "/var/lib/acornfox/unified-install"

var ErrStageCleanupUnknown = errors.New("unified stage cleanup outcome is unknown")
var ErrStageCommitUnknown = errors.New("unified stage commit outcome is unknown")

// StagedRelease names durable but inactive bytes, not install or publish authority.
type StagedRelease struct {
	Path, ReleaseID, Version, SourceCommit, ManifestSHA256 string
	Artifacts                                              []acornfoxrelease.UnifiedArtifactV1
}

// StageProductionCandidate consumes a full trusted intake into a private root.
// It does not create users, start roles, change current, or touch input offsets.
func StageProductionCandidate(ctx context.Context, input IntakeInput) (StagedRelease, error) {
	return stageProductionCandidateWithPreflight(ctx, input, InspectArtifactCandidate)
}

// The repair caller is package-private and may stage only verified bytes under
// its separate, closed-gate intent. Ordinary production staging still uses the
// full dependency observer above.
func stageProductionRepairBytes(ctx context.Context, input IntakeInput) (StagedRelease, error) {
	return stageProductionCandidateWithPreflight(ctx, input, inspectRepairArtifactCandidate)
}

func stageProductionCandidateWithPreflight(ctx context.Context, input IntakeInput, preflight func(context.Context, IntakeInput) (Preflight, error)) (StagedRelease, error) {
	if preflight == nil {
		return StagedRelease{}, ErrIncomplete
	}
	if os.Geteuid() != 0 || os.Getegid() != 0 {
		return StagedRelease{}, errors.New("root identity is required for production staging")
	}
	for parent := filepath.Dir(UnifiedPrivateStageRoot); ; parent = filepath.Dir(parent) {
		info, err := os.Lstat(parent)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 || artifactio.CheckFileOwner(info, 0, 0) != nil {
			return StagedRelease{}, errors.New("production staging parent is unsafe")
		}
		if parent == "/" {
			break
		}
	}
	return stageCandidateWithPreflight(ctx, input, UnifiedPrivateStageRoot, 0, 0, preflight)
}

// stageCandidate permits disposable same-UID fixtures without exporting that
// capability as a production root-owned staging claim.
func stageCandidate(ctx context.Context, input IntakeInput, privateRoot string, uid, gid int) (result StagedRelease, err error) {
	return stageCandidateWithPreflight(ctx, input, privateRoot, uid, gid, InspectArtifactCandidate)
}

func stageCandidateWithPreflight(ctx context.Context, input IntakeInput, privateRoot string, uid, gid int, preflight func(context.Context, IntakeInput) (Preflight, error)) (result StagedRelease, err error) {
	if preflight == nil || !artifactio.SafeDurableRoot(privateRoot) || uid < 0 || gid < 0 || input.InventoryUID != uid || input.InventoryGID != gid {
		return result, ErrIncomplete
	}
	pre, err := preflight(ctx, input)
	if err != nil {
		return result, err
	}
	snapshot, err := input.Witness.Snapshot()
	if err != nil {
		return result, err
	}
	manifest, err := acornfoxrelease.CanonicalUnifiedManifestV1(snapshot)
	if err != nil {
		return result, err
	}
	sum := sha256.Sum256(manifest)
	if hex.EncodeToString(sum[:]) != pre.ManifestSHA256 {
		return result, ErrIncomplete
	}

	writer, err := artifactio.NewDurableWriter(privateRoot, uid, gid)
	if err != nil {
		return result, err
	}
	if writer.RootInfo().Mode().Perm() != 0700 {
		return result, errors.Join(errors.New("private stage root must be mode 0700"), writer.Close())
	}
	root, err := os.OpenRoot(privateRoot)
	if err != nil {
		return result, errors.Join(err, writer.Close())
	}
	partial, renamed := "", false
	var stage *os.Root
	defer func() {
		if stage != nil {
			err = errors.Join(err, stage.Close())
		}
		if err != nil && partial != "" && !renamed {
			if removeErr := root.RemoveAll(partial); removeErr != nil {
				err = errors.Join(err, ErrStageCleanupUnknown, removeErr)
			} else if syncErr := writer.SyncRoot(); syncErr != nil {
				err = errors.Join(err, ErrStageCleanupUnknown, syncErr)
			}
		}
		if closeErr := root.Close(); closeErr != nil {
			if renamed {
				err = errors.Join(err, ErrStageCommitUnknown, closeErr)
			} else {
				err = errors.Join(err, closeErr)
			}
		}
		if closeErr := writer.Close(); closeErr != nil {
			if renamed {
				err = errors.Join(err, ErrStageCommitUnknown, closeErr)
			} else {
				err = errors.Join(err, closeErr)
			}
		}
		if err != nil {
			result = StagedRelease{}
		}
	}()
	if err := verifyStageDir(root, ".", writer.RootInfo(), uid, gid); err != nil {
		return result, err
	}
	partial, err = artifactio.DurableTempName("", ".partial-")
	if err != nil {
		return result, err
	}
	if err := root.Mkdir(partial, 0700); err != nil {
		partial = ""
		return result, err
	}
	if err := writer.SyncRoot(); err != nil {
		return result, err
	}
	stage, err = root.OpenRoot(partial)
	if err != nil {
		return result, err
	}
	partialInfo, err := root.Lstat(partial)
	if err != nil || !partialInfo.IsDir() || partialInfo.Mode().Perm() != 0700 || artifactio.CheckFileOwner(partialInfo, uid, gid) != nil {
		return result, ErrIncomplete
	}
	if err := verifyStageDir(stage, ".", partialInfo, uid, gid); err != nil {
		return result, err
	}
	if err := stage.Mkdir("payload", 0700); err != nil {
		return result, err
	}
	if err := writeStageFile(ctx, stage, "manifest.json", bytes.NewReader(manifest), int64(len(manifest)), pre.ManifestSHA256, 0600, uid, gid); err != nil {
		return result, err
	}
	entries := make(map[string]ArtifactFile, len(input.Inventory))
	for _, entry := range input.Inventory {
		entries[entry.ArtifactID] = entry
	}
	dirs := map[string]bool{".": true, "payload": true}
	for _, artifact := range pre.Artifacts {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		name := filepath.ToSlash(filepath.Join("payload", artifact.RelativePath))
		if err := artifactio.CleanRelative(name); err != nil {
			return result, err
		}
		if err := stageParents(stage, filepath.Dir(name), uid, gid, dirs); err != nil {
			return result, err
		}
		entry := entries[artifact.ID]
		mode := os.FileMode(0644)
		if artifact.Executable {
			mode = 0755
		}
		before, statErr := entry.File.Stat()
		if statErr != nil || !before.Mode().IsRegular() || before.Mode().Perm() != mode || before.Size() != artifact.SizeBytes || artifactio.CheckFileOwner(before, uid, gid) != nil {
			return result, ErrIncomplete
		}
		reader := io.NewSectionReader(entry.File, 0, artifact.SizeBytes+1)
		if err := writeStageFile(ctx, stage, name, reader, artifact.SizeBytes, artifact.SHA256, mode, uid, gid); err != nil {
			return result, err
		}
		var extra [1]byte
		if n, readErr := reader.Read(extra[:]); n != 0 || readErr != io.EOF {
			return result, ErrIncomplete
		}
		after, statErr := entry.File.Stat()
		if statErr != nil || !os.SameFile(before, after) || before.Size() != after.Size() || before.Mode() != after.Mode() || !before.ModTime().Equal(after.ModTime()) || artifactio.CheckFileOwner(after, uid, gid) != nil {
			return result, ErrIncomplete
		}
	}
	// File data and metadata are synced by writeStageFile; sync directories from
	// leaves to root before exposing a ready entry.
	for len(dirs) != 0 {
		deepest := ""
		for name := range dirs {
			if len(name) > len(deepest) {
				deepest = name
			}
		}
		if err := syncStageDir(stage, deepest, uid, gid); err != nil {
			return result, err
		}
		delete(dirs, deepest)
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if err := writer.VerifyLiveRoot(); err != nil {
		return result, err
	}
	latest, err := root.Lstat(partial)
	if err != nil || !os.SameFile(partialInfo, latest) || latest.Mode().Perm() != 0700 || artifactio.CheckFileOwner(latest, uid, gid) != nil {
		return result, ErrIncomplete
	}
	if err := stage.Close(); err != nil {
		return result, err
	}
	stage = nil
	ready, err := artifactio.DurableTempName("", "ready-")
	if err != nil {
		return result, err
	}
	if _, statErr := root.Lstat(ready); !errors.Is(statErr, os.ErrNotExist) {
		return result, fmt.Errorf("ready entry is not absent: %v", statErr)
	}
	if err := root.Rename(partial, ready); err != nil {
		return result, err
	}
	renamed = true
	if err := writer.SyncRoot(); err != nil {
		return result, errors.Join(ErrStageCommitUnknown, err)
	}
	readyInfo, err := root.Lstat(ready)
	if err != nil || !os.SameFile(partialInfo, readyInfo) || readyInfo.Mode().Perm() != 0700 || artifactio.CheckFileOwner(readyInfo, uid, gid) != nil {
		return result, ErrStageCommitUnknown
	}
	return StagedRelease{Path: filepath.Join(privateRoot, ready), ReleaseID: pre.ReleaseID, Version: pre.Version, SourceCommit: pre.SourceCommit, ManifestSHA256: pre.ManifestSHA256, Artifacts: append([]acornfoxrelease.UnifiedArtifactV1(nil), pre.Artifacts...)}, nil
}

func verifyStageDir(root *os.Root, name string, expected os.FileInfo, uid, gid int) error {
	file, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 || !os.SameFile(info, expected) {
		return ErrIncomplete
	}
	return artifactio.CheckFileOwner(info, uid, gid)
}

func syncStageDir(root *os.Root, name string, uid, gid int) error {
	file, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return ErrIncomplete
	}
	if err := artifactio.CheckFileOwner(info, uid, gid); err != nil {
		return err
	}
	return file.Sync()
}

func stageParents(root *os.Root, directory string, uid, gid int, seen map[string]bool) error {
	if directory == "." {
		return nil
	}
	if err := artifactio.CleanRelative(directory); err != nil {
		return err
	}
	current := ""
	for _, part := range strings.Split(filepath.ToSlash(directory), "/") {
		current = filepath.ToSlash(filepath.Join(current, part))
		if !seen[current] {
			if err := root.Mkdir(current, 0700); err != nil {
				return err
			}
			seen[current] = true
		}
		info, err := root.Lstat(current)
		if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
			return ErrIncomplete
		}
		if err := artifactio.CheckFileOwner(info, uid, gid); err != nil {
			return err
		}
	}
	return nil
}

func writeStageFile(ctx context.Context, root *os.Root, name string, source io.Reader, size int64, digest string, mode os.FileMode, uid, gid int) (err error) {
	file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, mode)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	if err := file.Chmod(mode); err != nil {
		return err
	}
	if err := file.Chown(uid, gid); err != nil {
		return err
	}
	hash := sha256.New()
	n, err := io.CopyN(io.MultiWriter(file, hash), contextReader{ctx, source}, size)
	if err != nil {
		return err
	}
	if n != size || hex.EncodeToString(hash.Sum(nil)) != digest {
		return ErrIncomplete
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != mode || info.Size() != size {
		return ErrIncomplete
	}
	if err := artifactio.CheckFileOwner(info, uid, gid); err != nil {
		return err
	}
	return file.Sync()
}
