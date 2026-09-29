package unifiedinstall

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"github.com/open-card/open-card/internal/acornfoxrelease"
	"github.com/open-card/open-card/internal/artifactio"
)

// verifiedStage is derived again from protected bytes; a StagedRelease path or
// its caller-provided receipt never becomes cross-process publish authority.
type verifiedStage struct {
	manifest acornfoxrelease.UnifiedReleaseManifestV1
	sha256   string
}

func reopenProductionStage(ctx context.Context, path string, pin acornfoxrelease.TrustedReleasePinV1) (verifiedStage, error) {
	if err := verifyRootRunAncestor(UnifiedPrivateStageRoot); err != nil {
		return verifiedStage{}, err
	}
	return verifyStagedRelease(ctx, path, UnifiedPrivateStageRoot, pin, 0, 0)
}

func verifyStagedRelease(ctx context.Context, path, privateRoot string, pin acornfoxrelease.TrustedReleasePinV1, uid, gid int) (verifiedStage, error) {
	var zero verifiedStage
	if ctx == nil {
		return zero, ErrIncomplete
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	if !artifactio.SafeDurableRoot(privateRoot) || !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Dir(path) != privateRoot || !strings.HasPrefix(filepath.Base(path), "ready-") {
		return zero, ErrIncomplete
	}
	parentInfo, err := os.Lstat(privateRoot)
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 || parentInfo.Mode().Perm() != 0700 || artifactio.CheckFileOwner(parentInfo, uid, gid) != nil {
		return zero, ErrIncomplete
	}
	before, err := os.Lstat(path)
	if err != nil || !before.IsDir() || before.Mode()&os.ModeSymlink != 0 || before.Mode().Perm() != 0700 || artifactio.CheckFileOwner(before, uid, gid) != nil {
		return zero, ErrIncomplete
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return zero, err
	}
	defer root.Close()
	if err := verifyStageDir(root, ".", before, uid, gid); err != nil {
		return zero, err
	}
	manifestFile, err := root.OpenFile("manifest.json", os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return zero, err
	}
	info, err := manifestFile.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() < 1 || info.Size() > 64<<10 || artifactio.CheckFileOwner(info, uid, gid) != nil {
		_ = manifestFile.Close()
		return zero, ErrIncomplete
	}
	raw, readErr := io.ReadAll(io.LimitReader(contextReader{ctx, manifestFile}, 64<<10+1))
	closeErr := manifestFile.Close()
	if readErr != nil || closeErr != nil || int64(len(raw)) != info.Size() {
		return zero, ErrIncomplete
	}
	witness, err := acornfoxrelease.ParseUnifiedManifestV1(raw)
	if err != nil {
		return zero, err
	}
	if err := acornfoxrelease.VerifyUnifiedManifestTrust(witness, pin); err != nil {
		return zero, err
	}
	manifest, err := witness.Snapshot()
	if err != nil {
		return zero, err
	}
	digest, err := witness.ManifestSHA256()
	if err != nil {
		return zero, err
	}
	wanted := make(map[string]acornfoxrelease.UnifiedArtifactV1, len(manifest.Artifacts))
	for _, item := range manifest.Artifacts {
		wanted[item.RelativePath] = item
	}
	seen := make(map[string]bool, len(wanted))
	if err := verifyStageTree(ctx, root, "payload", wanted, seen, uid, gid, 0); err != nil {
		return zero, err
	}
	if len(seen) != len(wanted) {
		return zero, ErrIncomplete
	}
	entries, err := readStageEntries(root, ".", uid, gid)
	if err != nil || len(entries) != 2 || entries[0] != "manifest.json" || entries[1] != "payload" {
		return zero, ErrIncomplete
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(before, after) || after.Mode().Perm() != 0700 || artifactio.CheckFileOwner(after, uid, gid) != nil {
		return zero, ErrIncomplete
	}
	parentAfter, err := os.Lstat(privateRoot)
	if err != nil || !os.SameFile(parentInfo, parentAfter) || artifactio.CheckFileOwner(parentAfter, uid, gid) != nil {
		return zero, ErrIncomplete
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	return verifiedStage{manifest: manifest, sha256: digest}, nil
}

func readStageEntries(root *os.Root, directory string, uid, gid int) ([]string, error) {
	file, err := root.OpenFile(directory, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	info, statErr := file.Stat()
	if statErr != nil || !info.IsDir() || info.Mode().Perm() != 0700 || artifactio.CheckFileOwner(info, uid, gid) != nil {
		_ = file.Close()
		return nil, ErrIncomplete
	}
	items, readErr := file.ReadDir(-1)
	closeErr := file.Close()
	if readErr != nil || closeErr != nil {
		return nil, ErrIncomplete
	}
	names := make([]string, 0, len(items))
	for _, item := range items {
		names = append(names, item.Name())
	}
	slices.Sort(names)
	return names, nil
}

func verifyStageTree(ctx context.Context, root *os.Root, directory string, wanted map[string]acornfoxrelease.UnifiedArtifactV1, seen map[string]bool, uid, gid, depth int) error {
	if depth > 16 {
		return ErrIncomplete
	}
	names, err := readStageEntries(root, directory, uid, gid)
	if err != nil {
		return err
	}
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return err
		}
		rel := filepath.ToSlash(filepath.Join(directory, name))
		if err := artifactio.CleanRelative(rel); err != nil {
			return err
		}
		info, err := root.Lstat(rel)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || artifactio.CheckFileOwner(info, uid, gid) != nil {
			return ErrIncomplete
		}
		if info.IsDir() {
			if info.Mode().Perm() != 0700 {
				return ErrIncomplete
			}
			prefix := strings.TrimPrefix(rel, "payload/") + "/"
			referenced := false
			for path := range wanted {
				if strings.HasPrefix(path, prefix) {
					referenced = true
					break
				}
			}
			if !referenced {
				return ErrIncomplete
			}
			if err := verifyStageTree(ctx, root, rel, wanted, seen, uid, gid, depth+1); err != nil {
				return err
			}
			continue
		}
		artifactPath := strings.TrimPrefix(rel, "payload/")
		item, ok := wanted[artifactPath]
		if !ok || seen[artifactPath] || !info.Mode().IsRegular() {
			return ErrIncomplete
		}
		mode := os.FileMode(0644)
		if item.Executable {
			mode = 0755
		}
		if info.Mode().Perm() != mode || info.Size() != item.SizeBytes {
			return ErrIncomplete
		}
		file, err := root.OpenFile(rel, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return err
		}
		opened, statErr := file.Stat()
		if statErr != nil || !os.SameFile(info, opened) || artifactio.CheckFileOwner(opened, uid, gid) != nil {
			_ = file.Close()
			return ErrIncomplete
		}
		reader, err := artifactio.NewExactArchiveReader(contextReader{ctx, io.NewSectionReader(file, 0, item.SizeBytes+1)}, item.SizeBytes, item.SizeBytes)
		if err != nil {
			_ = file.Close()
			return err
		}
		verifyErr := artifactio.VerifyArchiveMember(reader, item.SizeBytes, nil, item.SHA256, nil, item.RelativePath, uint32(mode))
		if verifyErr == nil {
			verifyErr = reader.Finish(item.SHA256)
		}
		closed := file.Close()
		if verifyErr != nil || closed != nil {
			return errors.Join(verifyErr, closed)
		}
		seen[artifactPath] = true
	}
	return nil
}

func stageRoleArtifact(m acornfoxrelease.UnifiedReleaseManifestV1, role string) (acornfoxrelease.UnifiedArtifactV1, error) {
	for _, r := range m.Roles {
		if r.Name != role {
			continue
		}
		for _, a := range m.Artifacts {
			if a.ID == r.RunnerArtifactID {
				return a, nil
			}
		}
	}
	return acornfoxrelease.UnifiedArtifactV1{}, fmt.Errorf("%w: role artifact %s is missing", ErrIncomplete, role)
}
