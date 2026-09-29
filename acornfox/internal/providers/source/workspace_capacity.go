package source

import (
	"errors"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/acornfox/acornfox/internal/domain"
	"github.com/acornfox/acornfox/internal/foundation"
)

const (
	workspaceMetadataBytes                    int64 = 4 << 10
	defaultWorkspaceCapacityBytes             int64 = 16 << 30
	defaultWorkspaceCapacityEntries           int64 = 1_000_000
	defaultWorkspaceOperationalReserveBytes   int64 = 1 << 30
	defaultWorkspaceOperationalReserveEntries int64 = 10_000
	workspaceLockName                               = ".workspace.lock"
)

var workspaceDigestName = regexp.MustCompile(`^[a-f0-9]{64}$`)

type workspaceUsage struct {
	bytes   int64
	entries int64
}

type workspaceReserve struct {
	bytes   int64
	entries int64
}

type workspaceFilesystemAvailability struct {
	bytes   int64
	entries int64
}

func normalizedWorkspaceCapacity(bytes, entries int64, limits foundation.ArchiveLimits) (int64, int64, error) {
	if bytes == 0 {
		bytes = defaultWorkspaceCapacityBytes
	}
	if entries == 0 {
		entries = defaultWorkspaceCapacityEntries
	}
	if bytes <= 0 || entries <= 0 {
		return 0, 0, errors.New("source workspace capacity must be finite and positive")
	}
	gitReserve, err := workspaceAdmissionReserve(domain.SourceGitHTTPS, limits)
	if err != nil {
		return 0, 0, err
	}
	minimumBytes, err := safeWorkspaceAdd(gitReserve.bytes, workspaceMetadataBytes)
	if err != nil {
		return 0, 0, err
	}
	minimumEntries, err := safeWorkspaceAdd(gitReserve.entries, 1)
	if err != nil || bytes < minimumBytes || entries < minimumEntries {
		return 0, 0, errors.New("source workspace capacity cannot admit one public Git preparation")
	}
	return bytes, entries, nil
}

func normalizedWorkspaceOperationalReserve(bytes, entries int64) (int64, int64, error) {
	if bytes == 0 {
		bytes = defaultWorkspaceOperationalReserveBytes
	}
	if entries == 0 {
		entries = defaultWorkspaceOperationalReserveEntries
	}
	if bytes < defaultWorkspaceOperationalReserveBytes || entries < defaultWorkspaceOperationalReserveEntries {
		return 0, 0, errors.New("source workspace operational reserve is undersized")
	}
	return bytes, entries, nil
}

func workspaceAdmissionReserve(kind domain.SourceKind, limits foundation.ArchiveLimits) (workspaceReserve, error) {
	doubledFiles, err := safeWorkspaceMultiply(limits.MaxFiles, 2)
	if err != nil {
		return workspaceReserve{}, err
	}
	perTreeEntries, err := safeWorkspaceAdd(doubledFiles, 1)
	if err != nil {
		return workspaceReserve{}, err
	}
	metadataBytes, err := safeWorkspaceMultiply(perTreeEntries, workspaceMetadataBytes)
	if err != nil {
		return workspaceReserve{}, err
	}
	perTreeBytes, err := safeWorkspaceAdd(limits.MaxUnpackedBytes, metadataBytes)
	if err != nil {
		return workspaceReserve{}, err
	}
	trees := int64(1)
	if kind == domain.SourceGitHTTPS {
		trees = 2
	}
	bytes, err := safeWorkspaceMultiply(perTreeBytes, trees)
	if err != nil {
		return workspaceReserve{}, err
	}
	entries, err := safeWorkspaceMultiply(perTreeEntries, trees)
	if err != nil {
		return workspaceReserve{}, err
	}
	return workspaceReserve{bytes: bytes, entries: entries}, nil
}

func safeWorkspaceAdd(left, right int64) (int64, error) {
	if left < 0 || right < 0 || left > math.MaxInt64-right {
		return 0, errors.New("source workspace capacity overflows")
	}
	return left + right, nil
}

func safeWorkspaceMultiply(left, right int64) (int64, error) {
	if left < 0 || right < 0 || left != 0 && right > math.MaxInt64/left {
		return 0, errors.New("source workspace capacity overflows")
	}
	return left * right, nil
}

func measureWorkspacePool(root string) (workspaceUsage, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return workspaceUsage{}, errWorkspaceUnavailable
	}
	usage := workspaceUsage{}
	for _, entry := range entries {
		name := entry.Name()
		if name == workspaceLockName {
			if err := measureWorkspaceNode(filepath.Join(root, name), false, &usage); err != nil {
				return workspaceUsage{}, errWorkspaceUnavailable
			}
			continue
		}
		if !(workspaceDigestName.MatchString(name) || strings.HasPrefix(name, ".source-stage-") || strings.HasPrefix(name, ".git-objects-")) {
			return workspaceUsage{}, errWorkspaceUnavailable
		}
		if err := measureWorkspaceNode(filepath.Join(root, name), true, &usage); err != nil {
			return workspaceUsage{}, errWorkspaceUnavailable
		}
	}
	return usage, nil
}

func measureWorkspaceNode(path string, mustBeDirectory bool, usage *workspaceUsage) error {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&fs.ModeSymlink != 0 {
		return errWorkspaceUnavailable
	}
	if mustBeDirectory && !info.IsDir() {
		return errWorkspaceUnavailable
	}
	if !mustBeDirectory && !info.Mode().IsRegular() {
		return errWorkspaceUnavailable
	}
	return filepath.WalkDir(path, func(itemPath string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return errWorkspaceUnavailable
		}
		itemInfo, err := os.Lstat(itemPath)
		if err != nil || itemInfo.Mode()&fs.ModeSymlink != 0 || !(itemInfo.IsDir() || itemInfo.Mode().IsRegular()) || itemInfo.Size() < 0 {
			return errWorkspaceUnavailable
		}
		bytes := itemInfo.Size()
		if bytes < workspaceMetadataBytes {
			bytes = workspaceMetadataBytes
		}
		var addErr error
		usage.bytes, addErr = safeWorkspaceAdd(usage.bytes, bytes)
		if addErr != nil {
			return errWorkspaceUnavailable
		}
		usage.entries, addErr = safeWorkspaceAdd(usage.entries, 1)
		if addErr != nil {
			return errWorkspaceUnavailable
		}
		return nil
	})
}

func workspaceAdmissionAllowed(usage workspaceUsage, reserve workspaceReserve, capacityBytes, capacityEntries int64) bool {
	return usage.bytes <= capacityBytes && reserve.bytes <= capacityBytes-usage.bytes && usage.entries <= capacityEntries && reserve.entries <= capacityEntries-usage.entries
}

func workspaceFilesystemAdmissionAllowed(available workspaceFilesystemAvailability, reserve workspaceReserve, operationalBytes, operationalEntries int64) bool {
	neededBytes, err := safeWorkspaceAdd(reserve.bytes, operationalBytes)
	if err != nil {
		return false
	}
	neededEntries, err := safeWorkspaceAdd(reserve.entries, operationalEntries)
	if err != nil {
		return false
	}
	return available.bytes >= neededBytes && available.entries >= neededEntries
}
