package foundation

import (
	"errors"
	"fmt"
	"path"
	"strings"
)

// ArchiveEntryKind is deliberately explicit. A provider must classify an
// archive entry before extraction; unknown and special filesystem types are
// rejected instead of being silently coerced into regular files.
type ArchiveEntryKind string

const (
	ArchiveRegular   ArchiveEntryKind = "regular"
	ArchiveDirectory ArchiveEntryKind = "directory"
	ArchiveSymlink   ArchiveEntryKind = "symlink"
	ArchiveHardlink  ArchiveEntryKind = "hardlink"
	ArchiveDevice    ArchiveEntryKind = "device"
	ArchiveFIFO      ArchiveEntryKind = "fifo"
	ArchiveSocket    ArchiveEntryKind = "socket"
	ArchiveUnknown   ArchiveEntryKind = "unknown"
)

type ArchiveViolation string

const (
	ViolationInvalidPath   ArchiveViolation = "invalid_path"
	ViolationPathTraversal ArchiveViolation = "path_traversal"
	ViolationAbsolutePath  ArchiveViolation = "absolute_path"
	ViolationSpecialFile   ArchiveViolation = "special_file"
	ViolationNegativeSize  ArchiveViolation = "negative_size"
	ViolationTooManyFiles  ArchiveViolation = "too_many_files"
	ViolationTooLarge      ArchiveViolation = "too_large"
)

var ErrArchiveRejected = errors.New("archive entry rejected")

// ArchiveEntry describes metadata supplied by a tar/zip reader. It contains
// no extracted bytes, so inspection can be performed before writing anything
// to a workspace.
type ArchiveEntry struct {
	Name     string
	Kind     ArchiveEntryKind
	Size     int64
	Linkname string
}

// ArchiveLimits are safety limits for one uploaded archive. A zero limit is
// unbounded only when the corresponding limit is intentionally omitted; the
// package defaults use finite limits through DefaultArchiveLimits.
type ArchiveLimits struct {
	MaxFileBytes     int64
	MaxFiles         int64
	MaxUnpackedBytes int64
	IgnoreHidden     bool
}

var DefaultArchiveLimits = ArchiveLimits{
	MaxFiles:         100_000,
	MaxUnpackedBytes: 2 << 30,
	// Application dotfiles may be meaningful source (for example
	// .well-known). Common operating-system metadata is omitted regardless;
	// callers can opt into omitting every hidden path with IgnoreHidden.
	IgnoreHidden: false,
}

// ArchiveDecision is the classification result for one entry. Rejected is
// never an instruction to continue extraction: callers should discard the
// entire archive (fail closed).
type ArchiveDecision struct {
	Entry          ArchiveEntry
	NormalizedPath string
	Ignored        bool
	Violation      ArchiveViolation
}

type ArchiveReport struct {
	Decisions     []ArchiveDecision
	FileCount     int64
	UnpackedBytes int64
	IgnoredHidden int64
}

// ArchiveError contains a stable violation classification and entry path.
// The original archive path is retained for evidence, but no archive content
// is copied into the error.
type ArchiveError struct {
	Path      string
	Violation ArchiveViolation
	Message   string
}

func (e *ArchiveError) Error() string {
	if e == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%s: %s (%s)", e.Path, e.Message, e.Violation)
}

func (e *ArchiveError) Unwrap() error { return ErrArchiveRejected }

// InspectArchive validates all entry metadata and returns a report only when
// every entry is safe. Any single violation returns an error and the caller
// must not extract partial results.
func InspectArchive(entries []ArchiveEntry, limits ArchiveLimits) (ArchiveReport, error) {
	if limits.MaxFiles < 0 || limits.MaxUnpackedBytes < 0 || limits.MaxFileBytes < 0 {
		return ArchiveReport{}, &ArchiveError{Violation: ViolationInvalidPath, Message: "limits must be non-negative"}
	}
	report := ArchiveReport{Decisions: make([]ArchiveDecision, 0, len(entries))}
	seen := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		normalized, violation := NormalizeArchivePath(entry.Name)
		if violation != "" {
			return ArchiveReport{}, archiveReject(entry.Name, violation)
		}
		if _, exists := seen[normalized]; exists {
			return ArchiveReport{}, archiveReject(normalized, ViolationInvalidPath)
		}
		seen[normalized] = struct{}{}

		if entry.Size < 0 {
			return ArchiveReport{}, archiveReject(normalized, ViolationNegativeSize)
		}
		if !isArchiveKindAllowed(entry.Kind) {
			return ArchiveReport{}, archiveReject(normalized, violationForKind(entry.Kind))
		}
		if isIgnoredSystemPath(normalized) || (limits.IgnoreHidden && IsHiddenArchivePath(normalized)) {
			report.IgnoredHidden++
			report.Decisions = append(report.Decisions, ArchiveDecision{Entry: entry, NormalizedPath: normalized, Ignored: true})
			continue
		}
		if entry.Kind == ArchiveRegular {
			if limits.MaxFileBytes > 0 && entry.Size > limits.MaxFileBytes {
				return ArchiveReport{}, archiveReject(normalized, ViolationTooLarge)
			}
			report.FileCount++
			if limits.MaxFiles > 0 && report.FileCount > limits.MaxFiles {
				return ArchiveReport{}, archiveReject(normalized, ViolationTooManyFiles)
			}
			if limits.MaxUnpackedBytes > 0 && entry.Size > limits.MaxUnpackedBytes-report.UnpackedBytes {
				return ArchiveReport{}, archiveReject(normalized, ViolationTooLarge)
			}
			report.UnpackedBytes += entry.Size
		}
		report.Decisions = append(report.Decisions, ArchiveDecision{Entry: entry, NormalizedPath: normalized})
	}
	return report, nil
}

// ValidateArchiveEntries is a concise alias for callers that only need the
// fail-closed validation contract.
func ValidateArchiveEntries(entries []ArchiveEntry, limits ArchiveLimits) error {
	_, err := InspectArchive(entries, limits)
	return err
}

// NormalizeArchivePath canonicalizes slash-separated archive names and
// rejects absolute paths, drive-letter paths and traversal before clean-up.
func NormalizeArchivePath(name string) (string, ArchiveViolation) {
	raw := strings.ReplaceAll(strings.TrimSpace(name), "\\", "/")
	if raw == "" || strings.IndexByte(raw, 0) >= 0 {
		return "", ViolationInvalidPath
	}
	if strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") || isWindowsAbsolute(raw) {
		return "", ViolationAbsolutePath
	}
	parts := strings.Split(raw, "/")
	for _, part := range parts {
		if part == ".." {
			return "", ViolationPathTraversal
		}
		if part == "" || part == "." {
			continue
		}
		for _, r := range part {
			if r < 0x20 || r == 0x7f {
				return "", ViolationInvalidPath
			}
		}
	}
	clean := path.Clean("/" + raw)
	if clean == "/" || clean == "/." {
		return "", ViolationPathTraversal
	}
	return strings.TrimPrefix(clean, "/"), ""
}

// IsHiddenArchivePath detects dotfiles/directories. Product policy can use
// this to omit common system metadata while preserving legitimate app files
// when IgnoreHidden is false.
func IsHiddenArchivePath(name string) bool {
	for _, part := range strings.Split(name, "/") {
		if strings.HasPrefix(part, ".") && part != "." && part != ".." {
			return true
		}
	}
	return false
}

func isArchiveKindAllowed(kind ArchiveEntryKind) bool {
	return kind == ArchiveRegular || kind == ArchiveDirectory
}

func violationForKind(kind ArchiveEntryKind) ArchiveViolation {
	if kind == ArchiveSymlink || kind == ArchiveHardlink || kind == ArchiveDevice || kind == ArchiveFIFO || kind == ArchiveSocket || kind == ArchiveUnknown {
		return ViolationSpecialFile
	}
	return ViolationInvalidPath
}

func archiveReject(path string, violation ArchiveViolation) error {
	message := "archive safety policy rejected entry"
	switch violation {
	case ViolationPathTraversal:
		message = "path traversal is not allowed"
	case ViolationAbsolutePath:
		message = "absolute paths are not allowed"
	case ViolationSpecialFile:
		message = "special files and links are not allowed"
	case ViolationNegativeSize:
		message = "negative size is not allowed"
	case ViolationTooManyFiles:
		message = "file count limit exceeded"
	case ViolationTooLarge:
		message = "unpacked size limit exceeded"
	}
	return &ArchiveError{Path: path, Violation: violation, Message: message}
}
