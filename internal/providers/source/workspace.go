package source

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/open-card/open-card/internal/foundation"
)

// copyDirectory copies a local upload through a staging directory. It never
// follows a symlink and checks the actual bytes copied, rather than trusting
// file metadata that may change while an upload handler is finalizing a file.
func copyDirectory(source, destination string, limits foundation.ArchiveLimits) error {
	var files, bytes int64
	return filepath.WalkDir(source, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return errUploadRejected
		}
		if path == source {
			return nil
		}
		rel, err := filepath.Rel(source, path)
		if err != nil {
			return errUploadRejected
		}
		if ignoredSystemPath(rel) {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		info, err := os.Lstat(path)
		if err != nil || info.Mode()&fs.ModeSymlink != 0 {
			return errUploadRejected
		}
		if info.IsDir() {
			return makeDestinationDir(destination, rel)
		}
		if !sourceSingleLinkedRegular(info) {
			return errUploadRejected
		}
		files++
		if files > limits.MaxFiles || info.Size() < 0 || info.Size() > limits.MaxUnpackedBytes-bytes {
			return errUploadRejected
		}
		if err := copyLocalFile(path, destination, rel, info, limits.MaxUnpackedBytes-bytes); err != nil {
			return err
		}
		bytes += info.Size()
		return nil
	})
}

func copyLocalFile(source, destination, relative string, expected fs.FileInfo, max int64) error {
	input, err := os.Open(source)
	if err != nil {
		return errUploadRejected
	}
	defer input.Close()
	actual, err := input.Stat()
	if err != nil || !sourceSingleLinkedRegular(actual) || !os.SameFile(expected, actual) || actual.Size() != expected.Size() {
		return errUploadRejected
	}
	output, err := createDestinationFile(destination, relative)
	if err != nil {
		return err
	}
	defer output.Close()
	if _, err := copyExact(output, input, expected.Size(), max); err != nil {
		return err
	}
	return nil
}

func sourceSingleLinkedRegular(info fs.FileInfo) bool {
	if !info.Mode().IsRegular() || info.Mode()&fs.ModeSymlink != 0 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return !ok || stat.Nlink == 1
}

func extractArchive(source, destination string, limits foundation.ArchiveLimits) error {
	lower := strings.ToLower(source)
	switch {
	case strings.HasSuffix(lower, ".zip"):
		return extractZIP(source, destination, limits)
	case strings.HasSuffix(lower, ".tar"):
		return extractTarFile(source, destination, limits, false)
	case strings.HasSuffix(lower, ".tar.gz"), strings.HasSuffix(lower, ".tgz"):
		return extractTarFile(source, destination, limits, true)
	default:
		return errUploadRejected
	}
}

func extractZIP(source, destination string, limits foundation.ArchiveLimits) error {
	reader, err := zip.OpenReader(source)
	if err != nil {
		return errUploadRejected
	}
	defer reader.Close()
	entries := make([]foundation.ArchiveEntry, 0, len(reader.File))
	for _, file := range reader.File {
		if file.Flags&1 != 0 || file.UncompressedSize64 > math.MaxInt64 {
			return errUploadRejected
		}
		entries = append(entries, foundation.ArchiveEntry{Name: file.Name, Kind: zipKind(file), Size: int64(file.UncompressedSize64)})
	}
	report, err := foundation.InspectArchive(entries, limits)
	if err != nil {
		return errUploadRejected
	}
	allowed := allowedEntries(report)
	var bytes int64
	for _, file := range reader.File {
		normalized, violation := foundation.NormalizeArchivePath(file.Name)
		if violation != "" || !allowed[normalized] {
			continue
		}
		if file.FileInfo().IsDir() {
			if err := makeDestinationDir(destination, normalized); err != nil {
				return err
			}
			continue
		}
		input, err := file.Open()
		if err != nil {
			return errUploadRejected
		}
		output, err := createDestinationFile(destination, normalized)
		if err == nil {
			_, err = copyExact(output, input, int64(file.UncompressedSize64), limits.MaxUnpackedBytes-bytes)
		}
		closeErr := input.Close()
		if output != nil {
			closeErr = errors.Join(closeErr, output.Close())
		}
		if err != nil || closeErr != nil {
			return errUploadRejected
		}
		bytes += int64(file.UncompressedSize64)
	}
	return nil
}

func extractTarFile(source, destination string, limits foundation.ArchiveLimits, compressed bool) error {
	input, err := os.Open(source)
	if err != nil {
		return errUploadRejected
	}
	defer input.Close()
	if compressed {
		gzipReader, err := gzip.NewReader(input)
		if err != nil {
			return errUploadRejected
		}
		defer gzipReader.Close()
		return extractTar(tar.NewReader(gzipReader), destination, limits)
	}
	return extractTar(tar.NewReader(input), destination, limits)
}

// extractTar applies the same inspection rules while streaming. Tar cannot be
// pre-scanned without a second read, so every header and byte count is checked
// before it is written to the staging workspace.
func extractTar(reader *tar.Reader, destination string, limits foundation.ArchiveLimits) error {
	seen := make(map[string]struct{})
	var files, bytes int64
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read archive header: %w", errUploadRejected)
		}
		if header.Typeflag == tar.TypeXGlobalHeader {
			if header.Size < 0 || header.Size > 64<<10 {
				return fmt.Errorf("global archive metadata exceeds limit: %w", errUploadRejected)
			}
			if _, err := io.CopyN(io.Discard, reader, header.Size); err != nil {
				return fmt.Errorf("read global archive metadata: %w", errUploadRejected)
			}
			continue
		}
		// GNU/bsdtar commonly emits one harmless archive-root directory entry
		// before the actual tree when called with `-C source .`. It names no
		// extractable child and is not a traversal path, so skip only these two
		// exact directory spellings while retaining fail-closed path handling for
		// every other entry.
		if header.Typeflag == tar.TypeDir && (header.Name == "." || header.Name == "./") {
			continue
		}
		entry := foundation.ArchiveEntry{Name: header.Name, Kind: tarKind(header), Size: header.Size, Linkname: header.Linkname}
		report, err := foundation.InspectArchive([]foundation.ArchiveEntry{entry}, foundation.ArchiveLimits{MaxFiles: 1, MaxUnpackedBytes: limits.MaxUnpackedBytes, IgnoreHidden: limits.IgnoreHidden})
		if err != nil || len(report.Decisions) != 1 {
			return fmt.Errorf("inspect archive entry %q type=%d size=%d: %w", header.Name, header.Typeflag, header.Size, errUploadRejected)
		}
		decision := report.Decisions[0]
		if _, exists := seen[decision.NormalizedPath]; exists {
			return fmt.Errorf("duplicate archive entry: %w", errUploadRejected)
		}
		seen[decision.NormalizedPath] = struct{}{}
		if decision.Ignored {
			continue
		}
		if header.Typeflag == tar.TypeDir {
			if err := makeDestinationDir(destination, decision.NormalizedPath); err != nil {
				return err
			}
			continue
		}
		files++
		if files > limits.MaxFiles || header.Size < 0 || header.Size > limits.MaxUnpackedBytes-bytes {
			return fmt.Errorf("archive entry exceeds limits: %w", errUploadRejected)
		}
		output, err := createDestinationFile(destination, decision.NormalizedPath)
		if err != nil {
			return err
		}
		_, err = copyExact(output, reader, header.Size, limits.MaxUnpackedBytes-bytes)
		closeErr := output.Close()
		if err != nil || closeErr != nil {
			return fmt.Errorf("copy archive entry: %w", errUploadRejected)
		}
		bytes += header.Size
	}
}

func allowedEntries(report foundation.ArchiveReport) map[string]bool {
	allowed := make(map[string]bool, len(report.Decisions))
	for _, decision := range report.Decisions {
		if !decision.Ignored {
			allowed[decision.NormalizedPath] = true
		}
	}
	return allowed
}

func zipKind(file *zip.File) foundation.ArchiveEntryKind {
	mode := file.Mode()
	switch {
	case mode&fs.ModeSymlink != 0:
		return foundation.ArchiveSymlink
	case mode&fs.ModeDevice != 0:
		return foundation.ArchiveDevice
	case mode&fs.ModeNamedPipe != 0:
		return foundation.ArchiveFIFO
	case file.FileInfo().IsDir():
		return foundation.ArchiveDirectory
	case mode.IsRegular():
		return foundation.ArchiveRegular
	default:
		return foundation.ArchiveUnknown
	}
}

func tarKind(header *tar.Header) foundation.ArchiveEntryKind {
	switch header.Typeflag {
	case tar.TypeReg, tar.TypeRegA:
		return foundation.ArchiveRegular
	case tar.TypeDir:
		return foundation.ArchiveDirectory
	case tar.TypeSymlink:
		return foundation.ArchiveSymlink
	case tar.TypeLink:
		return foundation.ArchiveHardlink
	case tar.TypeChar, tar.TypeBlock:
		return foundation.ArchiveDevice
	case tar.TypeFifo:
		return foundation.ArchiveFIFO
	default:
		return foundation.ArchiveUnknown
	}
}

func makeDestinationDir(destination, relative string) error {
	path, err := destinationPath(destination, relative)
	if err != nil {
		return err
	}
	return os.MkdirAll(path, 0o700)
}

func createDestinationFile(destination, relative string) (*os.File, error) {
	path, err := destinationPath(destination, relative)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, errWorkspaceUnavailable
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, errUploadRejected
	}
	return file, nil
}

func destinationPath(destination, relative string) (string, error) {
	normalized, violation := foundation.NormalizeArchivePath(relative)
	if violation != "" {
		return "", errUploadRejected
	}
	path := filepath.Join(destination, filepath.FromSlash(normalized))
	rel, err := filepath.Rel(destination, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", errUploadRejected
	}
	return path, nil
}

func copyExact(destination io.Writer, source io.Reader, expected, remaining int64) (int64, error) {
	if expected < 0 || remaining < expected {
		return 0, errUploadRejected
	}
	written, err := io.Copy(destination, io.LimitReader(source, expected+1))
	if err != nil || written != expected {
		return written, errUploadRejected
	}
	var trailing [1]byte
	if count, _ := source.Read(trailing[:]); count != 0 {
		return written, errUploadRejected
	}
	return written, nil
}

func makeReadOnly(root string) error {
	return filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.Type()&fs.ModeSymlink != 0 {
			return errUploadRejected
		}
		if entry.IsDir() {
			return os.Chmod(path, 0o555)
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			return errUploadRejected
		}
		return os.Chmod(path, 0o444)
	})
}

func ignoredSystemPath(value string) bool {
	for _, part := range strings.Split(filepath.ToSlash(value), "/") {
		switch strings.ToLower(part) {
		case ".ds_store", "thumbs.db", "desktop.ini", "__macosx":
			return true
		}
	}
	return false
}
