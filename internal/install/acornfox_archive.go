package install

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"

	"github.com/open-card/open-card/internal/artifactio"
)

const acornFoxArchiveStreamBuffer = artifactio.StreamBufferSize

// acornFoxExactArchiveReader is deliberately both an io.Reader and an
// io.ByteReader. gzip uses the latter to avoid read-ahead, which lets finish
// distinguish the first gzip member from trailing compressed bytes.
type acornFoxExactArchiveReader struct {
	inner *artifactio.ExactArchiveReader
}

// acornFoxArchiveSink is package-private so only a verified installation leaf
// can receive members from the canonical USTAR walker.
type acornFoxArchiveSink interface {
	OpenMember(string, uint32) (acornFoxArchiveMember, error)
}

type acornFoxArchiveMember interface {
	io.Writer
	Sync() error
	Close() error
}

type sinkAdapter struct {
	acornFoxArchiveSink
}

func (s sinkAdapter) OpenMember(name string, mode uint32) (artifactio.ArchiveMember, error) {
	return s.acornFoxArchiveSink.OpenMember(name, mode)
}

func newAcornFoxExactArchiveReader(reader io.Reader, size int64) (*acornFoxExactArchiveReader, error) {
	inner, err := artifactio.NewExactArchiveReader(reader, size, acornFoxArchiveMaxBytes)
	if err != nil {
		return nil, errors.New("AcornFox archive size is invalid")
	}
	return &acornFoxExactArchiveReader{inner: inner}, nil
}

func (r *acornFoxExactArchiveReader) Read(target []byte) (int, error) {
	return r.inner.Read(target)
}

func (r *acornFoxExactArchiveReader) ReadByte() (byte, error) {
	return r.inner.ReadByte()
}

func (r *acornFoxExactArchiveReader) finish(expectedSHA256 string) error {
	err := r.inner.Finish(expectedSHA256)
	if err == nil {
		return nil
	}
	switch err.Error() {
	case "archive is shorter than declared size":
		return errors.New("AcornFox archive is shorter than declared size")
	case "archive is longer than declared size":
		return errors.New("AcornFox archive is longer than declared size")
	case "archive reader made no progress":
		return errors.New("AcornFox archive reader made no progress")
	case "archive sha256 mismatch":
		return errors.New("AcornFox archive sha256 mismatch")
	default:
		return fmt.Errorf("read AcornFox archive tail: %w", err)
	}
}

func verifyAcornFoxArchive(reader io.Reader, size int64, expectedSHA256 string, rawManifest []byte, manifest Manifest, sink acornFoxArchiveSink) error {
	stream, err := newAcornFoxExactArchiveReader(reader, size)
	if err != nil {
		return err
	}
	gzipReader, err := gzip.NewReader(stream)
	if err != nil {
		return fmt.Errorf("open AcornFox archive: %w", err)
	}
	gzipReader.Multistream(false)
	if err := verifyAcornFoxArchiveTree(gzipReader, rawManifest, manifest, sink); err != nil {
		_ = gzipReader.Close()
		return err
	}
	if _, err := io.Copy(io.Discard, gzipReader); err != nil {
		_ = gzipReader.Close()
		return fmt.Errorf("read AcornFox archive tail: %w", err)
	}
	if err := gzipReader.Close(); err != nil {
		return fmt.Errorf("close AcornFox archive: %w", err)
	}
	return stream.finish(expectedSHA256)
}

func verifyAcornFoxArchiveTree(reader *gzip.Reader, rawManifest []byte, manifest Manifest, sink acornFoxArchiveSink) error {
	// RELEASE-12 must emit USTAR members. A legacy PAX writer cannot be reused:
	// PAX metadata is rejected before any member is treated as installable.
	expected := make(map[string]FileDigest, len(manifest.Files))
	for _, file := range manifest.Files {
		expected["release/"+file.Path] = file
	}
	seen := make(map[string]struct{}, len(expected)+1)
	tarReader := tar.NewReader(reader)
	var memberCount int
	var total int64
	for {
		header, nextErr := tarReader.Next()
		if nextErr == io.EOF {
			break
		}
		if nextErr != nil {
			return fmt.Errorf("read AcornFox archive: %w", nextErr)
		}
		memberCount++
		if memberCount > acornFoxArchiveMaxMembers || header.Size < 0 || header.Size > acornFoxArchiveMaxMemberBytes {
			return errors.New("AcornFox archive member bounds are invalid")
		}
		total += header.Size
		if total > acornFoxArchiveMaxTotalBytes {
			return errors.New("AcornFox archive total size is invalid")
		}
		if header.Typeflag != tar.TypeReg || header.Format != tar.FormatUSTAR || header.Linkname != "" || len(header.PAXRecords) != 0 || len(header.Xattrs) != 0 || header.Uid != 0 || header.Gid != 0 || header.Uname != "" || header.Gname != "" {
			return fmt.Errorf("AcornFox archive member %q has unsafe metadata", header.Name)
		}
		if _, duplicate := seen[header.Name]; duplicate {
			return fmt.Errorf("AcornFox archive has duplicate member %q", header.Name)
		}
		seen[header.Name] = struct{}{}
		if header.Name == "release/manifest.json" {
			if header.Mode != 0o644 || header.Size != int64(len(rawManifest)) || verifyAcornFoxArchiveMember(tarReader, header.Size, rawManifest, "", sink, header.Name, uint32(header.Mode)) != nil {
				return errors.New("AcornFox archive manifest member is invalid")
			}
			continue
		}
		file, ok := expected[header.Name]
		if !ok || header.Mode != int64(file.Mode) {
			return fmt.Errorf("AcornFox archive member %q is unlisted or has wrong mode", header.Name)
		}
		if err := verifyAcornFoxArchiveMember(tarReader, header.Size, nil, file.SHA256, sink, header.Name, uint32(header.Mode)); err != nil {
			return fmt.Errorf("AcornFox archive member %q content is invalid", header.Name)
		}
	}
	if _, ok := seen["release/manifest.json"]; !ok {
		return errors.New("AcornFox archive is missing manifest member")
	}
	for path := range expected {
		if _, ok := seen[path]; !ok {
			return fmt.Errorf("AcornFox archive is missing member %q", path)
		}
	}
	return nil
}

func verifyAcornFoxArchiveMember(reader io.Reader, size int64, want []byte, expectedSHA256 string, sink acornFoxArchiveSink, name string, mode uint32) error {
	var artSink artifactio.ArchiveSink
	if sink != nil {
		artSink = sinkAdapter{sink}
	}
	err := artifactio.VerifyArchiveMember(reader, size, want, expectedSHA256, artSink, name, mode)
	if err == nil {
		return nil
	}
	switch err.Error() {
	case "archive member is truncated":
		return errors.New("AcornFox archive member is truncated")
	case "archive member content differs":
		return errors.New("AcornFox archive member content differs")
	case "archive manifest size mismatch":
		return errors.New("AcornFox archive manifest size mismatch")
	case "archive member checksum mismatch":
		return errors.New("AcornFox archive member checksum mismatch")
	default:
		return err
	}
}
