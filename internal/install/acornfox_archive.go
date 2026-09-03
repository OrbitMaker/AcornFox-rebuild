package install

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
)

const acornFoxArchiveStreamBuffer = 32 * 1024

// acornFoxExactArchiveReader is deliberately both an io.Reader and an
// io.ByteReader. gzip uses the latter to avoid read-ahead, which lets finish
// distinguish the first gzip member from trailing compressed bytes.
type acornFoxExactArchiveReader struct {
	reader    io.Reader
	remaining int64
	hash      hash.Hash
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

func newAcornFoxExactArchiveReader(reader io.Reader, size int64) (*acornFoxExactArchiveReader, error) {
	if reader == nil || size < 1 || size > acornFoxArchiveMaxBytes {
		return nil, errors.New("AcornFox archive size is invalid")
	}
	return &acornFoxExactArchiveReader{reader: reader, remaining: size, hash: sha256.New()}, nil
}

func (r *acornFoxExactArchiveReader) Read(target []byte) (int, error) {
	if r.remaining == 0 {
		return 0, io.EOF
	}
	if int64(len(target)) > r.remaining {
		target = target[:r.remaining]
	}
	n, err := r.reader.Read(target)
	if n > 0 {
		r.remaining -= int64(n)
		_, _ = r.hash.Write(target[:n])
	}
	return n, err
}

func (r *acornFoxExactArchiveReader) ReadByte() (byte, error) {
	var one [1]byte
	n, err := r.Read(one[:])
	if n == 1 {
		return one[0], nil
	}
	return 0, err
}

func (r *acornFoxExactArchiveReader) finish(expectedSHA256 string) error {
	if r.remaining != 0 {
		return errors.New("AcornFox archive is shorter than declared size")
	}
	var extra [1]byte
	n, err := r.reader.Read(extra[:])
	if n != 0 {
		return errors.New("AcornFox archive is longer than declared size")
	}
	if err == nil {
		return errors.New("AcornFox archive reader made no progress")
	}
	if err != nil && err != io.EOF {
		return fmt.Errorf("read AcornFox archive tail: %w", err)
	}
	if hex.EncodeToString(r.hash.Sum(nil)) != expectedSHA256 {
		return errors.New("AcornFox archive sha256 mismatch")
	}
	return nil
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
	buffer := make([]byte, acornFoxArchiveStreamBuffer)
	var member acornFoxArchiveMember
	if sink != nil {
		var err error
		member, err = sink.OpenMember(name, mode)
		if err != nil {
			return err
		}
	}
	closed := false
	defer func() {
		if member != nil && !closed {
			_ = member.Close()
		}
	}()
	hash := sha256.New()
	for offset, remaining := int64(0), size; remaining > 0; {
		chunk := int64(len(buffer))
		if chunk > remaining {
			chunk = remaining
		}
		if _, err := io.ReadFull(reader, buffer[:chunk]); err != nil {
			return errors.New("AcornFox archive member is truncated")
		}
		if want != nil && !bytes.Equal(buffer[:chunk], want[offset:offset+chunk]) {
			return errors.New("AcornFox archive member content differs")
		}
		if _, err := hash.Write(buffer[:chunk]); err != nil {
			return err
		}
		if member != nil {
			if written, err := member.Write(buffer[:chunk]); err != nil || written != int(chunk) {
				if err != nil {
					return err
				}
				return io.ErrShortWrite
			}
		}
		offset += chunk
		remaining -= chunk
	}
	if want != nil && size != int64(len(want)) {
		return errors.New("AcornFox archive manifest size mismatch")
	}
	if expectedSHA256 != "" && hex.EncodeToString(hash.Sum(nil)) != expectedSHA256 {
		return errors.New("AcornFox archive member checksum mismatch")
	}
	if member != nil {
		if err := member.Sync(); err != nil {
			return err
		}
		if err := member.Close(); err != nil {
			return err
		}
		closed = true
	}
	return nil
}
