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

func verifyAcornFoxArchive(reader io.Reader, size int64, expectedSHA256 string, rawManifest []byte, manifest Manifest) error {
	stream, err := newAcornFoxExactArchiveReader(reader, size)
	if err != nil {
		return err
	}
	gzipReader, err := gzip.NewReader(stream)
	if err != nil {
		return fmt.Errorf("open AcornFox archive: %w", err)
	}
	gzipReader.Multistream(false)
	if err := verifyAcornFoxArchiveTree(gzipReader, rawManifest, manifest); err != nil {
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

func verifyAcornFoxArchiveTree(reader *gzip.Reader, rawManifest []byte, manifest Manifest) error {
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
			if header.Mode != 0o644 || header.Size != int64(len(rawManifest)) || !equalAcornFoxArchiveMember(tarReader, rawManifest) {
				return errors.New("AcornFox archive manifest member is invalid")
			}
			continue
		}
		file, ok := expected[header.Name]
		if !ok || header.Mode != int64(file.Mode) {
			return fmt.Errorf("AcornFox archive member %q is unlisted or has wrong mode", header.Name)
		}
		if digest, err := hashAcornFoxArchiveMember(tarReader, header.Size); err != nil || digest != file.SHA256 {
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

func equalAcornFoxArchiveMember(reader io.Reader, want []byte) bool {
	buffer := make([]byte, acornFoxArchiveStreamBuffer)
	for offset := 0; offset < len(want); {
		chunk := len(want) - offset
		if chunk > len(buffer) {
			chunk = len(buffer)
		}
		if _, err := io.ReadFull(reader, buffer[:chunk]); err != nil || !bytes.Equal(buffer[:chunk], want[offset:offset+chunk]) {
			return false
		}
		offset += chunk
	}
	return true
}

func hashAcornFoxArchiveMember(reader io.Reader, size int64) (string, error) {
	hash := sha256.New()
	if copied, err := io.CopyN(hash, reader, size); err != nil || copied != size {
		return "", errors.New("AcornFox archive member is truncated")
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
