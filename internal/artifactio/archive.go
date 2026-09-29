package artifactio

import (
	"archive/tar"
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
)

const StreamBufferSize = 32 * 1024

// ExactArchiveReader is an io.Reader and io.ByteReader that enforces exact
// size limits and streams SHA256 checksum calculation.
type ExactArchiveReader struct {
	reader    io.Reader
	remaining int64
	hash      hash.Hash
}

type ArchiveSink interface {
	OpenMember(name string, mode uint32) (ArchiveMember, error)
}

type ArchiveMember interface {
	io.Writer
	Sync() error
	Close() error
}

func NewExactArchiveReader(reader io.Reader, size int64, maxBytes int64) (*ExactArchiveReader, error) {
	if reader == nil || size < 1 || (maxBytes > 0 && size > maxBytes) {
		return nil, errors.New("archive size is invalid")
	}
	return &ExactArchiveReader{
		reader:    bufio.NewReaderSize(reader, StreamBufferSize),
		remaining: size,
		hash:      sha256.New(),
	}, nil
}

func (r *ExactArchiveReader) Read(target []byte) (int, error) {
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

func (r *ExactArchiveReader) ReadByte() (byte, error) {
	var one [1]byte
	n, err := r.Read(one[:])
	if n == 1 {
		return one[0], nil
	}
	return 0, err
}

func (r *ExactArchiveReader) Finish(expectedSHA256 string) error {
	if r.remaining != 0 {
		return errors.New("archive is shorter than declared size")
	}
	var extra [1]byte
	n, err := r.reader.Read(extra[:])
	if n != 0 {
		return errors.New("archive is longer than declared size")
	}
	if err == nil {
		return errors.New("archive reader made no progress")
	}
	if err != nil && err != io.EOF {
		return fmt.Errorf("read archive tail: %w", err)
	}
	actual := hex.EncodeToString(r.hash.Sum(nil))
	if actual != expectedSHA256 {
		return errors.New("archive sha256 mismatch")
	}
	return nil
}

func ValidateUSTARRegularHeader(header *tar.Header) error {
	if header == nil {
		return errors.New("nil tar header")
	}
	if header.Typeflag != tar.TypeReg || header.Format != tar.FormatUSTAR {
		return fmt.Errorf("archive member %q must be USTAR regular file", header.Name)
	}
	if header.Linkname != "" || len(header.PAXRecords) != 0 || len(header.Xattrs) != 0 {
		return fmt.Errorf("archive member %q has unsafe metadata", header.Name)
	}
	if header.Uid != 0 || header.Gid != 0 || header.Uname != "" || header.Gname != "" {
		return fmt.Errorf("archive member %q has non-zero ownership or identity", header.Name)
	}
	return nil
}

func VerifyArchiveMember(reader io.Reader, size int64, want []byte, expectedSHA256 string, sink ArchiveSink, name string, mode uint32) error {
	if reader == nil {
		return errors.New("archive member reader is nil")
	}
	if size < 0 {
		return errors.New("archive member size is negative")
	}
	if want != nil && size != int64(len(want)) {
		return errors.New("archive manifest size mismatch")
	}
	if expectedSHA256 != "" && len(expectedSHA256) != 64 {
		return errors.New("archive member checksum is invalid")
	}
	if name == "" {
		return errors.New("archive member name is invalid")
	}

	buffer := make([]byte, StreamBufferSize)
	var member ArchiveMember
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
	h := sha256.New()
	for offset, remaining := int64(0), size; remaining > 0; {
		chunk := int64(len(buffer))
		if chunk > remaining {
			chunk = remaining
		}
		if _, err := io.ReadFull(reader, buffer[:chunk]); err != nil {
			return errors.New("archive member is truncated")
		}
		if want != nil && !bytes.Equal(buffer[:chunk], want[offset:offset+chunk]) {
			return errors.New("archive member content differs")
		}
		if _, err := h.Write(buffer[:chunk]); err != nil {
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
		return errors.New("archive manifest size mismatch")
	}
	if expectedSHA256 != "" && hex.EncodeToString(h.Sum(nil)) != expectedSHA256 {
		return errors.New("archive member checksum mismatch")
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
