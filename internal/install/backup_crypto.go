package install

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
)

const backupEncryptionChunkSize = 4 << 20
const backupEncryptionMagic = "OCBKPENC1\n"

var ErrBackupEncryption = errors.New("backup encryption validation failed")

// BackupEncryptionContext binds an encrypted backup to durable identities
// without carrying a path, DSN, or secret.
type BackupEncryptionContext struct {
	BackupID                   string `json:"backup_id"`
	BackupMetadataSHA256       string `json:"backup_metadata_sha256"`
	SourceActivationID         string `json:"source_activation_id"`
	SourceActivationJSONSHA256 string `json:"source_activation_json_sha256"`
	ReleaseID                  string `json:"release_id"`
	ReleaseManifestSHA256      string `json:"release_manifest_sha256"`
	ObjectKey                  string `json:"object_key"`
	KeyVersion                 string `json:"key_version"`
}

func (c BackupEncryptionContext) Validate() error {
	if !validBackupID(c.BackupID) || !validSHA(c.BackupMetadataSHA256) || !validID(c.SourceActivationID) || !validSHA(c.SourceActivationJSONSHA256) || !validID(c.ReleaseID) || !validSHA(c.ReleaseManifestSHA256) || !validID(c.KeyVersion) || !validBackupObjectKey(c.ObjectKey, c.BackupID) {
		return ErrBackupEncryption
	}
	return nil
}

func validBackupObjectKey(value, backupID string) bool {
	parts := bytes.Split([]byte(value), []byte("/"))
	return len(parts) == 4 && string(parts[0]) == "open-card" && string(parts[1]) == "backups" && validID(string(parts[2])) && string(parts[3]) == backupID+".ocbkp"
}

type BackupEncryptionReceipt struct {
	SchemaVersion   int    `json:"schema_version"`
	Cipher          string `json:"cipher"`
	ObjectSHA256    string `json:"object_sha256"`
	ObjectSize      int64  `json:"object_size"`
	HeaderSHA256    string `json:"header_sha256"`
	PlaintextSHA256 string `json:"plaintext_sha256"`
	PlaintextSize   int64  `json:"plaintext_size"`
	ChunkCount      uint32 `json:"chunk_count"`
}

func (r BackupEncryptionReceipt) Validate() error {
	if r.SchemaVersion != 1 || r.Cipher != "AES-256-GCM-CHUNKED" || !validSHA(r.ObjectSHA256) || !validSHA(r.HeaderSHA256) || !validSHA(r.PlaintextSHA256) || r.ObjectSize <= 0 || r.PlaintextSize <= 0 || r.ChunkCount == 0 {
		return ErrBackupEncryption
	}
	return nil
}

func MarshalBackupEncryptionReceipt(receipt BackupEncryptionReceipt) ([]byte, error) {
	if receipt.Validate() != nil {
		return nil, ErrBackupEncryption
	}
	return json.Marshal(receipt)
}

func ParseBackupEncryptionReceipt(raw []byte) (BackupEncryptionReceipt, error) {
	var receipt BackupEncryptionReceipt
	if err := decodeStrict(raw, &receipt); err != nil {
		return receipt, ErrBackupEncryption
	}
	if err := requireStrictFields(raw, []string{"schema_version", "cipher", "object_sha256", "object_size", "header_sha256", "plaintext_sha256", "plaintext_size", "chunk_count"}); err != nil || receipt.Validate() != nil {
		return receipt, ErrBackupEncryption
	}
	return receipt, nil
}

type backupEncryptionHeader struct {
	SchemaVersion   int    `json:"schema_version"`
	Cipher          string `json:"cipher"`
	ChunkSize       int    `json:"chunk_size"`
	NoncePrefix     string `json:"nonce_prefix"`
	ContextSHA256   string `json:"context_sha256"`
	PlaintextSHA256 string `json:"plaintext_sha256"`
	PlaintextSize   int64  `json:"plaintext_size"`
	ChunkCount      uint32 `json:"chunk_count"`
}

func (h backupEncryptionHeader) Validate() error {
	if h.SchemaVersion != 1 || h.Cipher != "AES-256-GCM-CHUNKED" || h.ChunkSize != backupEncryptionChunkSize || !validSHA(h.ContextSHA256) || !validSHA(h.PlaintextSHA256) || h.PlaintextSize <= 0 || h.ChunkCount == 0 {
		return ErrBackupEncryption
	}
	expected := (h.PlaintextSize + int64(h.ChunkSize) - 1) / int64(h.ChunkSize)
	if expected <= 0 || expected > math.MaxUint32 || uint32(expected) != h.ChunkCount {
		return ErrBackupEncryption
	}
	prefix, err := hex.DecodeString(h.NoncePrefix)
	if err != nil || len(prefix) != 8 {
		return ErrBackupEncryption
	}
	return nil
}

func canonicalBackupJSON(value any) ([]byte, error) {
	return json.Marshal(value)
}

func backupContextDigest(context BackupEncryptionContext) (string, error) {
	if err := context.Validate(); err != nil {
		return "", err
	}
	raw, err := canonicalBackupJSON(context)
	if err != nil {
		return "", ErrBackupEncryption
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, ErrBackupEncryption
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrBackupEncryption
	}
	return cipher.NewGCM(block)
}

func plaintextEvidence(source io.ReadSeeker) (int64, string, uint32, error) {
	if _, err := source.Seek(0, io.SeekStart); err != nil {
		return 0, "", 0, ErrBackupEncryption
	}
	hash := sha256.New()
	size, err := io.Copy(hash, source)
	if err != nil || size <= 0 {
		return 0, "", 0, ErrBackupEncryption
	}
	chunks := (size + backupEncryptionChunkSize - 1) / backupEncryptionChunkSize
	if chunks <= 0 || chunks > math.MaxUint32 {
		return 0, "", 0, ErrBackupEncryption
	}
	if _, err := source.Seek(0, io.SeekStart); err != nil {
		return 0, "", 0, ErrBackupEncryption
	}
	return size, hex.EncodeToString(hash.Sum(nil)), uint32(chunks), nil
}

func frameAAD(headerDigest []byte, index uint32) []byte {
	value := make([]byte, len(headerDigest)+4)
	copy(value, headerDigest)
	binary.BigEndian.PutUint32(value[len(headerDigest):], index)
	return value
}

func writeAll(writer io.Writer, value []byte) error {
	for len(value) > 0 {
		written, err := writer.Write(value)
		if err != nil || written <= 0 || written > len(value) {
			return ErrBackupEncryption
		}
		value = value[written:]
	}
	return nil
}

// EncryptBackup rejects empty plaintext by contract. It performs a complete
// first pass over source before any ciphertext is emitted.
func EncryptBackup(destination io.Writer, source io.ReadSeeker, key []byte, context BackupEncryptionContext, random io.Reader) (BackupEncryptionReceipt, error) {
	if destination == nil || source == nil || random == nil {
		return BackupEncryptionReceipt{}, ErrBackupEncryption
	}
	gcm, err := newGCM(key)
	if err != nil {
		return BackupEncryptionReceipt{}, err
	}
	size, plainDigest, chunks, err := plaintextEvidence(source)
	if err != nil {
		return BackupEncryptionReceipt{}, err
	}
	contextDigest, err := backupContextDigest(context)
	if err != nil {
		return BackupEncryptionReceipt{}, err
	}
	prefix := make([]byte, 8)
	if _, err := io.ReadFull(random, prefix); err != nil {
		return BackupEncryptionReceipt{}, ErrBackupEncryption
	}
	header := backupEncryptionHeader{1, "AES-256-GCM-CHUNKED", backupEncryptionChunkSize, hex.EncodeToString(prefix), contextDigest, plainDigest, size, chunks}
	headerRaw, err := canonicalBackupJSON(header)
	if err != nil || len(headerRaw) == 0 || len(headerRaw) > math.MaxUint32 {
		return BackupEncryptionReceipt{}, ErrBackupEncryption
	}
	headerSum := sha256.Sum256(headerRaw)
	objectHash := sha256.New()
	writer := io.MultiWriter(destination, objectHash)
	if err := writeAll(writer, []byte(backupEncryptionMagic)); err != nil {
		return BackupEncryptionReceipt{}, err
	}
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(headerRaw)))
	if err := writeAll(writer, length[:]); err != nil || writeAll(writer, headerRaw) != nil {
		return BackupEncryptionReceipt{}, ErrBackupEncryption
	}
	buffer := make([]byte, backupEncryptionChunkSize)
	for index := uint32(0); index < chunks; index++ {
		remaining := size - int64(index)*backupEncryptionChunkSize
		want := backupEncryptionChunkSize
		if remaining < int64(want) {
			want = int(remaining)
		}
		if _, err := io.ReadFull(source, buffer[:want]); err != nil {
			return BackupEncryptionReceipt{}, ErrBackupEncryption
		}
		nonce := make([]byte, gcm.NonceSize())
		copy(nonce, prefix)
		binary.BigEndian.PutUint32(nonce[8:], index)
		ciphertext := gcm.Seal(nil, nonce, buffer[:want], frameAAD(headerSum[:], index))
		binary.BigEndian.PutUint32(length[:], uint32(len(ciphertext)))
		if err := writeAll(writer, length[:]); err != nil || writeAll(writer, ciphertext) != nil {
			return BackupEncryptionReceipt{}, ErrBackupEncryption
		}
	}
	if extra := make([]byte, 1); func() bool { n, e := source.Read(extra); return n != 0 || (e != nil && e != io.EOF) }() {
		return BackupEncryptionReceipt{}, ErrBackupEncryption
	}
	objectSum := objectHash.Sum(nil)
	fixed := int64(len(backupEncryptionMagic) + 4 + len(headerRaw))
	frameOverhead := int64(chunks) * int64(4+gcm.Overhead())
	if fixed < 0 || frameOverhead < 0 || size > math.MaxInt64-fixed-frameOverhead {
		return BackupEncryptionReceipt{}, ErrBackupEncryption
	}
	objectSize := fixed + frameOverhead + size
	return BackupEncryptionReceipt{1, header.Cipher, hex.EncodeToString(objectSum), objectSize, hex.EncodeToString(headerSum[:]), plainDigest, size, chunks}, nil
}

func readExact(reader io.Reader, size int) ([]byte, error) {
	value := make([]byte, size)
	if _, err := io.ReadFull(reader, value); err != nil {
		return nil, ErrBackupEncryption
	}
	return value, nil
}

type countingReader struct {
	reader io.Reader
	size   int64
}

func (r *countingReader) Read(value []byte) (int, error) {
	n, err := r.reader.Read(value)
	r.size += int64(n)
	return n, err
}

func decodeHeader(raw []byte) (backupEncryptionHeader, error) {
	var header backupEncryptionHeader
	if err := decodeStrict(raw, &header); err != nil {
		return backupEncryptionHeader{}, ErrBackupEncryption
	}
	if err := requireStrictFields(raw, []string{"schema_version", "cipher", "chunk_size", "nonce_prefix", "context_sha256", "plaintext_sha256", "plaintext_size", "chunk_count"}); err != nil || header.Validate() != nil {
		return backupEncryptionHeader{}, ErrBackupEncryption
	}
	return header, nil
}

// DecryptBackup verifies context, receipt, every frame, and the absence of
// trailing bytes before accepting plaintext.
func DecryptBackup(destination io.Writer, scratch io.ReadWriteSeeker, source io.Reader, key []byte, context BackupEncryptionContext, receipt BackupEncryptionReceipt) error {
	if destination == nil || scratch == nil || source == nil || receipt.Validate() != nil {
		return ErrBackupEncryption
	}
	// Scratch is the private, caller-owned quarantine for unverified plaintext.
	// Always overwrite it from the beginning so a reused file or an arbitrary
	// caller offset cannot affect the plaintext accepted after verification.
	if _, err := scratch.Seek(0, io.SeekStart); err != nil {
		return ErrBackupEncryption
	}
	gcm, err := newGCM(key)
	if err != nil {
		return err
	}
	objectHash := sha256.New()
	counted := &countingReader{reader: source}
	reader := io.TeeReader(counted, objectHash)
	magic, err := readExact(reader, len(backupEncryptionMagic))
	if err != nil || string(magic) != backupEncryptionMagic {
		return ErrBackupEncryption
	}
	lengthRaw, err := readExact(reader, 4)
	if err != nil {
		return err
	}
	headerSize := binary.BigEndian.Uint32(lengthRaw)
	if headerSize == 0 || headerSize > 1<<20 {
		return ErrBackupEncryption
	}
	headerRaw, err := readExact(reader, int(headerSize))
	if err != nil {
		return err
	}
	header, err := decodeHeader(headerRaw)
	if err != nil {
		return err
	}
	headerSum := sha256.Sum256(headerRaw)
	contextDigest, err := backupContextDigest(context)
	if err != nil || header.ContextSHA256 != contextDigest || hex.EncodeToString(headerSum[:]) != receipt.HeaderSHA256 || header.PlaintextSize != receipt.PlaintextSize || header.PlaintextSHA256 != receipt.PlaintextSHA256 || header.ChunkCount != receipt.ChunkCount {
		return ErrBackupEncryption
	}
	prefix, _ := hex.DecodeString(header.NoncePrefix)
	plainHash := sha256.New()
	var plainSize int64
	for index := uint32(0); index < header.ChunkCount; index++ {
		lengthRaw, err = readExact(reader, 4)
		if err != nil {
			return err
		}
		cipherSize := binary.BigEndian.Uint32(lengthRaw)
		if cipherSize < uint32(gcm.Overhead()) || cipherSize > backupEncryptionChunkSize+uint32(gcm.Overhead()) {
			return ErrBackupEncryption
		}
		ciphertext, err := readExact(reader, int(cipherSize))
		if err != nil {
			return err
		}
		nonce := make([]byte, gcm.NonceSize())
		copy(nonce, prefix)
		binary.BigEndian.PutUint32(nonce[8:], index)
		plain, err := gcm.Open(nil, nonce, ciphertext, frameAAD(headerSum[:], index))
		if err != nil {
			return ErrBackupEncryption
		}
		expectedPlain := backupEncryptionChunkSize
		if remaining := header.PlaintextSize - int64(index)*int64(backupEncryptionChunkSize); remaining < int64(expectedPlain) {
			expectedPlain = int(remaining)
		}
		if len(plain) != expectedPlain || writeAll(scratch, plain) != nil {
			return ErrBackupEncryption
		}
		plainHash.Write(plain)
		plainSize += int64(len(plain))
	}
	extra := make([]byte, 1)
	n, e := reader.Read(extra)
	if n != 0 || e != io.EOF {
		return ErrBackupEncryption
	}
	if plainSize != header.PlaintextSize || counted.size != receipt.ObjectSize || hex.EncodeToString(plainHash.Sum(nil)) != header.PlaintextSHA256 || hex.EncodeToString(objectHash.Sum(nil)) != receipt.ObjectSHA256 {
		return ErrBackupEncryption
	}
	if _, err := scratch.Seek(0, io.SeekStart); err != nil {
		return ErrBackupEncryption
	}
	written, err := io.CopyN(destination, scratch, plainSize)
	if err != nil || written != plainSize {
		return ErrBackupEncryption
	}
	return nil
}
