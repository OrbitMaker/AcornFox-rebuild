package install

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func cryptoContext() BackupEncryptionContext {
	return BackupEncryptionContext{BackupID: "backup-crypto-1", BackupMetadataSHA256: strings.Repeat("a", 64), SourceActivationID: "activation-crypto-1", SourceActivationJSONSHA256: strings.Repeat("b", 64), ReleaseID: "release-crypto-1", ReleaseManifestSHA256: strings.Repeat("c", 64), ObjectKey: "open-card/backups/production/backup-crypto-1.ocbkp", KeyVersion: "key-v1"}
}

func backupScratch(t *testing.T) *os.File {
	t.Helper()
	file, err := os.CreateTemp(t.TempDir(), "backup-scratch-")
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = file.Close() })
	return file
}

func TestChunkedBackupAEADRoundTripAndBoundaries(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	if err := cryptoContext().Validate(); err != nil {
		t.Fatalf("context: %v", err)
	}
	for _, size := range []int{1, backupEncryptionChunkSize, backupEncryptionChunkSize + 1, 2*backupEncryptionChunkSize + 7} {
		plain := bytes.Repeat([]byte("x"), size)
		var encrypted bytes.Buffer
		receipt, err := EncryptBackup(&encrypted, bytes.NewReader(plain), key, cryptoContext(), bytes.NewReader(bytes.Repeat([]byte{9}, 8)))
		if err != nil || receipt.ChunkCount != uint32((size+backupEncryptionChunkSize-1)/backupEncryptionChunkSize) {
			t.Fatalf("encrypt size %d: %#v %v", size, receipt, err)
		}
		var restored bytes.Buffer
		if err := DecryptBackup(&restored, backupScratch(t), bytes.NewReader(encrypted.Bytes()), key, cryptoContext(), receipt); err != nil || !bytes.Equal(restored.Bytes(), plain) {
			t.Fatalf("decrypt size %d: %v", size, err)
		}
	}
}

func TestChunkedBackupAEADRandomPrefixAndInjectedDeterminism(t *testing.T) {
	key, plain := bytes.Repeat([]byte{5}, 32), []byte("deterministic encrypted backup")
	var first, second, randomA, randomB bytes.Buffer
	if _, err := EncryptBackup(&first, bytes.NewReader(plain), key, cryptoContext(), bytes.NewReader(bytes.Repeat([]byte{1}, 8))); err != nil {
		t.Fatal(err)
	}
	if _, err := EncryptBackup(&second, bytes.NewReader(plain), key, cryptoContext(), bytes.NewReader(bytes.Repeat([]byte{1}, 8))); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.Bytes(), second.Bytes()) {
		t.Fatal("injected randomness was not deterministic")
	}
	if _, err := EncryptBackup(&randomA, bytes.NewReader(plain), key, cryptoContext(), rand.Reader); err != nil {
		t.Fatal(err)
	}
	if _, err := EncryptBackup(&randomB, bytes.NewReader(plain), key, cryptoContext(), rand.Reader); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(randomA.Bytes(), randomB.Bytes()) {
		t.Fatal("random nonce prefixes were reused")
	}
}

func TestChunkedBackupAEADRejectsTamperWrongContextTruncateAndExtra(t *testing.T) {
	key, plain := bytes.Repeat([]byte{3}, 32), bytes.Repeat([]byte("z"), backupEncryptionChunkSize+1)
	var encrypted bytes.Buffer
	receipt, err := EncryptBackup(&encrypted, bytes.NewReader(plain), key, cryptoContext(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range [][]byte{encrypted.Bytes()[:len(encrypted.Bytes())-1], append(append([]byte(nil), encrypted.Bytes()...), 1)} {
		var destination bytes.Buffer
		if err := DecryptBackup(&destination, backupScratch(t), bytes.NewReader(value), key, cryptoContext(), receipt); err == nil || destination.Len() != 0 {
			t.Fatal("invalid frame accepted")
		}
	}
	tampered := append([]byte(nil), encrypted.Bytes()...)
	tampered[len(tampered)-1] ^= 1
	var tamperedDestination bytes.Buffer
	if err := DecryptBackup(&tamperedDestination, backupScratch(t), bytes.NewReader(tampered), key, cryptoContext(), receipt); err == nil || tamperedDestination.Len() != 0 {
		t.Fatal("tamper accepted")
	}
	wrong := cryptoContext()
	wrong.BackupID = "backup-crypto-2"
	if err := DecryptBackup(ioDiscard{}, backupScratch(t), bytes.NewReader(encrypted.Bytes()), key, wrong, receipt); err == nil {
		t.Fatal("wrong context accepted")
	}
	for name, mutate := range map[string]func(*BackupEncryptionContext){
		"backup-metadata":      func(c *BackupEncryptionContext) { c.BackupMetadataSHA256 = strings.Repeat("d", 64) },
		"activation-id":        func(c *BackupEncryptionContext) { c.SourceActivationID = "activation-crypto-2" },
		"activation-digest":    func(c *BackupEncryptionContext) { c.SourceActivationJSONSHA256 = strings.Repeat("d", 64) },
		"release-id":           func(c *BackupEncryptionContext) { c.ReleaseID = "release-crypto-2" },
		"release-manifest":     func(c *BackupEncryptionContext) { c.ReleaseManifestSHA256 = strings.Repeat("d", 64) },
		"object-key":           func(c *BackupEncryptionContext) { c.ObjectKey = "open-card/backups/production/backup-crypto-2.ocbkp" },
		"key-version":          func(c *BackupEncryptionContext) { c.KeyVersion = "key-v2" },
		"object-scope-invalid": func(c *BackupEncryptionContext) { c.ObjectKey = "open-card/backups/../backup-crypto-1.ocbkp" },
	} {
		t.Run(name, func(t *testing.T) {
			context := cryptoContext()
			mutate(&context)
			if err := DecryptBackup(ioDiscard{}, backupScratch(t), bytes.NewReader(encrypted.Bytes()), key, context, receipt); err == nil {
				t.Fatal("context drift accepted")
			}
		})
	}
	if err := DecryptBackup(ioDiscard{}, backupScratch(t), bytes.NewReader(encrypted.Bytes()), bytes.Repeat([]byte{8}, 32), cryptoContext(), receipt); err == nil {
		t.Fatal("wrong key accepted")
	}
	wrongSize := receipt
	wrongSize.ObjectSize++
	if err := DecryptBackup(ioDiscard{}, backupScratch(t), bytes.NewReader(encrypted.Bytes()), key, cryptoContext(), wrongSize); err == nil {
		t.Fatal("wrong object size accepted")
	}
	if _, err := EncryptBackup(&bytes.Buffer{}, bytes.NewReader(nil), key, cryptoContext(), rand.Reader); err == nil {
		t.Fatal("empty plaintext accepted")
	}
}

func TestBackupEncryptionHeaderAndReceiptAreStrict(t *testing.T) {
	key := bytes.Repeat([]byte{4}, 32)
	var encrypted bytes.Buffer
	receipt, err := EncryptBackup(&encrypted, bytes.NewReader([]byte("strict backup payload")), key, cryptoContext(), bytes.NewReader(bytes.Repeat([]byte{2}, 8)))
	if err != nil {
		t.Fatal(err)
	}
	raw := encrypted.Bytes()
	offset := len(backupEncryptionMagic)
	headerSize := int(binary.BigEndian.Uint32(raw[offset : offset+4]))
	headerRaw := append([]byte(nil), raw[offset+4:offset+4+headerSize]...)
	if _, err := decodeHeader(headerRaw); err != nil {
		t.Fatal(err)
	}
	for name, mutation := range map[string][]byte{
		"duplicate": append([]byte(`{"schema_version":1,`), headerRaw[1:]...),
		"missing":   bytes.Replace(headerRaw, []byte(`"cipher":"AES-256-GCM-CHUNKED",`), nil, 1),
		"unknown":   append(headerRaw[:len(headerRaw)-1], []byte(`,"unknown":true}`)...),
		"trailing":  append(append([]byte(nil), headerRaw...), []byte(` {}`)...),
		"null":      bytes.Replace(headerRaw, []byte(`"nonce_prefix":"`), []byte(`"nonce_prefix":null,"old_nonce":"`), 1),
	} {
		t.Run("header-"+name, func(t *testing.T) {
			if _, err := decodeHeader(mutation); err == nil {
				t.Fatal("invalid header accepted")
			}
		})
	}
	receiptRaw, err := MarshalBackupEncryptionReceipt(receipt)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseBackupEncryptionReceipt(receiptRaw)
	if err != nil || parsed != receipt {
		t.Fatalf("receipt=%+v err=%v", parsed, err)
	}
	for name, mutation := range map[string][]byte{
		"duplicate": append([]byte(`{"schema_version":1,`), receiptRaw[1:]...),
		"missing":   bytes.Replace(receiptRaw, []byte(`"cipher":"AES-256-GCM-CHUNKED",`), nil, 1),
		"unknown":   append(receiptRaw[:len(receiptRaw)-1], []byte(`,"unknown":true}`)...),
		"trailing":  append(append([]byte(nil), receiptRaw...), []byte(` {}`)...),
		"null":      bytes.Replace(receiptRaw, []byte(`"object_sha256":"`), []byte(`"object_sha256":null,"old_object":"`), 1),
	} {
		t.Run("receipt-"+name, func(t *testing.T) {
			if _, err := ParseBackupEncryptionReceipt(mutation); err == nil {
				t.Fatal("invalid receipt accepted")
			}
		})
	}
	encoded, _ := json.Marshal(receipt)
	for _, forbidden := range []string{"password", "postgresql://", "token", "/var/lib"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("receipt leaked %q", forbidden)
		}
	}
}

type ioDiscard struct{}

func (ioDiscard) Write(p []byte) (int, error) { return len(p), nil }
