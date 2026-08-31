package install

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"testing"
)

func platformCryptoFixture(t *testing.T) ([]byte, BackupEncryptionContextV2) {
	t.Helper()
	return platformCryptoFixtureInput(t, platformBackupInput(t))
}

func assertEmptyBackupScratch(t *testing.T, scratch *os.File) {
	t.Helper()
	info, err := scratch.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != 0 {
		t.Fatalf("scratch retained plaintext: size=%d", info.Size())
	}
}

func platformCryptoFixtureInput(t *testing.T, input PlatformBackupPackageInput) ([]byte, BackupEncryptionContextV2) {
	t.Helper()
	packageRaw := platformBackupBytes(t, input)
	manifestSize := platformTestManifestSize(t, packageRaw)
	manifestRaw := packageRaw[512 : 512+manifestSize]
	manifest, err := ParsePlatformBackupV3(manifestRaw)
	if err != nil {
		t.Fatal(err)
	}
	packageSum, manifestSum := sha256.Sum256(packageRaw), sha256.Sum256(manifestRaw)
	context := BackupEncryptionContextV2{
		BackupID: manifest.BackupID, SourceInstallationIDSHA256: manifest.SourceInstallationIDSHA256,
		PackageManifestSHA256: hex.EncodeToString(manifestSum[:]), PackageSHA256: hex.EncodeToString(packageSum[:]),
		SourceActivationID: manifest.SourceActivationID, SourceActivationJSONSHA256: manifest.SourceActivationJSONSHA256,
		ReleaseID: manifest.SourceRelease.ID, ReleaseManifestSHA256: manifest.SourceRelease.ManifestSHA256,
		ObjectKey: "open-card/backups/" + manifest.SourceInstallationIDSHA256 + "/" + manifest.BackupID + ".ocbkp", KeyVersion: "key-v1",
	}
	if err := context.Validate(); err != nil {
		t.Fatal(err)
	}
	return packageRaw, context
}

func TestPlatformBackupEncryptionContextV2CanonicalAndDomainSeparated(t *testing.T) {
	_, context := platformCryptoFixture(t)
	raw, err := MarshalBackupEncryptionContextV2(context)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseBackupEncryptionContextV2(raw)
	if err != nil || parsed != context {
		t.Fatalf("parsed=%+v err=%v", parsed, err)
	}
	for name, mutate := range map[string][]byte{
		"unknown":   append(append([]byte(nil), raw[:len(raw)-1]...), []byte(`,"unknown":true}`)...),
		"trailing":  append(append([]byte(nil), raw...), []byte(" {}")...),
		"schema":    bytes.Replace(raw, []byte(BackupEncryptionContextV2Schema), []byte("other"), 1),
		"version":   bytes.Replace(raw, []byte(`"schema_version":2`), []byte(`"schema_version":1`), 1),
		"reordered": append([]byte(`{ "schema":"`+BackupEncryptionContextV2Schema+`"}`), nil...),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseBackupEncryptionContextV2(mutate); err == nil {
				t.Fatal("non-canonical context accepted")
			}
		})
	}
	v1 := cryptoContext()
	v1Digest, err := backupContextDigest(v1)
	if err != nil {
		t.Fatal(err)
	}
	v2Digest, err := backupContextDigestV2(context)
	if err != nil || v1Digest == v2Digest {
		t.Fatalf("v1=%s v2=%s err=%v", v1Digest, v2Digest, err)
	}
	for name, mutate := range map[string]func(*BackupEncryptionContextV2){
		"wrong-scope": func(c *BackupEncryptionContextV2) {
			c.ObjectKey = "open-card/backups/production/" + c.BackupID + ".ocbkp"
		},
		"invalid-key-version": func(c *BackupEncryptionContextV2) { c.KeyVersion = "v1" },
	} {
		t.Run(name, func(t *testing.T) {
			invalid := context
			mutate(&invalid)
			if err := invalid.Validate(); err == nil {
				t.Fatal("invalid V2 binding accepted")
			}
		})
	}
}

func TestPlatformBackupEncryptionV2RoundTripAndAuthenticatedContext(t *testing.T) {
	packageRaw, context := platformCryptoFixture(t)
	key := bytes.Repeat([]byte{6}, 32)
	var encrypted bytes.Buffer
	receipt, err := EncryptPlatformBackup(&encrypted, bytes.NewReader(packageRaw), key, context, bytes.NewReader(bytes.Repeat([]byte{8}, 8)))
	if err != nil || receipt.PlaintextSize != int64(len(packageRaw)) {
		t.Fatalf("receipt=%+v err=%v", receipt, err)
	}
	var restored bytes.Buffer
	scratch := backupScratch(t)
	if err := DecryptPlatformBackup(&restored, scratch, bytes.NewReader(encrypted.Bytes()), key, context, receipt); err != nil || !bytes.Equal(restored.Bytes(), packageRaw) {
		t.Fatalf("decrypt=%v", err)
	}
	assertEmptyBackupScratch(t, scratch)
	for name, mutate := range map[string]func(*BackupEncryptionContextV2){
		"backup-id": func(c *BackupEncryptionContextV2) {
			c.BackupID = "backup-other"
			c.ObjectKey = "open-card/backups/" + c.SourceInstallationIDSHA256 + "/backup-other.ocbkp"
		},
		"installation":     func(c *BackupEncryptionContextV2) { c.SourceInstallationIDSHA256 = strings.Repeat("d", 64) },
		"manifest":         func(c *BackupEncryptionContextV2) { c.PackageManifestSHA256 = strings.Repeat("d", 64) },
		"package":          func(c *BackupEncryptionContextV2) { c.PackageSHA256 = strings.Repeat("d", 64) },
		"activation-id":    func(c *BackupEncryptionContextV2) { c.SourceActivationID = "activation-other" },
		"activation-json":  func(c *BackupEncryptionContextV2) { c.SourceActivationJSONSHA256 = strings.Repeat("d", 64) },
		"release-id":       func(c *BackupEncryptionContextV2) { c.ReleaseID = "release-other" },
		"release-manifest": func(c *BackupEncryptionContextV2) { c.ReleaseManifestSHA256 = strings.Repeat("d", 64) },
		"object-key":       func(c *BackupEncryptionContextV2) { c.ObjectKey = "open-card/backups/staging/" + c.BackupID + ".ocbkp" },
		"key-version":      func(c *BackupEncryptionContextV2) { c.KeyVersion = "key-v2" },
	} {
		t.Run(name, func(t *testing.T) {
			wrong := context
			mutate(&wrong)
			var destination bytes.Buffer
			if err := DecryptPlatformBackup(&destination, backupScratch(t), bytes.NewReader(encrypted.Bytes()), key, wrong, receipt); err == nil || destination.Len() != 0 {
				t.Fatal("context drift accepted")
			}
		})
	}
	var v1Destination bytes.Buffer
	if err := DecryptBackup(&v1Destination, backupScratch(t), bytes.NewReader(encrypted.Bytes()), key, cryptoContext(), receipt); err == nil || v1Destination.Len() != 0 {
		t.Fatal("V2 ciphertext accepted as V1")
	}
	var v1Ciphertext bytes.Buffer
	v1Receipt, err := EncryptBackup(&v1Ciphertext, bytes.NewReader([]byte("v1 plaintext")), key, cryptoContext(), bytes.NewReader(bytes.Repeat([]byte{8}, 8)))
	if err != nil {
		t.Fatal(err)
	}
	if err := DecryptPlatformBackup(ioDiscard{}, backupScratch(t), bytes.NewReader(v1Ciphertext.Bytes()), key, context, v1Receipt); err == nil {
		t.Fatal("V1 ciphertext accepted as V2")
	}
}

func TestPlatformBackupEncryptionV2MultiChunk(t *testing.T) {
	input := platformBackupInput(t)
	platformTestReplace(&input, "database/control-plane.dump", bytes.Repeat([]byte("d"), backupEncryptionChunkSize+1))
	packageRaw, context := platformCryptoFixtureInput(t, input)
	key := bytes.Repeat([]byte{4}, 32)
	var encrypted bytes.Buffer
	receipt, err := EncryptPlatformBackup(&encrypted, bytes.NewReader(packageRaw), key, context, bytes.NewReader(bytes.Repeat([]byte{4}, 8)))
	if err != nil || receipt.ChunkCount < 2 {
		t.Fatalf("receipt=%+v err=%v", receipt, err)
	}
	var restored bytes.Buffer
	if err := DecryptPlatformBackup(&restored, backupScratch(t), bytes.NewReader(encrypted.Bytes()), key, context, receipt); err != nil || !bytes.Equal(restored.Bytes(), packageRaw) {
		t.Fatalf("decrypt=%v", err)
	}
}

func TestPlatformBackupEncryptionV2RejectsCorruptionAndDoesNotReleasePlaintext(t *testing.T) {
	packageRaw, context := platformCryptoFixture(t)
	key := bytes.Repeat([]byte{2}, 32)
	var encrypted bytes.Buffer
	receipt, err := EncryptPlatformBackup(&encrypted, bytes.NewReader(packageRaw), key, context, bytes.NewReader(bytes.Repeat([]byte{3}, 8)))
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string][]byte{
		"header":   append([]byte(nil), encrypted.Bytes()[:len(backupEncryptionMagic)+7]...),
		"frame":    func() []byte { v := append([]byte(nil), encrypted.Bytes()...); v[len(v)-1] ^= 1; return v }(),
		"trailing": append(append([]byte(nil), encrypted.Bytes()...), 1),
	} {
		t.Run(name, func(t *testing.T) {
			var destination bytes.Buffer
			if err := DecryptPlatformBackup(&destination, backupScratch(t), bytes.NewReader(value), key, context, receipt); err == nil || destination.Len() != 0 {
				t.Fatal("corruption released plaintext")
			}
		})
	}
	var wrongKey bytes.Buffer
	if err := DecryptPlatformBackup(&wrongKey, backupScratch(t), bytes.NewReader(encrypted.Bytes()), bytes.Repeat([]byte{9}, 32), context, receipt); err == nil || wrongKey.Len() != 0 {
		t.Fatal("wrong key accepted")
	}
	wrongPackage := context
	wrongPackage.PackageSHA256 = strings.Repeat("f", 64)
	if _, err := EncryptPlatformBackup(&bytes.Buffer{}, bytes.NewReader(packageRaw), key, wrongPackage, bytes.NewReader(bytes.Repeat([]byte{3}, 8))); err == nil {
		t.Fatal("wrong package evidence emitted ciphertext")
	}
	if _, err := EncryptPlatformBackup(&bytes.Buffer{}, bytes.NewReader(nil), key, context, bytes.NewReader(bytes.Repeat([]byte{3}, 8))); err == nil {
		t.Fatal("zero-length source accepted")
	}
	mutated := append([]byte(nil), packageRaw...)
	mutated[len(mutated)-1] ^= 1
	var partial bytes.Buffer
	if _, err := EncryptPlatformBackup(&partial, &platformBackupMutatingReader{current: bytes.NewReader(packageRaw), replacement: mutated, mutateAtStartSeek: 3}, key, context, bytes.NewReader(bytes.Repeat([]byte{3}, 8))); err == nil {
		t.Fatal("source mutation after evidence accepted")
	}
}

func TestPlatformBackupEncryptionV2FailureTruncatesScratch(t *testing.T) {
	input := platformBackupInput(t)
	platformTestReplace(&input, "database/control-plane.dump", bytes.Repeat([]byte("d"), backupEncryptionChunkSize+1))
	packageRaw, context := platformCryptoFixtureInput(t, input)
	key := bytes.Repeat([]byte{1}, 32)
	var encrypted bytes.Buffer
	receipt, err := EncryptPlatformBackup(&encrypted, bytes.NewReader(packageRaw), key, context, bytes.NewReader(bytes.Repeat([]byte{1}, 8)))
	if err != nil || receipt.ChunkCount < 2 {
		t.Fatalf("receipt=%+v err=%v", receipt, err)
	}
	lateFrame := append([]byte(nil), encrypted.Bytes()...)
	lateFrame[len(lateFrame)-1] ^= 1
	trailing := append(append([]byte(nil), encrypted.Bytes()...), 1)
	for name, source := range map[string][]byte{"late-frame": lateFrame, "trailing-after-plaintext": trailing} {
		t.Run(name, func(t *testing.T) {
			scratch := backupScratch(t)
			var destination bytes.Buffer
			if err := DecryptPlatformBackup(&destination, scratch, bytes.NewReader(source), key, context, receipt); err == nil || destination.Len() != 0 {
				t.Fatal("invalid object released plaintext")
			}
			assertEmptyBackupScratch(t, scratch)
		})
	}

	contextDigest, err := backupContextDigestV2(context)
	if err != nil {
		t.Fatal(err)
	}
	var validAEAD bytes.Buffer
	invalidPackageReceipt, err := encryptBackup(&validAEAD, bytes.NewReader([]byte("not a PlatformBackupV3 package")), key, contextDigest, bytes.NewReader(bytes.Repeat([]byte{2}, 8)), plaintextEvidence)
	if err != nil {
		t.Fatal(err)
	}
	scratch := backupScratch(t)
	var destination bytes.Buffer
	if err := DecryptPlatformBackup(&destination, scratch, bytes.NewReader(validAEAD.Bytes()), key, context, invalidPackageReceipt); err == nil || destination.Len() != 0 {
		t.Fatal("invalid decrypted package released plaintext")
	}
	assertEmptyBackupScratch(t, scratch)
}

type platformBackupMutatingReader struct {
	current           *bytes.Reader
	replacement       []byte
	startSeeks        int
	mutateAtStartSeek int
}

func (r *platformBackupMutatingReader) Read(value []byte) (int, error) { return r.current.Read(value) }
func (r *platformBackupMutatingReader) Seek(offset int64, whence int) (int64, error) {
	if offset == 0 && whence == 0 {
		r.startSeeks++
		if r.startSeeks == r.mutateAtStartSeek {
			r.current = bytes.NewReader(r.replacement)
		}
	}
	return r.current.Seek(offset, whence)
}
