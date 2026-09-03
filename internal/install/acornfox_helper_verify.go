package install

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"syscall"
)

const acornFoxHelperReceiptMaxBytes = 1 << 20
const acornFoxHelperExecutableMaxBytes = 256 << 20

type acornFoxHelperVerifyDependencies struct {
	lstat  func(string) (os.FileInfo, error)
	read   func(string) ([]byte, error)
	digest func([]byte) string
}

// VerifyProductionAcornFoxHelperContract reads only fixed production paths.
// It returns the public result object directly so callers never format local
// paths, errno values, or raw receipt contents into their output.
func VerifyProductionAcornFoxHelperContract(identity AcornFoxBuildIdentityV1) AcornFoxHelperContractResultV1 {
	fail := func(code string) AcornFoxHelperContractResultV1 {
		return AcornFoxHelperContractResultV1{SchemaVersion: AcornFoxHelperContractV1Schema, Code: code}
	}
	if identity.Validate() != nil {
		return fail(AcornFoxHelperCodeIdentityMismatch)
	}
	const receiptParent = "/var/lib/acornfox/install/releases"
	if ensureNoSymlinkBetween("/var/lib", receiptParent) != nil {
		return fail(AcornFoxHelperCodeReceiptInvalid)
	}
	parentInfo, err := os.Lstat(receiptParent)
	if err != nil {
		return fail(AcornFoxHelperCodeReceiptUnavailable)
	}
	if !safeAcornFoxHelperReceiptParentInfo(parentInfo) {
		return fail(AcornFoxHelperCodeReceiptInvalid)
	}
	root, err := os.OpenRoot(receiptParent)
	if err != nil {
		return fail(AcornFoxHelperCodeReceiptUnavailable)
	}
	defer root.Close()
	directory, err := root.OpenFile(".", os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return fail(AcornFoxHelperCodeReceiptInvalid)
	}
	directoryInfo, statErr := directory.Stat()
	closeErr := directory.Close()
	if statErr != nil || closeErr != nil || directoryInfo == nil || !os.SameFile(parentInfo, directoryInfo) || !safeAcornFoxHelperReceiptParentInfo(directoryInfo) {
		return fail(AcornFoxHelperCodeReceiptInvalid)
	}
	file, err := root.OpenFile(identity.ReleaseID+".json", os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return fail(AcornFoxHelperCodeReceiptUnavailable)
	}
	info, statErr := file.Stat()
	if statErr != nil || !safeAcornFoxHelperReceiptInfo(info) {
		_ = file.Close()
		return fail(AcornFoxHelperCodeReceiptInvalid)
	}
	raw, readErr := readBoundedAcornFoxHelperOpenFile(file, acornFoxHelperReceiptMaxBytes)
	closeErr = file.Close()
	if readErr != nil || closeErr != nil {
		return fail(AcornFoxHelperCodeReceiptUnavailable)
	}
	self, err := os.Open("/proc/self/exe")
	if err != nil {
		return fail(AcornFoxHelperCodeExecutableUnavailable)
	}
	selfInfo, selfStatErr := self.Stat()
	if selfStatErr != nil || !safeAcornFoxHelperExecutableInfo(selfInfo) {
		_ = self.Close()
		return fail(AcornFoxHelperCodeExecutableUnavailable)
	}
	selfDigest, selfReadErr := hashAcornFoxHelperOpenFile(self, acornFoxHelperExecutableMaxBytes)
	selfCloseErr := self.Close()
	if selfReadErr != nil || selfCloseErr != nil {
		return fail(AcornFoxHelperCodeExecutableUnavailable)
	}
	return verifyAcornFoxHelperResult(identity, raw, selfDigest)
}

func verifyAcornFoxHelperContract(identity AcornFoxBuildIdentityV1, deps acornFoxHelperVerifyDependencies) AcornFoxHelperContractResultV1 {
	fail := func(code string) AcornFoxHelperContractResultV1 {
		return AcornFoxHelperContractResultV1{SchemaVersion: AcornFoxHelperContractV1Schema, Code: code}
	}
	if identity.Validate() != nil || deps.lstat == nil || deps.read == nil || deps.digest == nil {
		return fail(AcornFoxHelperCodeIdentityMismatch)
	}
	receiptPath := identity.ReleaseID + ".json"
	info, err := deps.lstat(receiptPath)
	if err != nil {
		return fail(AcornFoxHelperCodeReceiptUnavailable)
	}
	if !safeAcornFoxHelperReceiptInfo(info) {
		return fail(AcornFoxHelperCodeReceiptInvalid)
	}
	raw, err := deps.read(receiptPath)
	if err != nil {
		return fail(AcornFoxHelperCodeReceiptUnavailable)
	}
	self, err := deps.read("/proc/self/exe")
	if err != nil {
		return fail(AcornFoxHelperCodeExecutableUnavailable)
	}
	return verifyAcornFoxHelperResult(identity, raw, deps.digest(self))
}

func verifyAcornFoxHelperResult(identity AcornFoxBuildIdentityV1, raw []byte, selfDigest string) AcornFoxHelperContractResultV1 {
	fail := func(code string) AcornFoxHelperContractResultV1 {
		return AcornFoxHelperContractResultV1{SchemaVersion: AcornFoxHelperContractV1Schema, Code: code}
	}
	receipt, err := ParseInactiveSubstrateReceiptV1(raw)
	if err != nil {
		return fail(AcornFoxHelperCodeReceiptInvalid)
	}
	if receipt.CandidateReceipt.Version != identity.Version || receipt.CandidateReceipt.ReleaseID != identity.ReleaseID || receipt.CandidateReceipt.SourceCommit != identity.SourceCommit || receipt.CandidateReceipt.Validate() != nil {
		return fail(AcornFoxHelperCodeBindingMismatch)
	}
	want := receipt.UpgradeHelperSHA256
	if identity.Role == "healthcheck" {
		want = receipt.HealthHelperSHA256
	}
	if selfDigest != want {
		return fail(AcornFoxHelperCodeExecutableMismatch)
	}
	copyIdentity := identity
	return AcornFoxHelperContractResultV1{SchemaVersion: AcornFoxHelperContractV1Schema, OK: true, Code: AcornFoxHelperCodeOK, Identity: &copyIdentity, BindingSHA256: receipt.CandidateReceipt.BindingSHA256, ExecutableSHA256: want, SubstrateReceiptSHA256: acornFoxHelperSHA256(raw)}
}

func acornFoxHelperSHA256(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func safeAcornFoxHelperReceiptInfo(info os.FileInfo) bool {
	if info == nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == 0 && stat.Gid == 0 && stat.Nlink == 1
}

func safeAcornFoxHelperOwner(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == 0 && stat.Gid == 0 && info.Mode().Perm()&0o022 == 0
}

func safeAcornFoxHelperReceiptParentInfo(info os.FileInfo) bool {
	return info != nil && info.Mode()&os.ModeSymlink == 0 && info.IsDir() && info.Mode().Perm() == 0o755 && safeAcornFoxHelperOwner(info)
}
func safeAcornFoxHelperExecutableInfo(info os.FileInfo) bool {
	return info != nil && info.Mode().IsRegular() && info.Mode().Perm()&0o111 != 0 && info.Size() >= 1 && info.Size() <= acornFoxHelperExecutableMaxBytes && safeAcornFoxHelperOwner(info)
}

func readBoundedAcornFoxHelperFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, acornFoxHelperReceiptMaxBytes+1))
	if err != nil || len(data) > acornFoxHelperReceiptMaxBytes {
		return nil, os.ErrInvalid
	}
	return data, nil
}

func readBoundedAcornFoxHelperOpenFile(file *os.File, maximum int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(data)) > maximum {
		return nil, os.ErrInvalid
	}
	return data, nil
}
func hashAcornFoxHelperOpenFile(file *os.File, maximum int64) (string, error) {
	hash := sha256.New()
	if _, err := io.CopyBuffer(hash, io.LimitReader(file, maximum+1), make([]byte, 32<<10)); err != nil {
		return "", err
	}
	if offset, err := file.Seek(0, io.SeekCurrent); err != nil || offset > maximum {
		return "", os.ErrInvalid
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
