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

type acornFoxHelperOpenedFile interface {
	io.Reader
	io.Seeker
	Stat() (os.FileInfo, error)
}

// VerifyProductionAcornFoxHelperContract reads only fixed host paths. Both
// production and modeled-rootfs callers converge on the opened-file core.
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
	receipt, err := root.OpenFile(identity.ReleaseID+".json", os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return fail(AcornFoxHelperCodeReceiptUnavailable)
	}
	defer receipt.Close()
	self, err := os.Open("/proc/self/exe")
	if err != nil {
		return fail(AcornFoxHelperCodeExecutableUnavailable)
	}
	defer self.Close()
	return verifyAcornFoxHelperOpenedFiles(identity, receipt, self, 0, 0)
}

// verifyPublishedAcornFoxHelperContract opens through the pinned modeled root.
// It is internal test/publisher evidence, not an activation API.
func verifyPublishedAcornFoxHelperContract(identity AcornFoxBuildIdentityV1, published *PublishedAcornFoxSubstrateV1) AcornFoxHelperContractResultV1 {
	fail := func(code string) AcornFoxHelperContractResultV1 {
		return AcornFoxHelperContractResultV1{SchemaVersion: AcornFoxHelperContractV1Schema, Code: code}
	}
	if identity.Validate() != nil {
		return fail(AcornFoxHelperCodeIdentityMismatch)
	}
	if published == nil || published.root == nil {
		return fail(AcornFoxHelperCodeReceiptUnavailable)
	}
	receiptPath := acornFoxSubstrateTarget("var/lib/acornfox/install/releases/" + identity.ReleaseID + ".json")
	receipt, err := published.fs.openFile(published.root, receiptPath, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return fail(AcornFoxHelperCodeReceiptUnavailable)
	}
	defer receipt.Close()
	helperPath := AcornFoxUpgradeHelperPath
	if identity.Role == "healthcheck" {
		helperPath = AcornFoxHealthcheckHelperPath(published.receipt.CandidateReceipt)
	}
	helper, err := published.fs.openFile(published.root, acornFoxSubstrateTarget(helperPath), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return fail(AcornFoxHelperCodeExecutableUnavailable)
	}
	defer helper.Close()
	return verifyAcornFoxHelperOpenedFiles(identity, receipt, helper, published.uid, published.gid)
}

func verifyAcornFoxHelperOpenedFiles(identity AcornFoxBuildIdentityV1, receiptFile, executable acornFoxHelperOpenedFile, uid, gid int) AcornFoxHelperContractResultV1 {
	fail := func(code string) AcornFoxHelperContractResultV1 {
		return AcornFoxHelperContractResultV1{SchemaVersion: AcornFoxHelperContractV1Schema, Code: code}
	}
	if identity.Validate() != nil || receiptFile == nil || executable == nil || uid < 0 || gid < 0 {
		return fail(AcornFoxHelperCodeIdentityMismatch)
	}
	receiptInfo, err := receiptFile.Stat()
	if err != nil || !safeAcornFoxHelperReceiptInfo(receiptInfo, uid, gid) {
		return fail(AcornFoxHelperCodeReceiptInvalid)
	}
	raw, err := readBoundedAcornFoxHelperOpenedFile(receiptFile, acornFoxHelperReceiptMaxBytes)
	if err != nil {
		return fail(AcornFoxHelperCodeReceiptUnavailable)
	}
	executableInfo, err := executable.Stat()
	if err != nil || !safeAcornFoxHelperExecutableInfo(executableInfo, uid, gid) {
		return fail(AcornFoxHelperCodeExecutableUnavailable)
	}
	digest, err := hashAcornFoxHelperOpenedFile(executable, acornFoxHelperExecutableMaxBytes)
	if err != nil {
		return fail(AcornFoxHelperCodeExecutableUnavailable)
	}
	return verifyAcornFoxHelperResult(identity, raw, digest)
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

func safeAcornFoxHelperReceiptInfo(info os.FileInfo, uid, gid int) bool {
	if info == nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(uid) && stat.Gid == uint32(gid) && stat.Nlink == 1
}

func safeAcornFoxHelperOwner(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == 0 && stat.Gid == 0 && info.Mode().Perm()&0o022 == 0
}

func safeAcornFoxHelperReceiptParentInfo(info os.FileInfo) bool {
	return info != nil && info.Mode()&os.ModeSymlink == 0 && info.IsDir() && info.Mode().Perm() == 0o755 && safeAcornFoxHelperOwner(info)
}

func safeAcornFoxHelperExecutableInfo(info os.FileInfo, uid, gid int) bool {
	if info == nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 || info.Size() < 1 || info.Size() > acornFoxHelperExecutableMaxBytes {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(uid) && stat.Gid == uint32(gid) && stat.Nlink == 1
}

func readBoundedAcornFoxHelperOpenedFile(file io.ReadSeeker, maximum int64) ([]byte, error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(data)) > maximum {
		return nil, os.ErrInvalid
	}
	return data, nil
}

func hashAcornFoxHelperOpenedFile(file io.ReadSeeker, maximum int64) (string, error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	hash := sha256.New()
	if _, err := io.CopyBuffer(hash, io.LimitReader(file, maximum+1), make([]byte, 32<<10)); err != nil {
		return "", err
	}
	if offset, err := file.Seek(0, io.SeekCurrent); err != nil || offset > maximum {
		return "", os.ErrInvalid
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
