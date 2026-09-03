package install

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

const acornFoxHelperReceiptMaxBytes = 1 << 20

type acornFoxHelperVerifyDependencies struct {
	lstat  func(string) (os.FileInfo, error)
	read   func(string) ([]byte, error)
	digest func([]byte) string
}

// VerifyProductionAcornFoxHelperContract reads only fixed production paths.
// It returns the public result object directly so callers never format local
// paths, errno values, or raw receipt contents into their output.
func VerifyProductionAcornFoxHelperContract(identity AcornFoxBuildIdentityV1) AcornFoxHelperContractResultV1 {
	return verifyAcornFoxHelperContract(identity, acornFoxHelperVerifyDependencies{lstat: os.Lstat, read: readBoundedAcornFoxHelperFile, digest: acornFoxHelperSHA256})
}

func verifyAcornFoxHelperContract(identity AcornFoxBuildIdentityV1, deps acornFoxHelperVerifyDependencies) AcornFoxHelperContractResultV1 {
	fail := func(code string) AcornFoxHelperContractResultV1 {
		return AcornFoxHelperContractResultV1{SchemaVersion: AcornFoxHelperContractV1Schema, Code: code}
	}
	if identity.Validate() != nil || deps.lstat == nil || deps.read == nil || deps.digest == nil {
		return fail(AcornFoxHelperCodeIdentityMismatch)
	}
	receiptPath := filepath.Join("/var/lib/acornfox/install/releases", identity.ReleaseID+".json")
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
	receipt, err := ParseInactiveSubstrateReceiptV1(raw)
	if err != nil {
		return fail(AcornFoxHelperCodeReceiptInvalid)
	}
	if receipt.CandidateReceipt.Version != identity.Version || receipt.CandidateReceipt.ReleaseID != identity.ReleaseID || receipt.CandidateReceipt.SourceCommit != identity.SourceCommit {
		return fail(AcornFoxHelperCodeBindingMismatch)
	}
	want := receipt.UpgradeHelperSHA256
	if identity.Role == "healthcheck" {
		want = receipt.HealthHelperSHA256
	}
	self, err := deps.read("/proc/self/exe")
	if err != nil {
		return fail(AcornFoxHelperCodeExecutableUnavailable)
	}
	if deps.digest(self) != want {
		return fail(AcornFoxHelperCodeExecutableMismatch)
	}
	copyIdentity := identity
	return AcornFoxHelperContractResultV1{SchemaVersion: AcornFoxHelperContractV1Schema, OK: true, Code: AcornFoxHelperCodeOK, Identity: &copyIdentity, BindingSHA256: receipt.CandidateReceipt.BindingSHA256, ExecutableSHA256: want, SubstrateReceiptSHA256: deps.digest(raw)}
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
	return ok && stat.Uid == 0
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
