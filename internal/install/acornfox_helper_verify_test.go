package install

import (
	"errors"
	"os"
	"syscall"
	"testing"
	"time"
)

type helperReceiptInfo struct {
	mode os.FileMode
	uid  uint32
}

func (i helperReceiptInfo) Name() string       { return "receipt" }
func (i helperReceiptInfo) Size() int64        { return 1 }
func (i helperReceiptInfo) Mode() os.FileMode  { return i.mode }
func (i helperReceiptInfo) ModTime() time.Time { return time.Time{} }
func (i helperReceiptInfo) IsDir() bool        { return false }
func (i helperReceiptInfo) Sys() any           { return &syscall.Stat_t{Uid: i.uid, Gid: 0, Nlink: 1} }

func TestAcornFoxHelperVerifierReturnsOnlyCompleteEvidence(t *testing.T) {
	receipt := substrateReceiptFixture()
	raw, err := MarshalInactiveSubstrateReceiptV1(receipt)
	if err != nil {
		t.Fatal(err)
	}
	identity := AcornFoxBuildIdentityV1{SchemaVersion: AcornFoxHelperContractV1Schema, Product: AcornFoxV1Product, LayoutVersion: AcornFoxSubstrateLayoutV1, Role: "upgrade", Version: receipt.CandidateReceipt.Version, ReleaseID: receipt.CandidateReceipt.ReleaseID, SourceCommit: receipt.CandidateReceipt.SourceCommit}
	deps := acornFoxHelperVerifyDependencies{
		lstat: func(string) (os.FileInfo, error) { return helperReceiptInfo{mode: 0o600, uid: 0}, nil },
		read: func(path string) ([]byte, error) {
			if path == "/proc/self/exe" {
				return []byte("self"), nil
			}
			return raw, nil
		},
		digest: func(value []byte) string {
			if string(value) == "self" {
				return receipt.UpgradeHelperSHA256
			}
			return substrateDigest("e")
		},
	}
	result := verifyAcornFoxHelperContract(identity, deps)
	if result.Validate() != nil || !result.OK || result.Code != AcornFoxHelperCodeOK {
		t.Fatalf("result=%#v", result)
	}
	for _, test := range []struct {
		name   string
		mutate func(*acornFoxHelperVerifyDependencies)
		code   string
	}{
		{"receipt unavailable", func(d *acornFoxHelperVerifyDependencies) {
			d.lstat = func(string) (os.FileInfo, error) { return nil, errors.New("x") }
		}, AcornFoxHelperCodeReceiptUnavailable},
		{"receipt mode", func(d *acornFoxHelperVerifyDependencies) {
			d.lstat = func(string) (os.FileInfo, error) { return helperReceiptInfo{mode: 0o644, uid: 0}, nil }
		}, AcornFoxHelperCodeReceiptInvalid},
		{"self unavailable", func(d *acornFoxHelperVerifyDependencies) {
			d.read = func(path string) ([]byte, error) {
				if path == "/proc/self/exe" {
					return nil, errors.New("x")
				}
				return raw, nil
			}
		}, AcornFoxHelperCodeExecutableUnavailable},
		{"self mismatch", func(d *acornFoxHelperVerifyDependencies) {
			d.digest = func([]byte) string { return substrateDigest("f") }
		}, AcornFoxHelperCodeExecutableMismatch},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := deps
			test.mutate(&changed)
			got := verifyAcornFoxHelperContract(identity, changed)
			if got.Code != test.code || got.OK || got.Identity != nil {
				t.Fatalf("got=%#v", got)
			}
		})
	}
	invalidReceipt := deps
	invalidReceipt.read = func(path string) ([]byte, error) {
		if path == "/proc/self/exe" {
			return []byte("self"), nil
		}
		return []byte(`{}`), nil
	}
	if got := verifyAcornFoxHelperContract(identity, invalidReceipt); got.Code != AcornFoxHelperCodeReceiptInvalid || got.Identity != nil {
		t.Fatalf("invalid receipt=%#v", got)
	}
	mismatchIdentity := identity
	mismatchIdentity.SourceCommit = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if got := verifyAcornFoxHelperContract(mismatchIdentity, deps); got.Code != AcornFoxHelperCodeBindingMismatch || got.Identity != nil {
		t.Fatalf("binding mismatch=%#v", got)
	}
}
