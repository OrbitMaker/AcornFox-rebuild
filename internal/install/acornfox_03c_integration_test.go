package install

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func newAcornFox03CPublished(t *testing.T) (string, *TaskAcornFoxSubstratePublisher, *PublishedAcornFoxSubstrateV1, InactiveSubstrateReceiptV1) {
	t.Helper()
	root, publisher, stage, candidate := newAcornFoxSubstrateTestPublisher(t)
	publishedResult, err := publisher.Publish(context.Background(), stage, candidate.BindingSHA256)
	if err != nil || publishedResult.Outcome != AcornFoxReconcileCompleted {
		t.Fatalf("publish=%#v err=%v", publishedResult, err)
	}
	published, err := publisher.Reopen(candidate.BindingSHA256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = published.Close() })
	return root, publisher, published, publishedResult.Receipt
}

func acornFox03CIdentity(receipt InactiveSubstrateReceiptV1, role string) AcornFoxBuildIdentityV1 {
	return AcornFoxBuildIdentityV1{SchemaVersion: AcornFoxHelperContractV1Schema, Product: AcornFoxV1Product, LayoutVersion: AcornFoxSubstrateLayoutV1, Role: role, Version: receipt.CandidateReceipt.Version, ReleaseID: receipt.CandidateReceipt.ReleaseID, SourceCommit: receipt.CandidateReceipt.SourceCommit}
}

func acornFox03CControlPath(root string, receipt InactiveSubstrateReceiptV1) string {
	return filepath.Join(root, acornFoxSubstrateRootfs, "var", "lib", "acornfox", "install", "releases", receipt.CandidateReceipt.ReleaseID+".json")
}

func TestAcornFox03CCandidateStagePublishReopenHelperEvidence(t *testing.T) {
	root, _, published, receipt := newAcornFox03CPublished(t)
	if err := published.Verify(); err != nil {
		t.Fatal(err)
	}
	outer, err := os.ReadFile(filepath.Join(root, acornFoxSubstrateReceipt))
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := MarshalInactiveSubstrateReceiptV1(receipt)
	if err != nil || string(outer) != string(canonical) {
		t.Fatalf("outer receipt canonical=%t err=%v", string(outer) == string(canonical), err)
	}
	control, err := os.ReadFile(acornFox03CControlPath(root, receipt))
	if err != nil || string(control) != string(outer) {
		t.Fatalf("release control differs from outer receipt: %v", err)
	}
	if substrateEntryAt(receipt.Entries, "var/lib/acornfox/install/releases/"+receipt.CandidateReceipt.ReleaseID+".json") != nil {
		t.Fatal("receipt control leaked into InstalledTree entries")
	}
	if string(outer) != string(canonical) || strings.Contains(string(outer), "substrate_receipt_sha256") || strings.Contains(string(outer), "self_hash") {
		t.Fatal("receipt control carries noncanonical or self-hash evidence")
	}
	for _, forbidden := range []string{filepath.Join(root, acornFoxSubstrateRootfs, "opt", "acornfox", "current"), filepath.Join(root, acornFoxSubstrateRootfs, "opt", "acornfox", "active")} {
		if _, err := os.Lstat(forbidden); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("inactive rootfs contains risk path %s: %v", forbidden, err)
		}
	}
	results := make(map[string]AcornFoxHelperContractResultV1)
	for _, role := range []string{"upgrade", "healthcheck"} {
		result := verifyPublishedAcornFoxHelperContract(acornFox03CIdentity(receipt, role), published)
		if result.Validate() != nil || !result.OK || result.Code != AcornFoxHelperCodeOK {
			t.Fatalf("role=%s result=%#v", role, result)
		}
		if result.BindingSHA256 != receipt.CandidateReceipt.BindingSHA256 || result.SubstrateReceiptSHA256 != acornFoxHelperSHA256(outer) {
			t.Fatalf("role=%s result is not bound to published receipt: %#v", role, result)
		}
		results[role] = result
	}
	if results["upgrade"].ExecutableSHA256 != receipt.UpgradeHelperSHA256 || results["healthcheck"].ExecutableSHA256 != receipt.HealthHelperSHA256 {
		t.Fatalf("helper digest evidence = %#v", results)
	}
}

func TestAcornFox03CRejectsPublishedHelperAndBindingTamper(t *testing.T) {
	for _, test := range []struct {
		name  string
		apply func(string, InactiveSubstrateReceiptV1, *PublishedAcornFoxSubstrateV1) AcornFoxBuildIdentityV1
		code  string
	}{
		{"upgrade helper", func(root string, receipt InactiveSubstrateReceiptV1, _ *PublishedAcornFoxSubstrateV1) AcornFoxBuildIdentityV1 {
			if err := os.WriteFile(filepath.Join(root, acornFoxSubstrateRootfs, filepath.FromSlash(AcornFoxUpgradeHelperPath)), []byte("tampered"), 0o755); err != nil {
				t.Fatal(err)
			}
			return acornFox03CIdentity(receipt, "upgrade")
		}, AcornFoxHelperCodeExecutableMismatch},
		{"health helper", func(root string, receipt InactiveSubstrateReceiptV1, _ *PublishedAcornFoxSubstrateV1) AcornFoxBuildIdentityV1 {
			if err := os.WriteFile(filepath.Join(root, acornFoxSubstrateRootfs, filepath.FromSlash(AcornFoxHealthcheckHelperPath(receipt.CandidateReceipt))), []byte("tampered"), 0o755); err != nil {
				t.Fatal(err)
			}
			return acornFox03CIdentity(receipt, "healthcheck")
		}, AcornFoxHelperCodeExecutableMismatch},
		{"receipt", func(root string, receipt InactiveSubstrateReceiptV1, _ *PublishedAcornFoxSubstrateV1) AcornFoxBuildIdentityV1 {
			if err := os.WriteFile(acornFox03CControlPath(root, receipt), []byte("{}"), 0o600); err != nil {
				t.Fatal(err)
			}
			return acornFox03CIdentity(receipt, "upgrade")
		}, AcornFoxHelperCodeReceiptInvalid},
		{"binding identity", func(_ string, receipt InactiveSubstrateReceiptV1, _ *PublishedAcornFoxSubstrateV1) AcornFoxBuildIdentityV1 {
			identity := acornFox03CIdentity(receipt, "upgrade")
			identity.SourceCommit = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
			return identity
		}, AcornFoxHelperCodeBindingMismatch},
	} {
		t.Run(test.name, func(t *testing.T) {
			root, _, published, receipt := newAcornFox03CPublished(t)
			identity := test.apply(root, receipt, published)
			if got := verifyPublishedAcornFoxHelperContract(identity, published); got.OK || got.Code != test.code || got.Identity != nil {
				t.Fatalf("got=%#v", got)
			}
		})
	}
}

func TestAcornFox03CRejectsUnsafeOpenedEvidence(t *testing.T) {
	for _, test := range []struct {
		name  string
		apply func(string, InactiveSubstrateReceiptV1)
	}{
		{"receipt symlink", func(root string, receipt InactiveSubstrateReceiptV1) {
			path := acornFox03CControlPath(root, receipt)
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("receipt.json", path); err != nil {
				t.Fatal(err)
			}
		}},
		{"helper symlink", func(root string, receipt InactiveSubstrateReceiptV1) {
			path := filepath.Join(root, acornFoxSubstrateRootfs, filepath.FromSlash(AcornFoxUpgradeHelperPath))
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("acornfox-upgrade", path); err != nil {
				t.Fatal(err)
			}
		}},
		{"receipt mode", func(root string, receipt InactiveSubstrateReceiptV1) {
			if err := os.Chmod(acornFox03CControlPath(root, receipt), 0o644); err != nil {
				t.Fatal(err)
			}
		}},
		{"helper mode", func(root string, receipt InactiveSubstrateReceiptV1) {
			if err := os.Chmod(filepath.Join(root, acornFoxSubstrateRootfs, filepath.FromSlash(AcornFoxUpgradeHelperPath)), 0o644); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			root, _, published, receipt := newAcornFox03CPublished(t)
			test.apply(root, receipt)
			if got := verifyPublishedAcornFoxHelperContract(acornFox03CIdentity(receipt, "upgrade"), published); got.OK || got.Identity != nil {
				t.Fatalf("unsafe evidence accepted: %#v", got)
			}
		})
	}
	_, _, published, receipt := newAcornFox03CPublished(t)
	receiptFile, err := published.fs.openFile(published.root, acornFoxSubstrateTarget("var/lib/acornfox/install/releases/"+receipt.CandidateReceipt.ReleaseID+".json"), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer receiptFile.Close()
	helperFile, err := published.fs.openFile(published.root, acornFoxSubstrateTarget(AcornFoxUpgradeHelperPath), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer helperFile.Close()
	if got := verifyAcornFoxHelperOpenedFiles(acornFox03CIdentity(receipt, "upgrade"), receiptFile, helperFile, published.uid+1, published.gid); got.OK || got.Code != AcornFoxHelperCodeReceiptInvalid {
		t.Fatalf("owner-mismatched receipt accepted: %#v", got)
	}
}
