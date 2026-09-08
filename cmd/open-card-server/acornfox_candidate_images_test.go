package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
)

type candidateImageDeleteTracker struct {
	contracts.ImageStore
	deleted []domain.ImageDigest
}

func (s *candidateImageDeleteTracker) Delete(ctx context.Context, image domain.ImageDigest, operation contracts.OperationContext) error {
	s.deleted = append(s.deleted, image)
	return s.ImageStore.Delete(ctx, image, operation)
}

type candidateImageGuardFixture struct {
	disposition acornFoxCandidateImageDisposition
}

func (g *candidateImageGuardFixture) Disposition(context.Context, domain.ID, domain.ImageDigest) (acornFoxCandidateImageDisposition, error) {
	return g.disposition, nil
}

type candidateImageGateFixture struct {
	mu       sync.Mutex
	delegate contracts.ImageStore
}

func (g *candidateImageGateFixture) With(_ context.Context, mutate func(contracts.ImageStore) error) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	return mutate(g.delegate)
}

func TestCandidateImageStoreTracksSharesAndRecoversCleanupReceipts(t *testing.T) {
	delegate := &candidateImageDeleteTracker{ImageStore: contracts.NewFakeImageStore(true)}
	gated := &acornFoxGatedImageStore{delegate: delegate, gate: &candidateImageGateFixture{delegate: delegate}}
	guard := &candidateImageGuardFixture{disposition: acornFoxCandidateImageDelete}
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := newAcornFoxCandidateImageStore(gated, guard, root)
	if err != nil {
		t.Fatal(err)
	}
	image, _ := domain.ParseImageDigest("acornfox.local/apps", "sha256:"+strings.Repeat("a", 64))
	first := domain.ID("candidate_0123456789abcdef0123456789abcdef")
	second := domain.ID("candidate_fedcba9876543210fedcba9876543210")
	for index, id := range []domain.ID{first, second} {
		request := contracts.StoreOCIRequest{Image: image, StorageKey: "acornfox-candidate-" + id.String(), Archive: bytes.NewReader([]byte("oci archive")), Operation: contracts.OperationContext{IdempotencyKey: "store-candidate-" + string(rune('a'+index)), Actor: "test"}}
		if result, err := store.StoreOCI(context.Background(), request); err != nil || result.Image != image || result.StorageRef == "" {
			t.Fatalf("id=%s result=%+v err=%v", id, result, err)
		}
	}
	if receipts, err := store.receipts(); err != nil || len(receipts) != 2 || !receipts[first].Stored || receipts[first].StorageRef == "" {
		t.Fatalf("receipts=%+v err=%v", receipts, err)
	}
	if err := store.CleanupCandidate(context.Background(), first, image); err != nil || len(delegate.deleted) != 0 {
		t.Fatalf("shared cleanup deletes=%v err=%v", delegate.deleted, err)
	}
	if err := store.CleanupCandidate(context.Background(), second, image); err != nil || len(delegate.deleted) != 1 || delegate.deleted[0] != image {
		t.Fatalf("last cleanup deletes=%v err=%v", delegate.deleted, err)
	}

	guard.disposition = acornFoxCandidateImageForget
	third := domain.ID("candidate_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if _, err := store.StoreOCI(context.Background(), contracts.StoreOCIRequest{Image: image, StorageKey: "acornfox-candidate-" + third.String(), Archive: bytes.NewReader([]byte("oci archive")), Operation: contracts.OperationContext{IdempotencyKey: "store-third", Actor: "test"}}); err != nil {
		t.Fatal(err)
	}
	if err := store.CleanupCandidate(context.Background(), third, image); err != nil || len(delegate.deleted) != 1 {
		t.Fatalf("normal artifact cleanup deletes=%v err=%v", delegate.deleted, err)
	}

	guard.disposition = acornFoxCandidateImageWait
	fourth := domain.ID("candidate_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	if _, err := store.StoreOCI(context.Background(), contracts.StoreOCIRequest{Image: image, StorageKey: "acornfox-candidate-" + fourth.String(), Archive: bytes.NewReader([]byte("oci archive")), Operation: contracts.OperationContext{IdempotencyKey: "store-fourth", Actor: "test"}}); err != nil {
		t.Fatal(err)
	}
	if err := store.Recover(context.Background()); err == nil {
		t.Fatal("active candidate image cleanup was not deferred")
	}
	guard.disposition = acornFoxCandidateImageDelete
	if err := store.Recover(context.Background()); err != nil || len(delegate.deleted) != 2 {
		t.Fatalf("recovery deletes=%v err=%v", delegate.deleted, err)
	}
	if receipts, err := store.receipts(); err != nil || len(receipts) != 0 {
		t.Fatalf("remaining receipts=%+v err=%v", receipts, err)
	}

	intentImage, _ := domain.ParseImageDigest("acornfox.local/apps", "sha256:"+strings.Repeat("d", 64))
	freshIntent := acornFoxCandidateImageReceipt{CandidateID: "candidate_cccccccccccccccccccccccccccccccc", Image: intentImage, CreatedAt: time.Now().UTC()}
	if err := store.writeReceipt(freshIntent); err != nil {
		t.Fatal(err)
	}
	if err := store.Recover(context.Background()); err == nil {
		t.Fatal("fresh StoreOCI intent was reconciled while its writer may still be active")
	}
	if receipts, err := store.receipts(); err != nil || receipts[freshIntent.CandidateID] != freshIntent {
		t.Fatalf("fresh intent receipts=%+v err=%v", receipts, err)
	}
	store.mu.Lock()
	err = store.removeReceiptLocked(freshIntent.CandidateID)
	store.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	staleIntent := acornFoxCandidateImageReceipt{CandidateID: "candidate_dddddddddddddddddddddddddddddddd", Image: intentImage, CreatedAt: time.Now().UTC().Add(-acornFoxFixCandidateExecutionLimit - 2*time.Minute)}
	if err := store.writeReceipt(staleIntent); err != nil {
		t.Fatal(err)
	}
	if err := store.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if receipts, err := store.receipts(); err != nil || len(receipts) != 0 {
		t.Fatalf("stale intent receipts=%+v err=%v", receipts, err)
	}
}

func TestCandidateImageStoreRejectsLinkedReceiptRoot(t *testing.T) {
	parent := t.TempDir()
	target := filepath.Join(parent, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	linked := filepath.Join(parent, "candidate-images")
	if err := os.Symlink(target, linked); err != nil {
		t.Fatal(err)
	}
	delegate := contracts.NewFakeImageStore(true)
	gated := &acornFoxGatedImageStore{delegate: delegate, gate: &candidateImageGateFixture{delegate: delegate}}
	if _, err := newAcornFoxCandidateImageStore(gated, &candidateImageGuardFixture{disposition: acornFoxCandidateImageDelete}, linked); err == nil {
		t.Fatal("linked candidate image receipt root was accepted")
	}
}
