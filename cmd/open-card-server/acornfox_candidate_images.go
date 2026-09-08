package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/persistence/postgres"
)

type acornFoxCandidateImageDisposition string

const (
	acornFoxCandidateImageDelete acornFoxCandidateImageDisposition = "delete"
	acornFoxCandidateImageForget acornFoxCandidateImageDisposition = "forget"
	acornFoxCandidateImageWait   acornFoxCandidateImageDisposition = "wait"
)

type acornFoxCandidateImageGuard interface {
	Disposition(context.Context, domain.ID, domain.ImageDigest) (acornFoxCandidateImageDisposition, error)
}

const acornFoxImageMutationLockName = "open-card:oci-image-mutation:v1"

type acornFoxImageMutationGate interface {
	With(context.Context, func(contracts.ImageStore) error) error
}

type postgresAcornFoxImageMutationGate struct {
	db       *sql.DB
	delegate contracts.ImageStore
}

func (g postgresAcornFoxImageMutationGate) With(ctx context.Context, mutate func(contracts.ImageStore) error) error {
	if g.db == nil || g.delegate == nil || ctx == nil || mutate == nil {
		return errors.New("image mutation gate is unavailable")
	}
	conn, err := g.db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_lock(hashtextextended($1,0))`, acornFoxImageMutationLockName); err != nil {
		return err
	}
	mutationErr := mutate(g.delegate)
	var unlocked bool
	releaseContext, releaseCancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	releaseErr := conn.QueryRowContext(releaseContext, `SELECT pg_advisory_unlock(hashtextextended($1,0))`, acornFoxImageMutationLockName).Scan(&unlocked)
	releaseCancel()
	if mutationErr != nil {
		return mutationErr
	}
	if releaseErr != nil || !unlocked {
		return errors.New("image mutation gate release failed")
	}
	return nil
}

type acornFoxGatedImageStore struct {
	delegate contracts.ImageStore
	gate     acornFoxImageMutationGate
}

func newAcornFoxGatedImageStore(delegate contracts.ImageStore, db *sql.DB) (*acornFoxGatedImageStore, error) {
	if delegate == nil || db == nil {
		return nil, errors.New("gated image store is unavailable")
	}
	store := &acornFoxGatedImageStore{delegate: delegate}
	store.gate = postgresAcornFoxImageMutationGate{db: db, delegate: delegate}
	return store, nil
}

func (s *acornFoxGatedImageStore) Metadata(ctx context.Context) contracts.ProviderMetadata {
	return s.delegate.Metadata(ctx)
}
func (s *acornFoxGatedImageStore) Resolve(ctx context.Context, request contracts.ImageResolveRequest) (contracts.ImageResolveResult, error) {
	return s.delegate.Resolve(ctx, request)
}
func (s *acornFoxGatedImageStore) Pull(ctx context.Context, image domain.ImageDigest, operation contracts.OperationContext) (contracts.Evidence, error) {
	return s.delegate.Pull(ctx, image, operation)
}
func (s *acornFoxGatedImageStore) Retain(ctx context.Context, image domain.ImageDigest, operation contracts.OperationContext) error {
	return s.gate.With(ctx, func(delegate contracts.ImageStore) error { return delegate.Retain(ctx, image, operation) })
}
func (s *acornFoxGatedImageStore) Delete(ctx context.Context, image domain.ImageDigest, operation contracts.OperationContext) error {
	return s.gate.With(ctx, func(delegate contracts.ImageStore) error { return delegate.Delete(ctx, image, operation) })
}
func (s *acornFoxGatedImageStore) StoreOCI(ctx context.Context, request contracts.StoreOCIRequest) (result contracts.StoreOCIResult, err error) {
	err = s.gate.With(ctx, func(delegate contracts.ImageStore) error {
		result, err = delegate.StoreOCI(ctx, request)
		return err
	})
	return result, err
}
func (s *acornFoxGatedImageStore) OpenOCI(ctx context.Context, image domain.ImageDigest, operation contracts.OperationContext) (io.ReadCloser, contracts.StoreOCIResult, error) {
	return s.delegate.OpenOCI(ctx, image, operation)
}

type postgresAcornFoxCandidateImageGuard struct{ store *postgres.Store }

func (g postgresAcornFoxCandidateImageGuard) Disposition(ctx context.Context, candidateID domain.ID, image domain.ImageDigest) (acornFoxCandidateImageDisposition, error) {
	if g.store == nil || candidateID.Empty() || image.Validate() != nil {
		return "", errors.New("candidate image guard is unavailable")
	}
	var activeCandidate, activeBuild, normalArtifact bool
	if err := g.store.DB().QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM operations WHERE target_ref=$1 AND state IN ('pending','leased','running','waiting','cancelling'))`, "candidate/"+candidateID.String()+"/runtime").Scan(&activeCandidate); err != nil {
		return "", err
	}
	if activeCandidate {
		return acornFoxCandidateImageWait, nil
	}
	if err := g.store.DB().QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM builds build JOIN build_plans plan ON plan.id=build.plan_id WHERE plan.target_repository=$1 AND build.state IN ('pending','running'))`, image.Repository).Scan(&activeBuild); err != nil {
		return "", err
	}
	if activeBuild {
		return acornFoxCandidateImageWait, nil
	}
	if err := g.store.DB().QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM artifacts WHERE image_repository=$1 AND image_digest=$2)`, image.Repository, image.Digest).Scan(&normalArtifact); err != nil {
		return "", err
	}
	if normalArtifact {
		return acornFoxCandidateImageForget, nil
	}
	return acornFoxCandidateImageDelete, nil
}

type acornFoxCandidateImageReceipt struct {
	CandidateID domain.ID          `json:"candidate_id"`
	Image       domain.ImageDigest `json:"image"`
	StorageRef  string             `json:"storage_ref,omitempty"`
	Stored      bool               `json:"stored"`
	CreatedAt   time.Time          `json:"created_at"`
}

func (r acornFoxCandidateImageReceipt) Validate() error {
	if !acornFoxCandidateIDString(r.CandidateID.String()) || r.Image.Validate() != nil || r.Stored != (strings.TrimSpace(r.StorageRef) != "") || strings.ContainsAny(r.StorageRef, "\r\n\x00") || r.CreatedAt.IsZero() {
		return errors.New("candidate image receipt is invalid")
	}
	return nil
}

type acornFoxCandidateImageStore struct {
	delegate *acornFoxGatedImageStore
	guard    acornFoxCandidateImageGuard
	root     string
	mu       sync.Mutex
}

func newAcornFoxCandidateImageStore(delegate *acornFoxGatedImageStore, guard acornFoxCandidateImageGuard, root string) (*acornFoxCandidateImageStore, error) {
	if delegate == nil || guard == nil {
		return nil, errors.New("candidate image store dependencies are unavailable")
	}
	if err := prepareAcornFoxCandidateWorkRoot(root); err != nil {
		return nil, err
	}
	store := &acornFoxCandidateImageStore{delegate: delegate, guard: guard, root: root}
	if _, err := store.receipts(); err != nil {
		return nil, err
	}
	return store, nil
}

func (s *acornFoxCandidateImageStore) Metadata(ctx context.Context) contracts.ProviderMetadata {
	return s.delegate.Metadata(ctx)
}
func (s *acornFoxCandidateImageStore) Resolve(ctx context.Context, request contracts.ImageResolveRequest) (contracts.ImageResolveResult, error) {
	return s.delegate.Resolve(ctx, request)
}
func (s *acornFoxCandidateImageStore) Pull(ctx context.Context, image domain.ImageDigest, operation contracts.OperationContext) (contracts.Evidence, error) {
	return s.delegate.Pull(ctx, image, operation)
}
func (s *acornFoxCandidateImageStore) Retain(ctx context.Context, image domain.ImageDigest, operation contracts.OperationContext) error {
	return s.delegate.Retain(ctx, image, operation)
}
func (s *acornFoxCandidateImageStore) Delete(ctx context.Context, image domain.ImageDigest, operation contracts.OperationContext) error {
	return s.delegate.Delete(ctx, image, operation)
}
func (s *acornFoxCandidateImageStore) OpenOCI(ctx context.Context, image domain.ImageDigest, operation contracts.OperationContext) (io.ReadCloser, contracts.StoreOCIResult, error) {
	return s.delegate.OpenOCI(ctx, image, operation)
}

func (s *acornFoxCandidateImageStore) StoreOCI(ctx context.Context, request contracts.StoreOCIRequest) (contracts.StoreOCIResult, error) {
	candidateID, err := candidateIDFromStorageKey(request.StorageKey)
	if err != nil || request.Image.Validate() != nil {
		return contracts.StoreOCIResult{}, errors.New("candidate OCI store request is invalid")
	}
	receipt := acornFoxCandidateImageReceipt{CandidateID: candidateID, Image: request.Image, CreatedAt: time.Now().UTC()}
	if err := s.writeReceipt(receipt); err != nil {
		return contracts.StoreOCIResult{}, err
	}
	result, err := s.delegate.StoreOCI(ctx, request)
	if err != nil {
		_ = s.reconcileIntent(context.WithoutCancel(ctx), receipt)
		return contracts.StoreOCIResult{}, err
	}
	if result.Image != request.Image || strings.TrimSpace(result.StorageRef) == "" {
		return contracts.StoreOCIResult{}, errors.New("candidate OCI result changed image identity")
	}
	receipt.Stored, receipt.StorageRef = true, result.StorageRef
	if err := s.writeReceipt(receipt); err != nil {
		return contracts.StoreOCIResult{}, err
	}
	return result, nil
}

func (s *acornFoxCandidateImageStore) CleanupCandidate(ctx context.Context, candidateID domain.ID, image domain.ImageDigest) error {
	if s == nil || !acornFoxCandidateIDString(candidateID.String()) || image.Validate() != nil {
		return errors.New("candidate image cleanup request is invalid")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	receipts, err := s.receiptsLocked()
	if err != nil {
		return err
	}
	current, ok := receipts[candidateID]
	if !ok {
		return nil
	}
	if current.Image != image {
		return errors.New("candidate image cleanup identity changed")
	}
	if !current.Stored {
		return errors.New("candidate image store outcome is not reconciled")
	}
	err = s.delegate.gate.With(ctx, func(delegate contracts.ImageStore) error {
		disposition, err := s.guard.Disposition(ctx, candidateID, image)
		if err != nil {
			return err
		}
		if disposition == acornFoxCandidateImageWait {
			return errors.New("candidate image cleanup is waiting for terminal runtime state")
		}
		for otherID, other := range receipts {
			if otherID != candidateID && other.Image == image {
				return nil
			}
		}
		if disposition == acornFoxCandidateImageDelete {
			err = delegate.Delete(ctx, image, contracts.OperationContext{IdempotencyKey: "candidate-image-delete:" + candidateID.String(), Actor: "acornfox-candidate-cleanup"})
			if err != nil && !candidateImageDeleteCanForget(err) {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	return s.removeReceiptLocked(candidateID)
}

func (s *acornFoxCandidateImageStore) Recover(ctx context.Context) error {
	if s == nil {
		return errors.New("candidate image store is unavailable")
	}
	receipts, err := s.receipts()
	if err != nil {
		return err
	}
	deferred := false
	for id, receipt := range receipts {
		if !receipt.Stored && time.Now().UTC().Before(receipt.CreatedAt.Add(acornFoxFixCandidateExecutionLimit+time.Minute)) {
			deferred = true
			continue
		}
		if !receipt.Stored {
			if err := s.reconcileIntent(ctx, receipt); err != nil {
				deferred = true
				continue
			}
		}
		if err := s.CleanupCandidate(ctx, id, receipt.Image); err != nil {
			deferred = true
		}
	}
	if deferred {
		return errors.New("candidate image cleanup was deferred")
	}
	return nil
}

func (s *acornFoxCandidateImageStore) reconcileIntent(ctx context.Context, receipt acornFoxCandidateImageReceipt) error {
	archive, result, err := s.delegate.OpenOCI(ctx, receipt.Image, contracts.OperationContext{IdempotencyKey: "candidate-image-reconcile:" + receipt.CandidateID.String(), Actor: "acornfox-candidate-cleanup"})
	if archive != nil {
		_ = archive.Close()
	}
	if err != nil {
		var provider *contracts.ProviderError
		if errors.As(err, &provider) && provider.Code == contracts.ErrNotFound {
			s.mu.Lock()
			defer s.mu.Unlock()
			return s.removeReceiptLocked(receipt.CandidateID)
		}
		return err
	}
	if result.Image != receipt.Image || strings.TrimSpace(result.StorageRef) == "" {
		return errors.New("candidate image reconciliation changed storage identity")
	}
	receipt.Stored, receipt.StorageRef = true, result.StorageRef
	return s.writeReceipt(receipt)
}

func (s *acornFoxCandidateImageStore) writeReceipt(receipt acornFoxCandidateImageReceipt) error {
	if receipt.Validate() != nil {
		return errors.New("candidate image receipt is invalid")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	receipts, err := s.receiptsLocked()
	if err != nil {
		return err
	}
	if existing, ok := receipts[receipt.CandidateID]; ok {
		if existing.Image != receipt.Image || existing.Stored && receipt.Stored && existing.StorageRef != receipt.StorageRef {
			return errors.New("candidate image receipt identity changed")
		}
		if existing.Stored || !receipt.Stored {
			return nil
		}
		receipt.CreatedAt = existing.CreatedAt
	}
	encoded, err := json.Marshal(receipt)
	if err != nil {
		return err
	}
	temporary := filepath.Join(s.root, "."+receipt.CandidateID.String()+".tmp")
	file, err := os.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err = file.Write(encoded); err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	final := s.receiptPath(receipt.CandidateID)
	if err := os.Rename(temporary, final); err != nil {
		return err
	}
	return syncAcornFoxCandidateDirectory(s.root)
}

func (s *acornFoxCandidateImageStore) receipts() (map[domain.ID]acornFoxCandidateImageReceipt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.receiptsLocked()
}

func (s *acornFoxCandidateImageStore) receiptsLocked() (map[domain.ID]acornFoxCandidateImageReceipt, error) {
	entries, err := os.ReadDir(s.root)
	if err != nil {
		return nil, err
	}
	result := make(map[domain.ID]acornFoxCandidateImageReceipt, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, ".candidate_") && strings.HasSuffix(name, ".tmp") {
			info, err := entry.Info()
			if err != nil || !singleAcornFoxCandidateReceipt(info) {
				return nil, errors.New("candidate image temporary receipt is unsafe")
			}
			if err := os.Remove(filepath.Join(s.root, name)); err != nil {
				return nil, err
			}
			continue
		}
		if !strings.HasSuffix(name, ".json") || !acornFoxCandidateIDString(strings.TrimSuffix(name, ".json")) || entry.Type()&os.ModeSymlink != 0 {
			return nil, errors.New("candidate image receipt root contains an unknown entry")
		}
		path := filepath.Join(s.root, name)
		info, err := os.Lstat(path)
		if err != nil || !singleAcornFoxCandidateReceipt(info) || info.Mode().Perm()&0o177 != 0 {
			return nil, errors.New("candidate image receipt is unsafe")
		}
		encoded, err := os.ReadFile(path)
		if err != nil || len(encoded) == 0 || len(encoded) > 1024 {
			return nil, errors.New("candidate image receipt is unreadable")
		}
		var receipt acornFoxCandidateImageReceipt
		decoder := json.NewDecoder(bytes.NewReader(encoded))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&receipt) != nil || decoder.Decode(&struct{}{}) != io.EOF || receipt.Validate() != nil || receipt.CandidateID.String()+".json" != name {
			return nil, errors.New("candidate image receipt is invalid")
		}
		result[receipt.CandidateID] = receipt
	}
	return result, nil
}

func singleAcornFoxCandidateReceipt(info fs.FileInfo) bool {
	if info == nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return false
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok && stat.Nlink != 1 {
		return false
	}
	return true
}

func (s *acornFoxCandidateImageStore) receiptPath(candidateID domain.ID) string {
	return filepath.Join(s.root, candidateID.String()+".json")
}

func (s *acornFoxCandidateImageStore) removeReceiptLocked(candidateID domain.ID) error {
	if err := os.Remove(s.receiptPath(candidateID)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return syncAcornFoxCandidateDirectory(s.root)
}

func candidateIDFromStorageKey(key string) (domain.ID, error) {
	const prefix = "acornfox-candidate-"
	if !strings.HasPrefix(key, prefix) {
		return "", errors.New("candidate storage key is invalid")
	}
	id := domain.ID(strings.TrimPrefix(key, prefix))
	if !acornFoxCandidateIDString(id.String()) || key != prefix+id.String() {
		return "", errors.New("candidate storage key is invalid")
	}
	return id, nil
}

func acornFoxCandidateIDString(value string) bool {
	if len(value) != len("candidate_")+32 || !strings.HasPrefix(value, "candidate_") {
		return false
	}
	for _, character := range value[len("candidate_"):] {
		if !(character >= '0' && character <= '9' || character >= 'a' && character <= 'f') {
			return false
		}
	}
	return true
}

func candidateImageDeleteCanForget(err error) bool {
	var provider *contracts.ProviderError
	return errors.As(err, &provider) && (provider.Code == contracts.ErrNotFound || provider.Code == contracts.ErrConflict)
}

func syncAcornFoxCandidateDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync candidate directory: %w", err)
	}
	return nil
}
