package application

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
)

var (
	ErrAcornFoxSourceUpdateInProgress = errors.New("source update is in progress")
	ErrAcornFoxSourceUpdateUnknown    = errors.New("source update outcome is unknown")
	ErrAcornFoxSourceUpdateFailed     = errors.New("source update failed")
)

type AcornFoxSourceUpdateRequest struct {
	UploadID             domain.ID
	ApplicationID        domain.ID
	BaseSourceRevisionID domain.ID
	Ref                  string
	IdempotencyKey       string
}

type AcornFoxSourceUpdateReservation struct {
	Replay        *contracts.AcornFoxSourceUpdateResult
	RepositoryURL string
}

// AcornFoxSourceUpdateLease fences one app writer across preparation and its
// completion transaction. Implementations must not transparently reconnect a
// lease, because a dropped session relinquishes its advisory lock.
type AcornFoxSourceUpdateLease interface{ AcornFoxSourceUpdateLease() }

type AcornFoxSourceUpdateStore interface {
	AcquireAcornFoxSourceUpdate(context.Context, AcornFoxSourceUpdateRequest, string, time.Time) (AcornFoxSourceUpdateReservation, AcornFoxSourceUpdateLease, error)
	CompleteAcornFoxSourceUpdate(context.Context, AcornFoxSourceUpdateLease, AcornFoxSourceUpdateRequest, string, domain.SourceRevision, time.Time) (contracts.AcornFoxSourceUpdateResult, error)
	FailAcornFoxSourceUpdate(context.Context, AcornFoxSourceUpdateLease, AcornFoxSourceUpdateRequest, string, time.Time) error
	ReleaseAcornFoxSourceUpdate(context.Context, AcornFoxSourceUpdateLease)
}

type AcornFoxSourceUpdateService struct {
	Store    AcornFoxSourceUpdateStore
	Preparer contracts.SourceProvider
	Clock    func() time.Time
	mu       sync.Mutex
	locks    map[domain.ID]*sync.Mutex
}

func (s *AcornFoxSourceUpdateService) Update(ctx context.Context, request AcornFoxSourceUpdateRequest) (contracts.AcornFoxSourceUpdateResult, error) {
	if s == nil || s.Store == nil || s.Preparer == nil {
		return contracts.AcornFoxSourceUpdateResult{}, domain.NewError(domain.ErrUnavailable, "source update is unavailable")
	}
	if err := domain.RequireID(request.ApplicationID, "application id"); err != nil {
		return contracts.AcornFoxSourceUpdateResult{}, err
	}
	if err := domain.RequireID(request.BaseSourceRevisionID, "base source revision id"); err != nil {
		return contracts.AcornFoxSourceUpdateResult{}, err
	}
	if request.IdempotencyKey == "" {
		return contracts.AcornFoxSourceUpdateResult{}, domain.ValidationError("source update request is invalid")
	}
	if request.UploadID.Empty() {
		ref, err := contracts.NormalizeAcornFoxSourceUpdateRef(request.Ref)
		if err != nil {
			return contracts.AcornFoxSourceUpdateResult{}, domain.ValidationError("source update request is invalid")
		}
		request.Ref = ref
	} else if request.Ref != "" || domain.ValidateSourceUploadStorageRef("upload://"+request.UploadID.String(), request.UploadID) != nil {
		return contracts.AcornFoxSourceUpdateResult{}, domain.ValidationError("upload source update is invalid")
	}
	digest := sourceUpdateDigest(request)
	lock := s.lock(request.ApplicationID)
	lock.Lock()
	defer lock.Unlock()
	now := time.Now().UTC()
	if s.Clock != nil {
		now = s.Clock().UTC()
	}
	reservation, lease, err := s.Store.AcquireAcornFoxSourceUpdate(ctx, request, digest, now)
	if err != nil {
		return contracts.AcornFoxSourceUpdateResult{}, err
	}
	if lease != nil {
		defer s.Store.ReleaseAcornFoxSourceUpdate(context.Background(), lease)
	}
	if reservation.Replay != nil {
		return *reservation.Replay, nil
	}
	prepareRequest := contracts.PrepareSourceRequest{ApplicationID: request.ApplicationID, Kind: domain.SourceGitHTTPS, Locator: reservation.RepositoryURL, Ref: request.Ref, WorkspaceRef: "memory://" + request.ApplicationID.String(), Operation: contracts.OperationContext{IdempotencyKey: "acornfox-source-update:" + request.ApplicationID.String() + ":" + request.IdempotencyKey, Actor: "acornfox-source-update"}}
	if !request.UploadID.Empty() {
		prepareRequest.Kind = domain.SourceUpload
		prepareRequest.Locator = "upload://" + request.UploadID.String()
		prepareRequest.Ref = ""
	}
	prepared, err := s.Preparer.Prepare(ctx, prepareRequest)
	if err != nil {
		_ = s.Store.FailAcornFoxSourceUpdate(context.Background(), lease, request, digest, now)
		return contracts.AcornFoxSourceUpdateResult{}, err
	}
	completedAt := time.Now().UTC()
	if s.Clock != nil {
		completedAt = s.Clock().UTC()
	}
	result, commitErr := s.Store.CompleteAcornFoxSourceUpdate(ctx, lease, request, digest, prepared.Revision, completedAt)
	if commitErr != nil {
		if !errors.Is(commitErr, ErrAcornFoxSourceUpdateUnknown) {
			// Final workspaces are shared by tree digest. Never remove one on
			// a failed update; another accepted revision may still reference it.
			// Transient stages are cleaned by Prepare itself.
			_ = s.Store.FailAcornFoxSourceUpdate(context.Background(), lease, request, digest, now)
		}
		return contracts.AcornFoxSourceUpdateResult{}, commitErr
	}
	return result, nil
}

func (s *AcornFoxSourceUpdateService) lock(applicationID domain.ID) *sync.Mutex {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.locks == nil {
		s.locks = make(map[domain.ID]*sync.Mutex)
	}
	if s.locks[applicationID] == nil {
		s.locks[applicationID] = &sync.Mutex{}
	}
	return s.locks[applicationID]
}

func sourceUpdateDigest(request AcornFoxSourceUpdateRequest) string {
	input := request.ApplicationID.String() + "\x00" + request.BaseSourceRevisionID.String() + "\x00" + request.Ref
	if !request.UploadID.Empty() {
		input += "\x00upload\x00" + request.UploadID.String()
	}
	sum := sha256.Sum256([]byte(input))
	return "sha256:" + hex.EncodeToString(sum[:])
}
