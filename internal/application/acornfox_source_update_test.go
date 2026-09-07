package application

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
)

type sourceUpdateLease struct{}

func (sourceUpdateLease) AcornFoxSourceUpdateLease() {}

type sourceUpdateStore struct {
	reservation AcornFoxSourceUpdateReservation
	complete    int
}

func (s *sourceUpdateStore) AcquireAcornFoxSourceUpdate(context.Context, AcornFoxSourceUpdateRequest, string, time.Time) (AcornFoxSourceUpdateReservation, AcornFoxSourceUpdateLease, error) {
	return s.reservation, sourceUpdateLease{}, nil
}
func (s *sourceUpdateStore) CompleteAcornFoxSourceUpdate(_ context.Context, _ AcornFoxSourceUpdateLease, _ AcornFoxSourceUpdateRequest, _ string, revision domain.SourceRevision, _ time.Time) (contracts.AcornFoxSourceUpdateResult, error) {
	s.complete++
	return contracts.AcornFoxSourceUpdateResult{SourceRevisionID: revision.ID, Status: contracts.AcornFoxSourceUpdateImported}, nil
}
func (*sourceUpdateStore) FailAcornFoxSourceUpdate(context.Context, AcornFoxSourceUpdateLease, AcornFoxSourceUpdateRequest, string, time.Time) error {
	return nil
}
func (*sourceUpdateStore) ReleaseAcornFoxSourceUpdate(context.Context, AcornFoxSourceUpdateLease) {}

type sourceUpdatePreparer struct{ calls, releases int }

func (*sourceUpdatePreparer) Metadata(context.Context) contracts.ProviderMetadata {
	return contracts.ProviderMetadata{Name: "source-update-test", Version: "1", ContractVersion: contracts.ContractAPIVersion}
}
func (p *sourceUpdatePreparer) Prepare(_ context.Context, r contracts.PrepareSourceRequest) (contracts.PrepareSourceResult, error) {
	p.calls++
	rev, err := domain.NewSourceRevision(r.ApplicationID, domain.SourceGitHTTPS, r.Locator, r.Ref, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "memory://updated", time.Unix(1, 0).UTC())
	return contracts.PrepareSourceResult{Revision: rev}, err
}
func (p *sourceUpdatePreparer) Release(context.Context, contracts.ReleaseSourceRequest) error {
	p.releases++
	return nil
}

type lostCommitAcknowledgementStore struct {
	result *contracts.AcornFoxSourceUpdateResult
	fails  int
}

func (s *lostCommitAcknowledgementStore) AcquireAcornFoxSourceUpdate(_ context.Context, _ AcornFoxSourceUpdateRequest, _ string, _ time.Time) (AcornFoxSourceUpdateReservation, AcornFoxSourceUpdateLease, error) {
	if s.result != nil {
		return AcornFoxSourceUpdateReservation{Replay: s.result}, nil, nil
	}
	return AcornFoxSourceUpdateReservation{RepositoryURL: "https://github.com/acme/app.git"}, sourceUpdateLease{}, nil
}
func (s *lostCommitAcknowledgementStore) CompleteAcornFoxSourceUpdate(_ context.Context, _ AcornFoxSourceUpdateLease, _ AcornFoxSourceUpdateRequest, _ string, revision domain.SourceRevision, _ time.Time) (contracts.AcornFoxSourceUpdateResult, error) {
	result := &contracts.AcornFoxSourceUpdateResult{SourceRevisionID: revision.ID, Status: contracts.AcornFoxSourceUpdateImported}
	s.result = result
	return contracts.AcornFoxSourceUpdateResult{}, ErrAcornFoxSourceUpdateUnknown
}
func (s *lostCommitAcknowledgementStore) FailAcornFoxSourceUpdate(context.Context, AcornFoxSourceUpdateLease, AcornFoxSourceUpdateRequest, string, time.Time) error {
	s.fails++
	return nil
}
func (*lostCommitAcknowledgementStore) ReleaseAcornFoxSourceUpdate(context.Context, AcornFoxSourceUpdateLease) {
}
func TestAcornFoxSourceUpdateUsesReservedRepositoryAndDoesNotDeploy(t *testing.T) {
	store := &sourceUpdateStore{reservation: AcornFoxSourceUpdateReservation{RepositoryURL: "https://github.com/acme/app.git"}}
	prep := &sourceUpdatePreparer{}
	service := &AcornFoxSourceUpdateService{Store: store, Preparer: prep, Clock: func() time.Time { return time.Unix(2, 0).UTC() }}
	result, err := service.Update(context.Background(), AcornFoxSourceUpdateRequest{ApplicationID: "app_1", BaseSourceRevisionID: "src_1", Ref: "main", IdempotencyKey: "one"})
	if err != nil || result.Status != contracts.AcornFoxSourceUpdateImported || prep.calls != 1 || store.complete != 1 {
		t.Fatalf("result=%+v calls=%d complete=%d err=%v", result, prep.calls, store.complete, err)
	}
}

func TestAcornFoxSourceUpdateLostCommitAcknowledgementDoesNotCleanupOrFail(t *testing.T) {
	store, prep := &lostCommitAcknowledgementStore{}, &sourceUpdatePreparer{}
	service := &AcornFoxSourceUpdateService{Store: store, Preparer: prep}
	request := AcornFoxSourceUpdateRequest{ApplicationID: "app_1", BaseSourceRevisionID: "src_1", Ref: "main", IdempotencyKey: "lost-ack"}
	if _, err := service.Update(context.Background(), request); !errors.Is(err, ErrAcornFoxSourceUpdateUnknown) || prep.releases != 0 || store.fails != 0 {
		t.Fatalf("err=%v releases=%d fails=%d", err, prep.releases, store.fails)
	}
	replay, err := service.Update(context.Background(), request)
	if err != nil || replay.SourceRevisionID.Empty() || prep.calls != 1 {
		t.Fatalf("replay=%+v err=%v calls=%d", replay, err, prep.calls)
	}
}
