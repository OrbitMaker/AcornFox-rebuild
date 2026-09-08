package main

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/acornfoxcandidate"
	"github.com/open-card/open-card/internal/application"
	"github.com/open-card/open-card/internal/domain"
)

type fixCandidateAsyncFixture struct {
	mu         sync.Mutex
	accepted   int
	executed   int
	canceled   int
	started    chan struct{}
	start      sync.Once
	replay     *application.AcornFoxFixCandidate
	executeErr error
}

func (f *fixCandidateAsyncFixture) Replay(context.Context, application.AcornFoxFixCandidateCreateRequest) (*application.AcornFoxFixCandidate, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.replay == nil {
		return nil, nil
	}
	value := *f.replay
	return &value, nil
}

func (f *fixCandidateAsyncFixture) Accept(_ context.Context, request application.AcornFoxFixCandidateCreateRequest) (application.AcornFoxFixCandidate, bool, string, error) {
	f.mu.Lock()
	f.accepted++
	sequence := f.accepted
	f.mu.Unlock()
	digest := "sha256:" + strings.Repeat(string("0123456789abcdef"[(sequence-1)%16]), 64)
	return application.AcornFoxFixCandidate{ID: application.AcornFoxFixCandidateIDFromRequestDigest(digest), ApplicationID: request.ApplicationID, BaseSourceRevisionID: request.BaseSourceRevisionID, OwnerAdminID: request.OwnerAdminID, RequestKey: request.IdempotencyKey, Status: application.AcornFoxFixCandidatePreparing, CreatedAt: time.Unix(1_700_000_000, int64(sequence)).UTC()}, true, digest, nil
}

func (f *fixCandidateAsyncFixture) Execute(ctx context.Context, _ application.AcornFoxFixCandidate, _ application.AcornFoxFixCandidateCreateRequest, _ string) (application.AcornFoxFixCandidate, error) {
	f.mu.Lock()
	f.executed++
	f.mu.Unlock()
	if f.started != nil {
		f.start.Do(func() { close(f.started) })
	}
	if f.executeErr != nil {
		return application.AcornFoxFixCandidate{}, f.executeErr
	}
	<-ctx.Done()
	f.mu.Lock()
	f.canceled++
	f.mu.Unlock()
	return application.AcornFoxFixCandidate{}, ctx.Err()
}

func TestFixCandidateCoordinatorLogsOnlyFixedFailureStage(t *testing.T) {
	lifecycle, cancel := context.WithCancel(context.Background())
	defer cancel()
	fixture := &fixCandidateAsyncFixture{executeErr: errors.New("secret-token-should-not-be-logged")}
	coordinator, err := newAcornFoxFixCandidateCoordinator(lifecycle, fixture)
	if err != nil {
		t.Fatal(err)
	}
	logged := make(chan string, 1)
	coordinator.failureLog = func(id domain.ID, stage string) { logged <- id.String() + ":" + stage }
	request := application.AcornFoxFixCandidateCreateRequest{ApplicationID: "app_candidate", BaseSourceRevisionID: "src_base", Paths: []string{"Dockerfile"}, UnifiedDiff: []byte("diff\n"), ContainerPort: 8080, IdempotencyKey: "candidate-log-stage", OwnerAdminID: "admin_candidate"}
	accepted, err := coordinator.Create(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case value := <-logged:
		if value != accepted.ID.String()+":unknown" || strings.Contains(value, "secret-token") {
			t.Fatalf("logged=%q", value)
		}
	case <-time.After(time.Second):
		t.Fatal("candidate failure stage was not logged")
	}
	closeContext, closeCancel := context.WithTimeout(context.Background(), time.Second)
	defer closeCancel()
	if err := coordinator.Close(closeContext); err != nil {
		t.Fatal(err)
	}
}

func TestFixCandidateCoordinatorDetachesAcceptedWorkFromRequestCancellation(t *testing.T) {
	lifecycle, stop := context.WithCancel(context.Background())
	fixture := &fixCandidateAsyncFixture{started: make(chan struct{})}
	coordinator, err := newAcornFoxFixCandidateCoordinator(lifecycle, fixture)
	if err != nil {
		t.Fatal(err)
	}
	requestContext, cancelRequest := context.WithCancel(context.Background())
	request := application.AcornFoxFixCandidateCreateRequest{ApplicationID: "app_candidate", BaseSourceRevisionID: "src_base", Paths: []string{"Dockerfile"}, UnifiedDiff: []byte("diff\n"), ContainerPort: 8080, IdempotencyKey: "candidate-detached", OwnerAdminID: "admin_candidate"}
	if accepted, err := coordinator.Create(requestContext, request); err != nil || accepted.Status != application.AcornFoxFixCandidatePreparing {
		t.Fatalf("accepted=%+v err=%v", accepted, err)
	}
	cancelRequest()
	select {
	case <-fixture.started:
	case <-time.After(time.Second):
		t.Fatal("accepted work did not start")
	}
	fixture.mu.Lock()
	canceledBeforeStop := fixture.canceled
	fixture.mu.Unlock()
	if canceledBeforeStop != 0 {
		t.Fatal("HTTP request cancellation canceled accepted work")
	}
	stop()
	closeContext, closeCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer closeCancel()
	if err := coordinator.Close(closeContext); err != nil {
		t.Fatal(err)
	}
	fixture.mu.Lock()
	canceledAfterStop := fixture.canceled
	fixture.mu.Unlock()
	if canceledAfterStop != 1 {
		t.Fatalf("lifecycle cancellation count=%d", canceledAfterStop)
	}
}

func (f *fixCandidateAsyncFixture) ReadSource(context.Context, domain.ID, domain.ID, []string) (acornfoxcandidate.ReadResult, error) {
	return acornfoxcandidate.ReadResult{}, nil
}
func (f *fixCandidateAsyncFixture) ReadSourceForAI(context.Context, domain.ID, domain.ID, []string) (acornfoxcandidate.ReadResult, error) {
	return acornfoxcandidate.ReadResult{}, nil
}
func (f *fixCandidateAsyncFixture) MatchSource(context.Context, domain.ID, domain.ID, domain.ID, domain.ID) (application.AcornFoxFixCandidate, error) {
	return application.AcornFoxFixCandidate{}, nil
}
func (f *fixCandidateAsyncFixture) Publish(context.Context, domain.ID, domain.ID, domain.ID, string) (application.AcornFoxDeliveryResult, error) {
	return application.AcornFoxDeliveryResult{}, nil
}

func TestFixCandidateCoordinatorReturnsAcceptedBeforeWorkAndBoundsQueue(t *testing.T) {
	lifecycle, cancel := context.WithCancel(context.Background())
	fixture := &fixCandidateAsyncFixture{}
	coordinator, err := newAcornFoxFixCandidateCoordinator(lifecycle, fixture)
	if err != nil {
		t.Fatal(err)
	}
	request := application.AcornFoxFixCandidateCreateRequest{ApplicationID: "app_candidate", BaseSourceRevisionID: "src_base", Paths: []string{"Dockerfile"}, UnifiedDiff: []byte("diff\n"), ContainerPort: 8080, OwnerAdminID: "admin_candidate"}
	for index := 0; index < acornFoxFixCandidateQueueCapacity; index++ {
		request.IdempotencyKey = "candidate-" + string(rune('a'+index))
		accepted, err := coordinator.Create(context.Background(), request)
		if err != nil || accepted.Status != application.AcornFoxFixCandidatePreparing || accepted.ID.Empty() {
			t.Fatalf("index=%d accepted=%+v err=%v", index, accepted, err)
		}
	}
	fixture.mu.Lock()
	replay := application.AcornFoxFixCandidate{ID: "candidate_ffffffffffffffffffffffffffffffff", ApplicationID: request.ApplicationID, BaseSourceRevisionID: request.BaseSourceRevisionID, OwnerAdminID: request.OwnerAdminID, RequestKey: "candidate-replay", Status: application.AcornFoxFixCandidateFailed, CreatedAt: time.Unix(1_700_000_000, 0).UTC()}
	fixture.replay = &replay
	fixture.mu.Unlock()
	request.IdempotencyKey = replay.RequestKey
	if got, err := coordinator.Create(context.Background(), request); err != nil || got.ID != replay.ID || got.Status != application.AcornFoxFixCandidateFailed {
		t.Fatalf("saturated replay=%+v err=%v", got, err)
	}
	fixture.mu.Lock()
	fixture.replay = nil
	fixture.mu.Unlock()
	request.IdempotencyKey = "candidate-over-capacity"
	if _, err := coordinator.Create(context.Background(), request); !domain.IsCode(err, domain.ErrUnavailable) {
		t.Fatalf("queue overflow err=%v", err)
	}
	fixture.mu.Lock()
	acceptedCalls := fixture.accepted
	fixture.mu.Unlock()
	if acceptedCalls != acornFoxFixCandidateQueueCapacity {
		t.Fatalf("accepted after queue capacity=%d", acceptedCalls)
	}
	cancel()
	closeContext, closeCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer closeCancel()
	if err := coordinator.Close(closeContext); err != nil {
		t.Fatal(err)
	}
	fixture.mu.Lock()
	executed, canceled := fixture.executed, fixture.canceled
	fixture.mu.Unlock()
	if executed != acornFoxFixCandidateQueueCapacity || canceled != executed {
		t.Fatalf("executed=%d canceled=%d", executed, canceled)
	}
	if _, err := coordinator.Create(context.Background(), request); !domain.IsCode(err, domain.ErrUnavailable) || errors.Is(err, context.Canceled) {
		t.Fatalf("post-close create err=%v", err)
	}
}
