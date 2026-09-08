package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/application"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/persistence/postgres"
)

type fixCandidateRuntimeStoreFixture struct {
	request postgres.AcornFoxFixCandidateRuntimeTaskRequest
	reads   int
}

type fixCandidateImageCleanupFixture struct {
	candidate domain.ID
	image     domain.ImageDigest
}

func (f *fixCandidateImageCleanupFixture) CleanupCandidate(_ context.Context, candidate domain.ID, image domain.ImageDigest) error {
	f.candidate, f.image = candidate, image
	return nil
}

func (f *fixCandidateRuntimeStoreFixture) EnqueueAcornFoxFixCandidateRuntimeTask(_ context.Context, request postgres.AcornFoxFixCandidateRuntimeTaskRequest) (domain.ID, error) {
	f.request = request
	return "task_candidate", nil
}
func (f *fixCandidateRuntimeStoreFixture) GetAcornFoxFixCandidateRuntimeEvidence(_ context.Context, taskID domain.ID, image domain.ImageDigest) (application.AcornFoxFixCandidateRuntimeEvidence, bool, error) {
	f.reads++
	if f.reads == 1 {
		return application.AcornFoxFixCandidateRuntimeEvidence{}, false, nil
	}
	return application.AcornFoxFixCandidateRuntimeEvidence{TaskID: taskID, Image: image, RuntimeState: "stopped", ProbeOutcome: "responded", CleanupConfirmed: true, EvidenceDigest: "sha256:" + strings.Repeat("a", 64)}, true, nil
}

func TestAcornFoxFixCandidateRuntimeDispatcherWaitsForCleanupEvidence(t *testing.T) {
	store := &fixCandidateRuntimeStoreFixture{}
	cleanup := &fixCandidateImageCleanupFixture{}
	dispatcher := &acornFoxFixCandidateRuntimeDispatcher{store: store, images: cleanup, poll: time.Millisecond, clock: func() time.Time { return time.Unix(1, 0).UTC() }}
	image, _ := domain.ParseImageDigest("local/candidate", "sha256:"+strings.Repeat("b", 64))
	evidence, err := dispatcher.ValidateCandidateRuntime(context.Background(), application.AcornFoxFixCandidateRuntimeRequest{CandidateID: "candidate_0123456789abcdef0123456789abcdef", ApplicationID: "app_candidate", Image: image, ContainerPort: 8080, IdempotencyKey: "runtime", Actor: "admin"})
	if err != nil || !evidence.CleanupConfirmed || store.reads != 2 || store.request.Image != image || store.request.ContainerPort != 8080 || cleanup.candidate != "candidate_0123456789abcdef0123456789abcdef" || cleanup.image != image {
		t.Fatalf("evidence=%+v request=%+v reads=%d err=%v", evidence, store.request, store.reads, err)
	}
}
