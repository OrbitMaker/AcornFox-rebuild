package application

import (
	"context"
	"testing"

	"github.com/open-card/open-card/internal/domain"
)

func TestAcornFoxUploadDeliveryCreationSuccessAndReplay(t *testing.T) {
	f := newAcornFoxDeliveryFixture(t)
	f.source.Kind = domain.SourceUpload
	f.source.Locator = "upload://upload_delivery"
	f.source.Ref = ""
	f.source.Commit = ""

	initialTasks := len(f.tasks)
	initialBuilds := f.completedBuilds
	initialCalls := f.buildProvider.calls

	req := AcornFoxDeliveryCreateRequest{
		ApplicationID:    f.source.ApplicationID,
		SourceRevisionID: f.source.ID,
		ContainerPort:    8080,
		IdempotencyKey:   "upload-delivery-create-01",
		Actor:            "admin",
	}

	resp, err := f.service.Create(context.Background(), req)
	if err != nil {
		t.Fatalf("expected successful delivery creation with upload source, got: %v", err)
	}
	if resp.Status != "accepted" {
		t.Fatal("expected non-nil delivery creation response")
	}

	if len(f.tasks)-initialTasks != 1 {
		t.Errorf("expected exactly 1 task queued, got %d", len(f.tasks)-initialTasks)
	}
	if f.completedBuilds-initialBuilds != 1 {
		t.Errorf("expected exactly 1 completed build, got %d", f.completedBuilds-initialBuilds)
	}
	if f.buildProvider.calls-initialCalls != 1 {
		t.Errorf("expected exactly 1 build provider call, got %d", f.buildProvider.calls-initialCalls)
	}

	// Idempotent replay: should not build or queue tasks again
	respReplay, err := f.service.Create(context.Background(), req)
	if err != nil {
		t.Fatalf("expected replay to succeed, got: %v", err)
	}
	if respReplay != resp {
		t.Fatal("expected non-nil response on replay")
	}

	if len(f.tasks)-initialTasks != 1 {
		t.Errorf("replay should not queue additional tasks, task count delta: %d", len(f.tasks)-initialTasks)
	}
	if f.completedBuilds-initialBuilds != 1 {
		t.Errorf("replay should not trigger additional builds, completed builds delta: %d", f.completedBuilds-initialBuilds)
	}
	if f.buildProvider.calls-initialCalls != 1 {
		t.Errorf("replay should not call build provider again, provider calls delta: %d", f.buildProvider.calls-initialCalls)
	}
}

func TestAcornFoxUploadDeliveryRejectsNonImmutableSource(t *testing.T) {
	f := newAcornFoxDeliveryFixture(t)
	f.source.Kind = domain.SourceUpload
	f.source.Locator = "upload://upload_delivery"
	f.source.Ref = ""
	f.source.Commit = ""
	f.source.Immutable = false

	req := AcornFoxDeliveryCreateRequest{
		ApplicationID:    f.source.ApplicationID,
		SourceRevisionID: f.source.ID,
		ContainerPort:    8080,
		IdempotencyKey:   "upload-delivery-non-immutable",
		Actor:            "admin",
	}

	_, err := f.service.Create(context.Background(), req)
	if err == nil {
		t.Fatal("expected delivery creation to fail for non-immutable source revision, got nil")
	}

	if len(f.tasks) != 0 {
		t.Errorf("expected 0 tasks queued when validation fails, got %d", len(f.tasks))
	}
	if f.completedBuilds != 0 {
		t.Errorf("expected 0 completed builds when validation fails, got %d", f.completedBuilds)
	}
	if f.buildProvider.calls != 0 {
		t.Errorf("expected 0 build provider calls when validation fails, got %d", f.buildProvider.calls)
	}
}

func TestAcornFoxUploadDeliveryRejectsCrossAppSource(t *testing.T) {
	f := newAcornFoxDeliveryFixture(t)
	f.source.Kind = domain.SourceUpload
	f.source.Locator = "upload://upload_delivery"
	f.source.Ref = ""
	f.source.Commit = ""

	req := AcornFoxDeliveryCreateRequest{
		ApplicationID:    "app_cross_attacker_app",
		SourceRevisionID: f.source.ID,
		ContainerPort:    8080,
		IdempotencyKey:   "upload-delivery-cross-app",
		Actor:            "admin",
	}

	_, err := f.service.Create(context.Background(), req)
	if err == nil {
		t.Fatal("expected delivery creation to fail for cross-app source revision, got nil")
	}

	if len(f.tasks) != 0 {
		t.Errorf("expected 0 tasks queued on cross-app rejection, got %d", len(f.tasks))
	}
	if f.completedBuilds != 0 {
		t.Errorf("expected 0 completed builds on cross-app rejection, got %d", f.completedBuilds)
	}
	if f.buildProvider.calls != 0 {
		t.Errorf("expected 0 build provider calls on cross-app rejection, got %d", f.buildProvider.calls)
	}
}

func TestAcornFoxUploadDeliveryRejectsCorruptedDigest(t *testing.T) {
	testCases := []struct {
		name   string
		digest string
	}{
		{
			name:   "empty digest rejected",
			digest: "",
		},
		{
			name:   "malformed digest format rejected",
			digest: "invalid-sha256-digest-format",
		},
		{
			name:   "short hex string rejected",
			digest: "1234abcd",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f := newAcornFoxDeliveryFixture(t)
			f.source.Kind = domain.SourceUpload
			f.source.Locator = "upload://upload_delivery"
			f.source.Ref = ""
			f.source.Commit = ""
			f.source.ContentDigest = tc.digest

			req := AcornFoxDeliveryCreateRequest{
				ApplicationID:    f.source.ApplicationID,
				SourceRevisionID: f.source.ID,
				ContainerPort:    8080,
				IdempotencyKey:   "upload-delivery-digest-" + tc.name,
				Actor:            "admin",
			}

			_, err := f.service.Create(context.Background(), req)
			if err == nil {
				t.Fatalf("expected delivery creation to fail for corrupted digest %q, got nil", tc.digest)
			}

			if len(f.tasks) != 0 {
				t.Errorf("expected 0 tasks queued on corrupted digest, got %d", len(f.tasks))
			}
			if f.completedBuilds != 0 {
				t.Errorf("expected 0 completed builds on corrupted digest, got %d", f.completedBuilds)
			}
			if f.buildProvider.calls != 0 {
				t.Errorf("expected 0 build provider calls on corrupted digest, got %d", f.buildProvider.calls)
			}
		})
	}
}

func TestAcornFoxUploadDeliveryRejectsDisallowedSourceKind(t *testing.T) {
	f := newAcornFoxDeliveryFixture(t)
	f.source.Kind = "unsupported_source_kind"
	f.source.Locator = "ftp://remote/archive.tar.gz"
	f.source.Ref = ""
	f.source.Commit = ""

	req := AcornFoxDeliveryCreateRequest{
		ApplicationID:    f.source.ApplicationID,
		SourceRevisionID: f.source.ID,
		ContainerPort:    8080,
		IdempotencyKey:   "upload-delivery-disallowed-kind",
		Actor:            "admin",
	}

	_, err := f.service.Create(context.Background(), req)
	if err == nil {
		t.Fatal("expected delivery creation to fail for disallowed source kind, got nil")
	}

	if len(f.tasks) != 0 {
		t.Errorf("expected 0 tasks queued on disallowed source kind, got %d", len(f.tasks))
	}
	if f.completedBuilds != 0 {
		t.Errorf("expected 0 completed builds on disallowed source kind, got %d", f.completedBuilds)
	}
	if f.buildProvider.calls != 0 {
		t.Errorf("expected 0 build provider calls on disallowed source kind, got %d", f.buildProvider.calls)
	}
}
