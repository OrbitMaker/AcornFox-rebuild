package application

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
)

type acornFoxCancelContextKey struct{}
type acornFoxCancelBuildProvider struct {
	contracts.BuildProvider
	cancel context.CancelFunc
}

func (p acornFoxCancelBuildProvider) Build(ctx context.Context, _ contracts.BuildRequest) (contracts.BuildResult, error) {
	if p.cancel != nil {
		p.cancel()
	}
	return contracts.BuildResult{}, fmt.Errorf("private build log https://example.invalid/build?token=do-not-persist: %w", ctx.Err())
}

type acornFoxCancelPersistence struct {
	*acornFoxDeliveryFixture
	t                     *testing.T
	buildErr, deliveryErr error
	contexts              []context.Context
	reasons               []string
}

func (p *acornFoxCancelPersistence) check(ctx context.Context, reason string) {
	p.t.Helper()
	if ctx.Err() != nil {
		p.t.Fatalf("failure persistence inherited cancelled context: %v", ctx.Err())
	}
	deadline, ok := ctx.Deadline()
	remaining := time.Until(deadline)
	if !ok || remaining <= 0 || remaining > acornFoxDeliveryFailureTimeout {
		p.t.Fatal("failure persistence must have a finite independent deadline")
	}
	if ctx.Value(acornFoxCancelContextKey{}) != "request-trace" {
		p.t.Fatal("request values were lost")
	}
	if strings.Contains(reason, "token=") || strings.Contains(reason, "https://") || strings.Contains(reason, "private build log") {
		p.t.Fatal("raw provider diagnostics leaked into failure facts")
	}
	p.contexts = append(p.contexts, ctx)
	p.reasons = append(p.reasons, reason)
}
func (p *acornFoxCancelPersistence) FailBuild(ctx context.Context, id domain.ID, reason string, now time.Time) (domain.Build, error) {
	p.check(ctx, reason)
	if p.buildErr != nil {
		return domain.Build{}, p.buildErr
	}
	return p.acornFoxDeliveryFixture.FailBuild(ctx, id, reason, now)
}
func (p *acornFoxCancelPersistence) FailAcornFoxDelivery(ctx context.Context, key, digest, reason string, now time.Time) error {
	p.check(ctx, reason)
	if p.deliveryErr != nil {
		return p.deliveryErr
	}
	return p.acornFoxDeliveryFixture.FailAcornFoxDelivery(ctx, key, digest, reason, now)
}
func TestAcornFoxDeliveryPersistsCancelledBuildWithIndependentBoundedContexts(t *testing.T) {
	for _, expired := range []bool{false, true} {
		t.Run(map[bool]string{false: "cancelled", true: "deadline"}[expired], func(t *testing.T) {
			f := newAcornFoxDeliveryFixture(t)
			persistence := &acornFoxCancelPersistence{acornFoxDeliveryFixture: f, t: t}
			f.service.Builds, f.service.Idempotency = persistence, persistence
			base := context.WithValue(context.Background(), acornFoxCancelContextKey{}, "request-trace")
			ctx, cancel := context.WithCancel(base)
			if expired {
				cancel()
				ctx, cancel = context.WithDeadline(base, time.Now().Add(-time.Second))
			}
			defer cancel()
			f.service.Builder = acornFoxCancelBuildProvider{BuildProvider: f.buildProvider, cancel: cancel}
			request := AcornFoxDeliveryCreateRequest{ApplicationID: f.source.ApplicationID, SourceRevisionID: f.source.ID, ContainerPort: 8080, IdempotencyKey: "cancelled-create", Actor: "admin"}
			result, err := f.service.Create(ctx, request)
			wanted := context.Canceled
			reason := "AcornFox operation was cancelled"
			if expired {
				wanted = context.DeadlineExceeded
				reason = "AcornFox operation timed out"
			}
			if !errors.Is(err, wanted) || !result.DeploymentID.Empty() || f.failedBuilds != 1 || f.completedBuilds != 0 || len(f.tasks) != 0 || f.requests[request.IdempotencyKey].status != "failed" {
				t.Fatalf("cancelled create was not durably failed: error=%v failed=%d tasks=%d", err, f.failedBuilds, len(f.tasks))
			}
			if len(persistence.contexts) != 2 {
				t.Fatal("both build and reserved delivery must settle")
			}
			for n, ctx := range persistence.contexts {
				if ctx.Err() != context.Canceled || persistence.reasons[n] != reason {
					t.Fatal("persistence context leaked or reason was not classified")
				}
			}
		})
	}
}
func TestAcornFoxDeliveryCancellationPersistenceFailureStaysUnknown(t *testing.T) {
	for _, failure := range []string{"build", "delivery"} {
		t.Run(failure, func(t *testing.T) {
			f := newAcornFoxDeliveryFixture(t)
			p := &acornFoxCancelPersistence{acornFoxDeliveryFixture: f, t: t}
			if failure == "build" {
				p.buildErr = context.DeadlineExceeded
			} else {
				p.deliveryErr = context.DeadlineExceeded
			}
			f.service.Builds, f.service.Idempotency = p, p
			ctx, cancel := context.WithCancel(context.WithValue(context.Background(), acornFoxCancelContextKey{}, "request-trace"))
			defer cancel()
			f.service.Builder = acornFoxCancelBuildProvider{BuildProvider: f.buildProvider, cancel: cancel}
			result, err := f.service.Create(ctx, AcornFoxDeliveryCreateRequest{ApplicationID: f.source.ApplicationID, SourceRevisionID: f.source.ID, ContainerPort: 8080, IdempotencyKey: "cancel-write-failure", Actor: "admin"})
			if !domain.IsCode(err, domain.ErrUnknownState) || !result.DeploymentID.Empty() || len(f.tasks) != 0 || f.completedBuilds != 0 {
				t.Fatal("failed persistence was reported as a settled successful outcome")
			}
			if len(p.contexts) != 2 {
				t.Fatal("delivery failure was not attempted with a fresh bounded context")
			}
			if failure == "build" && p.reasons[1] != "AcornFox operation outcome is unknown" {
				t.Fatal("unknown build outcome was replaced with a confirmed cancellation fact")
			}
		})
	}
}

func TestAcornFoxDeliveryFailureReasonRetainsOnlySafeProviderClasses(t *testing.T) {
	private := errors.New("private build log https://example.invalid/build?token=do-not-persist")
	for _, test := range []struct {
		code contracts.ErrorCode
		want string
	}{
		{contracts.ErrCapacity, "AcornFox capacity limit was exceeded (capacity_exceeded)"},
		{contracts.ErrForbidden, "AcornFox operation was forbidden (forbidden)"},
		{contracts.ErrValidation, "AcornFox operation failed validation (validation_failed)"},
		{contracts.ErrUnsupportedCapability, "AcornFox requested capability is unsupported (unsupported_capability)"},
		{contracts.ErrorCode(private.Error()), "AcornFox operation failed"},
	} {
		provider := &contracts.ProviderError{Code: test.code, Provider: private.Error(), Message: private.Error(), Cause: private}
		wrapped := fmt.Errorf("%s: %w", private.Error(), provider)
		if got := acornFoxDeliveryFailureReason(wrapped); got != test.want {
			t.Fatal("safe failure class changed or private diagnostics escaped")
		}
		if got := acornFoxDeliveryFailureReason(contracts.ProviderOutcomeUnknown(wrapped)); got != "AcornFox operation outcome is unknown" {
			t.Fatal("unknown outcome was incorrectly classified as a confirmed provider failure")
		}
	}
}
