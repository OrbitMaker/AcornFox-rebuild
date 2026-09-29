package application

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
)

// AcornFoxPublicAccessErrorCode is the fixed public error vocabulary for the
// standalone public-access endpoint. HTTP mapping belongs to the server leaf;
// this package only makes the semantic distinction stable.
type AcornFoxPublicAccessErrorCode string

const (
	AcornFoxPublicAccessIdempotencyConflict AcornFoxPublicAccessErrorCode = "public_access_idempotency_conflict"
	AcornFoxInternalEndpointNotReady        AcornFoxPublicAccessErrorCode = "internal_endpoint_not_ready"
	AcornFoxPublicAccessConflict            AcornFoxPublicAccessErrorCode = "public_access_conflict"
	AcornFoxPublicAccessOwnershipConflict   AcornFoxPublicAccessErrorCode = "public_access_ownership_conflict"
	AcornFoxPublicAccessUnavailable         AcornFoxPublicAccessErrorCode = "public_access_unavailable"
)

type acornFoxPublicAccessError struct {
	code  AcornFoxPublicAccessErrorCode
	cause error
}

func (err *acornFoxPublicAccessError) Error() string {
	if err == nil {
		return ""
	}
	if err.cause == nil {
		return string(err.code)
	}
	return string(err.code) + ": " + err.cause.Error()
}

func (err *acornFoxPublicAccessError) Unwrap() error { return err.cause }

func (err *acornFoxPublicAccessError) Is(target error) bool {
	other, ok := target.(*acornFoxPublicAccessError)
	return ok && err != nil && err.code == other.code
}

var (
	ErrAcornFoxPublicAccessIdempotencyConflict = &acornFoxPublicAccessError{code: AcornFoxPublicAccessIdempotencyConflict}
	ErrAcornFoxInternalEndpointNotReady        = &acornFoxPublicAccessError{code: AcornFoxInternalEndpointNotReady}
	ErrAcornFoxPublicAccessConflict            = &acornFoxPublicAccessError{code: AcornFoxPublicAccessConflict}
	ErrAcornFoxPublicAccessOwnershipConflict   = &acornFoxPublicAccessError{code: AcornFoxPublicAccessOwnershipConflict}
	ErrAcornFoxPublicAccessUnavailable         = &acornFoxPublicAccessError{code: AcornFoxPublicAccessUnavailable}
)

// AcornFoxPublicAccessErrorCodeOf lets the server map only the five stable
// public errors without inspecting provider/database error strings.
func AcornFoxPublicAccessErrorCodeOf(err error) (AcornFoxPublicAccessErrorCode, bool) {
	var public *acornFoxPublicAccessError
	if errors.As(err, &public) {
		return public.code, true
	}
	return "", false
}

// AcornFoxPublicAccessStore owns durable per-deployment serialization and
// command replay. It is deliberately not a generic operation framework: this
// one small interface records only public-access facts and reads only an
// already accepted local routable endpoint.
type AcornFoxPublicAccessStore interface {
	BeginAcornFoxPublicAccess(context.Context, contracts.AcornFoxPublicAccessFact, contracts.AcornFoxPublicRouteIntent, bool, string, string, domain.ID, time.Time) (contracts.AcornFoxPublicAccessFact, bool, error)
	// Commit receives the exact owned route intent used by the local router.
	// Keeping it alongside the command fact is necessary for a later disable
	// after a process restart; callers never provide a hostname or target.
	CommitAcornFoxPublicAccess(context.Context, contracts.AcornFoxPublicAccessFact, contracts.AcornFoxPublicRouteIntent, string, string, time.Time) error
	MarkAcornFoxPublicAccessReconcileRequired(context.Context, domain.ID, domain.ID, string, string, time.Time) error
	FailAcornFoxPublicAccess(context.Context, domain.ID, domain.ID, string, string, string, time.Time) error
	GetAcornFoxPublicAccess(context.Context, domain.ID, domain.ID) (contracts.AcornFoxPublicAccessFact, bool, error)
	GetAcornFoxRoutableEndpoint(context.Context, domain.ID, domain.ID) (contracts.AcornFoxRoutableEndpoint, error)
	GetAcornFoxPublicRouteIntent(context.Context, domain.ID, domain.ID) (contracts.AcornFoxPublicRouteIntent, bool, error)
}

// AcornFoxPublicAccessRouter is the narrow application seam around the
// existing RouteProvider/controller family. Implementations must apply/remove
// only the supplied owned intent and must report an ownership conflict instead
// of deleting a foreign Caddy route at the derived hostname.
type AcornFoxPublicAccessRouter interface {
	EnsureAcornFoxPublicRoute(context.Context, contracts.AcornFoxPublicRouteIntent, string) error
	RemoveAcornFoxPublicRoute(context.Context, contracts.AcornFoxPublicRouteIntent, string) error
}

type AcornFoxPublicAccessConfig struct {
	AuthorizedRoot string
}

func (config AcornFoxPublicAccessConfig) validate() error {
	_, err := contracts.AcornFoxPublicHostname(config.AuthorizedRoot, "app_validation", "dep_validation")
	return err
}

// AcornFoxPublicAccessService coordinates local Caddy desired state. It never
// imports a DNS client, certificate client, runtime driver, storage provider,
// or database package. Enabling records PENDING_EXTERNAL_VALIDATION; only a
// future external-validation leaf can add a stronger public-ready claim.
type AcornFoxPublicAccessService struct {
	Store  AcornFoxPublicAccessStore
	Router AcornFoxPublicAccessRouter
	Config AcornFoxPublicAccessConfig
	Clock  func() time.Time
}

type AcornFoxPublicAccessRequest struct {
	ApplicationID       domain.ID
	DeploymentID        domain.ID
	Enabled             bool
	IdempotencyKey      string
	ManagementCommandID domain.ID
}

// Get reports only the local command fact. An absent durable fact is the
// intentional default PUBLIC_DISABLED state; it does not trigger a runtime,
// route, DNS, or certificate observation.
func (service *AcornFoxPublicAccessService) Get(ctx context.Context, applicationID, deploymentID domain.ID) (contracts.AcornFoxPublicAccessFact, error) {
	if err := service.ready(); err != nil {
		return contracts.AcornFoxPublicAccessFact{}, newAcornFoxPublicAccessError(AcornFoxPublicAccessUnavailable, err)
	}
	if applicationID.Empty() || deploymentID.Empty() {
		return contracts.AcornFoxPublicAccessFact{}, domain.ValidationError("AcornFox public-access identity is invalid")
	}
	hostname, err := contracts.AcornFoxPublicHostname(service.Config.AuthorizedRoot, applicationID, deploymentID)
	if err != nil {
		return contracts.AcornFoxPublicAccessFact{}, newAcornFoxPublicAccessError(AcornFoxPublicAccessUnavailable, err)
	}
	fact, found, err := service.Store.GetAcornFoxPublicAccess(ctx, applicationID, deploymentID)
	if err != nil {
		return contracts.AcornFoxPublicAccessFact{}, acornFoxPublicAccessStoreError(err)
	}
	if !found {
		return acornFoxPublicAccessFact(applicationID, deploymentID, hostname, false, contracts.AcornFoxInternalEndpointNotObserved, contracts.AcornFoxLocalRouteDisabled), nil
	}
	if err := fact.Validate(); err != nil || fact.ApplicationID != applicationID || fact.DeploymentID != deploymentID || fact.Hostname != hostname {
		return contracts.AcornFoxPublicAccessFact{}, newAcornFoxPublicAccessError(AcornFoxPublicAccessUnavailable, errors.New("durable public-access fact is invalid"))
	}
	return fact, nil
}

func (service *AcornFoxPublicAccessService) Set(ctx context.Context, request AcornFoxPublicAccessRequest) (contracts.AcornFoxPublicAccessFact, error) {
	if err := service.ready(); err != nil {
		return contracts.AcornFoxPublicAccessFact{}, newAcornFoxPublicAccessError(AcornFoxPublicAccessUnavailable, err)
	}
	if err := validateAcornFoxPublicAccessRequest(request); err != nil {
		return contracts.AcornFoxPublicAccessFact{}, err
	}
	hostname, err := contracts.AcornFoxPublicHostname(service.Config.AuthorizedRoot, request.ApplicationID, request.DeploymentID)
	if err != nil {
		return contracts.AcornFoxPublicAccessFact{}, newAcornFoxPublicAccessError(AcornFoxPublicAccessUnavailable, err)
	}
	intent, found, err := service.intent(ctx, request, hostname)
	if err != nil {
		return contracts.AcornFoxPublicAccessFact{}, err
	}
	endpointState := contracts.AcornFoxInternalEndpointNotObserved
	if found {
		endpointState = contracts.AcornFoxInternalEndpointAccepted
	}
	// Begin needs a truthful durable desired-state fact. The completed fact is
	// constructed only after the provider returned success below.
	localRoute := contracts.AcornFoxLocalRouteDisabled
	if request.Enabled {
		localRoute = contracts.AcornFoxLocalRouteDesired
	}
	result := acornFoxPublicAccessFact(request.ApplicationID, request.DeploymentID, hostname, request.Enabled, endpointState, localRoute)
	digest := acornFoxPublicAccessDigest(request, hostname)
	if replay, replayed, err := service.Store.BeginAcornFoxPublicAccess(ctx, result, intent, request.Enabled, request.IdempotencyKey, digest, request.ManagementCommandID, service.now()); err != nil {
		return contracts.AcornFoxPublicAccessFact{}, acornFoxPublicAccessStoreError(err)
	} else if replayed {
		return replay, nil
	}
	if request.Enabled {
		err = service.Router.EnsureAcornFoxPublicRoute(ctx, intent, request.IdempotencyKey)
	} else if found {
		err = service.Router.RemoveAcornFoxPublicRoute(ctx, intent, request.IdempotencyKey)
	}
	if err != nil {
		// A Caddy/provider error does not prove that no side effect happened.
		// Keep the durable M3 intent and let the bounded reconciler observe the
		// same command after restart rather than terminally inventing failure.
		if markErr := service.Store.MarkAcornFoxPublicAccessReconcileRequired(ctx, request.ApplicationID, request.DeploymentID, request.IdempotencyKey, digest, service.now()); markErr != nil {
			return contracts.AcornFoxPublicAccessFact{}, newAcornFoxPublicAccessError(AcornFoxPublicAccessUnavailable, markErr)
		}
		// Return the same durable component projection available to GET. The
		// transport still returns the stable error, but callers that retain the
		// value cannot mistake an unknown provider outcome for a terminal one.
		fact, getErr := service.Get(ctx, request.ApplicationID, request.DeploymentID)
		if getErr != nil {
			return contracts.AcornFoxPublicAccessFact{}, newAcornFoxPublicAccessError(AcornFoxPublicAccessUnavailable, getErr)
		}
		return fact, acornFoxPublicAccessRouterError(err)
	}
	if request.Enabled {
		result = acornFoxPublicAccessFact(request.ApplicationID, request.DeploymentID, hostname, true, contracts.AcornFoxInternalEndpointAccepted, contracts.AcornFoxLocalRouteConfigured)
	} else {
		result = acornFoxPublicAccessFact(request.ApplicationID, request.DeploymentID, hostname, false, endpointState, contracts.AcornFoxLocalRouteDisabled)
	}
	if err := result.Validate(); err != nil {
		return contracts.AcornFoxPublicAccessFact{}, service.fail(ctx, request, digest, newAcornFoxPublicAccessError(AcornFoxPublicAccessUnavailable, err))
	}
	if err := service.Store.CommitAcornFoxPublicAccess(ctx, result, intent, request.IdempotencyKey, digest, service.now()); err != nil {
		_ = service.Store.MarkAcornFoxPublicAccessReconcileRequired(ctx, request.ApplicationID, request.DeploymentID, request.IdempotencyKey, digest, service.now())
		fact, getErr := service.Get(ctx, request.ApplicationID, request.DeploymentID)
		if getErr == nil {
			return fact, newAcornFoxPublicAccessError(AcornFoxPublicAccessUnavailable, err)
		}
		return contracts.AcornFoxPublicAccessFact{}, newAcornFoxPublicAccessError(AcornFoxPublicAccessUnavailable, err)
	}
	return result, nil
}

func acornFoxPublicAccessFact(applicationID, deploymentID domain.ID, hostname string, desired bool, endpoint contracts.AcornFoxInternalEndpointState, route contracts.AcornFoxLocalRouteState) contracts.AcornFoxPublicAccessFact {
	status := contracts.AcornFoxPublicDisabled
	if desired {
		status = contracts.AcornFoxPublicPendingExternalValidation
	}
	return contracts.AcornFoxPublicAccessFact{ApplicationID: applicationID, DeploymentID: deploymentID, Hostname: hostname, Status: status, DesiredPublic: desired, InternalEndpoint: endpoint, LocalRoute: route}
}

func (service *AcornFoxPublicAccessService) intent(ctx context.Context, request AcornFoxPublicAccessRequest, hostname string) (contracts.AcornFoxPublicRouteIntent, bool, error) {
	// Disabling has no endpoint prerequisite. The derived identity is sufficient
	// for an ownership-checked remove, so stopped applications can be closed.
	if !request.Enabled {
		intent, found, err := service.Store.GetAcornFoxPublicRouteIntent(ctx, request.ApplicationID, request.DeploymentID)
		if err != nil {
			return contracts.AcornFoxPublicRouteIntent{}, false, newAcornFoxPublicAccessError(AcornFoxPublicAccessUnavailable, err)
		}
		if !found {
			return contracts.AcornFoxPublicRouteIntent{}, false, nil
		}
		if err := intent.Validate(); err != nil || intent.ApplicationID != request.ApplicationID || intent.DeploymentID != request.DeploymentID || intent.Hostname != hostname {
			return contracts.AcornFoxPublicRouteIntent{}, false, newAcornFoxPublicAccessError(AcornFoxPublicAccessOwnershipConflict, errors.New("stored public route is not owned by requested deployment"))
		}
		return intent, true, nil
	}
	endpoint, err := service.Store.GetAcornFoxRoutableEndpoint(ctx, request.ApplicationID, request.DeploymentID)
	if err != nil {
		return contracts.AcornFoxPublicRouteIntent{}, false, newAcornFoxPublicAccessError(AcornFoxInternalEndpointNotReady, err)
	}
	if err := endpoint.Validate(); err != nil || endpoint.ApplicationID != request.ApplicationID || endpoint.DeploymentID != request.DeploymentID {
		return contracts.AcornFoxPublicRouteIntent{}, false, newAcornFoxPublicAccessError(AcornFoxInternalEndpointNotReady, errors.New("persisted routable endpoint is absent or unowned"))
	}
	intent := contracts.AcornFoxPublicRouteIntent{ApplicationID: request.ApplicationID, DeploymentID: request.DeploymentID, Hostname: hostname, ServiceName: endpoint.ServiceName, Port: endpoint.Port}
	if err := intent.Validate(); err != nil {
		return contracts.AcornFoxPublicRouteIntent{}, false, newAcornFoxPublicAccessError(AcornFoxInternalEndpointNotReady, err)
	}
	return intent, true, nil
}

func (service *AcornFoxPublicAccessService) fail(ctx context.Context, request AcornFoxPublicAccessRequest, digest string, cause error) error {
	if cause == nil {
		return nil
	}
	if err := service.Store.FailAcornFoxPublicAccess(ctx, request.ApplicationID, request.DeploymentID, request.IdempotencyKey, digest, cause.Error(), service.now()); err != nil {
		return newAcornFoxPublicAccessError(AcornFoxPublicAccessUnavailable, fmt.Errorf("public-access outcome could not be recorded: %w", err))
	}
	return cause
}

func (service *AcornFoxPublicAccessService) ready() error {
	if service == nil || service.Store == nil || service.Router == nil {
		return errors.New("AcornFox public-access service is unavailable")
	}
	return service.Config.validate()
}

func (service *AcornFoxPublicAccessService) now() time.Time {
	if service != nil && service.Clock != nil {
		return service.Clock().UTC()
	}
	return time.Now().UTC()
}

func validateAcornFoxPublicAccessRequest(request AcornFoxPublicAccessRequest) error {
	if request.ApplicationID.Empty() || request.DeploymentID.Empty() || strings.TrimSpace(request.IdempotencyKey) == "" {
		return domain.ValidationError("AcornFox public-access request is invalid")
	}
	return nil
}

func acornFoxPublicAccessDigest(request AcornFoxPublicAccessRequest, hostname string) string {
	sum := sha256.Sum256([]byte("acornfox-public-access-command\x00" + request.ApplicationID.String() + "\x00" + request.DeploymentID.String() + "\x00" + fmt.Sprint(request.Enabled) + "\x00" + hostname))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func newAcornFoxPublicAccessError(code AcornFoxPublicAccessErrorCode, cause error) error {
	return &acornFoxPublicAccessError{code: code, cause: cause}
}

func acornFoxPublicAccessStoreError(err error) error {
	switch {
	case errors.Is(err, ErrNotFound), domain.IsCode(err, domain.ErrNotFound):
		return ErrNotFound
	case errors.Is(err, ErrAcornFoxPublicAccessIdempotencyConflict), errors.Is(err, ErrIdempotencyConflict):
		return newAcornFoxPublicAccessError(AcornFoxPublicAccessIdempotencyConflict, err)
	case domain.IsCode(err, domain.ErrConflict):
		return ErrAcornFoxPublicAccessConflict
	case errors.Is(err, ErrAcornFoxPublicAccessConflict):
		return err
	case errors.Is(err, ErrAcornFoxPublicAccessOwnershipConflict):
		return err
	default:
		return newAcornFoxPublicAccessError(AcornFoxPublicAccessUnavailable, err)
	}
}

func acornFoxPublicAccessRouterError(err error) error {
	switch {
	case errors.Is(err, ErrAcornFoxPublicAccessOwnershipConflict):
		return err
	case errors.Is(err, ErrAcornFoxPublicAccessConflict):
		return err
	default:
		return newAcornFoxPublicAccessError(AcornFoxPublicAccessUnavailable, err)
	}
}
