package controllers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
)

type M3DNSManager interface {
	VerifyPlatform(context.Context, string, string, contracts.OperationContext) (domain.DomainBinding, error)
	VerifyApplication(context.Context, domain.ID, string, string, contracts.OperationContext) (domain.DomainBinding, error)
}

type M3CertificateManager interface {
	Issue(context.Context, domain.DomainBinding, contracts.OperationContext) (domain.CertificateReference, error)
	Renew(context.Context, domain.CertificateReference, contracts.OperationContext) (domain.CertificateReference, error)
}

type M3AccessStore interface {
	PutDomainBinding(context.Context, domain.DomainBinding) error
	PutCertificateReference(context.Context, domain.CertificateReference) error
	PutDesiredRoute(context.Context, domain.Route, int) error
	ListDesiredRoutes(context.Context) ([]domain.DesiredRoute, error)
	SetRoutePointer(context.Context, domain.ID, domain.ID, string) error
	RecordTrafficSwitch(context.Context, domain.TrafficSwitch) error
	AppendAccessEvent(context.Context, domain.ID, string, string, string, bool) error
}

type M3RouteTarget struct {
	ApplicationID domain.ID
	DeploymentID  domain.ID
	ServiceName   string
	Port          int
	Path          string
	Routable      bool
}

type M3IPFallbackRequest struct {
	Target         M3RouteTarget
	ServerIP       string
	RuntimeReady   bool
	IdempotencyKey string
	Actor          string
}

type M3DomainRouteRequest struct {
	Binding        domain.DomainBinding
	Certificate    domain.CertificateReference
	Targets        []M3RouteTarget
	RuntimeReady   bool
	IdempotencyKey string
	Actor          string
}

type M3SwitchRequest struct {
	ApplicationID  domain.ID
	Old            []domain.DesiredRoute
	Candidate      []domain.DesiredRoute
	Healthy        func(context.Context, domain.ID) error
	Observe        func(context.Context, domain.ID) error
	Window         time.Duration
	IdempotencyKey string
	Actor          string
}

type M3AccessController struct {
	Routes       contracts.RouteProvider
	Store        M3AccessStore
	DNS          M3DNSManager
	Certificates M3CertificateManager
	Clock        func() time.Time
	Sleep        func(context.Context, time.Duration) error
}

func (c *M3AccessController) EnsureIPFallback(ctx context.Context, request M3IPFallbackRequest) (domain.AccessState, error) {
	if err := c.validate(); err != nil {
		return domain.AccessState{}, err
	}
	if !request.RuntimeReady {
		return domain.AccessState{}, domain.NewError(domain.ErrInvalidTransition, "IP fallback requires a runtime-ready deployment")
	}
	if ip := net.ParseIP(strings.TrimSpace(request.ServerIP)); ip == nil {
		return domain.AccessState{}, domain.ValidationError("IP fallback requires a literal server IP")
	} else {
		request.ServerIP = ip.String()
	}
	if err := validateM3Target(request.Target); err != nil {
		return domain.AccessState{}, err
	}
	// The runtime's already allocated loopback/public host port is the fallback.
	// It must not depend on Caddy, DNS, or certificate state.
	_ = ctx
	state := domain.AccessState{ApplicationID: request.Target.ApplicationID, DeploymentID: request.Target.DeploymentID, RuntimeReady: true, IPAvailable: true, IPAddress: fmt.Sprintf("http://%s:%d%s", request.ServerIP, request.Target.Port, request.Target.Path), Serving: true, Message: "IP address is available; no domain or HTTPS has been claimed"}
	if err := c.Store.AppendAccessEvent(ctx, request.Target.ApplicationID, request.IdempotencyKey, "route.ip_fallback_ready", state.Message, true); err != nil {
		return domain.AccessState{}, err
	}
	return state, nil
}

func (c *M3AccessController) BindPlatformDomain(ctx context.Context, baseDomain, target, key, actor string) (domain.DomainBinding, domain.CertificateReference, error) {
	if err := c.validate(); err != nil {
		return domain.DomainBinding{}, domain.CertificateReference{}, err
	}
	binding, err := c.DNS.VerifyPlatform(ctx, baseDomain, target, m3Operation(key+":dns", actor))
	if err != nil {
		return c.failedDomain(ctx, domain.DomainBindingPlatform, "", baseDomain, "", err)
	}
	if err := c.Store.PutDomainBinding(ctx, binding); err != nil {
		return domain.DomainBinding{}, domain.CertificateReference{}, err
	}
	certificate, err := c.Certificates.Issue(ctx, binding, m3Operation(key+":certificate", actor))
	if err != nil {
		binding.Status = domain.DomainFailed
		binding.FailureReason = "certificate issuance failed; IP fallback remains available"
		binding.UpdatedAt = c.now()
		_ = c.Store.PutDomainBinding(ctx, binding)
		return binding, domain.CertificateReference{}, err
	}
	binding.Status = domain.DomainReady
	binding.CertificateRef = certificate.ID.String()
	binding.UpdatedAt = c.now()
	if err := c.Store.PutCertificateReference(ctx, certificate); err != nil {
		return domain.DomainBinding{}, domain.CertificateReference{}, err
	}
	if err := c.Store.PutDomainBinding(ctx, binding); err != nil {
		return domain.DomainBinding{}, domain.CertificateReference{}, err
	}
	return binding, certificate, nil
}

func (c *M3AccessController) BindApplicationDomain(ctx context.Context, applicationID domain.ID, host, target, key, actor string) (domain.DomainBinding, domain.CertificateReference, error) {
	if err := c.validate(); err != nil {
		return domain.DomainBinding{}, domain.CertificateReference{}, err
	}
	binding, err := c.DNS.VerifyApplication(ctx, applicationID, host, target, m3Operation(key+":dns", actor))
	if err != nil {
		return c.failedDomain(ctx, domain.DomainBindingApplication, applicationID, host, target, err)
	}
	if err := c.Store.PutDomainBinding(ctx, binding); err != nil {
		return domain.DomainBinding{}, domain.CertificateReference{}, err
	}
	certificate, err := c.Certificates.Issue(ctx, binding, m3Operation(key+":certificate", actor))
	if err != nil {
		binding.Status = domain.DomainFailed
		binding.FailureReason = "certificate issuance failed; IP fallback remains available"
		binding.UpdatedAt = c.now()
		_ = c.Store.PutDomainBinding(ctx, binding)
		_ = c.Store.AppendAccessEvent(ctx, applicationID, key, "domain.certificate_failed", binding.FailureReason, false)
		return binding, domain.CertificateReference{}, err
	}
	binding.Status = domain.DomainReady
	binding.CertificateRef = certificate.ID.String()
	binding.UpdatedAt = c.now()
	if err := c.Store.PutCertificateReference(ctx, certificate); err != nil {
		return domain.DomainBinding{}, domain.CertificateReference{}, err
	}
	if err := c.Store.PutDomainBinding(ctx, binding); err != nil {
		return domain.DomainBinding{}, domain.CertificateReference{}, err
	}
	if err := c.Store.AppendAccessEvent(ctx, applicationID, key, "domain.application_ready", "application CNAME and certificate are ready", true); err != nil {
		return domain.DomainBinding{}, domain.CertificateReference{}, err
	}
	return binding, certificate, nil
}

func (c *M3AccessController) CreatePlatformApplicationDomain(ctx context.Context, applicationID domain.ID, applicationName string, platform domain.DomainBinding) (domain.DomainBinding, error) {
	if err := c.validate(); err != nil {
		return domain.DomainBinding{}, err
	}
	if platform.Kind != domain.DomainBindingPlatform || platform.Status != domain.DomainReady || platform.CertificateRef == "" {
		return domain.DomainBinding{}, domain.NewError(domain.ErrInvalidTransition, "platform domain must be verified with a ready wildcard certificate")
	}
	host, err := domain.StableApplicationHost(applicationName, applicationID, platform.Host)
	if err != nil {
		return domain.DomainBinding{}, err
	}
	now := c.now()
	sum := sha256.Sum256([]byte("managed:" + applicationID.String() + ":" + platform.ID.String()))
	binding := domain.DomainBinding{ID: domain.ID("domain_" + hex.EncodeToString(sum[:16])), Kind: domain.DomainBindingApplication, ApplicationID: applicationID, PlatformDomainID: platform.ID, Managed: true, Host: host, Status: domain.DomainReady, CertificateRef: platform.CertificateRef, VerifiedAt: &now, CreatedAt: now, UpdatedAt: now}
	if err := binding.Validate(); err != nil {
		return domain.DomainBinding{}, err
	}
	if err := c.Store.PutDomainBinding(ctx, binding); err != nil {
		return domain.DomainBinding{}, err
	}
	if err := c.Store.AppendAccessEvent(ctx, applicationID, "platform-host:"+binding.ID.String(), "domain.platform_application_ready", "stable platform application hostname is ready", true); err != nil {
		return domain.DomainBinding{}, err
	}
	return binding, nil
}

func (c *M3AccessController) RenewCertificate(ctx context.Context, applicationID domain.ID, previous domain.CertificateReference, key, actor string) (domain.CertificateReference, error) {
	if err := c.validate(); err != nil {
		return domain.CertificateReference{}, err
	}
	if err := domain.RequireID(applicationID, "certificate application id"); err != nil {
		return domain.CertificateReference{}, err
	}
	if previous.Status != domain.CertificateReady {
		return domain.CertificateReference{}, domain.NewError(domain.ErrInvalidTransition, "only a ready certificate can be renewed")
	}
	renewed, err := c.Certificates.Renew(ctx, previous, m3Operation(key+":renew", actor))
	if err != nil {
		_ = c.Store.AppendAccessEvent(ctx, applicationID, key, "certificate.renewal_failed", "certificate renewal failed; current certificate and IP fallback remain active", false)
		return domain.CertificateReference{}, err
	}
	renewed.ID = previous.ID
	renewed.DomainBindingID = previous.DomainBindingID
	if err := c.Store.PutCertificateReference(ctx, renewed); err != nil {
		return domain.CertificateReference{}, err
	}
	if err := c.Store.AppendAccessEvent(ctx, applicationID, key, "certificate.renewed", "replacement certificate is ready", true); err != nil {
		return domain.CertificateReference{}, err
	}
	return renewed, nil
}

func (c *M3AccessController) ApplyDomainRoutes(ctx context.Context, request M3DomainRouteRequest) ([]domain.Route, domain.AccessState, error) {
	if err := c.validate(); err != nil {
		return nil, domain.AccessState{}, err
	}
	if !request.RuntimeReady || request.Binding.Status != domain.DomainReady || request.Certificate.Status != domain.CertificateReady || request.Binding.CertificateRef != request.Certificate.ID.String() {
		return nil, domain.AccessState{}, domain.NewError(domain.ErrInvalidTransition, "verified domain and ready certificate are required before routing")
	}
	if len(request.Targets) == 0 {
		return nil, domain.AccessState{}, domain.ValidationError("at least one route target is required")
	}
	targets := append([]M3RouteTarget(nil), request.Targets...)
	for index := range targets {
		if err := validateM3Target(targets[index]); err != nil {
			return nil, domain.AccessState{}, err
		}
		path, _ := domain.NormalizeRoutePath(targets[index].Path)
		targets[index].Path = path
	}
	if err := rejectM3RouteConflicts(targets); err != nil {
		return nil, domain.AccessState{}, err
	}
	sort.Slice(targets, func(i, j int) bool { return len(targets[i].Path) > len(targets[j].Path) })
	applied := make([]domain.Route, 0, len(targets))
	for index, target := range targets {
		op := m3Operation(fmt.Sprintf("%s:route:%d", request.IdempotencyKey, index), request.Actor)
		route, _, err := c.Routes.Apply(ctx, contracts.RouteRequest{Route: contracts.RouteSpec{Host: request.Binding.Host, Path: target.Path, DeploymentID: target.DeploymentID, ServiceName: target.ServiceName, Port: target.Port, CertificateRef: request.Certificate.ID.String(), Verified: true}, Operation: op})
		if err != nil {
			c.rollbackApplied(applied, targets[:index], request.IdempotencyKey, request.Actor)
			_ = c.Store.AppendAccessEvent(ctx, target.ApplicationID, request.IdempotencyKey, "route.apply_failed", "domain route failed; IP fallback remains available", false)
			return nil, domain.AccessState{ApplicationID: target.ApplicationID, DeploymentID: target.DeploymentID, RuntimeReady: true, IPAvailable: true, DomainStatus: domain.DomainFailed, Domain: request.Binding.Host, Message: "domain route failed; IP fallback remains available"}, err
		}
		route.ApplicationID = target.ApplicationID
		route.ServiceName = target.ServiceName
		route.Verified, route.Serving = true, true
		if err := c.Store.PutDesiredRoute(ctx, route, target.Port); err != nil {
			c.rollbackApplied(append(applied, route), targets[:index+1], request.IdempotencyKey, request.Actor)
			return nil, domain.AccessState{}, err
		}
		if err := c.Store.SetRoutePointer(ctx, route.ID, target.DeploymentID, request.IdempotencyKey); err != nil {
			return nil, domain.AccessState{}, err
		}
		applied = append(applied, route)
	}
	first := targets[0]
	state := domain.AccessState{ApplicationID: first.ApplicationID, DeploymentID: first.DeploymentID, RuntimeReady: true, IPAvailable: true, DomainStatus: domain.DomainReady, Domain: request.Binding.Host, HTTPSReady: true, Serving: true, Message: "HTTPS address is ready"}
	if err := c.Store.AppendAccessEvent(ctx, first.ApplicationID, request.IdempotencyKey, "route.serving", "verified HTTPS routes are serving", true); err != nil {
		return nil, domain.AccessState{}, err
	}
	return applied, state, nil
}

func (c *M3AccessController) RebuildRoutes(ctx context.Context, key, actor string) (contracts.Evidence, error) {
	if err := c.validate(); err != nil {
		return contracts.Evidence{}, err
	}
	stored, err := c.Store.ListDesiredRoutes(ctx)
	if err != nil {
		return contracts.Evidence{}, err
	}
	requests := make([]contracts.RouteRequest, 0, len(stored))
	for index, item := range stored {
		requests = append(requests, contracts.RouteRequest{Route: routeSpecFrom(item.Route, item.Port), Operation: m3Operation(fmt.Sprintf("%s:route:%d", key, index), actor)})
	}
	if rebuilder, ok := c.Routes.(contracts.RouteSetRebuilder); ok {
		return rebuilder.RebuildRoutes(ctx, requests, m3Operation(key, actor))
	}
	var evidence contracts.Evidence
	for _, request := range requests {
		_, current, err := c.Routes.Apply(ctx, request)
		if err != nil {
			return contracts.Evidence{}, err
		}
		evidence.Refs = append(evidence.Refs, current.Refs...)
	}
	return evidence, nil
}

func (c *M3AccessController) Switch(ctx context.Context, request M3SwitchRequest) error {
	if err := c.validate(); err != nil {
		return err
	}
	if len(request.Old) == 0 || len(request.Candidate) == 0 || request.Healthy == nil || request.Observe == nil {
		return domain.ValidationError("traffic switch requires old/candidate routes and health checks")
	}
	next := request.Candidate[0].Route.DeploymentID
	previous := request.Old[0].Route.DeploymentID
	if err := request.Healthy(ctx, next); err != nil {
		_ = c.recordSwitch(ctx, request, previous, next, "failed", "candidate health check failed")
		return domain.WrapError(domain.ErrUnavailable, "candidate health check failed; old deployment remains serving", err)
	}
	for _, item := range request.Candidate {
		if err := c.Store.PutDesiredRoute(ctx, item.Route, item.Port); err != nil {
			return err
		}
	}
	for index, item := range request.Candidate {
		_, _, err := c.Routes.Apply(ctx, contracts.RouteRequest{Route: routeSpecFrom(item.Route, item.Port), Operation: m3Operation(fmt.Sprintf("%s:apply:%d", request.IdempotencyKey, index), request.Actor)})
		if err != nil {
			c.restoreRoutes(request.Old, request.IdempotencyKey, request.Actor)
			_ = c.recordSwitch(ctx, request, previous, next, "old_serving", "route switch failed; old deployment restored")
			return err
		}
	}
	if request.Window > 0 {
		if err := c.sleep(ctx, request.Window); err != nil {
			c.restoreRoutes(request.Old, request.IdempotencyKey, request.Actor)
			return err
		}
	}
	if err := request.Observe(ctx, next); err != nil {
		c.restoreRoutes(request.Old, request.IdempotencyKey, request.Actor)
		_ = c.recordSwitch(ctx, request, previous, next, "old_serving", "observation failed; old deployment restored")
		return domain.WrapError(domain.ErrUnavailable, "observation failed; old deployment restored and remains serving", err)
	}
	for _, item := range request.Candidate {
		if err := c.Store.SetRoutePointer(ctx, item.Route.ID, next, request.IdempotencyKey); err != nil {
			c.restoreRoutes(request.Old, request.IdempotencyKey, request.Actor)
			return err
		}
	}
	return c.recordSwitch(ctx, request, previous, next, "stable", "candidate passed health and observation window")
}

func (c *M3AccessController) validate() error {
	if c == nil || c.Routes == nil || c.Store == nil || c.DNS == nil || c.Certificates == nil {
		return errors.New("M3 access controller dependencies are incomplete")
	}
	if c.Clock == nil {
		c.Clock = time.Now
	}
	return nil
}

func (c *M3AccessController) now() time.Time { return c.Clock().UTC() }
func (c *M3AccessController) sleep(ctx context.Context, duration time.Duration) error {
	if c.Sleep != nil {
		return c.Sleep(ctx, duration)
	}
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func validateM3Target(target M3RouteTarget) error {
	if err := domain.RequireID(target.ApplicationID, "route application id"); err != nil {
		return err
	}
	if err := domain.RequireID(target.DeploymentID, "route deployment id"); err != nil {
		return err
	}
	if !target.Routable || strings.TrimSpace(target.ServiceName) == "" {
		return domain.NewError(domain.ErrForbidden, "worker/database services are not routable")
	}
	if target.Port < 1 || target.Port > 65535 {
		return domain.ValidationError("route target must use a system-assigned port")
	}
	_, err := domain.NormalizeRoutePath(target.Path)
	return err
}

func rejectM3RouteConflicts(targets []M3RouteTarget) error {
	for i := range targets {
		for j := i + 1; j < len(targets); j++ {
			if domain.RoutePathsConflict(targets[i].Path, targets[j].Path) {
				return domain.NewError(domain.ErrConflict, "route path prefixes overlap ambiguously")
			}
		}
	}
	return nil
}

func routeSpecFrom(route domain.Route, port int) contracts.RouteSpec {
	return contracts.RouteSpec{Host: route.Host, Path: route.Path, DeploymentID: route.DeploymentID, ServiceName: route.ServiceName, Port: port, CertificateRef: route.CertificateRef, Verified: route.Verified}
}

func (c *M3AccessController) rollbackApplied(routes []domain.Route, targets []M3RouteTarget, key, actor string) {
	for index := len(routes) - 1; index >= 0; index-- {
		_ = c.Routes.Remove(context.Background(), contracts.RouteRequest{Route: routeSpecFrom(routes[index], targets[index].Port), Operation: m3Operation(fmt.Sprintf("%s:rollback:%d", key, index), actor)})
	}
}

func (c *M3AccessController) restoreRoutes(routes []domain.DesiredRoute, key, actor string) {
	for index, item := range routes {
		_, _, _ = c.Routes.Apply(context.Background(), contracts.RouteRequest{Route: routeSpecFrom(item.Route, item.Port), Operation: m3Operation(fmt.Sprintf("%s:restore:%d", key, index), actor)})
	}
}

func (c *M3AccessController) recordSwitch(ctx context.Context, request M3SwitchRequest, previous, next domain.ID, status, reason string) error {
	sum := sha256.Sum256([]byte(request.IdempotencyKey + ":" + status))
	record := domain.TrafficSwitch{ID: domain.ID("switch_" + hex.EncodeToString(sum[:16])), ApplicationID: request.ApplicationID, RouteID: request.Candidate[0].Route.ID, PreviousDeploymentID: previous, NextDeploymentID: next, Status: status, Reason: reason, ObservedAt: c.now()}
	if err := c.Store.RecordTrafficSwitch(ctx, record); err != nil {
		return err
	}
	return c.Store.AppendAccessEvent(ctx, request.ApplicationID, request.IdempotencyKey+":"+status, "route.switch."+status, reason, status == "stable")
}

func (c *M3AccessController) failedDomain(ctx context.Context, kind domain.DomainBindingKind, applicationID domain.ID, host, target string, cause error) (domain.DomainBinding, domain.CertificateReference, error) {
	now := c.now()
	sum := sha256.Sum256([]byte(string(kind) + ":" + applicationID.String() + ":" + host))
	binding := domain.DomainBinding{ID: domain.ID("domain_" + hex.EncodeToString(sum[:16])), Kind: kind, ApplicationID: applicationID, Host: strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), ".")), ExpectedCNAME: target, Status: domain.DomainFailed, FailureReason: "DNS verification failed; IP fallback remains available", CreatedAt: now, UpdatedAt: now}
	_ = c.Store.PutDomainBinding(ctx, binding)
	if !applicationID.Empty() {
		_ = c.Store.AppendAccessEvent(ctx, applicationID, "domain-failed:"+binding.ID.String(), "domain.verification_failed", binding.FailureReason, false)
	}
	return binding, domain.CertificateReference{}, cause
}

func m3Operation(key, actor string) contracts.OperationContext {
	return contracts.OperationContext{IdempotencyKey: strings.TrimSpace(key), Actor: strings.TrimSpace(actor), Deadline: time.Now().Add(2 * time.Minute)}
}
