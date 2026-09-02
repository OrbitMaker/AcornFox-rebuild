// Package probe implements the narrow standalone AcornFox loopback probe.
// It has no Agent, database, DNS, TLS, proxy, or public-network dependency.
package probe

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"syscall"
	"time"

	"github.com/open-card/open-card/internal/contracts"
)

const (
	maxTimeout       = time.Minute
	maxResponseBytes = int64(1 << 20)
)

// Config is process-owned configuration. Probe requests cannot override these
// limits or introduce a target, timeout, proxy, or other network setting.
type Config struct {
	HTTPTimeout      time.Duration
	TCPTimeout       time.Duration
	MaxResponseBytes int64
}

func DefaultConfig() Config {
	return Config{HTTPTimeout: 5 * time.Second, TCPTimeout: 3 * time.Second, MaxResponseBytes: 64 << 10}
}

func (config Config) Validate() error {
	if config.HTTPTimeout <= 0 || config.HTTPTimeout > maxTimeout || config.TCPTimeout <= 0 || config.TCPTimeout > maxTimeout || config.MaxResponseBytes <= 0 || config.MaxResponseBytes > maxResponseBytes {
		return fmt.Errorf("probe configuration is invalid")
	}
	return nil
}

// LoopbackTarget is derived only after the runtime observer has provided a
// matching current observation. Its address must be canonical IPv4 loopback.
type LoopbackTarget struct {
	Address    string
	Applicable bool
}

// DeriveLoopbackTarget rejects every address except exactly 127.0.0.1:port.
// A missing runtime port is a successful not-applicable condition, not a dial.
func DeriveLoopbackTarget(request contracts.AcornFoxProbeRequest, observation contracts.AcornFoxRuntimeObservation) (LoopbackTarget, error) {
	if err := request.Validate(); err != nil {
		return LoopbackTarget{}, err
	}
	deploymentID, err := contracts.AcornFoxRuntimeDeploymentID(request.Reference.Fact)
	if err != nil || observation.DeploymentID != deploymentID || observation.ServiceName != request.Reference.Fact.ServiceName {
		return LoopbackTarget{}, fmt.Errorf("runtime observation does not match probe reference")
	}
	if request.Reference.Fact.ContainerPort == 0 {
		if observation.InternalAddress != "" {
			return LoopbackTarget{}, fmt.Errorf("runtime observation unexpectedly exposes a loopback address")
		}
		return LoopbackTarget{}, nil
	}
	if observation.InternalAddress == "" {
		return LoopbackTarget{}, fmt.Errorf("runtime observation is missing its loopback address")
	}
	host, rawPort, err := net.SplitHostPort(observation.InternalAddress)
	if err != nil || host != "127.0.0.1" || rawPort == "" {
		return LoopbackTarget{}, fmt.Errorf("runtime observation loopback address is invalid")
	}
	port, err := strconv.Atoi(rawPort)
	if err != nil {
		return LoopbackTarget{}, fmt.Errorf("runtime observation loopback address is invalid")
	}
	canonical, err := contracts.AcornFoxRuntimeLoopbackAddress(port)
	if err != nil || canonical != observation.InternalAddress {
		return LoopbackTarget{}, fmt.Errorf("runtime observation loopback address is invalid")
	}
	return LoopbackTarget{Address: canonical, Applicable: true}, nil
}

// Prober performs one bounded local observation. It deliberately returns an
// outcome fact for transport failures so callers never persist raw errors.
type Prober struct {
	config      Config
	now         func() time.Time
	dialContext func(context.Context, string, string) (net.Conn, error)
}

func New(config Config, now func() time.Time) (*Prober, error) {
	if err := config.Validate(); err != nil || now == nil {
		return nil, fmt.Errorf("probe dependencies are invalid")
	}
	return &Prober{config: config, now: now, dialContext: (&net.Dialer{}).DialContext}, nil
}

func (prober *Prober) Probe(ctx context.Context, request contracts.AcornFoxProbeRequest, observation contracts.AcornFoxRuntimeObservation) (contracts.AcornFoxProbeResult, error) {
	if prober == nil || prober.now == nil || prober.dialContext == nil {
		return contracts.AcornFoxProbeResult{}, fmt.Errorf("probe is unavailable")
	}
	if ctx == nil {
		return contracts.AcornFoxProbeResult{}, fmt.Errorf("probe context is required")
	}
	target, err := DeriveLoopbackTarget(request, observation)
	if err != nil {
		return contracts.AcornFoxProbeResult{}, err
	}
	if !target.Applicable {
		return prober.result(request, observation, contracts.AcornFoxProbeOutcomeNotApplicable, nil, 0)
	}

	started := time.Now()
	var outcome contracts.AcornFoxProbeOutcome
	var status *int
	switch request.Protocol {
	case contracts.AcornFoxProbeProtocolHTTP:
		outcome, status = prober.http(ctx, target, request.HTTPPath)
	case contracts.AcornFoxProbeProtocolTCP:
		outcome = prober.tcp(ctx, target)
	default:
		return contracts.AcornFoxProbeResult{}, fmt.Errorf("probe protocol is invalid")
	}
	latency := time.Since(started).Milliseconds()
	if latency < 0 {
		latency = 0
	}
	if latency > 60_000 {
		latency = 60_000
	}
	return prober.result(request, observation, outcome, status, latency)
}

func (prober *Prober) http(ctx context.Context, target LoopbackTarget, httpPath string) (contracts.AcornFoxProbeOutcome, *int) {
	attempt, cancel := context.WithTimeout(ctx, prober.config.HTTPTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(attempt, http.MethodGet, "http://"+target.Address+httpPath, nil)
	if err != nil {
		return contracts.AcornFoxProbeOutcomeMalformedResponse, nil
	}
	transport := &http.Transport{
		Proxy:              nil,
		DialContext:        prober.dialContext,
		DisableCompression: true,
		ForceAttemptHTTP2:  false,
	}
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	response, err := client.Do(request)
	if err != nil {
		transport.CloseIdleConnections()
		return classify(ctx, attempt, err), nil
	}
	defer response.Body.Close()
	defer transport.CloseIdleConnections()
	if _, err := io.Copy(io.Discard, io.LimitReader(response.Body, prober.config.MaxResponseBytes)); err != nil {
		return classify(ctx, attempt, err), nil
	}
	status := response.StatusCode
	return contracts.AcornFoxProbeOutcomeResponded, &status
}

func (prober *Prober) tcp(ctx context.Context, target LoopbackTarget) contracts.AcornFoxProbeOutcome {
	attempt, cancel := context.WithTimeout(ctx, prober.config.TCPTimeout)
	defer cancel()
	connection, err := prober.dialContext(attempt, "tcp", target.Address)
	if err != nil {
		return classify(ctx, attempt, err)
	}
	_ = connection.Close()
	return contracts.AcornFoxProbeOutcomeResponded
}

func classify(parent, attempt context.Context, err error) contracts.AcornFoxProbeOutcome {
	if errors.Is(parent.Err(), context.Canceled) || errors.Is(err, context.Canceled) {
		return contracts.AcornFoxProbeOutcomeCancelled
	}
	if errors.Is(parent.Err(), context.DeadlineExceeded) || errors.Is(attempt.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
		return contracts.AcornFoxProbeOutcomeTimeout
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return contracts.AcornFoxProbeOutcomeRefused
	}
	// The bounded fact deliberately omits raw parser and transport details.
	// Every remaining failure is represented as malformed_response.
	return contracts.AcornFoxProbeOutcomeMalformedResponse
}

func (prober *Prober) result(request contracts.AcornFoxProbeRequest, observation contracts.AcornFoxRuntimeObservation, outcome contracts.AcornFoxProbeOutcome, status *int, latency int64) (contracts.AcornFoxProbeResult, error) {
	digest, err := contracts.AcornFoxProbeFactDigest(request, observation, outcome, status)
	if err != nil {
		return contracts.AcornFoxProbeResult{}, err
	}
	result := contracts.AcornFoxProbeResult{
		ApplicationID: request.Reference.Fact.ApplicationID,
		EnvironmentID: request.Reference.Fact.EnvironmentID,
		ReleaseID:     request.Reference.Fact.ReleaseID,
		DeploymentID:  observation.DeploymentID,
		ServiceName:   observation.ServiceName,
		Protocol:      request.Protocol,
		TargetClass:   contracts.AcornFoxProbeTargetClassLoopback,
		Outcome:       outcome,
		HTTPStatus:    status,
		LatencyMS:     latency,
		ObservedAt:    prober.now().UTC(),
		FactDigest:    digest,
	}
	switch outcome {
	case contracts.AcornFoxProbeOutcomeTimeout:
		result.ErrorCode = contracts.AcornFoxProbeErrorTimeout
	case contracts.AcornFoxProbeOutcomeRefused:
		result.ErrorCode = contracts.AcornFoxProbeErrorConnectionRefused
	case contracts.AcornFoxProbeOutcomeMalformedResponse:
		result.ErrorCode = contracts.AcornFoxProbeErrorMalformedResponse
	case contracts.AcornFoxProbeOutcomeCancelled:
		result.ErrorCode = contracts.AcornFoxProbeErrorCancelled
	}
	if err := result.Validate(); err != nil {
		return contracts.AcornFoxProbeResult{}, err
	}
	return result, nil
}
