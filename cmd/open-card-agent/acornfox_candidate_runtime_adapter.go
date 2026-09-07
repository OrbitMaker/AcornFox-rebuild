package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
	acornfoxprobe "github.com/open-card/open-card/internal/probe"
)

type acornFoxCandidateContainerInspector interface {
	ContainerAbsent(context.Context, string) (bool, string, error)
}

type acornFoxCandidateRuntimeAdapter struct {
	driver    contracts.RuntimeDriver
	prober    *acornfoxprobe.Prober
	inspector acornFoxCandidateContainerInspector
	clock     func() time.Time
	mu        sync.Mutex
	observed  map[string]AcornFoxCandidateRuntimeObservation
}

func newAcornFoxCandidateRuntimeAdapter(driver contracts.RuntimeDriver, prober *acornfoxprobe.Prober, inspector acornFoxCandidateContainerInspector) (AcornFoxCandidateRuntime, error) {
	if driver == nil || prober == nil || inspector == nil {
		return nil, errors.New("candidate runtime dependencies are unavailable")
	}
	return &acornFoxCandidateRuntimeAdapter{driver: driver, prober: prober, inspector: inspector, clock: time.Now, observed: make(map[string]AcornFoxCandidateRuntimeObservation)}, nil
}

func (a *acornFoxCandidateRuntimeAdapter) Deploy(ctx context.Context, spec AcornFoxCandidateRuntimeSpec) error {
	fact, deploymentID, err := a.fact(spec)
	if err != nil {
		return err
	}
	request := contracts.DeployRequest{DeploymentID: deploymentID, Spec: contracts.RuntimeSpec{ApplicationID: fact.ApplicationID, EnvironmentID: fact.EnvironmentID, ReleaseID: fact.ReleaseID, ServiceName: fact.ServiceName, Image: fact.Image, Resources: contracts.ResourceLimits{CPUMillis: fact.Resources.CPUMillis, MemoryBytes: fact.Resources.MemoryBytes, DiskBytes: fact.Resources.DiskReservationBytes, PIDs: fact.Resources.PIDs}, Port: fact.ContainerPort}, Operation: a.operation(spec, "deploy")}
	_, err = a.driver.Deploy(ctx, request)
	return err
}

func (a *acornFoxCandidateRuntimeAdapter) Observe(ctx context.Context, spec AcornFoxCandidateRuntimeSpec) (AcornFoxCandidateRuntimeObservation, error) {
	fact, deploymentID, err := a.fact(spec)
	if err != nil {
		return AcornFoxCandidateRuntimeObservation{}, err
	}
	observed, err := a.driver.Observe(ctx, contracts.ObserveRequest{DeploymentID: deploymentID, Operation: a.operation(spec, "observe")})
	if err != nil {
		return AcornFoxCandidateRuntimeObservation{}, err
	}
	if observed.DeploymentID != deploymentID || observed.ServiceName != fact.ServiceName || (observed.Status != "running" && !observed.Healthy) || observed.ContainerID == "" || observed.HostPort < 1 || observed.Limits.CPUMillis != spec.Resources.CPUMillis || observed.Limits.MemoryBytes != spec.Resources.MemoryBytes || observed.Limits.PIDs != spec.Resources.PIDs || !observed.CgroupVerified {
		return AcornFoxCandidateRuntimeObservation{}, errors.New("candidate runtime observation does not match requested limits")
	}
	runtimeID, _ := AcornFoxCandidateRuntimeID(spec)
	value := AcornFoxCandidateRuntimeObservation{RuntimeID: runtimeID, ContainerID: observed.ContainerID, RuntimeState: "running", Image: spec.Image, HostPort: observed.HostPort, AppliedResources: spec.Resources, ObservedAt: observed.ObservedAt.UTC()}
	a.mu.Lock()
	a.observed[runtimeID] = value
	a.mu.Unlock()
	return value, nil
}

func (a *acornFoxCandidateRuntimeAdapter) Probe(ctx context.Context, spec AcornFoxCandidateRuntimeSpec, observation AcornFoxCandidateRuntimeObservation) (AcornFoxCandidateRuntimeProbe, error) {
	fact, deploymentID, err := a.fact(spec)
	if err != nil {
		return AcornFoxCandidateRuntimeProbe{}, err
	}
	request, err := contracts.NewAcornFoxProbeRequest(contracts.AcornFoxRuntimeReference{Fact: fact}, contracts.AcornFoxProbeProtocolHTTP, "/", a.operation(spec, "probe").IdempotencyKey)
	if err != nil {
		return AcornFoxCandidateRuntimeProbe{}, err
	}
	runtimeObservation := contracts.AcornFoxRuntimeObservation{DeploymentID: deploymentID, ServiceName: "web", RuntimeState: "running", InternalAddress: net.JoinHostPort("127.0.0.1", fmt.Sprint(observation.HostPort)), ObservedAt: observation.ObservedAt}
	result, err := a.prober.Probe(ctx, request, runtimeObservation)
	if err != nil || result.Outcome != contracts.AcornFoxProbeOutcomeResponded {
		return AcornFoxCandidateRuntimeProbe{}, errors.New("candidate runtime loopback probe did not respond")
	}
	return AcornFoxCandidateRuntimeProbe{RuntimeID: observation.RuntimeID, ContainerID: observation.ContainerID, TargetClass: "loopback", Outcome: string(result.Outcome), EvidenceRef: "candidate-probe:" + result.FactDigest, ObservedAt: result.ObservedAt.UTC()}, nil
}

func (a *acornFoxCandidateRuntimeAdapter) Destroy(ctx context.Context, spec AcornFoxCandidateRuntimeSpec) error {
	_, deploymentID, err := a.fact(spec)
	if err != nil {
		return err
	}
	return a.driver.Destroy(ctx, contracts.DestroyRequest{DeploymentID: deploymentID, PreserveVolumes: true, Operation: a.operation(spec, "destroy")})
}

func (a *acornFoxCandidateRuntimeAdapter) ConfirmAbsent(ctx context.Context, spec AcornFoxCandidateRuntimeSpec) (AcornFoxCandidateRuntimeAbsence, error) {
	runtimeID, err := AcornFoxCandidateRuntimeID(spec)
	if err != nil {
		return AcornFoxCandidateRuntimeAbsence{}, err
	}
	a.mu.Lock()
	observation, ok := a.observed[runtimeID]
	a.mu.Unlock()
	if !ok || observation.ContainerID == "" {
		return AcornFoxCandidateRuntimeAbsence{}, errors.New("candidate runtime identity was not observed")
	}
	absent, evidence, err := a.inspector.ContainerAbsent(ctx, observation.ContainerID)
	if err != nil || !absent || strings.TrimSpace(evidence) == "" {
		return AcornFoxCandidateRuntimeAbsence{}, errors.New("candidate container absence is not confirmed")
	}
	return AcornFoxCandidateRuntimeAbsence{RuntimeID: runtimeID, Absent: true, EvidenceRef: evidence, ObservedAt: a.now()}, nil
}

func (a *acornFoxCandidateRuntimeAdapter) fact(spec AcornFoxCandidateRuntimeSpec) (contracts.AcornFoxRuntimeReleaseFact, domain.ID, error) {
	runtimeID, err := AcornFoxCandidateRuntimeID(spec)
	if err != nil {
		return contracts.AcornFoxRuntimeReleaseFact{}, "", err
	}
	suffix := strings.TrimPrefix(runtimeID, "candidate_runtime_")
	image, err := domain.ParseImageDigest(spec.Image.Repository, spec.Image.Digest)
	if err != nil {
		return contracts.AcornFoxRuntimeReleaseFact{}, "", err
	}
	fact := contracts.AcornFoxRuntimeReleaseFact{ApplicationID: spec.ApplicationID, EnvironmentID: domain.ID("candidate_env_" + suffix[:24]), ReleaseID: domain.ID("candidate_release_" + suffix[:24]), ServiceName: "web", Image: image, Resources: contracts.AcornFoxRuntimeRequestedResources{CPUMillis: spec.Resources.CPUMillis, MemoryBytes: spec.Resources.MemoryBytes, PIDs: spec.Resources.PIDs, DiskReservationBytes: spec.Resources.DiskReservationBytes}, ContainerPort: spec.ContainerPort, AcceptedAt: time.Unix(1, 0).UTC(), Immutable: true}
	if err := fact.Validate(); err != nil {
		return contracts.AcornFoxRuntimeReleaseFact{}, "", err
	}
	deploymentID, err := contracts.AcornFoxRuntimeDeploymentID(fact)
	return fact, deploymentID, err
}

func (a *acornFoxCandidateRuntimeAdapter) operation(spec AcornFoxCandidateRuntimeSpec, action string) contracts.OperationContext {
	return contracts.OperationContext{IdempotencyKey: "candidate-runtime:" + spec.CandidateID.String() + ":" + action, Actor: "acornfox-candidate-runtime"}
}

func (a *acornFoxCandidateRuntimeAdapter) now() time.Time {
	if a.clock == nil {
		return time.Now().UTC()
	}
	return a.clock().UTC()
}

type unixAcornFoxCandidateContainerInspector struct{ client *http.Client }

func newUnixAcornFoxCandidateContainerInspector(socketPath string) (acornFoxCandidateContainerInspector, error) {
	if !strings.HasPrefix(socketPath, "/") {
		return nil, errors.New("candidate Docker socket is invalid")
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "unix", socketPath)
	}, DisableCompression: true}
	return &unixAcornFoxCandidateContainerInspector{client: &http.Client{Transport: transport, Timeout: 5 * time.Second}}, nil
}

func (i *unixAcornFoxCandidateContainerInspector) ContainerAbsent(ctx context.Context, containerID string) (bool, string, error) {
	if i == nil || i.client == nil || len(containerID) != 64 {
		return false, "", errors.New("candidate container identity is invalid")
	}
	for _, character := range containerID {
		if !(character >= '0' && character <= '9' || character >= 'a' && character <= 'f') {
			return false, "", errors.New("candidate container identity is invalid")
		}
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker/containers/"+containerID+"/json", nil)
	if err != nil {
		return false, "", err
	}
	response, err := i.client.Do(request)
	if err != nil {
		return false, "", err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNotFound {
		return false, "", nil
	}
	digest := sha256.Sum256([]byte("candidate-container-absent\x00" + containerID))
	return true, "candidate-absence:sha256:" + hex.EncodeToString(digest[:]), nil
}
