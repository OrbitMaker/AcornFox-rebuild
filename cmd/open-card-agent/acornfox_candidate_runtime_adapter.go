package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
	acornfoxprobe "github.com/open-card/open-card/internal/probe"
)

type acornFoxCandidateContainerInspector interface {
	ContainerAbsent(context.Context, string) (bool, string, error)
	ContainerEndpoint(context.Context, acornFoxCandidateContainerExpectation) (acornFoxCandidateContainerBinding, error)
}

type acornFoxCandidateContainerExpectation struct {
	ContainerID string
	Deployment  domain.ID
	Fact        contracts.AcornFoxRuntimeReleaseFact
	HostPort    int
}

type acornFoxCandidateContainerBinding struct {
	Address   string
	NetworkID string
}

type acornFoxCandidateProbeRelay interface {
	Address() string
	Close() error
}

type acornFoxCandidateRelayFactory func(context.Context, string) (acornFoxCandidateProbeRelay, error)

type acornFoxCandidateRuntimeAdapter struct {
	driver    contracts.RuntimeDriver
	prober    *acornfoxprobe.Prober
	inspector acornFoxCandidateContainerInspector
	relay     acornFoxCandidateRelayFactory
	clock     func() time.Time
	mu        sync.Mutex
	observed  map[string]AcornFoxCandidateRuntimeObservation
}

func newAcornFoxCandidateRuntimeAdapter(driver contracts.RuntimeDriver, prober *acornfoxprobe.Prober, inspector acornFoxCandidateContainerInspector) (AcornFoxCandidateRuntime, error) {
	if driver == nil || prober == nil || inspector == nil {
		return nil, errors.New("candidate runtime dependencies are unavailable")
	}
	return &acornFoxCandidateRuntimeAdapter{driver: driver, prober: prober, inspector: inspector, relay: func(ctx context.Context, target string) (acornFoxCandidateProbeRelay, error) {
		return newAcornFoxCandidateLoopbackRelay(ctx, target)
	}, clock: time.Now, observed: make(map[string]AcornFoxCandidateRuntimeObservation)}, nil
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
	binding, err := a.inspector.ContainerEndpoint(ctx, acornFoxCandidateContainerExpectation{ContainerID: observation.ContainerID, Deployment: deploymentID, Fact: fact, HostPort: observation.HostPort})
	if err != nil {
		return AcornFoxCandidateRuntimeProbe{}, errors.New("candidate runtime endpoint is unavailable")
	}
	relay, err := a.relay(ctx, binding.Address)
	if err != nil {
		return AcornFoxCandidateRuntimeProbe{}, errors.New("candidate runtime loopback relay is unavailable")
	}
	runtimeObservation := contracts.AcornFoxRuntimeObservation{DeploymentID: deploymentID, ServiceName: "web", RuntimeState: "running", InternalAddress: relay.Address(), ObservedAt: observation.ObservedAt}
	result, err := a.prober.Probe(ctx, request, runtimeObservation)
	closeErr := relay.Close()
	if closeErr != nil {
		return AcornFoxCandidateRuntimeProbe{}, errors.New("candidate runtime loopback relay cleanup failed")
	}
	if err != nil || result.Outcome != contracts.AcornFoxProbeOutcomeResponded {
		return AcornFoxCandidateRuntimeProbe{}, errors.New("candidate runtime loopback probe did not respond")
	}
	confirmedBinding, err := a.inspector.ContainerEndpoint(ctx, acornFoxCandidateContainerExpectation{ContainerID: observation.ContainerID, Deployment: deploymentID, Fact: fact, HostPort: observation.HostPort})
	if err != nil || confirmedBinding != binding {
		return AcornFoxCandidateRuntimeProbe{}, errors.New("candidate runtime endpoint changed during probe")
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

type acornFoxCandidateLoopbackRelay struct {
	listener net.Listener
	target   string
	ctx      context.Context
	cancel   context.CancelFunc
	mu       sync.Mutex
	active   map[net.Conn]struct{}
	closing  bool
	wait     sync.WaitGroup
	once     sync.Once
	closeErr error
	dial     func(context.Context, string, string) (net.Conn, error)
}

func newAcornFoxCandidateLoopbackRelay(parent context.Context, target string) (*acornFoxCandidateLoopbackRelay, error) {
	return newAcornFoxCandidateLoopbackRelayWithDial(parent, target, (&net.Dialer{Timeout: 2 * time.Second}).DialContext)
}

func newAcornFoxCandidateLoopbackRelayWithDial(parent context.Context, target string, dial func(context.Context, string, string) (net.Conn, error)) (*acornFoxCandidateLoopbackRelay, error) {
	address, err := netip.ParseAddrPort(target)
	if parent == nil || dial == nil || err != nil || !address.Addr().Is4() || !address.Addr().IsPrivate() || address.Addr().IsLoopback() || address.Port() == 0 || address.String() != target {
		return nil, errors.New("candidate relay target is invalid")
	}
	listener, err := (&net.ListenConfig{}).Listen(parent, "tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(parent)
	relay := &acornFoxCandidateLoopbackRelay{listener: listener, target: target, ctx: ctx, cancel: cancel, active: make(map[net.Conn]struct{}), dial: dial}
	relay.wait.Add(1)
	go relay.accept()
	return relay, nil
}

func (r *acornFoxCandidateLoopbackRelay) Address() string {
	if r == nil || r.listener == nil {
		return ""
	}
	return r.listener.Addr().String()
}

func (r *acornFoxCandidateLoopbackRelay) accept() {
	defer r.wait.Done()
	for {
		connection, err := r.listener.Accept()
		if err != nil {
			return
		}
		if !r.track(connection, true) {
			_ = connection.Close()
			return
		}
		r.wait.Add(1)
		go r.forward(connection)
	}
}

func (r *acornFoxCandidateLoopbackRelay) forward(downstream net.Conn) {
	defer r.wait.Done()
	defer r.track(downstream, false)
	defer downstream.Close()
	upstream, err := r.dial(r.ctx, "tcp4", r.target)
	if err != nil {
		return
	}
	if !r.track(upstream, true) {
		_ = upstream.Close()
		return
	}
	defer r.track(upstream, false)
	defer upstream.Close()
	var copies sync.WaitGroup
	copies.Add(2)
	go func() { defer copies.Done(); _, _ = io.Copy(upstream, downstream) }()
	go func() { defer copies.Done(); _, _ = io.Copy(downstream, upstream) }()
	copies.Wait()
}

func (r *acornFoxCandidateLoopbackRelay) track(connection net.Conn, add bool) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if add {
		if r.closing {
			return false
		}
		r.active[connection] = struct{}{}
	} else {
		delete(r.active, connection)
	}
	return true
}

func (r *acornFoxCandidateLoopbackRelay) Close() error {
	if r == nil {
		return nil
	}
	r.once.Do(func() {
		r.cancel()
		if err := r.listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			r.closeErr = err
		}
		r.mu.Lock()
		r.closing = true
		for connection := range r.active {
			_ = connection.Close()
		}
		r.mu.Unlock()
		r.wait.Wait()
	})
	return r.closeErr
}

func candidateDockerName(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for index, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || index > 0 && (character == '_' || character == '.' || character == '-') {
			continue
		}
		return false
	}
	return true
}

func validCandidateContainerID(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range value {
		if !(character >= '0' && character <= '9' || character >= 'a' && character <= 'f') {
			return false
		}
	}
	return true
}

type unixAcornFoxCandidateContainerInspector struct {
	client      *http.Client
	taskPrefix  string
	networkName string
}

func newUnixAcornFoxCandidateContainerInspector(socketPath, taskPrefix, networkName string) (acornFoxCandidateContainerInspector, error) {
	if !strings.HasPrefix(socketPath, "/") || !candidateDockerName(taskPrefix) || networkName != taskPrefix+"-network" {
		return nil, errors.New("candidate Docker socket is invalid")
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "unix", socketPath)
	}, DisableCompression: true}
	return &unixAcornFoxCandidateContainerInspector{client: &http.Client{Transport: transport, Timeout: 5 * time.Second}, taskPrefix: taskPrefix, networkName: networkName}, nil
}

func (i *unixAcornFoxCandidateContainerInspector) ContainerEndpoint(ctx context.Context, expected acornFoxCandidateContainerExpectation) (acornFoxCandidateContainerBinding, error) {
	if i == nil || i.client == nil || !validCandidateContainerID(expected.ContainerID) || expected.Deployment.Empty() || expected.Fact.Validate() != nil || expected.HostPort < 1 || expected.HostPort > 65535 {
		return acornFoxCandidateContainerBinding{}, errors.New("candidate container endpoint expectation is invalid")
	}
	var container struct {
		ID    string `json:"Id"`
		Image string `json:"Image"`
		State struct {
			Running bool `json:"Running"`
		} `json:"State"`
		Config struct {
			Labels  map[string]string `json:"Labels"`
			Volumes map[string]any    `json:"Volumes"`
		} `json:"Config"`
		HostConfig struct {
			NetworkMode   string   `json:"NetworkMode"`
			Privileged    bool     `json:"Privileged"`
			Binds         []string `json:"Binds"`
			CapAdd        []string `json:"CapAdd"`
			CapDrop       []string `json:"CapDrop"`
			Memory        int64    `json:"Memory"`
			MemorySwap    int64    `json:"MemorySwap"`
			CPUPeriod     int64    `json:"CpuPeriod"`
			CPUQuota      int64    `json:"CpuQuota"`
			PIDsLimit     *int64   `json:"PidsLimit"`
			SecurityOpt   []string `json:"SecurityOpt"`
			RestartPolicy struct {
				Name string `json:"Name"`
			} `json:"RestartPolicy"`
			PortBindings map[string][]struct {
				HostIP   string `json:"HostIp"`
				HostPort string `json:"HostPort"`
			} `json:"PortBindings"`
		} `json:"HostConfig"`
		NetworkSettings struct {
			Networks map[string]struct {
				NetworkID string `json:"NetworkID"`
				IPAddress string `json:"IPAddress"`
			} `json:"Networks"`
		} `json:"NetworkSettings"`
	}
	if err := i.getDockerJSON(ctx, "/containers/"+expected.ContainerID+"/json", &container); err != nil {
		return acornFoxCandidateContainerBinding{}, err
	}
	var network struct {
		Name     string            `json:"Name"`
		ID       string            `json:"Id"`
		Internal bool              `json:"Internal"`
		Labels   map[string]string `json:"Labels"`
	}
	if err := i.getDockerJSON(ctx, "/networks/"+url.PathEscape(i.networkName), &network); err != nil {
		return acornFoxCandidateContainerBinding{}, err
	}
	portKey := fmt.Sprintf("%d/tcp", expected.Fact.ContainerPort)
	binding := container.HostConfig.PortBindings[portKey]
	attachment, attached := container.NetworkSettings.Networks[i.networkName]
	labels := container.Config.Labels
	secureRuntime := !container.HostConfig.Privileged && len(container.HostConfig.Binds) == 0 && len(container.HostConfig.CapAdd) == 0 && len(container.HostConfig.CapDrop) == 1 && container.HostConfig.CapDrop[0] == "ALL" && len(container.HostConfig.SecurityOpt) == 1 && container.HostConfig.SecurityOpt[0] == "no-new-privileges=true" && container.HostConfig.RestartPolicy.Name == "no" && container.HostConfig.Memory == expected.Fact.Resources.MemoryBytes && container.HostConfig.MemorySwap == expected.Fact.Resources.MemoryBytes && container.HostConfig.CPUPeriod == 100000 && container.HostConfig.CPUQuota == expected.Fact.Resources.CPUMillis*100 && container.HostConfig.PIDsLimit != nil && *container.HostConfig.PIDsLimit == expected.Fact.Resources.PIDs
	if container.ID != expected.ContainerID || container.Image != expected.Fact.Image.Digest || !container.State.Running || len(container.Config.Volumes) != 0 || !secureRuntime || container.HostConfig.NetworkMode != i.networkName || len(container.HostConfig.PortBindings) != 1 || len(binding) != 1 || binding[0].HostIP != "127.0.0.1" || binding[0].HostPort != fmt.Sprint(expected.HostPort) || len(container.NetworkSettings.Networks) != 1 || !attached || !validCandidateContainerID(network.ID) || attachment.NetworkID != network.ID || network.Name != i.networkName || !network.Internal || network.Labels["open-card.managed"] != "true" || network.Labels["open-card.task-prefix"] != i.taskPrefix {
		return acornFoxCandidateContainerBinding{}, errors.New("candidate container endpoint identity changed")
	}
	wantLabels := map[string]string{
		"open-card.managed":          "true",
		"open-card.task-prefix":      i.taskPrefix,
		"open-card.deployment-id":    expected.Deployment.String(),
		"open-card.application-id":   expected.Fact.ApplicationID.String(),
		"open-card.environment-id":   expected.Fact.EnvironmentID.String(),
		"open-card.release-id":       expected.Fact.ReleaseID.String(),
		"open-card.service":          expected.Fact.ServiceName,
		"open-card.image-repository": expected.Fact.Image.Repository,
		"open-card.image-digest":     expected.Fact.Image.Digest,
	}
	for key, value := range wantLabels {
		if labels[key] != value {
			return acornFoxCandidateContainerBinding{}, errors.New("candidate container endpoint labels changed")
		}
	}
	address, err := netip.ParseAddr(attachment.IPAddress)
	if err != nil || !address.Is4() || !address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsMulticast() || address.String() != attachment.IPAddress {
		return acornFoxCandidateContainerBinding{}, errors.New("candidate container endpoint address is invalid")
	}
	return acornFoxCandidateContainerBinding{Address: net.JoinHostPort(address.String(), fmt.Sprint(expected.Fact.ContainerPort)), NetworkID: network.ID}, nil
}

func (i *unixAcornFoxCandidateContainerInspector) getDockerJSON(ctx context.Context, path string, target any) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker"+path, nil)
	if err != nil {
		return err
	}
	response, err := i.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return errors.New("candidate Docker inspection failed")
	}
	encoded, err := io.ReadAll(io.LimitReader(response.Body, 1<<20+1))
	if err != nil || len(encoded) == 0 || len(encoded) > 1<<20 || json.Unmarshal(encoded, target) != nil {
		return errors.New("candidate Docker inspection response is invalid")
	}
	return nil
}

func (i *unixAcornFoxCandidateContainerInspector) ContainerAbsent(ctx context.Context, containerID string) (bool, string, error) {
	if i == nil || i.client == nil || !validCandidateContainerID(containerID) {
		return false, "", errors.New("candidate container identity is invalid")
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
