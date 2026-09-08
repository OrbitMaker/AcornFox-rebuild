package main

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
	acornfoxprobe "github.com/open-card/open-card/internal/probe"
)

type candidateAdapterDriver struct {
	contracts.RuntimeDriver
	port      int
	deployed  contracts.DeployRequest
	destroyed bool
}

func (d *candidateAdapterDriver) Deploy(_ context.Context, request contracts.DeployRequest) (domain.Deployment, error) {
	d.deployed = request
	return domain.Deployment{ID: request.DeploymentID}, nil
}
func (d *candidateAdapterDriver) Observe(_ context.Context, request contracts.ObserveRequest) (contracts.RuntimeObservation, error) {
	return contracts.RuntimeObservation{DeploymentID: request.DeploymentID, ServiceName: "web", ContainerID: strings.Repeat("a", 64), Status: "running", Healthy: true, HostPort: d.port, Limits: d.deployed.Spec.Resources, CgroupVerified: true, ObservedAt: time.Unix(2, 0).UTC()}, nil
}
func (d *candidateAdapterDriver) Destroy(context.Context, contracts.DestroyRequest) error {
	d.destroyed = true
	return nil
}

type candidateAdapterInspector struct {
	called       bool
	endpoint     string
	nextEndpoint string
	networkID    string
	nextNetwork  string
	endpointCall int
}

func (i *candidateAdapterInspector) ContainerEndpoint(_ context.Context, expected acornFoxCandidateContainerExpectation) (acornFoxCandidateContainerBinding, error) {
	if expected.ContainerID != strings.Repeat("a", 64) || expected.HostPort < 1 {
		return acornFoxCandidateContainerBinding{}, context.Canceled
	}
	i.endpointCall++
	if i.endpointCall > 1 && i.nextEndpoint != "" {
		return acornFoxCandidateContainerBinding{Address: i.nextEndpoint, NetworkID: i.nextNetwork}, nil
	}
	return acornFoxCandidateContainerBinding{Address: i.endpoint, NetworkID: i.networkID}, nil
}

func (i *candidateAdapterInspector) ContainerAbsent(_ context.Context, id string) (bool, string, error) {
	i.called = id == strings.Repeat("a", 64)
	return i.called, "candidate-absence:sha256:" + strings.Repeat("b", 64), nil
}

type candidatePassthroughRelay struct{ address string }

func (r *candidatePassthroughRelay) Address() string { return r.address }
func (r *candidatePassthroughRelay) Close() error    { return nil }

func TestCandidateRuntimeAdapterUsesIsolatedIdentityProbeAndIndependentAbsence(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer server.Close()
	_, rawPort, err := net.SplitHostPort(strings.TrimPrefix(server.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(rawPort)
	driver := &candidateAdapterDriver{RuntimeDriver: contracts.NewFakeRuntimeDriver(true), port: port}
	prober, err := acornfoxprobe.New(acornfoxprobe.DefaultConfig(), func() time.Time { return time.Unix(3, 0).UTC() })
	if err != nil {
		t.Fatal(err)
	}
	inspector := &candidateAdapterInspector{endpoint: "172.18.0.2:8080", networkID: strings.Repeat("b", 64)}
	raw, err := newAcornFoxCandidateRuntimeAdapter(driver, prober, inspector)
	if err != nil {
		t.Fatal(err)
	}
	adapter := raw.(*acornFoxCandidateRuntimeAdapter)
	adapter.relay = func(context.Context, string) (acornFoxCandidateProbeRelay, error) {
		return &candidatePassthroughRelay{address: strings.TrimPrefix(server.URL, "http://")}, nil
	}
	spec := AcornFoxCandidateRuntimeSpec{CandidateID: "candidate_0123456789abcdef0123456789abcdef", ApplicationID: "app_candidate", Image: AcornFoxCandidateImage{Repository: "local/candidate", Digest: "sha256:" + strings.Repeat("c", 64)}, ContainerPort: 8080, Resources: AcornFoxCandidateRuntimeResources{CPUMillis: 500, MemoryBytes: 512 << 20, PIDs: 128, DiskReservationBytes: 1 << 30}}
	if err := adapter.Deploy(context.Background(), spec); err != nil {
		t.Fatal(err)
	}
	if driver.deployed.Spec.EnvironmentID.String()[:14] != "candidate_env_" || driver.deployed.Spec.ReleaseID.String()[:18] != "candidate_release_" || driver.deployed.Spec.Secrets != nil {
		t.Fatalf("runtime spec escaped candidate namespace: %+v", driver.deployed.Spec)
	}
	observation, err := adapter.Observe(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	probe, err := adapter.Probe(context.Background(), spec, observation)
	if err != nil || probe.Outcome != "responded" || probe.TargetClass != "loopback" {
		t.Fatalf("probe=%+v err=%v", probe, err)
	}
	if inspector.endpointCall != 2 {
		t.Fatalf("endpoint inspections=%d want 2", inspector.endpointCall)
	}
	if err := adapter.Destroy(context.Background(), spec); err != nil {
		t.Fatal(err)
	}
	absence, err := adapter.ConfirmAbsent(context.Background(), spec)
	if err != nil || !driver.destroyed || !inspector.called || !absence.Absent {
		t.Fatalf("absence=%+v destroyed=%v inspected=%v err=%v", absence, driver.destroyed, inspector.called, err)
	}
}

func TestCandidateRuntimeAdapterRejectsEndpointDriftDuringProbe(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer server.Close()
	_, rawPort, err := net.SplitHostPort(strings.TrimPrefix(server.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(rawPort)
	driver := &candidateAdapterDriver{RuntimeDriver: contracts.NewFakeRuntimeDriver(true), port: port}
	prober, err := acornfoxprobe.New(acornfoxprobe.DefaultConfig(), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	inspector := &candidateAdapterInspector{endpoint: "172.18.0.2:8080", networkID: strings.Repeat("b", 64), nextEndpoint: "172.18.0.2:8080", nextNetwork: strings.Repeat("d", 64)}
	raw, err := newAcornFoxCandidateRuntimeAdapter(driver, prober, inspector)
	if err != nil {
		t.Fatal(err)
	}
	adapter := raw.(*acornFoxCandidateRuntimeAdapter)
	adapter.relay = func(context.Context, string) (acornFoxCandidateProbeRelay, error) {
		return &candidatePassthroughRelay{address: strings.TrimPrefix(server.URL, "http://")}, nil
	}
	spec := candidateRuntimeSpec()
	if err := adapter.Deploy(context.Background(), spec); err != nil {
		t.Fatal(err)
	}
	observation, err := adapter.Observe(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	if probe, err := adapter.Probe(context.Background(), spec, observation); err == nil || probe.Outcome != "" {
		t.Fatalf("probe=%+v err=%v", probe, err)
	}
}

type candidateRoundTripFunc func(*http.Request) (*http.Response, error)

func (function candidateRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func TestCandidateContainerEndpointBindsExactInternalNetworkIdentity(t *testing.T) {
	spec := candidateRuntimeSpec()
	adapter := &acornFoxCandidateRuntimeAdapter{}
	fact, deployment, err := adapter.fact(spec)
	if err != nil {
		t.Fatal(err)
	}
	containerID := strings.Repeat("a", 64)
	networkID := strings.Repeat("b", 64)
	taskPrefix := "open-card-candidate"
	networkName := taskPrefix + "-network"
	wantLabels := map[string]string{
		"open-card.managed":          "true",
		"open-card.task-prefix":      taskPrefix,
		"open-card.deployment-id":    deployment.String(),
		"open-card.application-id":   fact.ApplicationID.String(),
		"open-card.environment-id":   fact.EnvironmentID.String(),
		"open-card.release-id":       fact.ReleaseID.String(),
		"open-card.service":          fact.ServiceName,
		"open-card.image-repository": fact.Image.Repository,
		"open-card.image-digest":     fact.Image.Digest,
	}
	container := map[string]any{
		"Id": containerID, "Image": fact.Image.Digest,
		"State":  map[string]any{"Running": true},
		"Config": map[string]any{"Labels": wantLabels, "Volumes": nil, "ExposedPorts": map[string]any{"8080/tcp": map[string]any{}}},
		"HostConfig": map[string]any{
			"NetworkMode": networkName, "Privileged": false, "Binds": nil, "CapAdd": nil, "CapDrop": []string{"ALL"},
			"Memory": fact.Resources.MemoryBytes, "MemorySwap": fact.Resources.MemoryBytes, "CpuPeriod": int64(100000), "CpuQuota": fact.Resources.CPUMillis * 100, "PidsLimit": fact.Resources.PIDs,
			"SecurityOpt": []string{"no-new-privileges=true"}, "RestartPolicy": map[string]string{"Name": "no"},
			"PortBindings": map[string]any{"8080/tcp": []map[string]string{{"HostIp": "127.0.0.1", "HostPort": "42373"}}},
		},
		"NetworkSettings": map[string]any{"Networks": map[string]any{networkName: map[string]any{"NetworkID": networkID, "IPAddress": "172.18.0.2"}}},
	}
	network := map[string]any{"Name": networkName, "Id": networkID, "Internal": true, "Labels": map[string]string{"open-card.managed": "true", "open-card.task-prefix": taskPrefix}}
	inspector := &unixAcornFoxCandidateContainerInspector{taskPrefix: taskPrefix, networkName: networkName}
	installCandidateDockerResponses(t, inspector, container, network)
	expectation := acornFoxCandidateContainerExpectation{ContainerID: containerID, Deployment: deployment, Fact: fact, HostPort: 42373}
	binding, err := inspector.ContainerEndpoint(context.Background(), expectation)
	if err != nil || binding.Address != "172.18.0.2:8080" || binding.NetworkID != networkID {
		t.Fatalf("binding=%+v err=%v", binding, err)
	}

	t.Run("identity drift has no private-network fallback", func(t *testing.T) {
		changed := cloneCandidateJSON(t, container)
		networks := changed["NetworkSettings"].(map[string]any)["Networks"].(map[string]any)
		networks["foreign-private-network"] = map[string]any{"NetworkID": strings.Repeat("d", 64), "IPAddress": "172.30.0.7"}
		changedInspector := &unixAcornFoxCandidateContainerInspector{taskPrefix: taskPrefix, networkName: networkName}
		installCandidateDockerResponses(t, changedInspector, changed, network)
		if binding, err := changedInspector.ContainerEndpoint(context.Background(), expectation); err == nil || binding != (acornFoxCandidateContainerBinding{}) {
			t.Fatalf("binding=%+v err=%v", binding, err)
		}
	})

	t.Run("network id drift is rejected", func(t *testing.T) {
		changed := cloneCandidateJSON(t, network)
		changed["Id"] = strings.Repeat("e", 64)
		changedInspector := &unixAcornFoxCandidateContainerInspector{taskPrefix: taskPrefix, networkName: networkName}
		installCandidateDockerResponses(t, changedInspector, container, changed)
		if binding, err := changedInspector.ContainerEndpoint(context.Background(), expectation); err == nil || binding != (acornFoxCandidateContainerBinding{}) {
			t.Fatalf("binding=%+v err=%v", binding, err)
		}
	})

	t.Run("abnormal address is rejected", func(t *testing.T) {
		changed := cloneCandidateJSON(t, container)
		networks := changed["NetworkSettings"].(map[string]any)["Networks"].(map[string]any)
		networks[networkName].(map[string]any)["IPAddress"] = "127.0.0.2"
		changedInspector := &unixAcornFoxCandidateContainerInspector{taskPrefix: taskPrefix, networkName: networkName}
		installCandidateDockerResponses(t, changedInspector, changed, network)
		if binding, err := changedInspector.ContainerEndpoint(context.Background(), expectation); err == nil || binding != (acornFoxCandidateContainerBinding{}) {
			t.Fatalf("binding=%+v err=%v", binding, err)
		}
	})

	securityDrifts := map[string]func(map[string]any){
		"privileged": func(host map[string]any) { host["Privileged"] = true },
		"bind":       func(host map[string]any) { host["Binds"] = []string{"/host:/host"} },
		"cap add":    func(host map[string]any) { host["CapAdd"] = []string{"NET_ADMIN"} },
		"cap drop":   func(host map[string]any) { host["CapDrop"] = []string{"CHOWN"} },
		"security":   func(host map[string]any) { host["SecurityOpt"] = nil },
		"restart":    func(host map[string]any) { host["RestartPolicy"] = map[string]string{"Name": "always"} },
		"memory":     func(host map[string]any) { host["Memory"] = float64(fact.Resources.MemoryBytes + 1) },
		"swap":       func(host map[string]any) { host["MemorySwap"] = float64(fact.Resources.MemoryBytes + 1) },
		"cpu":        func(host map[string]any) { host["CpuQuota"] = float64(fact.Resources.CPUMillis*100 + 1) },
		"pids":       func(host map[string]any) { host["PidsLimit"] = float64(fact.Resources.PIDs + 1) },
	}
	for name, mutate := range securityDrifts {
		t.Run("runtime security drift "+name, func(t *testing.T) {
			changed := cloneCandidateJSON(t, container)
			mutate(changed["HostConfig"].(map[string]any))
			changedInspector := &unixAcornFoxCandidateContainerInspector{taskPrefix: taskPrefix, networkName: networkName}
			installCandidateDockerResponses(t, changedInspector, changed, network)
			if binding, err := changedInspector.ContainerEndpoint(context.Background(), expectation); err == nil || binding != (acornFoxCandidateContainerBinding{}) {
				t.Fatalf("binding=%+v err=%v", binding, err)
			}
		})
	}
}

func TestCandidateLoopbackRelayUsesSharedProberAndClosesListener(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer upstream.Close()
	dial := func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, strings.TrimPrefix(upstream.URL, "http://"))
	}
	relay, err := newAcornFoxCandidateLoopbackRelayWithDial(context.Background(), "172.18.0.2:8080", dial)
	if err != nil {
		t.Fatal(err)
	}
	spec := candidateRuntimeSpec()
	adapter := &acornFoxCandidateRuntimeAdapter{}
	fact, deployment, err := adapter.fact(spec)
	if err != nil {
		t.Fatal(err)
	}
	request, err := contracts.NewAcornFoxProbeRequest(contracts.AcornFoxRuntimeReference{Fact: fact}, contracts.AcornFoxProbeProtocolHTTP, "/", "candidate-runtime-probe")
	if err != nil {
		t.Fatal(err)
	}
	prober, err := acornfoxprobe.New(acornfoxprobe.DefaultConfig(), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	result, err := prober.Probe(context.Background(), request, contracts.AcornFoxRuntimeObservation{DeploymentID: deployment, ServiceName: fact.ServiceName, RuntimeState: "running", InternalAddress: relay.Address(), ObservedAt: time.Now().UTC()})
	if err != nil || result.Outcome != contracts.AcornFoxProbeOutcomeResponded {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	address := relay.Address()
	if err := relay.Close(); err != nil {
		t.Fatal(err)
	}
	connection, err := net.DialTimeout("tcp4", address, 100*time.Millisecond)
	if err == nil {
		connection.Close()
		t.Fatal("relay listener remained reachable after probe")
	}
}

func TestCandidateLoopbackRelayCancellationClosesAcceptedConnections(t *testing.T) {
	upstream, peer := net.Pipe()
	defer peer.Close()
	dialed := make(chan struct{})
	var once sync.Once
	relay, err := newAcornFoxCandidateLoopbackRelayWithDial(context.Background(), "172.18.0.2:8080", func(context.Context, string, string) (net.Conn, error) {
		once.Do(func() { close(dialed) })
		return upstream, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	address := relay.Address()
	downstream, err := net.Dial("tcp4", address)
	if err != nil {
		t.Fatal(err)
	}
	defer downstream.Close()
	select {
	case <-dialed:
	case <-time.After(time.Second):
		t.Fatal("relay did not accept the connection")
	}
	closed := make(chan error, 1)
	go func() { closed <- relay.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("relay cleanup did not close active connections")
	}
	_ = peer.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if _, err := peer.Read(make([]byte, 1)); err == nil {
		t.Fatal("upstream connection remained active after relay cleanup")
	}
	connection, err := net.DialTimeout("tcp4", address, 100*time.Millisecond)
	if err == nil {
		connection.Close()
		t.Fatal("relay listener remained reachable after cancellation")
	}
}

func candidateRuntimeSpec() AcornFoxCandidateRuntimeSpec {
	return AcornFoxCandidateRuntimeSpec{CandidateID: "candidate_0123456789abcdef0123456789abcdef", ApplicationID: "app_candidate", Image: AcornFoxCandidateImage{Repository: "local/candidate", Digest: "sha256:" + strings.Repeat("c", 64)}, ContainerPort: 8080, Resources: AcornFoxCandidateRuntimeResources{CPUMillis: 500, MemoryBytes: 512 << 20, PIDs: 128, DiskReservationBytes: 1 << 30}}
}

func cloneCandidateJSON(t *testing.T, source map[string]any) map[string]any {
	t.Helper()
	encoded, err := json.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	var clone map[string]any
	if err := json.Unmarshal(encoded, &clone); err != nil {
		t.Fatal(err)
	}
	return clone
}

func installCandidateDockerResponses(t *testing.T, inspector *unixAcornFoxCandidateContainerInspector, container, network map[string]any) {
	t.Helper()
	containerJSON, err := json.Marshal(container)
	if err != nil {
		t.Fatal(err)
	}
	networkJSON, err := json.Marshal(network)
	if err != nil {
		t.Fatal(err)
	}
	inspector.client = &http.Client{Transport: candidateRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		body := containerJSON
		if strings.HasPrefix(request.URL.Path, "/networks/") {
			body = networkJSON
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(body)))}, nil
	})}
}
