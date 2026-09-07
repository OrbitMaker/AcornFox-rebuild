package main

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
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

type candidateAdapterInspector struct{ called bool }

func (i *candidateAdapterInspector) ContainerAbsent(_ context.Context, id string) (bool, string, error) {
	i.called = id == strings.Repeat("a", 64)
	return i.called, "candidate-absence:sha256:" + strings.Repeat("b", 64), nil
}

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
	inspector := &candidateAdapterInspector{}
	raw, err := newAcornFoxCandidateRuntimeAdapter(driver, prober, inspector)
	if err != nil {
		t.Fatal(err)
	}
	adapter := raw.(*acornFoxCandidateRuntimeAdapter)
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
	if err := adapter.Destroy(context.Background(), spec); err != nil {
		t.Fatal(err)
	}
	absence, err := adapter.ConfirmAbsent(context.Background(), spec)
	if err != nil || !driver.destroyed || !inspector.called || !absence.Absent {
		t.Fatalf("absence=%+v destroyed=%v inspected=%v err=%v", absence, driver.destroyed, inspector.called, err)
	}
}
