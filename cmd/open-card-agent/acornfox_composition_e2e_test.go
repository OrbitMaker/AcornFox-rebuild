package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/application"
	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/providers/standalone"
)

func TestComposeAcornFoxRuntimeRecoversPendingAbsentAndReplaysOriginalDeploy(t *testing.T) {
	fact := testAcornFoxFact()
	deploymentID, err := contracts.AcornFoxRuntimeDeploymentID(fact)
	if err != nil {
		t.Fatal(err)
	}
	runner := newCompositionRunner(fact, deploymentID)
	runner.failNextRun = true
	capacity := &compositionCapacity{port: 39124}
	root := t.TempDir()
	first := newCompositionStandalone(t, root, runner, capacity)
	firstRuntime, err := application.NewAcornFoxRuntimeService(first)
	if err != nil {
		t.Fatal(err)
	}
	request := contracts.AcornFoxRuntimeDeployRequest{Fact: fact, IdempotencyKey: "acornfox-recover-original"}
	if _, err := firstRuntime.Deploy(context.Background(), request); err == nil {
		t.Fatal("interrupted first deployment unexpectedly succeeded")
	}
	baselineReserve, baselineRuns := capacity.reserves(), runner.runCount()
	if baselineReserve != 1 || baselineRuns != 1 {
		t.Fatalf("first failed deployment did not create the expected durable pending state: reserve=%d run=%d", baselineReserve, baselineRuns)
	}

	fresh := newCompositionStandalone(t, root, runner, capacity)
	legacy, recovered, capabilities, err := composeAcornFoxRuntime(context.Background(), fresh)
	if err != nil || legacy != fresh || recovered == nil || !compositionHasCapability(capabilities, "acornfox.runtime.v1") {
		t.Fatalf("fresh AcornFox composition did not reconcile/advertise: legacy=%#v runtime=%#v capabilities=%v err=%v", legacy, recovered, capabilities, err)
	}
	deployed, err := recovered.Deploy(context.Background(), request)
	if err != nil || deployed.DeploymentID != deploymentID {
		t.Fatalf("original deploy caller key did not recover safely: deployment=%#v err=%v", deployed, err)
	}
	if got := capacity.reserves() - baselineReserve; got != 1 {
		t.Fatalf("recovery replay reserve delta=%d, want 1", got)
	}
	if got := runner.runCount() - baselineRuns; got != 1 {
		t.Fatalf("recovery replay docker run delta=%d, want 1", got)
	}
	observation, err := recovered.Observe(context.Background(), contracts.AcornFoxRuntimeReference{Fact: fact})
	if err != nil || observation.RuntimeState != "running" || observation.InternalAddress != "127.0.0.1:39124" {
		t.Fatalf("recovered runtime observation did not stay objective and loopback-only: %#v err=%v", observation, err)
	}
}

func TestComposeAcornFoxRuntimeFailsClosedWhenDaemonCannotConfirmPendingAbsence(t *testing.T) {
	fact := testAcornFoxFact()
	deploymentID, err := contracts.AcornFoxRuntimeDeploymentID(fact)
	if err != nil {
		t.Fatal(err)
	}
	runner := newCompositionRunner(fact, deploymentID)
	runner.failNextRun = true
	capacity := &compositionCapacity{port: 39124}
	root := t.TempDir()
	first := newCompositionStandalone(t, root, runner, capacity)
	firstRuntime, err := application.NewAcornFoxRuntimeService(first)
	if err != nil {
		t.Fatal(err)
	}
	request := contracts.AcornFoxRuntimeDeployRequest{Fact: fact, IdempotencyKey: "acornfox-daemon-unavailable"}
	if _, err := firstRuntime.Deploy(context.Background(), request); err == nil {
		t.Fatal("interrupted first deployment unexpectedly succeeded")
	}
	baselineReserve, baselineRuns := capacity.reserves(), runner.runCount()
	runner.listUnavailable = true
	fresh := newCompositionStandalone(t, root, runner, capacity)
	if _, _, capabilities, err := composeAcornFoxRuntime(context.Background(), fresh); err == nil || len(capabilities) != 0 {
		t.Fatalf("daemon-unavailable pending state was advertised as runnable: capabilities=%v err=%v", capabilities, err)
	}
	if got := capacity.reserves() - baselineReserve; got != 0 {
		t.Fatalf("failed reconciliation reserved new capacity: delta=%d", got)
	}
	if got := runner.runCount() - baselineRuns; got != 0 {
		t.Fatalf("failed reconciliation started a new container: delta=%d", got)
	}
}

func newCompositionStandalone(t *testing.T, root string, runner *compositionRunner, capacity *compositionCapacity) *standalone.Provider {
	t.Helper()
	provider, err := standalone.New(standalone.Config{
		TaskPrefix:            "acornfox-e2e",
		WorkRoot:              root,
		Runner:                runner,
		Capacity:              capacity,
		ImageStore:            compositionImageStore{image: runner.fact.Image},
		Clock:                 func() time.Time { return time.Unix(1700000000, 0).UTC() },
		WorkerNetworkIsolated: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return provider
}

func compositionHasCapability(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

type compositionRunner struct {
	mu              sync.Mutex
	fact            contracts.AcornFoxRuntimeReleaseFact
	deploymentID    domain.ID
	failNextRun     bool
	listUnavailable bool
	created         bool
	networkCreated  bool
	calls           [][]string
}

func newCompositionRunner(fact contracts.AcornFoxRuntimeReleaseFact, deploymentID domain.ID) *compositionRunner {
	return &compositionRunner{fact: fact, deploymentID: deploymentID}
}

func (r *compositionRunner) Run(_ context.Context, command string, args []string, stdout, _ io.Writer) error {
	if command != "docker" {
		return fmt.Errorf("unexpected command %q", command)
	}
	r.mu.Lock()
	r.calls = append(r.calls, append([]string(nil), args...))
	created, networkCreated := r.created, r.networkCreated
	r.mu.Unlock()
	switch strings.Join(args[:compositionMin(2, len(args))], " ") {
	case "container inspect":
		if !created {
			return errors.New("container not found")
		}
		payload, err := r.inspectPayload()
		if err != nil {
			return err
		}
		_, _ = io.WriteString(stdout, payload)
	case "container ls":
		r.mu.Lock()
		unavailable := r.listUnavailable
		r.mu.Unlock()
		if unavailable {
			return errors.New("daemon list unavailable")
		}
	case "load --input":
		return nil
	case "image inspect":
		_, _ = io.WriteString(stdout, r.fact.Image.Digest+`|{"Volumes":null}`)
	case "network inspect":
		if !networkCreated {
			return errors.New("network not found")
		}
		_, _ = io.WriteString(stdout, "true|acornfox-e2e")
	case "network create":
		r.mu.Lock()
		r.networkCreated = true
		r.mu.Unlock()
	case "run --detach":
		r.mu.Lock()
		if r.failNextRun {
			r.failNextRun = false
			r.mu.Unlock()
			return errors.New("interrupted before Docker run completion")
		}
		r.created = true
		r.mu.Unlock()
	}
	return nil
}

func (r *compositionRunner) runCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	count := 0
	for _, call := range r.calls {
		if len(call) > 0 && call[0] == "run" {
			count++
		}
	}
	return count
}

func (r *compositionRunner) inspectPayload() (string, error) {
	r.mu.Lock()
	var runArgs []string
	for index := len(r.calls) - 1; index >= 0; index-- {
		if len(r.calls[index]) > 0 && r.calls[index][0] == "run" {
			runArgs = append([]string(nil), r.calls[index]...)
			break
		}
	}
	r.mu.Unlock()
	if len(runArgs) == 0 {
		return "", errors.New("container inspect preceded Docker run")
	}
	labels := map[string]string{}
	value := func(flag string) string {
		for index := 0; index+1 < len(runArgs); index++ {
			if runArgs[index] == flag {
				return runArgs[index+1]
			}
		}
		return ""
	}
	for index := 0; index+1 < len(runArgs); index++ {
		if runArgs[index] != "--label" {
			continue
		}
		parts := strings.SplitN(runArgs[index+1], "=", 2)
		if len(parts) == 2 {
			labels[parts[0]] = parts[1]
		}
	}
	memory, memoryErr := strconv.ParseInt(value("--memory"), 10, 64)
	memorySwap, memorySwapErr := strconv.ParseInt(value("--memory-swap"), 10, 64)
	cpuQuota, cpuQuotaErr := strconv.ParseInt(value("--cpu-quota"), 10, 64)
	pids, pidsErr := strconv.ParseInt(value("--pids-limit"), 10, 64)
	if memoryErr != nil || memorySwapErr != nil || cpuQuotaErr != nil || pidsErr != nil {
		return "", errors.New("Docker run arguments are incomplete")
	}
	publish := strings.Split(value("--publish"), ":")
	if len(publish) != 3 {
		return "", errors.New("Docker run loopback publish is absent")
	}
	escape := func(value string) string {
		encoded, _ := json.Marshal(value)
		return string(encoded)
	}
	return fmt.Sprintf(`{"Id":"abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd","RestartCount":0,"Image":%s,"Config":{"Labels":{"open-card.managed":%s,"open-card.task-prefix":%s,"open-card.deployment-id":%s,"open-card.application-id":%s,"open-card.environment-id":%s,"open-card.release-id":%s,"open-card.service":%s,"open-card.image-repository":%s,"open-card.image-digest":%s},"Volumes":null},"State":{"Running":true},"HostConfig":{"NetworkMode":%s,"Privileged":false,"Binds":null,"CapAdd":null,"CapDrop":["ALL"],"Memory":%d,"MemorySwap":%d,"CpuPeriod":100000,"CpuQuota":%d,"PidsLimit":%d,"SecurityOpt":["no-new-privileges=true"],"RestartPolicy":{"Name":"no"},"PortBindings":{%s:[{"HostIp":%s,"HostPort":%s}]}}}`,
		escape(runArgs[len(runArgs)-1]), escape(labels["open-card.managed"]), escape(labels["open-card.task-prefix"]), escape(labels["open-card.deployment-id"]), escape(labels["open-card.application-id"]), escape(labels["open-card.environment-id"]), escape(labels["open-card.release-id"]), escape(labels["open-card.service"]), escape(labels["open-card.image-repository"]), escape(labels["open-card.image-digest"]), escape(value("--network")), memory, memorySwap, cpuQuota, pids, escape(publish[2]), escape(publish[0]), escape(publish[1])), nil
}

func compositionMin(left, right int) int {
	if left < right {
		return left
	}
	return right
}

type compositionImageStore struct{ image domain.ImageDigest }

func (compositionImageStore) Metadata(context.Context) contracts.ProviderMetadata {
	return contracts.ProviderMetadata{Name: "composition-image-store", Version: "test", ContractVersion: contracts.ContractAPIVersion, Capabilities: contracts.NewCapabilitySet(contracts.CapabilityImageResolve)}
}
func (compositionImageStore) Resolve(context.Context, contracts.ImageResolveRequest) (contracts.ImageResolveResult, error) {
	return contracts.ImageResolveResult{}, errors.New("not implemented")
}
func (compositionImageStore) Pull(context.Context, domain.ImageDigest, contracts.OperationContext) (contracts.Evidence, error) {
	return contracts.Evidence{}, errors.New("not implemented")
}
func (compositionImageStore) Retain(context.Context, domain.ImageDigest, contracts.OperationContext) error {
	return errors.New("not implemented")
}
func (compositionImageStore) Delete(context.Context, domain.ImageDigest, contracts.OperationContext) error {
	return errors.New("not implemented")
}
func (compositionImageStore) StoreOCI(context.Context, contracts.StoreOCIRequest) (contracts.StoreOCIResult, error) {
	return contracts.StoreOCIResult{}, errors.New("not implemented")
}
func (s compositionImageStore) OpenOCI(context.Context, domain.ImageDigest, contracts.OperationContext) (io.ReadCloser, contracts.StoreOCIResult, error) {
	return io.NopCloser(strings.NewReader("composition immutable OCI")), contracts.StoreOCIResult{Image: s.image, StorageRef: "oci://composition/immutable", SizeBytes: int64(len("composition immutable OCI"))}, nil
}

type compositionCapacity struct {
	mu           sync.Mutex
	port         int
	reserveCount int
}

func (c *compositionCapacity) Metadata(context.Context) contracts.ProviderMetadata {
	return contracts.ProviderMetadata{Name: "composition-capacity", Version: "test", ContractVersion: contracts.ContractAPIVersion, Capabilities: contracts.NewCapabilitySet(contracts.CapabilityCapacityCheck, contracts.CapabilityCapacityReserve)}
}
func (c *compositionCapacity) Preflight(_ context.Context, request contracts.CapacityRequest) (contracts.CapacitySnapshot, contracts.Evidence, error) {
	return contracts.CapacitySnapshot{Scope: request.Scope, AvailableCPUMillis: 8000, AvailableMemoryBytes: 8 << 30, AvailableDiskBytes: 8 << 30}, contracts.Evidence{Redacted: true}, nil
}
func (c *compositionCapacity) Reserve(_ context.Context, request contracts.CapacityRequest) (contracts.CapacityLease, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reserveCount++
	port := 0
	if request.HostPorts > 0 {
		port = c.port
	}
	return contracts.CapacityLease{ID: fmt.Sprintf("lease_%d", c.reserveCount), Scope: request.Scope, Resources: request.Resources, HostPort: port, ExpiresAt: time.Now().Add(time.Minute)}, nil
}
func (*compositionCapacity) Activate(context.Context, contracts.CapacityLease, contracts.OperationContext) error {
	return nil
}
func (*compositionCapacity) Release(context.Context, contracts.CapacityLease, contracts.OperationContext) error {
	return nil
}
func (c *compositionCapacity) ReconcileActive(context.Context, contracts.CapacityLease, contracts.OperationContext) error {
	return nil
}
func (c *compositionCapacity) reserves() int { c.mu.Lock(); defer c.mu.Unlock(); return c.reserveCount }
