package standalone

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/open-card/open-card/internal/contracts"
)

// Unlike the legacy lifecycle fixture, this uses the Native application's
// actual NetworkProfile with both external callbacks nil, an approved empty
// runtime config and operative port/network readback. It is not a live engine.
func TestApplicationProfileLifecycleAndManagedNetworkDrift(t *testing.T) {
	ctx := context.Background()
	runner := &fakeRunner{}
	ports := &fixedPorts{port: 39130}
	cfg := testProvider(t, runner, ports).config
	cfg.Network = ""
	cfg.NetworkProfile = ApplicationLoopbackNetworkProfile
	provider, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if provider.config.WorkerNetworkIsolated || provider.config.ExistingNetworkValidator != nil || provider.config.RestoreActiveGuard != nil {
		t.Fatal("fixture did not use the production Native application profile")
	}
	request := testRequest("native-app-deploy")
	request.Spec.Configuration = &contracts.AcornFoxRuntimeConfiguration{}
	request.Spec.ConfigDigest, err = contracts.CanonicalAcornFoxRuntimeConfigDigest(*request.Spec.Configuration, contracts.AcornFoxRuntimeRequestedResources{CPUMillis: request.Spec.Resources.CPUMillis, MemoryBytes: request.Spec.Resources.MemoryBytes, DiskReservationBytes: request.Spec.Resources.DiskBytes, PIDs: request.Spec.Resources.PIDs}, request.Spec.Port)
	if err != nil {
		t.Fatal(err)
	}
	networkName := provider.config.Network
	networkID := strings.Repeat("e", 64)
	created, running, foreignNetwork := false, false, false
	startedAt := "2026-09-28T00:00:00Z"
	runner.run = func(args []string, stdout io.Writer) error {
		switch args[0] {
		case "network":
			if args[1] != "inspect" {
				return errors.New("fixture forbids network create/remove")
			}
			owner := cfg.TaskPrefix
			if foreignNetwork {
				owner = "foreign"
			}
			return json.NewEncoder(stdout).Encode([]map[string]any{{"Id": networkID, "Name": networkName, "Driver": "bridge", "Internal": false, "Labels": map[string]string{"open-card.managed": "true", "open-card.task-prefix": owner, "open-card.network-profile": ApplicationLoopbackNetworkProfile}, "Options": map[string]string{"com.docker.network.bridge.gateway_mode_ipv4": "nat"}}})
		case "run":
			created = true
			running = true
			return nil
		case "load":
			return nil
		case "image":
			_, err := io.WriteString(stdout, testDigest+`|{"Volumes":null}`)
			return err
		case "stop":
			if args[1] != testContainerID {
				t.Fatal("stop used adoptable name")
			}
			running = false
			return nil
		case "start":
			if args[1] != testContainerID {
				t.Fatal("start changed immutable CID")
			}
			running = true
			startedAt = "2026-09-28T00:00:01Z"
			return nil
		case "restart":
			if args[1] != testContainerID {
				t.Fatal("restart changed immutable CID")
			}
			running = true
			startedAt = "2026-09-28T00:00:02Z"
			return nil
		case "container":
			if args[1] == "ls" {
				if created {
					_, err := io.WriteString(stdout, testContainerID+"\n")
					return err
				}
				return nil
			}
			if args[1] != "inspect" || !created {
				return errors.New("container absent")
			}
			var facts map[string]any
			if err := json.Unmarshal([]byte(ownedContainerInspect(request, testDigest)), &facts); err != nil {
				return err
			}
			facts["Config"].(map[string]any)["Labels"].(map[string]any)["open-card.config-digest"] = request.Spec.ConfigDigest
			facts["HostConfig"].(map[string]any)["NetworkMode"] = networkName
			status := "exited"
			if running {
				status = "running"
			}
			facts["State"] = map[string]any{"Running": running, "Status": status, "StartedAt": startedAt}
			publications := map[string]any{}
			if running {
				publications["8080/tcp"] = []map[string]string{{"HostIp": "127.0.0.1", "HostPort": "39130"}}
			}
			facts["NetworkSettings"] = map[string]any{"Networks": map[string]any{networkName: map[string]string{"NetworkID": networkID}}, "Ports": publications}
			return json.NewEncoder(stdout).Encode(facts)
		default:
			return errors.New("unexpected engine command in Native fixture")
		}
	}
	if _, err := provider.Deploy(ctx, request); err != nil {
		t.Fatalf("Native deploy: %v", err)
	}
	if err := provider.Stop(ctx, contracts.StopRequest{DeploymentID: request.DeploymentID, ServiceName: "web", Operation: contracts.OperationContext{IdempotencyKey: "native-app-stop"}}); err != nil {
		t.Fatalf("Native stop: %v", err)
	}
	// A fresh role/provider must observe retained schema3 paused state without
	// requiring the callback this network profile deliberately forbids.
	fresh, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	observation, err := fresh.ObserveDeploymentSnapshot(ctx, contracts.ObserveRequest{DeploymentID: request.DeploymentID, Operation: contracts.OperationContext{IdempotencyKey: "native-app-paused-observe"}})
	if err != nil || observation.Observation.ContainerID != testContainerID || observation.Observation.Status != "paused" || observation.Observation.HostPort != 39130 {
		t.Fatalf("Native paused reload/readback: %+v %v", observation, err)
	}
	foreignNetwork = true
	beforeStarts := len(runner.callsFor("start"))
	start := contracts.StartRequest{DeploymentID: request.DeploymentID, ServiceName: "web", Operation: contracts.OperationContext{IdempotencyKey: "native-app-start"}}
	if err := fresh.Start(ctx, start); err == nil {
		t.Fatal("managed-network owner drift passed start")
	}
	if len(runner.callsFor("start")) != beforeStarts {
		t.Fatal("network drift reached Docker start")
	}
	foreignNetwork = false
	if err := fresh.Start(ctx, start); err != nil {
		t.Fatalf("Native start: %v", err)
	}
	reloaded, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	observation, err = reloaded.ObserveDeploymentSnapshot(ctx, contracts.ObserveRequest{DeploymentID: request.DeploymentID, Operation: contracts.OperationContext{IdempotencyKey: "native-app-running-observe"}})
	if err != nil || observation.Observation.Status != "running" || observation.Observation.ContainerID != testContainerID || observation.Observation.HostPort != 39130 {
		t.Fatalf("Native active schema3 reload: %+v %v", observation, err)
	}
	if err := reloaded.Restart(ctx, contracts.RestartRequest{DeploymentID: request.DeploymentID, ServiceName: "web", Operation: contracts.OperationContext{IdempotencyKey: "native-app-restart"}}); err != nil {
		t.Fatalf("Native restart: %v", err)
	}
	if len(runner.callsFor("stop")) != 1 || len(runner.callsFor("start")) != 1 || len(runner.callsFor("restart")) != 1 || ports.allocated != 1 || ports.released != 0 {
		t.Fatal("Native lifecycle recreated, repeated or released retained allocation")
	}
}
