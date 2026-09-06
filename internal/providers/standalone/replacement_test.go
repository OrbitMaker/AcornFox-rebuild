package standalone

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/open-card/open-card/internal/contracts"
)

type replacementDocker struct {
	runner            *fakeRunner
	facts             *inspectFacts
	name              string
	serial            int
	hook              func(string)
	runError          bool
	runUnknown        bool
	createOnlyFailure bool
}

func newReplacementDocker(t *testing.T) *replacementDocker {
	t.Helper()
	d := &replacementDocker{}
	d.runner = &fakeRunner{run: func(args []string, out io.Writer) error {
		event := args[0]
		if len(args) > 1 && (event == "container" || event == "network" || event == "image") {
			event += " " + args[1]
		}
		if d.hook != nil {
			d.hook("before " + event)
		}
		switch event {
		case "container inspect":
			if d.facts == nil {
				return errors.New("absent")
			}
			raw, _ := json.Marshal(d.facts)
			_, _ = out.Write(raw)
		case "container ls":
			if d.facts != nil {
				_, _ = io.WriteString(out, "opencard-m1-runtime-owned")
			}
		case "network inspect":
			_, _ = io.WriteString(out, restoreNetworkFixture)
		case "image inspect":
			_, _ = io.WriteString(out, testDigest+`|{"Volumes":null}`)
		case "load":
			raw, err := os.ReadFile(args[2])
			if err != nil || string(raw) != "persistent OCI archive" {
				return errors.New("invalid staged archive")
			}
		case "rm":
			if d.facts == nil || len(args) != 3 || (args[2] != d.facts.ID && args[2] != d.name) {
				return fmt.Errorf("removal did not bind exact present ID: %v", args)
			}
			d.facts = nil
		case "run":
			if d.runError {
				return errors.New("temporary run failure")
			}
			if d.facts != nil {
				return errors.New("container name occupied")
			}
			d.serial++
			var facts inspectFacts
			if err := json.Unmarshal([]byte(ownedContainerInspect(testRequest("stable-recreate"), testDigest)), &facts); err != nil {
				t.Fatal(err)
			}
			facts.ID = fmt.Sprintf("%064x", d.serial+10)
			facts.State.Status = "running"
			setRestoreNetworkFixture(&facts)
			for i := 0; i+1 < len(args); i++ {
				switch args[i] {
				case "--name":
					d.name = args[i+1]
				case "--publish":
					parts := strings.Split(args[i+1], ":")
					facts.HostConfig.PortBindings["8080/tcp"][0].HostPort = parts[1]
				case "--label":
					key, value, ok := strings.Cut(args[i+1], "=")
					if ok {
						facts.Config.Labels[key] = value
					}
				}
			}
			if d.createOnlyFailure {
				facts.State.Running = false
				facts.State.Status = "created"
				a := facts.NetworkSettings.Networks["opencard-m1-network"]
				a.NetworkID = ""
				facts.NetworkSettings.Networks["opencard-m1-network"] = a
			}
			d.facts = &facts
			_, _ = io.WriteString(out, facts.ID+"\n")
			if d.runUnknown || d.createOnlyFailure {
				return errors.New("response lost after run")
			}
		default:
			return fmt.Errorf("unexpected Docker mutation %v", args)
		}
		if d.hook != nil {
			d.hook("after " + event)
		}
		return nil
	}}
	return d
}

func stableReplacementProvider(t *testing.T, root string, d *replacementDocker, ports *fixedPorts) *Provider {
	t.Helper()
	p := testProviderAt(t, root, d.runner, ports)
	p.config.RestoreActiveGuard = func(context.Context) error { return nil }
	p.config.ExistingNetworkValidator = func(raw []byte) error {
		if string(raw) != restoreNetworkFixture {
			return errors.New("network drift")
		}
		return nil
	}
	return p
}

func TestInstalledRecreatePreservesLeaseAndPublishedPort(t *testing.T) {
	root := t.TempDir()
	d := newReplacementDocker(t)
	ports := &fixedPorts{port: 39124}
	p := stableReplacementProvider(t, root, d, ports)
	request := testRequest("stable-first")
	deployment, err := p.Deploy(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	before := mustDurableSnapshot(t, p, deployment.ID)
	request.Operation.IdempotencyKey = "stable-recreate"
	if _, err := p.Recreate(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	after := mustDurableSnapshot(t, p, deployment.ID)
	if calls := d.runner.callsFor("rm"); len(calls) != 1 || calls[0][2] != before.ContainerID {
		t.Fatalf("replacement did not remove exact original ID: %v", calls)
	}
	if after.ContainerID == before.ContainerID || after.Phase != "active" || !reflect.DeepEqual(before.Capacity, after.Capacity) || ports.allocated != 1 || ports.released != 0 {
		t.Fatalf("replacement changed its reservation: before=%+v after=%+v allocated=%d released=%d", before.Capacity, after.Capacity, ports.allocated, ports.released)
	}
	fresh := stableReplacementProvider(t, root, d, ports)
	if err := fresh.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := fresh.Recreate(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if d.serial != 2 {
		t.Fatalf("same-key replay repeated replacement: %d", d.serial)
	}
	request.Operation.IdempotencyKey = "stable-next-recreate"
	if _, err := fresh.Recreate(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if d.serial != 3 || ports.allocated != 1 || ports.released != 0 {
		t.Fatal("next replacement changed reservation")
	}
}

func TestInstalledReplacementCrashBoundariesRetainOriginalLease(t *testing.T) {
	for _, boundary := range []string{"before load", "before rm", "after rm", "before run", "after run"} {
		t.Run(boundary, func(t *testing.T) {
			root := t.TempDir()
			d := newReplacementDocker(t)
			ports := &fixedPorts{port: 39124}
			p := stableReplacementProvider(t, root, d, ports)
			request := testRequest("crash-first")
			deployment, err := p.Deploy(context.Background(), request)
			if err != nil {
				t.Fatal(err)
			}
			before := mustDurableSnapshot(t, p, deployment.ID)
			request.Operation.IdempotencyKey = "crash-recreate"
			crashed := false
			d.hook = func(event string) {
				if event == boundary {
					crashed = true
					panic("controlled process death")
				}
			}
			func() {
				defer func() {
					if recover() == nil {
						t.Fatal("crash point not reached")
					}
				}()
				_, _ = p.Recreate(context.Background(), request)
			}()
			if !crashed {
				t.Fatal("crash point not reached")
			}
			d.hook = nil
			pending := mustDurableSnapshot(t, p, deployment.ID)
			if pending.Phase != "replacing" || !reflect.DeepEqual(before.Capacity, pending.Capacity) || ports.released != 0 {
				t.Fatal("crash dropped retained lease")
			}
			countBefore := len(d.runner.callsFor())
			fresh := stableReplacementProvider(t, root, d, ports)
			if err := fresh.Reconcile(context.Background()); err != nil {
				t.Fatal(err)
			}
			for _, args := range d.runner.callsFor()[countBefore:] {
				if args[0] == "run" || args[0] == "start" || args[0] == "rm" {
					t.Fatalf("reconciliation executed replacement: %v", args)
				}
			}
			if ports.released != 0 || ports.allocated != 1 {
				t.Fatal("reconcile changed capacity")
			}
			if _, err := fresh.Recreate(context.Background(), request); err != nil {
				t.Fatal(err)
			}
			after := mustDurableSnapshot(t, fresh, deployment.ID)
			if after.Phase != "active" || after.ContainerID == before.ContainerID || !reflect.DeepEqual(before.Capacity, after.Capacity) || d.serial != 2 || ports.allocated != 1 || ports.released != 0 {
				t.Fatalf("crash retry failed fixed reservation or exactly one replacement: serial=%d", d.serial)
			}
		})
	}
}

func TestInstalledReplacementRunFailureAndUnknownResultRetry(t *testing.T) {
	for _, unknown := range []bool{false, true} {
		t.Run(fmt.Sprint("unknown=", unknown), func(t *testing.T) {
			root := t.TempDir()
			d := newReplacementDocker(t)
			ports := &fixedPorts{port: 39124}
			p := stableReplacementProvider(t, root, d, ports)
			request := testRequest("failure-first")
			if _, err := p.Deploy(context.Background(), request); err != nil {
				t.Fatal(err)
			}
			request.Operation.IdempotencyKey = "failure-recreate"
			d.runError = !unknown
			d.runUnknown = unknown
			if _, err := p.Recreate(context.Background(), request); err == nil {
				t.Fatal("failed or unknown run claimed success")
			}
			if ports.released != 0 || ports.allocated != 1 {
				t.Fatal("failure lost lease")
			}
			d.runError = false
			d.runUnknown = false
			fresh := stableReplacementProvider(t, root, d, ports)
			if err := fresh.Reconcile(context.Background()); err != nil {
				t.Fatal(err)
			}
			if _, err := fresh.Recreate(context.Background(), request); err != nil {
				t.Fatal(err)
			}
			if d.serial != 2 || ports.released != 0 || ports.allocated != 1 {
				t.Fatalf("retry repeated successful creation or changed lease: serial=%d", d.serial)
			}
		})
	}
}

func TestInstalledReplacementRejectsOtherTaskAndImmutableDrift(t *testing.T) {
	root := t.TempDir()
	d := newReplacementDocker(t)
	ports := &fixedPorts{port: 39124}
	p := stableReplacementProvider(t, root, d, ports)
	request := testRequest("conflict-first")
	if _, err := p.Deploy(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	changed := request
	changed.Operation.IdempotencyKey = "different-spec"
	changed.Spec.Resources.CPUMillis++
	if _, err := p.Recreate(context.Background(), changed); err == nil {
		t.Fatal("different immutable spec accepted")
	}
	if len(d.runner.callsFor("rm")) != 0 {
		t.Fatal("changed immutable spec removed old app")
	}
	request.Operation.IdempotencyKey = "pending-owner"
	d.runError = true
	if _, err := p.Recreate(context.Background(), request); err == nil {
		t.Fatal("fixture failure absent")
	}
	other := request
	other.Operation.IdempotencyKey = "other-recreate"
	if _, err := p.Recreate(context.Background(), other); err == nil {
		t.Fatal("different task took over pending replacement")
	}
	d.runError = false
	if _, err := p.Recreate(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Recreate(context.Background(), other); err != nil {
		t.Fatal(err)
	}
	if ports.allocated != 1 || ports.released != 0 {
		t.Fatal("serial replacements lost reservation")
	}
}

func TestDestroyCancelsFailedReplacementAndReleasesLease(t *testing.T) {
	for _, afterRun := range []bool{false, true} {
		t.Run(fmt.Sprint("newContainer=", afterRun), func(t *testing.T) {
			root := t.TempDir()
			d := newReplacementDocker(t)
			ports := &fixedPorts{port: 39124}
			p := stableReplacementProvider(t, root, d, ports)
			request := testRequest("cancel-first")
			if _, err := p.Deploy(context.Background(), request); err != nil {
				t.Fatal(err)
			}
			request.Operation.IdempotencyKey = "cancel-recreate"
			d.runError = !afterRun
			d.runUnknown = afterRun
			if _, err := p.Recreate(context.Background(), request); err == nil {
				t.Fatal("fixture failure absent")
			}
			d.runError = false
			d.runUnknown = false
			fresh := stableReplacementProvider(t, root, d, ports)
			if err := fresh.Reconcile(context.Background()); err != nil {
				t.Fatal(err)
			}
			destroy := contracts.DestroyRequest{DeploymentID: request.DeploymentID, Operation: contracts.OperationContext{IdempotencyKey: "cancel-destroy"}}
			if err := fresh.Destroy(context.Background(), destroy); err != nil {
				t.Fatal(err)
			}
			if err := fresh.Destroy(context.Background(), destroy); err != nil {
				t.Fatal(err)
			}
			if d.facts != nil || ports.released != 1 {
				t.Fatalf("Destroy did not converge: facts=%v releases=%d", d.facts != nil, ports.released)
			}
			last := stableReplacementProvider(t, root, d, ports)
			if err := last.Reconcile(context.Background()); err != nil {
				t.Fatal(err)
			}
			if _, err := last.Recreate(context.Background(), request); err == nil {
				t.Fatal("cancelled recreate was revived")
			}
			snapshot := mustDurableSnapshot(t, last, request.DeploymentID)
			if snapshot.Phase != "destroyed" || snapshot.Capacity != nil {
				t.Fatal("cancelled reservation leaked")
			}
		})
	}
}

func TestReplacementRefusesForeignContainerWithoutRemoval(t *testing.T) {
	for _, drift := range []string{"id", "labels", "port", "network"} {
		t.Run(drift, func(t *testing.T) {
			root := t.TempDir()
			d := newReplacementDocker(t)
			ports := &fixedPorts{port: 39124}
			p := stableReplacementProvider(t, root, d, ports)
			request := testRequest("foreign-first")
			if _, err := p.Deploy(context.Background(), request); err != nil {
				t.Fatal(err)
			}
			request.Operation.IdempotencyKey = "foreign-recreate"
			d.hook = func(event string) {
				if event == "before load" {
					panic("controlled interruption")
				}
			}
			func() { defer func() { _ = recover() }(); _, _ = p.Recreate(context.Background(), request) }()
			d.hook = nil
			switch drift {
			case "id":
				d.facts.ID = strings.Repeat("f", 64)
			case "labels":
				d.facts.Config.Labels["open-card.managed"] = "false"
			case "port":
				d.facts.HostConfig.PortBindings["8080/tcp"][0].HostPort = "39125"
			case "network":
				d.facts.NetworkSettings.Networks["foreign"] = d.facts.NetworkSettings.Networks["opencard-m1-network"]
			}
			if _, err := p.Recreate(context.Background(), request); err == nil {
				t.Fatal("foreign replacement adopted")
			}
			if err := p.Destroy(context.Background(), contracts.DestroyRequest{DeploymentID: request.DeploymentID, Operation: contracts.OperationContext{IdempotencyKey: "foreign-destroy"}}); err == nil {
				t.Fatal("foreign replacement removed by cancellation")
			}
			if len(d.runner.callsFor("rm")) != 0 || ports.released != 0 {
				t.Fatal("foreign identity was changed")
			}
		})
	}
}

func TestDestroyCancellationSurvivesCrashBeforeAndAfterRemoval(t *testing.T) {
	for _, boundary := range []string{"before rm", "after rm"} {
		t.Run(boundary, func(t *testing.T) {
			root := t.TempDir()
			d := newReplacementDocker(t)
			ports := &fixedPorts{port: 39124}
			p := stableReplacementProvider(t, root, d, ports)
			request := testRequest("cancel-crash-first")
			if _, err := p.Deploy(context.Background(), request); err != nil {
				t.Fatal(err)
			}
			request.Operation.IdempotencyKey = "cancel-crash-recreate"
			d.hook = func(event string) {
				if event == "before load" {
					panic("interrupt replacement")
				}
			}
			func() { defer func() { _ = recover() }(); _, _ = p.Recreate(context.Background(), request) }()
			d.hook = func(event string) {
				if event == boundary {
					panic("interrupt cancellation")
				}
			}
			destroy := contracts.DestroyRequest{DeploymentID: request.DeploymentID, Operation: contracts.OperationContext{IdempotencyKey: "cancel-crash-destroy"}}
			func() {
				defer func() {
					if recover() == nil {
						t.Fatal("cancellation crash point absent")
					}
				}()
				_ = p.Destroy(context.Background(), destroy)
			}()
			d.hook = nil
			fresh := stableReplacementProvider(t, root, d, ports)
			if err := fresh.Reconcile(context.Background()); err != nil {
				t.Fatal(err)
			}
			if _, err := fresh.Recreate(context.Background(), request); err == nil {
				t.Fatal("durably cancelled recreate revived")
			}
			if err := fresh.Destroy(context.Background(), destroy); err != nil {
				t.Fatal(err)
			}
			if ports.released != 1 || d.facts != nil {
				t.Fatal("cancel retry leaked lease or container")
			}
			// A new explicit request after Destroy retains legacy creation semantics;
			// the cancelled task itself must never revive or poison later generations.
			next := request
			next.Operation.IdempotencyKey = "fresh-after-cancel"
			if _, err := fresh.Recreate(context.Background(), next); err != nil {
				t.Fatal(err)
			}
			next.Operation.IdempotencyKey = "replace-after-cancel"
			if _, err := fresh.Recreate(context.Background(), next); err != nil {
				t.Fatal(err)
			}
			if _, err := fresh.Recreate(context.Background(), request); err == nil {
				t.Fatal("historical cancelled key revived")
			}
		})
	}
}

func TestReplacementRejectsDeployAndRestartWhilePending(t *testing.T) {
	root := t.TempDir()
	d := newReplacementDocker(t)
	ports := &fixedPorts{port: 39124}
	p := stableReplacementProvider(t, root, d, ports)
	original := testRequest("pending-first")
	if _, err := p.Deploy(context.Background(), original); err != nil {
		t.Fatal(err)
	}
	request := original
	request.Operation.IdempotencyKey = "pending-replacement"
	d.runError = true
	if _, err := p.Recreate(context.Background(), request); err == nil {
		t.Fatal("fixture failure absent")
	}
	for _, key := range []string{original.Operation.IdempotencyKey, "new-deploy"} {
		deploy := original
		deploy.Operation.IdempotencyKey = key
		if _, err := p.Deploy(context.Background(), deploy); err == nil {
			t.Fatal("Deploy bypassed pending replacement")
		}
	}
	if err := p.Restart(context.Background(), contracts.RestartRequest{DeploymentID: request.DeploymentID, Operation: contracts.OperationContext{IdempotencyKey: "pending-restart"}}); err == nil {
		t.Fatal("Restart bypassed pending replacement")
	}
	if ports.allocated != 1 || ports.released != 0 {
		t.Fatal("other API changed pending lease")
	}
}

func TestReplacementPersistenceFailuresDoNotLoseIntent(t *testing.T) {
	for _, completion := range []bool{false, true} {
		t.Run(fmt.Sprint("completion=", completion), func(t *testing.T) {
			root := t.TempDir()
			d := newReplacementDocker(t)
			ports := &fixedPorts{port: 39124}
			p := stableReplacementProvider(t, root, d, ports)
			request := testRequest("persist-first")
			if _, err := p.Deploy(context.Background(), request); err != nil {
				t.Fatal(err)
			}
			request.Operation.IdempotencyKey = "persist-replacement"
			path := p.durableStatePath(request.DeploymentID)
			var saved []byte
			armed := true
			d.hook = func(event string) {
				if !armed {
					return
				}
				selected := !completion && event == "after network inspect" || completion && event == "before container inspect" && d.serial == 2
				if selected {
					armed = false
					var err error
					saved, err = os.ReadFile(path)
					if err != nil {
						t.Fatal(err)
					}
					if err = os.Remove(path); err != nil {
						t.Fatal(err)
					}
					if err = os.Mkdir(path, 0700); err != nil {
						t.Fatal(err)
					}
				}
			}
			if _, err := p.Recreate(context.Background(), request); err == nil {
				t.Fatal("failed durable publication claimed success")
			}
			d.hook = nil
			if armed {
				t.Fatal("publication fault not reached")
			}
			state := p.states[request.DeploymentID]
			if state != nil && (completion && state.phase != "replacing" || !completion && state.phase != "active") {
				t.Fatalf("failed publication changed in-memory phase: %s", state.phase)
			}
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, saved, 0600); err != nil {
				t.Fatal(err)
			}
			fresh := stableReplacementProvider(t, root, d, ports)
			if err := fresh.Reconcile(context.Background()); err != nil {
				t.Fatal(err)
			}
			if _, err := fresh.Recreate(context.Background(), request); err != nil {
				t.Fatal(err)
			}
			if d.serial != 2 || ports.allocated != 1 || ports.released != 0 {
				t.Fatalf("persistence retry lost reservation or duplicated container: serial=%d", d.serial)
			}
		})
	}
}

func TestReplacementCreatedBeforeFailedStartCanRetryOrCancel(t *testing.T) {
	for _, cancelTask := range []bool{false, true} {
		t.Run(fmt.Sprint("cancel=", cancelTask), func(t *testing.T) {
			root := t.TempDir()
			d := newReplacementDocker(t)
			ports := &fixedPorts{port: 39124}
			p := stableReplacementProvider(t, root, d, ports)
			request := testRequest("created-first")
			if _, err := p.Deploy(context.Background(), request); err != nil {
				t.Fatal(err)
			}
			request.Operation.IdempotencyKey = "created-recreate"
			d.createOnlyFailure = true
			if _, err := p.Recreate(context.Background(), request); err == nil {
				t.Fatal("created without a running endpoint claimed success")
			}
			d.createOnlyFailure = false
			fresh := stableReplacementProvider(t, root, d, ports)
			if err := fresh.Reconcile(context.Background()); err != nil {
				t.Fatal(err)
			}
			if d.facts.State.Running || len(d.runner.callsFor("start")) != 0 {
				t.Fatal("reconcile started an incomplete created container")
			}
			if cancelTask {
				if err := fresh.Destroy(context.Background(), contracts.DestroyRequest{DeploymentID: request.DeploymentID, Operation: contracts.OperationContext{IdempotencyKey: "created-cancel"}}); err != nil {
					t.Fatal(err)
				}
				if d.facts != nil || ports.released != 1 {
					t.Fatal("created cancellation did not release")
				}
			} else {
				if _, err := fresh.Recreate(context.Background(), request); err != nil {
					t.Fatal(err)
				}
				if !d.facts.State.Running || d.serial != 3 || ports.released != 0 || ports.allocated != 1 {
					t.Fatal("created retry did not preserve reservation")
				}
			}
		})
	}
}

func TestCreatedReplacementExceptionRejectsForeignOrExtraAttachments(t *testing.T) {
	for _, drift := range []string{"label", "extra-network", "old-container"} {
		t.Run(drift, func(t *testing.T) {
			root := t.TempDir()
			d := newReplacementDocker(t)
			ports := &fixedPorts{port: 39124}
			p := stableReplacementProvider(t, root, d, ports)
			request := testRequest("created-drift-first")
			if _, err := p.Deploy(context.Background(), request); err != nil {
				t.Fatal(err)
			}
			oldID := d.facts.ID
			request.Operation.IdempotencyKey = "created-drift"
			d.createOnlyFailure = true
			if _, err := p.Recreate(context.Background(), request); err == nil {
				t.Fatal("fixture failure absent")
			}
			d.createOnlyFailure = false
			before := len(d.runner.callsFor("rm"))
			switch drift {
			case "label":
				delete(d.facts.Config.Labels, replacementLabel)
			case "extra-network":
				d.facts.NetworkSettings.Networks["foreign"] = d.facts.NetworkSettings.Networks["opencard-m1-network"]
			case "old-container":
				d.facts.ID = oldID
			}
			fresh := stableReplacementProvider(t, root, d, ports)
			if fresh.Reconcile(context.Background()) == nil {
				t.Fatal("unsafe created object reconciled")
			}
			if _, err := p.Recreate(context.Background(), request); err == nil {
				t.Fatal("unsafe created object retried")
			}
			if len(d.runner.callsFor("rm")) != before {
				t.Fatal("unsafe created object removed")
			}
		})
	}
}

func TestInstalledConcurrentRecreateKeysSerializeWithOneLease(t *testing.T) {
	root := t.TempDir()
	d := newReplacementDocker(t)
	ports := &fixedPorts{port: 39124}
	p := stableReplacementProvider(t, root, d, ports)
	request := testRequest("concurrent-fixed-first")
	if _, err := p.Deploy(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	var wait sync.WaitGroup
	results := make(chan error, 2)
	for _, key := range []string{"fixed-a", "fixed-b"} {
		wait.Add(1)
		go func(key string) {
			defer wait.Done()
			next := request
			next.Operation.IdempotencyKey = key
			_, err := p.Recreate(context.Background(), next)
			results <- err
		}(key)
	}
	wait.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal(err)
		}
	}
	if d.serial != 3 || ports.allocated != 1 || ports.released != 0 {
		t.Fatal("concurrent replacement overlapped or changed lease")
	}
}

func TestReplacementRetainsRealCapacityAccountingAcrossFreshProcess(t *testing.T) {
	root := t.TempDir()
	d := newReplacementDocker(t)
	p := stableReplacementProvider(t, root, d, &fixedPorts{port: 39124})
	capacity := realCapacityProvider(t)
	p.config.Capacity = capacity
	request := testRequest("real-fixed-first")
	if _, err := p.Deploy(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	before := mustDurableSnapshot(t, p, request.DeploymentID)
	request.Operation.IdempotencyKey = "real-fixed-recreate"
	d.runError = true
	if _, err := p.Recreate(context.Background(), request); err == nil {
		t.Fatal("fixture failure absent")
	}
	if capacity.ActiveLeaseCount() != 1 {
		t.Fatal("failure released actual capacity")
	}
	d.runError = false
	fresh := stableReplacementProvider(t, root, d, &fixedPorts{port: 39124})
	freshCapacity := realCapacityProvider(t)
	fresh.config.Capacity = freshCapacity
	if err := fresh.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if freshCapacity.ActiveLeaseCount() != 1 {
		t.Fatal("fresh process lost replacement reservation")
	}
	if _, err := fresh.Recreate(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	after := mustDurableSnapshot(t, fresh, request.DeploymentID)
	if !reflect.DeepEqual(before.Capacity, after.Capacity) || freshCapacity.ActiveLeaseCount() != 1 {
		t.Fatal("real replacement did not keep exact capacity")
	}
	if err := fresh.Destroy(context.Background(), contracts.DestroyRequest{DeploymentID: request.DeploymentID, Operation: contracts.OperationContext{IdempotencyKey: "real-fixed-destroy"}}); err != nil {
		t.Fatal(err)
	}
	if freshCapacity.ActiveLeaseCount() != 0 {
		t.Fatal("ordinary Destroy leaked real capacity")
	}
}

func TestDestroyedReplacementRejectsChangedSpecWithoutPoisoningNextCreation(t *testing.T) {
	root := t.TempDir()
	d := newReplacementDocker(t)
	ports := &fixedPorts{port: 39124}
	p := stableReplacementProvider(t, root, d, ports)
	request := testRequest("destroyed-spec-first")
	if _, err := p.Deploy(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if err := p.Destroy(context.Background(), contracts.DestroyRequest{DeploymentID: request.DeploymentID, Operation: contracts.OperationContext{IdempotencyKey: "destroyed-spec-destroy"}}); err != nil {
		t.Fatal(err)
	}
	path := p.durableStatePath(request.DeploymentID)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	calls := len(d.runner.callsFor())
	changed := request
	changed.Operation.IdempotencyKey = "destroyed-wrong-spec"
	changed.Spec.Resources.CPUMillis++
	if _, err := p.Recreate(context.Background(), changed); err == nil {
		t.Fatal("different immutable spec accepted after Destroy")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) || len(d.runner.callsFor()) != calls {
		t.Fatal("rejected spec mutated destroyed runtime")
	}
	request.Operation.IdempotencyKey = "destroyed-valid-spec"
	if _, err := p.Recreate(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	snapshot := mustDurableSnapshot(t, p, request.DeploymentID)
	for _, action := range snapshot.Actions {
		if action.Status == "started" {
			t.Fatalf("correct recreation inherited poison action: %+v", action)
		}
	}
	fresh := stableReplacementProvider(t, root, d, ports)
	if err := fresh.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
}
