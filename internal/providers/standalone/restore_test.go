package standalone

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"reflect"
	"testing"
)

func TestInstalledReconcileResumesOnlyVerifiedActiveContainers(t *testing.T) {
	for _, tc := range []struct {
		name                                                                   string
		phase                                                                  string
		mutate                                                                 func(*inspectFacts)
		guardError, networkError, startError, staysStopped, unfinished, legacy bool
		missingID, missingTopology, postStartDrift                             bool
		wantStarts                                                             int
		wantError                                                              bool
	}{
		{name: "active exited", wantStarts: 1},
		{name: "already running", mutate: func(f *inspectFacts) { f.State.Running = true; f.State.Status = "running" }},
		{name: "pending", phase: "pending"},
		{name: "explicit destroy underway", phase: "destroying"},
		{name: "explicitly destroyed", phase: "destroyed"},
		{name: "legacy observation only", legacy: true},
		{name: "foreign labels", mutate: func(f *inspectFacts) { f.Config.Labels["open-card.managed"] = "false" }, wantError: true},
		{name: "replacement same labels", mutate: func(f *inspectFacts) { f.ID = "1111111111111111111111111111111111111111111111111111111111111111" }, wantError: true},
		{name: "resource drift", mutate: func(f *inspectFacts) { f.HostConfig.Memory++ }, wantError: true},
		{name: "lease port drift", mutate: func(f *inspectFacts) { f.HostConfig.PortBindings["8080/tcp"][0].HostPort = "39125" }, wantError: true},
		{name: "unknown docker state", mutate: func(f *inspectFacts) { f.State.Status = "dead" }, wantError: true},
		{name: "missing persisted identity", missingID: true, wantError: true},
		{name: "missing topology validator", missingTopology: true, wantError: true},
		{name: "configuration changes after start", postStartDrift: true, wantStarts: 1, wantError: true},
		{name: "guard not ready", guardError: true, wantError: true},
		{name: "network changed", networkError: true, wantError: true},
		{name: "unfinished mutation", unfinished: true, wantError: true},
		{name: "start fails", startError: true, wantStarts: 1, wantError: true},
		{name: "start reports success but remains stopped", staysStopped: true, wantStarts: 1, wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			runner := dockerHappyRunner(t)
			ports := &fixedPorts{port: 39124}
			first := testProviderAt(t, root, runner, ports)
			deployment, err := first.Deploy(context.Background(), testRequest("restore-deploy"))
			if err != nil {
				t.Fatal(err)
			}
			snapshot := mustDurableSnapshot(t, first, deployment.ID)
			if tc.missingID {
				snapshot.ContainerID = ""
			}
			if tc.phase != "" {
				snapshot.Phase = tc.phase
			}
			if tc.unfinished {
				snapshot.Actions[0].Status = "started"
			}
			writeDurableSnapshot(t, first, snapshot)
			before, err := os.ReadFile(first.durableStatePath(deployment.ID))
			if err != nil {
				t.Fatal(err)
			}
			var facts inspectFacts
			if err := json.Unmarshal([]byte(ownedContainerInspect(testRequest("restore"), testDigest)), &facts); err != nil {
				t.Fatal(err)
			}
			facts.HostConfig.PortBindings["8080/tcp"][0].HostPort = "39124"
			facts.State.Running = false
			facts.State.Status = "exited"
			if tc.mutate != nil {
				tc.mutate(&facts)
			}
			starts, guards, networks := 0, 0, 0
			happy := runner.run
			runner.run = func(args []string, out io.Writer) error {
				if len(args) > 1 && args[0] == "container" && args[1] == "inspect" {
					raw, _ := json.Marshal(facts)
					_, err := out.Write(raw)
					return err
				}
				if len(args) > 1 && args[0] == "network" && args[1] == "inspect" {
					if guards == 0 {
						t.Fatal("topology checked without successful root guard readiness")
					}
					networks++
					_, err := io.WriteString(out, "fixed-topology")
					return err
				}
				if args[0] == "start" {
					starts++
					if !reflect.DeepEqual(args, []string{"start", testContainerID}) || guards == 0 || networks == 0 {
						t.Fatalf("unsafe start: %v guards=%d networks=%d", args, guards, networks)
					}
					if tc.startError {
						return errors.New("start failed")
					}
					if tc.postStartDrift {
						facts.HostConfig.Privileged = true
					}
					if !tc.staysStopped {
						facts.State.Running = true
						facts.State.Status = "running"
					}
					return nil
				}
				return happy(args, out)
			}
			fresh := testProviderAt(t, root, runner, ports)
			if !tc.legacy {
				fresh.config.RestoreActiveGuard = func(context.Context) error {
					guards++
					if tc.guardError {
						return errors.New("not ready")
					}
					return nil
				}
				fresh.config.ExistingNetworkValidator = func(raw []byte) error {
					if string(raw) != "fixed-topology" || tc.networkError {
						return errors.New("drift")
					}
					return nil
				}
			}
			if tc.missingTopology {
				fresh.config.ExistingNetworkValidator = nil
			}
			err = fresh.Reconcile(context.Background())
			if (err != nil) != tc.wantError || starts != tc.wantStarts {
				t.Fatalf("err=%v starts=%d wantError=%v wantStarts=%d", err, starts, tc.wantError, tc.wantStarts)
			}
			after, err := os.ReadFile(first.durableStatePath(deployment.ID))
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(before, after) {
				t.Fatal("reconcile fabricated a durable lifecycle success")
			}
			if tc.name == "active exited" {
				if err := fresh.Reconcile(context.Background()); err != nil || starts != 1 {
					t.Fatalf("repeat start: %d %v", starts, err)
				}
				if ports.allocated != 1 {
					t.Fatalf("new allocation during restore: %d", ports.allocated)
				}
			}
			if tc.wantError && fresh.states[deployment.ID] != nil {
				t.Fatal("failed recovery published runtime as ready")
			}
		})
	}
}

func TestInstalledRestoreFailureCanRetryWithoutNewContainer(t *testing.T) {
	root := t.TempDir()
	runner := dockerHappyRunner(t)
	ports := &fixedPorts{port: 39124}
	first := testProviderAt(t, root, runner, ports)
	deployment, err := first.Deploy(context.Background(), testRequest("restore-retry"))
	if err != nil {
		t.Fatal(err)
	}
	snapshot := mustDurableSnapshot(t, first, deployment.ID)
	var facts inspectFacts
	_ = json.Unmarshal([]byte(ownedContainerInspect(testRequest("restore"), testDigest)), &facts)
	facts.HostConfig.PortBindings["8080/tcp"][0].HostPort = "39124"
	facts.State.Running = false
	facts.State.Status = "exited"
	starts := 0
	runner.run = func(args []string, out io.Writer) error {
		if args[0] == "start" {
			starts++
			if starts == 1 {
				return errors.New("temporary failure")
			}
			facts.State.Running = true
			return nil
		}
		if args[0] == "container" {
			raw, _ := json.Marshal(facts)
			_, err := out.Write(raw)
			return err
		}
		return nil
	}
	fresh := testProviderAt(t, root, runner, ports)
	fresh.config.RestoreActiveGuard = func(context.Context) error { return nil }
	fresh.config.ExistingNetworkValidator = func([]byte) error { return nil }
	if fresh.Reconcile(context.Background()) == nil {
		t.Fatal("failed start accepted")
	}
	if err := fresh.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if starts != 2 || ports.allocated != 1 || mustDurableSnapshot(t, fresh, deployment.ID).ContainerID != snapshot.ContainerID {
		t.Fatal("retry replaced immutable deployment")
	}
}
