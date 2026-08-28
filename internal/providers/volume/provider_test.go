package volume

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/contracts"
)

type fakeRunner struct {
	mu          sync.Mutex
	calls       [][]string
	volumes     map[string]VolumeFacts
	run         func(context.Context, string, []string, io.Writer, io.Writer) error
	inspectWait <-chan struct{}
}

func (r *fakeRunner) Run(ctx context.Context, command string, args []string, stdout, stderr io.Writer) error {
	r.mu.Lock()
	r.calls = append(r.calls, append([]string(nil), args...))
	r.mu.Unlock()
	if r.run != nil {
		return r.run(ctx, command, args, stdout, stderr)
	}
	if command != "docker" {
		return fmt.Errorf("unexpected command %q", command)
	}
	if len(args) >= 2 && args[0] == "volume" && args[1] == "inspect" {
		if r.inspectWait != nil {
			select {
			case <-r.inspectWait:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		name := args[len(args)-1]
		r.mu.Lock()
		facts, ok := r.volumes[name]
		r.mu.Unlock()
		if !ok {
			_, _ = io.WriteString(stderr, "Error: no such volume: "+name)
			return errors.New("volume not found")
		}
		encoded, _ := json.Marshal(facts)
		_, _ = stdout.Write(encoded)
		return nil
	}
	if len(args) >= 2 && args[0] == "volume" && args[1] == "create" {
		name := args[len(args)-1]
		labels := map[string]string{}
		for index := 2; index+1 < len(args); index++ {
			if args[index] == "--label" {
				parts := strings.SplitN(args[index+1], "=", 2)
				if len(parts) == 2 {
					labels[parts[0]] = parts[1]
				}
				index++
			}
		}
		r.mu.Lock()
		r.volumes[name] = VolumeFacts{Name: name, Driver: "local", Scope: "local", Mountpoint: "/var/lib/docker/volumes/" + name + "/_data", Labels: labels}
		r.mu.Unlock()
		_, _ = io.WriteString(stdout, name+"\n")
		return nil
	}
	if len(args) >= 3 && args[0] == "volume" && args[1] == "rm" {
		name := args[len(args)-1]
		r.mu.Lock()
		delete(r.volumes, name)
		r.mu.Unlock()
		return nil
	}
	return fmt.Errorf("unexpected docker args %#v", args)
}

func (r *fakeRunner) callCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.calls)
}

func (r *fakeRunner) callsSnapshot() [][]string {
	r.mu.Lock()
	defer r.mu.Unlock()
	calls := make([][]string, len(r.calls))
	for index := range r.calls {
		calls[index] = append([]string(nil), r.calls[index]...)
	}
	return calls
}

func newProvider(t *testing.T, runner *fakeRunner) *Provider {
	t.Helper()
	provider, err := New(Config{TaskPrefix: "opencard-m2-test", Runner: runner})
	if err != nil {
		t.Fatal(err)
	}
	return provider
}

func request(key, name string) contracts.VolumeRequest {
	return contracts.VolumeRequest{
		Volume:    contracts.VolumeSpec{Name: name, MountPath: "/var/lib/app", SizeBytes: 1024},
		Operation: contracts.OperationContext{IdempotencyKey: key},
	}
}

func codeOf(t *testing.T, err error) contracts.ErrorCode {
	t.Helper()
	var providerErr *contracts.ProviderError
	if !errors.As(err, &providerErr) {
		t.Fatalf("want ProviderError, got %T: %v", err, err)
	}
	return providerErr.Code
}

func hasPair(args []string, key, value string) bool {
	for index := 0; index+1 < len(args); index++ {
		if args[index] == key && args[index+1] == value {
			return true
		}
	}
	return false
}

func TestNewRejectsUnsafeTaskPrefixAndMetadataDeclaresVolumeCapability(t *testing.T) {
	for _, prefix := range []string{"", "../task", "task/name", "task\x00name", "task name"} {
		if _, err := New(Config{TaskPrefix: prefix}); err == nil {
			t.Fatalf("prefix %q was accepted", prefix)
		}
	}
	provider := newProvider(t, &fakeRunner{volumes: map[string]VolumeFacts{}})
	metadata := provider.Metadata(context.Background())
	if err := metadata.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := metadata.Supports(contracts.CapabilityVolumeManage); err != nil {
		t.Fatal(err)
	}
}

func TestCreateDerivesOwnedNameLabelsFactsAndEvidence(t *testing.T) {
	runner := &fakeRunner{volumes: map[string]VolumeFacts{}}
	provider := newProvider(t, runner)
	created, evidence, err := provider.Create(context.Background(), request("create-1", "data"))
	if err != nil {
		t.Fatal(err)
	}
	if created.Name != "opencard-m2-test-volume-data" || created.MountPath != "/var/lib/app" || created.SizeBytes != 1024 {
		t.Fatalf("unexpected created spec: %#v", created)
	}
	if !evidence.Redacted || !strings.HasPrefix(evidence.Digest, "sha256:") || len(evidence.Refs) != 1 {
		t.Fatalf("missing redacted inspect evidence: %#v", evidence)
	}
	calls := runner.callsSnapshot()
	if len(calls) != 3 {
		t.Fatalf("want inspect/create/inspect, got %#v", calls)
	}
	if got := strings.Join(calls[0], " "); !strings.Contains(got, "volume inspect") || !strings.Contains(got, "opencard-m2-test-volume-data") {
		t.Fatalf("unexpected initial inspect: %#v", calls[0])
	}
	createArgs := calls[1]
	if !hasPair(createArgs, "--label", "open-card.managed=true") || !hasPair(createArgs, "--label", "open-card.task-prefix=opencard-m2-test") || !hasPair(createArgs, "--label", "open-card.task=opencard-m2-test") || !hasPair(createArgs, "--label", "open-card.volume-logical-name=data") || createArgs[len(createArgs)-1] != created.Name {
		t.Fatalf("create did not carry exact ownership labels: %#v", createArgs)
	}

	if _, _, err := provider.Create(context.Background(), request("create-1", "data")); err != nil {
		t.Fatal(err)
	}
	if runner.callCount() != 3 {
		t.Fatalf("same idempotency key invoked Docker again: %d calls", runner.callCount())
	}
}

func TestCreateExistingOwnedVolumeIsIdempotentAcrossProviderCalls(t *testing.T) {
	name := "opencard-m2-test-volume-data"
	runner := &fakeRunner{volumes: map[string]VolumeFacts{name: {
		Name: name, Driver: "local", Scope: "local", Mountpoint: "/data", Labels: map[string]string{
			"open-card.managed": "true", "open-card.task-prefix": "opencard-m2-test",
		},
	}}}
	provider := newProvider(t, runner)
	created, _, err := provider.Create(context.Background(), request("create-existing", "data"))
	if err != nil {
		t.Fatal(err)
	}
	if created.Name != name || runner.callCount() != 1 {
		t.Fatalf("existing owned volume was not adopted safely: %#v calls=%d", created, runner.callCount())
	}

	// A fresh operation key still uses Docker inspect as the source of truth;
	// it does not depend on process-local state.
	if _, _, err := provider.Create(context.Background(), request("create-existing-2", "data")); err != nil {
		t.Fatal(err)
	}
	if runner.callCount() != 2 {
		t.Fatalf("fresh idempotent create did not only inspect: %d calls", runner.callCount())
	}
}

func TestCreateFailsClosedForUnmanagedOrMalformedExistingVolume(t *testing.T) {
	name := "opencard-m2-test-volume-data"
	for _, facts := range []VolumeFacts{
		{Name: name, Driver: "local", Labels: map[string]string{}},
		{Name: "foreign-volume-data", Driver: "local", Labels: map[string]string{"open-card.managed": "true", "open-card.task-prefix": "opencard-m2-test"}},
	} {
		runner := &fakeRunner{volumes: map[string]VolumeFacts{name: facts}}
		provider := newProvider(t, runner)
		_, _, err := provider.Create(context.Background(), request("create-owned", "data"))
		if got := codeOf(t, err); got != contracts.ErrConflict {
			t.Fatalf("want conflict for facts %#v, got %s", facts, got)
		}
		if runner.callCount() != 1 {
			t.Fatalf("unmanaged resource reached create: %#v", runner.callsSnapshot())
		}
	}

	runner := &fakeRunner{volumes: map[string]VolumeFacts{}, run: func(_ context.Context, _ string, args []string, stdout, stderr io.Writer) error {
		if len(args) >= 2 && args[0] == "volume" && args[1] == "inspect" {
			_, _ = io.WriteString(stdout, "{not-json")
			return nil
		}
		return errors.New("create must not be reached")
	}}
	provider := newProvider(t, runner)
	_, _, err := provider.Create(context.Background(), request("create-malformed", "data"))
	if got := codeOf(t, err); got != contracts.ErrValidation {
		t.Fatalf("want validation for malformed inspect, got %s", got)
	}
}

func TestCreateDoesNotTreatUnknownDockerFailureAsAbsent(t *testing.T) {
	runner := &fakeRunner{run: func(_ context.Context, _ string, args []string, _, _ io.Writer) error {
		if len(args) >= 2 && args[0] == "volume" && args[1] == "inspect" {
			return errors.New("permission denied while contacting Docker")
		}
		return errors.New("create must not be reached")
	}}
	provider := newProvider(t, runner)
	_, _, err := provider.Create(context.Background(), request("create-unavailable", "data"))
	if got := codeOf(t, err); got != contracts.ErrUnavailable {
		t.Fatalf("want unavailable, got %s", got)
	}
	if runner.callCount() != 1 {
		t.Fatalf("unknown inspect failure triggered mutation: %#v", runner.callsSnapshot())
	}
}

func TestLifecycleOperationsInspectOnlyAndDestroyRequiresConfirmation(t *testing.T) {
	runner := &fakeRunner{volumes: map[string]VolumeFacts{}}
	provider := newProvider(t, runner)
	base := request("create-life", "data")
	if _, _, err := provider.Create(context.Background(), base); err != nil {
		t.Fatal(err)
	}
	beforeDestroy := runner.callCount()
	for _, operation := range []struct {
		name string
		call func(contracts.VolumeRequest) error
	}{
		{"attach", func(r contracts.VolumeRequest) error { return provider.Attach(context.Background(), r) }},
		{"detach", func(r contracts.VolumeRequest) error { return provider.Detach(context.Background(), r) }},
		{"retain", func(r contracts.VolumeRequest) error { return provider.Retain(context.Background(), r) }},
	} {
		req := base
		req.Operation.IdempotencyKey = "life-" + operation.name
		if err := operation.call(req); err != nil {
			t.Fatalf("%s: %v", operation.name, err)
		}
	}
	if runner.callCount() != beforeDestroy+3 {
		t.Fatalf("lifecycle operations did not inspect exactly once: %d -> %d", beforeDestroy, runner.callCount())
	}
	if err := provider.Destroy(context.Background(), base); err == nil || codeOf(t, err) != contracts.ErrUnauthorized {
		t.Fatalf("missing destroy confirmation was not rejected: %v", err)
	}
	if runner.callCount() != beforeDestroy+3 {
		t.Fatalf("missing confirmation reached Docker")
	}
	wrong := base
	wrong.Operation.IdempotencyKey = "destroy-wrong-volume-token"
	wrong.ConfirmationToken = "confirm-volume-destroy:opencard-m2-test-volume-other"
	if err := provider.Destroy(context.Background(), wrong); err == nil || codeOf(t, err) != contracts.ErrUnauthorized {
		t.Fatalf("confirmation for another volume was accepted: %v", err)
	}
	if runner.callCount() != beforeDestroy+3 {
		t.Fatalf("wrong scoped confirmation reached Docker")
	}

	destroy := base
	destroy.Operation.IdempotencyKey = "destroy-life"
	destroy.ConfirmationToken = provider.DestroyConfirmationToken("data")
	if err := provider.Destroy(context.Background(), destroy); err != nil {
		t.Fatal(err)
	}
	count := runner.callCount()
	if err := provider.Destroy(context.Background(), destroy); err != nil {
		t.Fatal(err)
	}
	if runner.callCount() != count {
		t.Fatalf("destroy replay repeated Docker side effect")
	}
	if err := provider.Destroy(context.Background(), contracts.VolumeRequest{Volume: base.Volume, ConfirmationToken: provider.DestroyConfirmationToken("data"), Operation: contracts.OperationContext{IdempotencyKey: "destroy-after-restart"}}); err == nil || codeOf(t, err) != contracts.ErrNotFound {
		t.Fatalf("destroy of absent volume was not classified as not found: %v", err)
	}
}

func TestInspectReturnsMountpointForExternalChecksumEvidence(t *testing.T) {
	name := "opencard-m2-test-volume-data"
	runner := &fakeRunner{volumes: map[string]VolumeFacts{name: {
		Name: name, Driver: "local", Scope: "local", Mountpoint: "/var/lib/docker/volumes/" + name + "/_data",
		Labels: map[string]string{"open-card.managed": "true", "open-card.task": "opencard-m2-test"},
	}}}
	provider := newProvider(t, runner)
	facts, evidence, err := provider.Inspect(context.Background(), request("inspect-1", "data"))
	if err != nil {
		t.Fatal(err)
	}
	if facts.Name != name || facts.Mountpoint == "" || facts.Driver != "local" {
		t.Fatalf("inspect did not preserve checksum-friendly facts: %#v", facts)
	}
	if evidence.Digest == "" || evidence.Refs[0].Locator != "docker://volume/"+name {
		t.Fatalf("inspect evidence is incomplete: %#v", evidence)
	}
	if _, err := provider.InspectFacts(context.Background(), request("inspect-2", "data")); err != nil {
		t.Fatal(err)
	}
}

func TestInvalidNamesAndContextFailBeforeDocker(t *testing.T) {
	runner := &fakeRunner{volumes: map[string]VolumeFacts{}}
	provider := newProvider(t, runner)
	for _, name := range []string{"", "../escape", "/host/path", "other-volume-data", "bad/name", "bad\x00name"} {
		_, _, err := provider.Create(context.Background(), request("bad-"+fmt.Sprint(len(name)), name))
		if err == nil || codeOf(t, err) != contracts.ErrInvalidArgument {
			t.Fatalf("name %q was not rejected: %v", name, err)
		}
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, err := provider.Create(canceled, request("cancelled", "data"))
	if codeOf(t, err) != contracts.ErrCancelled {
		t.Fatalf("cancelled operation was not classified: %v", err)
	}
	if runner.callCount() != 0 {
		t.Fatalf("invalid/cancelled requests reached Docker: %#v", runner.callsSnapshot())
	}
	badMount := request("bad-mount", "data")
	badMount.Volume.MountPath = "relative"
	_, _, err = provider.Create(context.Background(), badMount)
	if codeOf(t, err) != contracts.ErrValidation {
		t.Fatalf("relative mount path was not rejected: %v", err)
	}
}

func TestConcurrentCreateWithSameIdempotencyKeyHasOneDockerLifecycle(t *testing.T) {
	release := make(chan struct{})
	runner := &fakeRunner{volumes: map[string]VolumeFacts{}, inspectWait: release}
	provider := newProvider(t, runner)
	result := make(chan error, 2)
	go func() {
		_, _, err := provider.Create(context.Background(), request("create-concurrent", "data"))
		result <- err
	}()
	go func() {
		_, _, err := provider.Create(context.Background(), request("create-concurrent", "data"))
		result <- err
	}()
	time.Sleep(10 * time.Millisecond)
	close(release)
	for range 2 {
		if err := <-result; err != nil {
			t.Fatal(err)
		}
	}
	if runner.callCount() != 3 {
		t.Fatalf("concurrent idempotency caused duplicate Docker calls: %#v", runner.callsSnapshot())
	}
}
