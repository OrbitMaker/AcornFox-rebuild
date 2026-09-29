//go:build linux

package sourcebuildexecution

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	appcontracts "github.com/open-card/open-card/internal/application/contracts"
	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/foundation"
	"github.com/open-card/open-card/internal/localpeer"
	capacityprovider "github.com/open-card/open-card/internal/providers/capacity"
)

func TestSourceBuildUnixTransportUsesOriginalAuthorityAndPeer(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	att, err := localpeer.AttestLinuxProcess(int32(os.Getpid()))
	if err != nil {
		t.Fatal(err)
	}
	validator := func(pid int32, uid uint32) error {
		return localpeer.VerifyProcessIdentity(pid, uid, att.ExecutableSHA256, att.StartTime)
	}
	binding := appcontracts.SourceBuildBinding{TaskID: "task_unix", OperationID: "op_unix", ApplicationID: "app_unix", Owner: "core-worker", CoreGeneration: 1, LeaseGeneration: 1}
	request := contracts.PrepareSourceRequest{ApplicationID: binding.ApplicationID, Kind: domain.SourceGitHTTPS, Locator: "https://github.com/acme/app", Ref: strings.Repeat("a", 40), Operation: contracts.OperationContext{IdempotencyKey: "unix-prepare", Deadline: time.Now().Add(time.Minute), Actor: "core-source-build"}}
	command := SourceBuildCommand{Stage: appcontracts.SourceBuildPrepare, Binding: binding, Prepare: &request}
	sha, _ := SourceBuildCommandDigest(command)
	authority := &authorityFixture{check: func(c SourceBuildCommand) error {
		actual, _ := SourceBuildCommandDigest(c)
		if actual != sha {
			return ErrBinding
		}
		return nil
	}}
	as, err := NewAuthorityServer(ServerConfig{SocketPath: filepath.Join(root, "authority.sock"), ExpectedPID: att.PID, ExpectedUID: att.UID, PeerValidator: validator}, authority)
	if err != nil {
		t.Fatal(err)
	}
	defer as.Close()
	ac, err := NewAuthorityClient(ClientConfig{SocketPath: filepath.Join(root, "authority.sock"), ExpectedPID: att.PID, ExpectedUID: att.UID, PeerValidator: validator})
	if err != nil {
		t.Fatal(err)
	}
	cap, err := capacityprovider.New(capacityprovider.Config{})
	if err != nil {
		t.Fatal(err)
	}
	workspace := filepath.Join(root, "source-workspace")
	if err := os.Mkdir(workspace, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "Dockerfile"), []byte("FROM scratch\nCMD [\"/app\"]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	digestHex, err := foundation.HashDirectory(workspace)
	if err != nil {
		t.Fatal(err)
	}
	source := &transportSourceFixture{result: contracts.PrepareSourceResult{Revision: domain.SourceRevision{ID: "src_unix", ApplicationID: binding.ApplicationID, Kind: request.Kind, Locator: request.Locator, Ref: request.Ref, Commit: request.Ref, ContentDigest: "sha256:" + digestHex, WorkspaceRef: workspace, CreatedAt: time.Now().UTC(), Immutable: true}}}
	role, err := NewRuntime(Config{Source: source, Authority: ac, Capacity: cap, BuilderFactory: func(contracts.CapacityProvider) (contracts.BuildProvider, error) { return &buildFixture{}, nil }})
	if err != nil {
		t.Fatal(err)
	}
	es, err := NewExecutionServer(ServerConfig{SocketPath: filepath.Join(root, "execute.sock"), ExpectedPID: att.PID, ExpectedUID: att.UID, PeerValidator: validator}, role)
	if err != nil {
		t.Fatal(err)
	}
	defer es.Close()
	client, err := NewClient(ClientConfig{SocketPath: filepath.Join(root, "execute.sock"), ExpectedPID: att.PID, ExpectedUID: att.UID, PeerValidator: validator})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(command)
	out, err := client.ExecuteSourceBuild(context.Background(), raw)
	if err != nil || out.Binding != binding || out.CommandSHA256 != sha || out.Prepared == nil || out.Prepared.Revision.ID != "src_unix" {
		t.Fatalf("original Unix receipt: %v", err)
	}
	request.Ref = strings.Repeat("c", 40)
	raw, _ = json.Marshal(command)
	if _, err := client.ExecuteSourceBuild(context.Background(), raw); err == nil || source.prepared != 1 {
		t.Fatal("changed full command bypassed Core authority")
	}
	if _, err := NewClient(ClientConfig{SocketPath: filepath.Join(root, "execute.sock"), ExpectedPID: att.PID, ExpectedUID: att.UID}); err == nil {
		t.Fatal("missing live peer validator accepted")
	}
	if _, err := client.ExecuteSourceBuild(context.Background(), []byte(`{"stage":"cancel"}`)); err == nil || source.prepared != 1 {
		t.Fatal("unapproved control stage dispatched")
	}
	// A real accepted request cancellation must reach the role provider and
	// remain unknown, without an automatic second POST or private error text.
	request.Ref = strings.Repeat("a", 40)
	raw, _ = json.Marshal(command)
	source.entered = make(chan struct{})
	source.cancelled = make(chan struct{})
	cancelCtx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := client.ExecuteSourceBuild(cancelCtx, raw); done <- err }()
	select {
	case <-source.entered:
	case <-time.After(time.Second):
		t.Fatal("cancel fixture did not reach actual role")
	}
	cancel()
	select {
	case err := <-done:
		if !contracts.IsProviderOutcomeUnknown(err) || !errors.Is(err, context.Canceled) {
			t.Fatal("transport cancellation lost typed unknown cause")
		}
	case <-time.After(time.Second):
		t.Fatal("client cancellation not bounded")
	}
	select {
	case <-source.cancelled:
	case <-time.After(time.Second):
		t.Fatal("role provider context was not cancelled")
	}
	if source.prepared != 2 {
		t.Fatal("cancelled request was automatically redispatched")
	}
}

type transportSourceFixture struct {
	result             contracts.PrepareSourceResult
	prepared           int
	entered, cancelled chan struct{}
}

func (s *transportSourceFixture) Metadata(context.Context) contracts.ProviderMetadata {
	return contracts.ProviderMetadata{}
}
func (s *transportSourceFixture) Prepare(ctx context.Context, _ contracts.PrepareSourceRequest) (contracts.PrepareSourceResult, error) {
	s.prepared++
	if s.entered != nil {
		close(s.entered)
		<-ctx.Done()
		close(s.cancelled)
		return contracts.PrepareSourceResult{}, ctx.Err()
	}
	return s.result, nil
}
func (s *transportSourceFixture) Release(context.Context, contracts.ReleaseSourceRequest) error {
	return errors.New("release unavailable")
}
