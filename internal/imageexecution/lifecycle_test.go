package imageexecution

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	appcontracts "github.com/open-card/open-card/internal/application/contracts"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/packmanager"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type lifecycleAuthorityStore struct {
	appcontracts.ImageLifecycleStore
	binding appcontracts.ImageLifecycleBinding
	input   appcontracts.ImageLifecycleAuthorityInput
	calls   int
	reject  bool
}

func (s *lifecycleAuthorityStore) AuthorizeImageLifecycle(_ context.Context, in appcontracts.ImageLifecycleAuthorityInput) (appcontracts.ImageLifecycleBinding, error) {
	s.calls++
	s.input = in
	if s.reject {
		return appcontracts.ImageLifecycleBinding{}, appcontracts.ErrLeaseLost
	}
	return s.binding, nil
}
func TestLifecycleAuthorityUsesFreshCommandForEachDockerWrite(t *testing.T) {
	b := appcontracts.ImageLifecycleBinding{OperationID: domain.ID("op_command"), TaskID: domain.ID("task_command"), DeploymentID: domain.ID("dep_same"), ReleaseID: domain.ID("rel_same"), DeployOperationID: domain.ID("op_original"), PlanDigest: "sha256:fixture", ContainerID: "same-cid", Action: appcontracts.ImageLifecycleStop}
	a := appcontracts.ImageLifecycleAuthorityInput{BeginImageExecutionInput: appcontracts.BeginImageExecutionInput{TaskID: b.TaskID, OperationID: b.OperationID, Owner: "fresh", CoreGeneration: 12, LeaseGeneration: 15}, DeploymentID: b.DeploymentID, ReleaseID: b.ReleaseID, PlanDigest: b.PlanDigest, ContainerID: b.ContainerID, Action: b.Action}
	store := &lifecycleAuthorityStore{binding: b}
	sock := filepath.Join(t.TempDir(), "authority.sock")
	server, err := NewCoreAuthorityServer(CoreAuthorityServerConfig{Store: &fakeStoreForAuthority{}, LifecycleStore: store, SocketPath: sock, ExpectedContainerUID: uint32(os.Getuid()), ExpectedContainerPID: int32(os.Getpid())})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	runtime := &ContainerRuntime{authorityClient: packmanager.NewUnixHTTPClient(sock, int32(os.Getpid()), uint32(os.Getuid()), nil, time.Second)}
	base := &fakeDockerRunner{}
	runner := &authorizingCommandRunner{base: base}
	for _, action := range []appcontracts.ImageLifecycleAction{appcontracts.ImageLifecycleStop, appcontracts.ImageLifecycleStart, appcontracts.ImageLifecycleRestart} {
		store.binding.Action = action
		b.Action = action
		a.Action = action
		req := LifecycleRequest{Binding: b, Authority: a}
		ctx := withAuthorityCheck(context.Background(), func(ctx context.Context) error { return runtime.checkLifecycleAuthority(ctx, req) })
		if err := runner.Run(ctx, "docker", []string{string(action), "same-cid"}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
			t.Fatal(err)
		}
		if store.input.OperationID == b.DeployOperationID || store.input.Action != action || store.input.CoreGeneration != 12 || store.input.LeaseGeneration != 15 {
			t.Fatal("Docker effect used old deploy or wrong action authority")
		}
	}
	if store.calls != 3 {
		t.Fatalf("authority calls %d", store.calls)
	}
	store.reject = true
	req := LifecycleRequest{Binding: b, Authority: a}
	if err := runner.Run(withAuthorityCheck(context.Background(), func(ctx context.Context) error { return runtime.checkLifecycleAuthority(ctx, req) }), "docker", []string{"restart", "same-cid"}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("rejected fresh command still reached Docker")
	}
	if len(base.runs) != 3 {
		t.Fatal("rejected authority reached underlying Docker runner")
	}
}
func TestLifecycleClientUnknownOnEOFOrMalformedSuccess(t *testing.T) {
	for _, mode := range []string{"eof", "invalid-success", "trailing-json"} {
		t.Run(mode, func(t *testing.T) {
			sock := filepath.Join(t.TempDir(), "lifecycle.sock")
			ln, err := net.Listen("unix", sock)
			if err != nil {
				t.Fatal(err)
			}
			server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if mode == "eof" {
					conn, _, _ := w.(http.Hijacker).Hijack()
					_ = conn.Close()
					return
				}
				_ = json.NewEncoder(w).Encode(LifecycleResponse{Success: true})
				if mode == "trailing-json" {
					_, _ = w.Write([]byte(`{}`))
				}
			})}
			go server.Serve(ln)
			defer server.Close()
			client, err := NewClient(ClientConfig{SocketPath: sock, ExpectedPID: int32(os.Getpid()), ExpectedUID: uint32(os.Getuid()), Timeout: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.ExecuteLifecycle(context.Background(), appcontracts.ImageLifecycleBinding{Action: appcontracts.ImageLifecycleRestart}, appcontracts.ImageLifecycleAuthorityInput{})
			if !errors.Is(err, appcontracts.ErrOutcomeUnknown) {
				t.Fatalf("post-dispatch malformed result must remain unknown: %v", err)
			}
		})
	}
}

func TestLifecyclePostWriteVerificationErrorIsUnknown(t *testing.T) {
	err := errors.New("post-write inspect failed without typed unknown")
	if lifecycleEffectFailure(err, false).OutcomeUnknown {
		t.Fatal("pre-effect rejection fabricated an unknown write")
	}
	response := lifecycleEffectFailure(err, true)
	if !response.OutcomeUnknown || response.Success {
		t.Fatal("unverified post-write result was terminal failure")
	}
}
