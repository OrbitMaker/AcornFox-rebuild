package sqlite

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/acornfox/acornfox/internal/application"
	appcontracts "github.com/acornfox/acornfox/internal/application/contracts"
	"github.com/acornfox/acornfox/internal/gatewayexecution"
	"github.com/acornfox/acornfox/internal/providers/acornfoxroute"
)

// This one disposable fixture crosses real SQLite transactions and attested
// Unix HTTP sockets. Its Caddy Admin endpoint is a local fake, not a public
// Caddy, DNS or TLS acceptance result.
func TestImagePublicAccessGatewayApprovedUnixProjection(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	s, admin, confirm := setupExecutionStore(t)
	deployTask, ok, err := s.ClaimTask(ctx, appcontracts.ClaimTaskRequest{Kinds: []string{"image.deploy"}, Owner: "deploy-fixture", Now: time.Now().UTC(), LeasePolicy: appcontracts.LeasePolicy{Duration: time.Minute, MaxAttempts: 3}})
	if err != nil || !ok {
		t.Fatalf("claim deploy: %v", err)
	}
	deploy, err := s.BeginImageExecution(ctx, appcontracts.BeginImageExecutionInput{TaskID: deployTask.ID, OperationID: confirm.OperationID, Owner: "deploy-fixture", CoreGeneration: deployTask.CoreGeneration, LeaseGeneration: deployTask.LeaseGeneration})
	if err != nil {
		t.Fatal(err)
	}
	image := "sha256:72611294759dc6b304d1f3efa2d4b1de212ce422866244f31bc29f731e3b2079"
	if err := s.CommitImageExecutionResult(ctx, appcontracts.CommitImageExecutionResultInput{TaskID: deployTask.ID, OperationID: confirm.OperationID, DeploymentID: deploy.DeploymentID, ReleaseID: deploy.ReleaseID, Owner: "deploy-fixture", CoreGeneration: deployTask.CoreGeneration, LeaseGeneration: deployTask.LeaseGeneration, ContainerID: "gateway-fixture-container", ImageID: image, ManifestDigest: image, Artifact: appcontracts.StorageArtifactReceipt{StorageRef: "fixture/image", ContentDigest: image, SizeBytes: 123}, HostPort: 39898, ContainerPort: 9898, ObservedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	base := t.TempDir()
	if err := os.Chmod(base, 0o700); err != nil {
		t.Fatal(err)
	}
	lockDir := filepath.Join(base, "trust")
	if err := os.Mkdir(lockDir, 0o750); err != nil {
		t.Fatal(err)
	}
	lockPath := filepath.Join(lockDir, "gateway-projection.lock")
	if err := os.WriteFile(lockPath, nil, 0o660); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(lockPath, 0o660); err != nil {
		t.Fatal(err)
	}
	lock := application.GatewayProjectionLock{Path: lockPath, ExpectedOwnerUID: uint32(os.Getuid()), IPCGID: uint32(os.Getgid())}
	commands := application.ImagePublicAccessCommands{Store: s, Lock: lock}
	request := appcontracts.ImagePublicAccessRequest{DeploymentID: deploy.DeploymentID, Hostname: "app.customer.example", Action: appcontracts.ImagePublicAccessEnsure, IdempotencyKey: "gateway-fixture-key"}
	binding, err := commands.Begin(ctx, admin, request)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := commands.Begin(ctx, admin, request)
	if err != nil || replay.OperationID != binding.OperationID || replay.TaskID != binding.TaskID {
		t.Fatalf("durable same-key command replay: %v %+v", err, replay)
	}
	authorityDir := filepath.Join(base, "core-ipc")
	gatewayDir := filepath.Join(base, "gateway-ipc")
	adminDir := filepath.Join(base, "edge-admin")
	for _, dir := range []string{authorityDir, gatewayDir, adminDir} {
		if err := os.Mkdir(dir, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	coreSocket := filepath.Join(authorityDir, "authority.sock")
	gatewaySocket := filepath.Join(gatewayDir, "gateway.sock")
	adminSocket := filepath.Join(adminDir, "admin.sock")
	if err := os.Chmod(adminDir, os.ModeSetgid|0o750); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("unix", adminSocket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := os.Chmod(adminSocket, 0o660); err != nil {
		t.Fatal(err)
	}
	current := []byte(`{"@id":"acornfox-app-routes","handler":"subroute","routes":[]}`)
	var mu sync.Mutex
	methods := []string{}
	caddy := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.URL.Path != "/id/"+acornfoxroute.SubtreeID {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		methods = append(methods, r.Method)
		w.Header().Set("ETag", `"fixture-v1"`)
		switch r.Method {
		case http.MethodGet:
			_, _ = w.Write(current)
		case http.MethodPatch:
			if r.Header.Get("If-Match") != `"fixture-v1"` {
				w.WriteHeader(http.StatusPreconditionFailed)
				return
			}
			current, _ = io.ReadAll(io.LimitReader(r.Body, 1<<20))
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})}
	go caddy.Serve(listener)
	defer caddy.Close()
	peer := gatewayexecution.ServerConfig{PeerUID: uint32(os.Getuid())}
	peer.SocketPath = coreSocket
	coreServer, err := gatewayexecution.NewAuthorityServer(peer, s)
	if err != nil {
		t.Fatal(err)
	}
	defer coreServer.Close()
	authority, err := gatewayexecution.NewAuthorityClient(gatewayexecution.ClientConfig{SocketPath: coreSocket, PeerUID: peer.PeerUID})
	if err != nil {
		t.Fatal(err)
	}
	source := &gatewayexecution.Source{Authority: authority, Lock: lock}
	provider, err := acornfoxroute.New(acornfoxroute.Config{CustomOnly: true, Source: source, AdminUnixSocket: adminSocket, AdminSocketUID: uint32(os.Getuid()), AdminSocketGID: uint32(os.Getgid())})
	if err != nil {
		t.Fatal(err)
	}
	defer provider.Close()
	peer.SocketPath = gatewaySocket
	gatewayServer, err := gatewayexecution.NewExecutionServer(peer, &gatewayexecution.Runtime{Authority: authority, Projector: provider})
	if err != nil {
		t.Fatal(err)
	}
	defer gatewayServer.Close()
	client, err := gatewayexecution.NewClient(gatewayexecution.ClientConfig{SocketPath: gatewaySocket, PeerUID: peer.PeerUID})
	if err != nil {
		t.Fatal(err)
	}
	// An unclaimed/stale lease reaches the Unix Gateway but cannot obtain Core
	// authority. It must never touch the Caddy Admin socket.
	bad := appcontracts.ImagePublicAccessAuthority{BeginImageExecutionInput: appcontracts.BeginImageExecutionInput{TaskID: binding.TaskID, OperationID: binding.OperationID, Owner: "not-the-claim-owner", CoreGeneration: 1, LeaseGeneration: 1}, ApprovalID: binding.ApprovalID, DeploymentID: binding.DeploymentID, EndpointVersion: binding.EndpointVersion, ContainerID: binding.ContainerID, Action: binding.Action}
	if _, err := client.ExecuteImagePublicAccess(ctx, binding, bad); err == nil {
		t.Fatal("old lease crossed Core authority")
	}
	mu.Lock()
	preWrites := len(methods)
	mu.Unlock()
	if preWrites != 0 {
		t.Fatal("bad lease reached Caddy")
	}
	worker := &application.ImagePublicAccessWorker{Store: s, Tasks: s, Gateway: client, WorkerID: "gateway-fixture", LeaseDuration: time.Minute}
	if handled, err := worker.PollOnce(ctx); err != nil || !handled {
		t.Fatalf("approved SQLite task to Unix Gateway/Caddy to durable result: handled=%v err=%v", handled, err)
	}
	result, err := s.GetImagePublicAccess(ctx, admin, binding.DeploymentID)
	if err != nil || result.Command.State != "succeeded" || result.LocalRouteState != "configured" || result.ObservedAt == nil {
		t.Fatalf("durable projection result: %v %+v", err, result)
	}
	mu.Lock()
	patched := 0
	for _, method := range methods {
		if method == http.MethodPatch {
			patched++
		}
	}
	body := append([]byte(nil), current...)
	mu.Unlock()
	if patched != 1 || !strings.Contains(string(body), binding.Hostname) || !json.Valid(body) {
		t.Fatal("approved custom hostname was not projected exactly once")
	}
	terminalReplay, err := commands.Begin(ctx, admin, request)
	if err != nil || terminalReplay.OperationID != binding.OperationID || terminalReplay.State != "pending" {
		t.Fatalf("terminal same-key replay lost original response: %v %+v", err, terminalReplay)
	}
}
