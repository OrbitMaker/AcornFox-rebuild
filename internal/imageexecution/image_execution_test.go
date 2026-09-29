package imageexecution

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	appcontracts "github.com/open-card/open-card/internal/application/contracts"
	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/packmanager"
	imageprovider "github.com/open-card/open-card/internal/providers/image"
	"github.com/open-card/open-card/internal/providers/registryhttp"
	"github.com/open-card/open-card/internal/providers/standalone"
)

type fakeStoreForAuthority struct {
	authorized            bool
	authErr               error
	facts                 appcontracts.AuthorityBindingFacts
	observationOperation  domain.ID
	observationDeployment domain.ID
	observationDigest     string
	observationRepository string
	observationCanonical  *appcontracts.CanonicalExecutionInput
}

func (f *fakeStoreForAuthority) BeginImageExecution(ctx context.Context, input appcontracts.BeginImageExecutionInput) (appcontracts.ImageExecutionBinding, error) {
	return appcontracts.ImageExecutionBinding{}, nil
}

func (f *fakeStoreForAuthority) AuthorizeImageExecution(ctx context.Context, input appcontracts.AuthorizeImageExecutionInput) (appcontracts.AuthorityBindingFacts, error) {
	if !f.authorized {
		if f.authErr != nil {
			return appcontracts.AuthorityBindingFacts{}, f.authErr
		}
		return appcontracts.AuthorityBindingFacts{}, appcontracts.ErrLeaseLost
	}
	return f.facts, nil
}

func (f *fakeStoreForAuthority) CommitImageExecutionResult(ctx context.Context, input appcontracts.CommitImageExecutionResultInput) error {
	return nil
}

func (f *fakeStoreForAuthority) FailImageExecution(ctx context.Context, input appcontracts.FailImageExecutionInput) error {
	return nil
}

func (f *fakeStoreForAuthority) RecordImageExecutionUnknown(ctx context.Context, input appcontracts.RecordImageExecutionUnknownInput) error {
	return nil
}

func (f *fakeStoreForAuthority) ReadImageObservationBinding(ctx context.Context, operationID, deploymentID domain.ID) (appcontracts.ImageObservationBinding, error) {
	if !f.observationOperation.Empty() && (operationID != f.observationOperation || deploymentID != f.observationDeployment) {
		repository := f.observationRepository
		if repository == "" {
			repository = "ghcr.io/stefanprodan/podinfo"
		}
		digest := f.observationDigest
		if digest == "" {
			digest = "sha256:72611294759dc6b304d1f3efa2d4b1de212ce422866244f31bc29f731e3b2079"
		}
		return appcontracts.ImageObservationBinding{}, errors.New("operation deployment relation not found")
	}
	repository := f.observationRepository
	if repository == "" {
		repository = "ghcr.io/stefanprodan/podinfo"
	}
	digest := f.observationDigest
	if digest == "" {
		digest = "sha256:72611294759dc6b304d1f3efa2d4b1de212ce422866244f31bc29f731e3b2079"
	}
	return appcontracts.ImageObservationBinding{
		ApplicationID:  f.facts.ApplicationID,
		EnvironmentID:  f.facts.EnvironmentID,
		ReleaseID:      f.facts.ReleaseID,
		Repository:     repository,
		Digest:         digest,
		ApprovedPort:   f.facts.ApprovedPort,
		PlanDigest:     f.facts.PlanDigest,
		OperationState: "running",
		ImageOrigin:    f.facts.ImageOrigin,
		SourceArtifact: f.facts.SourceArtifact,
		CanonicalInput: f.observationCanonical,
	}, nil
}

func TestCoreAuthorityServer_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "authority.sock")

	planDigest := "sha256:1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff"
	store := &fakeStoreForAuthority{
		authorized: true,
		facts: appcontracts.AuthorityBindingFacts{
			PlanDigest:    planDigest,
			ApplicationID: domain.ID("app-01"),
			EnvironmentID: domain.ID("env-01"),
			ReleaseID:     domain.ID("rel-01"),
			ApprovedPort:  9898,
		},
	}

	currentUID := uint32(os.Getuid())
	currentPID := int32(os.Getpid())

	server, err := NewCoreAuthorityServer(CoreAuthorityServerConfig{
		Store:                store,
		SocketPath:           sockPath,
		ExpectedContainerUID: currentUID,
		ExpectedContainerPID: currentPID,
	})
	if err != nil {
		t.Fatalf("NewCoreAuthorityServer: %v", err)
	}
	defer server.Close()

	// Wait for socket to appear
	time.Sleep(50 * time.Millisecond)

	runtime := &ContainerRuntime{
		authorityClient: packmanager.NewUnixHTTPClient(sockPath, currentPID, currentUID, nil, 2*time.Second),
	}

	req := DeployRequest{
		TaskID:          domain.ID("task-auth-01"),
		OperationID:     domain.ID("op-auth-01"),
		DeploymentID:    domain.ID("dep-auth-01"),
		PlanDigest:      planDigest,
		TaskOwner:       "worker-01",
		CoreGeneration:  1,
		LeaseGeneration: 1,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	resp, err := runtime.checkAuthority(ctx, req)
	if err != nil {
		t.Fatalf("expected authorized, got: %v", err)
	}
	if !resp.Authorized || resp.PlanDigest != planDigest || resp.ApprovedPort != 9898 {
		t.Fatalf("unexpected authority response: %+v", resp)
	}

	// Now make store reject authority
	store.authorized = false
	if _, err := runtime.checkAuthority(ctx, req); err == nil {
		t.Fatal("expected authority rejection, got nil")
	}
}

func TestContainerClient_ObserveRoundTrip(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "container.sock")

	currentUID := uint32(os.Getuid())
	currentPID := int32(os.Getpid())

	rawListener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer rawListener.Close()

	verifiedListener := &peerVerifiedListener{
		Listener:    rawListener,
		expectedUID: currentUID,
		expectedPID: currentPID,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/image/observe", func(w http.ResponseWriter, r *http.Request) {
		var req ObserveRequest
		if err := decodeStrictJSON(r.Body, &req); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ObserveResponse{
			Success:        true,
			Status:         "running",
			Running:        true,
			ContainerID:    "c-observed-123",
			ContainerName:  "acornfox-dep-obs-1",
			ImageID:        "sha256:5b85a3c2678f134440c9502b406b7d6fb8fa83842f1f513f5fb4ebcbe5e638b9",
			ManifestDigest: "sha256:72611294759dc6b304d1f3efa2d4b1de212ce422866244f31bc29f731e3b2079",
			StorageRef:     "image/test",
			ContentDigest:  "sha256:1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff",
			SizeBytes:      1024,
			HostPort:       39898,
			ContainerPort:  9898,
			ObservedAt:     time.Now().UTC(),
		})
	})

	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(verifiedListener) }()
	defer srv.Close()

	client, err := NewClient(ClientConfig{
		SocketPath:  sockPath,
		ExpectedPID: currentPID,
		ExpectedUID: currentUID,
		Timeout:     2 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	obs, err := client.ObserveDeployment(context.Background(), domain.ID("dep-obs-1"), domain.ID("op-obs-1"))
	if err != nil {
		t.Fatalf("ObserveDeployment failed: %v", err)
	}
	if !obs.Running || obs.ContainerID != "c-observed-123" || obs.HostPort != 39898 {
		t.Fatalf("unexpected observation: %+v", obs)
	}
}

func TestRuntimePeerBinding_ValidateAndLoad(t *testing.T) {
	dir := t.TempDir()
	validJSON := `{
		"version": "1.0",
		"installation_id": "inst-test-01",
		"container_socket": "/run/acornfox/container.sock",
		"authority_socket": "/run/acornfox/core-authority.sock",
		"core_uid": 1000,
		"core_pid": 1234,
		"core_exe_sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"core_start_time": "123456",
		"container_uid": 1000,
		"container_pid": 5678,
		"container_exe_sha": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		"container_start_time": "234567"
	}`

	validPath := filepath.Join(dir, "valid.json")
	if err := os.WriteFile(validPath, []byte(validJSON), 0o600); err != nil {
		t.Fatal(err)
	}

	binding, err := ParseRuntimePeerBinding([]byte(validJSON))
	if err != nil {
		t.Fatalf("ParseRuntimePeerBinding valid: %v", err)
	}
	if binding.CorePID != 1234 || binding.ContainerPID != 5678 {
		t.Fatalf("unexpected binding: %+v", binding)
	}

	// Test unconfigured empty path -> returns nil, nil
	unconf, err := LoadProtectedRuntimePeerBinding("")
	if err != nil || unconf != nil {
		t.Fatalf("expected nil for empty path, got unconf=%v err=%v", unconf, err)
	}

	// Test non-existent path -> returns nil, nil
	nonexist, err := LoadProtectedRuntimePeerBinding(filepath.Join(dir, "absent.json"))
	if err != nil || nonexist != nil {
		t.Fatalf("expected nil for absent file, got nonexist=%v err=%v", nonexist, err)
	}

	// Test invalid PID 0 rejection
	invalidJSON := strings.Replace(validJSON, `"core_pid": 1234`, `"core_pid": 0`, 1)
	if _, err := ParseRuntimePeerBinding([]byte(invalidJSON)); err == nil {
		t.Fatal("expected error for core_pid=0, got nil")
	}

	// Test invalid SHA rejection
	invalidSHAJSON := strings.Replace(validJSON, `"core_exe_sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"`, `"core_exe_sha": "short"`, 1)
	if _, err := ParseRuntimePeerBinding([]byte(invalidSHAJSON)); err == nil {
		t.Fatal("expected error for short core_exe_sha, got nil")
	}
}

type fakeDockerRunner struct {
	runs []string
	mu   sync.Mutex
	run  func([]string, io.Writer) error
}

func (f *fakeDockerRunner) Run(ctx context.Context, command string, args []string, stdout, stderr io.Writer) error {
	f.mu.Lock()
	f.runs = append(f.runs, strings.Join(args, " "))
	f.mu.Unlock()
	if f.run != nil {
		return f.run(args, stdout)
	}
	return nil
}

func TestContainerRuntime_RequestBoundAuthority_ConcurrencyAndRejection(t *testing.T) {
	runner := &authorizingCommandRunner{
		base: &fakeDockerRunner{},
	}

	// 1. Mutating command without authority in context must be rejected
	err := runner.Run(context.Background(), "docker", []string{"run", "image"}, nil, nil)
	if err == nil {
		t.Fatal("expected error for mutating command without authority context, got nil")
	}

	// 2. Read-only command (e.g. inspect) succeeds without authority context
	err = runner.Run(context.Background(), "docker", []string{"inspect", "container"}, nil, nil)
	if err != nil {
		t.Fatalf("read-only command should not require authority context: %v", err)
	}

	for _, args := range [][]string{{"volume", "inspect", "named-volume"}, {"network", "inspect", "named-network"}, {"container", "inspect", "--format", "{{json .}}", "container"}, {"image", "inspect", "image"}, {"network", "ls", "--filter", "name=^task-application-network$", "--format", "{{.ID}}"}, {"container", "ls", "--all", "--filter", "name=^/task-runtime-0123456789abcdefabcd$", "--format", "{{.Names}}"}, {"container", "ls", "--all", "--filter", "id=^" + strings.Repeat("a", 64) + "$", "--format", "{{.ID}}"}} {
		if err := runner.Run(context.Background(), "docker", args, nil, nil); err != nil {
			t.Fatalf("read-only inspect rejected: %v", err)
		}
	}
	for _, args := range [][]string{{"volume", "create", "volume"}, {"network", "rm", "network"}, {"unrecognized"}, {"network", "ls"}, {"network", "ls", "--filter", "name=task", "--format", "{{.ID}}"}, {"container", "ls", "--all"}, {"container", "ls", "--all", "--filter", "name=task", "--format", "{{.Names}}"}, {"container", "ls", "--all", "--filter", "id=^short$", "--format", "{{.ID}}"}} {
		if err := runner.Run(context.Background(), "docker", args, nil, nil); err == nil {
			t.Fatalf("unguarded command accepted: %v", args)
		}
	}
	// 3. Concurrent requests with distinct authority contexts
	var authACalled, authBCalled bool
	ctxA := withAuthorityCheck(context.Background(), func(ctx context.Context) error {
		authACalled = true
		return nil
	})
	ctxB := withAuthorityCheck(context.Background(), func(ctx context.Context) error {
		authBCalled = true
		return errors.New("authority B rejected")
	})

	errA := runner.Run(ctxA, "docker", []string{"run", "imageA"}, nil, nil)
	if errA != nil || !authACalled {
		t.Fatalf("expected A to succeed with authority A: %v", errA)
	}

	errB := runner.Run(ctxB, "docker", []string{"run", "imageB"}, nil, nil)
	if errB == nil || !authBCalled {
		t.Fatalf("expected B to fail with authority B rejection, got nil")
	}
}

func TestClient_EOFResponseReturnsTypedUnknown(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "eof.sock")

	currentUID := uint32(os.Getuid())
	currentPID := int32(os.Getpid())

	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	// Server immediately closes connection on POST /v1/image/deploy, producing EOF
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			buf := make([]byte, 1024)
			_, _ = conn.Read(buf)
			_ = conn.Close()
		}
	}()

	client, err := NewClient(ClientConfig{
		SocketPath:  sockPath,
		ExpectedPID: currentPID,
		ExpectedUID: currentUID,
		Timeout:     2 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	_, execErr := client.ExecuteDeployment(context.Background(), appcontracts.ImageExecutionBinding{
		DeploymentID: domain.ID("dep-eof-1"),
		ReleaseID:    domain.ID("rel-eof-1"),
		Plan: appcontracts.ImagePlan{
			ResolvedImage: appcontracts.ResolvedImage{
				Digest: "sha256:72611294759dc6b304d1f3efa2d4b1de212ce422866244f31bc29f731e3b2079",
			},
		},
	})

	if execErr == nil {
		t.Fatal("expected error on lost response, got nil")
	}
	if !errors.Is(execErr, appcontracts.ErrOutcomeUnknown) {
		t.Fatalf("expected typed ErrOutcomeUnknown on EOF response, got %v", execErr)
	}
}

func TestClient_InvalidSuccessReturnsTypedUnknown(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "invalid-success.sock")
	listener, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(DeployResponse{
			Success: true, ObservedAt: time.Now().UTC(),
			ManifestDigest: "sha256:" + strings.Repeat("1", 64),
		})
	})}
	go server.Serve(listener)
	defer server.Close()
	client, err := NewClient(ClientConfig{
		SocketPath: sock, ExpectedPID: int32(os.Getpid()), ExpectedUID: uint32(os.Getuid()), Timeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.ExecuteDeployment(context.Background(), appcontracts.ImageExecutionBinding{
		Plan: appcontracts.ImagePlan{ResolvedImage: appcontracts.ResolvedImage{Digest: "sha256:" + strings.Repeat("2", 64)}},
	})
	if !errors.Is(err, appcontracts.ErrOutcomeUnknown) {
		t.Fatalf("invalid post-effect success must reconcile, got %v", err)
	}
}

// Exercise the production receipt consumer against an authenticated Core server and real durable image store.
func TestContainerRuntime_VerifiedReceiptRecovery(t *testing.T) {
	dir := t.TempDir()
	socket := filepath.Join(dir, "receipt.sock")
	store := &fakeStoreForAuthority{authorized: true, observationOperation: "op-receipt", observationDeployment: "dep-receipt", facts: appcontracts.AuthorityBindingFacts{ApplicationID: "app-receipt", EnvironmentID: "env-receipt", ReleaseID: "release-receipt", ApprovedPort: 8080, PlanDigest: "sha256:" + strings.Repeat("a", 64)}}
	server, err := NewCoreAuthorityServer(CoreAuthorityServerConfig{Store: store, SocketPath: socket, ExpectedContainerUID: uint32(os.Getuid()), ExpectedContainerPID: int32(os.Getpid())})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	images, err := imageprovider.New(imageprovider.Config{Root: filepath.Join(dir, "images")})
	if err != nil {
		t.Fatal(err)
	}
	runtime := &ContainerRuntime{authorityClient: packmanager.NewUnixHTTPClient(socket, int32(os.Getpid()), uint32(os.Getuid()), nil, time.Second), imageStore: images}
	configBytes := []byte(`{"architecture":"amd64","os":"linux","config":{"Volumes":null}}`)
	layer := []byte("bounded registry fixture layer")
	digestBytes := func(value []byte) string { return fmt.Sprintf("sha256:%x", sha256.Sum256(value)) }
	config := digestBytes(configBytes)
	layerDigest := digestBytes(layer)
	manifest, err := json.Marshal(map[string]any{"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json", "config": map[string]any{"mediaType": "application/vnd.oci.image.config.v1+json", "digest": config, "size": len(configBytes)}, "layers": []map[string]any{{"mediaType": "application/vnd.oci.image.layer.v1.tar", "digest": layerDigest, "size": len(layer)}}})
	if err != nil {
		t.Fatal(err)
	}
	store.observationDigest = digestBytes(manifest)
	registryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v2/stefanprodan/podinfo/manifests/" + store.observationDigest:
			w.Header().Set("Docker-Content-Digest", store.observationDigest)
			w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
			_, _ = w.Write(manifest)
		case "/v2/stefanprodan/podinfo/blobs/" + config:
			_, _ = w.Write(configBytes)
		case "/v2/stefanprodan/podinfo/blobs/" + layerDigest:
			_, _ = w.Write(layer)
		default:
			http.NotFound(w, r)
		}
	}))
	defer registryServer.Close()
	store.observationRepository = strings.TrimPrefix(registryServer.URL, "http://") + "/stefanprodan/podinfo"
	runtime.registry, err = registryhttp.New(registryhttp.Config{BaseURL: registryServer.URL, ImageStore: images, TempRoot: dir})
	if err != nil {
		t.Fatal(err)
	}
	binding, err := store.ReadImageObservationBinding(context.Background(), "op-receipt", "dep-receipt")
	if err != nil {
		t.Fatal(err)
	}
	op := contracts.OperationContext{IdempotencyKey: "receipt-observe", Deadline: time.Now().Add(time.Minute)}
	image := domain.ImageDigest{Repository: binding.Repository, Digest: binding.Digest}
	input := appcontracts.CanonicalExecutionInput{AppName: "receipt-app", Repository: binding.Repository, ResolvedRef: binding.Digest, Port: 8080, Resources: appcontracts.RuntimeRequestedResources{CPUMillis: 500, MemoryBytes: 134217728, DiskReservationBytes: 268435456, PIDs: 64}}
	plan, err := appcontracts.ComputePlanDigest(input, binding.Digest)
	if err != nil {
		t.Fatal(err)
	}
	store.facts.PlanDigest = plan
	actualEngineID := binding.Digest
	backendFacts := `{"driver":"overlayfs","driver_status":[["driver-type","io.containerd.snapshotter.v1"]]}`
	networkCreated := false
	var actualName string
	var labels = map[string]string{}
	docker := &fakeDockerRunner{}
	docker.run = func(args []string, stdout io.Writer) error {
		switch args[0] {
		case "run":
			for i := 1; i+1 < len(args); i++ {
				if args[i] == "--name" {
					actualName = args[i+1]
				}
				if args[i] == "--label" {
					parts := strings.SplitN(args[i+1], "=", 2)
					labels[parts[0]] = parts[1]
				}
			}
		case "info":
			_, err := io.WriteString(stdout, backendFacts)
			return err
		case "rm":
			actualName = ""
		case "container":
			if args[1] == "ls" {
				return nil
			}
			if actualName == "" || (args[len(args)-1] != actualName && args[len(args)-1] != strings.Repeat("c", 64)) {
				return errors.New("container absent")
			}
			facts := map[string]any{"Id": strings.Repeat("c", 64), "Name": "/" + actualName, "Image": actualEngineID, "Config": map[string]any{"Labels": labels}, "NetworkSettings": map[string]any{"Networks": map[string]any{"receipt-application-network": map[string]string{"NetworkID": strings.Repeat("e", 64)}}, "Ports": map[string]any{"8080/tcp": []map[string]string{{"HostIp": "127.0.0.1", "HostPort": "39001"}}, "9797/tcp": nil}}, "State": map[string]any{"Running": true, "Status": "running"}, "HostConfig": map[string]any{"NetworkMode": "receipt-application-network", "CapDrop": []string{"ALL"}, "SecurityOpt": []string{"no-new-privileges=true"}, "RestartPolicy": map[string]any{"Name": "no"}, "Memory": 134217728, "MemorySwap": 134217728, "CpuPeriod": 100000, "CpuQuota": 50000, "PidsLimit": 64, "PortBindings": map[string]any{"8080/tcp": []map[string]string{{"HostIp": "127.0.0.1", "HostPort": "39001"}}}}}
			return json.NewEncoder(stdout).Encode(facts)
		case "image":
			_, err := io.WriteString(stdout, actualEngineID+`|{"Volumes":null}`)
			return err
		case "network":
			switch args[1] {
			case "ls":
				return nil
			case "create":
				networkCreated = true
			case "inspect":
				if !networkCreated {
					return errors.New("network absent")
				}
				return json.NewEncoder(stdout).Encode([]map[string]any{{"Id": strings.Repeat("e", 64), "Name": "receipt-application-network", "Driver": "bridge", "Internal": false, "Labels": map[string]string{"open-card.managed": "true", "open-card.task-prefix": "receipt", "open-card.network-profile": standalone.ApplicationLoopbackNetworkProfile}, "Options": map[string]string{"com.docker.network.bridge.gateway_mode_ipv4": "nat"}}})
			}

		}
		return nil
	}
	provider, err := standalone.New(standalone.Config{TaskPrefix: "receipt", NetworkProfile: standalone.ApplicationLoopbackNetworkProfile, WorkRoot: dir, ImageStore: images, Capacity: contracts.NewFakeCapacityProvider(true), Runner: &authorizingCommandRunner{base: docker}})
	if err != nil {
		t.Fatal(err)
	}
	runtime.standalone = provider
	runtime.locks = make(map[domain.ID]*sync.Mutex)
	deploy := DeployRequest{OperationID: "op-receipt", DeploymentID: "dep-receipt", ApplicationID: binding.ApplicationID, EnvironmentID: binding.EnvironmentID, ReleaseID: binding.ReleaseID, PlanDigest: plan, CanonicalInput: input, ResolvedImage: appcontracts.ResolvedImage{Repository: binding.Repository, Digest: binding.Digest}, TimeoutSeconds: 30}
	created := runtime.Deploy(context.Background(), deploy)
	if !created.Success {
		t.Fatalf("normal Deploy consumer failed: %#v", created)
	}
	wantConfigDigest, err := contracts.CanonicalAcornFoxRuntimeConfigDigest(contracts.AcornFoxRuntimeConfiguration{}, contracts.AcornFoxRuntimeRequestedResources{CPUMillis: 500, MemoryBytes: 134217728, DiskReservationBytes: 268435456, PIDs: 64}, 8080)
	if err != nil {
		t.Fatal(err)
	}
	if labels["open-card.config-digest"] != wantConfigDigest || created.ImageID != actualEngineID || created.ManifestDigest != binding.Digest {
		t.Fatalf("runtime config and OCI identities not bound: labels=%v receipt=%#v", labels, created)
	}
	reader, persisted, err := images.OpenOCI(context.Background(), image, op)
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	snapshot, err := provider.ObserveDeploymentSnapshot(context.Background(), contracts.ObserveRequest{DeploymentID: "dep-receipt", Operation: op})
	if err != nil {
		t.Fatal(err)
	}
	expectedSpec, err := mappedImageRuntimeSpec(deploy, domain.ImageDigest{Repository: binding.Repository, Digest: actualEngineID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.ObserveExpectedDeploymentSnapshot(context.Background(), contracts.ObserveRequest{DeploymentID: "dep-receipt", Operation: op}, expectedSpec); err != nil {
		t.Fatalf("approved expected spec rejected: %v", err)
	}
	changedDeploy := deploy
	changedDeploy.CanonicalInput.Environment = []appcontracts.RuntimeEnvironmentVariable{{Name: "APP_MODE", Value: "changed", Kind: "literal"}}
	wrongSpec, err := mappedImageRuntimeSpec(changedDeploy, expectedSpec.Image)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.ObserveExpectedDeploymentSnapshot(context.Background(), contracts.ObserveRequest{DeploymentID: "dep-receipt", Operation: op}, wrongSpec); err == nil {
		t.Fatal("different valid approved runtime config accepted")
	}
	lifecycleBinding := appcontracts.ImageLifecycleBinding{DeploymentID: deploy.DeploymentID, ReleaseID: deploy.ReleaseID, ApplicationID: deploy.ApplicationID, EnvironmentID: deploy.EnvironmentID, DeployOperationID: deploy.OperationID, PlanDigest: deploy.PlanDigest, ContainerID: created.ContainerID, ImageID: created.ImageID, ManifestDigest: created.ManifestDigest, HostPort: created.HostPort + 1, ContainerPort: created.ContainerPort, Action: appcontracts.ImageLifecycleStop, Plan: appcontracts.ImagePlan{CanonicalInput: input, ResolvedImage: deploy.ResolvedImage}}
	if _, err := runtime.lifecycleSnapshot(context.Background(), lifecycleBinding, op, snapshot, false); err == nil {
		t.Fatal("pre-effect lifecycle snapshot allowed original host-port drift")
	}
	observed := runtime.Observe(context.Background(), ObserveRequest{OperationID: "op-receipt", DeploymentID: "dep-receipt"})
	if !observed.Success || observed.ContainerName != actualName {
		t.Fatalf("actual Observe consumer: %#v", observed)
	}

	already := runtime.Deploy(context.Background(), deploy)
	if !already.Success || already.ContainerName != actualName {
		t.Fatalf("already-running Deploy consumer: %#v", already)
	}
	receipt, err := runtime.verifiedReceipt(context.Background(), "op-receipt", "dep-receipt", op, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if !receipt.Success || receipt.ManifestDigest != binding.Digest || receipt.ImageID != actualEngineID || receipt.ContainerName != actualName || receipt.ContentDigest != persisted.Evidence.Digest || receipt.StorageRef != persisted.StorageRef || receipt.SizeBytes != persisted.SizeBytes {
		t.Fatalf("incomplete verified receipt: %#v", receipt)
	}
	// Unknown reconciliation for a source-origin image must compare the full
	// original Core runtime configuration, not merely matching digest labels.
	sourceFact := appcontracts.SourceBuiltArtifactFact{ApplicationID: binding.ApplicationID, EnvironmentID: binding.EnvironmentID, Image: image, StorageRef: persisted.StorageRef, ArchiveSHA256: persisted.Evidence.Digest, SizeBytes: persisted.SizeBytes}
	store.facts.ImageOrigin = "source-build"
	store.facts.SourceArtifact = &sourceFact
	store.observationCanonical = &input
	if sourceObserved := runtime.Observe(context.Background(), ObserveRequest{OperationID: "op-receipt", DeploymentID: "dep-receipt"}); !sourceObserved.Success {
		t.Fatalf("matching source-origin runtime refused: %#v", sourceObserved)
	}
	drifted := input
	drifted.Resources.MemoryBytes *= 2
	driftDigest, err := appcontracts.ComputePlanDigest(drifted, binding.Digest)
	if err != nil {
		t.Fatal(err)
	}
	store.facts.PlanDigest = driftDigest
	store.observationCanonical = &drifted
	if sourceObserved := runtime.Observe(context.Background(), ObserveRequest{OperationID: "op-receipt", DeploymentID: "dep-receipt"}); sourceObserved.Success {
		t.Fatal("source-origin unknown recovery accepted wrong observed resource limit")
	}
	store.facts.PlanDigest = plan
	store.facts.ImageOrigin = "registryhttp"
	store.facts.SourceArtifact = nil
	store.observationCanonical = nil
	if _, err := runtime.verifiedReceipt(context.Background(), "wrong-operation", "dep-receipt", op, snapshot); err == nil {
		t.Fatal("unbound operation accepted")
	}
	snapshot.Image.Digest = "sha256:" + strings.Repeat("d", 64)
	if _, err := runtime.verifiedReceipt(context.Background(), "op-receipt", "dep-receipt", op, snapshot); err == nil {
		t.Fatal("engine config mismatch accepted")
	}
	snapshot.Image.Digest = actualEngineID
	// A malformed bound archive with its own valid storage receipt never falls back to the engine digest.
	badImages, err := imageprovider.New(imageprovider.Config{Root: filepath.Join(dir, "bad-images")})
	if err != nil {
		t.Fatal(err)
	}
	op.IdempotencyKey = "bad-receipt-store"
	if _, err := badImages.StoreOCI(context.Background(), contracts.StoreOCIRequest{Image: image, StorageKey: "bad-receipt", Archive: strings.NewReader("unreadable manifest"), Operation: op}); err != nil {
		t.Fatal(err)
	}
	runtime.imageStore = badImages
	// A nil registry makes any erroneous recovery fallthrough to pull fail this test.
	runtime.registry = nil
	docker.mu.Lock()
	effectsBefore := len(docker.runs)
	docker.mu.Unlock()
	badObserve := runtime.Observe(context.Background(), ObserveRequest{OperationID: "op-receipt", DeploymentID: "dep-receipt"})
	if badObserve.Success {
		t.Fatal("actual Observe accepted malformed archive")
	}
	badDeploy := runtime.Deploy(context.Background(), deploy)
	if badDeploy.Success || !badDeploy.OutcomeUnknown {
		t.Fatalf("actual already-running Deploy accepted malformed archive: %#v", badDeploy)
	}
	docker.mu.Lock()
	newCommands := append([]string(nil), docker.runs[effectsBefore:]...)
	docker.mu.Unlock()
	for _, command := range newCommands {
		if strings.HasPrefix(command, "run ") || strings.HasPrefix(command, "load ") || strings.HasPrefix(command, "network create") {
			t.Fatalf("bad receipt caused new effect: %s", command)
		}
	}
	// Bad receipt must terminate without new Docker effects.

	if _, err := runtime.verifiedReceipt(context.Background(), "op-receipt", "dep-receipt", op, snapshot); err == nil {
		t.Fatal("failed manifest receipt accepted")
	}
	// A vanished container exercises the actual provider's read-only ID absence helper.
	actualName = ""
	if err := provider.Destroy(withAuthorityCheck(context.Background(), func(ctx context.Context) error { _, err := runtime.checkAuthority(ctx, deploy); return err }), contracts.DestroyRequest{DeploymentID: deploy.DeploymentID, Operation: contracts.OperationContext{IdempotencyKey: "destroy-receipt", Deadline: time.Now().Add(time.Minute)}}); err != nil {
		t.Fatal(err)
	}
	absenceQueried := false
	for _, command := range docker.runs {
		if command == "container ls --all --filter id=^"+strings.Repeat("c", 64)+"$ --format {{.ID}}" {
			absenceQueried = true
		}
	}
	if !absenceQueried {
		t.Fatal("actual provider did not prove bounded container absence")
	}
	// Use the explicit classic backend for the next new deployment, preserving the prior fingerprint.
	backendFacts = `{"driver":"overlay2","driver_status":[["Backing Filesystem","extfs"]]}`
	actualEngineID = config
	// A genuinely new deployment reuses the complete stored manifest without contacting a registry.
	runtime.imageStore = images
	cached := deploy
	cached.OperationID, cached.DeploymentID = "op-cached", "dep-cached"
	store.observationOperation, store.observationDeployment = cached.OperationID, cached.DeploymentID
	reused := runtime.Deploy(context.Background(), cached)
	if !reused.Success || reused.ManifestDigest != binding.Digest || reused.ImageID != actualEngineID || reused.ContentDigest != persisted.Evidence.Digest {
		t.Fatalf("fresh deployment did not reuse verified archive: %#v", reused)
	}

	aliasReader, _, err := images.OpenOCI(context.Background(), domain.ImageDigest{Repository: binding.Repository, Digest: config}, op)
	if err != nil {
		t.Fatalf("classic locator archive alias absent: %v", err)
	}
	if err := aliasReader.Close(); err != nil {
		t.Fatal(err)
	}

	// New deployment archive read/close/parse or integrity failures must terminate before network and Docker effects.
	docker.mu.Lock()
	beforeBadFresh := len(docker.runs)
	docker.mu.Unlock()
	broken := deploy
	broken.OperationID, broken.DeploymentID = "op-broken-archive", "dep-broken-archive"
	store.observationOperation, store.observationDeployment = broken.OperationID, broken.DeploymentID
	runtime.imageStore = badImages
	if result := runtime.Deploy(context.Background(), broken); result.Success {
		t.Fatalf("malformed cached archive accepted: %#v", result)
	}
	for _, fault := range []struct {
		name  string
		read  bool
		close bool
	}{{"read", true, false}, {"close", false, true}} {
		broken.OperationID, broken.DeploymentID = domain.ID("op-"+fault.name), domain.ID("dep-"+fault.name)
		store.observationOperation, store.observationDeployment = broken.OperationID, broken.DeploymentID
		runtime.imageStore = receiptFaultStore{ImageStore: images, readFault: fault.read, closeFault: fault.close}
		if result := runtime.Deploy(context.Background(), broken); result.Success {
			t.Fatalf("cached archive %s failure accepted: %#v", fault.name, result)
		}
	}
	archivePaths, err := filepath.Glob(filepath.Join(dir, "images", "archives", "*", strings.TrimPrefix(binding.Digest, "sha256:")+".oci"))
	if err != nil || len(archivePaths) != 1 {
		t.Fatalf("archive path: %v %v", archivePaths, err)
	}
	if err := os.Chmod(archivePaths[0], 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(archivePaths[0], []byte("corrupt stored contents"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(archivePaths[0], 0440); err != nil {
		t.Fatal(err)
	}
	runtime.imageStore = images
	broken.OperationID, broken.DeploymentID = "op-corrupt", "dep-corrupt"
	store.observationOperation, store.observationDeployment = broken.OperationID, broken.DeploymentID
	if result := runtime.Deploy(context.Background(), broken); result.Success {
		t.Fatalf("corrupt cached archive accepted: %#v", result)
	}
	docker.mu.Lock()
	afterBadFresh := append([]string(nil), docker.runs[beforeBadFresh:]...)
	docker.mu.Unlock()
	if len(afterBadFresh) != 0 {
		t.Fatalf("bad fresh archive reached Docker: %v", afterBadFresh)
	}

}

// Preserve real store verification while injecting reader errors at the consumer boundary.
type receiptFaultStore struct {
	contracts.ImageStore
	readFault, closeFault bool
}

func (s receiptFaultStore) OpenOCI(ctx context.Context, image domain.ImageDigest, op contracts.OperationContext) (io.ReadCloser, contracts.StoreOCIResult, error) {
	reader, result, err := s.ImageStore.OpenOCI(ctx, image, op)
	if err != nil {
		return nil, result, err
	}
	return receiptFaultReader{ReadCloser: reader, readFault: s.readFault, closeFault: s.closeFault}, result, nil
}

type receiptFaultReader struct {
	io.ReadCloser
	readFault, closeFault bool
}

func (r receiptFaultReader) Read(p []byte) (int, error) {
	if r.readFault {
		return 0, errors.New("injected archive read failure")
	}
	return r.ReadCloser.Read(p)
}
func (r receiptFaultReader) Close() error {
	err := r.ReadCloser.Close()
	if err == nil && r.closeFault {
		return errors.New("injected archive close failure")
	}
	return err
}
