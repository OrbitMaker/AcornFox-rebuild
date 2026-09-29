//go:build integration && linux

package buildkit_test

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/acornfox/acornfox/internal/application"
	"github.com/acornfox/acornfox/internal/contracts"
	"github.com/acornfox/acornfox/internal/domain"
	"github.com/acornfox/acornfox/internal/foundation"
	"github.com/acornfox/acornfox/internal/importers/dockerfile"
	buildkit "github.com/acornfox/acornfox/internal/providers/buildkit"
	imageprovider "github.com/acornfox/acornfox/internal/providers/image"
)

const afbBuildWorkerGate = "OPEN_CARD_AFB_BUILD_WORKER_TEST"
const afbBuildWorkerNetworkProbe = "OPEN_CARD_AFB_BUILD_WORKER_NETWORK_PROBE"
const afbBuildWorkerControlAddress = "OPEN_CARD_AFB_BUILD_WORKER_CONTROL_ADDRESS"
const afbBuildWorkerSystemdUnit = "OPEN_CARD_AFB_BUILD_WORKER_SYSTEMD_UNIT"

func TestAcornFoxRealOfflineBuildWorker(t *testing.T) {
	worker, ok := acornFoxBuildWorkerConfig(t)
	if !ok {
		return
	}
	root := t.TempDir()
	workspaceRoot := filepath.Join(root, "sources")
	workspace := filepath.Join(workspaceRoot, "fixture")
	if err := os.MkdirAll(workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "Dockerfile"), []byte("FROM scratch\nCOPY hello.txt /hello.txt\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "hello.txt"), []byte("hello from AcornFox\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	contentDigest, err := foundation.HashDirectory(workspace)
	if err != nil {
		t.Fatal(err)
	}
	source := domain.SourceRevision{ID: "src_afb_build_03a", ApplicationID: "app_afb_build_03a", Kind: domain.SourceUpload, Locator: "upload://afb-build-03a-fixture", ContentDigest: "sha256:" + contentDigest, WorkspaceRef: workspace, CreatedAt: time.Now().UTC(), Immutable: true}
	definition, err := dockerfile.Import(source)
	if err != nil || definition.Status != contracts.AcornFoxDockerfileReady {
		t.Fatalf("root Dockerfile definition=%#v err=%v", definition, err)
	}
	request, err := (application.AcornFoxBuildBinder{}).Bind(definition, source, "afb-build-03a-real-offline", "acornfox.local/fixture", "afb-build-03a-real-offline", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	request.Capacity = &contracts.CapacityLease{ID: "lease-afb-build-03a", Scope: contracts.CapacityBuild, Resources: request.Resources, ExpiresAt: time.Now().Add(5 * time.Minute)}
	store, err := imageprovider.New(imageprovider.Config{Root: filepath.Join(root, "oci")})
	if err != nil {
		t.Fatal(err)
	}
	logs := &acornFoxFileLogSink{root: filepath.Join(root, "logs")}
	provider, err := buildkit.New(buildkit.Config{Command: worker.command, Builder: worker.builder, Address: worker.address, WorkspaceRoot: workspaceRoot, WorkRoot: filepath.Join(root, "work"), ImageStore: store, Capacity: acornFoxBuildCapacity{}, LogSink: logs, RequireLogSink: true})
	if err != nil {
		t.Fatalf("worker configuration rejected: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	result, err := provider.Build(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if result.Artifact == nil || !strings.HasPrefix(result.Artifact.Image.Digest, "sha256:") || result.Artifact.OCIStorageRef == "" || result.LogRef == "" {
		t.Fatalf("real build result is incomplete: %#v", result)
	}
	if data, err := os.ReadFile(result.LogRef); err != nil || data == nil {
		t.Fatalf("durable build log is unavailable: err=%v", err)
	}
	if !hasEvidenceLocator(result.Evidence.Refs, "build.log", result.LogRef) {
		t.Fatalf("durable log reference is absent from evidence: %#v", result.Evidence)
	}
	archive, stored, err := store.OpenOCI(ctx, result.Artifact.Image, contracts.OperationContext{IdempotencyKey: "afb-build-03a-open-oci"})
	if err != nil {
		t.Fatal(err)
	}
	contents, readErr := io.ReadAll(archive)
	closeErr := archive.Close()
	if readErr != nil || closeErr != nil || len(contents) == 0 || stored.StorageRef != result.Artifact.OCIStorageRef {
		t.Fatalf("stored immutable OCI is not reopenable: bytes=%d read=%v close=%v stored=%#v", len(contents), readErr, closeErr, stored)
	}
	entries, err := os.ReadDir(filepath.Join(root, "work"))
	if err != nil || len(entries) != 0 {
		t.Fatalf("provider left transient build work: entries=%#v err=%v", entries, err)
	}
}

func TestAcornFoxRealOfflineBuildWorkerBlocksRemoteADD(t *testing.T) {
	worker, ok := acornFoxBuildWorkerConfig(t)
	if !ok {
		return
	}
	control := newAcornFoxPositiveControl(t, worker.controlAddress)
	defer control.close(t)
	control.assertReachable(t)
	control.requests.Store(0)
	request, provider, logRoot := newAcornFoxWorkerBuild(t, worker, "FROM scratch\nADD "+control.url+" /payload\n", "")
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	result, err := provider.Build(ctx, request)
	if err == nil || result.Artifact != nil || result.LogRef != "" {
		t.Fatalf("remote ADD produced a successful build claim: result=%#v err=%v", result, err)
	}
	if control.requests.Load() != 0 {
		t.Fatalf("BuildKit private network reached task positive control %d times", control.requests.Load())
	}
	if _, statErr := os.Stat(logRoot); !os.IsNotExist(statErr) {
		t.Fatalf("remote ADD produced durable build logs: %v", statErr)
	}
}

func TestAcornFoxRealOfflineBuildWorkerProbeReportsAllDenied(t *testing.T) {
	worker, ok := acornFoxBuildWorkerConfig(t)
	if !ok {
		return
	}
	control := newAcornFoxPositiveControl(t, worker.controlAddress)
	defer control.close(t)
	control.assertReachable(t)
	control.requests.Store(0)
	nonce := make([]byte, 16)
	if _, err := cryptorand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	probeControlURL := control.url + "?probe_nonce=" + hex.EncodeToString(nonce)
	probeArguments, err := json.Marshal([]string{"/network-probe", "https://example.com/", "http://127.0.0.1:1/", "http://169.254.169.254/latest/meta-data/", probeControlURL})
	if err != nil {
		t.Fatal(err)
	}
	request, provider, _ := newAcornFoxWorkerBuild(t, worker, "FROM scratch\nCOPY network-probe /network-probe\nRUN "+string(probeArguments)+"\n", worker.probe)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	result, err := provider.Build(ctx, request)
	if err != nil || result.Artifact == nil || result.LogRef == "" {
		t.Fatalf("network probe build did not succeed with a durable claim: result=%#v err=%v", result, err)
	}
	log, err := os.ReadFile(result.LogRef)
	if err != nil || !strings.Contains(string(log), "AFB_NETWORK_PROBE all_attempted_all_denied") {
		t.Fatalf("network probe did not emit all-denied marker: err=%v log=%q", err, log)
	}
	if control.requests.Load() != 0 {
		t.Fatalf("network probe reached task positive control %d times", control.requests.Load())
	}
}

func newAcornFoxWorkerBuild(t *testing.T, worker acornFoxWorker, contents, probePath string) (contracts.BuildRequest, *buildkit.Provider, string) {
	t.Helper()
	root := t.TempDir()
	workspaceRoot := filepath.Join(root, "sources")
	workspace := filepath.Join(workspaceRoot, "fixture")
	if err := os.MkdirAll(workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "Dockerfile"), []byte(contents), 0o400); err != nil {
		t.Fatal(err)
	}
	if probePath != "" {
		probe := readAcornFoxNetworkProbe(t, probePath)
		if err := os.WriteFile(filepath.Join(workspace, "network-probe"), probe, 0o500); err != nil {
			t.Fatal(err)
		}
	}
	digest, err := foundation.HashDirectory(workspace)
	if err != nil {
		t.Fatal(err)
	}
	source := domain.SourceRevision{ID: "src_afb_build_03a_hostile", ApplicationID: "app_afb_build_03a_hostile", Kind: domain.SourceUpload, Locator: "upload://afb-build-03a-hostile", ContentDigest: "sha256:" + digest, WorkspaceRef: workspace, CreatedAt: time.Now().UTC(), Immutable: true}
	definition, err := dockerfile.Import(source)
	if err != nil || definition.Status != contracts.AcornFoxDockerfileReady {
		t.Fatalf("hostile Dockerfile definition=%#v err=%v", definition, err)
	}
	request, err := (application.AcornFoxBuildBinder{}).Bind(definition, source, "afb-build-03a-hostile", "acornfox.local/hostile", "afb-build-03a-hostile", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	request.Capacity = &contracts.CapacityLease{ID: "lease-afb-build-03a-hostile", Scope: contracts.CapacityBuild, Resources: request.Resources, ExpiresAt: time.Now().Add(5 * time.Minute)}
	store, err := imageprovider.New(imageprovider.Config{Root: filepath.Join(root, "oci")})
	if err != nil {
		t.Fatal(err)
	}
	logRoot := filepath.Join(root, "logs")
	provider, err := buildkit.New(buildkit.Config{Command: worker.command, Builder: worker.builder, Address: worker.address, WorkspaceRoot: workspaceRoot, WorkRoot: filepath.Join(root, "work"), ImageStore: store, Capacity: acornFoxBuildCapacity{}, LogSink: &acornFoxFileLogSink{root: logRoot}, RequireLogSink: true})
	if err != nil {
		t.Fatal(err)
	}
	return request, provider, logRoot
}

type acornFoxPositiveControl struct {
	listener net.Listener
	server   *http.Server
	url      string
	requests atomic.Int64
}

func newAcornFoxPositiveControl(t *testing.T, address string) *acornFoxPositiveControl {
	t.Helper()
	listener, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatalf("bind task positive control: %v", err)
	}
	control := &acornFoxPositiveControl{listener: listener, url: "http://" + address + "/afb-build-03a-control"}
	control.server = &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		control.requests.Add(1)
		writer.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(writer, "acornfox-positive-control\n")
	})}
	go func() { _ = control.server.Serve(listener) }()
	return control
}

func (c *acornFoxPositiveControl) assertReachable(t *testing.T) {
	t.Helper()
	client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{Proxy: nil}}
	response, err := client.Get(c.url)
	if err != nil {
		t.Fatalf("ordinary guest namespace cannot reach positive control: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || c.requests.Load() != 1 {
		t.Fatalf("positive control did not observe ordinary namespace reachability: status=%d count=%d", response.StatusCode, c.requests.Load())
	}
}

func (c *acornFoxPositiveControl) close(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := c.server.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
}

func readAcornFoxNetworkProbe(t *testing.T, value string) []byte {
	t.Helper()
	path, err := filepath.Abs(value)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o111 == 0 || info.Size() < 1 || info.Size() > 10<<20 {
		t.Fatal("network probe must be a bounded executable regular file")
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return contents
}

type acornFoxWorker struct {
	command, address, builder, probe, controlAddress, systemdUnit string
}

func acornFoxBuildWorkerConfig(t *testing.T) (acornFoxWorker, bool) {
	t.Helper()
	if strings.TrimSpace(os.Getenv(afbBuildWorkerGate)) == "" {
		t.Skip(afbBuildWorkerGate + " is required for an authorized task worker")
	}
	if os.Getenv(afbBuildWorkerGate) != "enabled" {
		t.Fatal(afbBuildWorkerGate + " must equal enabled")
	}
	worker := acornFoxWorker{command: strings.TrimSpace(os.Getenv("OPEN_CARD_AFB_BUILD_WORKER_COMMAND")), address: strings.TrimSpace(os.Getenv("OPEN_CARD_AFB_BUILD_WORKER_ADDRESS")), builder: strings.TrimSpace(os.Getenv("OPEN_CARD_AFB_BUILD_WORKER_BUILDER")), probe: strings.TrimSpace(os.Getenv(afbBuildWorkerNetworkProbe)), controlAddress: strings.TrimSpace(os.Getenv(afbBuildWorkerControlAddress)), systemdUnit: strings.TrimSpace(os.Getenv(afbBuildWorkerSystemdUnit))}
	if worker.command == "" || worker.address == "" || worker.builder == "" || worker.probe == "" || worker.controlAddress == "" || worker.systemdUnit == "" {
		t.Fatal("worker command, address, builder, network probe, control address, and systemd unit are required")
	}
	if !strings.HasPrefix(worker.address, "unix:///run/open-card-buildkit/") || strings.Contains(worker.address, "..") || strings.ContainsAny(worker.address, "\r\n\x00 ") {
		t.Fatal("task worker address must be the bounded BuildKit unix socket")
	}
	if !safeAcornFoxSystemdUnit(worker.systemdUnit) {
		t.Fatal("task worker systemd unit is invalid")
	}
	verifyAcornFoxPrivateNetwork(t, worker.systemdUnit)
	validateAcornFoxControlAddress(t, worker.controlAddress)
	return worker, true
}

func safeAcornFoxSystemdUnit(value string) bool {
	return strings.HasSuffix(value, ".service") && strings.Trim(value, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-@") == ""
}

func verifyAcornFoxPrivateNetwork(t *testing.T, unit string) {
	t.Helper()
	output, err := exec.Command("systemctl", "show", "--property=PrivateNetwork", "--value", unit).Output()
	if err != nil || strings.TrimSpace(string(output)) != "yes" {
		t.Fatal("BuildKit systemd unit must attest PrivateNetwork=yes")
	}
}

func validateAcornFoxControlAddress(t *testing.T, address string) {
	t.Helper()
	host, port, err := net.SplitHostPort(address)
	parsedPort, parseErr := net.LookupPort("tcp", port)
	ip := net.ParseIP(host)
	if err != nil || parseErr != nil || parsedPort < 1 || ip == nil || !ip.IsPrivate() {
		t.Fatal("task worker control address must be an exact private IP and TCP port")
	}
}

type acornFoxFileLogSink struct{ root string }

func (s *acornFoxFileLogSink) StoreBuildLog(_ context.Context, request contracts.BuildRequest, content string) (string, error) {
	if err := os.MkdirAll(s.root, 0o700); err != nil {
		return "", err
	}
	path := filepath.Join(s.root, request.BuildID.String()+".log")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		return "", err
	}
	return path, nil
}

type acornFoxBuildCapacity struct{}

func (acornFoxBuildCapacity) Metadata(context.Context) contracts.ProviderMetadata {
	return contracts.ProviderMetadata{Name: "afb-build-03a-test-capacity", Version: "v1", ContractVersion: contracts.ContractAPIVersion, Capabilities: contracts.NewCapabilitySet(contracts.CapabilityCapacityCheck, contracts.CapabilityCapacityReserve)}
}
func (acornFoxBuildCapacity) Preflight(_ context.Context, request contracts.CapacityRequest) (contracts.CapacitySnapshot, contracts.Evidence, error) {
	return contracts.CapacitySnapshot{Scope: request.Scope}, contracts.Evidence{Redacted: true}, nil
}
func (acornFoxBuildCapacity) Reserve(_ context.Context, request contracts.CapacityRequest) (contracts.CapacityLease, error) {
	return contracts.CapacityLease{ID: "lease-" + request.Operation.IdempotencyKey, Scope: request.Scope, Resources: request.Resources, ExpiresAt: time.Now().Add(time.Minute)}, nil
}
func (acornFoxBuildCapacity) Activate(context.Context, contracts.CapacityLease, contracts.OperationContext) error {
	return nil
}
func (acornFoxBuildCapacity) Release(context.Context, contracts.CapacityLease, contracts.OperationContext) error {
	return nil
}

func hasEvidenceLocator(refs []domain.EvidenceRef, kind, locator string) bool {
	for _, reference := range refs {
		if reference.Kind == kind && reference.Locator == locator {
			return true
		}
	}
	return false
}

var _ buildkit.BuildLogSink = (*acornFoxFileLogSink)(nil)
var _ contracts.CapacityProvider = acornFoxBuildCapacity{}
