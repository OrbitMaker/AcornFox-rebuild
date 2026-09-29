package imageexecution

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	appcontracts "github.com/acornfox/acornfox/internal/application/contracts"
	"github.com/acornfox/acornfox/internal/contracts"
	"github.com/acornfox/acornfox/internal/domain"
	"github.com/acornfox/acornfox/internal/packmanager"
	imageprovider "github.com/acornfox/acornfox/internal/providers/image"
)

func builtArchiveFixture(t *testing.T) ([]byte, string) {
	t.Helper()
	digest := func(raw []byte) string { sum := sha256.Sum256(raw); return "sha256:" + hex.EncodeToString(sum[:]) }
	config := []byte(`{"architecture":"amd64","os":"linux","config":{"Cmd":["/app"]}}`)
	layer := bytes.Repeat([]byte("bounded-layer"), 8<<10)
	manifest, err := json.Marshal(map[string]any{"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json", "config": map[string]any{"mediaType": "application/vnd.oci.image.config.v1+json", "digest": digest(config), "size": len(config)}, "layers": []any{map[string]any{"mediaType": "application/vnd.oci.image.layer.v1.tar", "digest": digest(layer), "size": len(layer)}}})
	if err != nil {
		t.Fatal(err)
	}
	manifestDigest := digest(manifest)
	index, err := json.Marshal(map[string]any{"schemaVersion": 2, "manifests": []any{map[string]any{"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": manifestDigest, "size": len(manifest), "platform": map[string]any{"os": "linux", "architecture": "amd64"}}}})
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	w := tar.NewWriter(&out)
	for _, entry := range []struct {
		name string
		body []byte
	}{{"oci-layout", []byte(`{"imageLayoutVersion":"1.0.0"}`)}, {"index.json", index}, {"blobs/sha256/" + strings.TrimPrefix(manifestDigest, "sha256:"), manifest}, {"blobs/sha256/" + strings.TrimPrefix(digest(config), "sha256:"), config}, {"blobs/sha256/" + strings.TrimPrefix(digest(layer), "sha256:"), layer}} {
		if err := w.WriteHeader(&tar.Header{Name: entry.name, Mode: 0444, Size: int64(len(entry.body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(entry.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes(), manifestDigest
}

// Same-process attested Unix fixture proves the real Container client/server,
// Core authority, destination FileImageStore and byte-based OCI validator.
// It is not an installed multi-role or BuildKit-produced image test.
func TestBuiltOCIImportOriginalAuthorityAndDestinationReceipt(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	archive, manifestDigest := builtArchiveFixture(t)
	sourceRoot, destinationRoot := filepath.Join(root, "source"), filepath.Join(root, "container")
	for _, path := range []string{sourceRoot, destinationRoot} {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	source, err := imageprovider.New(imageprovider.Config{Root: sourceRoot})
	if err != nil {
		t.Fatal(err)
	}
	destination, err := imageprovider.New(imageprovider.Config{Root: destinationRoot})
	if err != nil {
		t.Fatal(err)
	}
	image := domain.ImageDigest{Repository: "ghcr.io/acme/built", Digest: manifestDigest}
	stored, err := source.StoreOCI(ctx, contracts.StoreOCIRequest{Image: image, StorageKey: "original-build", Archive: bytes.NewReader(archive), Operation: contracts.OperationContext{IdempotencyKey: "source-fixture"}})
	if err != nil {
		t.Fatal(err)
	}
	fact := appcontracts.SourceBuiltArtifactFact{AdminID: "admin-original", ApplicationID: "app-original", EnvironmentID: "env-original", BuildIntentID: "sbi-original", BuildID: "build-original", SourceRevisionID: "src-original", BuildPlanID: "plan-original", ArtifactID: "art-original", Image: image, StorageRef: stored.StorageRef, ArchiveSHA256: stored.Evidence.Digest, SizeBytes: stored.SizeBytes}
	coreSocket := filepath.Join(root, "core.sock")
	coreStore := &fakeStoreForAuthority{authorized: true, facts: appcontracts.AuthorityBindingFacts{PlanDigest: "sha256:" + strings.Repeat("a", 64), ApplicationID: fact.ApplicationID, EnvironmentID: fact.EnvironmentID, ReleaseID: "rel-original", ApprovedPort: 8080, ImageOrigin: "source-build", SourceArtifact: &fact}}
	authority, err := NewCoreAuthorityServer(CoreAuthorityServerConfig{Store: coreStore, SocketPath: coreSocket, ExpectedContainerUID: uint32(os.Getuid()), ExpectedContainerPID: int32(os.Getpid())})
	if err != nil {
		t.Fatal(err)
	}
	defer authority.Close()
	runtime := &ContainerRuntime{imageStore: destination, authorityClient: packmanager.NewUnixHTTPClient(coreSocket, int32(os.Getpid()), uint32(os.Getuid()), nil, time.Second)}
	containerSocket := filepath.Join(root, "container.sock")
	server, err := NewContainerServer(ContainerServerConfig{Runtime: runtime, SocketPath: containerSocket, ExpectedCoreUID: uint32(os.Getuid()), ExpectedCorePID: int32(os.Getpid())})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client, err := NewClient(ClientConfig{SocketPath: containerSocket, ExpectedPID: int32(os.Getpid()), ExpectedUID: uint32(os.Getuid()), Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	binding := appcontracts.ImageExecutionBinding{ApplicationID: fact.ApplicationID, EnvironmentID: fact.EnvironmentID, OperationID: "op-original", DeploymentID: "dep-original", TaskID: "task-original", Owner: "worker-original", CoreGeneration: 1, LeaseGeneration: 1, SourceArtifact: &fact, Plan: appcontracts.ImagePlan{PlanDigest: coreStore.facts.PlanDigest}}
	if _, present, err := client.ProbeBuiltOCI(ctx, binding); err != nil || present {
		t.Fatalf("destination falsely present: %v %v", present, err)
	}
	bad := binding
	changed := fact
	changed.ArchiveSHA256 = "sha256:" + strings.Repeat("0", 64)
	bad.SourceArtifact = &changed
	if _, err := client.ImportBuiltOCI(ctx, bad, bytes.NewReader(archive)); err == nil {
		t.Fatal("changed Core artifact imported")
	}
	if _, present, err := client.ProbeBuiltOCI(ctx, binding); err != nil || present {
		t.Fatalf("unauthorized import mutated destination: %v %v", present, err)
	}
	receipt, err := client.ImportBuiltOCI(ctx, binding, bytes.NewReader(archive))
	if err != nil {
		t.Fatal(err)
	}
	if receipt.ArchiveSHA256 != fact.ArchiveSHA256 || receipt.ManifestDigest != manifestDigest || receipt.ConfigDigest == "" || receipt.SizeBytes != fact.SizeBytes {
		t.Fatalf("import receipt differs from actual archive: %#v", receipt)
	}
	if probed, present, err := client.ProbeBuiltOCI(ctx, binding); err != nil || !present || probed != receipt {
		t.Fatalf("destination proof not replayable: %#v %v %v", probed, present, err)
	}
}
