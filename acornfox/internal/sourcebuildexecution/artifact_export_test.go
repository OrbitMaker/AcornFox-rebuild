//go:build linux

package sourcebuildexecution

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	appcontracts "github.com/acornfox/acornfox/internal/application/contracts"
	"github.com/acornfox/acornfox/internal/contracts"
	"github.com/acornfox/acornfox/internal/domain"
	capacityprovider "github.com/acornfox/acornfox/internal/providers/capacity"
	imageprovider "github.com/acornfox/acornfox/internal/providers/image"
)

func fixtureDigest(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// This is a structurally related OCI test archive, not a BuildKit-produced
// artifact or a Build→Run business result.
func sourceArchiveFixture(t *testing.T) ([]byte, string) {
	t.Helper()
	config := []byte(`{"architecture":"amd64","os":"linux","config":{"Cmd":["/app"]}}`)
	layer := make([]byte, 128<<10)
	manifest, _ := json.Marshal(map[string]any{"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json", "config": map[string]any{"mediaType": "application/vnd.oci.image.config.v1+json", "digest": fixtureDigest(config), "size": len(config)}, "layers": []any{map[string]any{"mediaType": "application/vnd.oci.image.layer.v1.tar", "digest": fixtureDigest(layer), "size": len(layer)}}})
	manifestSHA := fixtureDigest(manifest)
	index, _ := json.Marshal(map[string]any{"schemaVersion": 2, "manifests": []any{map[string]any{"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": manifestSHA, "size": len(manifest), "platform": map[string]any{"os": "linux", "architecture": "amd64"}}}})
	buf := new(bytes.Buffer)
	tarWriter := tar.NewWriter(buf)
	for _, entry := range []struct {
		name string
		data []byte
	}{{"oci-layout", []byte(`{"imageLayoutVersion":"1.0.0"}`)}, {"index.json", index}, {"blobs/sha256/" + strings.TrimPrefix(manifestSHA, "sha256:"), manifest}, {"blobs/sha256/" + strings.TrimPrefix(fixtureDigest(config), "sha256:"), config}, {"blobs/sha256/" + strings.TrimPrefix(fixtureDigest(layer), "sha256:"), layer}} {
		if err := tarWriter.WriteHeader(&tar.Header{Name: entry.name, Mode: 0444, Size: int64(len(entry.data))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tarWriter.Write(entry.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes(), manifestSHA
}
func TestBuiltOCIExportStreamsBoundedOriginalArchive(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	archive, manifestSHA := sourceArchiveFixture(t)
	if len(archive) <= 64<<10 {
		t.Fatal("stream fixture did not cross small protocol body cap")
	}
	imageRoot := filepath.Join(root, "oci")
	if err := os.Mkdir(imageRoot, 0700); err != nil {
		t.Fatal(err)
	}
	images, err := imageprovider.New(imageprovider.Config{Root: imageRoot})
	if err != nil {
		t.Fatal(err)
	}
	image := domain.ImageDigest{Repository: "ghcr.io/acme/source", Digest: manifestSHA}
	stored, err := images.StoreOCI(ctx, contracts.StoreOCIRequest{Image: image, StorageKey: "owned-build-output", Archive: bytes.NewReader(archive), Operation: contracts.OperationContext{IdempotencyKey: "actual-byte-fixture"}})
	if err != nil {
		t.Fatal(err)
	}
	peerUID := uint32(os.Getuid())
	capacity, err := capacityprovider.New(capacityprovider.Config{})
	if err != nil {
		t.Fatal(err)
	}
	role, err := NewRuntime(Config{Source: &sourceFixture{}, Capacity: capacity, Authority: &authorityFixture{check: func(SourceBuildCommand) error { return ErrBinding }}, BuilderFactory: func(contracts.CapacityProvider) (contracts.BuildProvider, error) { return &buildFixture{}, nil }})
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewExecutionServer(ServerConfig{SocketPath: filepath.Join(root, "role.sock"), PeerUID: peerUID, ArchiveStore: images}, role)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client, err := NewClient(ClientConfig{SocketPath: filepath.Join(root, "role.sock"), PeerUID: peerUID})
	if err != nil {
		t.Fatal(err)
	}
	fact := appcontracts.SourceBuiltArtifactFact{AdminID: "admin_owned", ApplicationID: "app_owned", EnvironmentID: "env_owned", BuildIntentID: "sbi_owned", BuildID: "build_owned", SourceRevisionID: "src_owned", BuildPlanID: "plan_owned", ArtifactID: "artifact_owned", Image: image, StorageRef: stored.StorageRef, ArchiveSHA256: stored.Evidence.Digest, SizeBytes: stored.SizeBytes}
	reader, err := client.OpenBuiltOCI(ctx, fact)
	if err != nil {
		t.Fatal(err)
	}
	copied, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(copied, archive) || fixtureDigest(copied) != stored.Evidence.Digest {
		t.Fatal("Core stream differed from immutable Source store bytes")
	}
	wrong := fact
	wrong.ArchiveSHA256 = "sha256:" + strings.Repeat("0", 64)
	if _, err := client.OpenBuiltOCI(ctx, wrong); err == nil {
		t.Fatal("mismatched whole archive SHA was exported")
	}
	wrong = fact
	wrong.SizeBytes--
	if _, err := client.OpenBuiltOCI(ctx, wrong); err == nil {
		t.Fatal("mismatched archive size was exported")
	}
	timeout, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	if err := client.CheckReady(timeout); err != nil {
		t.Fatal("Source execution interface was disrupted by archive export")
	}
}
