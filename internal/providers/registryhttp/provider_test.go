package registryhttp

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
)

const testRepositoryPath = "open-card/web"

var testCurrentRepository = "127.0.0.1:5000/" + testRepositoryPath

type registryFixture struct {
	index               []byte
	indexDigest         string
	manifest            []byte
	manifestDigest      string
	config              []byte
	configDigest        string
	layer               []byte
	layerDigest         string
	otherIndex          []byte
	otherDigest         string
	otherManifest       []byte
	otherManifestDigest string
	otherConfig         []byte
	otherConfigDigest   string
	mu                  sync.Mutex
	requests            []string
	auth                []string
	serveOther          bool
}

func newRegistryFixture(t *testing.T, architecture string) *registryFixture {
	t.Helper()
	config := []byte(`{"architecture":"` + architecture + `","os":"linux"}`)
	layer := []byte("deterministic-layer-content")
	configDigest := digestBytes(config)
	layerDigest := digestBytes(layer)
	manifest := []byte(`{"schemaVersion":2,"mediaType":"` + ociManifestMediaType + `","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"` + configDigest + `","size":` + itoa(len(config)) + `},"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar","digest":"` + layerDigest + `","size":` + itoa(len(layer)) + `}]}`)
	manifestDigest := digestBytes(manifest)
	index := []byte(`{"schemaVersion":2,"mediaType":"` + ociIndexMediaType + `","manifests":[{"mediaType":"` + ociManifestMediaType + `","digest":"` + manifestDigest + `","size":` + itoa(len(manifest)) + `,"platform":{"os":"linux","architecture":"` + architecture + `"}}]}`)
	indexDigest := digestBytes(index)
	otherConfig := []byte(`{"architecture":"amd64","os":"linux"}`)
	otherConfigDigest := digestBytes(otherConfig)
	otherManifest := []byte(`{"schemaVersion":2,"mediaType":"` + ociManifestMediaType + `","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"` + otherConfigDigest + `","size":` + itoa(len(otherConfig)) + `},"layers":[]}`)
	otherManifestDigest := digestBytes(otherManifest)
	otherIndex := []byte(`{"schemaVersion":2,"mediaType":"` + ociIndexMediaType + `","manifests":[{"mediaType":"` + ociManifestMediaType + `","digest":"` + otherManifestDigest + `","size":` + itoa(len(otherManifest)) + `,"platform":{"os":"linux","architecture":"amd64"}}]}`)
	return &registryFixture{index: index, indexDigest: indexDigest, manifest: manifest, manifestDigest: manifestDigest, config: config, configDigest: configDigest, layer: layer, layerDigest: layerDigest, otherIndex: otherIndex, otherDigest: digestBytes(otherIndex), otherManifest: otherManifest, otherManifestDigest: otherManifestDigest, otherConfig: otherConfig, otherConfigDigest: otherConfigDigest}
}

func itoa(value int) string {
	if value == 0 {
		return "0"
	}
	var digits [24]byte
	i := len(digits)
	for value > 0 {
		i--
		digits[i] = byte('0' + value%10)
		value /= 10
	}
	return string(digits[i:])
}

func (f *registryFixture) handler(t *testing.T, requireAuth string) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		f.mu.Lock()
		f.requests = append(f.requests, request.URL.Path)
		f.auth = append(f.auth, request.Header.Get("Authorization"))
		serveOther := f.serveOther
		f.mu.Unlock()
		if requireAuth != "" && request.Header.Get("Authorization") != requireAuth {
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}
		if request.URL.Path == "/v2/"+testRepositoryPath+"/manifests/stable" {
			if serveOther {
				writer.Header().Set("Docker-Content-Digest", f.otherDigest)
				writer.Header().Set("Content-Type", ociIndexMediaType)
				_, _ = writer.Write(f.otherIndex)
				return
			}
			writer.Header().Set("Docker-Content-Digest", f.indexDigest)
			writer.Header().Set("Content-Type", ociIndexMediaType)
			_, _ = writer.Write(f.index)
			return
		}
		if request.URL.Path == "/v2/"+testRepositoryPath+"/manifests/"+f.manifestDigest {
			writer.Header().Set("Docker-Content-Digest", f.manifestDigest)
			writer.Header().Set("Content-Type", ociManifestMediaType)
			_, _ = writer.Write(f.manifest)
			return
		}
		if request.URL.Path == "/v2/"+testRepositoryPath+"/manifests/"+f.otherManifestDigest {
			writer.Header().Set("Docker-Content-Digest", f.otherManifestDigest)
			writer.Header().Set("Content-Type", ociManifestMediaType)
			_, _ = writer.Write(f.otherManifest)
			return
		}
		if request.URL.Path == "/v2/"+testRepositoryPath+"/blobs/"+f.configDigest {
			_, _ = writer.Write(f.config)
			return
		}
		if request.URL.Path == "/v2/"+testRepositoryPath+"/blobs/"+f.layerDigest {
			_, _ = writer.Write(f.layer)
			return
		}
		if request.URL.Path == "/v2/"+testRepositoryPath+"/blobs/"+f.otherConfigDigest {
			_, _ = writer.Write(f.otherConfig)
			return
		}
		writer.WriteHeader(http.StatusNotFound)
	})
}

type fakeImageStore struct {
	mu         sync.Mutex
	metadata   contracts.ProviderMetadata
	images     []domain.ImageDigest
	archives   [][]byte
	operations []string
}

func newFakeImageStore() *fakeImageStore {
	return &fakeImageStore{metadata: contracts.ProviderMetadata{Name: "fake-store", Version: "test", ContractVersion: contracts.ContractAPIVersion, Capabilities: contracts.NewCapabilitySet(contracts.CapabilityImageStoreOCI)}}
}

func (f *fakeImageStore) Metadata(context.Context) contracts.ProviderMetadata { return f.metadata }

func (f *fakeImageStore) StoreOCI(_ context.Context, request contracts.StoreOCIRequest) (contracts.StoreOCIResult, error) {
	content, err := io.ReadAll(request.Archive)
	if err != nil {
		return contracts.StoreOCIResult{}, err
	}
	f.mu.Lock()
	f.images = append(f.images, request.Image)
	f.archives = append(f.archives, content)
	f.operations = append(f.operations, request.Operation.IdempotencyKey)
	f.mu.Unlock()
	return contracts.StoreOCIResult{Image: request.Image, StorageRef: "fake://" + storageKey(request.Image), SizeBytes: int64(len(content)), Evidence: contracts.Evidence{Redacted: true}}, nil
}

func (f *fakeImageStore) Resolve(context.Context, contracts.ImageResolveRequest) (contracts.ImageResolveResult, error) {
	return contracts.ImageResolveResult{}, errors.New("not used")
}

func (f *fakeImageStore) Pull(context.Context, domain.ImageDigest, contracts.OperationContext) (contracts.Evidence, error) {
	return contracts.Evidence{}, errors.New("not used")
}

func (f *fakeImageStore) Retain(context.Context, domain.ImageDigest, contracts.OperationContext) error {
	return errors.New("not used")
}

func (f *fakeImageStore) Delete(context.Context, domain.ImageDigest, contracts.OperationContext) error {
	return errors.New("not used")
}

func (f *fakeImageStore) OpenOCI(context.Context, domain.ImageDigest, contracts.OperationContext) (io.ReadCloser, contracts.StoreOCIResult, error) {
	return nil, contracts.StoreOCIResult{}, errors.New("not used")
}

type fakeSecretResolver struct {
	metadata contracts.ProviderMetadata
	material contracts.BuildSecretMaterial
	mu       sync.Mutex
	resolves []string
	revokes  []string
}

func (f *fakeSecretResolver) Metadata(context.Context) contracts.ProviderMetadata { return f.metadata }

func (f *fakeSecretResolver) ResolveBuildSecret(_ context.Context, _ domain.SecretReference, operation contracts.OperationContext) (contracts.BuildSecretMaterial, error) {
	f.mu.Lock()
	f.resolves = append(f.resolves, operation.IdempotencyKey)
	f.mu.Unlock()
	return f.material, nil
}

func (f *fakeSecretResolver) RevokeBuildSecret(_ context.Context, _ contracts.BuildSecretMaterial, operation contracts.OperationContext) error {
	f.mu.Lock()
	f.revokes = append(f.revokes, operation.IdempotencyKey)
	f.mu.Unlock()
	return nil
}

func baseRequest(key string) contracts.ImageResolveRequest {
	return contracts.ImageResolveRequest{Repository: testCurrentRepository, Tag: "stable", Operation: contracts.OperationContext{IdempotencyKey: key}}
}

func newProvider(t *testing.T, serverURL string, store contracts.ImageStore) *Provider {
	t.Helper()
	parsed, err := url.Parse(serverURL)
	if err != nil {
		t.Fatal(err)
	}
	testCurrentRepository = parsed.Host + "/" + testRepositoryPath
	provider, err := New(Config{BaseURL: serverURL, TempRoot: t.TempDir(), ImageStore: store, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return provider
}

func TestResolveHTTPFetchesConfigButNotLayersAndPinsTagDrift(t *testing.T) {
	fixture := newRegistryFixture(t, "amd64")
	server := httptest.NewServer(fixture.handler(t, ""))
	defer server.Close()
	provider := newProvider(t, server.URL, nil)
	first, err := provider.Resolve(context.Background(), baseRequest("resolve-first"))
	if err != nil {
		t.Fatal(err)
	}
	if first.Image.Digest != fixture.manifestDigest || first.Image.ResolvedTag != "stable" {
		t.Fatalf("unexpected resolved image: %#v", first.Image)
	}
	fixture.mu.Lock()
	requests := append([]string(nil), fixture.requests...)
	fixture.serveOther = true
	fixture.mu.Unlock()
	second, err := provider.Resolve(context.Background(), baseRequest("resolve-second"))
	if err != nil {
		t.Fatal(err)
	}
	if second.Image.Digest == first.Image.Digest {
		t.Fatalf("tag drift was not observed as a new resolve: %#v %#v", first.Image, second.Image)
	}
	for _, path := range requests {
		if strings.Contains(path, "/blobs/"+fixture.layerDigest) {
			t.Fatalf("resolve-only fetched a layer: %q", path)
		}
	}
	if first.Evidence.Redacted != true || strings.Contains(first.Evidence.Summary, "stable") {
		t.Fatalf("resolve evidence is not redacted/stable: %#v", first.Evidence)
	}
}

func TestResolveAndPullUsesVerifiedDigestAndDeterministicOCIArchive(t *testing.T) {
	fixture := newRegistryFixture(t, "amd64")
	server := httptest.NewServer(fixture.handler(t, ""))
	defer server.Close()
	store := newFakeImageStore()
	provider := newProvider(t, server.URL, store)
	result, err := provider.ResolveAndPull(context.Background(), baseRequest("pull-first"))
	if err != nil {
		t.Fatal(err)
	}
	if result.Image.Digest != fixture.manifestDigest {
		t.Fatalf("unexpected pulled digest: %#v", result.Image)
	}
	store.mu.Lock()
	if len(store.archives) != 1 || len(store.images) != 1 {
		t.Fatalf("store calls = %d images, %d archives", len(store.images), len(store.archives))
	}
	if store.images[0].ResolvedTag != "" {
		t.Fatalf("mutable tag crossed the ImageStore boundary: %#v", store.images[0])
	}
	archive := append([]byte(nil), store.archives[0]...)
	store.mu.Unlock()
	verifyOCIArchive(t, archive, fixture)
	fixture.mu.Lock()
	requests := append([]string(nil), fixture.requests...)
	fixture.mu.Unlock()
	seenTag := 0
	for _, path := range requests {
		if strings.HasSuffix(path, "/manifests/stable") {
			seenTag++
		}
		if strings.Contains(path, "/blobs/") || strings.Contains(path, "/manifests/sha256:") {
			if strings.Contains(path, ":stable") {
				t.Fatalf("digest pull path retained mutable tag: %q", path)
			}
		}
	}
	if seenTag != 1 {
		t.Fatalf("tag was resolved %d times, want once", seenTag)
	}
	// A distinct idempotency key produces the same deterministic archive.
	if _, err := provider.ResolveAndPull(context.Background(), baseRequest("pull-second")); err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	if len(store.archives) != 2 || !bytes.Equal(store.archives[0], store.archives[1]) {
		t.Fatal("identical verified content did not produce identical OCI archives")
	}
	store.mu.Unlock()
}

func verifyOCIArchive(t *testing.T, content []byte, fixture *registryFixture) {
	t.Helper()
	reader := tar.NewReader(bytes.NewReader(content))
	var names []string
	contents := make(map[string][]byte)
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, header.Name)
		value, readErr := io.ReadAll(reader)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if int64(len(value)) != header.Size {
			t.Fatalf("archive size mismatch for %q: header=%d bytes=%d", header.Name, header.Size, len(value))
		}
		contents[header.Name] = value
		if header.ModTime.Unix() != 0 || header.Uid != 0 || header.Gid != 0 || header.Mode != 0o644 {
			t.Fatalf("non-deterministic archive metadata: %#v", header)
		}
	}
	want := []string{"oci-layout", "index.json", "blobs/sha256/" + strings.TrimPrefix(fixture.configDigest, "sha256:"), "blobs/sha256/" + strings.TrimPrefix(fixture.layerDigest, "sha256:"), "blobs/sha256/" + strings.TrimPrefix(fixture.manifestDigest, "sha256:")}
	if len(names) != 5 || names[0] != want[0] || names[1] != want[1] {
		t.Fatalf("unexpected OCI archive entries: %#v", names)
	}
	for _, name := range names[2:] {
		found := false
		for _, expected := range want[2:] {
			if name == expected {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("unexpected OCI blob entry %q in %#v", name, names)
		}
	}
	for _, digest := range []string{fixture.manifestDigest, fixture.configDigest, fixture.layerDigest} {
		name := "blobs/sha256/" + strings.TrimPrefix(digest, "sha256:")
		if digestBytes(contents[name]) != digest {
			t.Fatalf("OCI blob %q failed digest verification", name)
		}
	}
	var index struct {
		Manifests []struct {
			Digest      string            `json:"digest"`
			Size        int64             `json:"size"`
			Annotations map[string]string `json:"annotations"`
		} `json:"manifests"`
	}
	if err := json.Unmarshal(contents["index.json"], &index); err != nil || len(index.Manifests) != 1 {
		t.Fatalf("invalid OCI index: %v", err)
	}
	entry := index.Manifests[0]
	if entry.Digest != fixture.manifestDigest || entry.Size != int64(len(fixture.manifest)) || entry.Annotations["org.opencontainers.image.ref.name"] != testCurrentRepository+":stable" {
		t.Fatalf("OCI index did not bind immutable manifest/tag provenance: %#v", entry)
	}
}

func TestResolveAndPullPrivateAuthIsTemporaryAndNeverInEvidence(t *testing.T) {
	fixture := newRegistryFixture(t, "amd64")
	server := httptest.NewServer(fixture.handler(t, "Basic "+base64.StdEncoding.EncodeToString([]byte("registry-user:canary-password"))))
	defer server.Close()
	secretPath := filepath.Join(t.TempDir(), "material")
	if err := os.WriteFile(secretPath, []byte("registry-user:canary-password"), 0o400); err != nil {
		t.Fatal(err)
	}
	secret := domain.SecretReference{ID: "secret_registry", Name: "registry", Provider: "filesystem-secret", Version: "v1"}
	resolver := &fakeSecretResolver{metadata: contracts.ProviderMetadata{Name: "fake-secret", Version: "test", ContractVersion: contracts.ContractAPIVersion, Capabilities: contracts.NewCapabilitySet(contracts.CapabilitySecretResolve)}, material: contracts.BuildSecretMaterial{MountID: "mount_private", Reference: secret, Path: secretPath, ExpiresAt: time.Now().Add(time.Minute)}}
	store := newFakeImageStore()
	provider := newProvider(t, server.URL, store)
	provider.config.SecretResolver = resolver
	request := baseRequest("private-pull")
	request.Secret = &secret
	result, err := provider.ResolveAndPull(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(result.Evidence.Summary, "canary-password") || strings.Contains(result.Evidence.Refs[0].Locator, "canary-password") {
		t.Fatalf("credential leaked into evidence: %#v", result.Evidence)
	}
	resolver.mu.Lock()
	if len(resolver.resolves) != 1 || len(resolver.revokes) != 1 {
		t.Fatalf("secret lifecycle = resolves %d revokes %d", len(resolver.resolves), len(resolver.revokes))
	}
	resolver.mu.Unlock()
	entries, err := os.ReadDir(provider.config.TempRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("temporary registry workspace leaked: %#v", entries)
	}
	fixture.mu.Lock()
	for _, value := range fixture.auth {
		if value != "Basic "+base64.StdEncoding.EncodeToString([]byte("registry-user:canary-password")) {
			t.Fatalf("private request did not use the materialized auth header: %q", value)
		}
	}
	fixture.mu.Unlock()
}

func TestRejectsNonLoopbackPlainHTTP(t *testing.T) {
	if _, err := New(Config{BaseURL: "http://registry.example.test"}); err == nil {
		t.Fatal("non-loopback HTTP registry endpoint was accepted")
	}
	if _, err := New(Config{BaseURL: "http://127.0.0.1:5000"}); err != nil {
		t.Fatalf("loopback HTTP fixture was rejected: %v", err)
	}
}

func TestResolveRejectsNonAMD64ImageConfig(t *testing.T) {
	fixture := newRegistryFixture(t, "arm64")
	server := httptest.NewServer(fixture.handler(t, ""))
	defer server.Close()
	provider := newProvider(t, server.URL, nil)
	_, err := provider.Resolve(context.Background(), baseRequest("wrong-arch"))
	var providerErr *contracts.ProviderError
	if !errors.As(err, &providerErr) || providerErr.Code != contracts.ErrConflict {
		t.Fatalf("expected platform conflict, got %v", err)
	}
}
