package registryhttp

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
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
		if request.URL.Path == "/v2/"+testRepositoryPath+"/manifests/stable" || request.URL.Path == "/v2/"+testRepositoryPath+"/manifests/"+f.indexDigest {
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

func TestAnonymousChallenge_RetryAndSuppliedDigest(t *testing.T) {
	fixture := newRegistryFixture(t, "amd64")
	var serverURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			q := r.URL.Query()
			if q.Get("scope") != "repository:"+testRepositoryPath+":pull" {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"token": "test-anon-bearer-token-12345"})
			return
		}
		authHeader := r.Header.Get("Authorization")
		if authHeader != "Bearer test-anon-bearer-token-12345" {
			w.Header().Set("Www-Authenticate", `Bearer realm="`+serverURL+`/token",service="test",scope="repository:`+testRepositoryPath+`:pull"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		fixture.handler(t, "Bearer test-anon-bearer-token-12345").ServeHTTP(w, r)
	}))
	defer server.Close()
	serverURL = server.URL

	provider := newProvider(t, server.URL, nil)

	// 1. Tag resolution with anonymous challenge retry
	tagReq := baseRequest("anon-resolve-tag")
	tagResult, err := provider.Resolve(context.Background(), tagReq)
	if err != nil {
		t.Fatalf("anonymous resolve with tag failed: %v", err)
	}
	if tagResult.Image.Digest != fixture.manifestDigest {
		t.Fatalf("expected resolved child manifest digest %s, got %s", fixture.manifestDigest, tagResult.Image.Digest)
	}
	if tagResult.Image.ResolvedTag != "stable" {
		t.Fatalf("expected resolved tag stable, got %s", tagResult.Image.ResolvedTag)
	}
	// Check token is not leaked into evidence
	if strings.Contains(tagResult.Evidence.Summary, "test-anon-bearer-token-12345") || strings.Contains(tagResult.Evidence.Digest, "test-anon-bearer-token-12345") {
		t.Fatalf("token leaked into evidence: %+v", tagResult.Evidence)
	}

	// 2. Supplied immutable sha256 index digest resolution
	digestReq := contracts.ImageResolveRequest{
		Repository: tagReq.Repository,
		Tag:        fixture.indexDigest,
		Operation:  contracts.OperationContext{IdempotencyKey: "anon-resolve-digest"},
	}
	digestResult, err := provider.Resolve(context.Background(), digestReq)
	if err != nil {
		t.Fatalf("anonymous resolve with index digest failed: %v", err)
	}
	if digestResult.Image.Digest != fixture.manifestDigest {
		t.Fatalf("expected child manifest digest %s, got %s", fixture.manifestDigest, digestResult.Image.Digest)
	}
	if digestResult.Image.ResolvedTag != "" {
		t.Fatalf("expected empty resolved tag for supplied digest, got %q", digestResult.Image.ResolvedTag)
	}
}

func TestAnonymousChallenge_MaliciousRealmAndScopeRejection(t *testing.T) {
	var challengeHeader string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Www-Authenticate", challengeHeader)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	provider := newProvider(t, server.URL, nil)

	// 1. Malicious realm (external / non-loopback origin)
	challengeHeader = `Bearer realm="http://evil.com/token",service="test",scope="repository:` + testRepositoryPath + `:pull"`
	_, err := provider.Resolve(context.Background(), baseRequest("malicious-realm"))
	if err == nil {
		t.Fatalf("expected error on malicious realm, got nil")
	}

	// 2. Malicious scope (push scope)
	challengeHeader = `Bearer realm="` + server.URL + `/token",service="test",scope="repository:` + testRepositoryPath + `:push"`
	_, err = provider.Resolve(context.Background(), baseRequest("malicious-scope"))
	if err == nil {
		t.Fatalf("expected error on push scope, got nil")
	}

	// 3. Ambiguous token response (different token and access_token)
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"token":        "first-token",
				"access_token": "second-token",
			})
			return
		}
		w.Header().Set("Www-Authenticate", `Bearer realm="`+r.Host+`/token",service="test",scope="repository:`+testRepositoryPath+`:pull"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer tokenServer.Close()

	challengeHeader = `Bearer realm="` + tokenServer.URL + `/token",service="test",scope="repository:` + testRepositoryPath + `:pull"`
	_, err = provider.Resolve(context.Background(), baseRequest("ambiguous-token"))
	if err == nil {
		t.Fatalf("expected error on ambiguous token response, got nil")
	}
}

type syntheticRoundTripper struct {
	roundTrip func(req *http.Request) (*http.Response, error)
}

func (s *syntheticRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return s.roundTrip(req)
}

func TestGHCRBlobRedirect_PermittedAndStrippedAuth(t *testing.T) {
	validConfig := []byte(`{"architecture":"amd64","os":"linux"}`)
	validConfigDigest := digestBytes(validConfig)
	manifest := []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"` + validConfigDigest + `","size":` + itoa(len(validConfig)) + `},"layers":[]}`)
	manifestDigest := digestBytes(manifest)

	var cdnAuthHeader, cdnProxyAuth, cdnCookie string
	var serveTampered bool

	transport := &syntheticRoundTripper{
		roundTrip: func(req *http.Request) (*http.Response, error) {
			// Manifest request to ghcr.io
			if req.URL.Host == "ghcr.io" && req.URL.Path == "/v2/myorg/myapp/manifests/latest" {
				resp := &http.Response{
					StatusCode: http.StatusOK,
					Header:     make(http.Header),
					Body:       io.NopCloser(bytes.NewReader(manifest)),
					Request:    req,
				}
				resp.Header.Set("Content-Type", ociManifestMediaType)
				resp.Header.Set("Docker-Content-Digest", manifestDigest)
				return resp, nil
			}

			// Blob request to ghcr.io -> returns 307 redirect to pkg-containers.githubusercontent.com
			if req.URL.Host == "ghcr.io" && req.URL.Path == "/v2/myorg/myapp/blobs/"+validConfigDigest {
				resp := &http.Response{
					StatusCode: http.StatusTemporaryRedirect,
					Header:     make(http.Header),
					Body:       io.NopCloser(bytes.NewReader(nil)),
					Request:    req,
				}
				resp.Header.Set("Location", "https://pkg-containers.githubusercontent.com/ghcr1/blobs/"+validConfigDigest+"?signature=signed_secret_query")
				return resp, nil
			}

			// CDN blob request to pkg-containers.githubusercontent.com
			if req.URL.Host == "pkg-containers.githubusercontent.com" && strings.HasPrefix(req.URL.Path, "/ghcr1/blobs/"+validConfigDigest) {
				cdnAuthHeader = req.Header.Get("Authorization")
				cdnProxyAuth = req.Header.Get("Proxy-Authorization")
				cdnCookie = req.Header.Get("Cookie")

				blobContent := validConfig
				if serveTampered {
					blobContent = []byte(`{"architecture":"amd64","os":"linux","tampered":true}`)
				}

				resp := &http.Response{
					StatusCode: http.StatusOK,
					Header:     make(http.Header),
					Body:       io.NopCloser(bytes.NewReader(blobContent)),
					Request:    req,
				}
				resp.Header.Set("Content-Type", "application/octet-stream")
				return resp, nil
			}

			return &http.Response{
				StatusCode: http.StatusNotFound,
				Header:     make(http.Header),
				Body:       io.NopCloser(bytes.NewReader(nil)),
				Request:    req,
			}, nil
		},
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	cdnURL, _ := url.Parse("https://pkg-containers.githubusercontent.com/")
	jar.SetCookies(cdnURL, []*http.Cookie{{Name: "test_cookie", Value: "must_not_reach_cdn", Secure: true}})
	client := &http.Client{Transport: transport, Jar: jar}
	provider, err := New(Config{HTTPClient: client})
	if err != nil {
		t.Fatalf("New provider failed: %v", err)
	}

	// 1. Successful resolve: follows redirect to pkg-containers.githubusercontent.com, strips auth, returns verified digest
	resolveReq := contracts.ImageResolveRequest{
		Repository: "ghcr.io/myorg/myapp",
		Tag:        "latest",
		Operation:  contracts.OperationContext{IdempotencyKey: "ghcr-cdn-success"},
	}
	res, err := provider.Resolve(context.Background(), resolveReq)
	if err != nil {
		t.Fatalf("expected successful resolve with CDN redirect, got: %v", err)
	}
	if res.Image.Digest != manifestDigest {
		t.Fatalf("expected manifest digest %s, got %s", manifestDigest, res.Image.Digest)
	}
	if cdnAuthHeader != "" {
		t.Fatalf("expected Authorization stripped on CDN hop, got %q", cdnAuthHeader)
	}
	if cdnProxyAuth != "" || cdnCookie != "" {
		t.Fatalf("expected Proxy-Authorization and Cookie stripped on CDN hop")
	}

	// 2. Tampered blob bytes: fails digest verification with ErrConflict
	serveTampered = true
	tamperedReq := contracts.ImageResolveRequest{
		Repository: "ghcr.io/myorg/myapp",
		Tag:        "latest",
		Operation:  contracts.OperationContext{IdempotencyKey: "ghcr-cdn-tampered"},
	}
	_, err = provider.Resolve(context.Background(), tamperedReq)
	if err == nil {
		t.Fatalf("expected error on tampered CDN blob, got nil")
	}
	var provErr *contracts.ProviderError
	if !errors.As(err, &provErr) || provErr.Code != contracts.ErrConflict {
		t.Fatalf("expected ErrConflict on tampered blob bytes, got: %v", err)
	}
}

func TestGHCRBlobRedirect_Denials(t *testing.T) {
	validConfig := []byte(`{"architecture":"amd64","os":"linux"}`)
	validConfigDigest := digestBytes(validConfig)
	manifest := []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"` + validConfigDigest + `","size":` + itoa(len(validConfig)) + `},"layers":[]}`)

	denialCases := []struct {
		name        string
		reqPath     string
		redirectLoc string
	}{
		{
			name:        "arbitrary target host rejected",
			reqPath:     "/v2/myorg/myapp/blobs/" + validConfigDigest,
			redirectLoc: "https://evil-cdn.example.com/blobs/" + validConfigDigest,
		},
		{
			name:        "manifest redirect to CDN rejected",
			reqPath:     "/v2/myorg/myapp/manifests/latest",
			redirectLoc: "https://pkg-containers.githubusercontent.com/manifests/latest",
		},
		{
			name:        "userinfo in CDN redirect rejected",
			reqPath:     "/v2/myorg/myapp/blobs/" + validConfigDigest,
			redirectLoc: "https://user:pass@pkg-containers.githubusercontent.com/blobs/" + validConfigDigest,
		},
		{
			name:        "non-443 port in CDN redirect rejected",
			reqPath:     "/v2/myorg/myapp/blobs/" + validConfigDigest,
			redirectLoc: "https://pkg-containers.githubusercontent.com:8443/blobs/" + validConfigDigest,
		},
		{
			name:        "scheme downgrade in CDN redirect rejected",
			reqPath:     "/v2/myorg/myapp/blobs/" + validConfigDigest,
			redirectLoc: "http://pkg-containers.githubusercontent.com/blobs/" + validConfigDigest,
		},
	}

	for _, tc := range denialCases {
		t.Run(tc.name, func(t *testing.T) {
			transport := &syntheticRoundTripper{
				roundTrip: func(req *http.Request) (*http.Response, error) {
					if req.URL.Host == "ghcr.io" && req.URL.Path == tc.reqPath {
						resp := &http.Response{
							StatusCode: http.StatusTemporaryRedirect,
							Header:     make(http.Header),
							Body:       io.NopCloser(bytes.NewReader(nil)),
							Request:    req,
						}
						resp.Header.Set("Location", tc.redirectLoc)
						return resp, nil
					}
					if req.URL.Host == "ghcr.io" && req.URL.Path == "/v2/myorg/myapp/manifests/latest" {
						resp := &http.Response{
							StatusCode: http.StatusOK,
							Header:     make(http.Header),
							Body:       io.NopCloser(bytes.NewReader(manifest)),
							Request:    req,
						}
						resp.Header.Set("Content-Type", ociManifestMediaType)
						resp.Header.Set("Docker-Content-Digest", digestBytes(manifest))
						return resp, nil
					}
					return &http.Response{
						StatusCode: http.StatusOK,
						Header:     make(http.Header),
						Body:       io.NopCloser(bytes.NewReader(validConfig)),
						Request:    req,
					}, nil
				},
			}

			client := &http.Client{Transport: transport}
			provider, err := New(Config{HTTPClient: client})
			if err != nil {
				t.Fatalf("New provider failed: %v", err)
			}

			resolveReq := contracts.ImageResolveRequest{
				Repository: "ghcr.io/myorg/myapp",
				Tag:        "latest",
				Operation:  contracts.OperationContext{IdempotencyKey: "denial-" + tc.name},
			}
			_, err = provider.Resolve(context.Background(), resolveReq)
			if err == nil {
				t.Fatalf("expected redirect denial for case %q, but got nil", tc.name)
			}
		})
	}
}

func TestResolveAndPullReadFailuresKeepCauseAndNeverStore(t *testing.T) {
	for _, kind := range []string{"layer-timeout", "layer-cancel", "metadata-timeout", "layer-digest"} {
		t.Run(kind, func(t *testing.T) {
			fixture := newRegistryFixture(t, "amd64")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			original := fixture.handler(t, "")
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				target := "/v2/" + testRepositoryPath + "/blobs/" + fixture.layerDigest
				if kind == "metadata-timeout" {
					target = "/v2/" + testRepositoryPath + "/manifests/stable"
				}
				if req.URL.Path != target {
					original.ServeHTTP(w, req)
					return
				}
				if kind == "layer-digest" {
					_, _ = w.Write([]byte("complete-but-wrong-layer"))
					return
				}
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("partial-body"))
				w.(http.Flusher).Flush()
				if kind == "layer-cancel" {
					cancel()
				}
				<-req.Context().Done()
			}))
			defer server.Close()
			store := newFakeImageStore()
			provider := newProvider(t, server.URL, store)
			provider.config.HTTPClient.Timeout = 50 * time.Millisecond
			_, err := provider.ResolveAndPull(ctx, baseRequest("read-failure-"+kind))
			var pe *contracts.ProviderError
			if !errors.As(err, &pe) {
				t.Fatalf("expected provider error, got %v", err)
			}
			want := contracts.ErrTimeout
			if kind == "layer-cancel" {
				want = contracts.ErrCancelled
			}
			if kind == "layer-digest" {
				want = contracts.ErrConflict
			}
			if pe.Code != want {
				t.Fatalf("%s: code=%s want=%s", kind, pe.Code, want)
			}
			if kind == "layer-cancel" && !errors.Is(err, context.Canceled) {
				t.Fatal("cancellation cause lost")
			}
			if strings.Contains(kind, "timeout") {
				var timeout net.Error
				if !errors.Is(err, context.DeadlineExceeded) && !(errors.As(err, &timeout) && timeout.Timeout()) {
					t.Fatal("timeout cause lost")
				}
			}
			if kind == "layer-digest" && pe.Cause != nil {
				t.Fatal("complete wrong digest fabricated a transport cause")
			}
			store.mu.Lock()
			calls := len(store.archives)
			store.mu.Unlock()
			if calls != 0 {
				t.Fatal("unverified input reached StoreOCI")
			}
			entries, readErr := os.ReadDir(provider.config.TempRoot)
			if readErr != nil || len(entries) != 0 {
				t.Fatalf("temporary workspace leaked: entries=%d err=%v", len(entries), readErr)
			}
		})
	}
}

func TestRegistryRequestTimeoutCauseIsPrivateAndUnwraps(t *testing.T) {
	cause := &url.Error{Op: "Get", URL: "https://cdn.example/secret-path?token=private-token", Err: &net.DNSError{Err: "private-token", IsTimeout: true}}
	client := &http.Client{Transport: &syntheticRoundTripper{roundTrip: func(*http.Request) (*http.Response, error) { return nil, cause }}}
	provider, err := New(Config{HTTPClient: client})
	if err != nil {
		t.Fatal(err)
	}
	base, _ := url.Parse("https://ghcr.io")
	_, err = provider.request(context.Background(), &httpSession{client: provider.config.HTTPClient, baseURL: base}, http.MethodGet, "/v2/stefanprodan/podinfo/manifests/stable", "")
	var pe *contracts.ProviderError
	if !errors.As(err, &pe) || pe.Code != contracts.ErrTimeout || !errors.Is(err, cause) {
		t.Fatalf("timeout classification/cause lost: %v", err)
	}
	encoded, marshalErr := json.Marshal(pe)
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	for _, text := range []string{pe.Error(), string(encoded)} {
		if strings.Contains(text, "cdn.example") || strings.Contains(text, "secret-path") || strings.Contains(text, "private-token") || strings.Contains(text, "token=") {
			t.Fatalf("cause leaked through public error: %s", text)
		}
	}
}

func TestResolveAndPullSameKeyRetriesCompletedRetryableFailure(t *testing.T) {
	fixture := newRegistryFixture(t, "amd64")
	original := fixture.handler(t, "")
	var mu sync.Mutex
	layerReads, wrongLayer := 0, false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/v2/"+testRepositoryPath+"/blobs/"+fixture.layerDigest {
			original.ServeHTTP(w, req)
			return
		}
		mu.Lock()
		layerReads++
		first, wrong := layerReads == 1, wrongLayer
		mu.Unlock()
		if first {
			_, _ = w.Write([]byte("partial-layer"))
			w.(http.Flusher).Flush()
			<-req.Context().Done()
			return
		}
		if wrong {
			_, _ = w.Write([]byte("fully-read-wrong-layer"))
			return
		}
		original.ServeHTTP(w, req)
	}))
	defer server.Close()
	store := newFakeImageStore()
	provider := newProvider(t, server.URL, store)
	provider.config.HTTPClient.Timeout = 50 * time.Millisecond
	request := baseRequest("retry-same-key")
	_, err := provider.ResolveAndPull(context.Background(), request)
	var pe *contracts.ProviderError
	if !errors.As(err, &pe) || pe.Code != contracts.ErrTimeout || !pe.Retryable {
		t.Fatalf("expected retryable read timeout, got %v", err)
	}
	result, err := provider.ResolveAndPull(context.Background(), request)
	if err != nil || result.Image.Digest != fixture.manifestDigest {
		t.Fatalf("same-key retry did not really succeed: %v", err)
	}
	if replay, err := provider.ResolveAndPull(context.Background(), request); err != nil || replay.Image.Digest != result.Image.Digest {
		t.Fatalf("successful replay changed result: %v", err)
	}
	changed := request
	changed.Tag = "another-tag"
	if _, err := provider.ResolveAndPull(context.Background(), changed); !errors.As(err, &pe) || pe.Code != contracts.ErrConflict {
		t.Fatalf("same-key different request accepted: %v", err)
	}
	mu.Lock()
	if layerReads != 2 {
		t.Errorf("success/fingerprint replay downloaded again: reads=%d", layerReads)
	}
	wrongLayer = true
	mu.Unlock()
	permanent := baseRequest("permanent-checksum-conflict")
	for i := 0; i < 2; i++ {
		_, err := provider.ResolveAndPull(context.Background(), permanent)
		if !errors.As(err, &pe) || pe.Code != contracts.ErrConflict || pe.Retryable {
			t.Fatalf("complete checksum conflict should remain permanent: %v", err)
		}
	}
	mu.Lock()
	if layerReads != 3 {
		t.Errorf("nonretryable failure was reexecuted: reads=%d", layerReads)
	}
	mu.Unlock()
	store.mu.Lock()
	if len(store.archives) != 1 {
		t.Errorf("expected exactly one verified StoreOCI call, got %d", len(store.archives))
	}
	store.mu.Unlock()
	entries, readErr := os.ReadDir(provider.config.TempRoot)
	if readErr != nil || len(entries) != 0 {
		t.Fatalf("temporary workspaces leaked: %d, %v", len(entries), readErr)
	}
}
