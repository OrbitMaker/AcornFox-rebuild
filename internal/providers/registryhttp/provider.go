// Package registryhttp implements the Open Card registry boundary using the
// OCI Distribution HTTP API.  It deliberately has no Docker CLI or socket
// dependency: the control plane may resolve and pull images without granting
// a systemd service access to a container runtime socket.
package registryhttp

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
)

const (
	providerName    = "oci-registry-http"
	providerVersion = "m2"
	defaultTimeout  = 2 * time.Minute
	maxMetadataSize = 16 << 20
	maxBlobSize     = 4 << 30

	ghcrHost        = "ghcr.io"
	ghcrCDNHost     = "pkg-containers.githubusercontent.com"
	maxRedirectHops = 3

	ociManifestMediaType        = "application/vnd.oci.image.manifest.v1+json"
	ociIndexMediaType           = "application/vnd.oci.image.index.v1+json"
	dockerManifestMediaType     = "application/vnd.docker.distribution.manifest.v2+json"
	dockerManifestListMediaType = "application/vnd.docker.distribution.manifest.list.v2+json"
)

var (
	errInvalidRegistry = errors.New("registry input is invalid")
	errPlatformMissing = errors.New("registry manifest has no compatible linux/amd64 platform")
	errCredential      = errors.New("registry credential material is invalid")
	errHTTPBoundary    = errors.New("registry HTTP endpoint violates the transport boundary")
)

// Config declares the HTTP and persistence boundaries.  BaseURL is used for
// every request; when empty, the repository's registry host is inferred and
// HTTPS is required.  Plain HTTP is accepted only for loopback test fixtures.
type Config struct {
	BaseURL string
	// RegistryURL is a descriptive alias accepted by composition roots that
	// name the same endpoint as a registry URL rather than a base URL.
	RegistryURL    string
	HTTPClient     *http.Client
	SecretResolver contracts.BuildSecretResolver
	ImageStore     contracts.ImageStore
	TempRoot       string
	Timeout        time.Duration
	Clock          func() time.Time
}

type Provider struct {
	config     Config
	metadata   contracts.ProviderMetadata
	mu         sync.Mutex
	operations map[string]*operationRecord
}

// RegistryImageProvider is the explicit composition-root name.
type RegistryImageProvider = Provider

type operationRecord struct {
	fingerprint string
	done        chan struct{}
	result      contracts.ImageResolveResult
	err         error
}

// New constructs a fail-closed provider.  It does not contact the registry or
// create a filesystem path until Resolve or ResolveAndPull is called.
func New(config Config) (*Provider, error) {
	normalized, err := normalizeConfig(config)
	if err != nil {
		return nil, err
	}
	return &Provider{
		config: normalized,
		metadata: contracts.ProviderMetadata{
			Name:            providerName,
			Version:         providerVersion,
			ContractVersion: contracts.ContractAPIVersion,
			Capabilities:    contracts.NewCapabilitySet(contracts.CapabilityImageResolve, contracts.CapabilityImagePull, contracts.CapabilityImageStoreOCI),
			SensitiveInputs: []string{"registry secret reference", "registry credential material", "authorization header"},
		},
		operations: make(map[string]*operationRecord),
	}, nil
}

func NewProvider(config Config) (*Provider, error) { return New(config) }

func (p *Provider) Metadata(context.Context) contracts.ProviderMetadata { return p.metadata }

// Resolve obtains an immutable platform-specific manifest digest and verifies
// its image config.  The returned tag is provenance only; callers must use
// Image.Digest for all subsequent operations.
func (p *Provider) Resolve(ctx context.Context, request contracts.ImageResolveRequest) (contracts.ImageResolveResult, error) {
	return p.run(ctx, request, "resolve", func(session *httpSession, opCtx context.Context) (contracts.ImageResolveResult, error) {
		image, _, err := p.resolveImage(opCtx, session, request, false)
		if err != nil {
			return contracts.ImageResolveResult{}, err
		}
		return p.resultFor(request, image, "resolve", "registry tag resolved to an immutable linux/amd64 digest"), nil
	})
}

// ResolveAndPull resolves a tag once, pulls only the resulting digest and
// verifies the downloaded manifest/config/layers.  The verified content is
// emitted as a deterministic OCI image-layout tar archive to the injected
// ImageStore; this package never talks to Docker or a socket.
func (p *Provider) ResolveAndPull(ctx context.Context, request contracts.ImageResolveRequest) (contracts.ImageResolveResult, error) {
	return p.run(ctx, request, "resolve_and_pull", func(session *httpSession, opCtx context.Context) (contracts.ImageResolveResult, error) {
		image, pulled, err := p.resolveImage(opCtx, session, request, true)
		if err != nil {
			return contracts.ImageResolveResult{}, err
		}
		if p.config.ImageStore == nil {
			return contracts.ImageResolveResult{}, p.failure(request.Operation, contracts.ErrUnavailable, "resolve_and_pull", "OCI image store is unavailable", nil)
		}
		if err := p.config.ImageStore.Metadata(opCtx).Supports(contracts.CapabilityImageStoreOCI); err != nil {
			return contracts.ImageResolveResult{}, p.failure(request.Operation, contracts.ErrUnsupportedCapability, "resolve_and_pull", "OCI image store capability is unavailable", nil)
		}
		archivePath, err := p.writeArchive(session, pulled, request)
		if err != nil {
			return contracts.ImageResolveResult{}, err
		}
		archive, err := os.Open(archivePath)
		if err != nil {
			return contracts.ImageResolveResult{}, p.failure(request.Operation, contracts.ErrUnavailable, "resolve_and_pull", "OCI archive could not be opened", nil)
		}
		defer archive.Close()
		storeOperation := request.Operation
		storeOperation.IdempotencyKey = "registryhttp:store_oci\x00" + request.Operation.IdempotencyKey
		storeImage := image
		storeImage.ResolvedTag = ""
		stored, err := p.config.ImageStore.StoreOCI(opCtx, contracts.StoreOCIRequest{
			Image: storeImage, StorageKey: storageKey(image), Archive: archive,
			Operation: storeOperation,
		})
		if err != nil {
			var providerErr *contracts.ProviderError
			if errors.As(err, &providerErr) {
				return contracts.ImageResolveResult{}, providerErr
			}
			return contracts.ImageResolveResult{}, p.failure(request.Operation, contracts.ErrUnavailable, "resolve_and_pull", "OCI image store rejected verified content", nil)
		}
		if stored.Image.Repository != image.Repository || stored.Image.Digest != image.Digest {
			return contracts.ImageResolveResult{}, p.failure(request.Operation, contracts.ErrConflict, "resolve_and_pull", "OCI image store returned a different immutable image", nil)
		}
		return p.resultFor(request, image, "resolve_and_pull", "registry image pulled and stored by immutable linux/amd64 digest"), nil
	})
}

func (p *Provider) run(ctx context.Context, request contracts.ImageResolveRequest, mode string, operation func(*httpSession, context.Context) (contracts.ImageResolveResult, error)) (contracts.ImageResolveResult, error) {
	fingerprint, err := requestFingerprint(request)
	if err != nil {
		return contracts.ImageResolveResult{}, p.failure(request.Operation, contracts.ErrValidation, mode, err.Error(), err)
	}
	if err := p.check(ctx, request.Operation); err != nil {
		return contracts.ImageResolveResult{}, err
	}
	key := mode + "\x00" + request.Operation.IdempotencyKey
	record, leader, err := p.begin(key, digestString(mode, fingerprint))
	if err != nil {
		return contracts.ImageResolveResult{}, p.failure(request.Operation, contracts.ErrConflict, mode, err.Error(), nil)
	}
	if !leader {
		if err := waitRecord(ctx, request.Operation, record); err != nil {
			return contracts.ImageResolveResult{}, p.classify(request.Operation, mode, err)
		}
		return cloneResult(record.result), record.err
	}

	result, opErr := p.execute(ctx, request, mode, operation)
	p.finish(record, result, opErr)
	return cloneResult(result), opErr
}

func (p *Provider) execute(ctx context.Context, request contracts.ImageResolveRequest, mode string, operation func(*httpSession, context.Context) (contracts.ImageResolveResult, error)) (contracts.ImageResolveResult, error) {
	opCtx, cancel := operationContext(ctx, request.Operation, p.config.Timeout)
	defer cancel()
	session, err := p.newSession(opCtx, request, mode)
	if err != nil {
		return contracts.ImageResolveResult{}, err
	}
	defer session.Close()
	return operation(session, opCtx)
}

type httpSession struct {
	baseURL      *url.URL
	client       *http.Client
	resolver     contracts.BuildSecretResolver
	material     *contracts.BuildSecretMaterial
	authHeader   string
	authBytes    []byte
	operation    contracts.OperationContext
	workspace    string
	repository   string
	tokenRetried bool
}

func (s *httpSession) Close() {
	if s == nil {
		return
	}
	if s.material != nil && s.resolver != nil {
		revoke := s.operation
		revoke.Deadline = time.Time{}
		_ = s.resolver.RevokeBuildSecret(context.Background(), *s.material, revoke)
	}
	for i := range s.authBytes {
		s.authBytes[i] = 0
	}
	s.authBytes = nil
	s.authHeader = ""
	if s.workspace != "" {
		_ = os.RemoveAll(s.workspace)
	}
}

func (p *Provider) newSession(ctx context.Context, request contracts.ImageResolveRequest, mode string) (*httpSession, error) {
	base, err := p.endpoint(request.Repository)
	if err != nil {
		return nil, p.failure(request.Operation, contracts.ErrForbidden, mode, "registry endpoint violates the transport boundary", nil)
	}
	workspace, err := os.MkdirTemp(p.config.TempRoot, "open-card-registry-http-")
	if err != nil {
		return nil, p.failure(request.Operation, contracts.ErrUnavailable, mode, "registry HTTP workspace could not be created", nil)
	}
	session := &httpSession{baseURL: base, client: p.config.HTTPClient, operation: request.Operation, workspace: workspace, repository: request.Repository}
	cleanupFailure := func(providerErr error) (*httpSession, error) {
		session.Close()
		return nil, providerErr
	}
	if err := os.Chmod(workspace, 0o700); err != nil {
		return cleanupFailure(p.failure(request.Operation, contracts.ErrUnavailable, mode, "registry HTTP workspace could not be secured", nil))
	}
	if request.Secret == nil {
		return session, nil
	}
	if p.config.SecretResolver == nil {
		return cleanupFailure(p.failure(request.Operation, contracts.ErrUnauthorized, mode, "registry credentials require a secret resolver", nil))
	}
	if err := request.Secret.Validate(); err != nil {
		return cleanupFailure(p.failure(request.Operation, contracts.ErrValidation, mode, "registry secret reference is invalid", nil))
	}
	secretOperation := request.Operation
	secretOperation.IdempotencyKey = mode + "\x00" + request.Operation.IdempotencyKey
	metadata := p.config.SecretResolver.Metadata(ctx)
	if metadata.Validate() != nil || !metadata.Capabilities.Has(contracts.CapabilitySecretResolve) {
		return cleanupFailure(p.failure(request.Operation, contracts.ErrUnauthorized, mode, "registry secret resolver capability is unavailable", nil))
	}
	material, err := p.config.SecretResolver.ResolveBuildSecret(ctx, *request.Secret, secretOperation)
	if err != nil {
		return cleanupFailure(p.failure(request.Operation, contracts.ErrUnauthorized, mode, "registry credentials could not be materialized", nil))
	}
	session.resolver = p.config.SecretResolver
	session.material = &material
	session.operation = secretOperation
	if material.Reference != *request.Secret || material.ExpiresAt.IsZero() || !material.ExpiresAt.After(p.config.Clock().UTC()) {
		return cleanupFailure(p.failure(request.Operation, contracts.ErrUnauthorized, mode, "registry credential material is expired or mismatched", nil))
	}
	auth, authBytes, err := readAuthorization(material.Path, registryHost(request.Repository))
	if err != nil {
		return cleanupFailure(p.failure(request.Operation, contracts.ErrUnauthorized, mode, "registry credentials are invalid", nil))
	}
	session.authHeader = auth
	session.authBytes = authBytes
	return session, nil
}

func (p *Provider) endpoint(repository string) (*url.URL, error) {
	baseValue := strings.TrimSpace(p.config.BaseURL)
	if baseValue == "" {
		baseValue = "https://" + registryHost(repository)
	}
	base, err := url.Parse(baseValue)
	if err != nil || base.User != nil || base.Host == "" || (base.Scheme != "http" && base.Scheme != "https") {
		return nil, errHTTPBoundary
	}
	if base.Scheme == "http" && !isLoopbackHost(base.Hostname()) {
		return nil, errHTTPBoundary
	}
	if explicitHost := registryHostIfExplicit(repository); explicitHost != "" && !strings.EqualFold(explicitHost, base.Host) {
		return nil, errHTTPBoundary
	}
	return base, nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func isGHCRBlobRequest(u *url.URL) bool {
	if u == nil || u.Scheme != "https" || !strings.EqualFold(u.Hostname(), ghcrHost) {
		return false
	}
	path := strings.TrimPrefix(u.Path, "/v2/")
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) < 2 {
		return false
	}
	if parts[len(parts)-2] != "blobs" {
		return false
	}
	digest := parts[len(parts)-1]
	return validDigest(digest)
}

func (p *Provider) resolveImage(ctx context.Context, session *httpSession, request contracts.ImageResolveRequest, pull bool) (domain.ImageDigest, pulledImage, error) {
	tagManifest, tagDigest, mediaType, err := p.getManifest(ctx, session, request.Repository, request.Tag)
	if err != nil {
		return domain.ImageDigest{}, pulledImage{}, err
	}
	selectedDigest := tagDigest
	selectedManifest := tagManifest
	selectedMediaType := mediaType
	var document manifestDocument
	if err := json.Unmarshal(tagManifest, &document); err != nil {
		return domain.ImageDigest{}, pulledImage{}, p.failure(request.Operation, contracts.ErrValidation, "resolve", "registry manifest JSON is invalid", nil)
	}
	if len(document.Manifests) > 0 {
		selected, ok := selectPlatform(document.Manifests)
		if !ok {
			return domain.ImageDigest{}, pulledImage{}, p.failure(request.Operation, contracts.ErrConflict, "resolve", errPlatformMissing.Error(), nil)
		}
		selectedDigest = selected.Digest
		selectedManifest, _, selectedMediaType, err = p.getManifest(ctx, session, request.Repository, selectedDigest)
		if err != nil {
			return domain.ImageDigest{}, pulledImage{}, err
		}
	}
	if !validDigest(selectedDigest) {
		return domain.ImageDigest{}, pulledImage{}, p.failure(request.Operation, contracts.ErrValidation, "resolve", "registry returned an invalid manifest digest", nil)
	}
	if validDigest(request.Tag) && tagDigest != request.Tag {
		return domain.ImageDigest{}, pulledImage{}, p.failure(request.Operation, contracts.ErrConflict, "resolve", "registry manifest digest does not match requested digest", nil)
	}
	if !bytes.Equal(tagManifest, selectedManifest) && digestBytes(selectedManifest) != selectedDigest {
		return domain.ImageDigest{}, pulledImage{}, p.failure(request.Operation, contracts.ErrConflict, "resolve", "registry manifest digest verification failed", nil)
	}
	if len(document.Manifests) == 0 {
		selectedMediaType = mediaType
	}
	var selectedDoc manifestDocument
	if err := json.Unmarshal(selectedManifest, &selectedDoc); err != nil || selectedDoc.Config.Digest == "" {
		return domain.ImageDigest{}, pulledImage{}, p.failure(request.Operation, contracts.ErrValidation, "resolve", "registry image manifest is incomplete", nil)
	}
	configBytes, err := p.getBlob(ctx, session, request.Repository, selectedDoc.Config.Digest)
	if err != nil {
		return domain.ImageDigest{}, pulledImage{}, err
	}
	var imageConfig struct {
		OS           string `json:"os"`
		Architecture string `json:"architecture"`
		Variant      string `json:"variant,omitempty"`
	}
	if err := json.Unmarshal(configBytes, &imageConfig); err != nil || normalizeOS(imageConfig.OS) != "linux" || normalizeArch(imageConfig.Architecture) != "amd64" {
		return domain.ImageDigest{}, pulledImage{}, p.failure(request.Operation, contracts.ErrConflict, "resolve", "registry image config is not linux/amd64", nil)
	}
	image, err := domain.ParseImageDigest(request.Repository, selectedDigest)
	if err != nil {
		return domain.ImageDigest{}, pulledImage{}, p.failure(request.Operation, contracts.ErrValidation, "resolve", "registry image digest is invalid", nil)
	}
	if !validDigest(request.Tag) {
		image.ResolvedTag = request.Tag
	} else {
		image.ResolvedTag = ""
	}
	pulled := pulledImage{Manifest: selectedManifest, ManifestMediaType: selectedMediaType, ConfigDigest: selectedDoc.Config.Digest, Config: configBytes}
	if !pull {
		return image, pulled, nil
	}
	for _, layer := range selectedDoc.Layers {
		if !validDigest(layer.Digest) {
			return domain.ImageDigest{}, pulledImage{}, p.failure(request.Operation, contracts.ErrValidation, "resolve_and_pull", "registry layer digest is invalid", nil)
		}
		path, size, err := p.downloadBlob(ctx, session, request.Repository, layer.Digest)
		if err != nil {
			return domain.ImageDigest{}, pulledImage{}, err
		}
		pulled.Layers = append(pulled.Layers, blobFile{Digest: layer.Digest, Path: path, Size: size})
	}
	return image, pulled, nil
}

type descriptor struct {
	MediaType   string            `json:"mediaType,omitempty"`
	Digest      string            `json:"digest"`
	Size        int64             `json:"size,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
	Platform    *struct {
		OS           string `json:"os"`
		Architecture string `json:"architecture"`
		Variant      string `json:"variant,omitempty"`
	} `json:"platform,omitempty"`
}

type manifestDocument struct {
	MediaType string       `json:"mediaType,omitempty"`
	Manifests []descriptor `json:"manifests,omitempty"`
	Config    descriptor   `json:"config"`
	Layers    []descriptor `json:"layers,omitempty"`
}

type pulledImage struct {
	Manifest          []byte
	ManifestMediaType string
	ConfigDigest      string
	Config            []byte
	Layers            []blobFile
}

type blobFile struct {
	Digest string
	Path   string
	Size   int64
}

type archiveBlob struct {
	Content []byte
	Path    string
	Size    int64
}

func selectPlatform(values []descriptor) (descriptor, bool) {
	for _, value := range values {
		if !validDigest(value.Digest) || value.Platform == nil {
			continue
		}
		if normalizeOS(value.Platform.OS) == "linux" && normalizeArch(value.Platform.Architecture) == "amd64" {
			return value, true
		}
	}
	return descriptor{}, false
}

func (p *Provider) getManifest(ctx context.Context, session *httpSession, repository, reference string) ([]byte, string, string, error) {
	if !validTag(reference) && !validDigest(reference) {
		return nil, "", "", p.failure(session.operation, contracts.ErrValidation, "resolve", "registry manifest reference is invalid", nil)
	}
	path := registryPath(session.baseURL, repository, "manifests", reference)
	body, mediaType, headerDigest, err := p.get(ctx, session, path, ociIndexMediaType+", "+dockerManifestListMediaType+", "+ociManifestMediaType+", "+dockerManifestMediaType)
	if err != nil {
		return nil, "", "", err
	}
	computed := digestBytes(body)
	if headerDigest != "" && headerDigest != computed {
		return nil, "", "", p.failure(session.operation, contracts.ErrConflict, "resolve", "registry manifest content digest does not match response header", nil)
	}
	if headerDigest == "" {
		headerDigest = computed
	}
	return body, headerDigest, mediaType, nil
}

func (p *Provider) getBlob(ctx context.Context, session *httpSession, repository, digest string) ([]byte, error) {
	if !validDigest(digest) {
		return nil, p.failure(session.operation, contracts.ErrValidation, "resolve", "registry blob digest is invalid", nil)
	}
	body, _, _, err := p.get(ctx, session, registryPath(session.baseURL, repository, "blobs", digest), "application/octet-stream")
	if err != nil {
		return nil, err
	}
	if digestBytes(body) != digest {
		return nil, p.failure(session.operation, contracts.ErrConflict, "resolve", "registry blob content digest does not match descriptor", nil)
	}
	return body, nil
}

func (p *Provider) downloadBlob(ctx context.Context, session *httpSession, repository, digest string) (string, int64, error) {
	if !validDigest(digest) {
		return "", 0, p.failure(session.operation, contracts.ErrValidation, "resolve_and_pull", "registry layer digest is invalid", nil)
	}
	path := registryPath(session.baseURL, repository, "blobs", digest)
	resp, err := p.request(ctx, session, http.MethodGet, path, "application/octet-stream")
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	tmp := filepath.Join(session.workspace, strings.TrimPrefix(digest, "sha256:")+".blob")
	file, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", 0, p.failure(session.operation, contracts.ErrUnavailable, "resolve_and_pull", "registry layer workspace could not be created", err)
	}
	hash := sha256.New()
	reader := io.TeeReader(io.LimitReader(resp.Body, maxBlobSize+1), hash)
	size, copyErr := io.Copy(file, reader)
	syncErr := file.Sync()
	closeErr := file.Close()
	if copyErr != nil {
		_ = os.Remove(tmp)
		var pathErr *os.PathError
		if errors.Is(copyErr, io.ErrShortWrite) || (errors.As(copyErr, &pathErr) && pathErr.Op == "write") {
			return "", 0, p.failure(session.operation, contracts.ErrUnavailable, "resolve_and_pull", "registry layer workspace write failed", copyErr)
		}
		failure := p.classify(session.operation, "resolve_and_pull", copyErr)
		failure.Message = "registry layer response read failed"
		return "", 0, failure
	}
	if syncErr != nil || closeErr != nil {
		_ = os.Remove(tmp)
		if syncErr != nil {
			return "", 0, p.failure(session.operation, contracts.ErrUnavailable, "resolve_and_pull", "registry layer workspace sync failed", syncErr)
		}
		return "", 0, p.failure(session.operation, contracts.ErrUnavailable, "resolve_and_pull", "registry layer workspace close failed", closeErr)
	}
	if size > maxBlobSize {
		_ = os.Remove(tmp)
		return "", 0, p.failure(session.operation, contracts.ErrValidation, "resolve_and_pull", "registry layer response is too large", nil)
	}
	if "sha256:"+hex.EncodeToString(hash.Sum(nil)) != digest {
		_ = os.Remove(tmp)
		return "", 0, p.failure(session.operation, contracts.ErrConflict, "resolve_and_pull", "registry layer digest verification failed", nil)
	}
	return tmp, size, nil
}

func (p *Provider) writeArchive(session *httpSession, pulled pulledImage, request contracts.ImageResolveRequest) (string, error) {
	archivePath := filepath.Join(session.workspace, "image.oci.tar")
	file, err := os.OpenFile(archivePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", p.failure(session.operation, contracts.ErrUnavailable, "resolve_and_pull", "OCI archive workspace could not be created", nil)
	}
	tw := tar.NewWriter(file)
	blobEntries := map[string]archiveBlob{
		"blobs/sha256/" + strings.TrimPrefix(digestBytes(pulled.Manifest), "sha256:"): {Content: pulled.Manifest},
		"blobs/sha256/" + strings.TrimPrefix(pulled.ConfigDigest, "sha256:"):          {Content: pulled.Config},
	}
	for _, layer := range pulled.Layers {
		name := "blobs/sha256/" + strings.TrimPrefix(layer.Digest, "sha256:")
		if _, ok := blobEntries[name]; ok {
			continue
		}
		blobEntries[name] = archiveBlob{Path: layer.Path, Size: layer.Size}
	}
	entries := make([]string, 0, len(blobEntries))
	for name := range blobEntries {
		entries = append(entries, name)
	}
	sort.Strings(entries)
	layout := []byte(`{"imageLayoutVersion":"1.0.0"}` + "\n")
	manifestMediaType := strings.TrimSpace(strings.Split(pulled.ManifestMediaType, ";")[0])
	if manifestMediaType == "" {
		manifestMediaType = ociManifestMediaType
	}
	index := struct {
		SchemaVersion int          `json:"schemaVersion"`
		Manifests     []descriptor `json:"manifests"`
	}{SchemaVersion: 2, Manifests: []descriptor{{MediaType: manifestMediaType, Digest: digestBytes(pulled.Manifest), Size: int64(len(pulled.Manifest)), Annotations: map[string]string{"org.opencontainers.image.ref.name": request.Repository + ":" + request.Tag}}}}
	indexBytes, _ := json.Marshal(index)
	indexBytes = append(indexBytes, '\n')
	writeBytes := func(name string, content []byte) error {
		header := &tar.Header{Name: name, Mode: 0o644, Size: int64(len(content)), ModTime: time.Unix(0, 0).UTC(), Uid: 0, Gid: 0, Typeflag: tar.TypeReg}
		if err := tw.WriteHeader(header); err != nil {
			return err
		}
		_, err := tw.Write(content)
		return err
	}
	if err := writeBytes("oci-layout", layout); err != nil {
		_ = file.Close()
		_ = os.Remove(archivePath)
		return "", p.failure(session.operation, contracts.ErrUnavailable, "resolve_and_pull", "OCI archive layout could not be written", nil)
	}
	if err := writeBytes("index.json", indexBytes); err != nil {
		_ = file.Close()
		_ = os.Remove(archivePath)
		return "", p.failure(session.operation, contracts.ErrUnavailable, "resolve_and_pull", "OCI archive index could not be written", nil)
	}
	for _, name := range entries {
		blob := blobEntries[name]
		if blob.Content != nil {
			if err := writeBytes(name, blob.Content); err != nil {
				_ = tw.Close()
				_ = file.Close()
				_ = os.Remove(archivePath)
				return "", p.failure(session.operation, contracts.ErrUnavailable, "resolve_and_pull", "OCI blob could not be archived", nil)
			}
			continue
		}
		layerFile, openErr := os.Open(blob.Path)
		if openErr != nil {
			_ = tw.Close()
			_ = file.Close()
			_ = os.Remove(archivePath)
			return "", p.failure(session.operation, contracts.ErrUnavailable, "resolve_and_pull", "OCI layer could not be opened", nil)
		}
		header := &tar.Header{Name: name, Mode: 0o644, Size: blob.Size, ModTime: time.Unix(0, 0).UTC(), Uid: 0, Gid: 0, Typeflag: tar.TypeReg}
		copyErr := tw.WriteHeader(header)
		if copyErr == nil {
			_, copyErr = io.Copy(tw, layerFile)
		}
		closeErr := layerFile.Close()
		if copyErr == nil {
			copyErr = closeErr
		}
		if copyErr != nil {
			_ = tw.Close()
			_ = file.Close()
			_ = os.Remove(archivePath)
			return "", p.failure(session.operation, contracts.ErrUnavailable, "resolve_and_pull", "OCI layer could not be archived", nil)
		}
	}
	if err := tw.Close(); err != nil {
		_ = file.Close()
		_ = os.Remove(archivePath)
		return "", p.failure(session.operation, contracts.ErrUnavailable, "resolve_and_pull", "OCI archive could not be finalized", nil)
	}
	if err := file.Sync(); err == nil {
		err = file.Close()
	} else {
		_ = file.Close()
	}
	if err != nil {
		_ = os.Remove(archivePath)
		return "", p.failure(session.operation, contracts.ErrUnavailable, "resolve_and_pull", "OCI archive could not be synced", nil)
	}
	return archivePath, nil
}

func registryPath(base *url.URL, repository, kind, reference string) string {
	prefix := strings.TrimSuffix(base.Path, "/")
	return prefix + "/v2/" + stripRegistryHost(repository) + "/" + kind + "/" + reference
}

func (p *Provider) get(ctx context.Context, session *httpSession, path, accept string) ([]byte, string, string, error) {
	resp, err := p.request(ctx, session, http.MethodGet, path, accept)
	if err != nil {
		return nil, "", "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxMetadataSize+1))
	if err != nil {
		failure := p.classify(session.operation, "registry_http", err)
		failure.Message = "registry metadata response read failed"
		return nil, "", "", failure
	}
	if len(body) > maxMetadataSize {
		return nil, "", "", p.failure(session.operation, contracts.ErrValidation, "registry_http", "registry response is too large", nil)
	}
	return body, resp.Header.Get("Content-Type"), resp.Header.Get("Docker-Content-Digest"), nil
}

func (p *Provider) request(ctx context.Context, session *httpSession, method, path, accept string) (*http.Response, error) {
	u := *session.baseURL
	u.Path = path
	u.RawPath = ""
	req, err := http.NewRequestWithContext(ctx, method, u.String(), nil)
	if err != nil {
		return nil, p.failure(session.operation, contracts.ErrValidation, "registry_http", "registry request could not be constructed", nil)
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	if session.authHeader != "" {
		req.Header.Set("Authorization", session.authHeader)
	}
	resp, err := session.client.Do(req)
	if err != nil {
		return nil, p.classify(session.operation, "registry_http", err)
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		if resp.StatusCode == http.StatusUnauthorized && session.authHeader == "" && !session.tokenRetried {
			session.tokenRetried = true
			if challengeErr := p.handleAnonymousChallenge(ctx, session, session.repository, resp); challengeErr != nil {
				_ = resp.Body.Close()
				return nil, challengeErr
			}
			_ = resp.Body.Close()

			reqRetry, err := http.NewRequestWithContext(ctx, method, u.String(), nil)
			if err != nil {
				return nil, p.failure(session.operation, contracts.ErrValidation, "registry_http", "registry retry request could not be constructed", nil)
			}
			if accept != "" {
				reqRetry.Header.Set("Accept", accept)
			}
			if session.authHeader != "" {
				reqRetry.Header.Set("Authorization", session.authHeader)
			}
			respRetry, err := session.client.Do(reqRetry)
			if err != nil {
				return nil, p.classify(session.operation, "registry_http", err)
			}
			if respRetry.StatusCode < http.StatusOK || respRetry.StatusCode >= http.StatusMultipleChoices {
				_ = respRetry.Body.Close()
				code := contracts.ErrUnavailable
				if respRetry.StatusCode == http.StatusUnauthorized || respRetry.StatusCode == http.StatusForbidden {
					code = contracts.ErrUnauthorized
				}
				if respRetry.StatusCode == http.StatusNotFound {
					code = contracts.ErrNotFound
				}
				return nil, p.failure(session.operation, code, "registry_http", "registry returned an unsuccessful response", nil)
			}
			return respRetry, nil
		}

		_ = resp.Body.Close()
		code := contracts.ErrUnavailable
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			code = contracts.ErrUnauthorized
		}
		if resp.StatusCode == http.StatusNotFound {
			code = contracts.ErrNotFound
		}
		return nil, p.failure(session.operation, code, "registry_http", "registry returned an unsuccessful response", nil)
	}
	return resp, nil
}

func normalizeConfig(config Config) (Config, error) {
	if strings.TrimSpace(config.BaseURL) == "" {
		config.BaseURL = strings.TrimSpace(config.RegistryURL)
	}
	if config.Timeout == 0 {
		config.Timeout = defaultTimeout
	}
	if config.Timeout <= 0 {
		return Config{}, errors.New("registry HTTP timeout must be positive")
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	if config.TempRoot != "" {
		root, err := filepath.Abs(config.TempRoot)
		if err != nil {
			return Config{}, errors.New("registry HTTP temp root is invalid")
		}
		if info, err := os.Lstat(root); err == nil {
			if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
				return Config{}, errors.New("registry HTTP temp root must be a directory")
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return Config{}, errors.New("registry HTTP temp root is unavailable")
		}
		config.TempRoot = root
	}
	if config.BaseURL != "" {
		parsed, err := url.Parse(strings.TrimSpace(config.BaseURL))
		if err != nil || parsed.User != nil || parsed.Host == "" || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
			return Config{}, errors.New("registry HTTP base URL is invalid")
		}
		if parsed.Scheme == "http" && !isLoopbackHost(parsed.Hostname()) {
			return Config{}, errors.New("plain HTTP registry endpoints must be loopback")
		}
		config.BaseURL = parsed.String()
	}
	client := config.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: config.Timeout}
	} else {
		copyClient := *client
		client = &copyClient
		if client.Timeout == 0 {
			client.Timeout = config.Timeout
		}
	}
	// Registry authentication is explicit; ambient cookies must never be sent to blob storage.
	client.Jar = nil
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) == 0 {
			return nil
		}
		if len(via) > maxRedirectHops {
			return errHTTPBoundary
		}
		previous := via[len(via)-1].URL
		initial := via[0].URL

		// 1. Same-host redirect
		if strings.EqualFold(previous.Host, req.URL.Host) {
			if !strings.EqualFold(previous.Scheme, req.URL.Scheme) {
				return errHTTPBoundary
			}
			if req.URL.Scheme == "http" && !isLoopbackHost(req.URL.Hostname()) {
				return errHTTPBoundary
			}
			if req.URL.User != nil || req.URL.Fragment != "" {
				return errHTTPBoundary
			}
			return nil
		}

		// 2. Cross-host redirect permitted ONLY for validated GHCR content-addressed blobs to EXACT pkg-containers.githubusercontent.com
		if isGHCRBlobRequest(initial) {
			if req.URL.Scheme != "https" {
				return errHTTPBoundary
			}
			if !strings.EqualFold(req.URL.Hostname(), ghcrCDNHost) {
				return errHTTPBoundary
			}
			if port := req.URL.Port(); port != "" && port != "443" {
				return errHTTPBoundary
			}
			if req.URL.User != nil || req.URL.Fragment != "" {
				return errHTTPBoundary
			}
			// Strip sensitive headers on CDN hops: never send registry bearer to CDN or return auth to registry after CDN
			req.Header.Del("Authorization")
			req.Header.Del("Proxy-Authorization")
			req.Header.Del("Cookie")
			return nil
		}

		return errHTTPBoundary
	}
	config.HTTPClient = client
	return config, nil
}

func (p *Provider) check(ctx context.Context, operation contracts.OperationContext) error {
	if err := p.metadata.Supports(contracts.CapabilityImageResolve); err != nil {
		return p.failure(operation, contracts.ErrUnsupportedCapability, "resolve", "registry provider capability is unavailable", err)
	}
	if err := operation.Validate(); err != nil {
		return p.failure(operation, contracts.ErrInvalidArgument, "resolve", "provider idempotency key is required", nil)
	}
	if err := ctx.Err(); err != nil {
		return p.classify(operation, "resolve", err)
	}
	if !operation.Deadline.IsZero() && !time.Now().Before(operation.Deadline) {
		return p.classify(operation, "resolve", context.DeadlineExceeded)
	}
	return nil
}

func (p *Provider) failure(operation contracts.OperationContext, code contracts.ErrorCode, action, message string, cause error) *contracts.ProviderError {
	retry, retryable := contracts.RetryNever, false
	if code == contracts.ErrUnavailable || code == contracts.ErrTimeout {
		retry, retryable = contracts.RetryBackoff, true
	}
	if code == contracts.ErrCancelled {
		retry, retryable = contracts.RetryAfterReconnect, true
	}
	if code == contracts.ErrUnauthorized || code == contracts.ErrConflict {
		retry = contracts.RetryUserAction
	}
	digest := sha256.Sum256([]byte(operation.IdempotencyKey))
	return &contracts.ProviderError{Provider: providerName, Code: code, Message: message, Retry: retry, Retryable: retryable, Capability: contracts.CapabilityImageResolve, Operation: action, Cause: cause,
		Details: map[string]string{"evidence_ref": "ev_" + hex.EncodeToString(digest[:])[:32]}}
}

func (p *Provider) classify(operation contracts.OperationContext, action string, err error) *contracts.ProviderError {
	if errors.Is(err, context.Canceled) {
		return p.failure(operation, contracts.ErrCancelled, action, "registry operation was cancelled", err)
	}
	var timeout net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &timeout) && timeout.Timeout()) {
		return p.failure(operation, contracts.ErrTimeout, action, "registry operation timed out", err)
	}
	return p.failure(operation, contracts.ErrUnavailable, action, "registry HTTP operation failed", err)
}

func (p *Provider) begin(key, fingerprint string) (*operationRecord, bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if previous, ok := p.operations[key]; ok {
		if previous.fingerprint != fingerprint {
			return nil, false, errors.New("idempotency key was reused for a different registry operation")
		}
		// A completed retryable failure may run again under the same immutable
		// request. In-flight calls, success and permanent failures still replay.
		select {
		case <-previous.done:
			var failure *contracts.ProviderError
			if !errors.As(previous.err, &failure) || !failure.Retryable {
				return previous, false, nil
			}
		default:
			return previous, false, nil
		}
	}
	// finish only writes its own record pointer under this same mutex. Replacing
	// a completed record cannot let its result overwrite the new attempt.
	record := &operationRecord{fingerprint: fingerprint, done: make(chan struct{})}
	p.operations[key] = record
	return record, true, nil
}

func (p *Provider) finish(record *operationRecord, result contracts.ImageResolveResult, err error) {
	p.mu.Lock()
	record.result = cloneResult(result)
	record.err = err
	close(record.done)
	p.mu.Unlock()
}

func waitRecord(ctx context.Context, operation contracts.OperationContext, record *operationRecord) error {
	if operation.Deadline.IsZero() {
		select {
		case <-record.done:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	timer := time.NewTimer(time.Until(operation.Deadline))
	defer timer.Stop()
	select {
	case <-record.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return context.DeadlineExceeded
	}
}

func cloneResult(result contracts.ImageResolveResult) contracts.ImageResolveResult {
	result.Evidence.Refs = append([]domain.EvidenceRef(nil), result.Evidence.Refs...)
	return result
}

func requestFingerprint(request contracts.ImageResolveRequest) (string, error) {
	if err := validateRepository(request.Repository); err != nil || (!validTag(request.Tag) && !validDigest(request.Tag)) {
		return "", errInvalidRegistry
	}
	secret := ""
	if request.Secret != nil {
		if err := request.Secret.Validate(); err != nil {
			return "", errInvalidRegistry
		}
		secret = string(request.Secret.ID) + "\x00" + request.Secret.Name + "\x00" + request.Secret.Provider + "\x00" + request.Secret.Version
	}
	return digestString(request.Repository, request.Tag, secret, "linux", "amd64"), nil
}

func operationContext(ctx context.Context, operation contracts.OperationContext, timeout time.Duration) (context.Context, context.CancelFunc) {
	if !operation.Deadline.IsZero() {
		return context.WithDeadline(ctx, operation.Deadline)
	}
	return context.WithTimeout(ctx, timeout)
}

func storageKey(image domain.ImageDigest) string {
	return "registryhttp/" + strings.TrimPrefix(digestString(image.Repository, image.Digest), "sha256:")
}

func (p *Provider) resultFor(request contracts.ImageResolveRequest, image domain.ImageDigest, mode, summary string) contracts.ImageResolveResult {
	resultDigest := digestString(mode, request.Repository, request.Tag, image.Digest, "linux", "amd64")
	return contracts.ImageResolveResult{
		Image: image,
		Evidence: contracts.Evidence{
			Refs: []domain.EvidenceRef{{
				ID:      domain.ID("ev_" + resultDigest[7:39]),
				Kind:    "registry.http." + mode,
				Digest:  resultDigest,
				Locator: "registry://" + request.Repository + "@" + image.Digest,
			}},
			Summary:  summary,
			Digest:   resultDigest,
			Redacted: true,
		},
	}
}

func readAuthorization(path, host string) (string, []byte, error) {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return "", nil, errCredential
	}
	file, err := os.Open(path)
	if err != nil {
		return "", nil, errCredential
	}
	content, readErr := io.ReadAll(io.LimitReader(file, 1<<20+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || len(content) == 0 || len(content) > 1<<20 {
		zeroBytes(content)
		return "", nil, errCredential
	}
	encoded, parseErr := parseCredential(content, host)
	zeroBytes(content)
	if parseErr != nil {
		return "", nil, parseErr
	}
	headerBytes := append([]byte("Basic "), encoded...)
	zeroBytes(encoded)
	return string(headerBytes), headerBytes, nil
}

type dockerAuthEntry struct {
	Auth     string `json:"auth,omitempty"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

type credentialPayload struct {
	Auth     string                     `json:"auth"`
	Username string                     `json:"username"`
	Password string                     `json:"password"`
	Token    string                     `json:"token"`
	Auths    map[string]dockerAuthEntry `json:"auths"`
}

func parseCredential(content []byte, host string) ([]byte, error) {
	trimmed := bytes.TrimSpace(content)
	if len(trimmed) == 0 {
		return nil, errCredential
	}
	if trimmed[0] == '{' {
		var payload credentialPayload
		if err := json.Unmarshal(trimmed, &payload); err != nil {
			return nil, errCredential
		}
		for key, entry := range payload.Auths {
			if registryKeyMatches(key, host) {
				if entry.Auth != "" {
					return []byte(entry.Auth), nil
				}
				return basicAuth(entry.Username, entry.Password)
			}
		}
		if payload.Auth != "" {
			return []byte(payload.Auth), nil
		}
		if payload.Token != "" {
			return basicAuth("", payload.Token)
		}
		return basicAuth(payload.Username, payload.Password)
	}
	text := strings.TrimSpace(string(trimmed))
	if strings.Contains(text, "\n") {
		parts := strings.SplitN(text, "\n", 2)
		return basicAuth(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
	}
	if index := strings.IndexByte(text, ':'); index > 0 {
		return basicAuth(text[:index], text[index+1:])
	}
	return basicAuth("", text)
}

func registryKeyMatches(key, host string) bool {
	normalize := func(value string) string {
		value = strings.TrimSuffix(strings.TrimSpace(value), "/")
		value = strings.TrimPrefix(value, "https://")
		value = strings.TrimPrefix(value, "http://")
		return value
	}
	return normalize(key) == normalize(host)
}

func basicAuth(username, password string) ([]byte, error) {
	if username == "" && password == "" {
		return nil, errCredential
	}
	return []byte(base64.StdEncoding.EncodeToString([]byte(username + ":" + password))), nil
}

func zeroBytes(value []byte) {
	for i := range value {
		value[i] = 0
	}
}

func validateRepository(repository string) error {
	if strings.TrimSpace(repository) != repository || repository == "" || strings.ContainsAny(repository, "\\@?#\r\n\x00 \t") || strings.HasPrefix(repository, "/") || strings.HasSuffix(repository, "/") || strings.Contains(repository, "..") {
		return errInvalidRegistry
	}
	for index, part := range strings.Split(repository, "/") {
		if part == "" || part == "." || part == ".." {
			return errInvalidRegistry
		}
		if strings.Contains(part, ":") {
			if index != 0 {
				return errInvalidRegistry
			}
			host, port, ok := strings.Cut(part, ":")
			if !ok || host == "" || port == "" || strings.Trim(port, "0123456789") != "" {
				return errInvalidRegistry
			}
			part = host
		}
		for _, r := range part {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._-", r)) {
				return errInvalidRegistry
			}
		}
	}
	return nil
}

func validTag(tag string) bool {
	if strings.TrimSpace(tag) != tag || tag == "" || len(tag) > 128 || strings.ContainsAny(tag, "/:@\\\r\n\x00 \t") {
		return false
	}
	for _, r := range tag {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("_.-", r)) {
			return false
		}
	}
	return true
}

func validDigest(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || value != strings.ToLower(value) || len(value) != len("sha256:")+64 {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil
}

func registryHost(repository string) string {
	host := strings.Split(repository, "/")[0]
	if !strings.ContainsAny(host, ".:") && host != "localhost" {
		return "registry-1.docker.io"
	}
	return host
}

func registryHostIfExplicit(repository string) string {
	host := strings.Split(repository, "/")[0]
	if strings.ContainsAny(host, ".:") || host == "localhost" || net.ParseIP(host) != nil {
		return host
	}
	return ""
}

func stripRegistryHost(repository string) string {
	if host := registryHostIfExplicit(repository); host != "" {
		_, path, ok := strings.Cut(repository, "/")
		if ok && path != "" {
			return path
		}
	}
	return repository
}

func normalizeOS(value string) string { return strings.ToLower(strings.TrimSpace(value)) }

func normalizeArch(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "x86_64":
		return "amd64"
	case "aarch64":
		return "arm64"
	default:
		return strings.ToLower(strings.TrimSpace(value))
	}
}

func digestBytes(value []byte) string {
	digest := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func digestString(values ...string) string {
	hash := sha256.New()
	for _, value := range values {
		_, _ = io.WriteString(hash, value)
		_, _ = hash.Write([]byte{0})
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil))
}

var _ interface {
	contracts.Provider
	Resolve(context.Context, contracts.ImageResolveRequest) (contracts.ImageResolveResult, error)
	ResolveAndPull(context.Context, contracts.ImageResolveRequest) (contracts.ImageResolveResult, error)
} = (*Provider)(nil)
