// Package source materializes bounded, immutable source workspaces for the
// control plane. It accepts only public HTTPS Git repositories and local
// uploads rooted in an explicitly configured directory. The package never
// persists a caller-supplied workspace reference or a source locator in its
// evidence/errors, because either could expose local topology or credentials.
package source

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/foundation"
)

const (
	providerName    = "bounded-source"
	providerVersion = "m1"
	prepareAction   = "prepare"
)

var commitPattern = regexp.MustCompile(`^[0-9a-f]{40}([0-9a-f]{24})?$`)

// Config declares the only two local filesystem boundaries used by Provider.
// UploadRoot is read-only input owned by the upload handler. WorkspaceRoot is
// provider-owned output; finalized directories are made filesystem read-only.
// Both paths are resolved once at construction, preventing a caller from
// selecting arbitrary host paths in a PrepareSourceRequest.
type Config struct {
	UploadRoot                         string
	WorkspaceRoot                      string
	WorkspaceCapacityBytes             int64
	WorkspaceCapacityEntries           int64
	WorkspaceOperationalReserveBytes   int64
	WorkspaceOperationalReserveEntries int64
	Limits                             foundation.ArchiveLimits
	GitBinary                          string
	// GitResolvers and GitResolverEndpoints are a fail-closed public-DNS
	// boundary. When both are empty, uploads remain available but public Git
	// preparation is deliberately unavailable rather than using the host
	// resolver.
	GitResolvers         []GitResolver
	GitResolverEndpoints []string
	Clock                func() time.Time
}

// Provider is a concrete contracts.SourceProvider. A mutex intentionally
// covers a complete preparation: it makes retries deterministic and avoids
// two callers racing to publish different content for one idempotency key.
type Provider struct {
	metadata                           contracts.ProviderMetadata
	uploadRoot                         string
	workspaceRoot                      string
	workspaceCapacityBytes             int64
	workspaceCapacityEntries           int64
	workspaceOperationalReserveBytes   int64
	workspaceOperationalReserveEntries int64
	filesystemAvailability             func(string) (workspaceFilesystemAvailability, error)
	limits                             foundation.ArchiveLimits
	gitBinary                          string
	gitResolvers                       []GitResolver
	clock                              func() time.Time

	// testGitFixture and gitTLSCAFile have no Config surface. They exist only
	// for the package-local HTTPS fixture which proves Git's TLS/pinned-address
	// behavior without making a local-address or custom-CA escape available to
	// the production process.
	testGitFixture bool
	gitTLSCAFile   string

	mu    sync.Mutex
	byKey map[string]storedResult
}

type storedResult struct {
	fingerprint string
	result      contracts.PrepareSourceResult
}

// New constructs a provider with finite, fail-closed archive limits. It does
// not create or modify either root; WorkspaceRoot is created on first use so
// startup remains read-only.
func New(config Config) (*Provider, error) {
	uploadRoot, err := existingDirectory(config.UploadRoot)
	if err != nil {
		return nil, fmt.Errorf("source upload root: %w", err)
	}
	workspaceRoot, err := absolutePath(config.WorkspaceRoot)
	if err != nil {
		return nil, fmt.Errorf("source workspace root: %w", err)
	}
	limits := config.Limits
	if limits.MaxFiles == 0 && limits.MaxUnpackedBytes == 0 {
		limits = foundation.DefaultArchiveLimits
	}
	if limits.MaxFiles <= 0 || limits.MaxUnpackedBytes <= 0 {
		return nil, errors.New("source limits must be finite and positive")
	}
	workspaceCapacityBytes, workspaceCapacityEntries, err := normalizedWorkspaceCapacity(config.WorkspaceCapacityBytes, config.WorkspaceCapacityEntries, limits)
	if err != nil {
		return nil, err
	}
	workspaceOperationalReserveBytes, workspaceOperationalReserveEntries, err := normalizedWorkspaceOperationalReserve(config.WorkspaceOperationalReserveBytes, config.WorkspaceOperationalReserveEntries)
	if err != nil {
		return nil, err
	}
	gitBinary := strings.TrimSpace(config.GitBinary)
	if gitBinary == "" {
		gitBinary = "git"
	}
	gitResolvers, err := configuredGitResolvers(config.GitResolvers, config.GitResolverEndpoints)
	if err != nil {
		return nil, fmt.Errorf("public Git resolvers: %w", err)
	}
	clock := config.Clock
	if clock == nil {
		clock = time.Now
	}
	return &Provider{
		metadata: contracts.ProviderMetadata{
			Name:            providerName,
			Version:         providerVersion,
			ContractVersion: contracts.ContractAPIVersion,
			Capabilities:    contracts.NewCapabilitySet(contracts.CapabilitySourcePrepare, contracts.CapabilitySourceRelease),
			SensitiveInputs: []string{"source.locator", "source.workspace_ref"},
		},
		uploadRoot: uploadRoot, workspaceRoot: workspaceRoot, limits: limits, workspaceCapacityBytes: workspaceCapacityBytes, workspaceCapacityEntries: workspaceCapacityEntries,
		workspaceOperationalReserveBytes: workspaceOperationalReserveBytes, workspaceOperationalReserveEntries: workspaceOperationalReserveEntries, filesystemAvailability: workspaceFilesystemAvailabilityForRoot,
		gitBinary: gitBinary, gitResolvers: gitResolvers, clock: clock, byKey: make(map[string]storedResult),
	}, nil
}

// Metadata reports the stable source preparation contract.
func (p *Provider) Metadata(context.Context) contracts.ProviderMetadata { return p.metadata }

// Release removes only the immutable workspace previously returned by this
// provider. It is idempotent and refuses caller-selected paths outside the
// configured workspace root.
func (p *Provider) Release(ctx context.Context, request contracts.ReleaseSourceRequest) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.checkFor(ctx, request.Operation, contracts.CapabilitySourceRelease); err != nil {
		return err
	}
	if err := request.Revision.Validate(); err != nil {
		return p.failure(request.Operation, contracts.ErrValidation, "source revision is invalid", nil)
	}
	releaseLock, err := acquireWorkspaceRootLock(p.workspaceRoot)
	if err != nil {
		return p.failure(request.Operation, contracts.ErrUnavailable, "source workspace is unavailable", nil)
	}
	defer releaseLock()
	workspace, err := filepath.Abs(request.Revision.WorkspaceRef)
	if err != nil || !withinSourceRoot(p.workspaceRoot, workspace) || filepath.Clean(workspace) == filepath.Clean(p.workspaceRoot) {
		return p.failure(request.Operation, contracts.ErrForbidden, "source workspace is outside provider boundary", nil)
	}
	resolved, err := filepath.EvalSymlinks(workspace)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	root, rootErr := filepath.EvalSymlinks(p.workspaceRoot)
	info, statErr := os.Lstat(workspace)
	if err != nil || rootErr != nil || statErr != nil || info.Mode()&fs.ModeSymlink != 0 || !info.IsDir() || !withinSourceRoot(root, resolved) {
		return p.failure(request.Operation, contracts.ErrForbidden, "source workspace is not a provider-owned immutable directory", nil)
	}
	if err := filepath.WalkDir(resolved, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&fs.ModeSymlink != 0 {
			return errors.New("source workspace contains a symbolic link")
		}
		mode := fs.FileMode(0o600)
		if entry.IsDir() {
			mode = 0o700
		}
		return os.Chmod(path, mode)
	}); err != nil {
		return p.failure(request.Operation, contracts.ErrUnavailable, "source workspace release failed", nil)
	}
	if err := os.RemoveAll(resolved); err != nil {
		return p.failure(request.Operation, contracts.ErrUnavailable, "source workspace release failed", nil)
	}
	p.invalidateCachedWorkspace(workspace)
	return nil
}

// Prepare validates, snapshots, hashes, and publishes a source workspace. No
// partially copied workspace is ever returned. A SourceRevision only becomes
// visible after its tree has been written, hashed, and made read-only.
func (p *Provider) Prepare(ctx context.Context, request contracts.PrepareSourceRequest) (contracts.PrepareSourceResult, error) {
	if err := p.checkPrepare(ctx, request.Operation); err != nil {
		return contracts.PrepareSourceResult{}, err
	}
	ctx, cancel := operationContext(ctx, request.Operation)
	defer cancel()
	if request.ApplicationID.Empty() {
		return contracts.PrepareSourceResult{}, p.failure(request.Operation, contracts.ErrInvalidArgument, "application id is required", nil)
	}
	if strings.TrimSpace(request.Locator) == "" {
		return contracts.PrepareSourceResult{}, p.failure(request.Operation, contracts.ErrInvalidArgument, "source locator is required", nil)
	}

	// Do not include raw locators in this fingerprint. Git locators have been
	// normalized below, but upload paths are still host-local implementation
	// details and must not become part of durable error/evidence data.
	fingerprint, err := p.requestFingerprint(request)
	if err != nil {
		return contracts.PrepareSourceResult{}, p.failure(request.Operation, contracts.ErrValidation, "source request is invalid", nil)
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if previous, ok := p.byKey[request.Operation.IdempotencyKey]; ok {
		if previous.fingerprint != fingerprint {
			return contracts.PrepareSourceResult{}, p.failure(request.Operation, contracts.ErrConflict, "idempotency key was reused for a different source", nil)
		}
		if err := p.ensureWorkspaceRoot(); err != nil {
			return contracts.PrepareSourceResult{}, p.failure(request.Operation, contracts.ErrUnavailable, "source workspace is unavailable", nil)
		}
		replayLock, err := acquireWorkspaceRootLock(p.workspaceRoot)
		if err != nil {
			return contracts.PrepareSourceResult{}, p.failure(request.Operation, contracts.ErrUnavailable, "source workspace is unavailable", nil)
		}
		defer replayLock()
		if err := p.verifyCachedRevision(previous.result.Revision); err != nil {
			delete(p.byKey, request.Operation.IdempotencyKey)
			return contracts.PrepareSourceResult{}, p.failure(request.Operation, contracts.ErrUnavailable, "source workspace is unavailable", nil)
		}
		return cloneResult(previous.result), nil
	}
	if err := p.ensureWorkspaceRoot(); err != nil {
		return contracts.PrepareSourceResult{}, p.failure(request.Operation, contracts.ErrUnavailable, "source workspace is unavailable", nil)
	}
	prepareLock, err := acquireWorkspaceRootLock(p.workspaceRoot)
	if err != nil {
		return contracts.PrepareSourceResult{}, p.failure(request.Operation, contracts.ErrUnavailable, "source workspace is unavailable", nil)
	}
	defer prepareLock()
	usage, err := measureWorkspacePool(p.workspaceRoot)
	if err != nil {
		return contracts.PrepareSourceResult{}, p.failure(request.Operation, contracts.ErrUnavailable, "source workspace is unavailable", nil)
	}
	reserve, err := workspaceAdmissionReserve(request.Kind, p.limits)
	if err != nil || !workspaceAdmissionAllowed(usage, reserve, p.workspaceCapacityBytes, p.workspaceCapacityEntries) {
		return contracts.PrepareSourceResult{}, p.failure(request.Operation, contracts.ErrUnavailable, "source workspace capacity is unavailable", nil)
	}
	availability, err := p.filesystemAvailability(p.workspaceRoot)
	if err != nil || !workspaceFilesystemAdmissionAllowed(availability, reserve, p.workspaceOperationalReserveBytes, p.workspaceOperationalReserveEntries) {
		return contracts.PrepareSourceResult{}, p.failure(request.Operation, contracts.ErrUnavailable, "source workspace capacity is unavailable", nil)
	}

	stage, err := os.MkdirTemp(p.workspaceRoot, ".source-stage-")
	if err != nil {
		return contracts.PrepareSourceResult{}, p.failure(request.Operation, contracts.ErrUnavailable, "source workspace is unavailable", nil)
	}
	defer os.RemoveAll(stage)

	var locator, ref, commit string
	switch request.Kind {
	case domain.SourceGitHTTPS:
		locator, ref, commit, err = p.materializeGit(ctx, stage, request)
	case domain.SourceUpload:
		locator, err = p.materializeUpload(stage, request.Locator)
	default:
		err = errUnsupportedSource
	}
	if err != nil {
		return contracts.PrepareSourceResult{}, p.classify(request.Operation, err)
	}

	digestHex, err := foundation.HashDirectory(stage)
	if err != nil {
		return contracts.PrepareSourceResult{}, p.failure(request.Operation, contracts.ErrValidation, "source tree failed safety validation", nil)
	}
	digest := "sha256:" + digestHex
	if expected := strings.TrimSpace(request.ContentDigest); expected != "" && !sameDigest(expected, digestHex) {
		return contracts.PrepareSourceResult{}, p.failure(request.Operation, contracts.ErrConflict, "source content digest did not match", nil)
	}
	workspace, err := p.publish(stage, digestHex)
	if err != nil {
		return contracts.PrepareSourceResult{}, p.failure(request.Operation, contracts.ErrUnavailable, "immutable source workspace could not be published", nil)
	}
	revision, err := domain.NewSourceRevision(request.ApplicationID, request.Kind, locator, ref, commit, digest, workspace, p.clock().UTC())
	if err != nil {
		return contracts.PrepareSourceResult{}, p.failure(request.Operation, contracts.ErrValidation, "immutable source revision is invalid", nil)
	}
	result := contracts.PrepareSourceResult{Revision: revision, Evidence: p.evidence(request.Operation, digest)}
	p.byKey[request.Operation.IdempotencyKey] = storedResult{fingerprint: fingerprint, result: result}
	return cloneResult(result), nil
}

var errUnsupportedSource = errors.New("unsupported source kind")

func (p *Provider) checkFor(ctx context.Context, operation contracts.OperationContext, capability contracts.Capability) error {
	if err := p.checkPrepareFor(ctx, operation, capability); err != nil {
		return err
	}
	if err := p.ensureWorkspaceRoot(); err != nil {
		return p.failure(operation, contracts.ErrUnavailable, "source workspace is unavailable", nil)
	}
	return nil
}

func (p *Provider) checkPrepare(ctx context.Context, operation contracts.OperationContext) error {
	return p.checkPrepareFor(ctx, operation, contracts.CapabilitySourcePrepare)
}

func (p *Provider) checkPrepareFor(ctx context.Context, operation contracts.OperationContext, capability contracts.Capability) error {
	if err := p.metadata.Validate(); err != nil {
		return err
	}
	if err := p.metadata.Supports(capability); err != nil {
		return err
	}
	if err := operation.Validate(); err != nil {
		return p.failure(operation, contracts.ErrInvalidArgument, "provider idempotency key is required", nil)
	}
	if err := contextError(ctx, operation); err != nil {
		return p.classify(operation, err)
	}
	return nil
}

func (p *Provider) ensureWorkspaceRoot() error {
	if err := os.MkdirAll(p.workspaceRoot, 0o700); err != nil {
		return errWorkspaceUnavailable
	}
	info, err := os.Lstat(p.workspaceRoot)
	if err != nil || !info.IsDir() || info.Mode()&fs.ModeSymlink != 0 {
		return errWorkspaceUnavailable
	}
	return nil
}

func (p *Provider) verifyCachedRevision(revision domain.SourceRevision) error {
	if err := revision.Validate(); err != nil {
		return errWorkspaceUnavailable
	}
	workspace, err := filepath.Abs(revision.WorkspaceRef)
	if err != nil || !withinSourceRoot(p.workspaceRoot, workspace) || filepath.Clean(workspace) == filepath.Clean(p.workspaceRoot) {
		return errWorkspaceUnavailable
	}
	info, err := os.Lstat(workspace)
	if err != nil || !info.IsDir() || info.Mode()&fs.ModeSymlink != 0 {
		return errWorkspaceUnavailable
	}
	digest, err := foundation.HashDirectory(workspace)
	if err != nil || !sameDigest(revision.ContentDigest, digest) {
		return errWorkspaceUnavailable
	}
	return nil
}

func (p *Provider) invalidateCachedWorkspace(workspace string) {
	for key, result := range p.byKey {
		if result.result.Revision.WorkspaceRef == workspace {
			delete(p.byKey, key)
		}
	}
}

func withinSourceRoot(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func (p *Provider) requestFingerprint(request contracts.PrepareSourceRequest) (string, error) {
	parts := []string{string(request.ApplicationID), string(request.Kind), strings.TrimSpace(request.Ref), strings.TrimSpace(request.ContentDigest)}
	switch request.Kind {
	case domain.SourceGitHTTPS:
		git, err := p.normalizeGitSource(request.Locator, request.Ref)
		if err != nil || git.Scheme != foundation.GitHTTPS {
			return "", errUnsupportedSource
		}
		parts[2] = git.Ref
		parts = append(parts, git.Locator)
	case domain.SourceUpload:
		if !strings.HasPrefix(request.Locator, "upload://") {
			return "", errUploadRejected
		}
		if _, err := p.storedUploadPath(request.Locator); err != nil {
			return "", err
		}
		parts = append(parts, request.Locator)
	default:
		return "", errUnsupportedSource
	}
	return digestStrings(parts...), nil
}

func (p *Provider) materializeGit(ctx context.Context, stage string, request contracts.PrepareSourceRequest) (string, string, string, error) {
	git, err := p.normalizeGitSource(request.Locator, request.Ref)
	if err != nil || git.Scheme != foundation.GitHTTPS {
		return "", "", "", errUnsupportedSource
	}
	gitContext, cancel := context.WithTimeout(ctx, defaultGitTimeout)
	defer cancel()
	authority, err := p.resolveGitAuthority(gitContext, git)
	if err != nil {
		return "", "", "", err
	}
	commit, err := p.resolveCommit(gitContext, git, authority)
	if err != nil {
		return "", "", "", err
	}
	gitDir, err := os.MkdirTemp(p.workspaceRoot, ".git-objects-")
	if err != nil {
		return "", "", "", errWorkspaceUnavailable
	}
	defer os.RemoveAll(gitDir)
	if err := p.git(ctx, gitDir, "init", "--bare"); err != nil {
		if ctx.Err() != nil {
			return "", "", "", ctx.Err()
		}
		return "", "", "", errGitUnavailable
	}
	if err := p.gitPinnedFetch(gitContext, gitDir, authority, "fetch", "--depth=1", "--no-tags", git.Locator, commit); err != nil {
		if gitContext.Err() != nil {
			return "", "", "", gitContext.Err()
		}
		if errors.Is(err, errGitTooLarge) {
			return "", "", "", err
		}
		return "", "", "", errGitUnavailable
	}
	if err := boundedGitObjectDirectory(gitDir, p.limits); err != nil {
		return "", "", "", err
	}
	if err := p.extractGitArchive(gitContext, gitDir, commit, stage); err != nil {
		return "", "", "", err
	}
	return git.Locator, git.Ref, commit, nil
}

func (p *Provider) resolveCommit(ctx context.Context, git foundation.GitSource, authority gitAuthority) (string, error) {
	output, err := p.gitOutputPinned(ctx, "", authority, "ls-remote", "--refs", "--exit-code", git.Locator, git.Ref)
	if err != nil {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		if errors.Is(err, errGitTooLarge) {
			return "", err
		}
		return "", errGitUnavailable
	}
	lines := strings.Fields(string(output))
	if len(lines) != 2 || !commitPattern.MatchString(strings.ToLower(lines[0])) {
		return "", errGitUnresolved
	}
	return strings.ToLower(lines[0]), nil
}

func (p *Provider) extractGitArchive(ctx context.Context, gitDir, commit, stage string) error {
	command := exec.CommandContext(ctx, p.gitBinary, "-C", gitDir, "-c", "core.hooksPath=/dev/null", "archive", "--format=tar", commit)
	command.Env = gitEnvironment()
	// A canceled archive must close inherited stdout writers too, otherwise
	// draining the pipe could outlive the Git parent and its deadline.
	startGitProcessGroup(command)
	command.Cancel = func() error { stopGitProcessGroup(command); return nil }
	stdout, err := command.StdoutPipe()
	if err != nil {
		return errGitUnavailable
	}
	if err := command.Start(); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errGitUnavailable
	}
	copyErr := extractTar(tar.NewReader(stdout), stage, p.limits)
	if copyErr == nil {
		// tar.Reader stops at its logical EOF, before Git's zero record padding.
		// Drain that bounded padding before Wait so a full stdout pipe cannot
		// prevent the archive producer from exiting. A second archive is not padding.
		const maxGitArchivePadding = 1 << 20
		tail := &io.LimitedReader{R: stdout, N: maxGitArchivePadding + 1}
		buffer := make([]byte, 32<<10)
		for {
			n, readErr := tail.Read(buffer)
			if n > 0 {
				if tail.N == 0 {
					copyErr = errGitTooLarge
					break
				}
				if len(bytes.Trim(buffer[:n], "\x00")) != 0 {
					copyErr = errUploadRejected
					break
				}
			}
			if readErr == io.EOF {
				break
			}
			if readErr != nil || n == 0 {
				copyErr = errGitUnavailable
				break
			}
		}
	}
	if copyErr != nil {
		stopGitProcessGroup(command)
		_ = command.Wait()
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return copyErr
	}
	waitErr := command.Wait()
	if waitErr != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errGitUnavailable
	}
	return nil
}

func (p *Provider) materializeUpload(stage, locator string) (string, error) {
	if strings.HasPrefix(locator, "upload://") {
		stored, err := p.storedUploadPath(locator)
		if err != nil {
			return "", err
		}
		files := filepath.Join(stored, "files")
		if info, statErr := os.Lstat(files); statErr == nil && info.IsDir() && info.Mode()&fs.ModeSymlink == 0 {
			if err := copyDirectory(files, stage, p.limits); err != nil {
				return "", err
			}
			return locator, nil
		}
		entries, err := os.ReadDir(stored)
		if err != nil {
			return "", errUploadRejected
		}
		var archive string
		for _, entry := range entries {
			if entry.IsDir() || entry.Type()&fs.ModeSymlink != 0 {
				continue
			}
			name := entry.Name()
			if name == "archive.zip" || name == "archive.tar.gz" || name == "archive.tgz" {
				if archive != "" {
					return "", errUploadRejected
				}
				archive = filepath.Join(stored, name)
			}
		}
		if archive == "" || extractArchive(archive, stage, p.limits) != nil {
			return "", errUploadRejected
		}
		return locator, nil
	}
	return "", errUploadRejected
}

func (p *Provider) storedUploadPath(locator string) (string, error) {
	id := strings.TrimPrefix(locator, "upload://")
	if id == "" || strings.ContainsAny(id, `/\\`) || domain.RequireID(domain.ID(id), "source upload id") != nil {
		return "", errUploadRejected
	}
	path := filepath.Join(p.uploadRoot, id)
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&fs.ModeSymlink != 0 {
		return "", errUploadRejected
	}
	return path, nil
}

func (p *Provider) publish(stage, digest string) (string, error) {
	final := filepath.Join(p.workspaceRoot, digest)
	if existing, err := os.Lstat(final); err == nil {
		if existing.Mode()&fs.ModeSymlink != 0 || !existing.IsDir() {
			return "", errWorkspaceUnavailable
		}
		got, err := foundation.HashDirectory(final)
		if err != nil || got != digest {
			return "", errWorkspaceUnavailable
		}
		return final, nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return "", errWorkspaceUnavailable
	}
	if err := makeReadOnly(stage); err != nil {
		return "", errWorkspaceUnavailable
	}
	if err := os.Rename(stage, final); err != nil {
		// A concurrent process may have published the same immutable digest.
		if existing, statErr := os.Lstat(final); statErr == nil && existing.IsDir() && existing.Mode()&fs.ModeSymlink == 0 {
			got, hashErr := foundation.HashDirectory(final)
			if hashErr == nil && got == digest {
				return final, nil
			}
		}
		return "", errWorkspaceUnavailable
	}
	return final, nil
}

func (p *Provider) git(ctx context.Context, dir string, args ...string) error {
	_, err := p.gitOutput(ctx, dir, args...)
	return err
}

// gitPinnedFetch monitors the transient bare repository while Git is still
// receiving network data. Archive limits are enforced again after completion,
// but this loop bounds retained pack/object growth instead of waiting for a
// hostile remote to finish an arbitrarily large transfer.
func (p *Provider) gitPinnedFetch(ctx context.Context, dir string, authority gitAuthority, args ...string) error {
	command := p.gitCommand(ctx, dir, p.pinnedGitConfig(authority), args...)
	command.Stdout, command.Stderr = io.Discard, io.Discard
	startGitProcessGroup(command)
	if err := command.Start(); err != nil {
		return err
	}
	completed := make(chan error, 1)
	go func() { completed <- command.Wait() }()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case err := <-completed:
			if err != nil {
				return err
			}
			return boundedGitObjectDirectory(dir, p.limits)
		case <-ticker.C:
			if err := boundedGitObjectDirectory(dir, p.limits); err != nil {
				stopGitProcessGroup(command)
				<-completed
				return errGitTooLarge
			}
		case <-ctx.Done():
			stopGitProcessGroup(command)
			<-completed
			return ctx.Err()
		}
	}
}

func (p *Provider) gitOutput(ctx context.Context, dir string, args ...string) ([]byte, error) {
	return p.gitOutputWithConfig(ctx, dir, nil, args...)
}

func (p *Provider) gitOutputPinned(ctx context.Context, dir string, authority gitAuthority, args ...string) ([]byte, error) {
	return p.gitOutputWithConfig(ctx, dir, p.pinnedGitConfig(authority), args...)
}

func (p *Provider) pinnedGitConfig(authority gitAuthority) []string {
	config := []string{
		"protocol.allow=never",
		"protocol.https.allow=always",
		"protocol.http.allow=never",
		"protocol.file.allow=never",
		"protocol.ssh.allow=never",
		"protocol.git.allow=never",
		"protocol.ext.allow=never",
		"http.followRedirects=false",
		"http.sslVerify=true",
		"http.curloptResolve=",
		"http.curloptResolve=" + authority.host + ":" + strconv.Itoa(int(authority.port)) + ":" + joinGitAddresses(authority.addresses),
		"fetch.recurseSubmodules=false",
	}
	if p.gitTLSCAFile != "" {
		config = append(config, "http.sslCAInfo="+p.gitTLSCAFile)
	}
	return config
}

func (p *Provider) gitOutputWithConfig(ctx context.Context, dir string, config []string, args ...string) ([]byte, error) {
	command := p.gitCommand(ctx, dir, config, args...)
	stdout := boundedGitOutput{limit: p.limits.MaxUnpackedBytes}
	command.Stdout, command.Stderr = &stdout, io.Discard
	startGitProcessGroup(command)
	if err := command.Start(); err != nil {
		return nil, err
	}
	completed := make(chan error, 1)
	go func() { completed <- command.Wait() }()
	select {
	case err := <-completed:
		if stdout.exceeded {
			return stdout.Bytes(), errGitTooLarge
		}
		return stdout.Bytes(), err
	case <-ctx.Done():
		stopGitProcessGroup(command)
		<-completed
		return stdout.Bytes(), ctx.Err()
	}
}

type boundedGitOutput struct {
	bytes.Buffer
	limit    int64
	exceeded bool
}

func (b *boundedGitOutput) Write(value []byte) (int, error) {
	if b.limit <= 0 || int64(len(value)) > b.limit-int64(b.Len()) {
		remaining := b.limit - int64(b.Len())
		if remaining > 0 {
			_, _ = b.Buffer.Write(value[:remaining])
		}
		b.exceeded = true
		return len(value), errGitTooLarge
	}
	return b.Buffer.Write(value)
}

func (p *Provider) gitCommand(ctx context.Context, dir string, config []string, args ...string) *exec.Cmd {
	commandArgs := make([]string, 0, len(args)+6)
	if dir != "" {
		commandArgs = append(commandArgs, "-C", dir)
	}
	commandArgs = append(commandArgs,
		"-c", "credential.helper=",
		"-c", "core.hooksPath=/dev/null",
		"-c", "protocol.file.allow=never",
	)
	for _, item := range config {
		commandArgs = append(commandArgs, "-c", item)
	}
	commandArgs = append(commandArgs, args...)
	command := exec.CommandContext(ctx, p.gitBinary, commandArgs...)
	command.Env = gitEnvironment()
	return command
}

func joinGitAddresses(addresses []netip.Addr) string {
	values := make([]string, 0, len(addresses))
	for _, address := range addresses {
		values = append(values, address.String())
	}
	return strings.Join(values, ",")
}

func gitEnvironment() []string {
	// Deliberately do not inherit GIT_* or credential-related environment
	// variables. Git receives only a small, non-interactive environment.
	path := os.Getenv("PATH")
	if path == "" {
		path = "/usr/bin:/bin"
	}
	return []string{
		"PATH=" + path,
		"HOME=" + os.TempDir(),
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_ATTR_NOSYSTEM=1",
		"GIT_TERMINAL_PROMPT=0",
		"GIT_ASKPASS=/bin/false",
		"GCM_INTERACTIVE=Never",
		"GIT_LFS_SKIP_SMUDGE=1",
	}
}

var (
	errGitUnavailable       = errors.New("git source could not be read")
	errGitUnresolved        = errors.New("git reference could not be resolved")
	errGitTooLarge          = errors.New("git source exceeded bounded object limits")
	errUploadRejected       = errors.New("upload source was rejected")
	errWorkspaceUnavailable = errors.New("source workspace unavailable")
)

func (p *Provider) classify(operation contracts.OperationContext, err error) error {
	switch {
	case errors.Is(err, context.Canceled):
		return p.failure(operation, contracts.ErrCancelled, "source preparation was cancelled", err)
	case errors.Is(err, context.DeadlineExceeded):
		return p.failure(operation, contracts.ErrTimeout, "source preparation timed out", err)
	case errors.Is(err, errGitUnavailable):
		return p.failure(operation, contracts.ErrUnavailable, "git source could not be read", nil)
	case errors.Is(err, errGitUnresolved):
		return p.failure(operation, contracts.ErrNotFound, "git reference could not be resolved", nil)
	case errors.Is(err, errGitPolicyUnavailable), errors.Is(err, errGitResolverUnavailable):
		return p.failure(operation, contracts.ErrUnavailable, "public Git resolver policy is unavailable", nil)
	case errors.Is(err, errGitResolverConflict):
		return p.failure(operation, contracts.ErrConflict, "public Git resolver answers conflicted", nil)
	case errors.Is(err, errGitRejected):
		return p.failure(operation, contracts.ErrValidation, "public Git source was rejected", nil)
	case errors.Is(err, errGitTooLarge):
		return p.failure(operation, contracts.ErrValidation, "public Git source exceeded bounded limits", nil)
	case errors.Is(err, errWorkspaceUnavailable):
		return p.failure(operation, contracts.ErrUnavailable, "source workspace is unavailable", nil)
	default:
		return p.failure(operation, contracts.ErrValidation, "source input was rejected", nil)
	}
}

func (p *Provider) failure(operation contracts.OperationContext, code contracts.ErrorCode, message string, cause error) *contracts.ProviderError {
	retry := contracts.RetryNever
	retryable := false
	if code == contracts.ErrUnavailable || code == contracts.ErrTimeout || code == contracts.ErrCancelled {
		retry, retryable = contracts.RetryBackoff, true
	}
	if code == contracts.ErrCancelled {
		retry = contracts.RetryAfterReconnect
	}
	return &contracts.ProviderError{
		Provider: providerName, Code: code, Message: message, Retry: retry, Retryable: retryable,
		Capability: contracts.CapabilitySourcePrepare, Operation: prepareAction, Cause: cause,
		Details: map[string]string{
			"evidence_ref": "ev_" + digestString(operation.IdempotencyKey)[:32],
			"log_ref":      "source://logs/" + digestString(operation.IdempotencyKey)[:32],
		},
	}
}

func (p *Provider) evidence(operation contracts.OperationContext, digest string) contracts.Evidence {
	id := domain.ID("ev_" + digestString(providerName, operation.IdempotencyKey, digest)[:32])
	return contracts.Evidence{
		Refs:    []domain.EvidenceRef{{ID: id, Kind: "source.prepare", Digest: digest, Locator: "source://evidence/" + id.String()}},
		Summary: "immutable source prepared", Digest: digest, Redacted: true,
	}
}

func cloneResult(result contracts.PrepareSourceResult) contracts.PrepareSourceResult {
	result.Evidence.Refs = append([]domain.EvidenceRef(nil), result.Evidence.Refs...)
	return result
}

func contextError(ctx context.Context, operation contracts.OperationContext) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !operation.Deadline.IsZero() && !time.Now().Before(operation.Deadline) {
		return context.DeadlineExceeded
	}
	return nil
}

func operationContext(ctx context.Context, operation contracts.OperationContext) (context.Context, context.CancelFunc) {
	if operation.Deadline.IsZero() {
		return context.WithCancel(ctx)
	}
	return context.WithDeadline(ctx, operation.Deadline)
}

func existingDirectory(value string) (string, error) {
	path, err := existingPath(value)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(path)
	if err != nil || !info.IsDir() {
		return "", errors.New("directory is required")
	}
	return path, nil
}

func existingPath(value string) (string, error) {
	path, err := absolutePath(value)
	if err != nil {
		return "", err
	}
	if _, err := os.Lstat(path); err != nil {
		return "", err
	}
	return path, nil
}

func absolutePath(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", errors.New("path is required")
	}
	return filepath.Abs(filepath.Clean(value))
}

func digestStrings(parts ...string) string {
	hash := sha256.New()
	for _, part := range parts {
		_, _ = io.WriteString(hash, fmt.Sprintf("%d:", len(part)))
		_, _ = io.WriteString(hash, part)
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func digestString(parts ...string) string { return digestStrings(parts...) }

func sameDigest(expected, actualHex string) bool {
	expected = strings.ToLower(strings.TrimSpace(expected))
	expected = strings.TrimPrefix(expected, "sha256:")
	return expected == actualHex
}
