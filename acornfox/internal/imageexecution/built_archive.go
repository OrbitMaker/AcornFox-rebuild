package imageexecution

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"

	appcontracts "github.com/acornfox/acornfox/internal/application/contracts"
	"github.com/acornfox/acornfox/internal/contracts"
	imageprovider "github.com/acornfox/acornfox/internal/providers/image"
)

var ErrBuiltOCIImport = errors.New("source-built OCI handoff is unverified")

func sameBuiltArtifact(left, right appcontracts.SourceBuiltArtifactFact) bool { return left == right }
func (r *ContainerRuntime) authorizeBuiltOCI(ctx context.Context, req BuiltOCIImportRequest) (appcontracts.SourceBuiltArtifactFact, error) {
	var zero appcontracts.SourceBuiltArtifactFact
	if r == nil || req.TaskID.Empty() || req.OperationID.Empty() || req.DeploymentID.Empty() || req.Owner == "" || req.CoreGeneration <= 0 || req.LeaseGeneration <= 0 || req.PlanDigest == "" || req.Artifact.SizeBytes <= 0 {
		return zero, ErrBuiltOCIImport
	}
	auth, err := r.checkAuthority(ctx, DeployRequest{DeploymentID: req.DeploymentID, OperationID: req.OperationID, TaskID: req.TaskID, TaskOwner: req.Owner, CoreGeneration: req.CoreGeneration, LeaseGeneration: req.LeaseGeneration, PlanDigest: req.PlanDigest, ImageOrigin: "source-build"})
	if err != nil {
		return zero, err
	}
	if auth.PlanDigest != req.PlanDigest || auth.ImageOrigin != "source-build" || auth.SourceArtifact == nil || auth.ApplicationID != req.Artifact.ApplicationID || auth.EnvironmentID != req.Artifact.EnvironmentID || !sameBuiltArtifact(*auth.SourceArtifact, req.Artifact) {
		return zero, ErrBuiltOCIImport
	}
	return *auth.SourceArtifact, nil
}
func builtOCIReceipt(f appcontracts.SourceBuiltArtifactFact, stored contracts.StoreOCIResult, identity imageprovider.OCIIdentity) (appcontracts.SourceBuiltContainerReceipt, error) {
	var zero appcontracts.SourceBuiltContainerReceipt
	if stored.Image.Repository != f.Image.Repository || stored.Image.Digest != f.Image.Digest || stored.StorageRef != f.StorageRef || stored.SizeBytes != f.SizeBytes || stored.Evidence.Digest != f.ArchiveSHA256 || identity.ManifestDigest != f.Image.Digest || identity.ArchiveSize != f.SizeBytes || identity.OS != "linux" || identity.Architecture != "amd64" {
		return zero, ErrBuiltOCIImport
	}
	return appcontracts.SourceBuiltContainerReceipt{Image: stored.Image, StorageRef: stored.StorageRef, ArchiveSHA256: stored.Evidence.Digest, SizeBytes: stored.SizeBytes, ManifestDigest: identity.ManifestDigest, ConfigDigest: identity.ConfigDigest}, nil
}

// ProbeBuiltOCI is the read-only restart/replay proof. Missing is distinct from
// damaged/unreadable: only an actually absent archive can enter import.
func (r *ContainerRuntime) ProbeBuiltOCI(ctx context.Context, req BuiltOCIImportRequest) (appcontracts.SourceBuiltContainerReceipt, bool, error) {
	var zero appcontracts.SourceBuiltContainerReceipt
	fact, err := r.authorizeBuiltOCI(ctx, req)
	if err != nil {
		return zero, false, err
	}
	op := contracts.OperationContext{IdempotencyKey: "source-oci-probe:" + fact.ArtifactID.String(), Actor: "core-source-built-handoff"}
	reader, stored, err := r.imageStore.OpenOCI(ctx, fact.Image, op)
	if err != nil {
		var providerErr *contracts.ProviderError
		if errors.As(err, &providerErr) && providerErr.Code == contracts.ErrNotFound {
			return zero, false, nil
		}
		return zero, false, fmt.Errorf("%w: destination archive unavailable: %v", ErrBuiltOCIImport, err)
	}
	seeker, ok := reader.(io.ReadSeeker)
	if !ok {
		reader.Close()
		return zero, false, ErrBuiltOCIImport
	}
	identity, inspectErr := imageprovider.InspectOCI(ctx, seeker, fact.Image.Digest, fact.SizeBytes)
	closeErr := reader.Close()
	if inspectErr != nil || closeErr != nil {
		return zero, false, ErrBuiltOCIImport
	}
	receipt, err := builtOCIReceipt(fact, stored, identity)
	if err != nil {
		return zero, false, err
	}
	return receipt, true, nil
}

type exactBuiltArchiveReader struct {
	ctx       context.Context
	source    io.Reader
	remaining int64
	expected  string
	hash      hash.Hash
	verified  bool
}

func (r *exactBuiltArchiveReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	if len(p) == 0 {
		return 0, nil
	}
	if r.remaining > 0 {
		if int64(len(p)) > r.remaining {
			p = p[:r.remaining]
		}
		n, err := r.source.Read(p)
		if n > 0 {
			r.hash.Write(p[:n])
			r.remaining -= int64(n)
		}
		if err == io.EOF {
			if r.remaining > 0 {
				return n, io.ErrUnexpectedEOF
			}
			if "sha256:"+hex.EncodeToString(r.hash.Sum(nil)) != r.expected {
				return n, ErrBuiltOCIImport
			}
			r.verified = true
		}
		return n, err
	}
	var probe [1]byte
	n, err := r.source.Read(probe[:])
	if n > 0 || err != io.EOF {
		return 0, ErrBuiltOCIImport
	}
	if "sha256:"+hex.EncodeToString(r.hash.Sum(nil)) != r.expected {
		return 0, ErrBuiltOCIImport
	}
	r.verified = true
	return 0, io.EOF
}

// ImportBuiltOCI changes only Container role's immutable archive store. It
// authorizes the original image.deploy lease first and never opens Docker.
func (r *ContainerRuntime) ImportBuiltOCI(ctx context.Context, req BuiltOCIImportRequest, body io.Reader) (appcontracts.SourceBuiltContainerReceipt, error) {
	var zero appcontracts.SourceBuiltContainerReceipt
	fact, err := r.authorizeBuiltOCI(ctx, req)
	if err != nil {
		return zero, err
	}
	if body == nil {
		return zero, ErrBuiltOCIImport
	}
	operation := contracts.OperationContext{IdempotencyKey: "source-oci-import:" + req.DeploymentID.String(), Actor: "core-source-built-handoff"}
	checked := &exactBuiltArchiveReader{ctx: ctx, source: body, remaining: fact.SizeBytes, expected: fact.ArchiveSHA256, hash: sha256.New()}
	stored, err := r.imageStore.StoreOCI(ctx, contracts.StoreOCIRequest{Image: fact.Image, StorageKey: "source-import-" + fact.ArtifactID.String(), Archive: checked, Operation: operation})
	if err != nil || !checked.verified {
		return zero, fmt.Errorf("%w: destination archive copy did not finish", ErrBuiltOCIImport)
	}
	if stored.Image.Repository != fact.Image.Repository || stored.Image.Digest != fact.Image.Digest || stored.StorageRef != fact.StorageRef || stored.SizeBytes != fact.SizeBytes || stored.Evidence.Digest != fact.ArchiveSHA256 {
		return zero, ErrBuiltOCIImport
	}
	verified, present, err := r.ProbeBuiltOCI(ctx, req)
	if err != nil || !present {
		return zero, ErrBuiltOCIImport
	}
	return verified, nil
}
