package sourcebuildexecution

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/acornfox/acornfox/internal/domain"
	"github.com/acornfox/acornfox/internal/hosthelper"
	"github.com/acornfox/acornfox/internal/localpeer"
)

type ProductionConfig struct {
	UploadRoot, WorkspaceRoot, WorkRoot, ImageStoreRoot, LogRoot string
	GitResolverEndpoints                                         []string
	Authority                                                    SourceBuildAuthority
}

func ValidateProductionConfig(c ProductionConfig) error {
	if c.Authority == nil || len(c.GitResolverEndpoints) == 0 {
		return errors.New("source-build requires Core authority and explicit public Git resolvers")
	}
	paths := []string{c.UploadRoot, c.WorkspaceRoot, c.WorkRoot, c.ImageStoreRoot, c.LogRoot}
	for i, path := range paths {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return errors.New("source-build roots must be explicit absolute canonical directories")
		}
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
			return errors.New("source-build roots must be provisioned private directories")
		}
		for _, other := range paths[:i] {
			if path == other {
				return errors.New("source-build roots must be distinct")
			}
		}
	}
	return nil
}

// VerifySourceBuildPeer requires the root helper in production. The helper
// independently checks the root-published role pair and exact live process.
func VerifySourceBuildPeer(ctx context.Context, helper *hosthelper.Client, b *localpeer.RuntimePeerBinding, target string, pid int32, uid uint32) error {
	if helper == nil || b == nil || b.Validate() != nil || !b.HasSourceBuild() {
		return errors.New("protected source-build binding and root attestation are required")
	}
	expectedPID, expectedUID, sha, start := b.CorePID, b.CoreUID, b.CoreExeSHA, b.CoreStartTime
	if target == "source-build" {
		expectedPID, expectedUID, sha, start = b.SourceBuildPID, b.SourceBuildUID, b.SourceBuildExeSHA, b.SourceBuildStartTime
	} else if target != "core" {
		return domain.ValidationError("invalid source-build peer role")
	}
	if pid != expectedPID || uid != expectedUID {
		return errors.New("source-build peer does not match protected tuple")
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	result, err := helper.AttestRuntimePeer(ctx, hosthelper.RuntimePeerAttestRequest{TargetRole: target, PeerPID: pid, PeerUID: uid, BindingDigest: b.Digest()})
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	if !result.Valid || result.PID != pid || result.UID != uid || result.ExeSHA != sha || result.StartTime != start || result.BindingDigest != b.Digest() || result.ObservedAt.IsZero() || result.ObservedAt.After(now) || now.Sub(result.ObservedAt) > 10*time.Second {
		return errors.New("root-attested source-build peer tuple is invalid")
	}
	return nil
}
