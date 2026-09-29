package imageexecution

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/open-card/open-card/internal/hosthelper"
	"github.com/open-card/open-card/internal/localpeer"
)

// VerifyCounterpartPeerViaHelper verifies kernel-captured peer credentials of a live connection
// using the trusted root host-helper attestation bridge.
func VerifyCounterpartPeerViaHelper(ctx context.Context, helperClient *hosthelper.Client, targetRole string, peerPID int32, peerUID uint32, binding *localpeer.RuntimePeerBinding) error {
	if binding == nil {
		return errors.New("runtime peer binding is required")
	}

	expectedPID := binding.ContainerPID
	expectedUID := binding.ContainerUID
	expectedExeSHA := binding.ContainerExeSHA
	expectedStartTime := binding.ContainerStartTime
	if targetRole == "core" {
		expectedPID = binding.CorePID
		expectedUID = binding.CoreUID
		expectedExeSHA = binding.CoreExeSHA
		expectedStartTime = binding.CoreStartTime
	}

	if peerPID != expectedPID || peerUID != expectedUID {
		return fmt.Errorf("peer credentials PID %d UID %d do not match expected %s tuple (%d, %d)", peerPID, peerUID, targetRole, expectedPID, expectedUID)
	}

	// If root helper client is provided, attest peer process via root /proc read
	if helperClient != nil {
		attestCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()

		resp, err := helperClient.AttestRuntimePeer(attestCtx, hosthelper.RuntimePeerAttestRequest{
			TargetRole:    targetRole,
			PeerPID:       peerPID,
			PeerUID:       peerUID,
			BindingDigest: binding.Digest(),
		})
		if err != nil {
			return fmt.Errorf("root helper attest peer: %w", err)
		}
		if !resp.Valid {
			return fmt.Errorf("root helper rejected peer: %s", resp.Error)
		}

		if resp.PID != expectedPID || resp.UID != expectedUID {
			return fmt.Errorf("attested PID %d UID %d mismatch", resp.PID, resp.UID)
		}
		if resp.ExeSHA != expectedExeSHA || resp.StartTime != expectedStartTime {
			return fmt.Errorf("attested process tuple mismatch for role %s", targetRole)
		}
		if resp.BindingDigest != binding.Digest() {
			return fmt.Errorf("binding digest mismatch: got %s want %s", resp.BindingDigest, binding.Digest())
		}

		now := time.Now().UTC()
		if resp.ObservedAt.IsZero() {
			return errors.New("attested observation time is zero")
		}
		if resp.ObservedAt.After(now) {
			return errors.New("attested observation time is in the future")
		}
		if now.Sub(resp.ObservedAt) > 10*time.Second {
			return errors.New("attested observation is expired (>10s)")
		}

		return nil
	}

	// Same-UID direct verification fallback (only when helper is nil, e.g. in standalone unit tests)
	if err := localpeer.VerifyProcessIdentity(peerPID, expectedUID, expectedExeSHA, expectedStartTime); err != nil {
		return fmt.Errorf("direct process verification failed: %w", err)
	}
	return nil
}
