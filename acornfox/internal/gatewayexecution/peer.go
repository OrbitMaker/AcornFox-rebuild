package gatewayexecution

import (
	"context"
	"errors"
	"time"

	"github.com/acornfox/acornfox/internal/hosthelper"
	"github.com/acornfox/acornfox/internal/localpeer"
)

// VerifyGatewayPeer requires the root helper's live kernel-credential and
// executable/start-time readback; a binding file alone never attests a peer.
func VerifyGatewayPeer(ctx context.Context, helper *hosthelper.Client, b *localpeer.RuntimePeerBinding, target string, pid int32, uid uint32) error {
	if helper == nil || b == nil || !b.HasGateway() || b.Validate() != nil {
		return errors.New("Gateway binding or helper unavailable")
	}
	var expectedPID int32
	var expectedUID uint32
	var expectedSHA, expectedStart string
	switch target {
	case "core":
		expectedPID, expectedUID, expectedSHA, expectedStart = b.CorePID, b.CoreUID, b.CoreExeSHA, b.CoreStartTime
	case "gateway":
		expectedPID, expectedUID, expectedSHA, expectedStart = b.GatewayPID, b.GatewayUID, b.GatewayExeSHA, b.GatewayStartTime
	default:
		return errors.New("Gateway peer role is not permitted")
	}
	if pid != expectedPID || uid != expectedUID {
		return errors.New("Gateway peer PID or UID differs from binding")
	}
	probe, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	receipt, err := helper.AttestRuntimePeer(probe, hosthelper.RuntimePeerAttestRequest{TargetRole: target, PeerPID: pid, PeerUID: uid, BindingDigest: b.Digest()})
	if err != nil || !receipt.Valid || receipt.PID != expectedPID || receipt.UID != expectedUID || receipt.ExeSHA != expectedSHA || receipt.StartTime != expectedStart || receipt.BindingDigest != b.Digest() || receipt.ObservedAt.IsZero() || receipt.ObservedAt.After(time.Now().UTC().Add(time.Second)) || time.Since(receipt.ObservedAt) > 10*time.Second {
		return errors.New("root helper did not attest exact Gateway peer")
	}
	return nil
}
