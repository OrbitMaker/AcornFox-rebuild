package buildnetwork

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"regexp"
	"time"
)

type AttestationRequest struct {
	SchemaVersion      int    `json:"schema_version"`
	PolicyDigest       string `json:"policy_digest"`
	RequestFingerprint string `json:"request_fingerprint"`
}

type AttestationReceipt struct {
	SchemaVersion      int    `json:"schema_version"`
	PolicyDigest       string `json:"policy_digest"`
	RequestFingerprint string `json:"request_fingerprint"`
}

var fingerprintPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
var policyDigestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

func validRequest(r AttestationRequest) bool {
	return r.SchemaVersion == 1 && policyDigestPattern.MatchString(r.PolicyDigest) && fingerprintPattern.MatchString(r.RequestFingerprint)
}

// Client uses only the fixed installed Unix socket. Peer credentials prevent
// an unprivileged process from impersonating the privileged policy owner.
type Client struct{}

func (Client) AttestWorkerPolicy(ctx context.Context, r AttestationRequest) (AttestationReceipt, error) {
	if !validRequest(r) {
		return AttestationReceipt{}, ErrPolicy
	}
	return attestSocket(ctx, SocketPath, r, 0)
}

func attestSocket(ctx context.Context, path string, r AttestationRequest, wantUID uint32) (AttestationReceipt, error) {
	var receipt AttestationReceipt
	dialer := net.Dialer{Timeout: 2 * time.Second}
	connection, err := dialer.DialContext(ctx, "unix", path)
	if err != nil {
		return receipt, err
	}
	defer connection.Close()
	uid, _, err := peerIdentity(connection)
	if err != nil || uid != wantUID {
		return receipt, errors.New("untrusted build policy peer")
	}
	deadline := time.Now().Add(3 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := connection.SetDeadline(deadline); err != nil {
		return receipt, err
	}
	if err := json.NewEncoder(connection).Encode(r); err != nil {
		return receipt, err
	}
	decoder := json.NewDecoder(io.LimitReader(connection, 8193))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&receipt); err != nil {
		return receipt, err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return receipt, ErrPolicy
	}
	if receipt.SchemaVersion != 1 || receipt.PolicyDigest != r.PolicyDigest || receipt.RequestFingerprint != r.RequestFingerprint {
		return AttestationReceipt{}, ErrPolicy
	}
	return receipt, nil
}
