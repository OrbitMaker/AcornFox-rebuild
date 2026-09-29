package gatewayexecution

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"time"

	appcontracts "github.com/acornfox/acornfox/internal/application/contracts"
)

const maxCommandBytes = 64 << 10
const maxInventoryBytes = 1 << 20

type Command struct {
	Binding   appcontracts.ImagePublicAccessCommand   `json:"binding"`
	Authority appcontracts.ImagePublicAccessAuthority `json:"authority"`
}

type ExecutionResponse struct {
	Observation    *appcontracts.ImagePublicAccessObservation `json:"observation,omitempty"`
	OutcomeUnknown bool                                       `json:"outcome_unknown,omitempty"`
	Error          string                                     `json:"error,omitempty"`
}

type AuthorityResponse struct {
	Binding appcontracts.ImagePublicAccessCommand `json:"binding"`
}

type InventoryResponse struct {
	Routes []appcontracts.ImagePublicAccessRoute `json:"routes"`
}

type SnapshotCheck struct {
	Command Command `json:"command"`
	Digest  string  `json:"digest"`
}

func strictDecode(raw []byte, maximum int, dst any) error {
	if len(raw) == 0 || len(raw) > maximum {
		return errors.New("Gateway protocol message exceeds bound")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return errors.New("Gateway protocol trailing data")
	}
	return nil
}

func sameCommand(a, b appcontracts.ImagePublicAccessCommand) bool {
	if !a.CreatedAt.Equal(b.CreatedAt) {
		return false
	}
	a.CreatedAt, b.CreatedAt = time.Time{}, time.Time{}
	a.State, b.State = "", ""
	return a == b
}

func commandValid(c Command) bool {
	b, a := c.Binding, c.Authority
	return !b.OperationID.Empty() && b.OperationID == a.OperationID && !b.TaskID.Empty() && b.TaskID == a.TaskID && !b.ApprovalID.Empty() && b.ApprovalID == a.ApprovalID && b.DeploymentID == a.DeploymentID && b.EndpointVersion == a.EndpointVersion && b.ContainerID == a.ContainerID && b.Action == a.Action &&
		(b.Action == appcontracts.ImagePublicAccessEnsure || b.Action == appcontracts.ImagePublicAccessRemove) &&
		appcontracts.ValidateImagePublicHostname(b.Hostname) == nil && b.HostPort >= 1024 && b.HostPort <= 65535 && b.ContainerPort >= 1 && b.ContainerPort <= 65535 &&
		!b.CreatedAt.IsZero() && b.CreatedAt.Before(time.Now().UTC().Add(time.Minute)) && a.Owner != "" && a.CoreGeneration > 0 && a.LeaseGeneration > 0
}

func inventoryDigest(routes []appcontracts.ImagePublicAccessRoute) (string, error) {
	raw, err := json.Marshal(routes)
	if err != nil || len(raw) > maxInventoryBytes {
		return "", errors.New("bounded Gateway inventory required")
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
