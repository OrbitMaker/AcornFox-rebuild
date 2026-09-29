package contracts

import (
	"context"
	"errors"
	"github.com/acornfox/acornfox/internal/domain"
	"time"
)

const ImageObservationLogBytes = 8 << 10
const ImageObservationLogTail = 64

// ManagedImageObservationBinding is read authority, never a task or effect permit.
type ManagedImageObservationBinding struct {
	AdminID domain.ID             `json:"admin_id"`
	Runtime ImageLifecycleBinding `json:"runtime"`
}
type ImageObservationRequest struct {
	AdminID      domain.ID `json:"admin_id"`
	DeploymentID domain.ID `json:"deployment_id"`
	Logs         bool      `json:"logs"`
	Tail         int       `json:"tail"`
	Since        time.Time `json:"since"`
}

func (r ImageObservationRequest) Valid(now time.Time) bool {
	return !r.AdminID.Empty() && !r.DeploymentID.Empty() && ((!r.Logs && r.Tail == 0 && r.Since.IsZero()) || (r.Logs && r.Tail >= 1 && r.Tail <= ImageObservationLogTail && (r.Since.IsZero() || (r.Since.Location() == time.UTC && !r.Since.After(now) && !r.Since.Before(now.Add(-30*time.Minute))))))
}

type ImageObservationLog struct {
	Stream string `json:"stream"`
	Data   string `json:"data"`
}
type ImageObservationResult struct {
	State         ImageLifecycleResult  `json:"state"`
	Records       []ImageObservationLog `json:"records,omitempty"`
	SourceLimited bool                  `json:"source_limited"`
}
type ManagedImageObservationStore interface {
	ReadManagedImageObservationBinding(context.Context, domain.ID, domain.ID) (ManagedImageObservationBinding, error)
}
type ImageObservationClient interface {
	ReadManagedImageObservation(context.Context, ImageObservationRequest) (ImageObservationResult, error)
}

func (r ImageObservationResult) Validate(now time.Time) error {
	s := r.State
	if s.EndpointReady || !s.VerifiedIdentity || s.ContainerID == "" || s.ImageID == "" || s.ManifestDigest == "" || s.HostPort < 1 || s.HostPort > 65535 || s.ContainerPort < 1 || s.ContainerPort > 65535 || s.ObservedAt.IsZero() || s.ObservedAt.After(now) || s.ObservedAt.Before(now.Add(-10*time.Second)) || len(r.Records) > ImageObservationLogTail {
		return errors.New("invalid observation state")
	}
	total := 0
	for _, line := range r.Records {
		if (line.Stream != "stdout" && line.Stream != "stderr") || line.Data == "" {
			return errors.New("invalid observation log")
		}
		total += len(line.Data)
	}
	if total > ImageObservationLogBytes {
		return errors.New("invalid observation log size")
	}
	return nil
}
