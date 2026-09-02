package contracts

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/open-card/open-card/internal/domain"
)

var acornFoxRuntimeServiceName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`)

// AcornFoxRuntimeReleaseFact is the complete, narrow input accepted by the
// single-service runtime. It is made only from a ready immutable Release that
// contains exactly one service image.
type AcornFoxRuntimeReleaseFact struct {
	ApplicationID domain.ID                         `json:"application_id"`
	EnvironmentID domain.ID                         `json:"environment_id"`
	ReleaseID     domain.ID                         `json:"release_id"`
	ServiceName   string                            `json:"service_name"`
	Image         domain.ImageDigest                `json:"image"`
	Resources     AcornFoxRuntimeRequestedResources `json:"resources"`
	ContainerPort int                               `json:"container_port,omitempty"`
	AcceptedAt    time.Time                         `json:"accepted_at"`
	Immutable     bool                              `json:"immutable"`
}

// ProjectAcornFoxRuntimeReleaseFact makes a single-service fact from the
// authoritative release and immutable image set. It refuses a release with
// more than one service instead of choosing one implicitly.
func ProjectAcornFoxRuntimeReleaseFact(release domain.Release, environmentID domain.ID, resources AcornFoxRuntimeRequestedResources, containerPort int, acceptedAt time.Time) (AcornFoxRuntimeReleaseFact, error) {
	if err := release.Validate(); err != nil || !release.IsImmutable() || release.Status != domain.ReleaseReady {
		return AcornFoxRuntimeReleaseFact{}, fmt.Errorf("runtime release is not accepted")
	}
	images := release.ServiceDigests()
	if len(images) != 1 {
		return AcornFoxRuntimeReleaseFact{}, fmt.Errorf("runtime accepts exactly one service image")
	}
	for service, image := range images {
		fact := AcornFoxRuntimeReleaseFact{ApplicationID: release.ApplicationID, EnvironmentID: environmentID, ReleaseID: release.ID, ServiceName: service, Image: image, Resources: resources, ContainerPort: containerPort, AcceptedAt: acceptedAt.UTC(), Immutable: true}
		if err := fact.Validate(); err != nil {
			return AcornFoxRuntimeReleaseFact{}, err
		}
		return fact, nil
	}
	return AcornFoxRuntimeReleaseFact{}, fmt.Errorf("runtime accepts exactly one service image")
}

func (fact AcornFoxRuntimeReleaseFact) Validate() error {
	if fact.ApplicationID.Empty() || fact.EnvironmentID.Empty() || fact.ReleaseID.Empty() || !acornFoxRuntimeServiceName.MatchString(fact.ServiceName) || !fact.Immutable || fact.AcceptedAt.IsZero() {
		return fmt.Errorf("runtime identity is invalid")
	}
	if err := fact.Image.Validate(); err != nil {
		return fmt.Errorf("runtime image is invalid")
	}
	if err := fact.Resources.Validate(); err != nil {
		return err
	}
	if fact.ContainerPort < 0 || fact.ContainerPort > 65535 {
		return fmt.Errorf("runtime container port is invalid")
	}
	return nil
}

// AcornFoxRuntimeRequestedResources is the accepted resource request for one
// container. DiskReservationBytes is capacity accounting, not a Docker
// per-container limit.
type AcornFoxRuntimeRequestedResources struct {
	CPUMillis            int64 `json:"cpu_millis"`
	MemoryBytes          int64 `json:"memory_bytes"`
	PIDs                 int64 `json:"pids"`
	DiskReservationBytes int64 `json:"disk_reservation_bytes"`
}

func (resources AcornFoxRuntimeRequestedResources) Validate() error {
	if resources.CPUMillis <= 0 || resources.MemoryBytes <= 0 || resources.PIDs <= 0 || resources.DiskReservationBytes <= 0 {
		return fmt.Errorf("runtime resources are invalid")
	}
	return nil
}

// AcornFoxRuntimeAppliedLimits are the limits independently read back from
// the container runtime. Disk is absent because Docker has no corresponding
// per-container cgroup limit.
type AcornFoxRuntimeAppliedLimits struct {
	CPUMillis   int64 `json:"cpu_millis"`
	MemoryBytes int64 `json:"memory_bytes"`
	PIDs        int64 `json:"pids"`
}

// AcornFoxRuntimeDiskFact states what the standalone runtime can honestly
// claim about disk. Capacity reconciliation is a later integration concern.
type AcornFoxRuntimeDiskFact struct {
	ReservationBytes     int64 `json:"reservation_bytes"`
	AccountingReconciled bool  `json:"accounting_reconciled"`
	PerContainerEnforced bool  `json:"per_container_enforced"`
}

// AcornFoxRuntimeDeployRequest keeps one explicit deploy method while making
// a new start after an intentional replacement unambiguous.
type AcornFoxRuntimeDeployRequest struct {
	Fact           AcornFoxRuntimeReleaseFact `json:"fact"`
	IdempotencyKey string                     `json:"idempotency_key"`
	Recreate       bool                       `json:"recreate,omitempty"`
}

// AcornFoxRuntimeReference identifies the one service derived from a fact.
type AcornFoxRuntimeReference struct {
	Fact AcornFoxRuntimeReleaseFact `json:"fact"`
}

// AcornFoxRuntimeActionRequest adds a caller-owned stable idempotency key to
// a mutating operation. Replaying a key is safe; a new key is a new request.
type AcornFoxRuntimeActionRequest struct {
	Fact           AcornFoxRuntimeReleaseFact `json:"fact"`
	IdempotencyKey string                     `json:"idempotency_key"`
}

func (request AcornFoxRuntimeActionRequest) Validate() error {
	if err := request.Fact.Validate(); err != nil {
		return err
	}
	if strings.TrimSpace(request.IdempotencyKey) == "" {
		return fmt.Errorf("runtime idempotency key is required")
	}
	return nil
}

func (request AcornFoxRuntimeDeployRequest) Validate() error {
	return AcornFoxRuntimeActionRequest{Fact: request.Fact, IdempotencyKey: request.IdempotencyKey}.Validate()
}

// AcornFoxRuntimeDeployment records only the objective result of asking the
// runtime to materialize one immutable fact. It does not make a reachability
// or application-response assertion.
type AcornFoxRuntimeDeployment struct {
	DeploymentID       domain.ID                         `json:"deployment_id"`
	ApplicationID      domain.ID                         `json:"application_id"`
	EnvironmentID      domain.ID                         `json:"environment_id"`
	ReleaseID          domain.ID                         `json:"release_id"`
	ServiceName        string                            `json:"service_name"`
	Image              domain.ImageDigest                `json:"image"`
	RuntimeState       string                            `json:"runtime_state"`
	OperationID        string                            `json:"operation_id"`
	RequestedResources AcornFoxRuntimeRequestedResources `json:"requested_resources"`
}

// AcornFoxRuntimeObservation separates the accepted requested limits from
// Docker readback. InternalAddress is loopback-only when a container port was
// accepted; absence of it makes no network-reachability claim.
type AcornFoxRuntimeObservation struct {
	DeploymentID       domain.ID                         `json:"deployment_id"`
	ServiceName        string                            `json:"service_name"`
	ContainerID        string                            `json:"container_id,omitempty"`
	RuntimeState       string                            `json:"runtime_state"`
	RestartCount       uint64                            `json:"restart_count"`
	InternalAddress    string                            `json:"internal_address,omitempty"`
	RequestedResources AcornFoxRuntimeRequestedResources `json:"requested_resources"`
	AppliedLimits      AcornFoxRuntimeAppliedLimits      `json:"applied_limits"`
	Disk               AcornFoxRuntimeDiskFact           `json:"disk"`
	ObservedAt         time.Time                         `json:"observed_at"`
}

// AcornFoxRuntimeDriver deliberately has only single-service lifecycle
// operations. It is a compatibility layer over the wider legacy runtime
// boundary, not a second runtime implementation.
type AcornFoxRuntimeDriver interface {
	Deploy(context.Context, AcornFoxRuntimeDeployRequest) (AcornFoxRuntimeDeployment, error)
	Observe(context.Context, AcornFoxRuntimeReference) (AcornFoxRuntimeObservation, error)
	Restart(context.Context, AcornFoxRuntimeActionRequest) error
	Destroy(context.Context, AcornFoxRuntimeActionRequest) error
}

// AcornFoxRuntimeDeploymentID is stable for one immutable service fact.
func AcornFoxRuntimeDeploymentID(fact AcornFoxRuntimeReleaseFact) (domain.ID, error) {
	if err := fact.Validate(); err != nil {
		return "", err
	}
	return domain.ID("dep_" + acornFoxRuntimeHash(fact.ApplicationID.String(), fact.EnvironmentID.String(), fact.ReleaseID.String(), fact.ServiceName, fact.Image.Repository, fact.Image.Digest, fmt.Sprint(fact.Resources), fmt.Sprint(fact.ContainerPort))[:32]), nil
}

// AcornFoxRuntimeOperationID is deterministic for one fact and operation.
func AcornFoxRuntimeOperationID(fact AcornFoxRuntimeReleaseFact, action, idempotencyKey string) (string, error) {
	if _, err := AcornFoxRuntimeDeploymentID(fact); err != nil || strings.TrimSpace(action) == "" || strings.TrimSpace(idempotencyKey) == "" {
		return "", fmt.Errorf("runtime operation identity is invalid")
	}
	return "acornfox-runtime-" + action + "-" + acornFoxRuntimeHash(fact.ApplicationID.String(), fact.EnvironmentID.String(), fact.ReleaseID.String(), fact.ServiceName, fact.Image.Repository, fact.Image.Digest, fmt.Sprint(fact.Resources), fmt.Sprint(fact.ContainerPort), action, idempotencyKey)[:24], nil
}

func AcornFoxRuntimeLoopbackAddress(port int) (string, error) {
	if port < 1 || port > 65535 {
		return "", fmt.Errorf("runtime loopback port is invalid")
	}
	return fmt.Sprintf("127.0.0.1:%d", port), nil
}

func acornFoxRuntimeHash(parts ...string) string {
	sum := sha256.New()
	for _, part := range parts {
		_, _ = sum.Write([]byte{0})
		_, _ = sum.Write([]byte(part))
	}
	return hex.EncodeToString(sum.Sum(nil))
}
