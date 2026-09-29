package contracts

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/acornfox/acornfox/internal/domain"
)

const (
	AcornFoxLogsMaxTail    = 64
	AcornFoxLogsMaxRecords = 64
	AcornFoxLogsMaxBytes   = 1 << 20

	AcornFoxLogStreamStdout = "stdout"
	AcornFoxLogStreamStderr = "stderr"
)

// AcornFoxLogRecord is one bounded, provider-read runtime log record. Stream
// is intentionally restricted to the process stream Docker exposed to the
// provider; callers must not claim a combined stream when that provenance was
// available.
type AcornFoxLogRecord struct {
	Stream string
	Data   string
}

// AcornFoxBoundedLogs is the complete, bounded result returned by a runtime
// provider. SourceLimited means bytes or logical records were discarded at the
// provider boundary. It does not describe application health or availability.
type AcornFoxBoundedLogs struct {
	Records       []AcornFoxLogRecord
	SourceLimited bool
}

func (result AcornFoxBoundedLogs) Validate() error {
	if len(result.Records) > AcornFoxLogsMaxRecords {
		return fmt.Errorf("AcornFox logs record count exceeds limit")
	}
	total := 0
	for _, record := range result.Records {
		if record.Stream != AcornFoxLogStreamStdout && record.Stream != AcornFoxLogStreamStderr {
			return fmt.Errorf("AcornFox logs stream is invalid")
		}
		if record.Data == "" {
			return fmt.Errorf("AcornFox log record data is required")
		}
		total += len(record.Data)
		if total > AcornFoxLogsMaxBytes {
			return fmt.Errorf("AcornFox logs byte limit exceeds bound")
		}
	}
	return nil
}

// AcornFoxBoundedLogReader is deliberately narrower than RuntimeDriver. It
// provides only an immutable-target, bounded read path for AcornFox logging;
// it does not let the Agent choose a Docker container or invoke a command.
type AcornFoxBoundedLogReader interface {
	ReadAcornFoxLogs(context.Context, LogsRequest) (AcornFoxBoundedLogs, error)
}

// AcornFoxLogsRequest is the complete read-only request for bounded runtime
// logs. It deliberately has no container, path, command, environment, or
// caller-selected runtime target. Deployment and service are repeated only as
// derived identity assertions; both must match the immutable release fact.
type AcornFoxLogsRequest struct {
	Reference      AcornFoxRuntimeReference `json:"runtime_reference"`
	DeploymentID   domain.ID                `json:"deployment_id"`
	ServiceName    string                   `json:"service_name"`
	Since          time.Time                `json:"since,omitempty"`
	Tail           int                      `json:"tail"`
	IdempotencyKey string                   `json:"idempotency_key"`
}

// NewAcornFoxLogsRequest derives the deployment and service identity from the
// accepted immutable runtime fact so callers cannot select another container.
func NewAcornFoxLogsRequest(reference AcornFoxRuntimeReference, since time.Time, tail int, idempotencyKey string) (AcornFoxLogsRequest, error) {
	deploymentID, err := AcornFoxRuntimeDeploymentID(reference.Fact)
	if err != nil {
		return AcornFoxLogsRequest{}, fmt.Errorf("logs runtime reference is invalid")
	}
	request := AcornFoxLogsRequest{
		Reference:      reference,
		DeploymentID:   deploymentID,
		ServiceName:    reference.Fact.ServiceName,
		Since:          since.UTC(),
		Tail:           tail,
		IdempotencyKey: strings.TrimSpace(idempotencyKey),
	}
	if since.IsZero() {
		request.Since = time.Time{}
	}
	if err := request.Validate(); err != nil {
		return AcornFoxLogsRequest{}, err
	}
	return request, nil
}

func (request AcornFoxLogsRequest) Validate() error {
	if err := request.Reference.Fact.Validate(); err != nil {
		return fmt.Errorf("logs runtime reference is invalid")
	}
	expected, err := AcornFoxRuntimeDeploymentID(request.Reference.Fact)
	if err != nil || request.DeploymentID != expected || request.ServiceName != request.Reference.Fact.ServiceName || !acornFoxRuntimeServiceName.MatchString(request.ServiceName) {
		return fmt.Errorf("logs runtime identity is invalid")
	}
	if request.Tail < 1 || request.Tail > AcornFoxLogsMaxTail {
		return fmt.Errorf("logs tail is invalid")
	}
	if strings.TrimSpace(request.IdempotencyKey) == "" {
		return fmt.Errorf("logs idempotency key is required")
	}
	if !request.Since.IsZero() && request.Since.Location() != time.UTC {
		return fmt.Errorf("logs since timestamp is not normalized")
	}
	return nil
}
