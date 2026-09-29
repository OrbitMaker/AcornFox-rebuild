package localpeer

import (
	"errors"
)

var (
	ErrProcessNotFound           = errors.New("process not found")
	ErrProcessExecutableMismatch = errors.New("process executable digest mismatch")
	ErrProcessStartTimeMismatch  = errors.New("process start time mismatch")
	ErrProcessOwnerMismatch      = errors.New("process uid mismatch")
)

type ProcessAttestation struct {
	PID              int32
	UID              uint32
	StartTime        string
	ExecutablePath   string
	ExecutableSHA256 string
}
