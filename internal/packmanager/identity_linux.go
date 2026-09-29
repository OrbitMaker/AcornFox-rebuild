//go:build linux

package packmanager

import (
	"github.com/open-card/open-card/internal/localpeer"
)

type ProcessAttestation = localpeer.ProcessAttestation

var (
	ErrProcessNotFound           = localpeer.ErrProcessNotFound
	ErrProcessExecutableMismatch = localpeer.ErrProcessExecutableMismatch
	ErrProcessStartTimeMismatch  = localpeer.ErrProcessStartTimeMismatch
	ErrProcessOwnerMismatch      = localpeer.ErrProcessOwnerMismatch
)

func ReadProcessStartTime(pid int32) (string, error) {
	return localpeer.ReadProcessStartTime(pid)
}

func ReadProcessUID(pid int32) (uint32, error) {
	return localpeer.ReadProcessUID(pid)
}

func AttestLinuxProcess(pid int32) (ProcessAttestation, error) {
	return localpeer.AttestLinuxProcess(pid)
}

func VerifyProcessIdentity(pid int32, expectedUID uint32, expectedExecutableSHA string, expectedStartTime string) error {
	return localpeer.VerifyProcessIdentity(pid, expectedUID, expectedExecutableSHA, expectedStartTime)
}
