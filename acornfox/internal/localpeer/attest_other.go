//go:build !linux

package localpeer

func ReadProcessStartTime(pid int32) (string, error) {
	return "", ErrUnsupportedPlatform
}

func ReadProcessUID(pid int32) (uint32, error) {
	return 0, ErrUnsupportedPlatform
}

func AttestLinuxProcess(pid int32) (ProcessAttestation, error) {
	return ProcessAttestation{}, ErrUnsupportedPlatform
}

func VerifyProcessIdentity(pid int32, expectedUID uint32, expectedExecutableSHA string, expectedStartTime string) error {
	return ErrUnsupportedPlatform
}
