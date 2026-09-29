//go:build linux

package localpeer

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

func ReadProcessStartTime(pid int32) (string, error) {
	statPath := fmt.Sprintf("/proc/%d/stat", pid)
	data, err := os.ReadFile(statPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", ErrProcessNotFound
		}
		return "", err
	}
	s := string(data)
	lastParen := strings.LastIndex(s, ")")
	if lastParen == -1 || lastParen+2 >= len(s) {
		return "", errors.New("malformed /proc/<pid>/stat")
	}
	fields := strings.Fields(s[lastParen+2:])
	if len(fields) < 20 {
		return "", errors.New("truncated /proc/<pid>/stat")
	}
	return fields[19], nil
}

func ReadProcessUID(pid int32) (uint32, error) {
	statusPath := fmt.Sprintf("/proc/%d/status", pid)
	data, err := os.ReadFile(statusPath)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, ErrProcessNotFound
		}
		return 0, err
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "Uid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				var uid uint32
				if _, err := fmt.Sscanf(fields[1], "%d", &uid); err == nil {
					return uid, nil
				}
			}
		}
	}
	return 0, errors.New("unable to determine process uid from status")
}

func AttestLinuxProcess(pid int32) (ProcessAttestation, error) {
	exeLink := fmt.Sprintf("/proc/%d/exe", pid)
	resolvedPath, err := os.Readlink(exeLink)
	if err != nil {
		if os.IsNotExist(err) {
			return ProcessAttestation{}, ErrProcessNotFound
		}
		return ProcessAttestation{}, err
	}

	f, err := os.Open(exeLink)
	if err != nil {
		return ProcessAttestation{}, err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ProcessAttestation{}, err
	}
	exeSHA := hex.EncodeToString(h.Sum(nil))

	startTime, err := ReadProcessStartTime(pid)
	if err != nil {
		return ProcessAttestation{}, err
	}

	procUID, err := ReadProcessUID(pid)
	if err != nil {
		return ProcessAttestation{}, err
	}

	return ProcessAttestation{
		PID:              pid,
		UID:              procUID,
		StartTime:        startTime,
		ExecutablePath:   resolvedPath,
		ExecutableSHA256: exeSHA,
	}, nil
}

func VerifyProcessIdentity(pid int32, expectedUID uint32, expectedExecutableSHA string, expectedStartTime string) error {
	att, err := AttestLinuxProcess(pid)
	if err != nil {
		return err
	}
	if att.UID != expectedUID {
		return ErrProcessOwnerMismatch
	}
	if expectedExecutableSHA != "" && att.ExecutableSHA256 != expectedExecutableSHA {
		return ErrProcessExecutableMismatch
	}
	if expectedStartTime != "" && att.StartTime != expectedStartTime {
		return ErrProcessStartTimeMismatch
	}
	return nil
}
