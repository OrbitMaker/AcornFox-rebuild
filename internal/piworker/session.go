package piworker

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

const maxBindingBytes = 4 << 10

type sessionBinding struct {
	SchemaVersion int    `json:"schema_version"`
	SessionID     string `json:"session_id"`
	Scope         Scope  `json:"scope"`
}

func bindSession(root string, request OpenRequest) (string, error) {
	if root == "" || !idPattern.MatchString(request.SessionID) || request.Scope.Validate() != nil {
		return "", ErrInvalidConfig
	}
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 || !ownedByCurrentUser(info) {
		return "", ErrInvalidConfig
	}
	sessionFile := filepath.Join(root, request.SessionID+".jsonl")
	if info, err := os.Lstat(sessionFile); err == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || !ownedByCurrentUser(info) {
			return "", ErrInvalidConfig
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", ErrInvalidConfig
	}
	bindingPath := filepath.Join(root, request.SessionID+".scope.json")
	wanted := sessionBinding{SchemaVersion: 1, SessionID: request.SessionID, Scope: request.Scope}
	if err := createOrVerifyBinding(bindingPath, wanted); err != nil {
		return "", err
	}
	return sessionFile, nil
}

func createOrVerifyBinding(path string, wanted sessionBinding) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err == nil {
		raw, encodeErr := json.Marshal(wanted)
		if encodeErr == nil {
			raw = append(raw, '\n')
			encodeErr = writeFull(file, raw)
		}
		if encodeErr == nil {
			encodeErr = file.Sync()
		}
		closeErr := file.Close()
		if encodeErr != nil || closeErr != nil {
			_ = os.Remove(path)
			return ErrInvalidConfig
		}
		return nil
	}
	if !errors.Is(err, os.ErrExist) {
		return ErrInvalidConfig
	}
	return verifyBinding(path, wanted)
}

func verifyBinding(path string, wanted sessionBinding) error {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return ErrInvalidConfig
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || !ownedByCurrentUser(info) || info.Size() <= 0 || info.Size() > maxBindingBytes {
		return ErrInvalidConfig
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxBindingBytes+1))
	if err != nil || len(raw) > maxBindingBytes {
		return ErrInvalidConfig
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var current sessionBinding
	if err := decoder.Decode(&current); err != nil || requireJSONEOF(decoder) != nil {
		return ErrInvalidConfig
	}
	if current != wanted {
		return ErrScopeMismatch
	}
	return nil
}

func ownedByCurrentUser(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(stat.Uid) == os.Geteuid()
}
