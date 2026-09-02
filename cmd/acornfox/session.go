package main

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type sessionState struct {
	Origin    string    `json:"origin"`
	Session   string    `json:"session"`
	CSRF      string    `json:"csrf"`
	ExpiresAt time.Time `json:"expires_at"`
}

func statePath(env func(string) string) (string, error) {
	root := env("XDG_STATE_HOME")
	if root == "" {
		home := env("HOME")
		if home == "" {
			return "", errors.New("state home is unavailable")
		}
		root = filepath.Join(home, ".local", "state")
	}
	return filepath.Join(root, "acornfox", "session.json"), nil
}

// noSymlinkPath checks every component under the OS root. macOS /var is a
// system-owned alias and is the only allowed link; all caller-controlled links
// (parent, XDG root, AcornFox directory, and leaf) fail closed.
func noSymlinkPath(path string) error {
	path = filepath.Clean(path)
	if !filepath.IsAbs(path) {
		return errors.New("AcornFox session path is unsafe")
	}
	current := string(filepath.Separator)
	for _, part := range strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator)) {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		candidate := current
		info, err := os.Lstat(candidate)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 && candidate != "/var" {
			return errors.New("AcornFox session path is unsafe")
		}
	}
	return nil
}
func checkStateModes(path string) error {
	dir, err := os.Lstat(filepath.Dir(path))
	if err != nil || !dir.IsDir() || dir.Mode().Perm() != 0700 {
		return errors.New("AcornFox session is invalid; login again")
	}
	file, err := os.Lstat(path)
	if err != nil || !file.Mode().IsRegular() || file.Mode().Perm() != 0600 {
		return errors.New("AcornFox session is invalid; login again")
	}
	return nil
}
func loadState(env func(string) string) (sessionState, error) {
	path, err := statePath(env)
	if err != nil {
		return sessionState{}, err
	}
	if err := noSymlinkPath(path); err != nil {
		return sessionState{}, errors.New("AcornFox session is unavailable; login first")
	}
	if err := checkStateModes(path); err != nil {
		return sessionState{}, err
	}
	file, err := os.Open(path)
	if err != nil {
		return sessionState{}, errors.New("AcornFox session is unavailable; login first")
	}
	defer file.Close()
	var state sessionState
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	if decoder.Decode(&state) != nil || decoder.Decode(&struct{}{}) != io.EOF || state.Origin == "" || state.Session == "" || state.CSRF == "" || state.ExpiresAt.IsZero() {
		return sessionState{}, errors.New("AcornFox session is invalid; login again")
	}
	if _, err := normalizeOrigin(state.Origin, false); err != nil {
		return sessionState{}, errors.New("AcornFox session is invalid; login again")
	}
	if !state.ExpiresAt.After(time.Now().UTC()) {
		if err := removeState(env); err != nil {
			return sessionState{}, localStateError()
		}
		return sessionState{}, errors.New("AcornFox session expired; login again")
	}
	return state, nil
}
func saveState(env func(string) string, state sessionState) error {
	path, err := statePath(env)
	if err != nil {
		return err
	}
	if err = noSymlinkPath(path); err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	if err = noSymlinkPath(path); err != nil {
		return err
	}
	if err = os.Chmod(filepath.Dir(path), 0700); err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".session-")
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if err = file.Chmod(0600); err == nil {
		err = json.NewEncoder(file).Encode(state)
	}
	if err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(temporary, path); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
func removeState(env func(string) string) error {
	path, err := statePath(env)
	if err != nil {
		return err
	}
	if err = noSymlinkPath(path); err != nil {
		return err
	}
	if err = os.Remove(path); os.IsNotExist(err) {
		return nil
	}
	return err
}
