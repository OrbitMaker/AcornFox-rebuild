package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
)

const (
	m3CompositionFixture    = "fixture"
	m3CompositionProduction = "production"
	m3FixtureTaskPrefix     = "opencard-mvp-fa8f8eab"
	m3FixtureMarkerPath     = "/etc/opencard-mvp-fa8f8eab-clean-worker"
	m3FixtureMarkerValue    = "opencard-mvp-fa8f8eab-build-worker-01"
)

type m3FixtureMarkerFact struct {
	Mode    os.FileMode
	OwnerID uint32
	Content string
}

type m3FixtureAuthorizer func(taskPrefix string) error

// resolveM3Composition makes the test-only provider boundary explicit. Gate
// 4B-1 intentionally has no production convergence provider, so production
// M3 must stop rather than silently constructing offline fixtures.
func resolveM3Composition(mode, taskPrefix string, productionProviderAvailable bool, authorizeFixture m3FixtureAuthorizer) (string, error) {
	mode = strings.TrimSpace(strings.ToLower(mode))
	taskPrefix = strings.TrimSpace(taskPrefix)
	switch mode {
	case m3CompositionFixture:
		if taskPrefix != m3FixtureTaskPrefix {
			return "", errors.New("M3 fixture composition requires the clean-worker task identity")
		}
		if authorizeFixture == nil {
			return "", errors.New("M3 fixture composition requires clean-worker host authorization")
		}
		if err := authorizeFixture(taskPrefix); err != nil {
			return "", fmt.Errorf("M3 fixture composition requires clean-worker host authorization: %w", err)
		}
		return m3CompositionFixture, nil
	case m3CompositionProduction:
		if !productionProviderAvailable {
			return "", errors.New("M3 production composition requires the Gate4B-2 convergence provider")
		}
		return m3CompositionProduction, nil
	default:
		return "", errors.New("M3 composition must be explicitly fixture or production")
	}
}

// authorizeM3FixtureHost proves that the process runs on the fixed clean
// worker. The marker path is a constant: production configuration cannot point
// the server at an arbitrary environment-selected marker.
func authorizeM3FixtureHost(taskPrefix string) error {
	if taskPrefix != m3FixtureTaskPrefix {
		return errors.New("unexpected fixture task identity")
	}
	fact, err := readM3FixtureMarker()
	if err != nil {
		return err
	}
	return validateM3FixtureMarker(fact)
}

func readM3FixtureMarker() (m3FixtureMarkerFact, error) {
	file, err := os.Open(m3FixtureMarkerPath)
	if err != nil {
		return m3FixtureMarkerFact{}, fmt.Errorf("open clean-worker marker: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return m3FixtureMarkerFact{}, fmt.Errorf("inspect opened clean-worker marker: %w", err)
	}
	pathInfo, err := os.Lstat(m3FixtureMarkerPath)
	if err != nil {
		return m3FixtureMarkerFact{}, fmt.Errorf("inspect clean-worker marker path: %w", err)
	}
	if !pathInfo.Mode().IsRegular() || !os.SameFile(info, pathInfo) {
		return m3FixtureMarkerFact{}, errors.New("clean-worker marker changed or is not a regular file")
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return m3FixtureMarkerFact{}, errors.New("inspect clean-worker marker owner")
	}
	content, err := io.ReadAll(file)
	if err != nil {
		return m3FixtureMarkerFact{}, fmt.Errorf("read clean-worker marker: %w", err)
	}
	return m3FixtureMarkerFact{Mode: info.Mode(), OwnerID: owner.Uid, Content: string(content)}, nil
}

func validateM3FixtureMarker(fact m3FixtureMarkerFact) error {
	if !fact.Mode.IsRegular() || fact.Mode&os.ModeSymlink != 0 {
		return errors.New("clean-worker marker must be a regular non-symlink file")
	}
	if fact.OwnerID != 0 || fact.Mode.Perm() != 0o644 {
		return errors.New("clean-worker marker must be root-owned mode 0644")
	}
	if strings.TrimSpace(fact.Content) != m3FixtureMarkerValue {
		return errors.New("clean-worker marker identity does not match")
	}
	return nil
}
