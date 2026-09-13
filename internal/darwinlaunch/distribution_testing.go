//go:build acornfox_test_distribution && darwin && cgo

package darwinlaunch

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
)

const DistributionMode = "test-distribution"

const (
	TestDistributionControllerIdentifier = "com.acornfox.test.host-update"
	TestDistributionLauncherIdentifier   = "com.acornfox.test.host-launcher"
)

func testDistributionBaseDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("user home dir: %w", err)
	}
	return filepath.Join(home, "Library", "Application Support", "AcornFox", "test-distribution-launch"), nil
}

func PrepareTestDistributionController(ctx context.Context, verifiedFD *os.File) (*PreparedChild, SourceIdentity, error) {
	if ctx == nil || ctx.Err() != nil || verifiedFD == nil {
		return nil, SourceIdentity{}, os.ErrInvalid
	}
	baseDir, err := testDistributionBaseDir()
	if err != nil {
		return nil, SourceIdentity{}, err
	}
	cfg := launchConfig{
		identifier: TestDistributionControllerIdentifier,
		args:       []string{"--controller"},
		allowAdHoc: true,
		baseDir:    baseDir,
	}
	return prepareChild(ctx, verifiedFD, cfg)
}

func PrepareTestDistributionSlotLauncher(ctx context.Context, verifiedFD *os.File, action LauncherAction) (*PreparedChild, SourceIdentity, error) {
	if ctx == nil || ctx.Err() != nil || verifiedFD == nil {
		return nil, SourceIdentity{}, os.ErrInvalid
	}
	var actionArg string
	switch action {
	case LauncherActionStart:
		actionArg = "start"
	case LauncherActionMaintenance:
		actionArg = "maintenance"
	case LauncherActionProbeHelper:
		actionArg = "probe-helper"
	default:
		return nil, SourceIdentity{}, ErrInvalidAction
	}
	baseDir, err := testDistributionBaseDir()
	if err != nil {
		return nil, SourceIdentity{}, err
	}
	cfg := launchConfig{
		identifier: TestDistributionLauncherIdentifier,
		args:       []string{actionArg},
		allowAdHoc: true,
		baseDir:    baseDir,
	}
	return prepareChild(ctx, verifiedFD, cfg)
}
