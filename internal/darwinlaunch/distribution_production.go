//go:build !acornfox_test_distribution && darwin && cgo

package darwinlaunch

import (
	"context"
	"os"
)

const DistributionMode = "production"

func PrepareTestDistributionController(ctx context.Context, verifiedFD *os.File) (*PreparedChild, SourceIdentity, error) {
	return nil, SourceIdentity{}, ErrTestDistributionUnavailable
}

func PrepareTestDistributionSlotLauncher(ctx context.Context, verifiedFD *os.File, action LauncherAction) (*PreparedChild, SourceIdentity, error) {
	return nil, SourceIdentity{}, ErrTestDistributionUnavailable
}
