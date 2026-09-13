//go:build fixture

package hostprovision

import (
	"context"

	"github.com/open-card/open-card/internal/desktopupdate"
)

// FixtureOptions is available only under the fixture build tag.
// It allows CLI integration tests to execute in isolated root-mode fixture paths.
type FixtureOptions struct {
	AllowNonRoot   bool
	Paths          ProvisionPaths
	GuestTransport desktopupdate.GuestTransport
}

// ProvisionForFixture provides a compilation-isolated bridge for the fixture CLI.
// It is strictly excluded from production builds.
func ProvisionForFixture(ctx context.Context, req ProvisionRequest, opts FixtureOptions) (*ProvisionReceipt, error) {
	return provisionWithOptions(ctx, req, provisionOptions{
		allowNonRoot:   opts.AllowNonRoot,
		paths:          opts.Paths,
		guestTransport: opts.GuestTransport,
	})
}
