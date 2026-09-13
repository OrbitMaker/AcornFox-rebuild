//go:build !fixture

package main

import (
	"context"

	"github.com/open-card/open-card/internal/hostprovision"
)

func isFixtureBuild() bool {
	return false
}

func runProvision(ctx context.Context, req hostprovision.ProvisionRequest) (*hostprovision.ProvisionReceipt, error) {
	return hostprovision.Provision(ctx, req)
}
