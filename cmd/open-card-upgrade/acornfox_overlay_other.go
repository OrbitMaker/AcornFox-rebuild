//go:build !linux

package main

import (
	"context"
	"errors"
)

func defaultProductionGuestProvision(ctx context.Context, req overlayGuestProvisionRequest) (*overlayGuestProvisionReceipt, error) {
	return nil, errors.New("guest provision is only supported on linux")
}
