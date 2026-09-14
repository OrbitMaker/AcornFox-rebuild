//go:build linux

package main

import (
	"context"

	"github.com/open-card/open-card/internal/desktopupdateguest"
)

func defaultProductionGuestProvision(ctx context.Context, req overlayGuestProvisionRequest) (*overlayGuestProvisionReceipt, error) {
	r, err := desktopupdateguest.Provision(ctx, desktopupdateguest.ProvisionRequest{
		Kind:                 req.Kind,
		BootstrapHostVersion: req.BootstrapHostVersion,
		WorkerSourcePath:     req.WorkerSourcePath,
		ExpectedWorkerSHA256: req.ExpectedWorkerSHA256,
		PolicySourcePath:     req.PolicySourcePath,
		ExpectedPolicySHA256: req.ExpectedPolicySHA256,
	})
	if err != nil {
		return nil, err
	}
	return &overlayGuestProvisionReceipt{
		Kind:                 r.Kind,
		InstanceID:           r.InstanceID,
		NativeID:             r.NativeID,
		WorkerSHA256:         r.WorkerSHA256,
		PolicySHA256:         r.PolicySHA256,
		InstanceSHA256:       r.InstanceSHA256,
		MarkerSHA256:         r.MarkerSHA256,
		BootstrapHostVersion: r.BootstrapHostVersion,
	}, nil
}
