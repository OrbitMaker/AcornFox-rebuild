//go:build linux

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/open-card/open-card/internal/desktopupdateguest"
)

func main() {
	var (
		kind             = flag.String("kind", "", "Provision kind: linux-local or mac-managed")
		bootstrapVersion = flag.String("bootstrap-version", "", "Bootstrap host semver version")
		workerSource     = flag.String("worker-source", "", "Path to worker binary file")
		workerSHA        = flag.String("worker-sha", "", "Expected SHA-256 hex of worker binary")
		policySource     = flag.String("policy-source", "", "Path to policy JSON file")
		policySHA        = flag.String("policy-sha", "", "Expected SHA-256 hex of policy JSON")
	)
	flag.Parse()

	if *kind == "" || *bootstrapVersion == "" || *workerSource == "" || *workerSHA == "" || *policySource == "" || *policySHA == "" {
		fmt.Fprintln(os.Stderr, "missing required flags")
		flag.Usage()
		os.Exit(2)
	}

	req := desktopupdateguest.ProvisionRequest{
		Kind:                 *kind,
		BootstrapHostVersion: *bootstrapVersion,
		WorkerSourcePath:     *workerSource,
		ExpectedWorkerSHA256: *workerSHA,
		PolicySourcePath:     *policySource,
		ExpectedPolicySHA256: *policySHA,
	}

	receipt, err := desktopupdateguest.Provision(context.Background(), req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "guest provision failed: %v\n", err)
		os.Exit(1)
	}

	out, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "receipt marshal failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(out))
}
