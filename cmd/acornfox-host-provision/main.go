package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/open-card/open-card/internal/hostprovision"
)

func main() {
	var (
		bootstrapVersion string
		bindingSHA       string
		bootstrapSource  string
		bootstrapSHA     string
		c0Source         string
		c0SHA            string
		policySource     string
		policySHA        string
	)

	fs := flag.NewFlagSet("acornfox-host-provision", flag.ContinueOnError)

	fs.StringVar(&bootstrapVersion, "bootstrap-version", "", "Bootstrap semver version (e.g. 1.0.0)")
	fs.StringVar(&bootstrapVersion, "version", "", "Alias for -bootstrap-version")

	fs.StringVar(&bindingSHA, "binding-sha", "", "Expected SHA256 hex of backend binding")
	fs.StringVar(&bindingSHA, "binding-sha256", "", "Alias for -binding-sha")

	fs.StringVar(&bootstrapSource, "bootstrap-source", "", "Path to stable bootstrap binary")
	fs.StringVar(&bootstrapSource, "stable-bootstrap-source", "", "Alias for -bootstrap-source")

	fs.StringVar(&bootstrapSHA, "bootstrap-sha", "", "Expected SHA256 hex of stable bootstrap binary")
	fs.StringVar(&bootstrapSHA, "bootstrap-sha256", "", "Alias for -bootstrap-sha")

	fs.StringVar(&c0Source, "c0-source", "", "Path to managed C0 binary")
	fs.StringVar(&c0Source, "managed-c0-source", "", "Alias for -c0-source")

	fs.StringVar(&c0SHA, "c0-sha", "", "Expected SHA256 hex of managed C0 binary")
	fs.StringVar(&c0SHA, "c0-sha256", "", "Alias for -c0-sha")

	fs.StringVar(&policySource, "policy-source", "", "Path to host policy JSON file")
	fs.StringVar(&policySource, "host-policy-source", "", "Alias for -policy-source")

	fs.StringVar(&policySHA, "policy-sha", "", "Expected SHA256 hex of host policy JSON file")
	fs.StringVar(&policySHA, "policy-sha256", "", "Alias for -policy-sha")

	if err := fs.Parse(os.Args[1:]); err != nil {
		os.Exit(2)
	}

	if fs.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "acornfox-host-provision: unexpected positional argument: %q\n", fs.Arg(0))
		os.Exit(2)
	}

	if bootstrapVersion == "" || bindingSHA == "" ||
		bootstrapSource == "" || bootstrapSHA == "" ||
		c0Source == "" || c0SHA == "" ||
		policySource == "" || policySHA == "" {
		fmt.Fprintln(os.Stderr, "acornfox-host-provision: missing required options")
		fs.Usage()
		os.Exit(2)
	}

	if !isFixtureBuild() && os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "acornfox-host-provision: root privileges required")
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	req := hostprovision.ProvisionRequest{
		BootstrapVersion:        bootstrapVersion,
		BootstrapBackendBinding: bindingSHA,
		StableBootstrapSource:   bootstrapSource,
		ExpectedBootstrapSHA256: bootstrapSHA,
		ManagedC0Source:         c0Source,
		ExpectedC0SHA256:        c0SHA,
		PolicySourcePath:        policySource,
		ExpectedPolicySHA256:    policySHA,
	}

	receipt, err := runProvision(ctx, req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "acornfox-host-provision: error: %v\n", err)
		os.Exit(1)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(receipt); err != nil {
		fmt.Fprintf(os.Stderr, "acornfox-host-provision: failed to encode receipt: %v\n", err)
		os.Exit(1)
	}
}
