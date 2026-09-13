package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if err := run(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "acornfox-host-release: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, out, diagnostic io.Writer) error {
	if len(args) == 0 {
		printUsage(diagnostic)
		return errors.New("subcommand required (build, sign-index, verify-bundle)")
	}

	switch args[0] {
	case "build":
		return runBuild(ctx, args[1:], out, diagnostic)
	case "sign-index":
		return runSignIndex(ctx, args[1:], out, diagnostic)
	case "verify-bundle":
		return runVerifyBundle(ctx, args[1:], out, diagnostic)
	case "help", "-h", "--help":
		printUsage(out)
		return nil
	default:
		printUsage(diagnostic)
		return fmt.Errorf("unknown subcommand %q", args[0])
	}
}

func runBuild(ctx context.Context, args []string, out, diagnostic io.Writer) error {
	fs := flag.NewFlagSet("build", flag.ContinueOnError)
	fs.SetOutput(diagnostic)

	var opts BuildOptions
	fs.StringVar(&opts.SpecPath, "spec", "", "Path to release spec JSON file")
	fs.StringVar(&opts.PayloadDir, "payload-dir", "", "Path to payload directory (containing launcher/, controller/, etc.)")
	fs.StringVar(&opts.OutputPath, "output", "", "Destination path for produced .tar.gz bundle artifact")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected positional arguments: %v", fs.Args())
	}

	if opts.SpecPath == "" || opts.PayloadDir == "" || opts.OutputPath == "" {
		return errors.New("missing required flags: --spec, --payload-dir, and --output must be provided")
	}

	_, err := buildHostArtifact(ctx, opts, out)
	return err
}

func runSignIndex(ctx context.Context, args []string, out, diagnostic io.Writer) error {
	fs := flag.NewFlagSet("sign-index", flag.ContinueOnError)
	fs.SetOutput(diagnostic)

	var (
		opts         SignIndexOptions
		allowedHosts string
		bundlesStr   string
		payloadRoots string
	)

	fs.StringVar(&opts.IndexSpecPath, "index-spec", "", "Path to IndexPayload JSON spec file")
	fs.StringVar(&opts.KeyFilePath, "key-file", "", "Path to 0600 Ed25519 PKCS#8 PEM private key file")
	fs.StringVar(&opts.OutputPath, "output", "", "Destination path for signed IndexEnvelope JSON file")
	fs.StringVar(&opts.AllowedChannel, "allowed-channel", "", "Operator policy: required allowed channel ('stable' or 'beta')")
	fs.StringVar(&allowedHosts, "allowed-hosts", "", "Operator policy: required comma-separated list of allowed hostnames")
	fs.StringVar(&bundlesStr, "bundles", "", "Operator policy: required comma-separated list of produced bundle .tar.gz paths")
	fs.StringVar(&payloadRoots, "payload-roots", "", "Operator policy: required comma-separated list of payload root directories")
	fs.StringVar(&opts.TargetOS, "target-os", "", "Optional target OS to verify (must be paired with --target-arch)")
	fs.StringVar(&opts.TargetArch, "target-arch", "", "Optional target architecture to verify (must be paired with --target-os)")
	fs.Uint64Var(&opts.CurrentSequence, "current-sequence", 0, "Current sequence floor for verification (default 0)")
	fs.StringVar(&opts.CurrentVersion, "current-version", "", "Current version baseline for verification")
	fs.Int64Var(&opts.MaxArtifactSize, "max-artifact-size", 0, "Maximum allowed artifact size in bytes")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected positional arguments: %v", fs.Args())
	}

	if opts.IndexSpecPath == "" || opts.KeyFilePath == "" || opts.OutputPath == "" {
		return errors.New("missing required flags: --index-spec, --key-file, and --output must be provided")
	}

	if opts.AllowedChannel == "" {
		return errors.New("operator policy flag --allowed-channel is required ('stable' or 'beta')")
	}
	if allowedHosts == "" {
		return errors.New("operator policy flag --allowed-hosts is required")
	}
	for _, h := range strings.Split(allowedHosts, ",") {
		trimmed := strings.TrimSpace(h)
		if trimmed != "" {
			opts.AllowedHosts = append(opts.AllowedHosts, trimmed)
		}
	}

	if bundlesStr == "" {
		return errors.New("operator policy flag --bundles is required")
	}
	for _, b := range strings.Split(bundlesStr, ",") {
		trimmed := strings.TrimSpace(b)
		if trimmed != "" {
			opts.BundleFiles = append(opts.BundleFiles, trimmed)
		}
	}

	if payloadRoots == "" {
		return errors.New("operator policy flag --payload-roots is required")
	}
	for _, p := range strings.Split(payloadRoots, ",") {
		trimmed := strings.TrimSpace(p)
		if trimmed != "" {
			opts.PayloadRoots = append(opts.PayloadRoots, trimmed)
		}
	}

	_, err := signIndex(ctx, opts, out)
	return err
}

func runVerifyBundle(ctx context.Context, args []string, out, diagnostic io.Writer) error {
	fs := flag.NewFlagSet("verify-bundle", flag.ContinueOnError)
	fs.SetOutput(diagnostic)

	var (
		opts         VerifyBundleOptions
		allowedHosts string
	)

	fs.StringVar(&opts.BundlePath, "bundle", "", "Path to host bundle .tar.gz artifact")
	fs.StringVar(&opts.EnvelopePath, "envelope", "", "Path to signed IndexEnvelope JSON file")
	fs.StringVar(&opts.PublicKeyFile, "public-key-file", "", "Path to Ed25519 public key file")
	fs.StringVar(&opts.PublicKeyHex, "public-key-hex", "", "Hex-encoded Ed25519 public key")
	fs.StringVar(&opts.TargetOS, "os", "", "Target OS")
	fs.StringVar(&opts.TargetArch, "arch", "", "Target architecture")
	fs.StringVar(&opts.AllowedChannel, "channel", "stable", "Allowed channel ('stable' or 'beta')")
	fs.StringVar(&allowedHosts, "allowed-hosts", "", "Comma-separated list of allowed hostnames")
	fs.Uint64Var(&opts.CurrentSequence, "current-sequence", 0, "Current sequence floor")
	fs.StringVar(&opts.CurrentVersion, "current-version", "", "Current version baseline")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected positional arguments: %v", fs.Args())
	}

	if opts.BundlePath == "" || opts.EnvelopePath == "" {
		return errors.New("missing required flags: --bundle and --envelope must be provided")
	}
	if opts.PublicKeyFile == "" && opts.PublicKeyHex == "" {
		return errors.New("either --public-key-file or --public-key-hex must be provided")
	}

	if allowedHosts != "" {
		for _, h := range strings.Split(allowedHosts, ",") {
			trimmed := strings.TrimSpace(h)
			if trimmed != "" {
				opts.AllowedHosts = append(opts.AllowedHosts, trimmed)
			}
		}
	}

	_, err := verifyBundle(ctx, opts, out)
	return err
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "acornfox-host-release: offline host release artifact builder and signed index writer")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  acornfox-host-release build --spec SPEC.json --payload-dir DIR --output BUNDLE.tar.gz")
	fmt.Fprintln(w, "  acornfox-host-release sign-index --index-spec INDEX.json --key-file KEY.pem --output index.json --allowed-channel CHANNEL --allowed-hosts HOSTS --bundles BUNDLES --payload-roots ROOTS")
	fmt.Fprintln(w, "  acornfox-host-release verify-bundle --bundle BUNDLE.tar.gz --envelope index.json (--public-key-file KEY | --public-key-hex HEX) [options]")
}
