package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/open-card/open-card/internal/acornfoxsetup"
)

type OutputFileSummary struct {
	RelativePath  string `json:"relative_path"`
	Mode          string `json:"mode"`
	IntendedOwner string `json:"intended_owner"`
	IntendedGroup string `json:"intended_group"`
	SHA256        string `json:"sha256"`
}

type LocalConfigReceipt struct {
	SchemaVersion int                 `json:"schema_version"`
	Origin        string              `json:"origin"`
	Version       string              `json:"version"`
	GeneratedAt   string              `json:"generated_at"`
	Files         []OutputFileSummary `json:"files"`
}

func run(args []string, stdout, stderr io.Writer, randomness io.Reader) int {
	fs := flag.NewFlagSet("acornfox-local-config", flag.ContinueOnError)
	fs.SetOutput(stderr)

	outputDir := fs.String("output-dir", "", "Target directory to write local runtime configuration files (must not exist)")
	version := fs.String("version", "v0.1.0-beta.1", "AcornFox release version")
	nowStr := fs.String("now", "", "Generation timestamp in RFC3339 format (optional, default current UTC time)")
	resolversStr := fs.String("resolvers", "", "Comma-separated public DNS resolvers (optional)")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	if len(fs.Args()) > 0 {
		fmt.Fprintf(stderr, "error: unexpected positional arguments: %v\n", fs.Args())
		return 2
	}

	if *outputDir == "" {
		fmt.Fprintln(stderr, "error: --output-dir is required")
		return 2
	}

	cleanTarget, err := filepath.Abs(filepath.Clean(*outputDir))
	if err != nil {
		fmt.Fprintf(stderr, "error: resolving output directory path %s: %v\n", *outputDir, err)
		return 3
	}
	parentDir := filepath.Dir(cleanTarget)
	baseDir := filepath.Base(cleanTarget)
	if baseDir == "." || baseDir == "/" || baseDir == "" {
		fmt.Fprintf(stderr, "error: invalid output directory name: %s\n", *outputDir)
		return 3
	}

	// Open parent directory as Root; parent must already exist
	parentRoot, err := os.OpenRoot(parentDir)
	if err != nil {
		fmt.Fprintf(stderr, "error: opening parent directory %s: %v\n", parentDir, err)
		return 3
	}
	defer parentRoot.Close()

	now := time.Now().UTC()
	if *nowStr != "" {
		parsed, err := time.Parse(time.RFC3339, *nowStr)
		if err != nil {
			fmt.Fprintf(stderr, "error: invalid --now format: %v\n", err)
			return 2
		}
		now = parsed.UTC()
	}

	var resolvers []string
	if *resolversStr != "" {
		for _, r := range strings.Split(*resolversStr, ",") {
			trimmed := strings.TrimSpace(r)
			if trimmed != "" {
				resolvers = append(resolvers, trimmed)
			}
		}
	}

	inputs := acornfoxsetup.Inputs{
		Origin:            acornfoxsetup.ExactLocalLoopbackOrigin,
		Version:           *version,
		ResolverEndpoints: resolvers,
		Now:               now,
	}

	bundle, err := acornfoxsetup.GenerateLocal(inputs, randomness)
	if err != nil {
		fmt.Fprintf(stderr, "error: generate local bundle failed: %v\n", err)
		return 4
	}

	// Create new target directory inside parent root with 0700 permissions.
	// Fails if baseDir already exists (directory, file, or symlink).
	if err := parentRoot.Mkdir(baseDir, 0700); err != nil {
		fmt.Fprintf(stderr, "error: create output directory %s in parent %s: %v\n", baseDir, parentDir, err)
		return 3
	}

	// Open the newly created target directory as Root
	targetRoot, err := parentRoot.OpenRoot(baseDir)
	if err != nil {
		fmt.Fprintf(stderr, "error: opening target root %s: %v\n", baseDir, err)
		return 5
	}
	defer targetRoot.Close()

	var fileSummaries []OutputFileSummary
	for _, f := range bundle.Files {
		relName := filepath.Base(f.Path)

		// Create file exclusively with O_CREATE|O_EXCL to prevent overwriting or following links
		perm := os.FileMode(f.Mode)
		fd, err := targetRoot.OpenFile(relName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
		if err != nil {
			fmt.Fprintf(stderr, "error: open file %s: %v\n", relName, err)
			return 5
		}

		// Write data
		if _, err := fd.Write(f.Data); err != nil {
			_ = fd.Close()
			fmt.Fprintf(stderr, "error: write file %s: %v\n", relName, err)
			return 5
		}

		// Explicitly Chmod on the open file descriptor to ensure requested mode under any umask
		if err := fd.Chmod(perm); err != nil {
			_ = fd.Close()
			fmt.Fprintf(stderr, "error: chmod file %s: %v\n", relName, err)
			return 5
		}

		if err := fd.Close(); err != nil {
			fmt.Fprintf(stderr, "error: close file %s: %v\n", relName, err)
			return 5
		}

		hash := sha256.Sum256(f.Data)
		hashHex := hex.EncodeToString(hash[:])

		fileSummaries = append(fileSummaries, OutputFileSummary{
			RelativePath:  relName,
			Mode:          fmt.Sprintf("%04o", f.Mode),
			IntendedOwner: string(f.Owner),
			IntendedGroup: string(f.Group),
			SHA256:        hashHex,
		})
	}

	receipt := LocalConfigReceipt{
		SchemaVersion: 1,
		Origin:        inputs.Origin,
		Version:       inputs.Version,
		GeneratedAt:   inputs.Now.Format(time.RFC3339),
		Files:         fileSummaries,
	}

	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(receipt); err != nil {
		fmt.Fprintf(stderr, "error: encode receipt failed: %v\n", err)
		return 6
	}

	return 0
}

func main() {
	code := run(os.Args[1:], os.Stdout, os.Stderr, rand.Reader)
	if code != 0 {
		os.Exit(code)
	}
}
