package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/open-card/open-card/internal/desktopupdate"
)

// PEM boundary markers identify key material; bare words also occur in compiled Go diagnostics.
var privatePEMMarker = regexp.MustCompile(`-----(?:BEGIN|END) [A-Z0-9 ]*PRIVATE[A-Z0-9 ]*-----`)

type BuildOptions struct {
	SpecPath   string
	PayloadDir string
	OutputPath string
}

type BuildReceipt struct {
	Artifact       string `json:"artifact"`
	SHA256         string `json:"sha256"`
	Size           int64  `json:"size"`
	OS             string `json:"os"`
	Architecture   string `json:"arch"`
	Version        string `json:"version"`
	BackendMode    string `json:"backend_mode"`
	BackendBinding string `json:"backend_binding"`
	Verified       bool   `json:"verified"`
}

func buildHostArtifact(ctx context.Context, opts BuildOptions, out io.Writer) (*BuildReceipt, error) {
	if ctx == nil {
		return nil, errors.New("context must not be nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if opts.SpecPath == "" {
		return nil, errors.New("spec file path is required")
	}
	if opts.PayloadDir == "" {
		return nil, errors.New("payload directory path is required")
	}
	if opts.OutputPath == "" {
		return nil, errors.New("output artifact path is required")
	}

	cleanOutput := filepath.Clean(opts.OutputPath)
	cleanPayload := filepath.Clean(opts.PayloadDir)

	if _, err := os.Lstat(cleanOutput); !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("destination already exists (no-clobber): %s", cleanOutput)
	}

	specData, err := os.ReadFile(opts.SpecPath)
	if err != nil {
		return nil, fmt.Errorf("cannot read spec file: %w", err)
	}

	spec, err := parseReleaseSpec(specData)
	if err != nil {
		return nil, fmt.Errorf("invalid release spec: %w", err)
	}

	payloadAbs, err := filepath.Abs(cleanPayload)
	if err != nil {
		return nil, fmt.Errorf("cannot resolve payload directory: %w", err)
	}
	payloadInfo, err := os.Lstat(payloadAbs)
	if err != nil {
		return nil, fmt.Errorf("cannot stat payload directory: %w", err)
	}
	if !payloadInfo.IsDir() {
		return nil, fmt.Errorf("payload path is not a directory: %s", payloadAbs)
	}
	if payloadInfo.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("payload path must not be a symlink: %s", payloadAbs)
	}

	if hook := testPreOpenPayloadRootHook; hook != nil {
		if err := hook(payloadAbs); err != nil {
			return nil, err
		}
	}

	payloadRoot, err := os.OpenRoot(payloadAbs)
	if err != nil {
		return nil, fmt.Errorf("cannot open payload root: %w", err)
	}
	defer payloadRoot.Close()

	rootStat, err := payloadRoot.Stat(".")
	if err != nil {
		return nil, fmt.Errorf("cannot stat opened payload root: %w", err)
	}
	if !os.SameFile(payloadInfo, rootStat) {
		return nil, fmt.Errorf("payload root directory was swapped or replaced between lstat and open: %s", payloadAbs)
	}
	if rootStat.Mode()&os.ModeSymlink != 0 || !rootStat.IsDir() || rootStat.Mode().Perm() != payloadInfo.Mode().Perm() {
		return nil, fmt.Errorf("payload root metadata changed between lstat and open: %s", payloadAbs)
	}

	// Scan and validate payload directory using the verified open root
	scannedFiles, fileDataMap, err := scanPayloadDirectory(payloadRoot)
	if err != nil {
		return nil, fmt.Errorf("payload scan failed: %w", err)
	}

	// Validate backend structure against mode
	if err := validateBackendFiles(spec, scannedFiles, fileDataMap); err != nil {
		return nil, fmt.Errorf("backend validation failed: %w", err)
	}

	// If spec contains explicit files inventory, verify exact match (no extra, no missing, exact hashes)
	var finalFiles []desktopupdate.HostBundleFile
	if len(spec.Files) > 0 {
		if err := verifyInventoryMatch(spec.Files, scannedFiles); err != nil {
			return nil, fmt.Errorf("inventory mismatch: %w", err)
		}
		finalFiles = append([]desktopupdate.HostBundleFile(nil), spec.Files...)
	} else {
		finalFiles = scannedFiles
	}

	// Sort files strictly ascending by Path
	sort.Slice(finalFiles, func(i, j int) bool {
		return finalFiles[i].Path < finalFiles[j].Path
	})

	// Check sorted order and launcher/controller presence
	launcherFound := false
	controllerFound := false
	var totalSize int64
	for i, f := range finalFiles {
		if i > 0 && f.Path <= finalFiles[i-1].Path {
			return nil, fmt.Errorf("files must be strictly ascending unique paths: %s <= %s", f.Path, finalFiles[i-1].Path)
		}
		if f.Path == spec.Launcher {
			if f.Mode != 0755 {
				return nil, fmt.Errorf("launcher %s mode must be 0755, got %04o", f.Path, f.Mode)
			}
			launcherFound = true
		}
		if f.Path == spec.Controller {
			if f.Mode != 0755 {
				return nil, fmt.Errorf("controller %s mode must be 0755, got %04o", f.Path, f.Mode)
			}
			controllerFound = true
		}
		totalSize += f.Size
		if totalSize > int64(4<<30) {
			return nil, fmt.Errorf("total uncompressed size %d exceeds 4GB limit", totalSize)
		}
	}
	if !launcherFound {
		return nil, fmt.Errorf("launcher %s not found in payload inventory", spec.Launcher)
	}
	if !controllerFound {
		return nil, fmt.Errorf("controller %s not found in payload inventory", spec.Controller)
	}
	if len(finalFiles) < 2 || len(finalFiles) > 4096 {
		return nil, fmt.Errorf("file count %d out of bounds (2..4096)", len(finalFiles))
	}

	manifest := spec.ToManifest(finalFiles)
	manifestRaw, err := json.Marshal(manifest)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal manifest: %w", err)
	}
	if len(manifestRaw) < 1 || len(manifestRaw) > 2<<20 {
		return nil, fmt.Errorf("manifest size %d out of bounds (1..2MB)", len(manifestRaw))
	}

	// Prepare output temporary artifact holder
	holder, err := newTempArtifact(cleanOutput)
	if err != nil {
		return nil, err
	}
	defer holder.Cleanup()

	// Write deterministic gzip + tar
	gw, err := gzip.NewWriterLevel(holder.file, gzip.BestCompression)
	if err != nil {
		return nil, fmt.Errorf("failed to create gzip writer: %w", err)
	}
	gw.Header.OS = 255 // unknown OS for cross-platform determinism
	gw.Header.ModTime = time.Unix(0, 0).UTC()
	gw.Header.Name = ""
	gw.Header.Comment = ""
	gw.Header.Extra = nil

	tw := tar.NewWriter(gw)

	// First entry: bundle.json
	bundleHdr := &tar.Header{
		Name:     "bundle.json",
		Mode:     0644,
		Size:     int64(len(manifestRaw)),
		ModTime:  time.Unix(0, 0).UTC(),
		Typeflag: tar.TypeReg,
		Format:   tar.FormatPAX,
	}
	if err := tw.WriteHeader(bundleHdr); err != nil {
		return nil, fmt.Errorf("failed to write bundle.json header: %w", err)
	}
	if _, err := tw.Write(manifestRaw); err != nil {
		return nil, fmt.Errorf("failed to write bundle.json data: %w", err)
	}

	// Next entries: regular files in sorted order
	for _, f := range finalFiles {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		data := fileDataMap[f.Path]
		hdr := &tar.Header{
			Name:     f.Path,
			Mode:     f.Mode,
			Size:     f.Size,
			ModTime:  time.Unix(0, 0).UTC(),
			Typeflag: tar.TypeReg,
			Format:   tar.FormatPAX,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, fmt.Errorf("failed to write header for %s: %w", f.Path, err)
		}
		sum := sha256.New()
		n, err := io.Copy(io.MultiWriter(tw, sum), bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("failed to stream %s into tar: %w", f.Path, err)
		}
		if n != f.Size {
			return nil, fmt.Errorf("file size mismatch while writing %s: %d != %d", f.Path, n, f.Size)
		}
		if hex.EncodeToString(sum.Sum(nil)) != f.SHA256 {
			return nil, fmt.Errorf("hash mismatch while writing %s", f.Path)
		}
	}

	if err := tw.Close(); err != nil {
		return nil, fmt.Errorf("failed to close tar archive: %w", err)
	}
	if err := gw.Close(); err != nil {
		return nil, fmt.Errorf("failed to close gzip stream: %w", err)
	}
	if err := holder.file.Sync(); err != nil {
		return nil, fmt.Errorf("failed to sync temp artifact: %w", err)
	}

	// Compute artifact size and SHA256
	artifactStat, err := holder.file.Stat()
	if err != nil {
		return nil, fmt.Errorf("failed to stat temp artifact: %w", err)
	}
	artifactSize := artifactStat.Size()
	if artifactSize > desktopupdate.MaxArtifactSizeBytes {
		return nil, fmt.Errorf("artifact size %d exceeds limit (1GB)", artifactSize)
	}

	if _, err := holder.file.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	artifactHash := sha256.New()
	if _, err := io.Copy(artifactHash, holder.file); err != nil {
		return nil, fmt.Errorf("failed to hash artifact: %w", err)
	}
	artifactSHA256 := hex.EncodeToString(artifactHash.Sum(nil))

	// Mandatory in-memory validation using VerifyHostBundle for all builds
	if err := validateProducedBundle(ctx, holder.path, manifest, artifactSHA256, artifactSize); err != nil {
		return nil, fmt.Errorf("VerifyHostBundle validation failed: %w", err)
	}

	// Atomic no-clobber finalization
	if err := holder.Finalize(cleanOutput, 0600); err != nil {
		return nil, fmt.Errorf("failed to finalize artifact: %w", err)
	}

	receipt := &BuildReceipt{
		Artifact:       cleanOutput,
		SHA256:         artifactSHA256,
		Size:           artifactSize,
		OS:             manifest.OS,
		Architecture:   manifest.Architecture,
		Version:        manifest.Version,
		BackendMode:    manifest.Backend.Mode,
		BackendBinding: manifest.Backend.ToBinding,
		Verified:       true,
	}

	if out != nil {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		_ = enc.Encode(receipt)
	}

	return receipt, nil
}

func scanPayloadDirectory(root *os.Root) ([]desktopupdate.HostBundleFile, map[string][]byte, error) {
	var files []desktopupdate.HostBundleFile
	fileDataMap := make(map[string][]byte)

	err := fs.WalkDir(root.FS(), ".", func(currentPath string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if currentPath == "." {
			return nil
		}

		lstatInfo, err := root.Lstat(currentPath)
		if err != nil {
			return fmt.Errorf("cannot lstat %s via root: %w", currentPath, err)
		}

		// Reject symlinks unconditionally
		if lstatInfo.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlinks are not permitted in payload tree: %s", currentPath)
		}

		// If directory, continue walking
		if lstatInfo.IsDir() {
			return nil
		}

		slashPath := filepath.ToSlash(currentPath)
		if !validHostMember(slashPath) {
			return fmt.Errorf("invalid or forbidden member path: %s", slashPath)
		}

		// Reject special files (devices, pipes, sockets)
		if !lstatInfo.Mode().IsRegular() {
			return fmt.Errorf("special files are not permitted in payload tree: %s", slashPath)
		}

		perm := lstatInfo.Mode().Perm()
		if perm != 0644 && perm != 0755 {
			return fmt.Errorf("invalid file mode %04o for %s (must be 0644 or 0755)", perm, slashPath)
		}

		size := lstatInfo.Size()
		if size < 1 {
			return fmt.Errorf("empty files not permitted in payload: %s", slashPath)
		}
		if size > int64(1<<30) {
			return fmt.Errorf("member size %d for %s exceeds 1GB limit", size, slashPath)
		}

		// Open file relative to root with O_NOFOLLOW
		file, err := root.OpenFile(currentPath, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return fmt.Errorf("cannot open file %s via root: %w", slashPath, err)
		}
		defer file.Close()

		statInfo, err := file.Stat()
		if err != nil || !os.SameFile(lstatInfo, statInfo) {
			return fmt.Errorf("file %s was replaced or swapped between lstat and open", slashPath)
		}
		if statInfo.Mode() != lstatInfo.Mode() || statInfo.Size() != lstatInfo.Size() {
			return fmt.Errorf("file %s metadata modified between lstat and open", slashPath)
		}
		if !statInfo.Mode().IsRegular() || statInfo.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("opened file %s is not regular", slashPath)
		}

		// Check hardlinks: stat.Nlink > 1
		if stat, ok := statInfo.Sys().(*syscall.Stat_t); ok {
			if stat.Nlink > 1 {
				return fmt.Errorf("hardlinks are not permitted in payload tree: %s", slashPath)
			}
		}

		data, err := io.ReadAll(io.LimitReader(file, size+1))
		if err != nil {
			return fmt.Errorf("cannot read file %s: %w", slashPath, err)
		}
		if int64(len(data)) != size {
			return fmt.Errorf("file size changed during read: %s", slashPath)
		}

		// Defense-in-depth: check for private key material in payload files
		if privatePEMMarker.Match(data) {
			return fmt.Errorf("private key material detected in payload file %s: private keys must never be in payload", slashPath)
		}
		if block, _ := pem.Decode(data); block != nil && strings.Contains(block.Type, "PRIVATE") {
			return fmt.Errorf("private key PEM block detected in payload file %s: private keys must never be in payload", slashPath)
		}

		h := sha256.Sum256(data)
		hashHex := hex.EncodeToString(h[:])

		files = append(files, desktopupdate.HostBundleFile{
			Path:   slashPath,
			SHA256: hashHex,
			Size:   size,
			Mode:   int64(perm),
		})
		fileDataMap[slashPath] = data
		return nil
	})

	if err != nil {
		return nil, nil, err
	}

	return files, fileDataMap, nil
}

func validateBackendFiles(spec *ReleaseSpec, files []desktopupdate.HostBundleFile, dataMap map[string][]byte) error {
	var backendMembers []string
	for _, f := range files {
		if strings.HasPrefix(f.Path, "backend/") {
			backendMembers = append(backendMembers, f.Path)
		}
	}

	if spec.Backend.Mode == "unchanged" {
		if len(backendMembers) > 0 {
			return fmt.Errorf("unchanged backend mode must not contain backend payload files (found %d)", len(backendMembers))
		}
		return nil
	}

	// Candidate mode requires exact 6 flat files under backend/candidate/
	expectedNames := []string{
		"backend/candidate/candidate-binding.json",
		"backend/candidate/candidate-binding.sha256",
		"backend/candidate/release-manifest.json",
		"backend/candidate/bundle-manifest.sha256",
		"backend/candidate/build-record.json",
		fmt.Sprintf("backend/candidate/acornfox-%s-production.tar.gz", spec.Version),
	}

	if len(backendMembers) != 6 {
		return fmt.Errorf("candidate backend mode requires exactly 6 flat files under backend/candidate/, found %d", len(backendMembers))
	}

	memberMap := make(map[string]desktopupdate.HostBundleFile)
	for _, f := range files {
		if strings.HasPrefix(f.Path, "backend/candidate/") {
			memberMap[f.Path] = f
		}
	}

	for _, name := range expectedNames {
		if _, ok := memberMap[name]; !ok {
			return fmt.Errorf("candidate backend missing expected file: %s", name)
		}
	}

	// Cross-validate candidate binding contents
	bindingRaw := dataMap["backend/candidate/candidate-binding.json"]
	bindingSHA := hex.EncodeToString(sha256Sum(bindingRaw))
	if bindingSHA != spec.Backend.ToBinding {
		return fmt.Errorf("candidate-binding.json SHA256 %s does not match to_binding %s", bindingSHA, spec.Backend.ToBinding)
	}

	bindingCheck := string(dataMap["backend/candidate/candidate-binding.sha256"])
	if bindingCheck != spec.Backend.ToBinding+"\n" {
		return fmt.Errorf("candidate-binding.sha256 content does not match to_binding + newline")
	}

	var bindingDoc struct {
		Schema    int    `json:"schema_version"`
		Product   string `json:"product"`
		Version   string `json:"version"`
		Release   string `json:"release_id"`
		Arch      string `json:"architecture"`
		Migration string `json:"migration_version"`
		Archive   string `json:"archive_sha256"`
		Manifest  string `json:"manifest_sha256"`
		Bundle    string `json:"bundle_manifest_sha256"`
		Previous  struct {
			Binding string `json:"binding_sha256"`
		} `json:"n_minus_one"`
	}
	if err := json.Unmarshal(bindingRaw, &bindingDoc); err != nil {
		return fmt.Errorf("cannot unmarshal candidate-binding.json: %w", err)
	}
	if bindingDoc.Schema != 1 || bindingDoc.Product != "acornfox" || bindingDoc.Arch != spec.Backend.Architecture || bindingDoc.Migration != "0040" || bindingDoc.Release != "release-"+spec.Version || bindingDoc.Previous.Binding != spec.Backend.FromBinding {
		return errors.New("candidate-binding.json fields do not match release spec")
	}

	archiveName := fmt.Sprintf("backend/candidate/acornfox-%s-production.tar.gz", spec.Version)
	if memberMap[archiveName].SHA256 != bindingDoc.Archive {
		return fmt.Errorf("archive SHA256 mismatch in candidate-binding.json: %s != %s", memberMap[archiveName].SHA256, bindingDoc.Archive)
	}

	releaseManifestRaw := dataMap["backend/candidate/release-manifest.json"]
	if hex.EncodeToString(sha256Sum(releaseManifestRaw)) != bindingDoc.Manifest {
		return errors.New("release-manifest.json SHA256 mismatch with candidate-binding.json")
	}

	bundleManifestRaw := dataMap["backend/candidate/bundle-manifest.sha256"]
	if hex.EncodeToString(sha256Sum(bundleManifestRaw)) != bindingDoc.Bundle {
		return errors.New("bundle-manifest.sha256 SHA256 mismatch with candidate-binding.json")
	}

	var manifestDoc struct {
		Product string `json:"product"`
		Version string `json:"version"`
		Release string `json:"release_id"`
		Arch    string `json:"architecture"`
		Files   []struct {
			Path   string `json:"path"`
			SHA256 string `json:"sha256"`
			Mode   int64  `json:"mode"`
		} `json:"files"`
	}
	if err := json.Unmarshal(releaseManifestRaw, &manifestDoc); err != nil {
		return fmt.Errorf("cannot unmarshal release-manifest.json: %w", err)
	}
	if manifestDoc.Product != bindingDoc.Product || manifestDoc.Version != bindingDoc.Version || manifestDoc.Release != bindingDoc.Release || manifestDoc.Arch != bindingDoc.Arch {
		return errors.New("release-manifest.json metadata does not match candidate binding")
	}

	helperFound := false
	for _, f := range manifestDoc.Files {
		if f.Path == "bin/acornfox-upgrade" {
			if f.SHA256 == spec.Backend.HelperSHA256 && f.Mode == 0755 {
				helperFound = true
				break
			}
		}
	}
	if !helperFound {
		return fmt.Errorf("release-manifest.json must contain bin/acornfox-upgrade with SHA256 %s and mode 0755", spec.Backend.HelperSHA256)
	}

	return nil
}

func verifyInventoryMatch(expected, actual []desktopupdate.HostBundleFile) error {
	actualMap := make(map[string]desktopupdate.HostBundleFile, len(actual))
	for _, f := range actual {
		actualMap[f.Path] = f
	}

	expectedMap := make(map[string]desktopupdate.HostBundleFile, len(expected))
	for _, f := range expected {
		expectedMap[f.Path] = f
		act, ok := actualMap[f.Path]
		if !ok {
			return fmt.Errorf("missing payload file: %s", f.Path)
		}
		if act.Size != f.Size {
			return fmt.Errorf("size mismatch for %s: expected %d, got %d", f.Path, f.Size, act.Size)
		}
		if act.SHA256 != f.SHA256 {
			return fmt.Errorf("SHA256 mismatch for %s: expected %s, got %s", f.Path, f.SHA256, act.SHA256)
		}
		if act.Mode != f.Mode {
			return fmt.Errorf("mode mismatch for %s: expected %04o, got %04o", f.Path, f.Mode, act.Mode)
		}
	}

	// Check for unexpected extra files
	for _, f := range actual {
		if _, ok := expectedMap[f.Path]; !ok {
			return fmt.Errorf("unexpected extra file in payload tree: %s", f.Path)
		}
	}

	return nil
}

func validateProducedBundle(ctx context.Context, artifactPath string, manifest desktopupdate.HostBundleManifest, artifactSHA string, artifactSize int64) error {
	version, err := desktopupdate.ParseSemver(manifest.Version)
	if err != nil {
		return err
	}
	channel := "stable"
	if version.IsPrerelease() {
		channel = "beta"
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	ephemeralPayload := desktopupdate.IndexPayload{
		Channel:   channel,
		Sequence:  1,
		ExpiresAt: time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339),
		Version:   manifest.Version,
		Artifacts: []desktopupdate.Artifact{
			{
				OS:             manifest.OS,
				Arch:           manifest.Architecture,
				URL:            "https://downloads.acornfox.local/bundle.tar.gz",
				SHA256:         artifactSHA,
				Size:           artifactSize,
				BackendBinding: manifest.Backend.ToBinding,
			},
		},
	}

	payloadRaw, err := json.Marshal(ephemeralPayload)
	if err != nil {
		return err
	}
	sig := ed25519.Sign(priv, payloadRaw)

	env := desktopupdate.IndexEnvelope{
		SchemaVersion: 1,
		Payload:       base64.StdEncoding.EncodeToString(payloadRaw),
		Signature:     base64.StdEncoding.EncodeToString(sig),
	}
	envRaw, err := json.Marshal(env)
	if err != nil {
		return err
	}

	opts := desktopupdate.CheckUpdateOptions{
		PublicKey:       pub,
		TargetOS:        manifest.OS,
		TargetArch:      manifest.Architecture,
		AllowedChannel:  channel,
		CurrentSequence: 0,
		CurrentVersion:  "",
		CurrentTime:     time.Now().UTC(),
		AllowedHosts:    []string{"downloads.acornfox.local"},
		MaxArtifactSize: desktopupdate.MaxArtifactSizeBytes,
	}

	bundle, err := desktopupdate.VerifyHostBundle(ctx, artifactPath, envRaw, opts)
	if err != nil {
		return err
	}
	return bundle.Close()
}

func sha256Sum(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}
