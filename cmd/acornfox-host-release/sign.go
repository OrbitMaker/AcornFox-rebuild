package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/open-card/open-card/internal/desktopupdate"
)

type SignIndexOptions struct {
	IndexSpecPath   string
	KeyFilePath     string
	OutputPath      string
	AllowedChannel  string   // required ("stable" or "beta")
	AllowedHosts    []string // required (non-empty list of DNS hostnames)
	PayloadRoots    []string // required (must verify key is outside all payload trees)
	BundleFiles     []string // required (must verify every artifact against real bundle)
	TargetOS        string
	TargetArch      string
	CurrentSequence uint64
	CurrentVersion  string
	MaxArtifactSize int64
}

type VerifiedBundleSummary struct {
	OS             string `json:"os"`
	Architecture   string `json:"arch"`
	BundlePath     string `json:"bundle_path"`
	SHA256         string `json:"sha256"`
	Size           int64  `json:"size"`
	BackendBinding string `json:"backend_binding"`
	Verified       bool   `json:"verified"`
}

type SignReceipt struct {
	Output               string                  `json:"output"`
	SchemaVersion        int                     `json:"schema_version"`
	Channel              string                  `json:"channel"`
	Sequence             uint64                  `json:"sequence"`
	Version              string                  `json:"version"`
	ExpiresAt            string                  `json:"expires_at"`
	PublicKeyHex         string                  `json:"public_key_hex"`
	PublicKeyFingerprint string                  `json:"public_key_fingerprint"`
	ArtifactsCount       int                     `json:"artifacts_count"`
	VerifiedBundles      []VerifiedBundleSummary `json:"verified_bundles"`
}

func signIndex(ctx context.Context, opts SignIndexOptions, out io.Writer) (*SignReceipt, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if opts.IndexSpecPath == "" {
		return nil, errors.New("index spec file path is required")
	}
	if opts.KeyFilePath == "" {
		return nil, errors.New("signing key file path is required")
	}
	if opts.OutputPath == "" {
		return nil, errors.New("output index envelope path is required")
	}

	// Operator policy enforcement: channel and allowed hosts must be explicitly provided
	if opts.AllowedChannel != "stable" && opts.AllowedChannel != "beta" {
		return nil, fmt.Errorf("operator policy --allowed-channel is required (must be 'stable' or 'beta', got %q)", opts.AllowedChannel)
	}
	if len(opts.AllowedHosts) == 0 {
		return nil, errors.New("operator policy --allowed-hosts is required (must be non-empty list of allowed hostnames)")
	}
	if (opts.TargetOS == "") != (opts.TargetArch == "") {
		return nil, errors.New("--target-os and --target-arch must either both be specified or both be omitted")
	}
	if len(opts.PayloadRoots) == 0 {
		return nil, errors.New("operator policy --payload-roots is required to verify key isolation outside all payload trees")
	}
	if len(opts.BundleFiles) == 0 {
		return nil, errors.New("operator policy --bundles is required to verify host release artifacts against envelope")
	}

	cleanOutput := filepath.Clean(opts.OutputPath)
	if _, err := os.Lstat(cleanOutput); !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("output file already exists (no-clobber): %s", cleanOutput)
	}

	// 1. Read and parse IndexPayload spec
	specData, err := os.ReadFile(opts.IndexSpecPath)
	if err != nil {
		return nil, fmt.Errorf("cannot read index spec: %w", err)
	}

	payload, err := parseIndexPayloadSpec(specData)
	if err != nil {
		return nil, fmt.Errorf("invalid index spec: %w", err)
	}

	// Verify payload channel matches operator policy
	if payload.Channel != opts.AllowedChannel {
		return nil, fmt.Errorf("payload channel %q does not match operator policy --allowed-channel %q", payload.Channel, opts.AllowedChannel)
	}

	// 2. Read private key from secure 0600 file outside output tree AND outside all payload trees
	outsideDirs := append([]string{filepath.Dir(cleanOutput)}, opts.PayloadRoots...)
	privKey, pubKey, err := loadPrivateKey(opts.KeyFilePath, outsideDirs)
	if err != nil {
		return nil, fmt.Errorf("failed to load signing key: %w", err)
	}
	defer func() {
		// Zero private key memory on return
		for i := range privKey {
			privKey[i] = 0
		}
	}()

	pubKeyHex := hex.EncodeToString(pubKey)
	pubFingerprint := hex.EncodeToString(sha256Sum(pubKey))

	// 3. Sign canonical json.Marshal(payload)
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal index payload: %w", err)
	}

	sig := ed25519.Sign(privKey, payloadBytes)

	envelope := desktopupdate.IndexEnvelope{
		SchemaVersion: desktopupdate.CurrentSchemaVersion,
		Payload:       base64.StdEncoding.EncodeToString(payloadBytes),
		Signature:     base64.StdEncoding.EncodeToString(sig),
	}

	envelopeBytes, err := json.Marshal(envelope)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal index envelope: %w", err)
	}

	maxSize := opts.MaxArtifactSize
	if maxSize <= 0 {
		maxSize = desktopupdate.MaxArtifactSizeBytes
	}

	// 4. Verify envelope with VerifyAndSelectUpdate using explicit operator policy
	if opts.TargetOS != "" && opts.TargetArch != "" {
		checkOpts := desktopupdate.CheckUpdateOptions{
			PublicKey:       pubKey,
			TargetOS:        opts.TargetOS,
			TargetArch:      opts.TargetArch,
			AllowedChannel:  opts.AllowedChannel,
			CurrentSequence: opts.CurrentSequence,
			CurrentVersion:  opts.CurrentVersion,
			CurrentTime:     time.Now().UTC(),
			AllowedHosts:    opts.AllowedHosts,
			MaxArtifactSize: maxSize,
		}
		if _, err := desktopupdate.VerifyAndSelectUpdate(envelopeBytes, checkOpts); err != nil {
			return nil, fmt.Errorf("VerifyAndSelectUpdate failed for %s/%s: %w", opts.TargetOS, opts.TargetArch, err)
		}
	} else {
		for _, art := range payload.Artifacts {
			checkOpts := desktopupdate.CheckUpdateOptions{
				PublicKey:       pubKey,
				TargetOS:        art.OS,
				TargetArch:      art.Arch,
				AllowedChannel:  opts.AllowedChannel,
				CurrentSequence: opts.CurrentSequence,
				CurrentVersion:  opts.CurrentVersion,
				CurrentTime:     time.Now().UTC(),
				AllowedHosts:    opts.AllowedHosts,
				MaxArtifactSize: maxSize,
			}
			if _, err := desktopupdate.VerifyAndSelectUpdate(envelopeBytes, checkOpts); err != nil {
				return nil, fmt.Errorf("VerifyAndSelectUpdate failed for %s/%s: %w", art.OS, art.Arch, err)
			}
		}
	}

	// 5. Verify every platform artifact against its real bundle using VerifyHostBundle
	var verifiedBundles []VerifiedBundleSummary
	for _, art := range payload.Artifacts {
		checkOpts := desktopupdate.CheckUpdateOptions{
			PublicKey:       pubKey,
			TargetOS:        art.OS,
			TargetArch:      art.Arch,
			AllowedChannel:  opts.AllowedChannel,
			CurrentSequence: opts.CurrentSequence,
			CurrentVersion:  opts.CurrentVersion,
			CurrentTime:     time.Now().UTC(),
			AllowedHosts:    opts.AllowedHosts,
			MaxArtifactSize: maxSize,
		}

		var matchedBundlePath string
		for _, bPath := range opts.BundleFiles {
			cleanBPath := filepath.Clean(bPath)
			bundle, err := desktopupdate.VerifyHostBundle(ctx, cleanBPath, envelopeBytes, checkOpts)
			if err == nil {
				m := bundle.Manifest()
				if m.OS == art.OS && m.Architecture == art.Arch {
					if bundle.SHA256() != art.SHA256 {
						bundle.Close()
						return nil, fmt.Errorf("bundle %s SHA256 %s does not match index artifact SHA256 %s", cleanBPath, bundle.SHA256(), art.SHA256)
					}
					if m.Backend.ToBinding != art.BackendBinding {
						bundle.Close()
						return nil, fmt.Errorf("bundle %s backend binding %s does not match artifact %s", cleanBPath, m.Backend.ToBinding, art.BackendBinding)
					}
					info, statErr := os.Stat(cleanBPath)
					if statErr != nil {
						bundle.Close()
						return nil, fmt.Errorf("cannot stat bundle %s: %w", cleanBPath, statErr)
					}
					if info.Size() != art.Size {
						bundle.Close()
						return nil, fmt.Errorf("bundle %s size mismatch: %d != %d", cleanBPath, info.Size(), art.Size)
					}
					bundle.Close()
					matchedBundlePath = cleanBPath
					break
				}
				bundle.Close()
			}
		}
		if matchedBundlePath == "" {
			return nil, fmt.Errorf("no valid bundle verified for artifact %s/%s among provided --bundles", art.OS, art.Arch)
		}

		verifiedBundles = append(verifiedBundles, VerifiedBundleSummary{
			OS:             art.OS,
			Architecture:   art.Arch,
			BundlePath:     matchedBundlePath,
			SHA256:         art.SHA256,
			Size:           art.Size,
			BackendBinding: art.BackendBinding,
			Verified:       true,
		})
	}

	// 6. Atomic no-clobber write of signed envelope
	if err := atomicWriteFileNoClobber(cleanOutput, envelopeBytes, 0644); err != nil {
		return nil, fmt.Errorf("failed to write index envelope: %w", err)
	}

	receipt := &SignReceipt{
		Output:               cleanOutput,
		SchemaVersion:        envelope.SchemaVersion,
		Channel:              payload.Channel,
		Sequence:             payload.Sequence,
		Version:              payload.Version,
		ExpiresAt:            payload.ExpiresAt,
		PublicKeyHex:         pubKeyHex,
		PublicKeyFingerprint: pubFingerprint,
		ArtifactsCount:       len(payload.Artifacts),
		VerifiedBundles:      verifiedBundles,
	}

	if out != nil {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		_ = enc.Encode(receipt)
	}

	return receipt, nil
}

func parseIndexPayloadSpec(data []byte) (*desktopupdate.IndexPayload, error) {
	if len(data) == 0 || len(data) > 1<<20 {
		return nil, errors.New("invalid index payload spec size")
	}

	allowedTopFields := map[string]struct{}{
		"channel":    {},
		"sequence":   {},
		"expires_at": {},
		"version":    {},
		"artifacts":  {},
	}

	if err := checkStrictJSONKeys(data, allowedTopFields); err != nil {
		return nil, fmt.Errorf("invalid keys in index spec: %w", err)
	}

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var p desktopupdate.IndexPayload
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("failed to decode index payload: %w", err)
	}
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("unexpected trailing data in index payload spec")
	}

	// Validate basic constraints
	if p.Channel != "stable" && p.Channel != "beta" {
		return nil, fmt.Errorf("invalid channel %q (must be 'stable' or 'beta')", p.Channel)
	}
	if p.Sequence == 0 {
		return nil, errors.New("sequence must be positive (sequence > 0)")
	}
	expTime, err := time.Parse(time.RFC3339, p.ExpiresAt)
	if err != nil {
		return nil, fmt.Errorf("invalid expires_at timestamp %q: %w", p.ExpiresAt, err)
	}
	if !time.Now().UTC().Before(expTime) {
		return nil, fmt.Errorf("index payload has already expired at %s", p.ExpiresAt)
	}
	semver, err := desktopupdate.ParseSemver(p.Version)
	if err != nil {
		return nil, fmt.Errorf("invalid semver version %q: %w", p.Version, err)
	}
	if p.Channel == "stable" && semver.IsPrerelease() {
		return nil, fmt.Errorf("stable channel cannot have prerelease version %q", p.Version)
	}
	if len(p.Artifacts) == 0 {
		return nil, errors.New("artifacts list must not be empty")
	}

	seenPlatforms := make(map[string]struct{})
	for _, art := range p.Artifacts {
		canonOS, canonArch, err := desktopupdate.CanonicalizePlatform(art.OS, art.Arch)
		if err != nil {
			return nil, err
		}
		if !isSupportedPlatform(canonOS, canonArch) {
			return nil, fmt.Errorf("unsupported artifact platform %s/%s", canonOS, canonArch)
		}
		platKey := canonOS + "/" + canonArch
		if _, seen := seenPlatforms[platKey]; seen {
			return nil, fmt.Errorf("duplicate artifact platform %q", platKey)
		}
		seenPlatforms[platKey] = struct{}{}

		if err := validateHexSHA256(art.SHA256); err != nil {
			return nil, fmt.Errorf("invalid artifact sha256 for %s: %w", platKey, err)
		}

		// Host release artifacts must always have a non-empty backend_binding
		if art.BackendBinding == "" {
			return nil, fmt.Errorf("host release artifact %s missing required backend_binding", platKey)
		}
		if err := validateHexSHA256(art.BackendBinding); err != nil {
			return nil, fmt.Errorf("invalid backend_binding for %s: %w", platKey, err)
		}

		if art.Size <= 0 {
			return nil, fmt.Errorf("invalid artifact size %d for %s", art.Size, platKey)
		}
		if !strings.HasPrefix(art.URL, "https://") {
			return nil, fmt.Errorf("artifact URL %q must use https", art.URL)
		}
	}

	return &p, nil
}

func loadPrivateKey(keyPath string, outsideDirs []string) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	file, err := checkRegularPrivateFile(keyPath, outsideDirs)
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()

	keyBytes, err := io.ReadAll(io.LimitReader(file, 64<<10))
	if err != nil {
		return nil, nil, errors.New("failed to read key file")
	}
	defer func() {
		// Zero buffer
		for i := range keyBytes {
			keyBytes[i] = 0
		}
	}()

	block, _ := pem.Decode(keyBytes)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, nil, errors.New("invalid private key file: expected PKCS#8 PEM with 'PRIVATE KEY' header")
	}
	defer func() {
		for i := range block.Bytes {
			block.Bytes[i] = 0
		}
	}()

	parsedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse PKCS#8 private key: %w", err)
	}

	edKey, ok := parsedKey.(ed25519.PrivateKey)
	if !ok {
		return nil, nil, errors.New("private key is not an Ed25519 key")
	}

	pubKey, ok := edKey.Public().(ed25519.PublicKey)
	if !ok || len(pubKey) != ed25519.PublicKeySize {
		return nil, nil, errors.New("failed to derive Ed25519 public key")
	}

	return edKey, pubKey, nil
}
