package main

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
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

type VerifyBundleOptions struct {
	BundlePath      string
	EnvelopePath    string
	PublicKeyFile   string
	PublicKeyHex    string
	TargetOS        string
	TargetArch      string
	AllowedChannel  string
	AllowedHosts    []string
	CurrentSequence uint64
	CurrentVersion  string
}

type VerifyReceipt struct {
	Bundle         string `json:"bundle"`
	SHA256         string `json:"sha256"`
	OS             string `json:"os"`
	Architecture   string `json:"arch"`
	Version        string `json:"version"`
	BackendMode    string `json:"backend_mode"`
	BackendBinding string `json:"backend_binding"`
	FilesCount     int    `json:"files_count"`
	Verified       bool   `json:"verified"`
}

func verifyBundle(ctx context.Context, opts VerifyBundleOptions, out io.Writer) (*VerifyReceipt, error) {
	if opts.BundlePath == "" {
		return nil, errors.New("bundle file path is required")
	}
	if opts.EnvelopePath == "" {
		return nil, errors.New("envelope file path is required")
	}

	cleanBundle := filepath.Clean(opts.BundlePath)
	cleanEnvelope := filepath.Clean(opts.EnvelopePath)

	envelopeData, err := os.ReadFile(cleanEnvelope)
	if err != nil {
		return nil, fmt.Errorf("cannot read envelope file: %w", err)
	}

	pubKey, err := loadPublicKey(opts.PublicKeyFile, opts.PublicKeyHex)
	if err != nil {
		return nil, fmt.Errorf("failed to load public key: %w", err)
	}

	channel := opts.AllowedChannel
	if channel == "" {
		channel = "stable"
	}

	allowedHosts := opts.AllowedHosts
	if len(allowedHosts) == 0 {
		return nil, errors.New("allowed hosts must be specified for verification")
	}

	checkOpts := desktopupdate.CheckUpdateOptions{
		PublicKey:       pubKey,
		TargetOS:        opts.TargetOS,
		TargetArch:      opts.TargetArch,
		AllowedChannel:  channel,
		CurrentSequence: opts.CurrentSequence,
		CurrentVersion:  opts.CurrentVersion,
		CurrentTime:     time.Now().UTC(),
		AllowedHosts:    allowedHosts,
		MaxArtifactSize: desktopupdate.MaxArtifactSizeBytes,
	}

	bundle, err := desktopupdate.VerifyHostBundle(ctx, cleanBundle, envelopeData, checkOpts)
	if err != nil {
		return nil, fmt.Errorf("VerifyHostBundle failed: %w", err)
	}
	defer bundle.Close()

	manifest := bundle.Manifest()
	receipt := &VerifyReceipt{
		Bundle:         cleanBundle,
		SHA256:         bundle.SHA256(),
		OS:             manifest.OS,
		Architecture:   manifest.Architecture,
		Version:        manifest.Version,
		BackendMode:    manifest.Backend.Mode,
		BackendBinding: manifest.Backend.ToBinding,
		FilesCount:     len(manifest.Files),
		Verified:       true,
	}

	if out != nil {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		_ = enc.Encode(receipt)
	}

	return receipt, nil
}

func loadPublicKey(keyFile, keyHex string) (ed25519.PublicKey, error) {
	if keyHex != "" {
		cleanHex := strings.TrimSpace(keyHex)
		b, err := hex.DecodeString(cleanHex)
		if err != nil {
			return nil, fmt.Errorf("invalid public key hex: %w", err)
		}
		if len(b) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("public key hex must be %d bytes, got %d", ed25519.PublicKeySize, len(b))
		}
		return ed25519.PublicKey(b), nil
	}

	if keyFile != "" {
		data, err := os.ReadFile(keyFile)
		if err != nil {
			return nil, fmt.Errorf("cannot read public key file: %w", err)
		}

		// Try PEM first
		block, _ := pem.Decode(data)
		if block != nil && (block.Type == "PUBLIC KEY" || strings.Contains(block.Type, "PUBLIC")) {
			pub, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err == nil {
				if edPub, ok := pub.(ed25519.PublicKey); ok {
					return edPub, nil
				}
			}
		}

		// Try raw 32 bytes
		trimmed := strings.TrimSpace(string(data))
		if len(trimmed) == 64 {
			if b, err := hex.DecodeString(trimmed); err == nil && len(b) == ed25519.PublicKeySize {
				return ed25519.PublicKey(b), nil
			}
		}
		if len(data) == ed25519.PublicKeySize {
			return ed25519.PublicKey(data), nil
		}

		return nil, errors.New("unrecognized public key file format (must be PEM PKIX, 64-char hex, or raw 32 bytes)")
	}

	return nil, errors.New("either public key file or public key hex is required")
}
