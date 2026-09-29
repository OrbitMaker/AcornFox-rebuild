package packprotocol

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"math"
	"net/url"
	"strings"
	"time"

	"github.com/open-card/open-card/internal/versionpolicy"
)

const CatalogSignatureDomain = "acornfox-pack-catalog-v1\x00"

type CatalogEnvelope struct {
	Schema    string `json:"schema"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}
type CatalogPayload struct {
	Publisher      string `json:"publisher"`
	PackID         string `json:"pack_id"`
	Version        string `json:"version"`
	OS             string `json:"os"`
	Arch           string `json:"arch"`
	Sequence       uint64 `json:"sequence"`
	ExpiresAt      string `json:"expires_at"`
	ManifestSHA256 string `json:"manifest_sha256"`
	ArtifactSHA256 string `json:"artifact_sha256"`
	ArtifactSize   int64  `json:"artifact_size"`
	ArtifactURL    string `json:"artifact_url"`
}

// Policy is supplied solely by trusted core configuration, never transport input.
// There is deliberately no default publisher/key/host or trust-any policy.
type VerificationPolicy struct {
	Publisher           string
	PublicKey           ed25519.PublicKey
	AllowedHosts        []string
	CoreVersion         string
	ProtocolVersion     string
	OS                  string
	Arch                string
	InstallationBinding string
	Now                 time.Time
}
type Selection struct {
	Publisher, PackID, Version, OS, Arch, ManifestSHA256, ArtifactSHA256, ArtifactURL, CatalogSHA256, InstallationBinding, MinCoreVersion, ProtocolVersion string
	ArtifactSize                                                                                                                                           int64
	CatalogSequence                                                                                                                                        int64
	ExpiresAt                                                                                                                                              time.Time
}
type VerifiedPackSelection struct {
	selection Selection
	manifest  []byte
	envelope  []byte
	verified  bool
}

func (v VerifiedPackSelection) Snapshot() (Selection, []byte, bool) {
	return v.selection, append([]byte(nil), v.manifest...), v.verified
}
func (v VerifiedPackSelection) VerificationMaterial() ([]byte, []byte, bool) {
	if !v.verified {
		return nil, nil, false
	}
	return append([]byte(nil), v.envelope...), append([]byte(nil), v.manifest...), true
}
func (v VerifiedPackSelection) Authorize(binding, core, protocol string, now time.Time) error {
	if !v.verified || binding != v.selection.InstallationBinding || !validDigest(binding) || protocol != v.selection.ProtocolVersion || !now.Before(v.selection.ExpiresAt) {
		return errors.New("selection_not_authorized")
	}
	current, err := versionpolicy.ParseSemver(core)
	if err != nil {
		return err
	}
	minimum, err := versionpolicy.ParseSemver(v.selection.MinCoreVersion)
	if err != nil || current.Compare(minimum) < 0 {
		return errors.New("core_incompatible")
	}
	return nil
}
func VerifySelection(envelope, manifest []byte, p VerificationPolicy) (VerifiedPackSelection, error) {
	if p.Publisher == "" || strings.TrimSpace(p.Publisher) != p.Publisher || len(p.PublicKey) != ed25519.PublicKeySize || len(p.AllowedHosts) == 0 || p.Now.IsZero() || !validDigest(p.InstallationBinding) || p.CoreVersion == "" || p.ProtocolVersion != "1.0" {
		return VerifiedPackSelection{}, errors.New("explicit_trust_policy_required")
	}
	var e CatalogEnvelope
	if err := strictJSON(envelope, &e, 256<<10); err != nil {
		return VerifiedPackSelection{}, err
	}
	if e.Schema != "acornfox-pack-catalog-envelope-v1" {
		return VerifiedPackSelection{}, errors.New("catalog_schema_rejected")
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(e.Payload)
	if err != nil || len(raw) > 128<<10 {
		return VerifiedPackSelection{}, errors.New("catalog_payload_rejected")
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(e.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(p.PublicKey, append([]byte(CatalogSignatureDomain), raw...), signature) {
		return VerifiedPackSelection{}, errors.New("catalog_signature_rejected")
	}
	var c CatalogPayload
	if err := strictJSON(raw, &c, 128<<10); err != nil {
		return VerifiedPackSelection{}, err
	}
	m, err := ParseManifest(manifest)
	if err != nil {
		return VerifiedPackSelection{}, err
	}
	if c.Publisher != p.Publisher || !ValidPackID(c.PackID) || c.PackID != m.PackID || c.Version != m.Version || c.OS != m.OS || c.Arch != m.Arch || c.OS != p.OS || c.Arch != p.Arch || c.Sequence == 0 || c.Sequence > math.MaxInt64 || c.ManifestSHA256 != digest(manifest) || !validDigest(c.ArtifactSHA256) || c.ArtifactSize <= 0 || c.ArtifactSize > 1<<30 {
		return VerifiedPackSelection{}, errors.New("catalog_manifest_binding_rejected")
	}
	u, err := url.Parse(c.ArtifactURL)
	if err != nil || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Port() != "" || u.Hostname() != strings.ToLower(u.Hostname()) || strings.HasSuffix(u.Hostname(), ".") {
		return VerifiedPackSelection{}, errors.New("catalog_url_rejected")
	}
	allowed := false
	for _, h := range p.AllowedHosts {
		if h == "" || h != strings.ToLower(h) || strings.ContainsAny(h, "/:@ ") || strings.HasSuffix(h, ".") {
			return VerifiedPackSelection{}, errors.New("catalog_host_policy_rejected")
		}
		if h == u.Hostname() {
			allowed = true
		}
	}
	if !allowed {
		return VerifiedPackSelection{}, errors.New("catalog_url_rejected")
	}
	expires, err := time.Parse(time.RFC3339Nano, c.ExpiresAt)
	if err != nil || !p.Now.Before(expires) {
		return VerifiedPackSelection{}, errors.New("catalog_expired")
	}
	s := Selection{Publisher: c.Publisher, PackID: c.PackID, Version: c.Version, OS: c.OS, Arch: c.Arch, ManifestSHA256: c.ManifestSHA256, ArtifactSHA256: c.ArtifactSHA256, ArtifactURL: c.ArtifactURL, ArtifactSize: c.ArtifactSize, CatalogSHA256: digest(raw), CatalogSequence: int64(c.Sequence), InstallationBinding: p.InstallationBinding, MinCoreVersion: m.MinCoreVersion, ProtocolVersion: m.ProtocolVersion, ExpiresAt: expires}
	verified := VerifiedPackSelection{selection: s, manifest: append([]byte(nil), manifest...), envelope: append([]byte(nil), envelope...), verified: true}
	if err := verified.Authorize(p.InstallationBinding, p.CoreVersion, p.ProtocolVersion, p.Now); err != nil {
		return VerifiedPackSelection{}, err
	}
	return verified, nil
}
