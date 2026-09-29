package packprotocol

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestCatalogAndManifestBoundedTrust(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	m := Manifest{Schema: "acornfox-pack-manifest-v1", PackID: "fixture-echo", Version: "1.0.0", OS: "linux", Arch: "amd64", MinCoreVersion: "1.0.0", ProtocolVersion: "1.0", Capabilities: []string{"echo.run"}, Dependencies: []Dependency{}, Permissions: []string{"state.private"}, Entries: []Entry{{Role: "adapter", Path: "bin/adapter"}}, Files: []File{{Path: "bin/adapter", SHA256: strings.Repeat("a", 64), Size: 42, Mode: 0755}}}
	manifest, _ := json.Marshal(m)
	c := CatalogPayload{Publisher: "fixture-publisher", PackID: m.PackID, Version: m.Version, OS: m.OS, Arch: m.Arch, Sequence: 7, ExpiresAt: now.Add(time.Hour).Format(time.RFC3339Nano), ManifestSHA256: digest(manifest), ArtifactSHA256: strings.Repeat("b", 64), ArtifactSize: 100, ArtifactURL: "https://fixture-packs.invalid/archive.tgz"}
	policy := VerificationPolicy{Publisher: c.Publisher, PublicKey: public, AllowedHosts: []string{"fixture-packs.invalid"}, CoreVersion: "1.0.0", ProtocolVersion: "1.0", OS: "linux", Arch: "amd64", InstallationBinding: strings.Repeat("c", 64), Now: now}
	envelope := func(payload CatalogPayload, domain string) []byte {
		b, _ := json.Marshal(payload)
		signature := ed25519.Sign(private, append([]byte(domain), b...))
		out, _ := json.Marshal(CatalogEnvelope{Schema: "acornfox-pack-catalog-envelope-v1", Payload: base64.StdEncoding.EncodeToString(b), Signature: base64.StdEncoding.EncodeToString(signature)})
		return out
	}
	verified, err := VerifySelection(envelope(c, CatalogSignatureDomain), manifest, policy)
	if err != nil {
		t.Fatal(err)
	}
	_, copyBytes, ok := verified.Snapshot()
	copyBytes[0] = '!'
	_, again, _ := verified.Snapshot()
	if !ok || again[0] != '{' {
		t.Fatal("selection accessor retained mutable manifest")
	}
	rawEnv, rawMan, hasMat := verified.VerificationMaterial()
	if !hasMat || len(rawEnv) == 0 || len(rawMan) == 0 {
		t.Fatal("expected verification material to be present")
	}
	rawEnv[0] = '!'
	rawMan[0] = '!'
	againEnv, againMan, _ := verified.VerificationMaterial()
	if againEnv[0] == '!' || againMan[0] == '!' {
		t.Fatal("verification material accessor retained mutable slice")
	}
	cases := []struct {
		name string
		run  func() error
	}{
		{"missing-policy", func() error {
			_, e := VerifySelection(envelope(c, CatalogSignatureDomain), manifest, VerificationPolicy{})
			return e
		}},
		{"desktop-signature-domain", func() error { _, e := VerifySelection(envelope(c, ""), manifest, policy); return e }},
		{"wrong-signature", func() error {
			bad := append([]byte(nil), envelope(c, CatalogSignatureDomain)...)
			bad[len(bad)/2] ^= 1
			_, e := VerifySelection(bad, manifest, policy)
			return e
		}},
		{"expired", func() error {
			bad := c
			bad.ExpiresAt = now.Format(time.RFC3339Nano)
			_, e := VerifySelection(envelope(bad, CatalogSignatureDomain), manifest, policy)
			return e
		}},
		{"wrong-pack", func() error {
			bad := c
			bad.PackID = "fixture-other"
			_, e := VerifySelection(envelope(bad, CatalogSignatureDomain), manifest, policy)
			return e
		}},
		{"wrong-platform", func() error {
			bad := c
			bad.Arch = "arm64"
			_, e := VerifySelection(envelope(bad, CatalogSignatureDomain), manifest, policy)
			return e
		}},
		{"credential-url", func() error {
			bad := c
			bad.ArtifactURL = "https://user:password@fixture-packs.invalid/a"
			_, e := VerifySelection(envelope(bad, CatalogSignatureDomain), manifest, policy)
			return e
		}},
		{"unknown-manifest-key", func() error {
			_, e := ParseManifest(append(manifest[:len(manifest)-1], []byte(`,"shell":"anything"}`)...))
			return e
		}},
		{"duplicate-key", func() error {
			_, e := ParseManifest(append([]byte(`{"pack_id":"fixture-other",`), manifest[1:]...))
			return e
		}},
		{"trailing-close", func() error { _, e := ParseManifest(append(append([]byte(nil), manifest...), ']')); return e }},
		{"escaping-entry", func() error {
			bad := m
			bad.Files = []File{{Path: "../adapter", SHA256: strings.Repeat("a", 64), Size: 1, Mode: 0755}}
			b, _ := json.Marshal(bad)
			_, e := ParseManifest(b)
			return e
		}},
		{"reserved-core", func() error {
			bad := m
			bad.PackID = "core"
			b, _ := json.Marshal(bad)
			_, e := ParseManifest(b)
			return e
		}},
		{"undeclared-executable", func() error {
			bad := m
			bad.Files = append(append([]File(nil), m.Files...), File{Path: "bin/extra", SHA256: strings.Repeat("a", 64), Size: 1, Mode: 0755})
			b, _ := json.Marshal(bad)
			_, e := ParseManifest(b)
			return e
		}},
		{"incompatible-core", func() error {
			bad := policy
			bad.CoreVersion = "0.9.0"
			_, e := VerifySelection(envelope(c, CatalogSignatureDomain), manifest, bad)
			return e
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if test.run() == nil {
				t.Fatal("untrusted declarative input accepted")
			}
		})
	}
}
