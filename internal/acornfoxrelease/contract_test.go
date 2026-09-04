package acornfoxrelease

import (
	"bytes"
	"strings"
	"testing"
)

func decisionFixture() DecisionV1 {
	return DecisionV1{SchemaVersion: DecisionV1Schema, Product: Product, Architecture: Architecture, Migration: Migration, Layout: Layout, Version: "1.2.3-rc.1", ReleaseID: "release-1.2.3-rc.1", SourceRepository: "https://github.com/acme/acornfox-fixture", SourceCommit: strings.Repeat("a", 40), SourcePolicySHA256: strings.Repeat("b", 64), ToolchainSHA256: strings.Repeat("c", 64), RuntimeInputSHA256: strings.Repeat("d", 64), LicenseInputSHA256: strings.Repeat("e", 64)}
}
func decisionRaw(t *testing.T) ([]byte, string) {
	t.Helper()
	raw, err := CanonicalDecisionV1(decisionFixture())
	if err != nil {
		t.Fatal(err)
	}
	return raw, sha256Text(raw)
}

func TestDecisionV1CanonicalWitness(t *testing.T) {
	raw, digest := decisionRaw(t)
	witness, err := ParseDecisionV1(raw, digest)
	version, versionErr := witness.Version()
	release, releaseErr := witness.ReleaseID()
	repo, repoErr := witness.SourceRepository()
	commit, commitErr := witness.SourceCommit()
	gotDigest, digestErr := witness.SHA256()
	if err != nil || !witness.Valid() || versionErr != nil || releaseErr != nil || repoErr != nil || commitErr != nil || digestErr != nil || version != "1.2.3-rc.1" || release != "release-1.2.3-rc.1" || repo != "https://github.com/acme/acornfox-fixture" || commit != strings.Repeat("a", 40) || gotDigest != digest {
		t.Fatalf("witness=%#v err=%v", witness, err)
	}
}

func TestDecisionV1ZeroWitnessIsExplicitlyInvalid(t *testing.T) {
	var witness Witness
	if witness.Valid() {
		t.Fatal("zero witness is valid")
	}
	if value, err := witness.SHA256(); err == nil || value != "" {
		t.Fatalf("zero SHA=%q err=%v", value, err)
	}
	if value, err := witness.Version(); err == nil || value != "" {
		t.Fatalf("zero version=%q err=%v", value, err)
	}
}

func TestDecisionV1RejectsNonCanonicalAndDigestDrift(t *testing.T) {
	raw, digest := decisionRaw(t)
	for name, bad := range map[string][]byte{
		"whitespace": append(append([]byte(nil), raw...), ' '),
		"unknown":    append(append([]byte(nil), raw[:len(raw)-1]...), []byte(`,"unknown":true}`)...),
		"duplicate":  bytes.Replace(raw, []byte(`"layout":1`), []byte(`"layout":1,"layout":1`), 1),
		"null":       bytes.Replace(raw, []byte(`"version":"1.2.3-rc.1"`), []byte(`"version":null`), 1),
		"trailing":   append(append([]byte(nil), raw...), []byte(`{}`)...),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseDecisionV1(bad, sha256Text(bad)); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	if _, err := ParseDecisionV1(raw, strings.Repeat("f", 64)); err == nil {
		t.Fatal("digest drift accepted")
	}
	if _, err := ParseDecisionV1(append(raw, make([]byte, maxDecisionBytes)...), digest); err == nil {
		t.Fatal("oversize accepted")
	}
}

func TestDecisionV1RejectsHostileGitHubURLs(t *testing.T) {
	for _, repository := range []string{
		"https://github.com/acme%2Fother/repo", "https://github.com/acme/%2e%2e", "https://github.com:443/acme/repo", "https://user@github.com/acme/repo", "https://github.com/acme/repo?x=1", "https://github.com/acme/repo?", "https://github.com/acme/repo#fragment", "https://github.com/acme/repo/", "https://github.com/acme/repo.git",
	} {
		t.Run(repository, func(t *testing.T) {
			decision := decisionFixture()
			decision.SourceRepository = repository
			if _, err := CanonicalDecisionV1(decision); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestDecisionV1RejectsUnsafeIdentityAndDigests(t *testing.T) {
	for name, mutate := range map[string]func(*DecisionV1){
		"uppercase digest": func(d *DecisionV1) { d.ToolchainSHA256 = strings.ToUpper(d.ToolchainSHA256) },
		"unsafe version":   func(d *DecisionV1) { d.Version = "01.2.3" },
		"wrong release":    func(d *DecisionV1) { d.ReleaseID = "release-9.9.9" },
		"unsafe repo":      func(d *DecisionV1) { d.SourceRepository = "https://github.com/acme/acornfox-fixture.git" },
		"unsafe commit":    func(d *DecisionV1) { d.SourceCommit = strings.Repeat("A", 40) },
		"wrong product":    func(d *DecisionV1) { d.Product = "other" },
	} {
		t.Run(name, func(t *testing.T) {
			d := decisionFixture()
			mutate(&d)
			if _, err := CanonicalDecisionV1(d); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}
