package contracts

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestAcornFoxPublicSourceProvenanceRequiresExplicitSafeURL(t *testing.T) {
	valid := AcornFoxPublicSourceProvenance{SourceRevisionID: "src_1", RepositoryURL: "https://github.com/acme/example.git"}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, repositoryURL := range []string{
		"http://github.com/acme/example.git",
		"https://user:password@github.com/acme/example.git",
		"https://github.com/acme/example.git?token=secret",
		"https://github.com/acme/example.git#private",
		"https://github.com:8443/acme/example.git",
	} {
		if err := (AcornFoxPublicSourceProvenance{SourceRevisionID: "src_1", RepositoryURL: repositoryURL}).Validate(); err == nil {
			t.Fatalf("repository URL %q was accepted", repositoryURL)
		}
	}
}

func TestAcornFoxUnavailableMetadataCannotLeakSourceFields(t *testing.T) {
	metadata := AcornFoxSourceMetadata{SourceRevisionID: "src_1", Availability: AcornFoxUnavailable}
	if err := metadata.Validate(); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "repository_url") {
		t.Fatalf("unavailable source metadata emitted an URL: %s", encoded)
	}
	if err := (AcornFoxDeploymentSource{DeploymentID: "dep_1", Availability: AcornFoxUnavailable, Commit: strings.Repeat("a", 40)}).Validate(); err == nil {
		t.Fatal("unavailable deployment source accepted a leaked commit")
	}
}
