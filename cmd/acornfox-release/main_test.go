package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/open-card/open-card/internal/install"
)

func TestBuildRejectsInvalidPredecessorBeforeProducingOutput(t *testing.T) {
	binding := install.AcornFoxCandidateBindingV1{SchemaVersion: 1, Product: "acornfox", Version: "1.2.3", ReleaseID: "release-1.2.3", SourceRepository: "https://github.com/acme/acornfox", SourceCommit: strings.Repeat("a", 40), Architecture: "amd64", MigrationVersion: install.AcornFoxV1MigrationVersion, ManifestSHA256: strings.Repeat("a", 64), ArchiveSHA256: strings.Repeat("b", 64), BundleManifestSHA256: strings.Repeat("c", 64)}
	raw, err := json.Marshal(binding)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(raw)
	digest := hex.EncodeToString(hash[:])
	root := t.TempDir()
	input := filepath.Join(root, "binding.json")
	if err := os.WriteFile(input, raw, 0644); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name  string
		flags []string
		want  string
	}{
		{"file only", []string{"--predecessor-binding", input}, "provided together"},
		{"sha only", []string{"--predecessor-sha256", digest}, "provided together"},
		{"wrong sha", []string{"--predecessor-binding", input, "--predecessor-sha256", strings.Repeat("0", 64)}, "sha256 mismatch"},
		{"missing file", []string{"--predecessor-binding", filepath.Join(root, "absent"), "--predecessor-sha256", digest}, "read predecessor binding"},
		// A valid pair gets past predecessor validation and reaches the existing
		// required-input validation, without creating output or starting a build.
		{"valid pair", []string{"--predecessor-binding", input, "--predecessor-sha256", digest}, "all build input"},
		{"bootstrap", nil, "all build input"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var out, diagnostic bytes.Buffer
			output := filepath.Join(root, "output")
			args := append([]string{"build", "--output", output}, test.flags...)
			if err := run(context.Background(), args, &out, &diagnostic); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("unexpected error %v", err)
			}
			if out.Len() != 0 {
				t.Fatal("invalid inputs wrote output")
			}
			if _, err := os.Lstat(output); !os.IsNotExist(err) {
				t.Fatal("invalid inputs created output directory")
			}
		})
	}
}

func TestBuildAcceptsPinned0039PredecessorBeforeRequiringBuildInputs(t *testing.T) {
	binding := install.AcornFoxCandidateBindingV1{SchemaVersion: 1, Product: "acornfox", Version: "1.2.3", ReleaseID: "release-1.2.3", SourceRepository: "https://github.com/acme/acornfox", SourceCommit: strings.Repeat("a", 40), Architecture: "amd64", MigrationVersion: "0039", ManifestSHA256: strings.Repeat("a", 64), ArchiveSHA256: strings.Repeat("b", 64), BundleManifestSHA256: strings.Repeat("c", 64)}
	raw, err := json.Marshal(binding)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	input := filepath.Join(t.TempDir(), "old-binding.json")
	if err = os.WriteFile(input, raw, 0600); err != nil {
		t.Fatal(err)
	}
	var out, diagnostic bytes.Buffer
	err = run(context.Background(), []string{"build", "--predecessor-binding", input, "--predecessor-sha256", hex.EncodeToString(sum[:])}, &out, &diagnostic)
	if err == nil || !strings.Contains(err.Error(), "all build input") {
		t.Fatalf("historical binding did not reach normal build-input validation: %v", err)
	}
}

func TestNativePartialModeRejectsLegacyAndArbitraryTargetsBeforeOutput(t *testing.T) {
	for _, flags := range [][]string{{"--decision", "old.json"}, {"--target", "./cmd/open-card-server"}, {"--allow-dirty"}, {"unexpected"}, nil} {
		var out, diagnostic bytes.Buffer
		args := append([]string{"native-partial-build", "--output", filepath.Join(t.TempDir(), "native")}, flags...)
		if err := run(context.Background(), args, &out, &diagnostic); err == nil {
			t.Fatal("incomplete or unsupported native input accepted")
		}
		if out.Len() != 0 {
			t.Fatal("invalid native mode emitted output")
		}
		if _, err := os.Lstat(args[2]); !os.IsNotExist(err) {
			t.Fatal("invalid native mode created output")
		}
	}
}

func TestNativeProductModeRejectsUnpinnedTargetBeforeOutput(t *testing.T) {
	var out, diagnostic bytes.Buffer
	output := filepath.Join(t.TempDir(), "native-product")
	if err := run(context.Background(), []string{"native-product-build", "--output", output, "--target", "./cmd/unapproved"}, &out, &diagnostic); err == nil {
		t.Fatal("product build accepted caller target")
	}
	if out.Len() != 0 {
		t.Fatal("invalid product mode emitted receipt")
	}
	if _, err := os.Lstat(output); !os.IsNotExist(err) {
		t.Fatal("invalid product mode created output")
	}
}
