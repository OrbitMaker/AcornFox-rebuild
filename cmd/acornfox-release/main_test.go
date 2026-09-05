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
