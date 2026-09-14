package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHostReleaseBuildLinuxVersions(t *testing.T) {
	bin := getTestBinary(t, "linux", "amd64")
	for _, version := range []string{"1.2.3", "1.2.3-beta.1", "1.2.3-rc.1"} {
		t.Run(version, func(t *testing.T) {
			dir := t.TempDir()
			payload := setupPayloadDir(t, dir, "linux", "amd64", bin)
			spec := ReleaseSpec{SchemaVersion: 1, Product: "acornfox", Kind: "host-update-v1", OS: "linux", Architecture: "amd64", Version: version, Launcher: "launcher/acornfox", Backend: BackendSpec{Mode: "unchanged", Binding: strings.Repeat("a", 64)}}
			raw, err := json.Marshal(spec)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "spec.json")
			if err := os.WriteFile(path, raw, 0644); err != nil {
				t.Fatal(err)
			}
			receipt, err := buildHostArtifact(context.Background(), BuildOptions{SpecPath: path, PayloadDir: payload, OutputPath: filepath.Join(dir, "bundle.tar.gz")}, nil)
			if err != nil {
				t.Fatal(err)
			}
			if receipt == nil || !receipt.Verified || receipt.Version != version {
				t.Fatalf("unverified build: %+v", receipt)
			}
		})
	}
}
