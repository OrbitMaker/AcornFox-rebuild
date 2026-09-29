package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestNativeFullManifestRequiresBothExternalPinsBeforeOutput(t *testing.T) {
	var output, diagnostic bytes.Buffer
	dir := t.TempDir()
	destination := filepath.Join(dir, "full")
	product := filepath.Join(dir, "product.json")
	materials := filepath.Join(dir, "materials.json")
	if err := os.WriteFile(product, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(materials, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	err := run(context.Background(), []string{"native-full-manifest", "--product-root", t.TempDir(), "--product-receipt", product, "--material-root", t.TempDir(), "--materials", materials, "--output", destination}, &output, &diagnostic)
	if err == nil || output.Len() != 0 {
		t.Fatal("full manifest accepted missing independent pins")
	}
	if _, err := os.Lstat(destination); !os.IsNotExist(err) {
		t.Fatal("incomplete input created full output")
	}
}
